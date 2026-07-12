"""Datastore connections: two isolated Postgres pools + Redis.

The schema in ARCHITECTURE.md enforces tenant isolation with Row-Level Security
that reads a per-transaction GUC, `app.current_gym_id`. Every request that
touches tenant data must run inside a transaction that has set that GUC, or RLS
will (correctly) return zero rows. `tenant_conn()` is the single chokepoint that
guarantees it.
"""
from contextlib import asynccontextmanager

import asyncpg
from redis.asyncio import Redis

from .config import get_settings

_app_pool: asyncpg.Pool | None = None   # owner/member portals
_hw_pool: asyncpg.Pool | None = None    # door hot-path (isolated; never starved)
_redis: Redis | None = None


async def connect() -> None:
    """Open pools + Redis. Called once on startup."""
    global _app_pool, _hw_pool, _redis
    s = get_settings()
    _app_pool = await asyncpg.create_pool(
        s.database_url, min_size=s.app_pool_min, max_size=s.app_pool_max
    )
    _hw_pool = await asyncpg.create_pool(
        s.database_url, min_size=s.hw_pool_min, max_size=s.hw_pool_max
    )
    _redis = Redis.from_url(s.redis_url, decode_responses=False)


async def disconnect() -> None:
    if _app_pool:
        await _app_pool.close()
    if _hw_pool:
        await _hw_pool.close()
    if _redis:
        await _redis.aclose()


def get_redis() -> Redis:
    assert _redis is not None, "datastores not connected"
    return _redis


def hw_pool() -> asyncpg.Pool:
    """Raw, isolated pool for the hardware verify-access path."""
    assert _hw_pool is not None, "datastores not connected"
    return _hw_pool


def app_pool() -> asyncpg.Pool:
    """App pool with no tenant GUC set. Use ONLY for the global catalog
    (`gyms`, `plans`) — tables that are not under Row-Level Security. Tenant
    data must always go through `tenant_conn()`.
    """
    assert _app_pool is not None, "datastores not connected"
    return _app_pool


@asynccontextmanager
async def tenant_conn(gym_id: str, *, pool: asyncpg.Pool | None = None):
    """Acquire a connection bound to one tenant for the whole tx.

    Sets `app.current_gym_id` as a transaction-local GUC so RLS policies apply.
    Everything yielded runs inside this transaction; on exit it commits (or
    rolls back on exception) and the GUC is discarded with the transaction.

    By default uses the app pool. The hardware verify-access path passes
    `pool=hw_pool()` so the door draws from its own isolated pool (ARCHITECTURE.md
    §1) and can never be starved by portal/analytics traffic — while still
    binding the GUC, since member_profiles/memberships/hardware_devices are all
    under RLS.
    """
    target = pool if pool is not None else _app_pool
    assert target is not None, "datastores not connected"
    async with target.acquire() as conn:
        async with conn.transaction():
            # set_config(_, _, is_local=true) → scoped to this transaction only.
            await conn.execute(
                "SELECT set_config('app.current_gym_id', $1, true)", gym_id
            )
            yield conn

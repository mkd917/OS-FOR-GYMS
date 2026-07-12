"""Shared test fixtures.

These are integration tests on purpose: tenant isolation lives in Postgres
Row-Level Security and the QR replay guard lives in Redis, so mocking the
datastores would test nothing real. Each test drives the FastAPI app
in-process via httpx's ASGITransport (no uvicorn) against the Postgres + Redis
that `docker compose up -d` brings up.

The `client` fixture opens the real pools, wipes tenant data for a clean slate
(keeping the seeded `plans` catalog), and flushes Redis so replay nonces and
the member cache never leak between tests.
"""
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app import db
from app.main import app

# Every tenant table — truncated between tests. `plans` is deliberately excluded:
# it's the seeded global catalog owner signup looks up by `code`.
_TENANT_TABLES = (
    "gyms, users, member_profiles, memberships, payments, body_metrics, "
    "personal_records, hardware_devices, attendance_logs, "
    "wearable_connections, wearable_samples"
)


@pytest_asyncio.fixture
async def client():
    # Connect on the test's own event loop so asyncpg pools bind to it.
    await db.connect()
    async with db.app_pool().acquire() as conn:
        # RESTART IDENTITY CASCADE also clears the attendance_logs partitions.
        await conn.execute(f"TRUNCATE {_TENANT_TABLES} RESTART IDENTITY CASCADE")
    await db.get_redis().flushdb()  # drop nonces + member cache

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c

    await db.disconnect()

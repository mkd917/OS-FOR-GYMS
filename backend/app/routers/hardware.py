"""Hardware door endpoint — the ESP32 turnstile calls this.

This is the latency-critical IoT path from ARCHITECTURE.md §3, reworked in two
ways from the blueprint:

  1. It uses the shared token codec in app/qr.py instead of an inline HMAC copy,
     so the signer (member portal) and verifier (this endpoint) are guaranteed
     identical — a drift here would lock every member out.
  2. It draws from the isolated hardware pool and binds the RLS GUC to the gym_id
     in the token, because member_profiles / memberships / hardware_devices are
     all under Row-Level Security. (The original blueprint queried them without
     the GUC, which RLS would have turned into zero rows → every member denied.)
     Security still comes from the device-key match + HMAC + replay nonce, not
     from the GUC; the GUC only scopes which tenant's rows are visible.

Auth model: NO JWT here. The device authenticates with its hashed device key;
the member authenticates by holding a validly-signed, unexpired, unreplayed QR.
"""
import hashlib

import orjson
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from redis.asyncio import Redis

from ..config import get_settings
from ..db import get_redis, hw_pool, tenant_conn
from ..qr import parse_token, verify

router = APIRouter(prefix="/api/hardware", tags=["hardware"])


class AccessRequest(BaseModel):
    token: str             # base64url("{gym_id}.{member_id}.{ts}.{sig}")
    device_key: str        # raw hardware key; hashed + matched server-side


class AccessResponse(BaseModel):
    access_granted: bool
    reason: str | None = None


async def _member_secret_and_status(redis: Redis, conn, gym_id: str, member_id: str):
    """Redis-first; falls back to Postgres on a cache miss, then back-fills.
    The Postgres read runs on the tenant-bound hardware connection."""
    cache_key = f"gym:{gym_id}:member:{member_id}"
    cached = await redis.get(cache_key)
    if cached:
        doc = orjson.loads(cached)
        return bytes.fromhex(doc["secret"]), doc["status"]

    row = await conn.fetchrow(
        """
        SELECT mp.qr_secret, m.status
          FROM member_profiles mp
          JOIN memberships m
            ON m.gym_id = mp.gym_id AND m.member_id = mp.user_id
         WHERE mp.gym_id = $1 AND mp.user_id = $2
        """,
        gym_id, member_id,
    )
    if not row:
        return None
    secret, status = bytes(row["qr_secret"]), row["status"]
    await redis.set(
        cache_key, orjson.dumps({"secret": secret.hex(), "status": status}), ex=300
    )
    return secret, status


@router.post("/verify-access", response_model=AccessResponse)
async def verify_access(
    body: AccessRequest,
    redis: Redis = Depends(get_redis),
) -> AccessResponse:
    s = get_settings()

    # ── 1. Parse token (no I/O) ─────────────────────────────────────────
    parsed = parse_token(body.token)
    if parsed is None:
        return AccessResponse(access_granted=False, reason="malformed_token")
    gym_id, member_id, ts, sig = parsed

    key_hash = hashlib.sha256(body.device_key.encode()).digest()

    # Bind RLS to the token's gym, on the isolated hardware pool.
    async with tenant_conn(gym_id, pool=hw_pool()) as conn:
        # ── 2. Authenticate the device ──────────────────────────────────
        device = await conn.fetchrow(
            "SELECT id FROM hardware_devices "
            "WHERE gym_id = $1 AND device_key_hash = $2 AND is_active",
            gym_id, key_hash,
        )
        if device is None:
            return AccessResponse(access_granted=False, reason="unknown_device")

        # ── 3. Member secret + status (Redis hot path) ──────────────────
        found = await _member_secret_and_status(redis, conn, gym_id, member_id)
        if found is None:
            return AccessResponse(access_granted=False, reason="no_member")
        secret, status = found

        # ── 4. Verify HMAC over the rounded window (shared codec) ───────
        if not verify(secret, gym_id, member_id, ts, sig):
            return AccessResponse(access_granted=False, reason="bad_signature")

        # ── 5. Replay guard: one use per signature per window ───────────
        # Burned only AFTER the device is authenticated and the signature
        # verifies, so an attacker who merely photographs a member's QR (no
        # valid device key) — or a transient error on a legitimate scan —
        # can't consume the member's single-use slot and lock them out. The
        # nonce is scoped by tenant + member to avoid cross-member collisions
        # on the 64-bit truncated signature.
        nonce_ttl = s.qr_window_seconds * (2 * s.qr_skew_windows + 1)
        nonce_key = f"nonce:{gym_id}:{member_id}:{sig}"
        if not await redis.set(nonce_key, b"1", ex=nonce_ttl, nx=True):
            return AccessResponse(access_granted=False, reason="replayed_token")

        # ── 6. Membership must be active ────────────────────────────────
        granted = status == "active"
        await conn.execute(
            "INSERT INTO attendance_logs "
            "(gym_id, member_id, device_id, access_granted, deny_reason) "
            "VALUES ($1, $2, $3, $4, $5)",
            gym_id, member_id, device["id"], granted,
            None if granted else "inactive_membership",
        )
        # Mark the device as alive so owners can spot an offline/dead door.
        await conn.execute(
            "UPDATE hardware_devices SET last_seen_at = now() WHERE id = $1",
            device["id"],
        )

    if not granted:
        return AccessResponse(access_granted=False, reason="inactive_membership")
    return AccessResponse(access_granted=True)

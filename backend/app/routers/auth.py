"""Authentication & the portal-routing decision.

This is the router that answers the user's question "why can't I log in?" — it
is the backend the /login and /signup pages were missing.

Three facts shape every handler here, all dictated by the schema in
ARCHITECTURE.md:

  1. Email is unique *within a gym* (`UNIQUE (gym_id, email)`), not globally.
     So we can't authenticate by email alone — we need the tenant first. Login
     takes a `gym_slug`, resolves it to a `gym_id`, then authenticates inside
     that tenant.
  2. There are exactly two roles (`user_role` enum: owner | member). The login
     response returns a `portal` field so the frontend knows which dashboard to
     send the user to. No third portal exists.
  3. A member needs a `member_profiles.qr_secret` (the TOTP seed the door
     verifies) and an active `memberships` row to actually get through a
     turnstile — so member signup provisions both.
"""
import secrets

import asyncpg
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from ..db import app_pool, tenant_conn
from ..security import hash_password, issue_token, needs_rehash, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Role → portal the frontend routes to. The single source of this mapping.
PORTAL_FOR_ROLE = {"owner": "owner", "member": "member"}


# ── Wire models ──────────────────────────────────────────────────────
class OwnerSignup(BaseModel):
    gym_slug: str = Field(min_length=2, max_length=63, pattern=r"^[a-z0-9-]+$")
    gym_name: str = Field(min_length=1, max_length=120)
    plan_code: str = "starter"
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class MemberSignup(BaseModel):
    gym_slug: str = Field(min_length=2, max_length=63, pattern=r"^[a-z0-9-]+$")
    full_name: str = Field(min_length=1, max_length=120)
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)


class Login(BaseModel):
    gym_slug: str = Field(min_length=2, max_length=63, pattern=r"^[a-z0-9-]+$")
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str                  # 'owner' | 'member'
    portal: str                # which dashboard the client should route to
    gym_id: str
    user_id: str


# ── Helpers ──────────────────────────────────────────────────────────
async def _resolve_gym(slug: str) -> str:
    """Slug → gym_id. `gyms` is the tenant root (not under RLS), so this one
    pre-auth lookup is safe on the plain app pool."""
    row = await app_pool().fetchrow("SELECT id FROM gyms WHERE slug = $1", slug)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_gym")
    return str(row["id"])


def _token_response(gym_id: str, user_id: str, role: str) -> TokenResponse:
    return TokenResponse(
        access_token=issue_token(gym_id=gym_id, user_id=user_id, role=role),
        role=role,
        portal=PORTAL_FOR_ROLE[role],
        gym_id=gym_id,
        user_id=user_id,
    )


# ── Owner signup: create a new gym + its first owner ──────────────────
@router.post("/signup/owner", response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED)
async def signup_owner(body: OwnerSignup) -> TokenResponse:
    pool = app_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            plan = await conn.fetchrow(
                "SELECT id FROM plans WHERE code = $1", body.plan_code
            )
            if plan is None:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "unknown_plan")

            try:
                gym_id = await conn.fetchval(
                    "INSERT INTO gyms (slug, name, plan_id) "
                    "VALUES ($1, $2, $3) RETURNING id",
                    body.gym_slug, body.gym_name, plan["id"],
                )
            except asyncpg.UniqueViolationError:
                raise HTTPException(status.HTTP_409_CONFLICT, "gym_slug_taken")

            # users is under RLS → bind the GUC before inserting.
            await conn.execute(
                "SELECT set_config('app.current_gym_id', $1, true)", str(gym_id)
            )
            user_id = await conn.fetchval(
                "INSERT INTO users (gym_id, role, email, password_hash, full_name) "
                "VALUES ($1, 'owner', $2, $3, $4) RETURNING id",
                gym_id, body.email, hash_password(body.password), body.full_name,
            )
    return _token_response(str(gym_id), str(user_id), "owner")


# ── Member signup: join an existing gym ───────────────────────────────
@router.post("/signup/member", response_model=TokenResponse,
             status_code=status.HTTP_201_CREATED)
async def signup_member(body: MemberSignup) -> TokenResponse:
    gym_id = await _resolve_gym(body.gym_slug)
    qr_secret = secrets.token_bytes(32)   # TOTP seed the ESP32 path verifies

    async with tenant_conn(gym_id) as conn:
        try:
            user_id = await conn.fetchval(
                "INSERT INTO users (gym_id, role, email, password_hash, full_name) "
                "VALUES ($1, 'member', $2, $3, $4) RETURNING id",
                gym_id, body.email, hash_password(body.password), body.full_name,
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(status.HTTP_409_CONFLICT, "email_taken")

        # Instagram-style profile shell + the QR signing secret.
        await conn.execute(
            "INSERT INTO member_profiles (user_id, gym_id, qr_secret) "
            "VALUES ($1, $2, $3)",
            user_id, gym_id, qr_secret,
        )
        # A membership so the door grants access immediately. In production the
        # owner's billing engine owns tier/price/status; this is a sane default.
        await conn.execute(
            "INSERT INTO memberships (gym_id, member_id, tier, status, price_cents) "
            "VALUES ($1, $2, 'Basic', 'active', 0)",
            gym_id, user_id,
        )
    return _token_response(gym_id, str(user_id), "member")


# ── Login: the handler the /login page POSTs to ───────────────────────
@router.post("/login", response_model=TokenResponse)
async def login(body: Login) -> TokenResponse:
    gym_id = await _resolve_gym(body.gym_slug)

    async with tenant_conn(gym_id) as conn:
        row = await conn.fetchrow(
            "SELECT id, role, password_hash FROM users WHERE gym_id = $1 AND email = $2",
            gym_id, body.email,
        )

    # Uniform failure for unknown email vs. bad password — don't leak which.
    if row is None or not verify_password(row["password_hash"], body.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid_credentials")

    # Opportunistically upgrade the hash if argon2 params have moved on.
    if needs_rehash(row["password_hash"]):
        async with tenant_conn(gym_id) as conn:
            await conn.execute(
                "UPDATE users SET password_hash = $1 WHERE gym_id = $2 AND id = $3",
                hash_password(body.password), gym_id, row["id"],
            )

    return _token_response(gym_id, str(row["id"]), row["role"])

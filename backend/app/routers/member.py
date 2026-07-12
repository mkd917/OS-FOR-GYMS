"""Member Portal — the B2C (Gym User) interface.

Every route is gated by `require_member` (an owner's token gets a 403) and is
**self-scoped**: a member reads/writes only their own rows. We enforce that with
`member_id = principal.user_id` on every query — RLS keeps you inside your gym,
this keeps you inside your own data within that gym.

Scope, per the product spec:
  • dynamic rotating QR for turnstile entry   (the headline feature)
  • Instagram-style profile (avatar, bio, height)
  • body metrics timeline (weight, height, body-fat)
  • personal records for Squat / Bench / Deadlift

Deliberately absent: class booking, trainer messaging, workout video.
"""
from datetime import datetime
from decimal import Decimal

from asyncpg import Connection
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ..deps import Principal, require_member, tenant_db
from ..qr import build_token

router = APIRouter(prefix="/api/member", tags=["member-portal"])

# The only lifts this platform tracks (mirrors the lift_category enum).
LIFTS = {"squat", "bench_press", "deadlift"}


# ── Models ────────────────────────────────────────────────────────────
class QRResponse(BaseModel):
    token: str                 # encode this string into the on-screen QR
    refresh_in_seconds: int    # re-fetch when this elapses (window rollover)
    window_seconds: int


class Profile(BaseModel):
    avatar_url: str | None = None
    bio: str | None = Field(default=None, max_length=500)
    height_cm: Decimal | None = Field(default=None, ge=0, le=300)


class BodyMetricIn(BaseModel):
    weight_kg: Decimal | None = Field(default=None, ge=0, le=600)
    body_fat_pct: Decimal | None = Field(default=None, ge=0, le=100)
    height_cm: Decimal | None = Field(default=None, ge=0, le=300)


class BodyMetricRow(BodyMetricIn):
    id: str
    recorded_at: datetime


class PRIn(BaseModel):
    lift: str                  # 'squat' | 'bench_press' | 'deadlift'
    weight_kg: Decimal = Field(gt=0, le=1000)
    reps: int = Field(default=1, ge=1, le=100)


class PRRow(PRIn):
    id: str
    achieved_at: datetime


# ── Dynamic rotating QR ───────────────────────────────────────────────
@router.get("/qr", response_model=QRResponse)
async def get_qr(
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> QRResponse:
    """Return the current entry token. The app polls this and re-renders the QR
    each window. The token is signed with the member's own qr_secret and is
    verified by the ESP32 door via the shared codec in app/qr.py."""
    row = await db.fetchrow(
        "SELECT qr_secret FROM member_profiles WHERE gym_id = $1 AND user_id = $2",
        principal.gym_id, principal.user_id,
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_profile")

    from ..config import get_settings
    token, refresh_in = build_token(
        bytes(row["qr_secret"]), principal.gym_id, principal.user_id
    )
    return QRResponse(token=token, refresh_in_seconds=refresh_in,
                      window_seconds=get_settings().qr_window_seconds)


# ── Profile ───────────────────────────────────────────────────────────
@router.get("/profile", response_model=Profile)
async def get_profile(
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> Profile:
    row = await db.fetchrow(
        "SELECT avatar_url, bio, height_cm FROM member_profiles "
        "WHERE gym_id = $1 AND user_id = $2",
        principal.gym_id, principal.user_id,
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_profile")
    return Profile(avatar_url=row["avatar_url"], bio=row["bio"],
                   height_cm=row["height_cm"])


@router.put("/profile", response_model=Profile)
async def update_profile(
    body: Profile,
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> Profile:
    # COALESCE so a null field leaves the existing value untouched (partial update).
    row = await db.fetchrow(
        """
        UPDATE member_profiles
           SET avatar_url = COALESCE($3, avatar_url),
               bio        = COALESCE($4, bio),
               height_cm  = COALESCE($5, height_cm)
         WHERE gym_id = $1 AND user_id = $2
        RETURNING avatar_url, bio, height_cm
        """,
        principal.gym_id, principal.user_id,
        body.avatar_url, body.bio, body.height_cm,
    )
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no_profile")
    return Profile(avatar_url=row["avatar_url"], bio=row["bio"],
                   height_cm=row["height_cm"])


# ── Body metrics ──────────────────────────────────────────────────────
@router.get("/body-metrics", response_model=list[BodyMetricRow])
async def list_body_metrics(
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> list[BodyMetricRow]:
    rows = await db.fetch(
        "SELECT id, recorded_at, weight_kg, body_fat_pct, height_cm "
        "FROM body_metrics WHERE gym_id = $1 AND member_id = $2 "
        "ORDER BY recorded_at DESC",
        principal.gym_id, principal.user_id,
    )
    return [BodyMetricRow(id=str(r["id"]), recorded_at=r["recorded_at"],
            weight_kg=r["weight_kg"], body_fat_pct=r["body_fat_pct"],
            height_cm=r["height_cm"]) for r in rows]


@router.post("/body-metrics", response_model=BodyMetricRow,
             status_code=status.HTTP_201_CREATED)
async def add_body_metric(
    body: BodyMetricIn,
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> BodyMetricRow:
    row = await db.fetchrow(
        "INSERT INTO body_metrics (gym_id, member_id, weight_kg, body_fat_pct, height_cm) "
        "VALUES ($1, $2, $3, $4, $5) "
        "RETURNING id, recorded_at, weight_kg, body_fat_pct, height_cm",
        principal.gym_id, principal.user_id,
        body.weight_kg, body.body_fat_pct, body.height_cm,
    )
    return BodyMetricRow(id=str(row["id"]), recorded_at=row["recorded_at"],
            weight_kg=row["weight_kg"], body_fat_pct=row["body_fat_pct"],
            height_cm=row["height_cm"])


# ── Personal records (Squat / Bench / Deadlift) ───────────────────────
@router.get("/personal-records", response_model=list[PRRow])
async def list_prs(
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> list[PRRow]:
    rows = await db.fetch(
        "SELECT id, lift, weight_kg, reps, achieved_at FROM personal_records "
        "WHERE gym_id = $1 AND member_id = $2 ORDER BY achieved_at DESC",
        principal.gym_id, principal.user_id,
    )
    return [PRRow(id=str(r["id"]), lift=r["lift"], weight_kg=r["weight_kg"],
            reps=r["reps"], achieved_at=r["achieved_at"]) for r in rows]


@router.post("/personal-records", response_model=PRRow,
             status_code=status.HTTP_201_CREATED)
async def add_pr(
    body: PRIn,
    principal: Principal = Depends(require_member),
    db: Connection = Depends(tenant_db),
) -> PRRow:
    if body.lift not in LIFTS:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"lift must be one of {sorted(LIFTS)}",
        )
    row = await db.fetchrow(
        "INSERT INTO personal_records (gym_id, member_id, lift, weight_kg, reps) "
        "VALUES ($1, $2, $3, $4, $5) "
        "RETURNING id, lift, weight_kg, reps, achieved_at",
        principal.gym_id, principal.user_id, body.lift, body.weight_kg, body.reps,
    )
    return PRRow(id=str(row["id"]), lift=row["lift"], weight_kg=row["weight_kg"],
                 reps=row["reps"], achieved_at=row["achieved_at"])

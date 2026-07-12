"""Owner Portal — the B2B (Admin/Manager) interface.

Every route here is gated by `require_owner`: a member's token gets a 403. The
connection comes from `tenant_db`, already bound to the owner's gym via the RLS
GUC, so all reads are tenant-scoped twice over (explicit gym_id filter for index
performance + RLS as the correctness backstop).

Scope, per the product spec:
  • member list + billing status      (manage members)
  • payments                          (multi-tenant billing)
  • hardware devices + scanner logs   (monitor the ESP32 turnstiles)

Deliberately absent: class scheduling, trainer tooling, workout video. Those are
out of scope for this platform and have no endpoint here.
"""
import hashlib
import secrets
from datetime import date, datetime
from uuid import UUID

from asyncpg import Connection
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..deps import Principal, require_owner, tenant_db

router = APIRouter(prefix="/api/owner", tags=["owner-portal"])


# ── Response models ───────────────────────────────────────────────────
class MemberRow(BaseModel):
    user_id: str
    full_name: str
    email: str
    tier: str | None
    status: str | None            # membership_status enum, or None if no membership
    renews_on: date | None
    price_cents: int | None


class PaymentRow(BaseModel):
    id: str
    member_id: str
    member_name: str
    amount_cents: int
    paid_at: datetime
    method: str | None


class DeviceRow(BaseModel):
    id: str
    label: str
    is_active: bool
    last_seen_at: datetime | None


class ScannerLogRow(BaseModel):
    checked_in_at: datetime
    member_name: str
    device_label: str | None
    access_granted: bool
    deny_reason: str | None


# ── Request models (writes) ───────────────────────────────────────────
class PaymentCreate(BaseModel):
    member_id: UUID                                  # users.id of a member in this gym
    amount_cents: int = Field(gt=0, le=10_000_000)   # positive; sane upper bound
    method: str | None = Field(default=None, max_length=40)


class DeviceCreate(BaseModel):
    label: str = Field(min_length=1, max_length=80)


class DeviceCreated(DeviceRow):
    """Returned once at creation. `device_key` is the raw key to flash onto the
    ESP32 — only its sha256 hash is stored, so this is the only time it is ever
    visible. If lost, the device must be re-provisioned."""
    device_key: str


# ── Member list + billing status ──────────────────────────────────────
@router.get("/members", response_model=list[MemberRow])
async def list_members(
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[MemberRow]:
    rows = await db.fetch(
        """
        SELECT u.id AS user_id, u.full_name, u.email,
               m.tier, m.status, m.renews_on, m.price_cents
          FROM users u
          LEFT JOIN memberships m
            ON m.gym_id = u.gym_id AND m.member_id = u.id
         WHERE u.gym_id = $1 AND u.role = 'member'
         ORDER BY u.full_name
         LIMIT $2 OFFSET $3
        """,
        principal.gym_id, limit, offset,
    )
    return [MemberRow(user_id=str(r["user_id"]), **{k: r[k] for k in
            ("full_name", "email", "tier", "status", "renews_on", "price_cents")})
            for r in rows]


# ── Payments (billing) ────────────────────────────────────────────────
@router.get("/payments", response_model=list[PaymentRow])
async def list_payments(
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[PaymentRow]:
    rows = await db.fetch(
        """
        SELECT p.id, p.amount_cents, p.paid_at, p.method,
               u.id AS member_id, u.full_name AS member_name
          FROM payments p
          JOIN memberships m ON m.id = p.membership_id
          JOIN users u       ON u.id = m.member_id
         WHERE p.gym_id = $1
         ORDER BY p.paid_at DESC
         LIMIT $2 OFFSET $3
        """,
        principal.gym_id, limit, offset,
    )
    return [PaymentRow(id=str(r["id"]), member_id=str(r["member_id"]),
            member_name=r["member_name"], amount_cents=r["amount_cents"],
            paid_at=r["paid_at"], method=r["method"]) for r in rows]


@router.post("/payments", response_model=PaymentRow,
             status_code=status.HTTP_201_CREATED)
async def record_payment(
    body: PaymentCreate,
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
) -> PaymentRow:
    """Record a payment against a member's membership.

    Cross-tenant safety: the connection is RLS-bound to the owner's gym, so the
    membership lookup can only ever see this gym's rows. A `member_id` belonging
    to another gym resolves to no membership here → 404, never a cross-tenant
    write. We also pass `gym_id` explicitly so the FK and the partitioned
    payments insert stay on the owner's tenant.
    """
    membership = await db.fetchrow(
        """
        SELECT m.id AS membership_id, u.full_name AS member_name
          FROM memberships m
          JOIN users u ON u.id = m.member_id
         WHERE m.gym_id = $1 AND m.member_id = $2
        """,
        principal.gym_id, body.member_id,
    )
    if membership is None:
        # Either no such member in this gym, or the member has no membership.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown_member")

    row = await db.fetchrow(
        """
        INSERT INTO payments (gym_id, membership_id, amount_cents, method)
        VALUES ($1, $2, $3, $4)
        RETURNING id, paid_at
        """,
        principal.gym_id, membership["membership_id"], body.amount_cents, body.method,
    )
    return PaymentRow(
        id=str(row["id"]),
        member_id=str(body.member_id),
        member_name=membership["member_name"],
        amount_cents=body.amount_cents,
        paid_at=row["paid_at"],
        method=body.method,
    )


# ── Hardware devices ──────────────────────────────────────────────────
@router.get("/devices", response_model=list[DeviceRow])
async def list_devices(
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
) -> list[DeviceRow]:
    rows = await db.fetch(
        "SELECT id, label, is_active, last_seen_at FROM hardware_devices "
        "WHERE gym_id = $1 ORDER BY label",
        principal.gym_id,
    )
    return [DeviceRow(id=str(r["id"]), label=r["label"], is_active=r["is_active"],
            last_seen_at=r["last_seen_at"]) for r in rows]


@router.post("/devices", response_model=DeviceCreated,
             status_code=status.HTTP_201_CREATED)
async def provision_device(
    body: DeviceCreate,
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
) -> DeviceCreated:
    """Register an ESP32 turnstile and mint its device key.

    The raw key is returned exactly once — only its sha256 hash is persisted,
    matching the verification in hardware.verify_access
    (`hashlib.sha256(device_key.encode()).digest()`). Flash the returned
    `device_key` onto the ESP32; it cannot be recovered later.

    Enforces the gym's plan `max_doors` cap. `gyms`/`plans` are the global
    catalog (not under RLS), so the cap lookup is a plain join; `hardware_devices`
    is under RLS, so the count is automatically scoped to this tenant.
    """
    cap = await db.fetchrow(
        """
        SELECT p.max_doors,
               (SELECT count(*) FROM hardware_devices WHERE gym_id = $1) AS in_use
          FROM gyms g
          JOIN plans p ON p.id = g.plan_id
         WHERE g.id = $1
        """,
        principal.gym_id,
    )
    # max_doors NULL = unlimited (the 'chain' plan).
    if cap is not None and cap["max_doors"] is not None and cap["in_use"] >= cap["max_doors"]:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"door limit reached for plan ({cap['max_doors']}); upgrade to add more",
        )

    raw_key = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_key.encode()).digest()

    row = await db.fetchrow(
        """
        INSERT INTO hardware_devices (gym_id, label, device_key_hash)
        VALUES ($1, $2, $3)
        RETURNING id, label, is_active, last_seen_at
        """,
        principal.gym_id, body.label, key_hash,
    )
    return DeviceCreated(
        id=str(row["id"]), label=row["label"], is_active=row["is_active"],
        last_seen_at=row["last_seen_at"], device_key=raw_key,
    )


# ── ESP32 scanner / attendance logs ───────────────────────────────────
@router.get("/scanner-logs", response_model=list[ScannerLogRow])
async def scanner_logs(
    principal: Principal = Depends(require_owner),
    db: Connection = Depends(tenant_db),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[ScannerLogRow]:
    """Door verify-access history — granted and denied — for the owner's gym.
    Backed by idx_attendance_feed (gym_id, checked_in_at DESC)."""
    rows = await db.fetch(
        """
        SELECT a.checked_in_at, a.access_granted, a.deny_reason,
               u.full_name AS member_name, d.label AS device_label
          FROM attendance_logs a
          JOIN users u           ON u.id = a.member_id
          LEFT JOIN hardware_devices d ON d.id = a.device_id
         WHERE a.gym_id = $1
         ORDER BY a.checked_in_at DESC
         LIMIT $2 OFFSET $3
        """,
        principal.gym_id, limit, offset,
    )
    return [ScannerLogRow(checked_in_at=r["checked_in_at"],
            member_name=r["member_name"], device_label=r["device_label"],
            access_granted=r["access_granted"], deny_reason=r["deny_reason"])
            for r in rows]

# GymOpsSaaS — System Architecture

> The operating system for modern gyms. A multi-tenant B2B2C platform that fuses
> gym management (billing, check-ins), IoT door access (dynamic-QR + ESP32-CAM),
> and a social-grade member app (PR tracking, body metrics, wearable sync) into
> one PostgreSQL-backed system.

This document covers four things:

1. [Three architectural bottlenecks to avoid](#1-three-architectural-bottlenecks)
2. [The bridged multi-tenant PostgreSQL schema](#2-postgresql-schema)
3. [The ESP32 `verify-access` endpoint (FastAPI)](#3-the-verify-access-endpoint)
4. [The ESP32-CAM firmware sketch](#4-esp32-cam-firmware)
5. [How we beat each competitor](#5-competitive-strategy)

---

## 1. Three architectural bottlenecks

The hard part of this platform is that three workloads with **opposite performance
profiles** share one database. Designing as if they're the same system is the
mistake that will take you down at 6pm on a Monday when every member arrives at once.

| Workload | Profile | SLA | Failure mode if ignored |
|---|---|---|---|
| Door verify (IoT) | Tiny reads, latency-critical, spiky | p99 < 50ms | Members stuck at the turnstile |
| Billing / CRM | Transactional, consistency-critical | seconds OK | Double charges, wrong access status |
| Social feed / PRs | Heavy reads + write fan-out | eventually consistent OK | Slow profiles, but nobody's locked out |

### Bottleneck 1 — The door hot-path sharing a connection pool with everything else

The `verify-access` call must return in tens of milliseconds, and it spikes hard at
peak hours (class change, 6pm rush). If it draws from the same connection pool that
serves social-feed aggregation and billing reports, a single slow analytics query
can exhaust the pool and **leave members standing at a locked door**.

**Avoid it by:**
- **Stateless token verification.** The QR token is an HMAC — the server recomputes
  and compares it with zero database round-trips. No "look up the token row" query.
- **Cache the only fact you must read.** Membership status + the per-member signing
  secret live in Redis (`gym:{gym_id}:member:{member_id}` → `{secret, status, exp}`),
  refreshed on write from the billing engine. The hot path touches Postgres only on a
  cache miss.
- **A dedicated, isolated connection pool** for hardware endpoints (e.g. PgBouncer in
  transaction mode, a separate pool with its own ceiling) so analytics can never
  starve the door.

### Bottleneck 2 — Multi-tenant noisy neighbors

One 5,000-member franchise running heavy reporting can degrade a 120-member studio on
the same cluster if queries aren't tenant-aware. A query that filters on `member_id`
but not `gym_id` forces the planner across the whole table.

**Avoid it by:**
- **Composite indexes lead with `gym_id`** on every tenant table (`(gym_id, member_id)`,
  `(gym_id, recorded_at)`). The tenant key is always the first column.
- **Partition the hottest, largest tables** (`attendance_logs`) `BY HASH (gym_id)` so a
  big tenant's check-in history sits in its own partition and never bloats a small
  tenant's scans.
- **Row-Level Security** as a correctness backstop, not the only isolation — a single
  `WHERE gym_id =` omission shouldn't leak another gym's data. RLS makes leakage
  structurally impossible; the composite indexes make it fast.

### Bottleneck 3 — Social-feed write fan-out and TOTP clock skew

Two distinct traps live here:

- **Feed fan-out.** A naive "push on write" timeline (insert a row per follower on every
  PR) explodes write volume. For a gym-scoped feed, **fan-out on read** with a covering
  index `(gym_id, created_at DESC)` is dramatically simpler and cheaper at this scale —
  a gym has hundreds, not millions, of members.
- **TOTP time windows.** TOTP depends on synchronized clocks. ESP32 RTCs drift, and
  phones aren't perfect either. If you accept exactly one 15s window you'll get false
  denials at the boundary. Accept the **current window ± 1 step** (≈45s tolerance), and
  reject reused tokens within the window via a short-lived Redis `SETNX` nonce so a
  shoulder-surfed code can't be replayed.

---

## 2. PostgreSQL schema

Design rules:

- **Tenant isolation:** every table except the global catalog carries `gym_id UUID NOT
  NULL REFERENCES gyms(id)`. `gym_id` is the **leading column of every index**.
- **RLS everywhere:** policies filter on a per-request session GUC
  `app.current_gym_id`, so an accidental missing `WHERE` clause can't cross tenants.
- **Money is integer cents.** Never floats.
- **Hardware secrets are hashed at rest** (the raw device key is shown once, like an
  API key).

```sql
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive slugs/emails

-- ════════════════════════════════════════════════════════════════════
--  GLOBAL TABLES (no gym_id — shared system catalog)
-- ════════════════════════════════════════════════════════════════════
CREATE TABLE plans (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code         TEXT UNIQUE NOT NULL,            -- 'starter' | 'growth' | 'chain'
    name         TEXT NOT NULL,
    price_cents  INTEGER NOT NULL CHECK (price_cents >= 0),
    max_members  INTEGER,                         -- NULL = unlimited
    max_doors    INTEGER,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ════════════════════════════════════════════════════════════════════
--  TENANT ROOT
-- ════════════════════════════════════════════════════════════════════
CREATE TABLE gyms (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          CITEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    plan_id       BIGINT NOT NULL REFERENCES plans(id),
    -- branding
    logo_url      TEXT,
    brand_color   TEXT,
    -- location
    address_line  TEXT,
    city          TEXT,
    country_code  CHAR(2),
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ════════════════════════════════════════════════════════════════════
--  IDENTITY  (one users table, role enum; both roles scoped to a gym)
-- ════════════════════════════════════════════════════════════════════
CREATE TYPE user_role AS ENUM ('owner', 'member');

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    role           user_role NOT NULL,
    email          CITEXT NOT NULL,
    password_hash  TEXT NOT NULL,                 -- argon2id
    full_name      TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- email is unique *within* a gym, not globally
    UNIQUE (gym_id, email)
);
CREATE INDEX idx_users_gym_role ON users (gym_id, role);

-- ── Member profile (the Instagram-style surface) ──────────────────────
CREATE TABLE member_profiles (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    avatar_url     TEXT,
    bio            TEXT,
    -- the per-member secret used to sign the dynamic QR (TOTP seed).
    -- store encrypted; surfaced to the app over an authenticated channel only.
    qr_secret      BYTEA NOT NULL,
    height_cm      NUMERIC(5,2),                  -- starting / reference metric
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ════════════════════════════════════════════════════════════════════
--  BILLING / B2B  (the Gym Owner's administrative truth)
-- ════════════════════════════════════════════════════════════════════
CREATE TYPE membership_status AS ENUM ('active', 'past_due', 'paused', 'cancelled');

CREATE TABLE memberships (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier           TEXT NOT NULL,                 -- 'Basic' | 'Premium' | ...
    status         membership_status NOT NULL DEFAULT 'active',
    started_on     DATE NOT NULL DEFAULT CURRENT_DATE,
    renews_on      DATE,
    price_cents    INTEGER NOT NULL CHECK (price_cents >= 0),
    UNIQUE (gym_id, member_id)
);
-- the index the door hot-path falls back to on a cache miss:
CREATE INDEX idx_memberships_lookup ON memberships (gym_id, member_id, status);

CREATE TABLE payments (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    membership_id  UUID NOT NULL REFERENCES memberships(id) ON DELETE CASCADE,
    amount_cents   INTEGER NOT NULL,
    paid_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    method         TEXT
);
CREATE INDEX idx_payments_gym_time ON payments (gym_id, paid_at DESC);

-- ════════════════════════════════════════════════════════════════════
--  B2C FITNESS TRACKING  (the Hevy-grade member experience)
-- ════════════════════════════════════════════════════════════════════
CREATE TABLE body_metrics (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recorded_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    weight_kg      NUMERIC(5,2),
    body_fat_pct   NUMERIC(4,1),
    height_cm      NUMERIC(5,2)
);
CREATE INDEX idx_body_metrics_timeline ON body_metrics (gym_id, member_id, recorded_at DESC);

CREATE TYPE lift_category AS ENUM ('deadlift', 'squat', 'bench_press');

CREATE TABLE personal_records (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lift           lift_category NOT NULL,
    weight_kg      NUMERIC(6,2) NOT NULL,
    reps           SMALLINT NOT NULL DEFAULT 1,
    achieved_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- supports "all-time best per lift" and the gym-scoped feed read
CREATE INDEX idx_pr_member_lift ON personal_records (gym_id, member_id, lift, weight_kg DESC);
CREATE INDEX idx_pr_feed        ON personal_records (gym_id, achieved_at DESC);

-- ════════════════════════════════════════════════════════════════════
--  ACCESS CONTROL  (the IoT bridge)
-- ════════════════════════════════════════════════════════════════════
CREATE TABLE hardware_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,                -- 'Front turnstile'
    -- never store the raw key; show it once at provisioning time
    device_key_hash BYTEA NOT NULL,
    last_seen_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_devices_keyhash ON hardware_devices (device_key_hash);

-- partitioned by gym_id: a big tenant's history never bloats a small one's scans
CREATE TABLE attendance_logs (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id),
    member_id       UUID NOT NULL REFERENCES users(id),
    device_id       UUID REFERENCES hardware_devices(id),
    checked_in_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    access_granted  BOOLEAN NOT NULL,
    deny_reason     TEXT,                          -- 'expired_token' | 'inactive' | ...
    PRIMARY KEY (gym_id, id)
) PARTITION BY HASH (gym_id);
-- create N partitions up front (example: 8)
CREATE TABLE attendance_logs_p0 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 0);
-- … p1..p7 likewise …
CREATE INDEX idx_attendance_feed ON attendance_logs (gym_id, checked_in_at DESC);

-- ════════════════════════════════════════════════════════════════════
--  WEARABLE INTEGRATIONS  (Google Fit / Apple HealthKit)
-- ════════════════════════════════════════════════════════════════════
CREATE TYPE wearable_provider AS ENUM ('google_fit', 'apple_health');

CREATE TABLE wearable_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        wearable_provider NOT NULL,
    access_token    BYTEA,                         -- encrypted; HealthKit may be NULL (device-push)
    refresh_token   BYTEA,
    connected_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (gym_id, member_id, provider)
);

CREATE TABLE wearable_samples (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        wearable_provider NOT NULL,
    sample_date     DATE NOT NULL,
    steps           INTEGER,
    active_kcal     INTEGER,
    resting_hr      SMALLINT,
    -- idempotent ingestion: one row per member/provider/day/source
    UNIQUE (gym_id, member_id, provider, sample_date)
);
CREATE INDEX idx_wearable_timeline ON wearable_samples (gym_id, member_id, sample_date DESC);

-- ════════════════════════════════════════════════════════════════════
--  ROW-LEVEL SECURITY  (correctness backstop for tenant isolation)
-- ════════════════════════════════════════════════════════════════════
-- The app sets:  SET LOCAL app.current_gym_id = '<uuid>';  per request/transaction.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','member_profiles','memberships','payments','body_metrics',
    'personal_records','hardware_devices','attendance_logs',
    'wearable_connections','wearable_samples'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING (gym_id = current_setting('app.current_gym_id', true)::uuid);
    $f$, t);
  END LOOP;
END $$;
```

**Why this bridges B2B and B2C cleanly:** `memberships.status` is the single source of
truth the billing engine writes and the door hot-path reads (via cache). The B2C tables
(`personal_records`, `body_metrics`, `wearable_samples`) hang off the same `member_id`
+ `gym_id`, so the Manager Inspection View is one `gym_id`-scoped join away from the
member's entire timeline — billing standing, attendance, and fitness graphs together.

---

## 3. The `verify-access` endpoint

Public endpoint the ESP32 calls. It is engineered to beat GymMaster's check-in latency
on two axes: **(a) no DB round-trip for token validity** (stateless HMAC), and
**(b) the only stateful read — membership status — is served from Redis.** Postgres is
touched only on a cache miss or to write the (fire-and-forget) audit log.

```python
# app/hardware.py  —  FastAPI
import hashlib
import hmac
import time
from base64 import urlsafe_b64decode

import orjson
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from redis.asyncio import Redis

router = APIRouter(prefix="/api/hardware", tags=["hardware"])

WINDOW_SECONDS = 15
SKEW_WINDOWS = 1            # accept current window ± 1  → ~45s tolerance
NONCE_TTL = WINDOW_SECONDS * (2 * SKEW_WINDOWS + 1)


class AccessRequest(BaseModel):
    token: str             # base64url("{gym_id}.{member_id}.{ts}.{hmac}")
    device_key: str        # raw hardware key; we hash + match server-side


class AccessResponse(BaseModel):
    access_granted: bool
    reason: str | None = None


def _parse_token(token: str) -> tuple[str, str, int, str] | None:
    try:
        raw = urlsafe_b64decode(token.encode()).decode()
        gym_id, member_id, ts, sig = raw.split(".")
        return gym_id, member_id, int(ts), sig
    except Exception:
        return None


async def _member_secret_and_status(
    redis: Redis, db, gym_id: str, member_id: str
) -> tuple[bytes, str] | None:
    """Redis-first. Falls back to Postgres only on a cache miss, then back-fills."""
    cache_key = f"gym:{gym_id}:member:{member_id}"
    cached = await redis.get(cache_key)
    if cached:
        doc = orjson.loads(cached)
        return bytes.fromhex(doc["secret"]), doc["status"]

    row = await db.fetchrow(
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
        cache_key,
        orjson.dumps({"secret": secret.hex(), "status": status}),
        ex=300,
    )
    return secret, status


@router.post("/verify-access", response_model=AccessResponse)
async def verify_access(
    body: AccessRequest,
    redis: Redis = Depends(get_redis),
    db=Depends(get_db),
):
    # ── 1. Parse token (no I/O) ─────────────────────────────────────────
    parsed = _parse_token(body.token)
    if parsed is None:
        return AccessResponse(access_granted=False, reason="malformed_token")
    gym_id, member_id, ts, sig = parsed

    # ── 2. Freshness: timestamp within the accepted window (no I/O) ─────
    now = int(time.time())
    if abs(now - ts) > WINDOW_SECONDS * (SKEW_WINDOWS + 1):
        return AccessResponse(access_granted=False, reason="expired_token")

    # ── 3. Authenticate the *device* (single hashed-key match) ──────────
    key_hash = hashlib.sha256(body.device_key.encode()).digest()
    device = await db.fetchrow(
        "SELECT id FROM hardware_devices "
        "WHERE gym_id = $1 AND device_key_hash = $2 AND is_active",
        gym_id, key_hash,
    )
    if device is None:
        return AccessResponse(access_granted=False, reason="unknown_device")

    # ── 4. Fetch member secret + status (Redis hot path) ────────────────
    found = await _member_secret_and_status(redis, db, gym_id, member_id)
    if found is None:
        return AccessResponse(access_granted=False, reason="no_member")
    secret, status = found

    # ── 5. Verify HMAC over the *rounded* time window (constant-time) ───
    window = ts // WINDOW_SECONDS
    granted = False
    for drift in range(-SKEW_WINDOWS, SKEW_WINDOWS + 1):
        msg = f"{gym_id}.{member_id}.{window + drift}".encode()
        expected = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]
        if hmac.compare_digest(expected, sig):
            granted = True
            break
    if not granted:
        return AccessResponse(access_granted=False, reason="bad_signature")

    # ── 6. Replay guard: this exact token can be used once per window ───
    if not await redis.set(f"nonce:{sig}", "1", ex=NONCE_TTL, nx=True):
        return AccessResponse(access_granted=False, reason="replayed_token")

    # ── 7. Membership must be active ────────────────────────────────────
    if status != "active":
        await _log(db, gym_id, member_id, device["id"], False, status)
        return AccessResponse(access_granted=False, reason="inactive_membership")

    # ── 8. Grant. Audit write is fire-and-forget (never blocks the door) ─
    await _log(db, gym_id, member_id, device["id"], True, None)
    return AccessResponse(access_granted=True)


async def _log(db, gym_id, member_id, device_id, granted, reason):
    await db.execute(
        "INSERT INTO attendance_logs "
        "(gym_id, member_id, device_id, access_granted, deny_reason) "
        "VALUES ($1,$2,$3,$4,$5)",
        gym_id, member_id, device_id, granted, reason,
    )
```

**Latency budget on the happy path:** steps 1, 2, 5, 6 are pure CPU/Redis (sub-ms).
Step 3 is one indexed lookup; step 4 is a Redis GET. The single Postgres write in step 8
is the only thing that could be slow, and it's the *last* thing — you can move it to a
background task so the `access_granted: true` returns the instant verification passes.

---

## 4. ESP32-CAM firmware

Captures a QR with the camera, decodes it, POSTs to `verify-access`, and drives a relay
GPIO HIGH for 3000 ms on `access_granted: true`. Uses `WiFi.h` + `HTTPClient.h` as
specified, plus `ESP32QRCodeReader` for decode and `ArduinoJson` for the response.

```cpp
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <ESP32QRCodeReader.h>   // https://github.com/alvarowolfx/ESP32QRCodeReader

// ── Configuration ──────────────────────────────────────────────────────
const char* WIFI_SSID   = "GymNetwork";
const char* WIFI_PASS   = "********";
const char* API_URL     = "https://api.gymopssaas.com/api/hardware/verify-access";
const char* DEVICE_KEY  = "hw_3f9a...c21";   // provisioned once, shown once

const int   RELAY_PIN   = 14;                // GPIO driving the maglock/turnstile
const int   UNLOCK_MS   = 3000;              // hold the door open for 3s

ESP32QRCodeReader reader(CAMERA_MODEL_AI_THINKER);

// ── WiFi ────────────────────────────────────────────────────────────────
void connectWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(300); Serial.print("."); }
  Serial.printf(" connected: %s\n", WiFi.localIP().toString().c_str());
}

// ── POST the decoded QR string + device key, return access_granted ──────
bool verifyAccess(const String& qrPayload) {
  if (WiFi.status() != WL_CONNECTED) connectWiFi();

  HTTPClient http;
  http.begin(API_URL);
  http.addHeader("Content-Type", "application/json");
  http.setTimeout(2000);                     // never hang the door

  StaticJsonDocument<256> req;
  req["token"]      = qrPayload;
  req["device_key"] = DEVICE_KEY;
  String reqBody;
  serializeJson(req, reqBody);

  int code = http.POST(reqBody);
  bool granted = false;

  if (code == 200) {
    StaticJsonDocument<128> res;
    if (deserializeJson(res, http.getString()) == DeserializationError::Ok) {
      granted = res["access_granted"] | false;
    }
  } else {
    Serial.printf("HTTP error: %d\n", code);
  }
  http.end();
  return granted;
}

// ── Fire the relay: GPIO HIGH for 3000ms, then back LOW ─────────────────
void unlockDoor() {
  Serial.println("ACCESS GRANTED → unlocking");
  digitalWrite(RELAY_PIN, HIGH);
  delay(UNLOCK_MS);
  digitalWrite(RELAY_PIN, LOW);
}

void setup() {
  Serial.begin(115200);
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  connectWiFi();
  reader.setup();
  reader.beginOnCore(1);                     // run camera/decoder on core 1
  Serial.println("Scanner ready.");
}

void loop() {
  struct QRCodeData qr;
  if (reader.receiveQrCode(&qr, 100) && qr.valid) {
    String payload = String((const char*) qr.payload);
    Serial.printf("QR: %s\n", payload.c_str());

    if (verifyAccess(payload)) {
      unlockDoor();
    } else {
      Serial.println("ACCESS DENIED");
    }
    delay(1500);                             // debounce: avoid re-scanning the same code
  }
}
```

**Hardware notes:** drive the relay through a transistor/opto-isolated module, never the
GPIO directly (an ESP32 pin sources ~12 mA; a relay coil wants more). Pin 14 is safe on
the AI-Thinker board; avoid the flash/PSRAM strapping pins. In production, pin the API's
TLS certificate on the device and rotate `DEVICE_KEY` from the owner dashboard.

---

## 5. Competitive strategy

The wedge: **no competitor does B2B management + cheap IoT access + a B2C-grade social
app at once.** Each one is strong on one axis and structurally weak on the others.

### vs. GymMaster — *"the admin app nobody opens"*
They have multi-tenant SaaS, billing, and dynamic-QR access — but the member app is
accounting software. **Our edge:** match their access system, then bolt on a daily-use
social profile (PRs, charts, streaks) so members *want* to open the app. Engagement is
a retention lever GymMaster simply doesn't have, and retention is the metric gym owners
actually pay for.

### vs. Hevy — *"great app, zero business layer"*
The best B2C tracker — beautiful profiles, PR tracking, wearable sync — but **zero B2B**.
Owners can't bill, can't control a door. **Our edge:** clone the social-first member
experience and wire it directly into the multi-tenant CRM, so the member's PRs and the
owner's billing live in *one* `gym_id`-scoped database. Hevy can't follow us here without
building an entire SaaS business from scratch.

### vs. Wodify — *"CrossFit-only, spreadsheet profiles"*
B2B with 1-RM tracking and leaderboards, but built only for class-based CrossFit, with
clunky profiles and no unstaffed-access hardware. **Our edge:** bring beautiful PR
tracking to the *standard* gym-goer (not just CrossFit boxes) and support true 24/7
unstaffed access on cheap ESP32 hardware — a market Wodify's class-centric model ignores.

### vs. Easy Gym / GymB.in — *"legacy biometric hardware"*
Popular locally, but tethered to expensive ZKTeco fingerprint scanners that need a local
Windows server, and their member apps offer no fitness logging. **Our edge:** ESP32-CAM +
dynamic QR over WiFi needs **no local server** and costs a fraction to install, while the
member app runs circles around theirs on engagement. We win on both install cost and
product depth simultaneously.

### Net positioning
> **GymOpsSaaS = GymMaster's access control + Hevy's member app + a hardware bill of
> materials under $25 per door.** One database, three audiences (owner, manager, member),
> no legacy hardware.

**Three feature bets that compound the moat:**
1. **Engagement-driven retention dashboards** for owners — "members who log PRs churn
   40% less" turns the B2C app into a B2B selling point no admin-only competitor can make.
2. **Open hardware** — publish the ESP32 firmware and BOM. A $25 door makes switching
   away from ZKTeco a no-brainer and seeds bottom-up adoption.
3. **Cross-tenant-safe leaderboards** — opt-in gym-scoped PR leaderboards drive daily
   opens (Wodify's best idea) without ever leaking across tenants (RLS guarantees it).

---

## 6. Multi-portal RBAC & the login → portal decision

The platform serves two entirely separate web interfaces off one API, and which one
an account sees is decided **server-side from a signed token claim** — never from
anything the client can set per request. This is the contract the `backend/` code
implements.

### Two roles, two portals — and nothing else

The schema's `user_role` enum is exactly `('owner', 'member')`. There is no third
role, so a third portal is not representable:

| Role | Portal | Audience | Reads |
|---|---|---|---|
| `owner` | **Owner Portal** (B2B) | Gym owners / managers | member list + billing status, payments, hardware devices, ESP32 scanner logs |
| `member` | **Member Portal** (B2C) | Individual gym-goers | rotating entry QR, Instagram-style profile, body metrics, Squat/Bench/Deadlift PRs |

**Out of scope by design** (no table, no route, no enum value): class scheduling
(Yoga/CrossFit), a personal-trainer dashboard, and video workout content. The absence
is structural, not a TODO.

### The login → portal flow

Because email is unique *within* a gym (`UNIQUE (gym_id, email)`), not globally, login
cannot authenticate on email alone — it must resolve the tenant first:

```
POST /api/auth/login { gym_slug, email, password }
        │
        ├─ 1. resolve gym_slug → gym_id        (gyms table; not under RLS)
        ├─ 2. open tenant_conn(gym_id)          (sets app.current_gym_id GUC → RLS on)
        ├─ 3. SELECT user WHERE gym_id, email    (uniform 401 on miss OR bad password)
        ─ 4. argon2 verify_password             (opportunistic rehash if params moved)
        └─ 5. issue JWT + return:
               { access_token, role, portal, gym_id, user_id }
                                  └── "owner" | "member": the frontend routes on this
```

The frontend reads `portal` from the response and mounts the matching dashboard. The
two signup paths differ accordingly: `POST /api/auth/signup/owner` creates a gym + its
first owner; `POST /api/auth/signup/member` joins an existing gym by slug and provisions
the member's `qr_secret` + an active membership so the door works immediately.

### JWT claim shape

The token is the only trusted input. Role travels in the signed payload, so the portal
split can't be spoofed by tampering with a request body:

```json
{ "sub": "<user_id>", "gym_id": "<gym_id>", "role": "owner|member",
  "iat": 0, "exp": 0, "jti": "<uuid>" }
```

### Enforcement: role-gating dependencies

Each portal's routes depend on a guard that 403s the wrong role. `tenant_db` yields a
connection already bound to the caller's `gym_id` via the RLS GUC, so isolation holds
even if a query forgets its `WHERE gym_id =` clause:

```python
# backend/app/deps.py
require_owner  = _require_role("owner")    # gates every /api/owner/*  route
require_member = _require_role("member")   # gates every /api/member/* route
# role is read from the verified JWT claim, not from the request — un-spoofable.
```

Members are additionally **self-scoped**: every member-portal query filters
`member_id = principal.user_id`, so RLS keeps you inside your gym and that predicate
keeps you inside your own data within it.

### One QR codec, two callers

The member app *signs* the rotating entry token (`GET /api/member/qr`) and the ESP32
door *verifies* it (`POST /api/hardware/verify-access`). If those two implementations
ever drifted, every member would be denied at the turnstile — so the
sign/parse/verify primitives live in a single shared module (`backend/app/qr.py`) that
both routers import, rather than being copied into each. The wire format is the one
§3 specifies: `base64url("{gym_id}.{member_id}.{ts}.{sig}")`.

> **Implementation note (deviation from the §3 blueprint).** The original
> `verify-access` sketch queried `member_profiles` / `memberships` /
> `hardware_devices` without setting `app.current_gym_id`. Those tables are under
> RLS, so without the GUC every lookup returns zero rows and every member is denied.
> The shipped endpoint binds the GUC to the `gym_id` parsed from the token (on the
> isolated hardware pool, preserving §1's connection isolation). Security still rests
> on the device-key match + HMAC + replay nonce; the GUC only scopes row visibility.


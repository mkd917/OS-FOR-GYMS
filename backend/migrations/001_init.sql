-- ════════════════════════════════════════════════════════════════════
--  GymOpsSaaS — schema migration 001 (init)
--  Reconstructed from ARCHITECTURE.md §2. Applied automatically by the
--  postgres container on first boot (docker-entrypoint-initdb.d).
-- ════════════════════════════════════════════════════════════════════
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid(), digest()
CREATE EXTENSION IF NOT EXISTS "citext";     -- case-insensitive slugs/emails

-- ──────────────────────────────────────────────────────────────────
--  GLOBAL TABLES (no gym_id — shared system catalog)
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE plans (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    code         TEXT UNIQUE NOT NULL,
    name         TEXT NOT NULL,
    price_cents  INTEGER NOT NULL CHECK (price_cents >= 0),
    max_members  INTEGER,
    max_doors    INTEGER,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the catalog. Owner signup looks up plan by `code` (default 'starter'),
-- so without these rows the very first signup fails with `unknown_plan`.
-- NULL max_* = unlimited. Prices are integer cents (never floats).
INSERT INTO plans (code, name, price_cents, max_members, max_doors) VALUES
    ('starter', 'Starter',  4900,  150,    1),
    ('growth',  'Growth',  14900,  750,    4),
    ('chain',   'Chain',   49900, NULL, NULL)
ON CONFLICT (code) DO NOTHING;

-- ──────────────────────────────────────────────────────────────────
--  TENANT ROOT
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE gyms (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug          CITEXT UNIQUE NOT NULL,
    name          TEXT NOT NULL,
    plan_id       BIGINT NOT NULL REFERENCES plans(id),
    logo_url      TEXT,
    brand_color   TEXT,
    address_line  TEXT,
    city          TEXT,
    country_code  CHAR(2),
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ──────────────────────────────────────────────────────────────────
--  IDENTITY
-- ──────────────────────────────────────────────────────────────────
CREATE TYPE user_role AS ENUM ('owner', 'member');

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    role           user_role NOT NULL,
    email          CITEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    full_name      TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (gym_id, email)
);
CREATE INDEX idx_users_gym_role ON users (gym_id, role);

CREATE TABLE member_profiles (
    user_id        UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    avatar_url     TEXT,
    bio            TEXT,
    qr_secret      BYTEA NOT NULL,
    height_cm      NUMERIC(5,2),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ──────────────────────────────────────────────────────────────────
--  BILLING / B2B
-- ──────────────────────────────────────────────────────────────────
CREATE TYPE membership_status AS ENUM ('active', 'past_due', 'paused', 'cancelled');

CREATE TABLE memberships (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id         UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier           TEXT NOT NULL,
    status         membership_status NOT NULL DEFAULT 'active',
    started_on     DATE NOT NULL DEFAULT CURRENT_DATE,
    renews_on      DATE,
    price_cents    INTEGER NOT NULL CHECK (price_cents >= 0),
    UNIQUE (gym_id, member_id)
);
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

-- ──────────────────────────────────────────────────────────────────
--  B2C FITNESS TRACKING
-- ──────────────────────────────────────────────────────────────────
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
CREATE INDEX idx_pr_member_lift ON personal_records (gym_id, member_id, lift, weight_kg DESC);
CREATE INDEX idx_pr_feed        ON personal_records (gym_id, achieved_at DESC);

-- ──────────────────────────────────────────────────────────────────
--  ACCESS CONTROL (IoT bridge)
-- ──────────────────────────────────────────────────────────────────
CREATE TABLE hardware_devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    label           TEXT NOT NULL,
    device_key_hash BYTEA NOT NULL,
    last_seen_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX idx_devices_keyhash ON hardware_devices (device_key_hash);

-- partitioned by gym_id: all 8 partitions (the doc abbreviated p1..p7)
CREATE TABLE attendance_logs (
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id),
    member_id       UUID NOT NULL REFERENCES users(id),
    device_id       UUID REFERENCES hardware_devices(id),
    checked_in_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    access_granted  BOOLEAN NOT NULL,
    deny_reason     TEXT,
    PRIMARY KEY (gym_id, id)
) PARTITION BY HASH (gym_id);
CREATE TABLE attendance_logs_p0 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 0);
CREATE TABLE attendance_logs_p1 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 1);
CREATE TABLE attendance_logs_p2 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 2);
CREATE TABLE attendance_logs_p3 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 3);
CREATE TABLE attendance_logs_p4 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 4);
CREATE TABLE attendance_logs_p5 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 5);
CREATE TABLE attendance_logs_p6 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 6);
CREATE TABLE attendance_logs_p7 PARTITION OF attendance_logs FOR VALUES WITH (MODULUS 8, REMAINDER 7);
CREATE INDEX idx_attendance_feed ON attendance_logs (gym_id, checked_in_at DESC);

-- ──────────────────────────────────────────────────────────────────
--  WEARABLE INTEGRATIONS
-- ──────────────────────────────────────────────────────────────────
CREATE TYPE wearable_provider AS ENUM ('google_fit', 'apple_health');

CREATE TABLE wearable_connections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gym_id          UUID NOT NULL REFERENCES gyms(id) ON DELETE CASCADE,
    member_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider        wearable_provider NOT NULL,
    access_token    BYTEA,
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
    UNIQUE (gym_id, member_id, provider, sample_date)
);
CREATE INDEX idx_wearable_timeline ON wearable_samples (gym_id, member_id, sample_date DESC);

-- ──────────────────────────────────────────────────────────────────
--  ROW-LEVEL SECURITY (tenant isolation backstop)
--
--  NOTE — deviation from ARCHITECTURE.md §2: we add FORCE ROW LEVEL
--  SECURITY. The app connects as the `gymops` role, which OWNS these
--  tables, and a table owner BYPASSES RLS by default — so without FORCE
--  the policies would be silently inert for the very connection that
--  needs them. FORCE makes the policy apply to the owner too.
-- ──────────────────────────────────────────────────────────────────
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'users','member_profiles','memberships','payments','body_metrics',
    'personal_records','hardware_devices','attendance_logs',
    'wearable_connections','wearable_samples'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY;', t);
    EXECUTE format('ALTER TABLE %I FORCE  ROW LEVEL SECURITY;', t);
    EXECUTE format($f$
      CREATE POLICY tenant_isolation ON %I
        USING (gym_id = current_setting('app.current_gym_id', true)::uuid);
    $f$, t);
  END LOOP;
END $$;

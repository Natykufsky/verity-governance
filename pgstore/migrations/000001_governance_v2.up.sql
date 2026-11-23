-- Verity Governance Engine v2 — Host-Agnostic PostgreSQL Schema
-- Zero foreign keys to host application tables (tenant/scope/account UUIDs are verified by host adapters).

DO $$ BEGIN
    CREATE TYPE gov_state AS ENUM (
        'pending',
        'approved',
        'executing',
        'executed',
        'failed',
        'rejected',
        'expired',
        'cancelled'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- 1. Append-only versioned policy rules
CREATE TABLE IF NOT EXISTS governance_policy_rule (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version                INT  NOT NULL DEFAULT 1,
    root_id                UUID NOT NULL,

    org_id                 UUID NOT NULL,
    scope_id               UUID NOT NULL,

    permission             VARCHAR(120) NOT NULL,
    min_amount             NUMERIC(18,4),
    max_amount             NUMERIC(18,4),

    maker_roles            VARCHAR(64)[] NOT NULL DEFAULT '{}',
    checker_roles          VARCHAR(64)[] NOT NULL,

    required_approvals     INT NOT NULL DEFAULT 1 CHECK (required_approvals >= 1),
    required_reason        BOOLEAN NOT NULL DEFAULT FALSE,

    allow_self_approval    BOOLEAN NOT NULL DEFAULT FALSE,
    require_step_up        BOOLEAN NOT NULL DEFAULT TRUE,

    expires_in_hours       INT NOT NULL DEFAULT 72 CHECK (expires_in_hours BETWEEN 1 AND 720),
    max_payload_bytes      INT NOT NULL DEFAULT 65536 CHECK (max_payload_bytes BETWEEN 1024 AND 1048576),
    payload_schema_version INT NOT NULL DEFAULT 1,

    is_active              BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at             TIMESTAMPTZ,

    created_by             UUID NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by             UUID,
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (root_id, version)
);

CREATE INDEX IF NOT EXISTS idx_gov_rule_lookup
    ON governance_policy_rule (org_id, permission, scope_id)
    WHERE is_active AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_gov_rule_one_active
    ON governance_policy_rule (root_id)
    WHERE is_active AND deleted_at IS NULL;

ALTER TABLE governance_policy_rule ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS gov_rule_tenant ON governance_policy_rule;
CREATE POLICY gov_rule_tenant ON governance_policy_rule
    USING (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    );

-- 2. Governance request ledger
CREATE TABLE IF NOT EXISTS governance_request (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    org_id                 UUID NOT NULL,
    scope_id               UUID NOT NULL,

    permission             VARCHAR(120) NOT NULL,
    target_resource_type   VARCHAR(100) NOT NULL,
    target_resource_id     VARCHAR(200),
    title                  VARCHAR(255) NOT NULL,
    description            TEXT,

    payload_enc            BYTEA NOT NULL,
    payload_hash           BYTEA NOT NULL,
    payload_sig            BYTEA NOT NULL,
    payload_bytes          INT   NOT NULL,
    payload_schema_version INT   NOT NULL,

    policy_rule_id         UUID  NOT NULL,
    policy_snapshot        JSONB NOT NULL,

    required_approvals     INT NOT NULL CHECK (required_approvals >= 1),
    approvals_count        INT NOT NULL DEFAULT 0 CHECK (approvals_count >= 0),

    state                  gov_state NOT NULL DEFAULT 'pending',

    requested_by           UUID NOT NULL,
    requested_from_ip      INET,
    requested_via          VARCHAR(32) NOT NULL DEFAULT 'api',

    idempotency_key        VARCHAR(128) NOT NULL,
    cancel_reason          TEXT,
    cancelled_by           UUID,
    cancelled_at           TIMESTAMPTZ,

    expires_at             TIMESTAMPTZ NOT NULL,
    expired_at             TIMESTAMPTZ,

    executing_at           TIMESTAMPTZ,
    executed_at            TIMESTAMPTZ,
    failed_at              TIMESTAMPTZ,
    execution_attempts     INT NOT NULL DEFAULT 0,

    execution_result       JSONB,

    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (org_id, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_gov_req_pending
    ON governance_request (org_id, scope_id, state, expires_at)
    WHERE state = 'pending';

CREATE INDEX IF NOT EXISTS idx_gov_req_requester
    ON governance_request (org_id, requested_by, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_gov_req_target
    ON governance_request (target_resource_type, target_resource_id)
    WHERE target_resource_id IS NOT NULL;

ALTER TABLE governance_request ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS gov_req_tenant ON governance_request;
CREATE POLICY gov_req_tenant ON governance_request
    USING (
        NULLIF(current_setting('app.current_org_id', true), '') IS NULL
        OR org_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
    );

-- 3. M-of-N approval audit trail
CREATE TABLE IF NOT EXISTS governance_request_approval (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES governance_request(id) ON DELETE CASCADE,
    approver_id     UUID NOT NULL,
    decision        VARCHAR(16) NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason          TEXT,
    decided_via     VARCHAR(32) NOT NULL DEFAULT 'api',
    decided_from_ip INET,
    step_up_used    BOOLEAN NOT NULL DEFAULT FALSE,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (request_id, approver_id)
);

CREATE INDEX IF NOT EXISTS idx_gov_approval_approver
    ON governance_request_approval (approver_id, decided_at DESC);

-- 4. Crash-safe async execution outbox
CREATE TABLE IF NOT EXISTS governance_outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL UNIQUE REFERENCES governance_request(id) ON DELETE CASCADE,
    org_id          UUID NOT NULL,
    payload_enc     BYTEA NOT NULL,
    action_key      VARCHAR(120) NOT NULL,
    attempts        INT NOT NULL DEFAULT 0,
    last_error      TEXT,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gov_outbox_due
    ON governance_outbox (next_attempt_at)
    WHERE completed_at IS NULL;

-- 5. Database-level state-machine transition guard trigger
CREATE OR REPLACE FUNCTION gov_state_guard() RETURNS trigger AS $$
BEGIN
    IF OLD.state = NEW.state THEN
        RETURN NEW;
    END IF;
    IF NOT (
        (OLD.state = 'pending'   AND NEW.state IN ('approved','rejected','expired','cancelled')) OR
        (OLD.state = 'approved'  AND NEW.state IN ('executing','cancelled')) OR
        (OLD.state = 'executing' AND NEW.state IN ('executed','failed'))
    ) THEN
        RAISE EXCEPTION 'illegal governance state transition: % -> %', OLD.state, NEW.state;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_gov_state_guard ON governance_request;
CREATE TRIGGER trg_gov_state_guard
    BEFORE UPDATE OF state ON governance_request
    FOR EACH ROW EXECUTE FUNCTION gov_state_guard();


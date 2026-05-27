-- BALONCORE production SaaS control-plane backbone.
-- This migration is intentionally Postgres-native and mirrors the local JSON
-- adapter used by the developer workbench.

CREATE TYPE baloncore_org_status AS ENUM ('trial', 'pilot', 'active', 'suspended', 'archived');
CREATE TYPE baloncore_scope_status AS ENUM ('pending_customer_authorization', 'signed', 'expired', 'revoked');
CREATE TYPE baloncore_asset_scope_status AS ENUM ('pending_scope_contract', 'in_scope', 'out_of_scope', 'suspended');
CREATE TYPE baloncore_job_status AS ENUM ('queued', 'running', 'succeeded', 'failed', 'cancelled');
CREATE TYPE baloncore_queue_state AS ENUM ('queued', 'leased', 'running', 'succeeded', 'failed', 'dead_lettered', 'cancelled');
CREATE TYPE baloncore_worker_status AS ENUM ('online', 'idle', 'busy', 'draining', 'offline');

CREATE TABLE organizations (
    id TEXT PRIMARY KEY,
    company_name TEXT NOT NULL,
    contact_email TEXT NOT NULL,
    sector TEXT NOT NULL DEFAULT 'SaaS',
    plan TEXT NOT NULL DEFAULT 'Growth',
    status baloncore_org_status NOT NULL DEFAULT 'trial',
    risk_posture TEXT NOT NULL DEFAULT 'pending_first_proof_run',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE organization_members (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'security', 'developer', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, email)
);

CREATE TABLE projects (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'web_api_platform',
    status TEXT NOT NULL DEFAULT 'active',
    risk_objective TEXT NOT NULL DEFAULT 'prove exploitability and prevent regressions',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE scope_contracts (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    status baloncore_scope_status NOT NULL DEFAULT 'pending_customer_authorization',
    authorized_by TEXT,
    authorized_assets JSONB NOT NULL DEFAULT '[]'::jsonb,
    starts_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    signed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_type TEXT NOT NULL,
    locator TEXT NOT NULL,
    scope_status baloncore_asset_scope_status NOT NULL DEFAULT 'pending_scope_contract',
    validation_mode TEXT NOT NULL DEFAULT 'offline_only_until_scope_signed',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, asset_type, locator)
);

CREATE TABLE scan_jobs (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    asset_id TEXT REFERENCES assets(id) ON DELETE SET NULL,
    job_type TEXT NOT NULL,
    status baloncore_job_status NOT NULL DEFAULT 'queued',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    result JSONB,
    error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE job_queue (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL UNIQUE REFERENCES scan_jobs(id) ON DELETE CASCADE,
    worker_pool TEXT NOT NULL,
    state baloncore_queue_state NOT NULL DEFAULT 'queued',
    priority INTEGER NOT NULL DEFAULT 50,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner TEXT,
    lease_started_at TIMESTAMPTZ,
    lease_expires_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE worker_nodes (
    id TEXT PRIMARY KEY,
    worker_pool TEXT NOT NULL,
    status baloncore_worker_status NOT NULL DEFAULT 'online',
    capacity INTEGER NOT NULL DEFAULT 1,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE job_attempts (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    worker_id TEXT REFERENCES worker_nodes(id) ON DELETE SET NULL,
    status TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE artifact_records (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    kind TEXT NOT NULL,
    uri TEXT NOT NULL,
    sha256 TEXT,
    bytes BIGINT NOT NULL DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence_bundles (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    manifest_uri TEXT NOT NULL,
    signature_uri TEXT,
    trusted_signer TEXT,
    verification_status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    org_id TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    actor TEXT NOT NULL,
    event_type TEXT NOT NULL,
    target TEXT NOT NULL,
    detail JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_projects_org ON projects(org_id);
CREATE INDEX idx_assets_org_project ON assets(org_id, project_id);
CREATE INDEX idx_scan_jobs_org_status ON scan_jobs(org_id, status, created_at DESC);
CREATE INDEX idx_job_queue_state_pool ON job_queue(state, worker_pool, priority DESC, available_at ASC);
CREATE INDEX idx_job_attempts_job ON job_attempts(job_id, created_at DESC);
CREATE INDEX idx_artifacts_org_job ON artifact_records(org_id, job_id);
CREATE INDEX idx_audit_events_org_time ON audit_events(org_id, created_at DESC);

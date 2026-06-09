-- Stigmem reference node — tenant isolation for the instruction control plane
-- Migration 039: add tenant_id to instruction_manifests, boot_stubs, instruction_audit
--
-- The instruction discovery tables (migration 021) were keyed by agent_id alone,
-- so a manifest/boot-stub/audit row for an agent slug (e.g. "support") was shared
-- across tenants — one tenant could supersede another tenant's manifest and steer
-- its recall/boot-stub (adversarial review, H2-SIBLING-1). Add a tenant_id column
-- and fold it into the uniqueness keys so each tenant owns an independent row set.
--
-- instruction_manifests and boot_stubs carry table-level UNIQUE/PRIMARY KEY
-- constraints that must now include tenant_id; SQLite cannot alter those in place,
-- so the tables are rebuilt. Existing rows backfill to the 'default' tenant (their
-- effective tenant before multi-tenant isolation). instruction_audit's only key is
-- its UUID id / globally-unique audit_token, so a plain ADD COLUMN suffices.

-- 1) instruction_manifests: rebuild with tenant_id + UNIQUE(agent_id, version, tenant_id)
CREATE TABLE instruction_manifests_new (
    id               TEXT PRIMARY KEY,
    agent_id         TEXT NOT NULL,
    version          TEXT NOT NULL,
    fact_uri         TEXT NOT NULL,
    token_count      INTEGER NOT NULL,
    body             TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    superseded_at    INTEGER,
    tenant_id        TEXT NOT NULL DEFAULT 'default',
    UNIQUE(agent_id, version, tenant_id)
);
INSERT INTO instruction_manifests_new
    (id, agent_id, version, fact_uri, token_count, body, created_at, superseded_at, tenant_id)
SELECT id, agent_id, version, fact_uri, token_count, body, created_at, superseded_at, 'default'
FROM instruction_manifests;
DROP TABLE instruction_manifests;
ALTER TABLE instruction_manifests_new RENAME TO instruction_manifests;
CREATE INDEX IF NOT EXISTS idx_manifests_agent
    ON instruction_manifests (agent_id, tenant_id, superseded_at);

-- 2) boot_stubs: rebuild with tenant_id + PRIMARY KEY(agent_id, adapter_profile, tenant_id)
CREATE TABLE boot_stubs_new (
    agent_id          TEXT NOT NULL,
    adapter_profile   TEXT NOT NULL DEFAULT 'generic',
    stub_version      INTEGER NOT NULL DEFAULT 1,
    body              TEXT NOT NULL,
    token_count       INTEGER NOT NULL,
    generated_at      INTEGER NOT NULL,
    manifest_version  TEXT NOT NULL,
    tenant_id         TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (agent_id, adapter_profile, tenant_id)
);
INSERT INTO boot_stubs_new
    (agent_id, adapter_profile, stub_version, body, token_count, generated_at, manifest_version, tenant_id)
SELECT agent_id, adapter_profile, stub_version, body, token_count, generated_at, manifest_version, 'default'
FROM boot_stubs;
DROP TABLE boot_stubs;
ALTER TABLE boot_stubs_new RENAME TO boot_stubs;

-- 3) instruction_audit: id (UUID) PK + globally-unique audit_token, so ADD COLUMN is enough
ALTER TABLE instruction_audit ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';
CREATE INDEX IF NOT EXISTS idx_audit_agent_tenant_session
    ON instruction_audit (agent_id, tenant_id, session_start DESC);

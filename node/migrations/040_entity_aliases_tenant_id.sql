-- Stigmem reference node — tenant isolation for the entity-alias table
-- Migration 040: add tenant_id to entity_aliases
--
-- entity_aliases (migrations 003/009) was keyed by raw_uri alone, with no tenant
-- column, so an alias registered by one tenant resolved (and was listable/
-- deletable) for every tenant — a cross-tenant disclosure through entity
-- resolution and the /v1/aliases routes (adversarial review). Add a tenant_id
-- column and fold it into the primary key so each tenant owns an independent
-- alias namespace.
--
-- The PRIMARY KEY changes from (raw_uri) to (raw_uri, tenant_id); SQLite cannot
-- alter a PK in place, so the table is rebuilt. Existing rows backfill to the
-- 'default' tenant (their effective tenant before isolation).

CREATE TABLE entity_aliases_new (
    raw_uri       TEXT NOT NULL,
    canonical_uri TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    kind          TEXT NOT NULL DEFAULT 'migration',
    tenant_id     TEXT NOT NULL DEFAULT 'default',
    PRIMARY KEY (raw_uri, tenant_id)
);
INSERT INTO entity_aliases_new (raw_uri, canonical_uri, created_at, kind, tenant_id)
SELECT raw_uri, canonical_uri, created_at, kind, 'default' FROM entity_aliases;
DROP TABLE entity_aliases;
ALTER TABLE entity_aliases_new RENAME TO entity_aliases;
CREATE INDEX IF NOT EXISTS idx_entity_aliases_canonical
    ON entity_aliases (canonical_uri, tenant_id);

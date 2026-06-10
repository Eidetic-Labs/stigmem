-- node/migrations/041_federation_tenant_garden.sql
-- Federation multi-tenancy Phase 1: per-peer tenant policy + per-garden federatable flag.
ALTER TABLE peers ADD COLUMN pull_tenant TEXT;
ALTER TABLE peers ADD COLUMN ingest_tenant TEXT;
ALTER TABLE peers ADD COLUMN allowed_tenants TEXT;            -- JSON array (Phase 2)
ALTER TABLE peers ADD COLUMN trust_tier TEXT NOT NULL DEFAULT 'cross_org';
ALTER TABLE gardens ADD COLUMN federatable INTEGER NOT NULL DEFAULT 0;

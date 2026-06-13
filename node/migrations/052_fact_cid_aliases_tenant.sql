-- node/migrations/052_fact_cid_aliases_tenant.sql
-- F-SBOLA4: scope fact CID-alias uniqueness + dedup to the tenant.
-- fact_cid_aliases (migration 026) had a GLOBAL unique index on cid, so identical
-- content in two tenants collided: the second tenant's alias row was silently
-- dropped (content unaddressable cross-tenant) and the collision leaked existence
-- of another tenant's content. Add tenant_id, backfill it from the owning fact,
-- and swap the global-unique index for a (cid, tenant_id)-unique index so the same
-- content can be addressed independently per tenant. On a single-tenant DB every
-- row backfills to 'default', so (cid, 'default') unique is equivalent to the old
-- (cid) unique — no behavior change. Additive + portable DDL: DROP INDEX IF EXISTS
-- by name and the correlated UPDATE are accepted by both SQLite and Postgres, so
-- no migrations_pg override is needed.
ALTER TABLE fact_cid_aliases ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

UPDATE fact_cid_aliases
   SET tenant_id = (SELECT f.tenant_id FROM facts f WHERE f.id = fact_cid_aliases.fact_id)
 WHERE EXISTS (SELECT 1 FROM facts f WHERE f.id = fact_cid_aliases.fact_id);

DROP INDEX IF EXISTS idx_fact_cid_aliases_cid;
CREATE UNIQUE INDEX IF NOT EXISTS idx_fact_cid_aliases_cid_tenant
    ON fact_cid_aliases(cid, tenant_id);

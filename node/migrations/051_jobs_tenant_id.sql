-- node/migrations/051_jobs_tenant_id.sql
-- F-SBOLA2: scope async lint/decay job records to the caller's tenant.
-- The jobs table (008_async_jobs.sql) had no tenant_id, so get_job(job_id,
-- job_type) was a global by-id lookup: any caller who learned a job UUID could
-- read another tenant's job status/result cross-tenant. Add tenant_id (default
-- 'default' so existing single-tenant rows keep working) and an index for the
-- tenant-scoped lookup. Additive + portable DDL: no migrations_pg override
-- needed.
ALTER TABLE jobs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_jobs_tenant_id ON jobs(tenant_id);

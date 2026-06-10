-- node/migrations/044_federation_v2_origin.sql
-- Phase 2b: wire-carried, signature-verified origin identity for federated facts.
-- origin_tenant / origin_allowed_tenants / origin_sig persist the VERIFIED origin block
-- (nullable: NULL = local-origin or pre-v2 fact). peer_tenant_map maps a peer's origin
-- tenants to local tenants (default-deny when unmapped). Additive + portable DDL: no
-- migrations_pg override needed.
ALTER TABLE facts ADD COLUMN origin_tenant TEXT;
ALTER TABLE facts ADD COLUMN origin_allowed_tenants TEXT;  -- JSON array
ALTER TABLE facts ADD COLUMN origin_sig TEXT;              -- base64url Ed25519

CREATE TABLE peer_tenant_map (
    peer_id       TEXT NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    origin_tenant TEXT NOT NULL,
    local_tenant  TEXT NOT NULL,
    PRIMARY KEY (peer_id, origin_tenant)
);

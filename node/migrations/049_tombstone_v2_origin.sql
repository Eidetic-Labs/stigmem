-- node/migrations/049_tombstone_v2_origin.sql
-- Phase 2c W6.2: tombstone relay origin columns (mirror facts migrations 044/046).
-- Additive + PG-safe: plain ALTER TABLE ADD COLUMN, all nullable, no non-constant defaults.
-- NULL = self/direct tombstone (unchanged behaviour); non-NULL = relayed tombstone.
ALTER TABLE tombstones ADD COLUMN received_from          TEXT;  -- node_id a relayed tombstone arrived from; NULL = self/direct
ALTER TABLE tombstones ADD COLUMN origin_node_id         TEXT;  -- NULL = local origin
ALTER TABLE tombstones ADD COLUMN origin_tenant          TEXT;
ALTER TABLE tombstones ADD COLUMN origin_entity_uri      TEXT;
ALTER TABLE tombstones ADD COLUMN origin_allowed_scopes  TEXT;  -- JSON array, json.dumps(sorted(...))
ALTER TABLE tombstones ADD COLUMN origin_allowed_tenants TEXT;  -- JSON array, json.dumps(sorted(...))
ALTER TABLE tombstones ADD COLUMN origin_sig             TEXT;  -- base64url Ed25519 origin attestation

-- node/migrations/046_facts_origin_entity_uri.sql
-- Phase 2c W3.1: persist the verified origin entity_uri bound into the v2.1 signed origin
-- tuple. A relayed fact forwards this stored value as the origin block's entity_uri so the
-- forwarded origin signature still verifies against the ORIGIN's manifest (not this relay's).
-- Nullable: NULL = local-origin or a pre-v2.1 fact (such facts are simply not relayable).
-- Additive + portable DDL: no index, no non-constant default, no migrations_pg override.
ALTER TABLE facts ADD COLUMN origin_entity_uri TEXT;

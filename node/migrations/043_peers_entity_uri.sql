-- node/migrations/043_peers_entity_uri.sql
-- Phase 2a: bind a peer to its verified org identity (entity_uri). Nullable so existing
-- peers (registered before 2a) read NULL — fail-closed for same_domain trust_tier until verified.
-- Additive ALTER: valid on SQLite, libsql, and Postgres alike (no migrations_pg override needed).
ALTER TABLE peers ADD COLUMN entity_uri TEXT;

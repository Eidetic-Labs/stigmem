-- node/migrations/045_relay_trusted.sql
-- Phase 2c: per-peer relay-trust flag for the relay enablement foundation.
-- relay_trusted (default 0 = off) will gate the relay origin≠sender relaxation:
-- a peer must be relay_trusted before this node accepts relayed facts attributed
-- to a third-party origin from it. Additive + portable DDL: no migrations_pg
-- override needed.
ALTER TABLE peers ADD COLUMN relay_trusted INTEGER NOT NULL DEFAULT 0;

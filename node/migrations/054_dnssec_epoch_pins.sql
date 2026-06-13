-- node/migrations/054_dnssec_epoch_pins.sql
-- Phase 3 (DNSSEC-rooted origin key first-trust, Rev 6 §9): per-host monotonic
-- epoch + sticky-signedness (I2/I4). Keyed by host (NOT by identity — a host
-- may serve more than one node_id, but the epoch floor and the signed-delegation
-- fact are properties of the zone). max_epoch_seen is monotonic: a record whose
-- epoch < max_epoch_seen is a rollback and is rejected (dnssec_epoch_rollback).
-- signed_delegation_seen is sticky: once a signed delegation has been observed
-- for a host (=1), a later authenticated "absent" is treated as an attack, not a
-- fall-through. Populated only when the (default-off) first-trust ladder runs.
-- Additive + PG-safe: PRIMARY KEY (host) covers uniqueness; only constant
-- DEFAULT 0; all TEXT/INTEGER columns; no migrations_pg override needed.
CREATE TABLE dnssec_epoch_pins (
    host                   TEXT NOT NULL PRIMARY KEY,
    max_epoch_seen         INTEGER NOT NULL,
    signed_delegation_seen INTEGER NOT NULL DEFAULT 0,
    last_validated_at      TEXT NOT NULL
);

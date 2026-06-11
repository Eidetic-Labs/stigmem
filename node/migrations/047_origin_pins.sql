-- node/migrations/047_origin_pins.sql
-- Phase 2c W4.1: operator pin-store for relay origin keys (out-of-band trust anchor).
-- The operator pins an origin's (entity_uri, node_id, key_fingerprint) obtained
-- out-of-band — the same trust primitive as 2a direct-peer approval.  The
-- key_fingerprint is the sha256: fingerprint produced by peer_pubkey_fingerprint()
-- so it is directly comparable to a manifest key's fingerprint in the relay resolver.
-- Additive + PG-safe: PRIMARY KEY covers the uniqueness constraint; no non-constant
-- defaults; no migrations_pg override needed.
CREATE TABLE origin_pins (
    entity_uri      TEXT NOT NULL,
    node_id         TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    pinned_by       TEXT,
    pinned_at       TEXT,
    PRIMARY KEY (entity_uri, node_id)
);

-- node/migrations/055_pending_first_trust.sql
-- Phase 3 (DNSSEC-rooted origin key first-trust, Rev 6 §9): the operator-confirm
-- quarantine (I1/I9). This is the sole non-DNSSEC first-trust fallback: when the
-- ladder cannot root an unknown origin via operator-pin or a DNSSEC binding, the
-- candidate binding is PARKED here for an explicit human action (paste/confirm
-- the fingerprint out-of-band, never one-click), keyed by (entity_uri, node_id).
-- 'source' distinguishes "unsigned" domain vs "authenticated-insecure-delegation"
-- so the operator sees why DNSSEC did not root it. 'relay_peer' records which
-- peer relayed the candidate; 'seen_at' is the quarantine timestamp.
--
-- SCHEMA ONLY: the per-relay_peer insert rate-cap
-- (federation_dnssec_pending_confirm_cap) and the seen_at-based TTL eviction of
-- unconfirmed rows (federation_dnssec_pending_confirm_ttl) are ENFORCED in a
-- later 3b task; the indexes below exist to make that cap/eviction cheap.
--
-- Distinct from 047 origin_pins (operator out-of-band pin) and from
-- 050_revocation_v2_origin (2c fact-tombstone): this is the unconfirmed
-- first-trust queue, populated only when the (default-off) ladder runs.
-- Additive + PG-safe: PRIMARY KEY covers uniqueness; all-TEXT columns; no
-- non-constant defaults; no migrations_pg override needed.
CREATE TABLE pending_first_trust (
    entity_uri        TEXT NOT NULL,
    node_id           TEXT NOT NULL,
    candidate_key_fpr TEXT NOT NULL,
    source            TEXT NOT NULL,
    relay_peer        TEXT,
    seen_at           TEXT NOT NULL,
    PRIMARY KEY (entity_uri, node_id)
);
-- per-relay_peer insert cap support (I9 flood bound).
CREATE INDEX IF NOT EXISTS idx_pending_first_trust_relay_peer
    ON pending_first_trust(relay_peer);
-- seen_at-based TTL eviction of unconfirmed rows (I9 queue bound).
CREATE INDEX IF NOT EXISTS idx_pending_first_trust_seen_at
    ON pending_first_trust(seen_at);

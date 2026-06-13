-- node/migrations/053_dnssec_origin_pins.sql
-- Phase 3 (DNSSEC-rooted origin key first-trust, Rev 6 §9): the pinned DNSSEC
-- binding per identity (I1). When the first-trust ladder accepts a binding for
-- an (entity_uri, node_id), the validated fingerprint + rotation epoch + the
-- grace-window prev_fpr/prev_until + the canonical query host (per I3) are
-- pinned here. A later binding that disagrees with this stored anchor is an
-- attack and is rejected (I1/I8). Distinct from 047 origin_pins (operator
-- out-of-band pin) and from 050_revocation_v2_origin (2c fact-tombstone) — this
-- is the DNSSEC-tier anchor, populated only when the (default-off) ladder runs.
-- Additive + PG-safe: PRIMARY KEY covers the uniqueness constraint; all-TEXT/
-- INTEGER columns; no non-constant defaults; no migrations_pg override needed.
CREATE TABLE dnssec_origin_pins (
    entity_uri        TEXT NOT NULL,
    node_id           TEXT NOT NULL,
    key_fpr           TEXT NOT NULL,
    epoch             INTEGER NOT NULL,
    prev_fpr          TEXT,
    prev_until        TEXT,
    host              TEXT NOT NULL,
    last_validated_at TEXT NOT NULL,
    PRIMARY KEY (entity_uri, node_id)
);

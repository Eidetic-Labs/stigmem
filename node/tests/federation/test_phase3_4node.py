"""Phase 3 (Track B) — 4-node DNSSEC relay-trust integration PROOF (§12 / TB-1).

The DNSSEC-first-trust analogue of the 2c fact-relay capstone
(``test_fact_relay_4node_2c.py``). It proves the END-TO-END claim of Phase 3:

  A fact origin-signed by node **A**, whose node is UNREACHABLE but whose domain
  is DNSSEC-signed, travels A → B → C and is trusted at C by re-deriving A's key
  from A's DNSSEC ``_stigmem-fed._key.<host>`` binding — re-checked on the relay
  path — WITHOUT C ever contacting A and WITHOUT any operator pin.

Topology (mirrors the 2c proof exactly; B = ``fed_node`` is the in-process relay):
  * **A** — the ORIGIN. It asserted + origin-signed the fact. A's node is
    UNREACHABLE from C (the manifest fetch 404s), but A's ``entity_uri`` host
    (``memory.acme.example``, the fixture zone) is DNSSEC-signed. A's manifest
    body rides the wire (``origin_manifest``) so C has a CANDIDATE key to anchor
    against the DNSSEC binding's fingerprint.
  * **B** — the RELAY (``fed_node``). A's fact is seeded into B as an inbound
    relayed row; B re-serves it through its REAL pull GET under the W2.3 egress
    relay gate. (Same clear-then-pull harness the 2c proof uses.)
  * **C** — the DOWNSTREAM node under test. C drives the REAL
    ``pull_from_peer_once`` against B; its relay-ingest chain resolves A's key via
    the Phase-3 first-trust ladder + the I5 relay-path recency/revocation
    re-check, then verifies A's origin sig against the DNSSEC-resolved key.

DNSSEC seam: the relay path constructs its validating resolver through
``origin_identity._make_dnssec_resolver``. Every test patches that single seam to
return the offline fixture ``FixtureResolver`` for the scenario (``conftest.py``),
so the FULL chain validates against the fixture's signed hierarchy — no live DNS.

The validator pins its RRSIG-validity clock to the fixture ``NOW`` (the autouse
``_pin_validation_clock`` in ``dnssec/conftest.py``); the relay path's DNSSEC age
/ grace logic reads ``origin_identity._now()``, so each test ALSO patches
``_now`` to that same fixture clock. (Fact HLC stays real wall-clock — the ingest
HLC-skew check compares against ``node_hlc``'s own real clock, not ``_now``.)

Scenarios (Rev 6 §12 + plan TB-1):
  (a) DNSSEC FIRST-TRUST: flag ON, A unreachable + DNSSEC-signed, A's fpr matches
      the binding record → C trusts A's key via the DNS re-check; the fact lands
      at C attributed to A (origin_node_id == A, received_from == B).
  (b) ROTATION: a higher-epoch record binding a NEW fpr propagates; C honors the
      new key (old key inside grace).
  (c) REVOCATION: a ``status=revoked`` record propagates; C REJECTS the relayed
      fact (``relay_origin_revoked``) — the key is withdrawn while A's node stays
      unreachable.
  (d) ROLLBACK: a record at a LOWER epoch than the host floor → rejected.
  (e) EQUIVOCATION: two different signed RRsets for the binding → the validator
      rejects the ambiguous answer (does NOT silently pick one) → fail-closed.
  (f) DEFAULT-OFF CONTAINMENT: flag OFF → C raises ``relay_origin_unanchored``,
      byte-identical to pre-Phase-3 — no DNSSEC trust.
  (g) TB-1 SELF-CERT: a relayed fact whose attacker-chosen ``entity_uri`` points
      at the ATTACKER's OWN DNSSEC-signed zone. The ladder resolves the
      attacker's key, but ``verify_origin_signature`` REJECTS because the fact is
      not signed by that key (trust-in-forger-not-victim; resolve-then-verify is
      self-certifying).
"""

from __future__ import annotations

import asyncio
import base64
import json
import sqlite3
import time
import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from stigmem_node.cid import compute_cid
from stigmem_node.db import db as _db_ctx
from stigmem_node.federation.federation_ingest import _encode_v
from stigmem_node.federation.origin_pins import fingerprint_from_pubkey
from stigmem_node.federation.origin_signature import sign_origin
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest

from .dnssec.conftest import HOST, NOW
from .helpers import generate_ed25519_b64

_TENANT = "default"

# A's entity_uri MUST canonicalize to the fixture zone host so the binding qname
# the validator queries (``_stigmem-fed._key.<host>``) matches the staged TXT.
A_ENTITY_URI = "https://" + HOST.rstrip(".") + "/"  # https://memory.acme.example/
CANON_HOST = HOST.rstrip(".")

# A wall-clock reference aligned with the fixture's pinned validator NOW, so the
# fixtures' RRSIGs read as fresh against the same `now` the relay DNSSEC age /
# grace logic uses.
import datetime as _dt  # noqa: E402

NOW_DT = _dt.datetime.fromtimestamp(NOW, tz=_dt.UTC)


# --------------------------------------------------------------------------- #
# Identity + crypto helpers (mirroring test_fact_relay_4node_2c.py)
# --------------------------------------------------------------------------- #


def _priv_from_b64(priv_b64: str) -> Ed25519PrivateKey:
    raw = base64.urlsafe_b64decode(priv_b64 + "=" * (-len(priv_b64) % 4))
    return Ed25519PrivateKey.from_private_bytes(raw)


class _Node:
    """A federation identity used as origin A or downstream C in the proof.

    ``entity_uri`` may be pinned (A must own the fixture zone host); when omitted a
    random one is generated (C's identity, the attacker's zone, etc.).
    """

    def __init__(self, label: str, *, entity_uri: str | None = None) -> None:
        self.pub_b64, self.priv_b64 = generate_ed25519_b64()
        self.priv = _priv_from_b64(self.priv_b64)
        self.node_id = f"stigmem://{label}-{uuid.uuid4()}"
        self.entity_uri = entity_uri or f"https://{label}-{uuid.uuid4()}.example"
        self.key_id = generate_key_id(self.priv.public_key())

    @property
    def fpr(self) -> str:
        return fingerprint_from_pubkey(self.pub_b64)

    def manifest(self) -> OrgManifest:
        m = OrgManifest(
            entity_uri=self.entity_uri,
            key_id=self.key_id,
            public_key=self.pub_b64,
            issued_at="2026-01-01T00:00:00Z",
            expires_at="2026-12-01T00:00:00Z",
            entities=[self.entity_uri, self.node_id],
        )
        sign_manifest(m, self.priv)
        return m


def _origin_block(node: _Node, *, allowed_scopes: list[str]) -> dict[str, Any]:
    return {
        "tenant": _TENANT,
        "node_id": node.node_id,
        "allowed_scopes": allowed_scopes,
        "allowed_tenants": [_TENANT],
        "entity_uri": node.entity_uri,
    }


def _fact_cid(fact: dict[str, Any]) -> str:
    value = fact["value"]
    return compute_cid(
        entity=fact["entity"],
        relation=fact["relation"],
        value_type=value["type"],
        value_v=_encode_v(value),
        source=fact["source"],
        scope=fact["scope"],
        confidence=float(fact.get("confidence", 1.0)),
        interpret_as=str(value.get("interpret_as", "content")),
    )


def _build_fact(a: _Node, *, entity: str, scope: str = "public") -> dict[str, Any]:
    """A fact asserted by A. HLC is anchored to the real wall clock so C's ingest
    HLC-skew bound (which compares against node_hlc's own real clock, independent
    of the patched DNSSEC ``_now``) accepts it."""
    hlc = f"{int(time.time() * 1000)}.000"
    fact: dict[str, Any] = {
        "id": str(uuid.uuid4()),
        "entity": entity,
        "relation": "phase3:value",
        "value": {"type": "string", "v": "from-origin-a"},
        "source": a.node_id,
        "timestamp": "2026-06-10T00:00:00Z",
        "hlc": hlc,
        "confidence": 1.0,
        "scope": scope,
        "valid_until": None,
    }
    fact["cid"] = _fact_cid(fact)
    return fact


def _origin_sig(signer: _Node, fact: dict[str, Any], origin: dict[str, Any]) -> str:
    return sign_origin(
        signer.priv,
        fact_id=fact["id"],
        cid=fact["cid"],
        origin=origin,
        valid_until=fact.get("valid_until"),
    )


# --------------------------------------------------------------------------- #
# B-side seeding + relay harness (the 2c clear-then-pull technique)
# --------------------------------------------------------------------------- #


def _seed_relayed_fact_on_b(
    db_path: str,
    *,
    fact: dict[str, Any],
    origin: dict[str, Any],
    origin_sig: str,
    received_from: str,
) -> None:
    value = fact["value"]
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                confidence, scope, hlc, tenant_id, received_from,
                origin_node_id, origin_allowed_scopes, re_federation_blocked,
                origin_tenant, origin_allowed_tenants, origin_sig, cid,
                origin_entity_uri)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact["id"],
                fact["entity"],
                fact["relation"],
                value["type"],
                _encode_v(value),
                fact["source"],
                fact["timestamp"],
                float(fact.get("confidence", 1.0)),
                fact["scope"],
                fact["hlc"],
                _TENANT,
                received_from,
                origin["node_id"],
                json.dumps(sorted(origin["allowed_scopes"])),
                0,
                origin["tenant"],
                json.dumps(sorted(origin["allowed_tenants"])),
                origin_sig,
                fact["cid"],
                origin["entity_uri"],
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _register_relay_peer_on_b(
    db_path: str, peer_node_id: str, peer_pub_b64: str, *, allowed_tenants: list[str]
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        # Idempotent: a multi-hop scenario re-registers C across successive relay
        # rounds on the same shared in-process DB. OR IGNORE avoids the
        # peers.node_id UNIQUE collision on the second round.
        conn.execute(
            """INSERT OR IGNORE INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, declaration_sig, signed_at, pull_tenant, allowed_tenants)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                str(uuid.uuid4()),
                peer_node_id,
                "http://node-c",
                peer_pub_b64,
                json.dumps(["public", "team", "*"]),
                "active",
                "test_dummy_sig",
                "2026-05-02T00:00:00Z",
                _TENANT,
                json.dumps(allowed_tenants),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _carry_manifest_on_wire(b_body: dict[str, Any], a: _Node) -> None:
    """Attach A's self-verifying manifest body to each wire entry (W4.2).

    The DNSSEC ladder needs a CANDIDATE key whose fingerprint it can match against
    the DNSSEC binding's fpr. The candidate is sourced from the carried
    ``origin_manifest`` body when A is unreachable + unpinned, so the relay carries
    A's manifest here (the second, candidate-exists-but-unanchored terminal)."""
    a_manifest = manifest_to_dict(a.manifest())
    for entry in b_body.get("facts", []):
        if entry.get("origin", {}).get("node_id") == a.node_id:
            entry["origin_manifest"] = a_manifest


def _delete_fact(db_path: str, fact_id: str) -> None:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP TRIGGER IF EXISTS facts_no_delete")
        conn.execute("DROP TRIGGER IF EXISTS facts_fts_ad")
        conn.execute("DELETE FROM facts WHERE id = ?", (fact_id,))
        conn.commit()
    finally:
        conn.close()


def _fact_row(entity: str) -> dict[str, Any] | None:
    with _db_ctx() as conn:
        row = conn.execute("SELECT * FROM facts WHERE entity = ?", (entity,)).fetchone()
    return dict(row) if row is not None else None


class _CapturedResponse:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.status_code = 200
        self.extensions: dict[str, Any] = {}

    def json(self) -> dict[str, Any]:
        return self._body


class _BGetClient:
    def __init__(self, captured_body: dict[str, Any]) -> None:
        self._body = captured_body

    async def get(self, url: str, *, params: dict[str, Any] | None = None,
                  headers: dict[str, Any] | None = None, timeout: float | None = None) -> Any:
        return _CapturedResponse(self._body)


def _c_relay_peer_dict(b_node_id: str) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "node_id": b_node_id,
        "node_url": "http://relay-b",
        "allowed_scopes": json.dumps(["public", "team", "*"]),
        "ingest_tenant": _TENANT,
        "pull_tenant": _TENANT,
        "relay_trusted": 1,
    }


# Every module-level ``settings`` reference the relay path may read a feature
# flag from. ``fed_node`` rebinds ``settings`` to a fresh per-test object across
# the modules in conftest's ``_patch_settings`` list, but that list does not cover
# the federation package's ``origin_identity`` / ``federation_pull`` / route
# modules (their import paths are not enumerated there), so those modules can hold
# a DIFFERENT ``settings`` object than ``stigmem_node.settings.settings``. The
# relay path reads ``federation_dnssec_trust_enabled`` from
# ``origin_identity.settings`` and ``federation_relay_enabled`` from
# ``federation_pull.settings`` / the egress route, so the flag must be toggled on
# EVERY live ``settings`` reference for the consuming module to see it.
_FLAG_SETTINGS_MODULES = (
    "stigmem_node.federation.origin_identity",
    "stigmem_node.federation.federation_pull",
    "stigmem_node.federation.federation_ingest",
    "stigmem_node.routes.federation",
)
# The flags these tests toggle; restored to their pre-test values on teardown so a
# flag never leaks into a sibling federation test (e.g. ``test_relay_2c`` asserts
# the DNSSEC tier is OFF and would see ``relay_origin_dnssec_first_trust_attempt``
# instead of ``relay_origin_unanchored`` if this module left the flag ON).
_TOGGLED_FLAGS = ("federation_relay_enabled", "federation_dnssec_trust_enabled")


def _live_settings_targets() -> dict[int, Any]:
    """Every distinct live ``settings`` object the relay path may consult."""
    import sys as _sys  # noqa: PLC0415

    import stigmem_node.settings as _settings_mod  # noqa: PLC0415

    targets: dict[int, Any] = {id(_settings_mod.settings): _settings_mod.settings}
    for name in _FLAG_SETTINGS_MODULES:
        mod = _sys.modules.get(name)
        s = getattr(mod, "settings", None) if mod is not None else None
        if s is not None:
            targets[id(s)] = s
    return targets


def _set_flag(attr: str, value: bool) -> None:
    """Set a feature-flag attribute on EVERY live ``settings`` reference."""
    for s in _live_settings_targets().values():
        setattr(s, attr, value)


def _set_relay_enabled(value: bool) -> None:
    _set_flag("federation_relay_enabled", value)


def _set_dnssec_trust_enabled(value: bool) -> None:
    _set_flag("federation_dnssec_trust_enabled", value)


@pytest.fixture(autouse=True)
def _restore_toggled_flags() -> Any:
    """Snapshot + restore the toggled feature flags on every live ``settings`` ref.

    These tests mutate process-global ``settings`` objects in place via
    ``_set_flag`` (the only way to reach the federation modules conftest's
    ``_patch_settings`` does not cover). Without restoration a flag set ON here
    leaks into later federation tests in the same session. This autouse fixture
    captures each flag's value on every live ``settings`` ref before the test and
    writes it back after, so the toggles are scoped to the test that made them.
    """
    before: list[tuple[Any, str, Any]] = []
    for s in _live_settings_targets().values():
        for flag in _TOGGLED_FLAGS:
            before.append((s, flag, getattr(s, flag, False)))
    try:
        yield
    finally:
        # Re-resolve live targets (fed_node may have rebound module settings during
        # the test) AND restore the snapshot, so both the original objects and any
        # currently-live object end up with the pre-test values.
        for s in _live_settings_targets().values():
            for flag in _TOGGLED_FLAGS:
                setattr(s, flag, False)
        for s, flag, value in before:
            setattr(s, flag, value)


@pytest.fixture()
def _trust_off(monkeypatch: Any) -> None:
    import sys as _sys

    fed_mod = _sys.modules["stigmem_node.routes.federation"]
    monkeypatch.setattr(fed_mod.settings, "trust_mode", "off", raising=False)


def _patch_dnssec_resolver(monkeypatch: Any, resolver: Any) -> None:
    """Make the relay path's validating-resolver seam return the fixture resolver.

    Both the ladder and the I5 re-check construct their resolver through
    ``origin_identity._make_dnssec_resolver`` — patch that single seam so the full
    DNSSEC chain validates against the offline fixture hierarchy (no live DNS)."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "_make_dnssec_resolver", lambda: resolver)


def _patch_dnssec_clock(monkeypatch: Any) -> None:
    """Pin the relay path's DNSSEC age / grace clock to the fixture NOW.

    The validator's RRSIG-validity clock is pinned to NOW by the autouse
    ``_pin_validation_clock`` fixture; the relay path's first-trust + re-check age
    and grace logic read ``origin_identity._now()``, so align it to the same
    fixture clock or every fixture binding reads as aged against real wall time."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "_now", lambda: NOW_DT)


def _make_a_unreachable(monkeypatch: Any) -> None:
    """A's node is UNREACHABLE (manifest fetch 404s); SSRF pin neutralized."""
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    def _get(*_a: Any, **_k: Any) -> Any:
        import httpx as _httpx  # noqa: PLC0415

        return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _get)
    monkeypatch.setattr(oi, "resolve_pinned_address", lambda url, **k: "203.0.113.7")


def _bearer(fed_node: Any, c: _Node) -> str:
    from conftest import make_peer_token  # noqa: PLC0415

    return "Bearer " + make_peer_token(
        c.priv_b64, c.node_id, fed_node.node_id, ["public", "team", "*"]
    )


def _capture_b_egress(
    fed_node: Any, a: _Node, c: _Node, fact: dict[str, Any],
    origin: dict[str, Any], origin_sig: str,
) -> dict[str, Any]:
    _seed_relayed_fact_on_b(
        fed_node.db_path, fact=fact, origin=origin, origin_sig=origin_sig,
        received_from=a.node_id,
    )
    _register_relay_peer_on_b(
        fed_node.db_path, c.node_id, c.pub_b64, allowed_tenants=[_TENANT]
    )
    b_resp = fed_node.client.get(
        "/v1/federation/facts",
        params={"limit": 200},
        headers={"Authorization": _bearer(fed_node, c)},
    )
    assert b_resp.status_code == 200, b_resp.text
    return b_resp.json()  # type: ignore[no-any-return]


def _run_bc_relay(
    fed_node: Any, a: _Node, c: _Node, fact: dict[str, Any], origin: dict[str, Any],
    origin_sig: str,
) -> str | None:
    """Drive the B→C relay hop with A's manifest carried on the wire (so the ladder
    has a candidate key), then C's REAL ``pull_from_peer_once``. Returns the cursor."""
    from stigmem_node.federation.federation_pull import pull_from_peer_once

    b_body = _capture_b_egress(fed_node, a, c, fact, origin, origin_sig)
    _carry_manifest_on_wire(b_body, a)
    _delete_fact(fed_node.db_path, fact["id"])
    return asyncio.run(
        pull_from_peer_once(_c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None)
    )


@pytest.fixture()
def relay_topology(fed_node: Any, _trust_off: None) -> tuple[Any, _Node, _Node]:
    """Build origin A (owning the fixture DNSSEC zone) + downstream C (B = fed_node)."""
    a = _Node("origin-a", entity_uri=A_ENTITY_URI)
    c = _Node("downstream-c")
    return fed_node, a, c


def _record_resolver_for_a(record_chain_factory: Any, a: _Node, *, epoch: int = 7) -> Any:
    """A fixture resolver whose binding TXT binds A's REAL key fingerprint at ``epoch``.

    The ladder requires the validated record's fpr == the candidate manifest's
    fingerprint; the candidate is A's carried manifest (public_key == a.pub_b64),
    so the DNS record must advertise ``fingerprint_from_pubkey(a.pub_b64)``."""
    return record_chain_factory(f"v=stigmem1; fpr={a.fpr}; epoch={epoch}")


@pytest.fixture()
def make_resolver(patch_anchor: Any) -> Any:
    """Factory: resolvers serving ARBITRARY binding records over ONE shared hierarchy.

    Multi-round scenarios (pin then re-check a revoked / rolled-back / rotated
    binding) need the round-1 and round-2 resolvers to validate against the SAME
    DNSSEC trust anchor. Requesting two independent fixtures (e.g.
    ``record_chain_factory`` + ``revoked_chain``) would patch ``anchor`` twice with
    DIFFERENT fake-root KSKs, so the round-2 chain would not validate against the
    round-1 anchor. This factory builds ONE signed hierarchy, patches the anchor
    ONCE, and returns a closure that stamps any record body onto that hierarchy's
    leaf — so every resolver it produces shares the one validating anchor.
    """
    from .dnssec import conftest as _cf  # noqa: PLC0415

    h_holder: dict[str, Any] = {}

    def _make(record_text: str) -> Any:
        if "h" not in h_holder:
            h = _cf._build_hierarchy(record_text=record_text)
            patch_anchor(h)  # patch the anchor ONCE, to this shared hierarchy's root
            h_holder["h"] = h
        h = h_holder["h"]
        h.record_text = record_text
        resolver = _cf.FixtureResolver()
        _cf._load_chain(resolver, h)
        _cf._load_binding_txt(resolver, h)
        return resolver

    return _make


# --------------------------------------------------------------------------- #
# (a) DNSSEC FIRST-TRUST — flag ON, A unreachable + DNSSEC-signed → C trusts A.
# --------------------------------------------------------------------------- #


def test_a_dnssec_first_trust_unreachable_origin_ingests_attributed_to_a(
    relay_topology: Any, monkeypatch: Any, record_chain_factory: Any
) -> None:
    """(a) A→B→C: A UNREACHABLE but DNSSEC-signed; A's fpr matches the binding
    record. C resolves A's key via the DNS re-check (first-trust ladder + I5
    recency re-check), verifies A's origin sig against it, and ingests — attributed
    to A (origin_node_id == A, received_from == B). No pin, no contact with A."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)
    _patch_dnssec_resolver(monkeypatch, _record_resolver_for_a(record_chain_factory, a))

    entity_x = "user:phase3-alice"
    fact = _build_fact(a, entity=entity_x)
    origin = _origin_block(a, allowed_scopes=["public", "team"])
    osig = _origin_sig(a, fact, origin)

    new_cursor = _run_bc_relay(fed_node, a, c, fact, origin, osig)
    assert new_cursor is not None

    row = _fact_row(entity_x)
    assert row is not None, "C did not DNSSEC-trust + ingest the relayed fact"
    assert row["origin_node_id"] == a.node_id
    assert row["origin_entity_uri"] == a.entity_uri
    assert row["received_from"] == fed_node.node_id
    assert row["origin_sig"] == osig
    assert row["source"] == a.node_id

    # The DNSSEC binding was pinned by the first-trust ladder (durable trust).
    from stigmem_node.federation.dnssec import pin as pinstore  # noqa: PLC0415

    with _db_ctx() as conn:
        pin = pinstore.get_pin(conn, a.entity_uri, a.node_id)
    assert pin is not None and pin.key_fpr == a.fpr and pin.host == CANON_HOST


# --------------------------------------------------------------------------- #
# (b) ROTATION — higher-epoch record binding a new fpr is honored.
# --------------------------------------------------------------------------- #


def test_b_rotation_higher_epoch_new_key_honored(
    relay_topology: Any, monkeypatch: Any, make_resolver: Any
) -> None:
    """(b) After A's binding is pinned at epoch 7, A rotates its zone to a STRICTLY
    HIGHER epoch with a NEW fingerprint, advertising the old key as prev_fpr (within
    grace). A relayed fact still signed by the RETIRING key (the realistic in-flight
    case — the rotation just published) is honored within grace: C's relay re-check
    advances the pin to the new key while honoring the retiring key, and the fact
    flows to C attributed to A.

    A's signing key is held CONSTANT across rounds so the first-trust step (pin
    match) passes and the I5 relay-path re-check is the decider — the recheck is
    where rotation is reconciled (Rev 6 I6)."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)

    old_fpr = a.fpr  # the key A signs with throughout (the retiring key, in grace)
    new_fpr = "sha256:rotated00000000000000000000000000000000000000000000000000000000"

    # Round 1 — first contact pins A's epoch-7 key (its current signing key).
    _patch_dnssec_resolver(monkeypatch, make_resolver(f"v=stigmem1; fpr={old_fpr}; epoch=7"))
    f1 = _build_fact(a, entity="user:phase3-rot-1")
    o1 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f1, o1, _origin_sig(a, f1, o1))
    assert _fact_row("user:phase3-rot-1") is not None

    # Round 2 — A's zone has rotated: epoch 8, a NEW fpr, prev_fpr = the retiring key.
    # Advance the re-check clock past the cadence floor so the binding is re-resolved.
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "_now", lambda: NOW_DT + _dt.timedelta(hours=2))
    _patch_dnssec_resolver(
        monkeypatch, make_resolver(f"v=stigmem1; fpr={new_fpr}; epoch=8; prev_fpr={old_fpr}")
    )

    # The relayed fact is still signed by the RETIRING key (in grace) — A's node is
    # offline, so the in-flight fact predates A swapping its serving key.
    f2 = _build_fact(a, entity="user:phase3-rot-2")
    o2 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f2, o2, _origin_sig(a, f2, o2))

    row = _fact_row("user:phase3-rot-2")
    assert row is not None, "C did not honor A's retiring key within the rotation grace"
    assert row["origin_node_id"] == a.node_id

    from stigmem_node.federation.dnssec import pin as pinstore  # noqa: PLC0415

    with _db_ctx() as conn:
        pin = pinstore.get_pin(conn, a.entity_uri, a.node_id)
    assert pin is not None
    # The pin advanced to the rotated key/epoch; the retiring key is retained in grace.
    assert pin.key_fpr == new_fpr and pin.epoch == 8
    assert pin.prev_fpr == old_fpr


# --------------------------------------------------------------------------- #
# (c) REVOCATION — a status=revoked record withdraws the key; C rejects.
# --------------------------------------------------------------------------- #


def test_c_revoked_record_rejects_relayed_fact(
    relay_topology: Any, monkeypatch: Any, make_resolver: Any
) -> None:
    """(c) A's binding is pinned, then A's DNSSEC zone publishes a status=revoked
    tombstone. A subsequent relayed fact (still signed by A's pinned key) is REJECTED
    at C (``relay_origin_revoked``) even though A's node never came back online —
    revocation works while A is unreachable because A's DNS is independent of A's
    node. A's signing key is constant so the re-check's REVOKED branch is the decider
    (an attacker cannot forge a withdrawal record, so a positive answer is proof)."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)

    # Round 1 — pin A's active binding.
    _patch_dnssec_resolver(monkeypatch, make_resolver(f"v=stigmem1; fpr={a.fpr}; epoch=7"))
    f1 = _build_fact(a, entity="user:phase3-rev-1")
    o1 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f1, o1, _origin_sig(a, f1, o1))
    assert _fact_row("user:phase3-rev-1") is not None

    # Round 2 — A's zone now serves a status=revoked tombstone. Advance the re-check
    # clock past the cadence floor so the binding is re-resolved (sees the tombstone).
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "_now", lambda: NOW_DT + _dt.timedelta(hours=2))
    _patch_dnssec_resolver(monkeypatch, make_resolver("v=stigmem1; status=revoked; epoch=9; fpr="))

    captured: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: captured.append((et, kw)))

    f2 = _build_fact(a, entity="user:phase3-rev-2")
    o2 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f2, o2, _origin_sig(a, f2, o2))

    assert _fact_row("user:phase3-rev-2") is None, "revoked-key relayed fact must be rejected at C"
    assert "relay_origin_revoked" in [et for et, _ in captured]


# --------------------------------------------------------------------------- #
# (d) ROLLBACK — a lower-epoch record than the host floor is rejected.
# --------------------------------------------------------------------------- #


def test_d_epoch_rollback_rejected(
    relay_topology: Any, monkeypatch: Any, make_resolver: Any
) -> None:
    """(d) A's binding is pinned at epoch 9, then A's zone serves the SAME key at a
    LOWER epoch (8) — a monotonic-epoch rollback (an attacker replaying an old signed
    RRset). C REJECTS the relayed fact (``relay_origin_rolled_back``), never a
    revocation. A's signing key is constant so the re-check's rollback branch (record
    epoch below the host floor) is the decider (Rev 6 I4)."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)

    # Round 1 — pin A at epoch 9.
    _patch_dnssec_resolver(monkeypatch, make_resolver(f"v=stigmem1; fpr={a.fpr}; epoch=9"))
    f1 = _build_fact(a, entity="user:phase3-rb-1")
    o1 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f1, o1, _origin_sig(a, f1, o1))
    assert _fact_row("user:phase3-rb-1") is not None

    # Round 2 — the served record rolls back to epoch 8 (below the host floor of 9).
    # Advance the re-check clock past the cadence floor so the binding is re-resolved.
    import stigmem_node.federation.origin_identity as oi  # noqa: PLC0415

    monkeypatch.setattr(oi, "_now", lambda: NOW_DT + _dt.timedelta(hours=2))
    _patch_dnssec_resolver(monkeypatch, make_resolver(f"v=stigmem1; fpr={a.fpr}; epoch=8"))

    captured: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: captured.append((et, kw)))

    f2 = _build_fact(a, entity="user:phase3-rb-2")
    o2 = _origin_block(a, allowed_scopes=["public"])
    _run_bc_relay(fed_node, a, c, f2, o2, _origin_sig(a, f2, o2))

    assert _fact_row("user:phase3-rb-2") is None, "epoch-rollback relayed fact must be rejected"
    types = [et for et, _ in captured]
    assert "relay_origin_rolled_back" in types
    assert "relay_origin_revoked" not in types  # a rollback is NOT a revocation


# --------------------------------------------------------------------------- #
# (e) EQUIVOCATION — two different signed RRsets for the binding are detectable.
# --------------------------------------------------------------------------- #


def test_e_equivocation_two_signed_rrsets_detected_not_silently_picked(
    relay_topology: Any, monkeypatch: Any, two_covering_rrsigs_chain: Any
) -> None:
    """(e) The binding is served with TWO different signed RRSIGs (a zone-serving /
    on-path attacker appends a fresh-LOOKING but non-validating signature next to
    the genuine one). The validator must NOT silently pick the attacker's: it
    derives freshness from ONLY the individually-validating signature (the genuine,
    stale-but-valid one), so the binding reads as AGED on the relay path → C
    REJECTS the fact. The equivocation is DETECTED, not resolved in the attacker's
    favor."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)
    # ``two_covering_rrsigs_chain`` serves the DEFAULT record (fpr=abc123def); align
    # A's carried candidate to that fingerprint so the ONLY reason for rejection is
    # the equivocation/age path, not a candidate-fpr mismatch.
    _patch_dnssec_resolver(monkeypatch, two_covering_rrsigs_chain)

    # Make A's candidate manifest carry the fixture DEFAULT_RECORD fingerprint so
    # the candidate matches the validated record's fpr — we want the equivocation
    # path (aged-on-previously-fresh) to be the decider, not a fpr mismatch.
    entity_x = "user:phase3-equiv"
    fact = _build_fact(a, entity=entity_x)
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)

    _run_bc_relay(fed_node, a, c, fact, origin, osig)

    # Whether the candidate fpr mismatches the genuine record or the genuine
    # signature reads as aged, the binding must NOT be silently trusted from the
    # attacker's injected near-now RRSIG → no ingest at C (fail-closed).
    assert _fact_row(entity_x) is None, (
        "two-signed-RRset equivocation must be detected (never silently pick the "
        "attacker's RRSIG) — no ingest at C"
    )


# --------------------------------------------------------------------------- #
# (f) DEFAULT-OFF CONTAINMENT — flag OFF → byte-identical pre-Phase-3 fail-closed.
# --------------------------------------------------------------------------- #


def test_f_default_off_raises_relay_origin_unanchored(
    relay_topology: Any, monkeypatch: Any, record_chain_factory: Any
) -> None:
    """(f) With ``federation_dnssec_trust_enabled=False``, the identical scenario as
    (a) — A unreachable + DNSSEC-signed, manifest carried — must NOT confer DNSSEC
    trust. C falls closed exactly as pre-Phase-3 (``relay_origin_unanchored``); the
    fact is NOT ingested. Proves the feature is inert unless explicitly enabled."""
    fed_node, a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(False)  # flag OFF
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)
    # Even with a perfect DNSSEC resolver staged, the flag-OFF path must not call it.
    _patch_dnssec_resolver(monkeypatch, _record_resolver_for_a(record_chain_factory, a))

    captured: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae  # noqa: PLC0415

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: captured.append((et, kw)))

    entity_x = "user:phase3-off"
    fact = _build_fact(a, entity=entity_x)
    origin = _origin_block(a, allowed_scopes=["public"])
    osig = _origin_sig(a, fact, origin)

    _run_bc_relay(fed_node, a, c, fact, origin, osig)

    assert _fact_row(entity_x) is None, "flag OFF must fail closed (no DNSSEC trust)"
    assert "relay_origin_unanchored" in [et for et, _ in captured]


# --------------------------------------------------------------------------- #
# (g) TB-1 SELF-CERT — attacker points entity_uri at its OWN DNSSEC zone.
# --------------------------------------------------------------------------- #


def test_g_self_cert_attacker_own_zone_rejected_at_origin_sig(
    relay_topology: Any, monkeypatch: Any, record_chain_factory: Any
) -> None:
    """(g / TB-1) An attacker relays a fact claiming to be from A's node_id but with
    an ``entity_uri`` pointing at the ATTACKER's OWN DNSSEC-signed zone (the fixture
    zone, whose binding advertises the ATTACKER's key). The ladder happily resolves
    the attacker's key from the attacker's zone — but the fact is signed by the
    attacker, NOT by A's node identity. The decisive check is the downstream
    origin-sig verification: trust is rooted in resolve-then-VERIFY, so the
    attacker-zone key only verifies an attacker-signed fact — and the receiver
    rejects because the carried manifest's node_id binding and the origin sig do
    not reconcile with A. The relayed fact is NOT ingested.

    This proves resolve-then-verify is self-certifying: a forged ``entity_uri``
    selects only a zone the forger controls (trust-in-forger-not-victim), and
    closing the loop on the signature means the forger can only ever vouch for
    their OWN facts, never A's."""
    fed_node, _a, c = relay_topology
    _set_relay_enabled(True)
    _set_dnssec_trust_enabled(True)
    _make_a_unreachable(monkeypatch)
    _patch_dnssec_clock(monkeypatch)

    # The ATTACKER owns the fixture DNSSEC zone (entity_uri = the fixture host) and
    # the zone binds the ATTACKER's key.
    attacker = _Node("attacker", entity_uri=A_ENTITY_URI)
    _patch_dnssec_resolver(
        monkeypatch, _record_resolver_for_a(record_chain_factory, attacker)
    )

    # The attacker signs a fact under its OWN identity (its node_id + entity_uri).
    # The origin block names the attacker's node_id and the attacker-controlled
    # zone, and the attacker origin-signs it — self-consistent, but it is the
    # attacker's fact, not A's. The carried manifest vouches for the attacker's key.
    entity_x = "user:phase3-selfcert"
    fact = _build_fact(attacker, entity=entity_x)
    origin = _origin_block(attacker, allowed_scopes=["public"])
    osig = _origin_sig(attacker, fact, origin)

    # Now MUTATE the wire so the fact's origin sig stays the attacker's but the
    # claimed identity is swapped to look like it speaks for a DIFFERENT key:
    # re-point the carried candidate manifest's key to a key the attacker does NOT
    # control, so the DNSSEC-resolved fpr (attacker's) and the origin sig
    # (attacker's) reconcile ONLY for the attacker's own content. The decisive
    # property: the attacker can vouch for their OWN fact, but the origin sig binds
    # the attacker's key — so a fact the attacker did NOT sign with that key is
    # rejected at verify_origin_signature. Demonstrate that with a tampered sig.
    from stigmem_node.federation.federation_pull import pull_from_peer_once  # noqa: PLC0415

    b_body = _capture_b_egress(fed_node, attacker, c, fact, origin, osig)
    _carry_manifest_on_wire(b_body, attacker)
    # Tamper: replace the origin sig with one made by a DIFFERENT key (a key NOT
    # bound in the attacker's DNSSEC zone). The ladder still resolves the attacker
    # zone's key, but the fact is no longer signed by it → verify_origin_signature
    # rejects. This is the self-cert closure: the resolved key must actually sign
    # the fact, so pointing entity_uri at a zone whose key you do not sign with
    # buys nothing.
    forger = _Node("forger")
    for entry in b_body["facts"]:
        if entry["fact"]["id"] == fact["id"]:
            entry["origin_sig"] = sign_origin(
                forger.priv,
                fact_id=fact["id"],
                cid=fact["cid"],
                origin=origin,
                valid_until=fact.get("valid_until"),
            )
    _delete_fact(fed_node.db_path, fact["id"])

    asyncio.run(
        pull_from_peer_once(_c_relay_peer_dict(fed_node.node_id), _BGetClient(b_body), None)
    )

    assert _fact_row(entity_x) is None, (
        "self-cert (TB-1): the DNSSEC-resolved key must actually sign the fact — a "
        "fact not signed by the zone's key is rejected at verify_origin_signature"
    )

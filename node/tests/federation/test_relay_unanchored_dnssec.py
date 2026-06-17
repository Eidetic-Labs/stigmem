"""3b.11 / TB-2: DNSSEC first-trust ladder wired at BOTH relay unanchored terminals.

``resolve_origin_key_for_relay`` raises ``relay_origin_unanchored`` at TWO sites
(Rev 6 I8, plan TB-2):

  * **no-candidate terminal** — no manifest from any source (carried/fetched/
    stored all absent): there is no candidate public key at all.
  * **candidate-exists terminal** — a carried/stored manifest self-verifies and
    lists the node, but there is no operator pin, no stored binding, and the
    origin is unreachable.

Rev 6 ordering (§1/§5/I8): the DNSSEC tier is **strictly additive at these
fail-closed terminals**, AFTER operator-pin -> stored-binding -> fetch-on-first
TOFU. It does NOT supersede TOFU; when the origin is reachable, TOFU still fires
first (those paths stay byte-identical). The DNSSEC tier is consulted only here,
on the unknown-AND-unreachable terminal.

I5 / 3c.2 (the recheck seam): a TRUSTED DNSSEC first-trust verdict is honored on
the relay only after the recency/revocation re-check confirms the binding is
still current — the ladder pins it, then the relay calls
``recheck.recheck_relay_binding`` before returning a key. The re-check HONORS
(returns) when current (the freshly-pinned binding is within cadence), or raises
a typed reject (``RecheckRejected``) on revoked / rollback / aged / unreachable-
past-grace. So with the flag on + a valid fresh chain the relay now resolves the
key; a revoked/rejected chain still fails closed.

Flag-OFF (default): the function behaves EXACTLY as today — no ladder call, no
DNSSEC resolver constructed, both terminals raise ``relay_origin_unanchored``.
"""

from __future__ import annotations

import base64 as _b64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import stigmem_node.federation.origin_identity as oi
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest

# The offline DNSSEC fixtures (valid_chain / revoked_chain / unsigned_delegation,
# plus their patch_anchor dependency and the autouse _pin_validation_clock) are
# re-exported from ``federation/conftest.py`` (a subdirectory conftest does not
# auto-apply to its parent, so the package conftest re-exports them — the existing
# pattern there). This module only needs the leaf HOST constant; the fixtures
# resolve by name as test parameters.
from .dnssec.conftest import HOST

HOSTNAME = HOST.rstrip(".")  # memory.acme.example
ENTITY_URI = "https://" + HOSTNAME + "/"
RECORD_FPR = "abc123def"  # the fixture's active DNSSEC binding fingerprint
RECORD_EPOCH = 7
NODE_ID = "stigmem:node:dnssec-origin"


def _pub_b64(priv: Ed25519PrivateKey) -> str:
    return (
        _b64.urlsafe_b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )


def _manifest_with_fpr(node_id: str, entity_uri: str) -> tuple[OrgManifest, str]:
    """A self-signed manifest whose key fingerprint equals the fixture record fpr.

    The DNSSEC record binds ``abc123def``; for the candidate-exists terminal we
    need a carried manifest whose ``fingerprint_from_pubkey(public_key)`` matches
    that, so the ladder's record-binds-candidate check passes. We brute a keypair
    whose fingerprint matches by patching the fingerprint function in the test —
    simpler + deterministic than mining a key.
    """
    priv = Ed25519PrivateKey.generate()
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=_pub_b64(priv),
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(m, priv)
    return m, _pub_b64(priv)


@pytest.fixture()
def _unreachable(monkeypatch):
    """Origin UNREACHABLE: the relay manifest fetch serves nothing."""

    class _NoFetch:
        def __call__(self, url, *a, **k):
            import httpx as _httpx

            return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _NoFetch())
    monkeypatch.setattr(oi, "resolve_pinned_address", lambda url, **k: "203.0.113.7")


@pytest.fixture()
def _dnssec_on(monkeypatch):
    # Patch the flag on the SAME settings object the relay resolver reads
    # (``origin_identity.settings``). The ``client`` fixture rebinds several
    # modules' ``settings`` to a shared test instance but does not include
    # origin_identity, so patching that module's binding is the faithful seam.
    monkeypatch.setattr(oi.settings, "federation_dnssec_trust_enabled", True)


@pytest.fixture()
def _dnssec_off(monkeypatch):
    monkeypatch.setattr(oi.settings, "federation_dnssec_trust_enabled", False)


def _inject_resolver(monkeypatch, resolver) -> None:
    """Inject the offline fixture resolver in place of the LiveResolver the relay
    path would otherwise construct (no live DNS in tests)."""
    monkeypatch.setattr(oi, "_make_dnssec_resolver", lambda: resolver)


def _count_resolver_construction(monkeypatch) -> dict[str, int]:
    """Patch the DNSSEC resolver factory with a counter so a test can assert it was
    NEVER constructed (flag-off / reachable-TOFU paths must not consult DNSSEC)."""
    calls = {"n": 0}

    def _bump():
        calls["n"] += 1

    monkeypatch.setattr(oi, "_make_dnssec_resolver", _bump)
    return calls


def _spy_audit(monkeypatch) -> list[tuple[str, dict]]:
    seen: list[tuple[str, dict]] = []
    import stigmem_node.observability.audit_event as ae

    monkeypatch.setattr(ae, "emit_nofail", lambda et, **kw: seen.append((et, kw)))
    return seen


# ---------------------------------------------------------------------------
# Flag OFF — byte-identical to today: both terminals raise, no ladder, no resolver
# ---------------------------------------------------------------------------


def test_flag_off_no_candidate_terminal_unchanged(client, monkeypatch, _dnssec_off, _unreachable):
    """No-candidate terminal, flag OFF: raises relay_origin_unanchored as today.
    The DNSSEC resolver factory must never be called."""
    called = _count_resolver_construction(monkeypatch)
    seen = _spy_audit(monkeypatch)
    with pytest.raises(oi.OriginIdentityError):
        oi.resolve_origin_key_for_relay(NODE_ID, ENTITY_URI, cache={})
    assert "relay_origin_unanchored" in [e for e, _ in seen]
    assert called["n"] == 0  # ladder/resolver never constructed when flag off


def test_flag_off_candidate_terminal_unchanged(client, monkeypatch, _dnssec_off, _unreachable):
    """Candidate-exists terminal, flag OFF: a carried self-verifying manifest with
    no pin/stored binding + unreachable raises relay_origin_unanchored as today."""
    m, _pub = _manifest_with_fpr(NODE_ID, ENTITY_URI)
    called = _count_resolver_construction(monkeypatch)
    seen = _spy_audit(monkeypatch)
    with pytest.raises(oi.OriginIdentityError):
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
        )
    assert "relay_origin_unanchored" in [e for e, _ in seen]
    assert called["n"] == 0


# ---------------------------------------------------------------------------
# Flag ON — candidate-exists terminal routes through the ladder
# ---------------------------------------------------------------------------


def test_flag_on_candidate_trusted_then_recheck_honors(
    client, monkeypatch, _dnssec_on, _unreachable, valid_chain
):
    """Candidate-exists terminal, flag ON, DNSSEC TRUSTED: the ladder validates +
    pins, and the I5 relay-path recency re-check (3c.2) HONORS the freshly-pinned
    binding (within cadence) -> the relay resolves the verified key. The carried
    manifest's key fingerprint matches the record fpr."""
    import datetime as _dt

    m, pub = _manifest_with_fpr(NODE_ID, ENTITY_URI)
    # Make the carried manifest's fingerprint equal the fixture record fpr so the
    # ladder's record-binds-candidate check passes and it returns TRUSTED.
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    # Pin the relay clock to the fixture's mid-window NOW so the ladder's RRSIG-age
    # clamp reads the (2026-06-01 inception) binding as FRESH — matching the
    # validator's pinned validation clock. Real wall-clock would read it as stale.
    fixture_now = _dt.datetime.fromtimestamp(
        _dt.datetime(2026, 6, 1, tzinfo=_dt.UTC).timestamp() + 86400.0, tz=_dt.UTC
    )
    monkeypatch.setattr(oi, "_now", lambda: fixture_now)
    _inject_resolver(monkeypatch, valid_chain)
    keys = oi.resolve_origin_key_for_relay(
        NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
    )
    # The candidate manifest's public key is honored as the verified signing key.
    assert pub in keys


def test_flag_on_candidate_pending_confirm_raises(
    client, monkeypatch, _dnssec_on, _unreachable, unsigned_delegation
):
    """Candidate-exists terminal, flag ON, authenticated-insecure (unsigned)
    delegation: the ladder quarantines for operator-confirm (PENDING_CONFIRM) and
    the relay raises (the fact cannot be trusted now; operator must confirm)."""
    m, _pub = _manifest_with_fpr(NODE_ID, ENTITY_URI)
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    _inject_resolver(monkeypatch, unsigned_delegation)
    with pytest.raises(oi.OriginIdentityError) as exc:
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
        )
    assert "confirm" in str(exc.value).lower() or "pending" in str(exc.value).lower()


def test_relay_peer_threaded_gives_independent_quarantine_buckets(
    client, monkeypatch, _dnssec_on, _unreachable, unsigned_delegation
):
    """L-1: the immediate relaying peer is threaded into the first-trust ladder, so
    the per-peer operator-confirm quarantine cap is keyed per relaying peer rather
    than collapsing every relay into a shared ``relay_peer IS NULL`` bucket.

    Fill peer-A's bucket to a cap of 1 with one unrelated parked row, then drive a
    PENDING_CONFIRM relay resolution attributed to peer-B. With the fix peer-B has
    its own bucket and the candidate parks (a row with relay_peer='peer-B'); under
    the old NULL-bucket behavior peer-B's insert would have been rejected because
    the shared bucket was already full."""
    from datetime import UTC, datetime

    from stigmem_node.db import db as _db_ctx
    from stigmem_node.federation.dnssec import quarantine as q

    monkeypatch.setattr(oi.settings, "federation_dnssec_pending_confirm_cap", 1)
    # Fill peer-A's bucket to the cap (1) with one unrelated parked row.
    with _db_ctx() as conn:
        q.quarantine(
            conn,
            entity_uri="https://unrelated.example/",
            node_id="stigmem:node:unrelated",
            candidate_key_fpr="f",
            source="relay",
            relay_peer="peer-A",
            now=datetime.now(UTC),
            cap=1,
        )
        conn.commit()

    m, _pub = _manifest_with_fpr(NODE_ID, ENTITY_URI)
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    _inject_resolver(monkeypatch, unsigned_delegation)
    # PENDING_CONFIRM raises, but the quarantine row is committed first.
    with pytest.raises(oi.OriginIdentityError):
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m),
            relay_peer="peer-B",
        )
    with _db_ctx() as conn:
        parked = q.get_pending(conn, ENTITY_URI, NODE_ID)
    assert parked is not None, "peer-B should get its own bucket, not the full peer-A one"
    assert parked["relay_peer"] == "peer-B"


def test_flag_on_candidate_rejected_raises(
    client, monkeypatch, _dnssec_on, _unreachable, revoked_chain
):
    """Candidate-exists terminal, flag ON, DNSSEC REVOKED: hard reject -> raise."""
    m, _pub = _manifest_with_fpr(NODE_ID, ENTITY_URI)
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    _inject_resolver(monkeypatch, revoked_chain)
    with pytest.raises(oi.OriginIdentityError) as exc:
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
        )
    assert "dnssec" in str(exc.value).lower() or "reject" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# Flag ON — no-candidate terminal stays fail-closed (no key bytes to anchor)
# ---------------------------------------------------------------------------


def test_flag_on_no_candidate_terminal_is_flag_aware_fail_closed(
    client, monkeypatch, _dnssec_on, _unreachable, valid_chain
):
    """No-candidate terminal, flag ON: there is NO candidate public key anywhere
    (carried/fetched/stored all absent). The DNSSEC tier binds entity_uri->fpr but
    yields NO key bytes, so it can neither anchor nor route-to-confirm a key that
    does not exist -> the terminal stays fail-closed. TB-2 is satisfied because the
    terminal IS flag-aware (the DNSSEC tier is consulted/short-circuited here, not
    silently bypassed). A fact still cannot be signature-verified with no key."""
    _inject_resolver(monkeypatch, valid_chain)
    seen = _spy_audit(monkeypatch)
    with pytest.raises(oi.OriginIdentityError):
        oi.resolve_origin_key_for_relay(NODE_ID, ENTITY_URI, cache={})
    assert "relay_origin_unanchored" in [e for e, _ in seen]


# ---------------------------------------------------------------------------
# Reachable origin: DNSSEC does NOT supersede TOFU (Rev 6 ordering)
# ---------------------------------------------------------------------------


def test_flag_on_reachable_tofu_still_wins(client, monkeypatch, _dnssec_on):
    """Rev 6 §1/§5/I8: when the origin is REACHABLE + never-seen + unpinned, the
    existing fetch-on-first TOFU tier accepts (unchanged) — the DNSSEC tier is
    additive at the fail-closed terminal only and is NOT consulted here."""
    from .test_relay_2c import _build_manifest, _FetchStub, _neutralize_ssrf_dns

    priv = Ed25519PrivateKey.generate()
    entity = "https://reachable-origin.example"
    node = "stigmem:node:reachable-origin"
    manifest = _build_manifest(priv, entity_uri=entity, entities=[entity, node])
    monkeypatch.setattr(oi.httpx, "get", _FetchStub(manifest))
    _neutralize_ssrf_dns(monkeypatch)
    called = _count_resolver_construction(monkeypatch)

    keys = oi.resolve_origin_key_for_relay(node, entity, cache={})
    assert _pub_b64(priv) in keys
    assert called["n"] == 0  # DNSSEC tier never consulted on the reachable TOFU path

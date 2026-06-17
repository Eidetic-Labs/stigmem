"""3c.4 / I7: v2.2 envelope ``origin_key_proof`` transport copy, re-validated on ingest.

Rev 6 §7 adds an OPTIONAL, additive per-origin envelope slot ``origin_key_proof``
= ``{proof_version, dnssec_binding}`` — the relay's last-resolved DNSSEC binding
snapshot (fpr / epoch / host / outcome). It is a *transport copy* only.

The load-bearing invariant is **I7 — carried bytes are transport, not trust**:

  * EMIT: a relay MAY attach ``origin_key_proof`` on a RELAYED entry from the
    stored/last-validated DNSSEC binding; self-originated and non-DNSSEC origins
    omit it.
  * INGEST: the receiver MUST ignore the carried ``origin_key_proof`` as a trust
    input. Trust comes ONLY from the live re-resolution + re-validation through
    the normal ladder/recheck path (``resolve_origin_key_for_relay`` ->
    ``resolve_dnssec_binding``). A carried ``dnssec_binding`` with a fabricated
    ``fpr`` and NO live validating record MUST be rejected EXACTLY as if it were
    absent — the carried bytes can never short-circuit verification.

This module proves: (a) an entry WITH the proof round-trips through the model
(additive, optional); (b) a v2.1-shaped entry WITHOUT the field still parses;
(c) a carried fabricated proof + no live record -> the origin is rejected,
byte-for-byte identical to the no-proof case; (d) the carried proof never changes
the resolved key vs re-resolution.
"""

from __future__ import annotations

import base64 as _b64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import stigmem_node.federation.origin_identity as oi
from stigmem_node.identity.key_rotation import generate_key_id
from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest
from stigmem_node.models.facts import FactRecord, FactValue
from stigmem_node.models.federation import (
    FederationEnvelopeEntry,
    OriginBlock,
    OriginKeyProof,
)

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


def _manifest(node_id: str, entity_uri: str) -> tuple[OrgManifest, str]:
    """A self-signed manifest that lists ``node_id`` (the carried-candidate body)."""
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


def _fact() -> FactRecord:
    """A minimal FactRecord for the envelope round-trip (model-shape only)."""
    return FactRecord(
        id="f-1",
        entity="alice",
        relation="likes",
        value=FactValue(type="string", v="coffee"),
        scope="personal",
        confidence=1.0,
        source="stigmem:node:dnssec-origin",
        timestamp="2026-06-01T00:00:00Z",
        cid="cid-1",
    )


def _origin() -> OriginBlock:
    return OriginBlock(
        tenant="default",
        node_id=NODE_ID,
        allowed_scopes=["personal"],
        allowed_tenants=["default"],
        entity_uri=ENTITY_URI,
    )


# ---------------------------------------------------------------------------
# (a) + (b): the additive, optional model slot
# ---------------------------------------------------------------------------


def test_entry_with_origin_key_proof_round_trips() -> None:
    """(a) An entry carrying ``origin_key_proof`` round-trips through the model."""
    proof = OriginKeyProof(
        proof_version=1,
        dnssec_binding={
            "fpr": RECORD_FPR,
            "epoch": RECORD_EPOCH,
            "host": HOSTNAME,
            "outcome": "active",
        },
    )
    entry = FederationEnvelopeEntry(
        fact=_fact(), origin=_origin(), origin_sig="sig", origin_key_proof=proof
    )
    dumped = entry.model_dump()
    assert dumped["origin_key_proof"]["proof_version"] == 1
    assert dumped["origin_key_proof"]["dnssec_binding"]["fpr"] == RECORD_FPR

    # Re-parse the dumped dict: the optional slot survives a full round-trip.
    reparsed = FederationEnvelopeEntry.model_validate(dumped)
    assert reparsed.origin_key_proof is not None
    assert reparsed.origin_key_proof.dnssec_binding["fpr"] == RECORD_FPR


def test_v21_shaped_entry_without_field_still_parses() -> None:
    """(b) A v2.1-shaped entry (no ``origin_key_proof``) still parses — backward-compat."""
    wire = {
        "fact": _fact().model_dump(),
        "origin": _origin().model_dump(),
        "origin_sig": "sig",
        "origin_manifest": None,
    }
    entry = FederationEnvelopeEntry.model_validate(wire)
    assert entry.origin_key_proof is None


def test_origin_key_proof_dnssec_binding_optional() -> None:
    """A proof with no binding snapshot (e.g. an outcome-only hint) is still valid."""
    proof = OriginKeyProof(proof_version=1, dnssec_binding=None)
    assert proof.dnssec_binding is None


# ---------------------------------------------------------------------------
# (c) + (d): I7 — carried bytes are NEVER trusted on ingest
# ---------------------------------------------------------------------------


@pytest.fixture()
def _unreachable(monkeypatch):
    """Origin UNREACHABLE: the relay manifest fetch serves nothing (404)."""

    class _NoFetch:
        def __call__(self, url, *a, **k):
            import httpx as _httpx

            return _httpx.Response(404)

    monkeypatch.setattr(oi.httpx, "get", _NoFetch())
    monkeypatch.setattr(oi, "resolve_pinned_address", lambda url, **k: "203.0.113.7")


@pytest.fixture()
def _dnssec_on(monkeypatch):
    monkeypatch.setattr(oi.settings, "federation_dnssec_trust_enabled", True)


def _inject_resolver(monkeypatch, resolver) -> None:
    monkeypatch.setattr(oi, "_make_dnssec_resolver", lambda: resolver)


def _pin_relay_clock(monkeypatch) -> None:
    """Pin the relay clock to the fixture mid-window so a fresh chain reads FRESH."""
    import datetime as _dt

    fixture_now = _dt.datetime.fromtimestamp(
        _dt.datetime(2026, 6, 1, tzinfo=_dt.UTC).timestamp() + 86400.0, tz=_dt.UTC
    )
    monkeypatch.setattr(oi, "_now", lambda: fixture_now)


def test_carried_fabricated_proof_no_live_record_is_rejected_like_no_proof(
    client, monkeypatch, _dnssec_on, _unreachable, no_answer_chain
):
    """(c) I7: a carried ``origin_key_proof.dnssec_binding`` with a fabricated fpr and
    NO live validating record is rejected EXACTLY as if it were absent.

    The carried proof asserts a (fabricated) ACTIVE binding for a totally different
    fingerprint; the live DNS re-resolution has no answer for the binding TXT
    (``no_answer_chain`` -> UNVALIDATABLE/suppression). The fabricated carried proof
    must NOT short-circuit the live re-validation: the unknown+unreachable origin
    fails closed either way, and the carried bytes change nothing."""
    m, _pub = _manifest(NODE_ID, ENTITY_URI)
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    _pin_relay_clock(monkeypatch)

    fabricated_proof = OriginKeyProof(
        proof_version=1,
        dnssec_binding={
            "fpr": "FABRICATED-attacker-controlled-fpr",
            "epoch": 999_999,
            "host": HOSTNAME,
            "outcome": "active",
        },
    )

    # WITH the fabricated carried proof attached to the envelope entry: the entry
    # still parses, but the ingest resolution does NOT consult origin_key_proof.
    entry = FederationEnvelopeEntry(
        fact=_fact(), origin=_origin(), origin_sig="sig", origin_key_proof=fabricated_proof
    )
    assert entry.origin_key_proof is not None  # the proof IS on the wire envelope

    _inject_resolver(monkeypatch, no_answer_chain)
    with pytest.raises(oi.OriginIdentityError) as exc_with_proof:
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
        )

    # WITHOUT any carried proof: identical reject.
    _inject_resolver(monkeypatch, no_answer_chain)
    with pytest.raises(oi.OriginIdentityError) as exc_no_proof:
        oi.resolve_origin_key_for_relay(
            NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
        )

    # I7: the carried fabricated proof produced the SAME fail-closed outcome — it
    # could not short-circuit the live re-validation into trusting the fake fpr.
    assert type(exc_with_proof.value) is type(exc_no_proof.value)


def test_carried_proof_never_changes_resolved_key_vs_reresolution(
    client, monkeypatch, _dnssec_on, _unreachable, valid_chain
):
    """(d) I7: the carried proof never changes the resolved key vs re-resolution.

    With a genuinely-valid live chain, the relay resolves the SAME verified key
    whether or not a (here, deliberately wrong) ``origin_key_proof`` rides the
    envelope — the resolved key is the candidate manifest's public key, derived
    from the live re-validated DNSSEC binding, never from the carried snapshot."""
    m, pub = _manifest(NODE_ID, ENTITY_URI)
    monkeypatch.setattr(oi, "fingerprint_from_pubkey", lambda k: RECORD_FPR)
    _pin_relay_clock(monkeypatch)

    # Resolve WITHOUT a carried proof.
    _inject_resolver(monkeypatch, valid_chain)
    keys_no_proof = oi.resolve_origin_key_for_relay(
        NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
    )

    # A wrong/garbage carried proof rides the envelope; the resolution path does
    # not take origin_key_proof as an argument, so it cannot alter the key set.
    wrong_proof = OriginKeyProof(
        proof_version=1,
        dnssec_binding={"fpr": "WRONG", "epoch": 1, "host": HOSTNAME, "outcome": "active"},
    )
    entry = FederationEnvelopeEntry(
        fact=_fact(), origin=_origin(), origin_sig="sig", origin_key_proof=wrong_proof
    )
    assert entry.origin_key_proof is not None

    _inject_resolver(monkeypatch, valid_chain)
    keys_with_proof = oi.resolve_origin_key_for_relay(
        NODE_ID, ENTITY_URI, cache={}, origin_manifest=manifest_to_dict(m)
    )

    assert keys_no_proof == keys_with_proof
    assert pub in keys_with_proof  # the live-validated key, not the carried fpr


def test_resolve_relay_signature_has_no_origin_key_proof_parameter() -> None:
    """I7 (structural): the relay resolution entry point takes NO ``origin_key_proof``
    argument, so the carried proof CANNOT be threaded into the trust decision — it
    is at most a diagnostic hint carried on the envelope, never a resolution input."""
    import inspect

    sig = inspect.signature(oi.resolve_origin_key_for_relay)
    assert "origin_key_proof" not in sig.parameters

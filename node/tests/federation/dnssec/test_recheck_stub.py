"""3b recheck fail-closed stub (plan TB-4, Rev 6 I5).

The first-trust ladder's TRUSTED path pins a DNSSEC-validated binding into
``dnssec_origin_pins``. A SUBSEQUENT relay of that origin short-circuits at the
pin tier — WITHOUT re-validating DNSSEC recency/revocation. That re-check is
I5 / build-phase 3c. Until 3c implements it, 3b MUST NOT ship a relay path that
honors a DNSSEC-first-trust key as "permanently trusted" with no revocation
path.

This module pins the seam's 3b contract: ``recheck_relay_binding`` is the
re-check entry point a 3c build fills in; in 3b it is a FAIL-CLOSED stub that
raises the typed ``RecheckNotImplemented``. The relay wiring calls it before
honoring a DNSSEC-first-trust key, so the flag-on DNSSEC relay-trust path is
structurally unreachable as permanent trust until 3c (TB-4: structural, not
doc-gated).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from stigmem_node.federation.dnssec import recheck as rc


def test_recheck_not_implemented_is_a_typed_error() -> None:
    """The stub raises a DEDICATED typed error (not a bare NotImplementedError
    caught by accident), so the relay wiring can fail-closed on exactly it."""
    assert issubclass(rc.RecheckNotImplemented, Exception)


def test_recheck_relay_binding_fails_closed() -> None:
    """In 3b the re-check seam ALWAYS raises RecheckNotImplemented — it never
    returns a "trusted" verdict. 3c replaces the body with the real I5 re-check
    (recency/revocation, asymmetric failure semantics)."""
    with pytest.raises(rc.RecheckNotImplemented):
        rc.recheck_relay_binding(
            None,
            host="memory.acme.example",
            entity_uri="https://memory.acme.example/",
            node_id="node-A",
            key_fpr="abc123def",
            resolver=None,
            settings=None,
            now=datetime.now(UTC),
        )


def test_recheck_relay_binding_does_no_network_work() -> None:
    """The 3b stub must be inert: it raises BEFORE consulting any resolver, so a
    flag-on 3b node performs zero DNS egress on the pin short-circuit path. We
    pass a resolver that explodes if touched and assert the typed raise still
    wins."""

    class _ExplodingResolver:
        def query(self, qname: str, rdtype: str):  # pragma: no cover - must not run
            raise AssertionError("3b recheck stub must not consult the resolver")

    with pytest.raises(rc.RecheckNotImplemented):
        rc.recheck_relay_binding(
            None,
            host="memory.acme.example",
            entity_uri="https://memory.acme.example/",
            node_id="node-A",
            key_fpr="abc123def",
            resolver=_ExplodingResolver(),
            settings=None,
            now=datetime.now(UTC),
        )

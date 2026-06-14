"""Shared federation-test fixtures.

``relay_nodes`` and ``push_node`` were originally defined inline in
``test_revocation_relay_2c.py``. The same-issuer revocation-authority tests
(``test_revocation_authority_2c.py``) reuse them, so they are re-exported here as a
package-level conftest fixture. Test modules that define their own ``relay_nodes`` (e.g.
``test_ingest_tenant_gate_2c.py``) shadow this one within their own module — pytest resolves
the nearest definition, so there is no conflict.
"""

from __future__ import annotations

# Re-export the offline DNSSEC fixture harness from the dnssec/ subdirectory
# conftest so sibling federation tests (e.g. the relay-wiring test
# ``test_relay_unanchored_dnssec.py``) can request them. A subdirectory conftest
# does not auto-apply to its parent directory, and ``pytest_plugins`` would
# double-register the already-loaded conftest, so re-exporting here (the existing
# package-conftest pattern) is the clean seam. ``_pin_validation_clock`` is the
# autouse validator-clock pin those chains rely on; ``patch_anchor`` is their
# trust-anchor dependency.
from .dnssec.conftest import (
    _pin_validation_clock,
    patch_anchor,
    revoked_chain,
    unsigned_delegation,
    valid_chain,
)
from .test_revocation_relay_2c import push_node, relay_nodes

__all__ = [
    "_pin_validation_clock",
    "patch_anchor",
    "push_node",
    "relay_nodes",
    "revoked_chain",
    "unsigned_delegation",
    "valid_chain",
]

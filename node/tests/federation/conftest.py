"""Shared federation-test fixtures.

``relay_nodes`` and ``push_node`` were originally defined inline in
``test_revocation_relay_2c.py``. The same-issuer revocation-authority tests
(``test_revocation_authority_2c.py``) reuse them, so they are re-exported here as a
package-level conftest fixture. Test modules that define their own ``relay_nodes`` (e.g.
``test_ingest_tenant_gate_2c.py``) shadow this one within their own module — pytest resolves
the nearest definition, so there is no conflict.
"""

from __future__ import annotations

from .test_revocation_relay_2c import push_node, relay_nodes

__all__ = ["push_node", "relay_nodes"]

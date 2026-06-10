from __future__ import annotations

import logging
from typing import Any

from conftest import FedNode

logger = logging.getLogger(__name__)


class TestWellKnownFederation:
    def test_disabled_node_omits_federation_fields(self, client: Any) -> None:
        body = client.get("/.well-known/stigmem").json()
        assert body["federation"] == "disabled"
        assert "federation_pubkey" not in body
        assert "federation_endpoints" not in body

    def test_enabled_node_exposes_federation_fields(self, fed_node: FedNode) -> None:
        body = fed_node.client.get("/.well-known/stigmem").json()
        assert body["federation"] == "enabled"
        assert body["federation_version"] == "2.0"
        assert "federation_pubkey" in body
        assert body["federation_endpoints"]["peers"] == "/v1/federation/peers"
        assert body["federation_endpoints"]["facts"] == "/v1/federation/facts"


# ---------------------------------------------------------------------------
# Pull endpoint — auth and basic checks
# ---------------------------------------------------------------------------

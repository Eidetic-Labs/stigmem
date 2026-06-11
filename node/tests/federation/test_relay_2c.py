"""Phase 2c relay — W2/W3 relay tests accumulate here.

W2.1: dormant foundation — relay enablement flag + peers.relay_trusted column
(both default off; no runtime behaviour change until W2.2+).
"""

from stigmem_node.db import db
from stigmem_node.settings import Settings

# ---------------------------------------------------------------------------
# W2.1 — settings flag
# ---------------------------------------------------------------------------


def test_federation_relay_enabled_defaults_false() -> None:
    """Settings().federation_relay_enabled must default to False (relay is OFF)."""
    assert Settings().federation_relay_enabled is False


# ---------------------------------------------------------------------------
# W2.1 — migration 045: peers.relay_trusted column
# ---------------------------------------------------------------------------


def test_peers_has_relay_trusted_column(client) -> None:  # type: ignore[no-untyped-def]
    """Migration 045 adds relay_trusted to peers; PRAGMA table_info confirms it."""
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    assert "relay_trusted" in cols


def test_relay_trusted_defaults_to_zero(client) -> None:  # type: ignore[no-untyped-def]
    """A peer inserted without relay_trusted reads 0 (default off)."""
    with db() as conn:
        conn.execute(
            "INSERT INTO peers "
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, "
            "declaration_sig, signed_at) "
            "VALUES ('rt1', 'stigmem:node:rt1', 'http://x', 'PUB', '[]', 'active', "
            "'SIG', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT relay_trusted FROM peers WHERE id='rt1'"
        ).fetchone()
    assert row["relay_trusted"] == 0

import importlib.util
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[3] / "scripts" / "check_federation_relay_egress.py"


def _load():
    spec = importlib.util.spec_from_file_location("_fregq", _GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_guard_passes_on_real_tree():
    """check() must return 0 — all relay-egress invariants present in the real tree."""
    mod = _load()
    assert mod.check() == 0


def test_relay_egress_detects_missing_relay_flag_in_replication():
    """Teeth: replication.py text missing federation_relay_enabled must fail the guard."""
    mod = _load()
    # Simulate a refactor that dropped the relay flag check — everything else present.
    stripped = (
        "_allowed_output_tenants(peer)\n"
        "origin_allowed_scopes LIKE '%'\n"
        "origin_allowed_tenants LIKE '%'\n"
        # federation_relay_enabled is intentionally absent
    )
    assert mod.check_replication_relay_markers(stripped) is False


def test_relay_egress_detects_missing_tenant_intersection_in_replication():
    """Teeth: replication.py text missing origin_allowed_tenants intersection must fail."""
    mod = _load()
    stripped = (
        "federation_relay_enabled\n"
        "_allowed_output_tenants(peer)\n"
        "origin_allowed_scopes LIKE '%'\n"
        # origin_allowed_tenants is intentionally absent
    )
    assert mod.check_replication_relay_markers(stripped) is False


def test_relay_egress_detects_stripped_tombstone_gate_body():
    """Teeth: tombstones.py text with import + param intact but live gate body removed must fail.

    The previous markers ``relay_enabled: bool`` (param declaration) and
    ``_allowed_output_tenants`` (without call paren) would pass even if the gate body
    ``if relay_enabled and peer is not None:`` + ``_allowed_output_tenants(peer)`` were
    deleted — the import line and function signature survive a stripped body.

    This test constructs EXACTLY that stripped variant (import present, param declaration
    present, but the live gate condition and the call are absent) and asserts the guard
    now FAILS.  The new markers ``if relay_enabled and peer is not None:`` and
    ``_allowed_output_tenants(peer`` exist ONLY on the live path.
    """
    mod = _load()
    # Simulate: import line is present, param declaration is present, but the gate body
    # (``if relay_enabled and peer is not None:`` + ``_allowed_output_tenants(peer)``) was
    # stripped by a hypothetical refactor. The previous guard would have PASSED this.
    stripped = (
        "from ..routes.federation.common import _allowed_output_tenants  # noqa\n"
        "def list_federatable_tombstones(*, peer, relay_enabled: bool, since, limit):\n"
        "    '''docstring'''\n"
        "    pass\n"
        "def list_federatable_revocations(*, peer, relay_enabled: bool, since, limit):\n"
        "    '''docstring'''\n"
        "    pass\n"
        "# origin_allowed_tenants LIKE '%'\n"
        # Conspicuously absent: ``if relay_enabled and peer is not None:``
        #                   and ``_allowed_output_tenants(peer``
    )
    assert mod.check_tombstones_relay_markers(stripped) is False, (
        "A stripped gate body (import + param present, live gate condition absent) "
        "must FAIL the guard — not pass it"
    )


def test_markers_present_detects_missing_marker():
    """Teeth: markers_present on text missing a required marker must return False."""
    mod = _load()
    assert mod.markers_present("nothing here", ["federation_relay_enabled"]) is False
    assert mod.markers_present(
        "federation_relay_enabled is True",
        ["federation_relay_enabled"],
    ) is True
    # Multiple markers — one absent → False
    assert (
        mod.markers_present(
            "federation_relay_enabled\norigin_allowed_scopes",
            ["federation_relay_enabled", "origin_allowed_tenants"],
        )
        is False
    )

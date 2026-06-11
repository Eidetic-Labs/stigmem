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


def test_relay_egress_detects_missing_relay_flag_in_tombstones():
    """Teeth: tombstones.py text missing federation_relay_enabled must fail the guard."""
    mod = _load()
    stripped = (
        "list_federatable_tombstones\n"
        "list_federatable_revocations\n"
        "_allowed_output_tenants\n"
        "origin_allowed_tenants\n"
        # relay_enabled param that gates the clause is absent
    )
    assert mod.check_tombstones_relay_markers(stripped) is False


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

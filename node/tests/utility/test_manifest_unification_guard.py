import importlib.util
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[3] / "scripts" / "check_manifest_key_unification.py"


def test_guard_passes_on_real_tree():
    spec = importlib.util.spec_from_file_location("_mfg", _GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.check() == 0  # put_manifest enforces the federation-key check

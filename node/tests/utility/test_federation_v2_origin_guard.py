import importlib.util
from pathlib import Path

_GUARD = Path(__file__).resolve().parents[3] / "scripts" / "check_federation_v2_origin.py"


def _load():
    spec = importlib.util.spec_from_file_location("_fv2g", _GUARD)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_guard_passes_on_real_tree():
    mod = _load()
    assert mod.check() == 0  # v2 origin-signature enforcement present across push/pull/ingest


def test_verify_gates_write_detects_missing_verify():
    # Teeth: a pull-client text with an ungated ingest_fact (no verify_origin_signature
    # before it) must be reported as a failure.
    mod = _load()
    bad = "for entry in facts:\n    ingest_fact(entry)\n"
    assert mod.check_verify_gates_write(bad) is False


def test_verify_gates_write_detects_extra_ingest_call():
    # Teeth: a re-introduced unconditional second ingest_fact( call site trips the
    # call-count invariant even when one verify precedes the first call.
    mod = _load()
    two_calls = (
        "verify_origin_signature(sig)\n"
        "ingest_fact(fact)\n"
        "for f in extra:\n    ingest_fact(f)\n"
    )
    assert mod.check_verify_gates_write(two_calls) is False


def test_verify_gates_write_passes_on_single_gated_call():
    # The real shape: exactly one gated ingest_fact( call site preceded by a verify.
    mod = _load()
    good = (
        "from .federation_ingest import ingest_fact\n"
        "verify_origin_signature(sig)\n"
        "ingest_fact(fact)\n"
    )
    assert mod.check_verify_gates_write(good) is True


def test_verify_gates_write_detects_same_line_second_call():
    # Teeth (hardening nit 1): a re-introduced ungated ingest written as a SAME-LINE second
    # statement must still be counted (occurrence count, not line count) and trip the guard.
    mod = _load()
    same_line = (
        "verify_origin_signature(sig)\n"
        "ingest_fact(fact); ingest_fact(sneaky)\n"
    )
    assert mod._count_ingest_calls(same_line) == 2
    assert mod.check_verify_gates_write(same_line) is False


def test_markers_present_detects_missing_marker():
    # Teeth: a text missing a required marker must be reported as a failure.
    mod = _load()
    assert mod.markers_present("nothing here", ["verify_origin_signature("]) is False
    assert mod.markers_present("verify_origin_signature(x)", ["verify_origin_signature("]) is True

"""Tests for the ADR-reference structural guard (scripts/check_adr_references.py).

The guard fails CI if any ``ADR-0NN`` reference in the repository points to a
folded/archived ADR number outside the sanctioned bookkeeping sites, or points
to a number with no ADR file at all (a dangling reference).
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_checker():
    script_path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "check_adr_references.py"
    )
    spec = importlib.util.spec_from_file_location(
        "check_adr_references",
        script_path,
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_current_source_tree_has_no_stale_adr_references() -> None:
    checker = _load_checker()

    assert checker.check_paths([checker.ROOT]) == []


def test_stale_folded_reference_in_plain_file_is_flagged(tmp_path: Path) -> None:
    checker = _load_checker()
    doc = tmp_path / "guide.md"
    doc.write_text(
        "See ADR-010 for the modular-spec mechanics.\n",
        encoding="utf-8",
    )

    failures = checker.check_paths([tmp_path])

    assert len(failures) == 1
    assert "ADR-010" in failures[0]
    assert "guide.md:1:" in failures[0]


def test_folded_reference_on_a_fold_bookkeeping_line_is_allowed(tmp_path: Path) -> None:
    checker = _load_checker()
    doc = tmp_path / "020.md"
    doc.write_text(
        "**Folds:** ADR-010 (modular specs), ADR-014 (compatibility matrix)\n",
        encoding="utf-8",
    )

    assert checker.check_paths([tmp_path]) == []


def test_supersession_bookkeeping_line_is_allowed(tmp_path: Path) -> None:
    checker = _load_checker()
    doc = tmp_path / "013.md"
    doc.write_text(
        "**Superseded by ADR-008** (content folded; see ADR-008)\n",
        encoding="utf-8",
    )

    failures = checker.check_paths([tmp_path])

    # The folded number ADR-013 appears on a Superseded bookkeeping line: allowed.
    # The surviving target ADR-008 is always allowed.
    assert failures == []


def test_archive_directory_is_exempt(tmp_path: Path) -> None:
    checker = _load_checker()
    archive = tmp_path / "docs" / "adr" / "archive"
    archive.mkdir(parents=True)
    doc = archive / "010-modular-specs.md"
    doc.write_text(
        "# ADR-010\n\nThis archived ADR refers freely to ADR-010 throughout.\n",
        encoding="utf-8",
    )

    assert checker.check_paths([tmp_path]) == []


def test_dangling_reference_to_nonexistent_adr_is_flagged(tmp_path: Path) -> None:
    checker = _load_checker()
    doc = tmp_path / "notes.md"
    doc.write_text(
        "We considered ADR-099 but it does not exist.\n",
        encoding="utf-8",
    )

    failures = checker.check_paths([tmp_path])

    assert len(failures) == 1
    assert "ADR-099" in failures[0]
    assert "dangling" in failures[0].lower()


def test_living_reference_is_allowed(tmp_path: Path) -> None:
    checker = _load_checker()
    doc = tmp_path / "ok.md"
    doc.write_text(
        "See ADR-020 and ADR-008 and ADR-001 for the consolidated decisions.\n",
        encoding="utf-8",
    )

    assert checker.check_paths([tmp_path]) == []


if __name__ == "__main__":
    import sys

    import pytest

    sys.exit(pytest.main([__file__, "-v"]))

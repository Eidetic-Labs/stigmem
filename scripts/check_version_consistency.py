#!/usr/bin/env python3
"""Version consistency check (manifest-driven, per ADR-001).

Reads release/version-surfaces.yaml, derives the canonical release from the
PEP 440 anchor (root pyproject.toml), then asserts every other surface in the
manifest references the same release — normalized across PEP 440 and semver
spellings to a canonical key.

Per ADR-001: version drift is a hard error.
Per ADR-001 (per-ecosystem version-string convention): per-ecosystem spelling
    is expected; the normalizer maps
    0.9.0a1 (PEP 440) and 0.9.0-alpha.1 (semver) to the same canonical key.

Usage:
    python scripts/check_version_consistency.py
    python scripts/check_version_consistency.py --verbose

Exit codes:
    0 — every surface in the manifest agrees with the canonical release
    1 — at least one mismatch (details on stderr)
    2 — environmental error (missing manifest, missing PyYAML, etc.)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: PyYAML required. Install: pip install pyyaml\n")
    sys.exit(2)

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        sys.stderr.write("ERROR: tomllib (3.11+) or tomli is required.\n")
        sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "release" / "version-surfaces.yaml"
ANCHOR = REPO_ROOT / "pyproject.toml"  # Canonical release source: PEP 440 string here

# ---------------------------------------------------------------------------
# Normalizer — maps PEP 440 and semver spellings to a single canonical key
# ---------------------------------------------------------------------------

PEP440_PRE = re.compile(
    r"^(?P<release>\d+\.\d+\.\d+)"
    r"(?:(?P<kind>a|b|rc)(?P<n>\d+))?$"
)

SEMVER_PRE = re.compile(
    r"^(?P<release>\d+\.\d+\.\d+)"
    r"(?:-(?P<kind>alpha|beta|rc)\.(?P<n>\d+))?$"
)


def normalize(version_string: str) -> str | None:
    """Return canonical key (e.g. '0.9.0.alpha.1') or None if unparseable.

    Maps PEP 440 (0.9.0a1) and semver (0.9.0-alpha.1) and shorthand (v0.9.0a1)
    to a single canonical key for cross-ecosystem comparison.
    """
    if not version_string:
        return None
    s = version_string.strip().lstrip("v")

    # PEP 440 form
    m = PEP440_PRE.match(s)
    if m:
        release = m.group("release")
        kind = m.group("kind")
        n = m.group("n")
        if not kind:
            return f"{release}"
        kind_full = {"a": "alpha", "b": "beta", "rc": "rc"}[kind]
        return f"{release}.{kind_full}.{n}"

    # Semver form
    m = SEMVER_PRE.match(s)
    if m:
        release = m.group("release")
        kind = m.group("kind")
        n = m.group("n")
        if not kind:
            return f"{release}"
        return f"{release}.{kind}.{n}"

    return None


# ---------------------------------------------------------------------------
# Per-spelling extractors — read the version string from a file at a given field
# ---------------------------------------------------------------------------


def extract_toml(path: Path, field: str) -> str | None:
    """Read a dotted field from a TOML file. Field path: 'project.version'."""
    if not path.exists():
        return None
    data: Any = tomllib.loads(path.read_text())
    parts = field.split(".")
    cur = data
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return str(cur) if cur is not None else None


def extract_json(path: Path, field: str) -> str | None:
    """Read a dotted field from a JSON file. Field path: 'project.version' or 'version'."""
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    parts = field.split(".")
    cur: Any = data
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return str(cur) if cur is not None else None


def extract_yaml(path: Path, field: str) -> str | None:
    """Read a dotted field from a YAML file. Field path: 'appVersion'."""
    if not path.exists():
        return None
    data = yaml.safe_load(path.read_text()) or {}
    parts = field.split(".")
    cur = data
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return str(cur) if cur is not None else None


def extract_version_from_file(file_path: Path, field: str | None) -> str | None:
    """Dispatch by extension. Field is required for structured files."""
    if not field:
        return None
    suffix = file_path.suffix.lower()
    if suffix == ".toml":
        return extract_toml(file_path, field)
    if suffix == ".json":
        return extract_json(file_path, field)
    if suffix in {".yaml", ".yml"}:
        return extract_yaml(file_path, field)
    return None


def extract_pattern(path: Path, pattern: str, group: str = "version") -> str | None:
    """Extract a version string from text using a regex named capture group."""
    if not path.exists():
        return None
    match = re.search(pattern, path.read_text(), flags=re.MULTILINE)
    if match is None:
        return None
    try:
        return match.group(group)
    except IndexError:
        return None


def extract_literal(path: Path) -> Any:
    """Read a structured file as a literal value for non-version metadata checks."""
    if not path.exists():
        return None
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(path.read_text())
    if suffix in {".yaml", ".yml"}:
        return yaml.safe_load(path.read_text())
    if suffix == ".toml":
        return tomllib.loads(path.read_text())
    return path.read_text()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def fail(msg: str) -> None:
    sys.stderr.write(f"version-consistency: {msg}\n")


def _load_manifest_surfaces() -> tuple[list[Any] | None, str | None]:
    """Load the surfaces list from the manifest. Returns (surfaces, error_msg)."""
    if not MANIFEST.exists():
        return None, f"manifest not found at {MANIFEST.relative_to(REPO_ROOT)}"
    try:
        manifest = yaml.safe_load(MANIFEST.read_text())
    except yaml.YAMLError as e:
        return None, f"YAML parse error in manifest: {e}"
    surfaces = manifest.get("surfaces", []) if isinstance(manifest, dict) else []
    if not surfaces:
        return None, "no surfaces in manifest"
    return surfaces, None


def _load_canonical_version() -> tuple[str | None, str | None, str | None]:
    """Read the canonical version + key from the anchor pyproject.toml.

    Returns (canonical_str, canonical_key, error_msg) — error_msg is None on success.
    """
    canonical = extract_toml(ANCHOR, "project.version")
    if not canonical:
        return None, None, f"could not read project.version from {ANCHOR.relative_to(REPO_ROOT)}"
    canonical_key = normalize(canonical)
    if not canonical_key:
        return (
            None,
            None,
            f"anchor version {canonical!r} is not a parseable PEP 440 / semver string",
        )
    return canonical, canonical_key, None


def _entry_skip_reason(entry: dict[str, Any]) -> str | None:
    """Return a skip reason for entries that should not be version-checked, or None."""
    sid = entry["id"]
    if entry.get("retired"):
        return f"{sid} (retired {entry['retired']})"
    file_rel = entry.get("file")
    field = entry.get("field")
    if entry.get("pattern") or "expected" in entry:
        return None
    if not file_rel or not field:
        return f"{sid} (no file/field; protocol-only)"
    suffix = Path(file_rel).suffix.lower()
    kind = entry.get("kind")
    if kind == "documentation" and suffix == ".md":
        return f"{sid} (markdown prose; not yet checked)"
    if kind == "internal-protocol" and suffix == ".py":
        return f"{sid} (Python source; spec-defined, not yet checked)"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    surfaces, manifest_err = _load_manifest_surfaces()
    if surfaces is None:
        fail(manifest_err or "unknown manifest error")
        return 2

    canonical, canonical_key, anchor_err = _load_canonical_version()
    if canonical is None:
        fail(anchor_err or "unknown anchor error")
        return 2

    if args.verbose:
        print(f"Canonical (anchor): {canonical} → key {canonical_key}")

    mismatches, skipped, checked = _check_all_surfaces(surfaces, canonical_key, args.verbose)

    if mismatches:
        fail(
            f"\n{len(mismatches)} mismatch(es) against canonical "
            f"{canonical} (key={canonical_key}):"
        )
        for sid, file_rel, actual, actual_key in mismatches:
            fail(f"  {sid:<32}  {file_rel:<40}  got {actual!r} (key={actual_key})")
        return 1

    print(
        f"OK: {checked} surface(s) match canonical {canonical} (key={canonical_key}). "
        f"{len(skipped)} skipped (deferred or retired)."
    )
    if args.verbose and skipped:
        for s in skipped:
            print(f"  skipped: {s}")
    return 0


def _check_all_surfaces(
    surfaces: list[Any],
    canonical_key: str,
    verbose: bool,
) -> tuple[list[tuple[str, str, str | None, str | None]], list[str], int]:
    """Compare every surface entry against the canonical version key.

    Returns (mismatches, skipped, checked_count).
    """
    mismatches: list[tuple[str, str, str | None, str | None]] = []
    skipped: list[str] = []
    checked = 0
    for entry in surfaces:
        skip = _entry_skip_reason(entry)
        if skip is not None:
            skipped.append(skip)
            continue

        sid = entry["id"]
        file_rel = entry["file"]
        file_path = REPO_ROOT / file_rel

        if "expected" in entry and not entry.get("field") and not entry.get("pattern"):
            expected = entry["expected"]
            actual_literal = extract_literal(file_path)
            checked += 1
            if verbose:
                print(f"  {sid:<32}  {file_rel}  =  {actual_literal!r}  expected {expected!r}")
            if actual_literal != expected:
                mismatches.append((sid, file_rel, repr(actual_literal), f"expected {expected!r}"))
            continue

        pattern = entry.get("pattern")
        if pattern:
            actual = extract_pattern(file_path, str(pattern), str(entry.get("group", "version")))
        else:
            actual = extract_version_from_file(file_path, entry.get("field"))
        actual_key = normalize(actual) if actual else None

        checked += 1
        if verbose:
            locator = f"pattern {pattern!r}" if pattern else f"field {entry.get('field')}"
            print(f"  {sid:<32}  {file_rel}::{locator}  =  {actual!r}  → {actual_key}")

        if actual_key != canonical_key:
            mismatches.append((sid, file_rel, actual, actual_key))
    return mismatches, skipped, checked


if __name__ == "__main__":
    sys.exit(main())

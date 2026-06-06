#!/usr/bin/env python3
"""Schema validator for release/version-surfaces.yaml.

Per ADR-001 (version-surface manifest convention): every release surface that emits or references
a stigmem version string is registered in release/version-surfaces.yaml. This
script asserts the manifest itself is well-formed before check_version_consistency.py
consumes it.

Run as a CI step on every PR. Failure here blocks the version-consistency check.

Exit codes:
    0 — manifest is valid
    1 — schema or content errors (details on stderr)
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "ERROR: PyYAML is required. Install: pip install pyyaml\n"
    )
    sys.exit(2)


REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "release" / "version-surfaces.yaml"

REQUIRED_FIELDS = {"id", "kind", "category", "spelling", "sort_authority"}
ALLOWED_KINDS = {
    "external-registry",
    "internal-protocol",
    "internal-build-artifact",
    "documentation",
}
ALLOWED_SPELLINGS = {"pep440", "semver", "shorthand"}
ALLOWED_SORT_AUTHORITIES = {"pep440", "semver"}


def fail(msg: str) -> None:
    sys.stderr.write(f"version-surfaces: {msg}\n")


def _load_manifest() -> tuple[list[Any] | None, str | None]:
    """Load surfaces from the manifest. Returns (surfaces, error) — exactly one is None."""
    if not MANIFEST.exists():
        return None, f"manifest not found at {MANIFEST.relative_to(REPO_ROOT)}"
    try:
        data = yaml.safe_load(MANIFEST.read_text())
    except yaml.YAMLError as e:
        return None, f"YAML parse error: {e}"
    if not isinstance(data, dict):
        return None, "manifest root must be a mapping"
    schema_version = data.get("schema_version")
    if schema_version != 1:
        return None, f"unsupported schema_version: {schema_version!r} (expected 1)"
    surfaces = data.get("surfaces")
    if not isinstance(surfaces, list) or not surfaces:
        return None, "`surfaces` must be a non-empty list"
    return surfaces, None


def _validate_enums_and_spelling(entry: dict[str, Any], prefix: str) -> int:
    """Validate the enum fields + spelling/sort_authority consistency. Returns error count."""
    errors = 0
    if entry["kind"] not in ALLOWED_KINDS:
        fail(f"{prefix}: kind={entry['kind']!r} not in {sorted(ALLOWED_KINDS)}")
        errors += 1
    if entry["spelling"] not in ALLOWED_SPELLINGS:
        fail(f"{prefix}: spelling={entry['spelling']!r} not in {sorted(ALLOWED_SPELLINGS)}")
        errors += 1
    if entry["sort_authority"] not in ALLOWED_SORT_AUTHORITIES:
        fail(f"{prefix}: sort_authority={entry['sort_authority']!r} not in {sorted(ALLOWED_SORT_AUTHORITIES)}")
        errors += 1

    spelling = entry.get("spelling")
    sort_auth = entry.get("sort_authority")
    if spelling == "pep440" and sort_auth != "pep440":
        fail(f"{prefix}: spelling=pep440 must use sort_authority=pep440")
        errors += 1
    if spelling == "semver" and sort_auth != "semver":
        fail(f"{prefix}: spelling=semver must use sort_authority=semver")
        errors += 1
    return errors


def _validate_file_requirement(entry: dict[str, Any], prefix: str) -> int:
    """Documentation / external-registry entries must declare a `file:` path."""
    if entry.get("retired"):
        return 0
    if entry["kind"] not in {"external-registry", "internal-build-artifact", "documentation"}:
        return 0
    if entry.get("file"):
        return 0
    if entry["kind"] in {"external-registry", "documentation"}:
        fail(f"{prefix}: kind={entry['kind']} typically requires `file:` (none provided)")
        return 1
    return 0


def _validate_entry(i: int, entry: Any, seen_ids: set[str]) -> int:
    """Run all per-entry checks. Mutates `seen_ids`. Returns error count for this entry."""
    prefix = f"surfaces[{i}]"
    if not isinstance(entry, dict):
        fail(f"{prefix}: entry must be a mapping")
        return 1

    missing = REQUIRED_FIELDS - set(entry.keys())
    if missing:
        fail(f"{prefix} (id={entry.get('id', '<unknown>')}): missing fields: {sorted(missing)}")
        return 1

    sid = entry["id"]
    prefix = f"surfaces[{i}] (id={sid})"
    errors = 0
    if sid in seen_ids:
        fail(f"{prefix}: duplicate id")
        errors += 1
    seen_ids.add(sid)

    errors += _validate_enums_and_spelling(entry, prefix)
    errors += _validate_file_requirement(entry, prefix)
    return errors


def main() -> int:
    surfaces, err = _load_manifest()
    if surfaces is None:
        fail(err or "unknown manifest error")
        return 1

    seen_ids: set[str] = set()
    errors = sum(_validate_entry(i, entry, seen_ids) for i, entry in enumerate(surfaces))

    if errors:
        fail(f"{errors} error(s) in {MANIFEST.relative_to(REPO_ROOT)}")
        return 1

    print(f"OK: {len(seen_ids)} surfaces in {MANIFEST.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

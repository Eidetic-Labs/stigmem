#!/usr/bin/env python3
"""Structural guard: every ``ADR-0NN`` reference resolves to a living ADR.

After the 2026-06-06 de-contrition consolidation, nine ADRs were folded into
surviving ADRs and moved to ``docs/adr/archive/`` (full text preserved, with
supersession headers). This guard keeps the rest of the repository pointing at
the *surviving* ADR numbers, so a reader following a reference always reaches
current content.

A reference is a VIOLATION when it names a folded/archived number outside a
sanctioned bookkeeping site, or when it names a number that has no ADR file at
all (a dangling reference). Sanctioned bookkeeping sites are:

- anything under ``docs/adr/archive/`` (the frozen historical record);
- a line in a living ``docs/adr/*.md`` whose purpose is supersession/fold
  bookkeeping (the line contains ``Fold``, ``Supersede``, ``Superseded``, or
  ``Archived``, case-insensitive);
- any line inside the ADR README's "Archived / superseded" section.

The guard prints each violation as ``file:line: <text>`` and exits non-zero if
any are found.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

ADR_DIR = ROOT / "docs" / "adr"
ARCHIVE_DIR = ADR_DIR / "archive"

# Folded/archived ADR numbers retired by the de-contrition consolidation.
FOLDED_NUMBERS = {"005", "007", "009", "010", "012", "013", "014", "017", "018", "019"}

# Directory names pruned from the scan entirely.
EXCLUDED_DIR_NAMES = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    ".mypy_cache",
    "__pycache__",
    ".docusaurus",  # Docusaurus build cache, regenerated from source docs.
}
# Path fragments (relative to ROOT, posix) pruned from the scan.
# ``spec/archive`` and ``docs/archive`` hold frozen historical snapshots (old
# spec versions, superseded doc trees). They are part of the immutable record
# and must not be rewritten to point at current ADR numbers, so they are not
# scanned — same treatment as ``docs/adr/archive``.
EXCLUDED_PATH_PREFIXES = ("eval/results", "spec/archive", "docs/archive")
# This guard's own test file deliberately contains stale/dangling ADR strings as
# fixtures; scanning it would flag its own test data.
EXCLUDED_PATH_EXACT = (
    "tests/test_check_adr_references.py",
    "scripts/check_adr_references.py",
)

# Only scan text-ish files. Skip obvious binaries / lockfiles by suffix.
SKIP_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".whl",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".lock",
    ".pyc",
    ".so",
    ".dylib",
}

ADR_REF = re.compile(r"ADR-0(\d\d)\b")

# Path reference to an ADR *file*, e.g. ``docs/adr/007-argon2id.md`` or
# ``docs/adr/archive/007-argon2id.md``. group(1) is ``archive/`` when the path
# already points at the frozen copy; group(2) is the number. This catches stale
# file-path references (in JSON registries, link hrefs, etc.) to ADRs that were
# moved to ``archive/`` — a class the ``ADR-0NN`` token regex alone misses.
ADR_PATH_REF = re.compile(r"adr/(archive/)?0(\d\d)-[A-Za-z0-9._-]+\.md")

# A living ADR line is a fold/supersession bookkeeping line when it mentions any
# of these tokens (case-insensitive). Such lines are allowed to name folded
# numbers because that *is* their purpose.
BOOKKEEPING_TOKENS = ("fold", "supersede", "superseded", "archived")

# README section that legitimately lists every archived/superseded number.
ARCHIVED_SECTION_HEADING = re.compile(r"^\s*#+\s*Archived\s*/\s*superseded", re.IGNORECASE)
# Any subsequent top-level heading (or the closing rule) ends that section.
SECTION_TERMINATOR = re.compile(r"^\s*(#+\s|---\s*$)")


def _living_numbers() -> set[str]:
    nums: set[str] = set()
    if ADR_DIR.is_dir():
        for path in ADR_DIR.glob("*.md"):
            match = re.match(r"0(\d\d)-", path.name)
            if match:
                nums.add(match.group(1))
    return nums


def _archived_numbers() -> set[str]:
    nums: set[str] = set()
    if ARCHIVE_DIR.is_dir():
        for path in ARCHIVE_DIR.glob("*.md"):
            match = re.match(r"0(\d\d)-", path.name)
            if match:
                nums.add(match.group(1))
    return nums


def _is_excluded(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDED_DIR_NAMES:
        return True
    # Generated Python package metadata (e.g. ``stigmem.egg-info/PKG-INFO``) is
    # rebuilt from pyproject/README and should not be hand-edited.
    if any(part.endswith(".egg-info") for part in path.parts):
        return True
    try:
        rel = path.relative_to(ROOT).as_posix()
    except ValueError:
        rel = path.as_posix()
    if rel in EXCLUDED_PATH_EXACT:
        return True
    return any(rel.startswith(prefix) for prefix in EXCLUDED_PATH_PREFIXES)


def _iter_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for child in path.rglob("*"):
                if child.is_file():
                    files.append(child)
    selected: list[Path] = []
    for path in sorted(set(files)):
        if _is_excluded(path):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        selected.append(path)
    return selected


def _is_under_archive(path: Path) -> bool:
    # Exempt any file inside a ``docs/adr/archive`` directory, wherever rooted
    # (the real tree or a test fixture).
    parts = path.parts
    for i in range(len(parts) - 2):
        if parts[i] == "adr" and parts[i + 1] == "archive":
            return True
    return False


def _is_living_adr_doc(path: Path) -> bool:
    parts = path.parts
    if path.suffix != ".md":
        return False
    for i in range(len(parts) - 1):
        if parts[i] == "adr" and not _is_under_archive(path):
            # A markdown file directly under an ``adr`` directory (not archive).
            if path.parent.name == "adr":
                return True
    return False


def _is_bookkeeping_line(line: str) -> bool:
    lowered = line.lower()
    return any(token in lowered for token in BOOKKEEPING_TOKENS)


def _links_to_archive(line: str, number: str) -> bool:
    """True when the line links to this ADR number's archived copy.

    A reference that points at ``.../adr/archive/0NN-...`` reaches the frozen
    historical record, which is the sanctioned destination for an archived ADR.
    """
    return re.search(rf"archive/0{number}-", line) is not None


def check_paths(paths: list[Path]) -> list[str]:
    living = _living_numbers()
    archived = _archived_numbers()
    # When run against a test fixture tree with no docs/adr/, fall back to the
    # consolidation's known living set so fixtures behave deterministically.
    if not living and not archived:
        living = {"001", "002", "003", "004", "006", "008", "011", "015", "016", "020"}
        archived = set(FOLDED_NUMBERS)
    resolvable = living | archived

    failures: list[str] = []

    for path in _iter_files(paths):
        if _is_under_archive(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if "ADR-0" not in text and "adr/0" not in text:
            continue

        is_living_doc = _is_living_adr_doc(path)
        in_archived_section = False

        for index, line in enumerate(text.splitlines(), start=1):
            if is_living_doc:
                if ARCHIVED_SECTION_HEADING.match(line):
                    in_archived_section = True
                elif in_archived_section and SECTION_TERMINATOR.match(line):
                    in_archived_section = False

            for match in ADR_REF.finditer(line):
                number = match.group(1)
                try:
                    display = path.relative_to(ROOT).as_posix()
                except ValueError:
                    display = path.as_posix()

                if number not in resolvable:
                    # Forward-looking numbering prose in the README's archived
                    # section (e.g. "continue from ADR-021") is bookkeeping, not
                    # a real reference.
                    if in_archived_section:
                        continue
                    failures.append(
                        f"{display}:{index}: dangling reference ADR-0{number} "
                        f"(no living or archived ADR with that number): "
                        f"{line.strip()}"
                    )
                    continue

                if number in living:
                    # Reference to a surviving ADR is always fine.
                    continue

                # number is a folded/archived number: allowed only at sanctioned
                # bookkeeping sites:
                #   - inside the README's "Archived / superseded" section,
                #   - on a fold/supersession bookkeeping line, or
                #   - when the reference links to the ADR's archived copy (the
                #     reader reaches the frozen historical record — the intent of
                #     the archive). This is the sanctioned form for ADR-007, an
                #     archived settled migration with no fold survivor.
                if (
                    in_archived_section
                    or _is_bookkeeping_line(line)
                    or _links_to_archive(line, number)
                ):
                    continue

                failures.append(
                    f"{display}:{index}: stale reference to folded ADR-0{number} "
                    f"(redirect to its surviving ADR): {line.strip()}"
                )

            for pmatch in ADR_PATH_REF.finditer(line):
                points_at_archive = pmatch.group(1) is not None
                pnum = pmatch.group(2)
                if points_at_archive or pnum in living:
                    # Frozen-copy path, or a surviving ADR still at docs/adr/0NN- — fine.
                    continue
                if in_archived_section or _is_bookkeeping_line(line):
                    continue
                try:
                    display = path.relative_to(ROOT).as_posix()
                except ValueError:
                    display = path.as_posix()
                if pnum not in resolvable:
                    failures.append(
                        f"{display}:{index}: dangling ADR file path docs/adr/0{pnum}-... "
                        f"(no such ADR): {line.strip()}"
                    )
                else:
                    failures.append(
                        f"{display}:{index}: stale path to moved ADR file "
                        f"docs/adr/0{pnum}-... (now under docs/adr/archive/): "
                        f"{line.strip()}"
                    )

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Files or directories to scan. Defaults to the repository root.",
    )
    args = parser.parse_args(argv)
    paths = args.paths or [ROOT]
    failures = check_paths(paths)
    if failures:
        print("ADR-reference guard failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("OK: all ADR references resolve to living ADRs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

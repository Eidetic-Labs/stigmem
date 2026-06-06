#!/usr/bin/env python3
"""Generate the protocol composition index from modular spec frontmatter."""

from __future__ import annotations

import argparse
import difflib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPECS_DIR = ROOT / "spec" / "specs"
EXPERIMENTAL_DIR = ROOT / "experimental"
PROTOCOL_PATH = ROOT / "spec" / "PROTOCOL.md"

REQUIRED_FIELDS = (
    "spec_id",
    "version",
    "status",
    "applies_to",
    "last_updated",
    "supersedes",
    "depends_on",
)
VALID_STATUSES = {"Draft", "Experimental", "Stable", "Superseded", "Deprecated"}


@dataclass(frozen=True)
class SpecMetadata:
    path: Path
    kind: str
    spec_id: str
    version: str
    status: str
    applies_to: str
    last_updated: str
    supersedes: str
    depends_on: tuple[str, ...]


def _fail(message: str) -> None:
    raise ValueError(message)


def _parse_frontmatter(path: Path) -> dict[str, str | list[str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        _fail(f"{path}: missing opening YAML frontmatter marker")

    try:
        end = lines[1:].index("---") + 1
    except ValueError as exc:
        raise ValueError(f"{path}: missing closing YAML frontmatter marker") from exc

    metadata: dict[str, str | list[str]] = {}
    current_key: str | None = None

    for line_number, raw_line in enumerate(lines[1:end], start=2):
        if not raw_line.strip():
            continue

        if raw_line.startswith("  - "):
            if current_key != "depends_on":
                _fail(f"{path}:{line_number}: list item is only supported for depends_on")
            value = raw_line[4:].strip()
            if not value:
                _fail(f"{path}:{line_number}: empty depends_on entry")
            depends_on = metadata.setdefault("depends_on", [])
            if not isinstance(depends_on, list):
                _fail(f"{path}:{line_number}: depends_on must be a list")
            depends_on.append(value)
            continue

        if ":" not in raw_line:
            _fail(f"{path}:{line_number}: expected key: value frontmatter entry")

        key, raw_value = raw_line.split(":", 1)
        key = key.strip()
        value = raw_value.strip()
        current_key = key

        if key == "depends_on":
            if value == "[]":
                metadata[key] = []
            elif value:
                _fail(f"{path}:{line_number}: depends_on must use [] or indented list items")
            else:
                metadata[key] = []
            continue

        if not value:
            _fail(f"{path}:{line_number}: {key} must not be empty")
        metadata[key] = value

    return metadata


def _require_string(
    metadata: dict[str, str | list[str]],
    path: Path,
    field: str,
) -> str:
    value = metadata.get(field)
    if not isinstance(value, str):
        _fail(f"{path}: {field} must be a scalar string")
    return value


def _load_spec(path: Path, kind: str) -> SpecMetadata:
    metadata = _parse_frontmatter(path)
    missing = [field for field in REQUIRED_FIELDS if field not in metadata]
    if missing:
        _fail(f"{path}: missing required frontmatter field(s): {', '.join(missing)}")

    spec_id = _require_string(metadata, path, "spec_id")
    version = _require_string(metadata, path, "version")
    status = _require_string(metadata, path, "status")
    applies_to = _require_string(metadata, path, "applies_to")
    last_updated = _require_string(metadata, path, "last_updated")
    supersedes = _require_string(metadata, path, "supersedes")
    depends_raw = metadata["depends_on"]

    if not isinstance(depends_raw, list) or not all(
        isinstance(item, str) for item in depends_raw
    ):
        _fail(f"{path}: depends_on must be a list of strings")

    core_match = re.fullmatch(r"Spec-(\d{2})-[A-Za-z0-9-]+", spec_id)
    experimental_match = re.fullmatch(r"Spec-X(\d+)-[A-Za-z0-9-]+", spec_id)
    if kind == "core":
        if core_match is None:
            _fail(f"{path}: spec_id must look like Spec-01-Fact-Model")
        file_number = path.stem.split("-", 1)[0]
        if file_number != core_match.group(1):
            _fail(f"{path}: filename number does not match {spec_id}")
    elif kind == "experimental":
        if experimental_match is None:
            _fail(
                f"{path}: experimental spec_id must look like "
                + "Spec-X1-Lazy-Instruction-Discovery"
            )
    else:
        _fail(f"{path}: unknown spec kind {kind}")

    if status not in VALID_STATUSES:
        _fail(f"{path}: status must be one of {', '.join(sorted(VALID_STATUSES))}")

    return SpecMetadata(
        path=path,
        kind=kind,
        spec_id=spec_id,
        version=version,
        status=status,
        applies_to=applies_to,
        last_updated=last_updated,
        supersedes=supersedes,
        depends_on=tuple(depends_raw),
    )


def load_specs(specs_dir: Path, kind: str) -> list[SpecMetadata]:
    glob_pattern = "*.md" if kind == "core" else "*/spec.md"
    paths = sorted(specs_dir.glob(glob_pattern))
    if not paths:
        _fail(f"{specs_dir}: no {kind} spec files found")

    return [_load_spec(path, kind) for path in paths]


def load_all_specs() -> tuple[list[SpecMetadata], list[SpecMetadata]]:
    core_specs = load_specs(SPECS_DIR, "core")
    experimental_specs = load_specs(EXPERIMENTAL_DIR, "experimental")
    all_specs = [*core_specs, *experimental_specs]
    ids = {spec.spec_id for spec in all_specs}
    for spec in all_specs:
        unknown = [
            dependency
            for dependency in spec.depends_on
            if dependency.split(maxsplit=1)[0] not in ids
        ]
        if unknown:
            _fail(
                f"{spec.path}: depends_on references unknown spec(s): "
                + f"{', '.join(unknown)}"
            )
    return core_specs, experimental_specs


def _markdown_link(spec: SpecMetadata) -> str:
    if spec.kind == "core":
        link_target = spec.path.relative_to(ROOT / "spec")
    else:
        link_target = Path("..") / spec.path.relative_to(ROOT)
    return f"[`{spec.spec_id}`]({link_target.as_posix()})"


def _dependency_text(spec: SpecMetadata) -> str:
    if not spec.depends_on:
        return "None"
    return "<br>".join(f"`{dependency}`" for dependency in spec.depends_on)


def _spec_sort_key(spec: SpecMetadata) -> tuple[int, int]:
    pattern = r"Spec-(\d{2})-" if spec.kind == "core" else r"Spec-X(\d+)-"
    match = re.match(pattern, spec.spec_id)
    if match is None:
        return (1, 999)
    return (0 if spec.kind == "core" else 1, int(match.group(1)))


def render_protocol(
    core_specs: list[SpecMetadata],
    experimental_specs: list[SpecMetadata],
) -> str:
    all_specs = [*core_specs, *experimental_specs]
    latest_update = max(spec.last_updated for spec in all_specs)
    intro = (
        "This file records the ADR-020 modular specification composition for the "
        + "Stigmem protocol. It is generated from YAML frontmatter in component "
        + "[`spec/specs/`](specs/) files and colocated experimental specs under "
        + "`experimental/<feature>/spec.md`."
    )
    extraction_status = (
        "The files in `spec/specs/` are being populated incrementally as "
        + "ADR-020 extraction PRs migrate prose from the canonical and archived "
        + "source material into modular component specs. Files that still include an "
        + "`Extraction Status` stub are pending prose extraction."
    )
    experimental_status = (
        "Experimental and deferred material remains colocated under "
        + "`experimental/<feature>/spec.md`; those files now carry ADR-020 "
        + "frontmatter and appear in this generated protocol index."
    )
    lines = [
        "# Stigmem Protocol Composition",
        "",
        "> AUTO-GENERATED by `scripts/generate_protocol_md.py`; do not edit by hand.",
        "",
        intro,
        "",
        f"**Metadata last updated:** {latest_update}",
        "",
        "## Protocol Component Specs",
        "",
        "| Spec | Version | Status | Applies to | Last updated |",
        "|---|---|---|---|---|",
    ]

    for spec in sorted(core_specs, key=_spec_sort_key):
        lines.append(
            f"| {_markdown_link(spec)} | `{spec.version}` | {spec.status} | "
            + f"{spec.applies_to} | {spec.last_updated} |"
        )

    lines.extend(
        [
            "",
            "## Experimental Specs",
            "",
            "| Spec | Version | Status | Applies to | Location |",
            "|---|---|---|---|---|",
        ]
    )

    for spec in sorted(experimental_specs, key=_spec_sort_key):
        lines.append(
            f"| {_markdown_link(spec)} | `{spec.version}` | {spec.status} | "
            + f"{spec.applies_to} | `{spec.path.relative_to(ROOT).as_posix()}` |"
        )

    lines.extend(
        [
            "",
            "## Dependency Graph",
            "",
            "| Spec | Depends on | Supersedes |",
            "|---|---|---|",
        ]
    )

    for spec in sorted(all_specs, key=_spec_sort_key):
        lines.append(
            f"| `{spec.spec_id}` | {_dependency_text(spec)} | {spec.supersedes} |"
        )

    lines.extend(
        [
            "",
            "## Extraction Status",
            "",
            extraction_status,
            "",
            experimental_status,
            "",
        ]
    )
    return "\n".join(lines)


def check_protocol(rendered: str) -> int:
    if not PROTOCOL_PATH.exists():
        print(f"{PROTOCOL_PATH} is missing; run scripts/generate_protocol_md.py")
        return 1

    current = PROTOCOL_PATH.read_text(encoding="utf-8")
    if current == rendered:
        return 0

    diff = difflib.unified_diff(
        current.splitlines(keepends=True),
        rendered.splitlines(keepends=True),
        fromfile=str(PROTOCOL_PATH),
        tofile="generated",
    )
    sys.stdout.writelines(diff)
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate spec/PROTOCOL.md from modular spec frontmatter.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if spec/PROTOCOL.md is not up to date",
    )
    args = parser.parse_args(argv)

    try:
        rendered = render_protocol(*load_all_specs())
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.check:
        return check_protocol(rendered)

    PROTOCOL_PATH.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

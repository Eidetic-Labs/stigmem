#!/usr/bin/env python3
"""Validate colocated experimental security documentation.

The validator enforces ADR-020's mechanical contract: per-feature security
docs have frontmatter, owned risks are linked from the unified threat model,
and public security docs do not depend on Internal-Comms paths.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPERIMENTAL_ROOT = REPO_ROOT / "experimental"
THREAT_MODEL_PATH = REPO_ROOT / "spec" / "security" / "threat-model.md"
REQUIRED_FIELDS = {
    "feature",
    "spec_id",
    "status",
    "applies_to",
    "last_updated",
    "owned_risks",
    "contributed_risks",
}
VALID_STATUSES = {"Experimental", "Stable", "Deprecated"}
RISK_RE = re.compile(r"R-\d{2}")
SECURITY_LINK_RE = re.compile(r"experimental/[A-Za-z0-9_.-]+/security\.md")


def _parse_frontmatter(path: Path) -> tuple[dict[str, str | list[str]], str]:
    text = path.read_text()
    if not text.startswith("---\n"):
        raise ValueError("missing YAML frontmatter")
    try:
        _, raw_frontmatter, body = text.split("---\n", 2)
    except ValueError as exc:
        raise ValueError("unterminated YAML frontmatter") from exc

    values: dict[str, str | list[str]] = {}
    current_list: str | None = None
    for raw_line in raw_frontmatter.splitlines():
        line = raw_line.rstrip()
        if not line:
            continue
        if line.startswith("  - "):
            if current_list is None:
                raise ValueError(f"list item without key: {line}")
            item = line[4:].strip()
            existing = values.setdefault(current_list, [])
            if not isinstance(existing, list):
                raise ValueError(f"{current_list}: cannot mix scalar and list")
            existing.append(item)
            continue
        current_list = None
        if ":" not in line:
            raise ValueError(f"invalid frontmatter line: {line}")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if value == "[]":
            values[key] = []
        elif value:
            values[key] = value
        else:
            values[key] = []
            current_list = key
    return values, body


def _risk_statuses_from_threat_model(text: str) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("| R-"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if len(cells) < 8:
            continue
        status = cells[7].replace("*", "").strip()
        statuses[cells[0]] = status
    return statuses


def _feature_security_docs() -> list[Path]:
    return sorted(EXPERIMENTAL_ROOT.glob("*/security.md"))


def _validate_security_doc(
    path: Path,
    threat_model: str,
    threat_model_risks: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    rel_path = path.relative_to(REPO_ROOT)
    feature_dir = path.parent.name
    try:
        frontmatter, body = _parse_frontmatter(path)
    except ValueError as exc:
        return [f"{rel_path}: {exc}"]

    failures.extend(_frontmatter_shape_failures(rel_path, feature_dir, frontmatter))
    failures.extend(_risk_reference_failures(rel_path, frontmatter, body, threat_model_risks))
    failures.extend(_owned_risk_link_failures(rel_path, frontmatter, threat_model))
    failures.extend(_internal_comms_reference_failures(rel_path, body))
    return failures


def _frontmatter_shape_failures(
    rel_path: Path,
    feature_dir: str,
    frontmatter: dict[str, str | list[str]],
) -> list[str]:
    failures: list[str] = []
    missing = sorted(REQUIRED_FIELDS - set(frontmatter))
    if missing:
        failures.append(f"{rel_path}: missing frontmatter fields: {missing}")

    if frontmatter.get("feature") != feature_dir:
        failures.append(f"{rel_path}: feature must match directory name {feature_dir!r}")

    status = frontmatter.get("status")
    if status not in VALID_STATUSES:
        failures.append(f"{rel_path}: status must be one of {sorted(VALID_STATUSES)}")

    spec_id = frontmatter.get("spec_id")
    if not isinstance(spec_id, str) or not spec_id.startswith("Spec-"):
        failures.append(f"{rel_path}: spec_id must start with 'Spec-'")
    return failures


def _risk_reference_failures(
    rel_path: Path,
    frontmatter: dict[str, str | list[str]],
    body: str,
    threat_model_risks: dict[str, str],
) -> list[str]:
    failures: list[str] = []
    for field in ("owned_risks", "contributed_risks"):
        failures.extend(
            _risk_list_failures(rel_path, field, frontmatter.get(field), body, threat_model_risks)
        )
    return failures


def _risk_list_failures(
    rel_path: Path,
    field: str,
    risks: str | list[str] | None,
    body: str,
    threat_model_risks: dict[str, str],
) -> list[str]:
    if not isinstance(risks, list):
        return [f"{rel_path}: {field} must be a list"]

    failures: list[str] = []
    for risk_id in risks:
        if not RISK_RE.fullmatch(risk_id):
            failures.append(f"{rel_path}: {field} entry must match R-##: {risk_id}")
        if risk_id not in threat_model_risks:
            failures.append(f"{rel_path}: {risk_id} is not in the threat model")
        if risk_id not in body:
            failures.append(f"{rel_path}: body must mention {risk_id}")
    return failures


def _owned_risk_link_failures(
    rel_path: Path,
    frontmatter: dict[str, str | list[str]],
    threat_model: str,
) -> list[str]:
    owned_risks = frontmatter.get("owned_risks", [])
    if not isinstance(owned_risks, list):
        return []

    failures: list[str] = []
    for risk_id in owned_risks:
        if str(rel_path) not in threat_model:
            failures.append(f"{rel_path}: threat model must link to this owned-risk document")
            break
        if risk_id not in threat_model:
            failures.append(f"{rel_path}: threat model must mention {risk_id}")
    return failures


def _internal_comms_reference_failures(rel_path: Path, body: str) -> list[str]:
    if "Internal-Comms" in body or "Internal Comms" in body:
        return [f"{rel_path}: public security docs must not reference Internal-Comms"]
    return []


def _validate_threat_model_links(threat_model: str) -> list[str]:
    failures: list[str] = []
    for link in sorted(set(SECURITY_LINK_RE.findall(threat_model))):
        if not (REPO_ROOT / link).exists():
            failures.append(f"threat model links missing security doc: {link}")
    if "Internal-Comms" in threat_model or "Internal Comms" in threat_model:
        failures.append("threat model must not reference Internal-Comms")
    return failures


def main() -> int:
    failures: list[str] = []
    try:
        threat_model = THREAT_MODEL_PATH.read_text()
    except OSError as exc:
        print(
            f"security-docs: unable to read {THREAT_MODEL_PATH}: {exc}",
            file=sys.stderr,
        )
        return 2

    threat_model_risks = _risk_statuses_from_threat_model(threat_model)
    failures.extend(_validate_threat_model_links(threat_model))

    docs = _feature_security_docs()
    if not docs:
        failures.append("no experimental/*/security.md files found")
    for path in docs:
        failures.extend(_validate_security_doc(path, threat_model, threat_model_risks))

    if failures:
        for failure in failures:
            print(f"security-docs: {failure}", file=sys.stderr)
        return 1

    suffix = "s" if len(docs) != 1 else ""
    print(f"OK: {len(docs)} experimental security doc{suffix} validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

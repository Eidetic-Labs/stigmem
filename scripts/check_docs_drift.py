#!/usr/bin/env python3
"""Catch high-signal documentation drift after the feature-record migration."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FEATURE_INVENTORY = ROOT / "docs" / "internal" / "feature-tracker.md"

SCAN_PATHS = [
    ROOT / "README.md",
    ROOT / "LIMITATIONS.md",
    ROOT / "ROADMAP.md",
    ROOT / "SECURITY.md",
    ROOT / "docs" / "docs",
    ROOT / "experimental",
]

SKIP_PARTS = {"archive", "adr", "node_modules", ".next", ".turbo"}

ALLOWED_RETRACTED_LABEL_FILES = {
    ROOT / "SECURITY.md",
}

ALLOWED_RELEASE_MILESTONE_LABELS = {
    "v0.9.0a3",
    "v0.9.0a4",
    "v0.9.0a5",
    "v0.9.0a6",
    "v0.9.0a7",
    "v0.9.0a8",
    "v0.9.0a9",
    "v0.9.0a10",
    "v0.9.0a11",
}

FORBIDDEN_RELEASE_TOKENS = {
    "1.0.0rc1": (
        "Do not use the retracted release label in live docs. If the reference "
        "is historical security posture, add the file to ALLOWED_RETRACTED_LABEL_FILES."
    ),
    "v0.9.0b1": "Do not name a concrete beta milestone until the beta line is opened.",
    "v1.0.0rc1": (
        "Do not name a concrete release-candidate milestone until the RC line is opened."
    ),
}

FORBIDDEN_PATH_TOKENS = {
    "deploy/fly": "Use experimental/deploy-fly or features/deploy-fly.",
    "infra/fly": "Use experimental/deploy-fly.",
    "deploy/systemd": "Use experimental/deploy-systemd or features/deploy-systemd.",
    "deploy/paas": "Use experimental/deploy-paas or features/deploy-paas.",
    "experimental/deploy-grafana/stigmem-dashboard.json": (
        "Use experimental/deploy-grafana/dashboards/grafana/."
    ),
}

FORBIDDEN_NARRATIVE_PHRASES = {
    "Velocity outran validation.": (
        "Use neutral posture/reset language instead of self-critical narrative."
    ),
    "walked it back": (
        "Use neutral posture/reset language instead of self-critical narrative."
    ),
    "Honesty pass": "Use posture-calibration language for alpha release work.",
    "retraction failure mode": (
        "State the release invariant directly instead of carrying blame language forward."
    ),
    "failed with v1.0": (
        "State the release invariant directly instead of carrying blame language forward."
    ),
}


def iter_text_files() -> list[Path]:
    paths: list[Path] = []
    for root in SCAN_PATHS:
        if root.is_file():
            paths.append(root)
            continue
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(ROOT).parts
            if any(part in SKIP_PARTS for part in rel_parts):
                continue
            if path.suffix.lower() not in {".md", ".mdx", ".toml", ".yml", ".yaml", ".sh"}:
                continue
            paths.append(path)
    return sorted(set(paths))


def check_inventory_closed() -> list[str]:
    if not FEATURE_INVENTORY.exists():
        return [f"{FEATURE_INVENTORY}: missing feature migration inventory"]

    in_inventory_table = False
    seen_header = False
    errors: list[str] = []
    for line_no, raw in enumerate(FEATURE_INVENTORY.read_text(encoding="utf-8").splitlines(), 1):
        if raw == "## Feature Record Migration Inventory":
            in_inventory_table = True
            continue
        if not in_inventory_table:
            continue
        if raw.startswith("| Feature ID |"):
            seen_header = True
            continue
        if seen_header and raw and not raw.startswith("|"):
            break
        if seen_header and raw.startswith("| `") and "| `pending` |" in raw:
            errors.append(
                f"{FEATURE_INVENTORY}:{line_no}: feature inventory has a pending row; "
                "new feature work must add a feature record or an explicit non-pending disposition"
            )
    return errors


def check_tokens() -> list[str]:
    errors: list[str] = []
    for path in iter_text_files():
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(ROOT)

        for token, message in FORBIDDEN_PATH_TOKENS.items():
            if token in text:
                errors.append(f"{rel}: stale path token '{token}'. {message}")

        for token, message in FORBIDDEN_RELEASE_TOKENS.items():
            if path in ALLOWED_RETRACTED_LABEL_FILES:
                continue
            if token in text:
                errors.append(f"{rel}: stale release token '{token}'. {message}")

        for phrase, message in FORBIDDEN_NARRATIVE_PHRASES.items():
            if phrase in text:
                errors.append(f"{rel}: stale narrative phrase '{phrase}'. {message}")

        for line_no, line in enumerate(text.splitlines(), 1):
            if "github.com" not in line or "/milestone/" not in line:
                continue
            if any(label in line for label in ALLOWED_RELEASE_MILESTONE_LABELS):
                continue
            errors.append(
                f"{rel}:{line_no}: concrete milestone links are limited to "
                f"{sorted(ALLOWED_RELEASE_MILESTONE_LABELS)}; future release lines must stay "
                "documented as gated horizons until opened"
            )

    return errors


def main() -> int:
    errors = [*check_inventory_closed(), *check_tokens()]
    if errors:
        print("docs-drift: validation failed", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("docs-drift: migration inventory and stale-token checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate published-plugin catalog surfaces stay in sync."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]

PLUGINS: tuple[tuple[str, str], ...] = (
    ("cognee-adapter", "stigmem-plugin-cognee-adapter"),
    ("gemini-adapter", "stigmem-plugin-gemini-adapter"),
    ("letta-adapter", "stigmem-plugin-letta-adapter"),
    ("openai-tools-adapter", "stigmem-plugin-openai-tools-adapter"),
    ("zep-adapter", "stigmem-plugin-zep-adapter"),
    ("lazy-instruction-discovery", "stigmem-plugin-lazy-instruction-discovery"),
    ("memory-garden-acl", "stigmem-plugin-memory-garden-acl"),
    ("multi-tenant", "stigmem-plugin-multi-tenant"),
    ("source-attestation", "stigmem-plugin-source-attestation"),
    ("time-travel", "stigmem-plugin-time-travel"),
    ("tombstones", "stigmem-plugin-tombstones"),
)

ADAPTER_SLUGS = frozenset(
    {
        "cognee-adapter",
        "gemini-adapter",
        "letta-adapter",
        "openai-tools-adapter",
        "zep-adapter",
    }
)


def _root_pyproject() -> dict[str, object]:
    with (ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


def _dependency_names(values: list[str]) -> set[str]:
    return {value.split(">=", 1)[0].split("==", 1)[0].strip() for value in values}


def check_readme() -> list[str]:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    return [
        f"README.md: missing published plugin package {package}"
        for _slug, package in PLUGINS
        if package not in text
    ]


def check_pyproject_extras() -> list[str]:
    project = cast("dict[str, object]", _root_pyproject()["project"])
    optional = cast("dict[str, list[str]]", project.get("optional-dependencies", {}))
    errors: list[str] = []
    adapters = _dependency_names(optional.get("adapters", []))
    plugins_all = _dependency_names(optional.get("plugins-all", []))
    root_all = _dependency_names(optional.get("all", []))
    for slug, package in PLUGINS:
        extra_name = slug
        extra = _dependency_names(optional.get(extra_name, []))
        if package not in extra:
            errors.append(f"pyproject.toml: [{extra_name}] missing {package}")
        if slug in ADAPTER_SLUGS and package not in adapters:
            errors.append(f"pyproject.toml: [adapters] missing {package}")
        if package not in plugins_all:
            errors.append(f"pyproject.toml: [plugins-all] missing {package}")
        if package not in root_all:
            errors.append(f"pyproject.toml: [all] missing {package}")
    return errors


def check_docs_catalog() -> list[str]:
    docs_root = ROOT / "docs" / "docs" / "plugins"
    index = docs_root / "index.md"
    index_text = index.read_text(encoding="utf-8") if index.exists() else ""
    errors: list[str] = []
    if not index.exists():
        errors.append("docs/docs/plugins/index.md: missing plugin catalog index")
    for slug, package in PLUGINS:
        page = docs_root / f"{slug}.md"
        if not page.exists():
            errors.append(f"{page.relative_to(ROOT)}: missing plugin catalog page")
            continue
        page_text = page.read_text(encoding="utf-8")
        if package not in index_text:
            errors.append(f"docs/docs/plugins/index.md: missing {package}")
        if package not in page_text:
            errors.append(f"{page.relative_to(ROOT)}: missing package name {package}")
    return errors


def main() -> int:
    errors = [*check_readme(), *check_pyproject_extras(), *check_docs_catalog()]
    if errors:
        print("plugin-readme-pypi-consistency: failed", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"plugin-readme-pypi-consistency: validated {len(PLUGINS)} published plugins")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

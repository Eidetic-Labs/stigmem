#!/usr/bin/env python3
"""Validate the root README's public-orientation structure."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
PYPROJECT = ROOT / "pyproject.toml"

REQUIRED_H2 = [
    "Quickstart - 60 seconds to a running node",
    "Install",
    "Plugins",
    "MCP + editor integrations",
    "Federation, briefly",
    "Architecture",
    "Security posture",
    "Adjacent systems",
    "AI-authorship disclosure",
    "The name",
    "Spec",
    "Community",
    "Contributing",
    "Security",
    "License",
]

ALLOWED_MCP_TIERS = {"Validated", "Caveated", "Experimental"}
ADJACENT_FORBIDDEN = {"OpenClaw", "Paperclip", "Claude Code", "Cursor", "Zed"}


def h2_headings(text: str) -> list[str]:
    return [match.group(1).strip() for match in re.finditer(r"^## (.+)$", text, re.MULTILINE)]


def section(text: str, heading: str) -> str:
    pattern = rf"^## {re.escape(heading)}\n(?P<body>.*?)(?=^## |\Z)"
    match = re.search(pattern, text, re.MULTILINE | re.DOTALL)
    return match.group("body") if match else ""


def current_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return f"v{data['project']['version']}"


def plugin_extras() -> set[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    optional = data["project"]["optional-dependencies"]
    return {
        extra
        for extra, requirements in optional.items()
        if extra not in {"all", "plugins-all"}
        and any("stigmem-plugin-" in req for req in requirements)
    }


def readme_plugin_rows(text: str) -> set[str]:
    body = section(text, "Plugins")
    rows = set()
    for match in re.finditer(r"`stigmem\[([^`\]]+)\]`", body):
        rows.add(match.group(1))
    return rows


def mcp_tier_failures(text: str) -> list[str]:
    body = section(text, "MCP + editor integrations")
    failures = []
    for line in body.splitlines():
        if not line.startswith("| ") or line.startswith("| ---") or "Validation tier" in line:
            continue
        cells = [cell.strip(" `") for cell in line.strip("|").split("|")]
        if len(cells) >= 2 and cells[1] not in ALLOWED_MCP_TIERS:
            failures.append(f"README.md: invalid MCP tier {cells[1]!r} in row: {line}")
    return failures


def version_failures(text: str) -> list[str]:
    expected = current_version()
    failures = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in re.finditer(r"v0\.9\.0a\d+", line):
            value = match.group(0)
            if value == expected or value == "v0.9.0a1":
                continue
            failures.append(f"README.md:{line_number}: expected {expected}, found {value}")
    return failures


def main() -> int:
    text = README.read_text(encoding="utf-8")
    failures: list[str] = []

    headings = h2_headings(text)
    if headings != REQUIRED_H2:
        failures.append(
            "README.md: H2 sections differ from required order\n"
            f"expected: {REQUIRED_H2}\nactual:   {headings}"
        )

    expected_plugins = plugin_extras()
    actual_plugins = readme_plugin_rows(text)
    if actual_plugins != expected_plugins:
        failures.append(
            "README.md: plugin rows differ from pyproject optional-dependencies\n"
            f"expected: {sorted(expected_plugins)}\nactual:   {sorted(actual_plugins)}"
        )

    adjacent = section(text, "Adjacent systems")
    for forbidden in sorted(ADJACENT_FORBIDDEN):
        if forbidden in adjacent:
            failures.append(f"README.md: adjacent systems section names {forbidden!r}")

    failures.extend(mcp_tier_failures(text))
    failures.extend(version_failures(text))

    if failures:
        print("readme-shape: failed", file=sys.stderr)
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("readme-shape: root README structure is aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

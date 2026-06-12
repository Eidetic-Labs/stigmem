from __future__ import annotations

import tomllib
from pathlib import Path

import yaml

_OPENCLAW_ROOT = Path(__file__).resolve().parents[1]
_REPO_ROOT = _OPENCLAW_ROOT.parents[1]


def test_package_readme_does_not_render_pre_reset_changelog() -> None:
    readme = (_OPENCLAW_ROOT / "README.md").read_text()

    assert "### v1.0" not in readme
    assert "stigmem-py>=1.0" not in readme
    assert "v0.9.0a11 alpha/evaluation surface" in readme
    assert "queued for the v0.9.0a2 artifact refresh" not in readme


def test_package_dependency_stays_on_active_alpha_line() -> None:
    pyproject = tomllib.loads((_OPENCLAW_ROOT / "pyproject.toml").read_text())

    assert "stigmem-py>=0.9.0a11,<1.0.0" in pyproject["project"]["dependencies"]


def test_clawhub_skill_keeps_alpha_warning_and_limitation_link() -> None:
    skill_text = (_OPENCLAW_ROOT / "skill" / "SKILL.md").read_text()
    frontmatter = yaml.safe_load(skill_text.split("---\n", 2)[1])

    install_packages = [
        step["package"]
        for step in frontmatter["metadata"]["openclaw"]["install"]
        if step.get("kind") == "uv"
    ]
    assert install_packages == ["stigmem-openclaw>=0.9.0a11,<1.0.0"]
    assert "v0.9.0aN evaluation only" in skill_text
    assert "LIMITATIONS.md#9-running-the-openclaw-bundled-adapter-as-is" in skill_text


def test_public_docs_link_openclaw_limitations() -> None:
    docs_paths = [
        _REPO_ROOT / "docs/docs/sdks/connectors/openclaw.md",
        _REPO_ROOT / "docs/docs/concepts/federation/federation.md",
    ]

    for docs_path in docs_paths:
        assert (
            "LIMITATIONS.md#9-running-the-openclaw-bundled-adapter-as-is"
            in docs_path.read_text()
        )

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class PluginPackage:
    slug: str
    package_name: str
    module_name: str
    entry_point: str
    feature_slug: str
    includes_sql: bool = False

    @property
    def package_dir(self) -> Path:
        return ROOT / "experimental" / self.slug

    @property
    def feature_dir(self) -> Path:
        return ROOT / "features" / self.feature_slug


SECURITY_SENSITIVE_PLUGINS = (
    PluginPackage(
        slug="lazy-instruction-discovery",
        package_name="stigmem-plugin-lazy-instruction-discovery",
        module_name="stigmem_plugin_lazy_instruction_discovery",
        entry_point="lazy-instruction-discovery",
        feature_slug="lazy-instruction-discovery",
        includes_sql=True,
    ),
    PluginPackage(
        slug="time-travel",
        package_name="stigmem-plugin-time-travel",
        module_name="stigmem_plugin_time_travel",
        entry_point="time-travel",
        feature_slug="time-travel",
    ),
    PluginPackage(
        slug="tombstones",
        package_name="stigmem-plugin-tombstones",
        module_name="stigmem_plugin_tombstones",
        entry_point="tombstones",
        feature_slug="tombstones",
        includes_sql=True,
    ),
    PluginPackage(
        slug="memory-garden-acl",
        package_name="stigmem-plugin-memory-garden-acl",
        module_name="stigmem_plugin_memory_garden_acl",
        entry_point="memory-garden-acl",
        feature_slug="memory-garden-acl",
    ),
    PluginPackage(
        slug="source-attestation",
        package_name="stigmem-plugin-source-attestation",
        module_name="stigmem_plugin_source_attestation",
        entry_point="source-attestation",
        feature_slug="source-attestation",
    ),
    PluginPackage(
        slug="multi-tenant",
        package_name="stigmem-plugin-multi-tenant",
        module_name="stigmem_plugin_multi_tenant",
        entry_point="multi-tenant",
        feature_slug="multi-tenant",
    ),
)


@pytest.mark.parametrize("plugin", SECURITY_SENSITIVE_PLUGINS)
def test_security_sensitive_plugin_package_metadata_is_publication_ready(
    plugin: PluginPackage,
) -> None:
    pyproject = plugin.package_dir / "pyproject.toml"
    readme = plugin.package_dir / "README.md"

    assert pyproject.is_file()
    assert readme.is_file()

    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data["project"]
    urls = project["urls"]
    build_system = data["build-system"]
    wheel = data["tool"]["hatch"]["build"]["targets"]["wheel"]
    sdist_include = data["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]

    assert project["name"] == plugin.package_name
    assert project["version"] == "0.1.0"
    assert project["readme"] == "README.md"
    assert project["requires-python"] == ">=3.11"
    assert project["license"]["text"] == "Apache-2.0"
    assert {"name": "Eidetic Labs", "email": "oss@eidetic-labs.ai"} in project["authors"]
    assert "pydantic>=2,<3" in project["dependencies"]
    assert "stigmem-node>=0.9.0a8,<1.0.0" in project["dependencies"]
    assert project["entry-points"]["stigmem.plugins"][plugin.entry_point] == (
        f"{plugin.module_name}:plugin_manifest"
    )

    assert "Development Status :: 3 - Alpha" in project["classifiers"]
    assert "License :: OSI Approved :: Apache Software License" in project["classifiers"]
    assert "Programming Language :: Python :: 3.11" in project["classifiers"]
    assert "Programming Language :: Python :: 3.12" in project["classifiers"]

    assert urls["Homepage"] == "https://github.com/eidetic-labs/stigmem"
    assert urls["Repository"] == "https://github.com/eidetic-labs/stigmem"
    assert urls["Issues"] == "https://github.com/eidetic-labs/stigmem/issues"
    assert f"/features/{plugin.feature_slug}" in urls["Documentation"]

    assert build_system["build-backend"] == "hatchling.build"
    assert "hatchling" in build_system["requires"]
    assert wheel["packages"] == [f"src/{plugin.module_name}"]
    assert wheel["sources"] == {"src": ""}

    assert "README.md" in sdist_include
    assert "STATUS.md" in sdist_include
    assert "security.md" in sdist_include
    assert f"src/{plugin.module_name}/**/*.py" in sdist_include
    if plugin.includes_sql:
        assert f"src/{plugin.module_name}/**/*.sql" in sdist_include


@pytest.mark.parametrize("plugin", SECURITY_SENSITIVE_PLUGINS)
def test_security_sensitive_plugin_feature_record_captures_publication_hold(
    plugin: PluginPackage,
) -> None:
    status = (plugin.feature_dir / "status.md").read_text(encoding="utf-8")
    evidence = (plugin.feature_dir / "evidence.md").read_text(encoding="utf-8")

    if "| Status | `deprecated`" in status:
        pytest.skip(f"{plugin.slug} graduated to core; no publication hold required")

    assert "| Publication state | `hold`" in status
    assert "dry-run evidence and maintainer clearance" in status
    assert "node/tests/plugins/test_security_plugin_publication_contract.py" in evidence
    assert "Package metadata, entry point, build metadata, README presence" in evidence

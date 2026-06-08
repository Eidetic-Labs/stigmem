from __future__ import annotations

import importlib
import inspect
import sys
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

import pytest

import stigmem_node.plugins.discovery as discovery
from stigmem_node.plugins import (
    ENTRY_POINT_GROUP,
    Allow,
    HookRegistry,
    PluginContext,
    PluginHealthStatus,
    PluginManifest,
    discover_plugin_manifests,
)

_FEATURE_DIR = Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl"
_SRC_DIR = _FEATURE_DIR / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

_PLUGIN = importlib.import_module("stigmem_plugin_memory_garden_acl")
MemoryGardenAclConfig = _PLUGIN.MemoryGardenAclConfig
PLUGIN_NAME = _PLUGIN.PLUGIN_NAME
plugin_manifest = _PLUGIN.plugin_manifest
T = TypeVar("T")


@dataclass(frozen=True)
class _Dist:
    metadata: dict[str, str]


@dataclass(frozen=True)
class _EntryPoint:
    name: str
    value: str
    loaded: Any
    group: str = ENTRY_POINT_GROUP
    dist: _Dist | None = None

    def load(self) -> Any:
        return self.loaded


class _EntryPointSet(list[_EntryPoint]):
    def select(self, *, group: str) -> _EntryPointSet:
        return _EntryPointSet([entry_point for entry_point in self if entry_point.group == group])


def test_pyproject_declares_stigmem_plugin_entry_point() -> None:
    data = tomllib.loads((_FEATURE_DIR / "pyproject.toml").read_text(encoding="utf-8"))

    assert data["project"]["name"] == PLUGIN_NAME
    assert (
        data["project"]["entry-points"]["stigmem.plugins"]["memory-garden-acl"]
        == "stigmem_plugin_memory_garden_acl:plugin_manifest"
    )


def test_manifest_declares_expected_boundary() -> None:
    data = tomllib.loads((_FEATURE_DIR / "pyproject.toml").read_text(encoding="utf-8"))
    manifest = plugin_manifest()

    assert isinstance(manifest, PluginManifest)
    assert manifest.name == PLUGIN_NAME
    assert manifest.version == data["project"]["version"]
    assert manifest.requires_stigmem == ">=0.9.0a3"
    assert manifest.config_schema is MemoryGardenAclConfig
    assert manifest.capabilities == frozenset(
        {
            "facts.read",
            "facts.write",
            "recall.read",
            "identity.read",
            "audit.emit",
            "config.read",
        }
    )
    assert set(manifest.hooks) == {
        "pre_assert_authorize",
        "pre_recall_authorize",
        "recall_filter",
    }
    assert manifest.routes == ()


def test_default_config_keeps_behavior_disabled() -> None:
    config = MemoryGardenAclConfig()

    assert config.enabled is False
    assert config.enforce_assert_authorize is False
    assert config.enforce_recall_authorize is False
    assert config.apply_recall_filter is False
    assert config.enable_oidc_permission_ceiling is False


def test_config_loads_environment_gates() -> None:
    config = _PLUGIN.config.load_config_from_env(
        {
            "STIGMEM_MEMORY_GARDEN_ACL_ENABLED": "true",
            "STIGMEM_MEMORY_GARDEN_ACL_ENFORCE_ASSERT_AUTHORIZE": "1",
            "STIGMEM_MEMORY_GARDEN_ACL_ENFORCE_RECALL_AUTHORIZE": "yes",
            "STIGMEM_MEMORY_GARDEN_ACL_APPLY_RECALL_FILTER": "on",
            "STIGMEM_MEMORY_GARDEN_ACL_ENABLE_OIDC_PERMISSION_CEILING": "true",
        }
    )

    assert config.enabled is True
    assert config.enforce_assert_authorize is True
    assert config.enforce_recall_authorize is True
    assert config.apply_recall_filter is True
    assert config.enable_oidc_permission_ceiling is True


def test_manifest_registers_with_hook_registry() -> None:
    registry = HookRegistry()
    manifest = plugin_manifest()

    registry.register_plugin(manifest)

    assert PLUGIN_NAME in registry.registered_plugins()
    assert isinstance(registry.fire_voting("pre_assert_authorize"), Allow)
    assert isinstance(registry.fire_voting("pre_recall_authorize"), Allow)
    assert registry.fire_filter_chain("recall_filter", ["fact"]) == ["fact"]
    reports = {report.plugin_name: report for report in registry.poll_plugin_health()}
    report = reports[PLUGIN_NAME]
    assert report.status == PluginHealthStatus.HEALTHY
    assert "plugin scaffold registered" in report.message


def test_public_handlers_document_stub_failure_mode_and_core_fallback() -> None:
    handlers = importlib.import_module("stigmem_plugin_memory_garden_acl.handlers")
    public_functions = {
        name: fn
        for name, fn in inspect.getmembers(handlers, inspect.isfunction)
        if fn.__module__ == handlers.__name__ and not name.startswith("_")
    }

    assert {"pre_assert_authorize", "pre_recall_authorize", "recall_filter"} <= set(
        public_functions
    )
    for name, fn in public_functions.items():
        doc = inspect.getdoc(fn) or ""
        assert doc, f"{name} must document its scaffold behavior"
        if name == "health_check":
            continue
        assert "Stub:" in doc
        assert "fail-open" in doc
        assert "Core fallback" in doc or "core fallback" in doc


def test_memory_garden_acl_plugin_hook_order_is_deterministic() -> None:
    calls: list[str] = []
    manifest = _recording_manifest(calls)
    registry = HookRegistry()

    def core_assert_authorize(_ctx: PluginContext, **_: object) -> Allow:
        calls.append("core:pre_assert_authorize")
        return Allow()

    def core_recall_authorize(_ctx: PluginContext, **_: object) -> Allow:
        calls.append("core:pre_recall_authorize")
        return Allow()

    def core_recall_filter(_ctx: PluginContext, value: list[str], **_: object) -> list[str]:
        calls.append("core:recall_filter")
        return value

    registry.register_core_handler(
        "pre_assert_authorize",
        core_assert_authorize,
        name="core.001.assert-authorize",
    )
    registry.register_core_handler(
        "pre_recall_authorize",
        core_recall_authorize,
        name="core.001.recall-authorize",
    )
    registry.register_core_handler("recall_filter", core_recall_filter, name="core.001.filter")
    registry.register_plugin(manifest)

    assert _handler_names(registry, "pre_assert_authorize") == (
        "core.001.assert-authorize",
        f"{PLUGIN_NAME}.pre_assert_authorize",
    )
    assert _handler_names(registry, "pre_recall_authorize") == (
        "core.001.recall-authorize",
        f"{PLUGIN_NAME}.pre_recall_authorize",
    )
    assert _handler_names(registry, "recall_filter") == (
        f"{PLUGIN_NAME}.recall_filter",
        "core.001.filter",
    )

    registry.fire_voting("pre_assert_authorize")
    registry.fire_voting("pre_recall_authorize")
    registry.fire_filter_chain("recall_filter", ["fact-1"])

    assert calls == [
        "core:pre_assert_authorize",
        "plugin:pre_assert_authorize",
        "core:pre_recall_authorize",
        "plugin:pre_recall_authorize",
        "plugin:recall_filter",
        "core:recall_filter",
    ]


def test_entry_point_factory_is_discoverable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "entry_points",
        lambda: _EntryPointSet(
            [
                _EntryPoint(
                    name="memory-garden-acl",
                    value="stigmem_plugin_memory_garden_acl:plugin_manifest",
                    loaded=plugin_manifest,
                    dist=_Dist({"Name": PLUGIN_NAME}),
                )
            ]
        ),
    )

    discovered = discover_plugin_manifests()

    # Graduated to core: the entry point is discovered but skipped via the
    # GRADUATED_PLUGINS denylist, so it registers nothing.
    assert discovered == ()


def _recording_manifest(calls: list[str]) -> PluginManifest:
    manifest = plugin_manifest()
    hooks: dict[str, Callable[..., Any]] = {}
    for hook_name, handler in manifest.hooks.items():
        hooks[hook_name] = _recording_handler(hook_name, handler, calls)
    return manifest.model_copy(update={"hooks": hooks})


def _recording_handler(
    hook_name: str,
    handler: Callable[..., T],
    calls: list[str],
) -> Callable[..., T]:
    def wrapper(ctx: PluginContext, *args: object, **kwargs: object) -> T:
        calls.append(f"plugin:{hook_name}")
        return handler(ctx, *args, **kwargs)

    wrapper.__name__ = handler.__name__
    return wrapper


def _handler_names(registry: HookRegistry, hook_name: str) -> tuple[str, ...]:
    return tuple(entry.handler_name for entry in registry.handlers_for(hook_name))

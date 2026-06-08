from __future__ import annotations

import importlib
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import pytest

from stigmem_node.memory_garden_acl_gate import (
    oidc_permission_ceiling_enabled,
    recall_filter_enabled,
)
from stigmem_node.plugins import Allow, HookRegistry, PluginContext, PluginManifest

_FEATURE_DIR = Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl"
_SRC_DIR = _FEATURE_DIR / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

_PLUGIN = importlib.import_module("stigmem_plugin_memory_garden_acl")
PLUGIN_NAME = _PLUGIN.PLUGIN_NAME
plugin_manifest = _PLUGIN.plugin_manifest
T = TypeVar("T")


def test_oidc_permission_ceiling_is_core_and_off_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Graduated to core: settings-gated, off by default (no plugin/env required).
    import stigmem_node.settings as settings_module

    monkeypatch.setattr(settings_module.settings, "oidc_permission_ceiling", False)
    assert oidc_permission_ceiling_enabled() is False
    monkeypatch.setattr(settings_module.settings, "oidc_permission_ceiling", True)
    assert oidc_permission_ceiling_enabled() is True


def test_recall_filter_is_core_default_on(monkeypatch: pytest.MonkeyPatch) -> None:
    # F-CONF-1: recall filtering graduated to core — on by default, independent of
    # the plugin/env; opt out only via the settings flag.
    import stigmem_node.settings as settings_module

    monkeypatch.setattr(settings_module.settings, "memory_garden_acl_recall_filter", True)
    assert recall_filter_enabled() is True
    monkeypatch.setattr(settings_module.settings, "memory_garden_acl_recall_filter", False)
    assert recall_filter_enabled() is False


def test_memory_garden_acl_hook_ordering_is_deterministic() -> None:
    calls: list[str] = []
    registry = HookRegistry()
    registry.register_core_handler(
        "pre_assert_authorize",
        _record_core_vote("core:pre_assert_authorize", calls),
        name="core.010.assert-authorize",
    )
    registry.register_core_handler(
        "pre_recall_authorize",
        _record_core_vote("core:pre_recall_authorize", calls),
        name="core.010.recall-authorize",
    )
    registry.register_core_handler(
        "recall_filter",
        _record_core_filter("core:recall_filter", calls),
        name="core.010.recall-filter",
    )
    registry.register_plugin(_recording_manifest(calls))

    assert _handler_names(registry, "pre_assert_authorize") == (
        "core.010.assert-authorize",
        f"{PLUGIN_NAME}.pre_assert_authorize",
    )
    assert _handler_names(registry, "pre_recall_authorize") == (
        "core.010.recall-authorize",
        f"{PLUGIN_NAME}.pre_recall_authorize",
    )
    assert _handler_names(registry, "recall_filter") == (
        f"{PLUGIN_NAME}.recall_filter",
        "core.010.recall-filter",
    )

    registry.fire_voting("pre_assert_authorize")
    registry.fire_voting("pre_recall_authorize")
    assert registry.fire_filter_chain("recall_filter", ["fact-1"]) == ["fact-1"]
    assert calls == [
        "core:pre_assert_authorize",
        "plugin:pre_assert_authorize",
        "core:pre_recall_authorize",
        "plugin:pre_recall_authorize",
        "plugin:recall_filter",
        "core:recall_filter",
    ]


def _record_core_vote(label: str, calls: list[str]) -> Callable[..., Allow]:
    def handler(_ctx: PluginContext, **_: object) -> Allow:
        calls.append(label)
        return Allow()

    return handler


def _record_core_filter(label: str, calls: list[str]) -> Callable[..., list[str]]:
    def handler(_ctx: PluginContext, value: list[str], **_: object) -> list[str]:
        calls.append(label)
        return value

    return handler


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

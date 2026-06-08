"""Graduated plugins are discovered but skipped (denylist safeguard)."""

import importlib
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import stigmem_node.plugins.discovery as discovery

_SRC = Path(__file__).resolve().parents[3] / "experimental" / "memory-garden-acl" / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
_PLUGIN = importlib.import_module("stigmem_plugin_memory_garden_acl")


def test_graduated_plugin_is_discovered_but_skipped(monkeypatch, caplog):
    fake_ep = SimpleNamespace(
        name="memory-garden-acl",
        value="stigmem_plugin_memory_garden_acl:plugin_manifest",
        load=lambda: _PLUGIN.plugin_manifest,
    )
    monkeypatch.setattr(discovery, "_entry_points_for_group", lambda group: [fake_ep])

    with caplog.at_level(logging.WARNING, logger="stigmem.plugins"):
        result = discovery.discover_plugin_manifests()

    assert result == ()  # graduated plugin not registered
    assert "graduated into core" in caplog.text


def test_memory_garden_acl_is_on_the_graduated_denylist():
    assert "stigmem-plugin-memory-garden-acl" in discovery.GRADUATED_PLUGINS

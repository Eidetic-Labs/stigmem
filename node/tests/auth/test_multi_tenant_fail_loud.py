"""F-ID-1: loud warning when a non-default tenant can't actually be isolated.

The key is still registered (single-tenant installs intentionally collapse
non-default tenants to one partition) — this only removes the *silence*.
"""

import logging

import stigmem_node.multi_tenant_gate as mtg


def test_default_tenant_emits_no_warning(monkeypatch, caplog):
    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: False)
    with caplog.at_level(logging.WARNING, logger="stigmem.tenant"):
        assert mtg.warn_if_tenant_not_isolatable("default") is False
    assert "SECURITY WARNING" not in caplog.text


def test_nondefault_tenant_warns_without_plugin(monkeypatch, caplog):
    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: False)
    with caplog.at_level(logging.WARNING, logger="stigmem.tenant"):
        assert mtg.warn_if_tenant_not_isolatable("acme") is True
    assert "not isolated" in caplog.text.lower()


def test_nondefault_tenant_no_warning_with_plugin(monkeypatch, caplog):
    monkeypatch.setattr(mtg, "multi_tenant_plugin_registered", lambda: True)
    with caplog.at_level(logging.WARNING, logger="stigmem.tenant"):
        assert mtg.warn_if_tenant_not_isolatable("acme") is False
    assert "SECURITY WARNING" not in caplog.text


def test_plugin_absent_in_clean_registry():
    # The multi-tenant plugin is a separate package, not installed in node tests.
    assert mtg.multi_tenant_plugin_registered() is False

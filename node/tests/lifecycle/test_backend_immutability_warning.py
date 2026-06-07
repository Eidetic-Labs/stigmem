"""P-DESTROY-1 honesty: warn at boot when the backend lacks immutability triggers."""

import logging

import stigmem_node.main as main_mod


def test_sqlite_backend_no_warning(monkeypatch, caplog):
    monkeypatch.setattr(main_mod.settings, "storage_backend", "sqlite")
    with caplog.at_level(logging.WARNING, logger="stigmem"):
        main_mod._warn_if_backend_immutability_unenforced()
    assert "facts immutability" not in caplog.text


def test_postgres_backend_warns(monkeypatch, caplog):
    monkeypatch.setattr(main_mod.settings, "storage_backend", "postgres")
    with caplog.at_level(logging.WARNING, logger="stigmem"):
        main_mod._warn_if_backend_immutability_unenforced()
    assert "does NOT enforce database-level" in caplog.text
    assert "postgres" in caplog.text


def test_libsql_backend_warns(monkeypatch, caplog):
    monkeypatch.setattr(main_mod.settings, "storage_backend", "libsql")
    with caplog.at_level(logging.WARNING, logger="stigmem"):
        main_mod._warn_if_backend_immutability_unenforced()
    assert "does NOT enforce database-level" in caplog.text

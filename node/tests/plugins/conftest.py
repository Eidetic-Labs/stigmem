"""Fixtures shared across the plugins test package."""

from __future__ import annotations

from collections.abc import Generator

import pytest

import stigmem_node.db as db_mod
import stigmem_node.settings as settings_module
from stigmem_node.db import apply_migrations
from stigmem_node.settings import Settings

# Re-export helpers from the parent conftest so that test modules in this
# package that do ``from conftest import ...`` continue to find them here
# (Python's conftest resolution picks the nearest conftest.py first).
from tests.conftest import _make_enc_settings, _patch_settings, _restore_settings

__all__ = ["_make_enc_settings", "_patch_settings", "_restore_settings"]


@pytest.fixture()
def migrated_db(tmp_path: object, monkeypatch: pytest.MonkeyPatch) -> Generator[str, None, None]:
    """Provide a fully-migrated SQLite DB and patch db_mod.settings to point at it.

    Tests that do not request the ``client`` fixture (and therefore skip the
    normal ``tmp_db`` → ``client`` setup path) must request this fixture
    explicitly if they invoke code paths that call ``db()`` internally — e.g.
    any recall-ranking path that touches ``caller_visible_gardens``.

    Using ``monkeypatch`` ensures the settings override is automatically
    reverted at test teardown with no manual restore needed.
    """
    db_file = str(tmp_path) + "/test.db"  # type: ignore[operator]
    apply_migrations(db_path=db_file)
    test_settings = Settings(db_path=db_file, auth_required=False, node_url="http://testnode")
    monkeypatch.setattr(settings_module, "settings", test_settings)
    monkeypatch.setattr(db_mod, "settings", test_settings)
    yield db_file

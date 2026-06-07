"""F-ID-4: warn at boot when legacy SHA-256 hash acceptance is unbounded."""

import logging
from datetime import UTC, datetime

import stigmem_node.main as main_mod


def test_unbounded_acceptance_warns(monkeypatch, caplog):
    monkeypatch.setattr(main_mod.settings, "legacy_sha256_accept_until", None)
    with caplog.at_level(logging.WARNING, logger="stigmem"):
        main_mod._warn_if_legacy_sha256_acceptance_unbounded()
    assert "legacy SHA-256" in caplog.text
    assert "no cutoff" in caplog.text


def test_bounded_acceptance_no_warning(monkeypatch, caplog):
    monkeypatch.setattr(
        main_mod.settings,
        "legacy_sha256_accept_until",
        datetime(2026, 12, 31, tzinfo=UTC),
    )
    with caplog.at_level(logging.WARNING, logger="stigmem"):
        main_mod._warn_if_legacy_sha256_acceptance_unbounded()
    assert "legacy SHA-256" not in caplog.text

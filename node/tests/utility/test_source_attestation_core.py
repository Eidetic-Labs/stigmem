"""Source ↔ identity attestation core evaluation (P-INJ-1)."""

import types

import stigmem_node.source_attestation as sa

_A = "stigmem://testnode/agent/admin"
_X = "stigmem://testnode/user/x"


def _identity(uri: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(entity_uri=uri)


def test_attested_true_when_source_matches_principal(monkeypatch):
    monkeypatch.setattr(sa, "_live_settings", lambda: types.SimpleNamespace(auth_required=True))
    assert sa.evaluate_source_attested(_A, _identity(_A)) is True


def test_attested_false_when_source_mismatch(monkeypatch):
    monkeypatch.setattr(sa, "_live_settings", lambda: types.SimpleNamespace(auth_required=True))
    assert sa.evaluate_source_attested(_X, _identity(_A)) is False


def test_attested_none_when_auth_disabled(monkeypatch):
    monkeypatch.setattr(sa, "_live_settings", lambda: types.SimpleNamespace(auth_required=False))
    assert sa.evaluate_source_attested(_X, _identity(_A)) is None


def test_enforce_reads_settings_flag(monkeypatch):
    monkeypatch.setattr(
        sa, "_live_settings", lambda: types.SimpleNamespace(source_attestation_enforce=True)
    )
    assert sa.source_attestation_enforce_enabled() is True
    monkeypatch.setattr(
        sa, "_live_settings", lambda: types.SimpleNamespace(source_attestation_enforce=False)
    )
    assert sa.source_attestation_enforce_enabled() is False

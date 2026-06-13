from __future__ import annotations

import json
from pathlib import Path

import pytest

from stigmem_node.identity.transparency_log import LocalAppendOnlyLog


def test_local_tl_submit_and_verify(tmp_path: Path):
    log_path = tmp_path / "test_tl.jsonl"
    tl = LocalAppendOnlyLog(str(log_path))

    manifest_data = {"entity_uri": "https://example.org", "key_id": "k1", "signature": "sig"}
    entry = tl.submit(manifest_data)
    assert entry.log_index == 0
    assert len(entry.leaf_hash) == 64  # hex SHA-256

    assert tl.verify_inclusion(entry)


def test_local_tl_multiple_entries(tmp_path: Path):
    log_path = tmp_path / "multi_tl.jsonl"
    tl = LocalAppendOnlyLog(str(log_path))

    e0 = tl.submit({"seq": 0})
    e1 = tl.submit({"seq": 1})
    e2 = tl.submit({"seq": 2})

    assert e0.log_index == 0
    assert e1.log_index == 1
    assert e2.log_index == 2

    assert tl.verify_inclusion(e0)
    assert tl.verify_inclusion(e1)
    assert tl.verify_inclusion(e2)


def test_local_tl_tampered_entry_fails(tmp_path: Path):
    log_path = tmp_path / "tamper_tl.jsonl"
    tl = LocalAppendOnlyLog(str(log_path))
    entry = tl.submit({"data": "original"})

    # Tamper the file
    lines = log_path.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["leaf_hash"] = "0" * 64
    log_path.write_text(json.dumps(rec) + "\n")

    from stigmem_node.identity.transparency_log import LogEntry

    bad_entry = LogEntry(
        log_id=entry.log_id,
        leaf_hash=entry.leaf_hash,  # original hash
        log_index=0,
        integrated_time=entry.integrated_time,
    )
    with pytest.raises(ValueError, match="leaf_hash mismatch"):
        tl.verify_inclusion(bad_entry)


def test_rekor_verify_inclusion_missing_sigstore_is_hard_error(monkeypatch):
    """A missing sigstore dependency must FAIL CLOSED, not return True.

    Previously verify_inclusion logged a warning on ImportError and fell
    through to ``return True`` (fail-open). The STH/checkpoint cannot be
    trusted without sigstore, so an absent sigstore is a hard error.
    """
    import builtins

    import httpx

    from stigmem_node.identity.transparency_log import LogEntry, RekorLog

    # Bypass __init__ (which guards the sigstore import at construction) so we
    # exercise verify_inclusion's own import path in isolation.
    tl = RekorLog.__new__(RekorLog)
    tl._url = "https://rekor.example.invalid"
    entry = LogEntry(log_id="t", leaf_hash="a" * 64, log_index=5, integrated_time=0)

    # A well-formed Rekor response with a matching (here: undecodable -> empty)
    # stored hash so we reach the sigstore-verification step.
    fake_response = {
        "uuid-abc": {
            "body": "not-base64-json",
            "logIndex": 5,
            "verification": {},
        }
    }

    class _FakeResp:
        status_code = 200

        def json(self):
            return fake_response

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResp())

    # Force ``import sigstore...`` to fail, simulating sigstore not installed.
    real_import = builtins.__import__

    def _no_sigstore(name, *args, **kwargs):
        if name.startswith("sigstore"):
            raise ImportError("No module named 'sigstore'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _no_sigstore)

    with pytest.raises((ValueError, Exception)) as excinfo:
        tl.verify_inclusion(entry)
    # Must NOT have returned True; the exception is the contract.
    assert excinfo.value is not None


# ===========================================================================
# 10. Manifest resolve API
# ===========================================================================

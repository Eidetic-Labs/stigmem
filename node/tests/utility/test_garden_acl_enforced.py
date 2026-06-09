"""Garden ACL enforcement is fail-closed + batched (secure-path for M3/F-3).

The operator disable flag must NOT be able to turn off the garden access
boundary once gardens-with-members exist, and the per-caller membership lookup
must be a single batched query (no per-fact DB lookup).
"""

import types

import stigmem_node.memory_garden_acl_gate as gate


def _settings(flag: bool) -> types.SimpleNamespace:
    return types.SimpleNamespace(memory_garden_acl_recall_filter=flag)


def test_enforced_when_flag_on(monkeypatch) -> None:
    monkeypatch.setattr(gate, "_live_settings", lambda: _settings(True))
    # Should not even need to consult gardens-exist when the flag is on.
    monkeypatch.setattr(gate, "gardens_with_members_exist", lambda: False)
    assert gate.garden_acl_enforced() is True


def test_disabled_when_flag_off_and_no_gardens(monkeypatch) -> None:
    monkeypatch.setattr(gate, "_live_settings", lambda: _settings(False))
    monkeypatch.setattr(gate, "gardens_with_members_exist", lambda: False)
    # No gardens to protect → the filter is a pure no-op, so "disabled" is safe.
    assert gate.garden_acl_enforced() is False


def test_failclosed_when_flag_off_but_gardens_exist(monkeypatch) -> None:
    # THE security property: the off-switch cannot disable the boundary once a
    # real garden access boundary exists.
    monkeypatch.setattr(gate, "_live_settings", lambda: _settings(False))
    monkeypatch.setattr(gate, "gardens_with_members_exist", lambda: True)
    assert gate.garden_acl_enforced() is True


class _Cursor:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def fetchall(self) -> list[dict]:
        return self._rows


class _Conn:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.calls = 0

    def execute(self, *_a) -> _Cursor:
        self.calls += 1
        return _Cursor(self._rows)

    def __enter__(self) -> "_Conn":
        return self

    def __exit__(self, *_a) -> bool:
        return False


def test_caller_visible_gardens_is_one_batched_query(monkeypatch) -> None:
    conn = _Conn([{"garden_id": "A"}, {"garden_id": "B"}])
    monkeypatch.setattr(gate, "db", lambda: conn)
    out = gate.caller_visible_gardens(types.SimpleNamespace(entity_uri="user:x"))
    assert out == frozenset({"A", "B"})
    assert conn.calls == 1  # single query, not per-fact


def test_caller_visible_gardens_empty_without_identity(monkeypatch) -> None:
    out = gate.caller_visible_gardens(types.SimpleNamespace())  # no entity_uri
    assert out == frozenset()

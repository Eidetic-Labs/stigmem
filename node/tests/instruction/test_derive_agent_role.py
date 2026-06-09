"""_derive_agent_role escapes LIKE metacharacters (audit F-10).

A caller-supplied agent_id was interpolated into a `LIKE '%{agent_id}%'`
pattern, so `%`/`_` acted as wildcards and `agent_id="%"` matched any key
row. The agent_id must be matched literally.
"""

import sqlite3

from stigmem_node.routes.instruction import _derive_agent_role


def _conn_with(entity_uri: str) -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE api_keys (entity_uri TEXT)")
    conn.execute("INSERT INTO api_keys (entity_uri) VALUES (?)", (entity_uri,))
    return conn


def test_wildcard_does_not_match_arbitrary_row() -> None:
    conn = _conn_with("agent:victim")
    # "%" must be treated literally — no entity_uri contains a literal "%".
    assert _derive_agent_role("%", conn) == "Agent"


def test_underscore_is_literal() -> None:
    conn = _conn_with("agent:victim")
    # "_" would otherwise match any single char ("v_ctim"); must be literal.
    assert _derive_agent_role("v_ctim", conn) == "Agent"


def test_legitimate_substring_still_resolves() -> None:
    conn = _conn_with("stigmem://org/agent/cto")
    assert _derive_agent_role("cto", conn) == "CTO"

"""Agent-access authorization is whole-segment, not substring (audit H3 / F-4).

`_check_agent_access` previously granted access when `agent_id` was a *substring*
of the caller's entity_uri, so `agent:cto-shadow` could access agent `cto`'s
instruction surface. Access must require a whole path/scheme segment match.
"""

import types

import pytest
from fastapi import HTTPException

import stigmem_node.routes.instruction as instr


def _id(uri: str, admin: bool = False) -> types.SimpleNamespace:
    return types.SimpleNamespace(entity_uri=uri, is_admin=lambda: admin)


def test_exact_segment_grants_access() -> None:
    # Each of these has `cto` as a whole segment — access allowed (no raise).
    instr._check_agent_access(_id("stigmem://deploy/agent/cto"), "cto")
    instr._check_agent_access(_id("agent:cto"), "cto")
    instr._check_agent_access(_id("cto"), "cto")


def test_substring_does_not_grant_access() -> None:
    # "cto" must NOT match the longer slug "cto-shadow" (substring abuse).
    with pytest.raises(HTTPException) as exc:
        instr._check_agent_access(_id("agent:cto-shadow"), "cto")
    assert exc.value.status_code == 403


def test_partial_segment_denied() -> None:
    with pytest.raises(HTTPException) as exc:
        instr._check_agent_access(_id("agent:cto"), "c")
    assert exc.value.status_code == 403


def test_admin_bypasses() -> None:
    # Admin is allowed regardless of entity_uri.
    instr._check_agent_access(_id("anything", admin=True), "whatever")

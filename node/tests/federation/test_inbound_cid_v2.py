"""Federation inbound CID verification under CID v2 (binds interpret_as)."""

import hashlib
import json

import pytest

from stigmem_node.cid import compute_cid
from stigmem_node.federation.federation_ingest import (
    FederationIntegrityError,
    _encode_v,
    _verify_inbound_cid,
)


def _fact(interpret_as: str, cid: str) -> dict:
    return {
        "id": "f1",
        "entity": "user:1",
        "relation": "prefers",
        "value": {"type": "string", "v": "tea", "interpret_as": interpret_as},
        "source": "agent:a",
        "scope": "company",
        "confidence": 1.0,
        "cid": cid,
    }


def _v2_cid(interpret_as: str) -> str:
    value = {"type": "string", "v": "tea", "interpret_as": interpret_as}
    return compute_cid(
        entity="user:1",
        relation="prefers",
        value_type="string",
        value_v=_encode_v(value),
        source="agent:a",
        scope="company",
        confidence=1.0,
        interpret_as=interpret_as,
    )


def test_inbound_v2_instruction_fact_verifies():
    cid = _v2_cid("instruction")
    assert _verify_inbound_cid(_fact("instruction", cid), "peer:1") == cid


def test_inbound_interpret_as_flip_rejected():
    # CID bound `content`; the fact now claims `instruction` -> recompute mismatch.
    cid = _v2_cid("content")
    with pytest.raises(FederationIntegrityError):
        _verify_inbound_cid(_fact("instruction", cid), "peer:1")


def test_inbound_v1_peer_cid_rejected():
    # A v1 peer's CID (7-field body, no interpret_as) is rejected under v2.
    value = {"type": "string", "v": "tea"}
    body = {
        "confidence": 1.0,
        "entity": "user:1",
        "relation": "prefers",
        "scope": "company",
        "source": "agent:a",
        "value_type": "string",
        "value_v": _encode_v(value),
    }
    v1 = "sha256:" + hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    with pytest.raises(FederationIntegrityError):
        _verify_inbound_cid(_fact("content", v1), "peer:1")

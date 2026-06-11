"""Phase 2c W5.1 — reject cross-origin wire-id collision on federated ingest (F-1 residual).

A peer must NOT be able to pre-occupy (overwrite or silently-dedup-alias) another
origin's fact `id` by sending a different payload under the same wire `id`.  If an
inbound fact re-uses an id that already exists locally with a DIFFERENT cid, the
ingest must be REJECTED (audited) and the existing row left untouched.

Same-cid re-pull remains a no-op (idempotent pull; spec §5.8).
Global guard: `facts.id` is a GLOBAL PRIMARY KEY (one fact = one tenant), so the
collision check is global — a cross-tenant same-id/different-cid is still a collision
and must be caught cleanly as a FederationIntegrityError (not a raw sqlite UNIQUE error).
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import uuid
from typing import Any

import pytest

# conftest is at tests/ (one level above); add it to the path for FedNode import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from conftest import FedNode  # noqa: E402

from stigmem_node.cid import compute_cid
from stigmem_node.db import db
from stigmem_node.federation.federation_ingest import (
    FederationIntegrityError,
    _encode_v,
    ingest_fact,
)

from .helpers import make_federated_fact

SENDER = "stigmem://peer-attacker"
TENANT = "default"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fact(
    *,
    fact_id: str | None = None,
    entity: str = "test:entity",
    relation: str = "test:relation",
    value: str = "original-value",
    scope: str = "public",
) -> dict[str, Any]:
    fact = make_federated_fact(entity=entity, relation=relation, value=value, scope=scope)
    if fact_id is not None:
        fact["id"] = fact_id
    return fact


def _add_cid(fact: dict[str, Any]) -> dict[str, Any]:
    """Compute + attach the correct CID so _verify_inbound_cid passes."""
    v = fact["value"]
    fact["cid"] = compute_cid(
        entity=fact["entity"],
        relation=fact["relation"],
        value_type=v["type"],
        value_v=_encode_v(v),
        source=fact["source"],
        scope=fact["scope"],
        confidence=float(fact.get("confidence", 1.0)),
        interpret_as=str(v.get("interpret_as", "content")),
    )
    return fact


def _seed_row(
    *,
    fact_id: str,
    entity: str = "test:entity",
    relation: str = "test:relation",
    value: str = "original-value",
    scope: str = "public",
    tenant_id: str = TENANT,
) -> str:
    """Seed a fact row via ingest_fact (ensures CID is byte-for-byte identical to what
    _verify_inbound_cid will compute on a matching re-pull).  Returns the stored CID."""
    fact = _add_cid(
        _make_fact(fact_id=fact_id, entity=entity, relation=relation, value=value, scope=scope)
    )
    ingest_fact(fact, sender_node_id=SENDER, tenant_id=tenant_id)
    stored = _stored_cid(fact_id, tenant_id=tenant_id)
    assert stored is not None, "seed via ingest_fact must write a cid"
    return stored


def _stored_cid(fact_id: str, tenant_id: str = TENANT) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT cid FROM facts WHERE id = ? AND tenant_id = ?",
            (fact_id, tenant_id),
        ).fetchone()
    return row["cid"] if row else None


def _stored_value(fact_id: str, tenant_id: str = TENANT) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT value_v FROM facts WHERE id = ? AND tenant_id = ?",
            (fact_id, tenant_id),
        ).fetchone()
    return row["value_v"] if row else None


def _integrity_audit(fact_id: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            """SELECT event_type, fact_id, source, detail
               FROM fact_audit_log
               WHERE fact_id = ?
               AND event_type = 'federation_integrity_rejected'
               ORDER BY seq DESC
               LIMIT 1""",
            (fact_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "event_type": row["event_type"],
        "fact_id": row["fact_id"],
        "source": row["source"],
        "detail": json.loads(row["detail"]),
    }


# ---------------------------------------------------------------------------
# (a) Different cid → REJECT + original row untouched + audit emitted
# ---------------------------------------------------------------------------


def test_wire_id_collision_different_cid_raises_integrity_error(fed_node: FedNode) -> None:
    """An inbound fact that reuses an existing wire id with DIFFERENT content must raise."""
    fact_id = str(uuid.uuid4())
    _seed_row(fact_id=fact_id, value="original-value")

    # Build a colliding fact: same wire id, different value → different cid
    attacker_fact = _add_cid(
        _make_fact(fact_id=fact_id, value="ATTACKER-value")
    )

    with pytest.raises(FederationIntegrityError) as exc_info:
        ingest_fact(attacker_fact, sender_node_id=SENDER, tenant_id=TENANT)

    exc = exc_info.value
    assert exc.fact_id == fact_id
    assert exc.sender_node_id == SENDER
    assert "wire_id_collision" in exc.reason


def test_wire_id_collision_original_row_untouched(fed_node: FedNode) -> None:
    """The existing row MUST NOT be mutated when a collision is detected."""
    fact_id = str(uuid.uuid4())
    original_cid = _seed_row(fact_id=fact_id, value="original-value")

    attacker_fact = _add_cid(_make_fact(fact_id=fact_id, value="ATTACKER-value"))

    with pytest.raises(FederationIntegrityError):
        ingest_fact(attacker_fact, sender_node_id=SENDER, tenant_id=TENANT)

    assert _stored_cid(fact_id) == original_cid
    assert _stored_value(fact_id) == "original-value"


def test_wire_id_collision_emits_integrity_audit(fed_node: FedNode) -> None:
    """A wire-id collision must emit a 'federation_integrity_rejected' audit event."""
    fact_id = str(uuid.uuid4())
    _seed_row(fact_id=fact_id, value="original-value")

    attacker_fact = _add_cid(_make_fact(fact_id=fact_id, value="ATTACKER-value"))

    with pytest.raises(FederationIntegrityError):
        ingest_fact(attacker_fact, sender_node_id=SENDER, tenant_id=TENANT)

    audit = _integrity_audit(fact_id)
    assert audit is not None
    assert audit["event_type"] == "federation_integrity_rejected"
    assert audit["fact_id"] == fact_id
    assert audit["source"] == SENDER
    assert audit["detail"]["sender_node_id"] == SENDER
    assert audit["detail"]["reason"] == "wire_id_collision"


# ---------------------------------------------------------------------------
# (b) Same cid → no-op (legitimate re-pull), no raise
# ---------------------------------------------------------------------------


def test_same_wire_id_same_cid_noop(fed_node: FedNode) -> None:
    """A re-pull of the exact same fact (same id + same cid) must be a no-op, not raise."""
    fact_id = str(uuid.uuid4())
    _seed_row(fact_id=fact_id, value="original-value")

    # Build the same fact with the matching CID
    same_fact = _add_cid(_make_fact(fact_id=fact_id, value="original-value"))

    result = ingest_fact(same_fact, sender_node_id=SENDER, tenant_id=TENANT)
    assert result is False  # no-op, already ingested


def test_same_wire_id_same_cid_no_audit(fed_node: FedNode) -> None:
    """A legitimate re-pull must NOT emit a rejection audit event."""
    fact_id = str(uuid.uuid4())
    _seed_row(fact_id=fact_id, value="original-value")

    same_fact = _add_cid(_make_fact(fact_id=fact_id, value="original-value"))
    ingest_fact(same_fact, sender_node_id=SENDER, tenant_id=TENANT)

    assert _integrity_audit(fact_id) is None


# ---------------------------------------------------------------------------
# (c) Overwrite attempt does NOT mutate the existing row
# ---------------------------------------------------------------------------


def test_overwrite_attempt_does_not_mutate_row(fed_node: FedNode) -> None:
    """Triple-check: even if ingest_fact silently eats the exception, the row is unchanged."""
    fact_id = str(uuid.uuid4())
    original_cid = _seed_row(fact_id=fact_id, value="original-value")

    attacker_fact = _add_cid(_make_fact(fact_id=fact_id, value="OVERWRITE-attempt"))

    with contextlib.suppress(FederationIntegrityError):
        ingest_fact(attacker_fact, sender_node_id=SENDER, tenant_id=TENANT)

    assert _stored_cid(fact_id) == original_cid
    assert _stored_value(fact_id) == "original-value"


# ---------------------------------------------------------------------------
# (d) Dedup guard is GLOBAL: a wire id collision across tenants is ALSO caught
#     cleanly as FederationIntegrityError (not a raw sqlite UNIQUE error)
# ---------------------------------------------------------------------------


def test_cross_tenant_wire_id_collision_rejected_cleanly(fed_node: FedNode) -> None:
    """facts.id is a GLOBAL PRIMARY KEY — one fact belongs to exactly one tenant.
    A cross-tenant same-id/different-cid ingest is therefore a real collision/attack
    and MUST be caught by the guard as a typed FederationIntegrityError (audited),
    NOT allowed to fall through to a raw sqlite UNIQUE IntegrityError.

    This test seeds fact_id=X in tenant-A, then attempts to ingest the SAME wire id
    with DIFFERENT content targeted at tenant-B.  The dedup SELECT is global
    (WHERE id = ?) so the guard fires and raises FederationIntegrityError.
    """
    fact_id = str(uuid.uuid4())
    # Seed the fact in TENANT (tenant-A)
    _seed_row(fact_id=fact_id, value="tenant-a-value", tenant_id=TENANT)

    # Attempt to ingest the same wire id (different value/cid) into a different tenant.
    # The collision guard is global, so it MUST catch this and raise our typed error.
    other_tenant = "other-tenant"
    other_fact = _add_cid(_make_fact(fact_id=fact_id, value="tenant-b-value"))

    with pytest.raises(FederationIntegrityError) as exc_info:
        ingest_fact(other_fact, sender_node_id=SENDER, tenant_id=other_tenant)

    exc = exc_info.value
    assert exc.fact_id == fact_id
    assert exc.sender_node_id == SENDER
    assert exc.reason == "wire_id_collision", (
        "cross-tenant wire-id collision must be caught by the typed guard "
        "(global dedup SELECT), not a raw sqlite IntegrityError"
    )


def test_cross_tenant_wire_id_collision_emits_audit(fed_node: FedNode) -> None:
    """A cross-tenant wire-id collision must emit a 'federation_integrity_rejected'
    audit event (same auditing requirement as same-tenant collision).
    """
    fact_id = str(uuid.uuid4())
    _seed_row(fact_id=fact_id, value="tenant-a-value", tenant_id=TENANT)

    other_fact = _add_cid(_make_fact(fact_id=fact_id, value="tenant-b-value"))

    with pytest.raises(FederationIntegrityError):
        ingest_fact(other_fact, sender_node_id=SENDER, tenant_id="other-tenant")

    audit = _integrity_audit(fact_id)
    assert audit is not None
    assert audit["event_type"] == "federation_integrity_rejected"
    assert audit["fact_id"] == fact_id
    assert audit["detail"]["reason"] == "wire_id_collision"

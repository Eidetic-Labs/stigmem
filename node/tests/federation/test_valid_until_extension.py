from __future__ import annotations

import json
import uuid

import pytest

from stigmem_node.db import db
from stigmem_node.federation.federation_ingest import (
    FederationValidUntilExtensionError,
    ingest_fact,
)

from .helpers import make_federated_fact

SENDER = "stigmem://peer-b"


def _fact(*, fact_id: str | None = None, valid_until: str | None) -> dict:
    fact = make_federated_fact(
        entity="user:valid-until",
        relation="profile:status",
        value="active",
    )
    fact["id"] = fact_id or str(uuid.uuid4())
    fact["valid_until"] = valid_until
    return fact


def _seed_fact(*, fact_id: str, valid_until: str | None) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, timestamp,
                valid_until, confidence, scope, tenant_id, hlc)
               VALUES (?, 'user:valid-until', 'profile:status', 'string',
                       'active', ?, '2026-05-01T00:00:00+00:00', ?,
                       1.0, 'public', 'default', '0.000')""",
            (fact_id, SENDER, valid_until),
        )


def _stored_valid_until(fact_id: str) -> str | None:
    with db() as conn:
        row = conn.execute("SELECT valid_until FROM facts WHERE id = ?", (fact_id,)).fetchone()
    return row["valid_until"]


def _rejection_audit(fact_id: str) -> dict | None:
    with db() as conn:
        row = conn.execute(
            """SELECT event_type, fact_id, source, detail
               FROM fact_audit_log
               WHERE fact_id = ?
               AND event_type = 'federation_valid_until_extension_rejected'
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


def test_first_observation_accepts_and_idempotent_replay_noops(fed_node) -> None:
    fact = _fact(valid_until="2027-01-01T00:00:00+00:00")

    assert ingest_fact(fact, sender_node_id=SENDER, tenant_id="default") is True
    assert ingest_fact(fact, sender_node_id=SENDER, tenant_id="default") is False

    assert _stored_valid_until(fact["id"]) == "2027-01-01T00:00:00+00:00"
    assert _rejection_audit(fact["id"]) is None


def test_valid_until_extension_rejects_and_audits(fed_node) -> None:
    fact_id = str(uuid.uuid4())
    _seed_fact(fact_id=fact_id, valid_until="2027-01-01T00:00:00+00:00")

    with pytest.raises(FederationValidUntilExtensionError):
        ingest_fact(
            _fact(fact_id=fact_id, valid_until="2027-06-01T00:00:00+00:00"),
            sender_node_id=SENDER, tenant_id="default",
        )

    assert _stored_valid_until(fact_id) == "2027-01-01T00:00:00+00:00"
    audit = _rejection_audit(fact_id)
    assert audit is not None
    assert audit["event_type"] == "federation_valid_until_extension_rejected"
    assert audit["fact_id"] == fact_id
    assert audit["source"] == SENDER
    assert audit["detail"]["sender_node_id"] == SENDER
    assert audit["detail"]["stored_valid_until"] == "2027-01-01T00:00:00+00:00"
    assert audit["detail"]["incoming_valid_until"] == "2027-06-01T00:00:00+00:00"


def test_valid_until_shrinkage_noops_without_mutating_local_value(fed_node) -> None:
    fact_id = str(uuid.uuid4())
    _seed_fact(fact_id=fact_id, valid_until="2027-06-01T00:00:00+00:00")

    assert (
        ingest_fact(
            _fact(fact_id=fact_id, valid_until="2027-01-01T00:00:00+00:00"),
            sender_node_id=SENDER, tenant_id="default",
        )
        is False
    )

    assert _stored_valid_until(fact_id) == "2027-06-01T00:00:00+00:00"
    assert _rejection_audit(fact_id) is None


def test_local_unbounded_visibility_wins_over_incoming_finite_expiry(fed_node) -> None:
    fact_id = str(uuid.uuid4())
    _seed_fact(fact_id=fact_id, valid_until=None)

    assert (
        ingest_fact(
            _fact(fact_id=fact_id, valid_until="2027-01-01T00:00:00+00:00"),
            sender_node_id=SENDER, tenant_id="default",
        )
        is False
    )

    assert _stored_valid_until(fact_id) is None
    assert _rejection_audit(fact_id) is None


def test_incoming_unbounded_visibility_rejects_when_local_has_expiry(fed_node) -> None:
    fact_id = str(uuid.uuid4())
    _seed_fact(fact_id=fact_id, valid_until="2027-01-01T00:00:00+00:00")

    with pytest.raises(FederationValidUntilExtensionError):
        ingest_fact(
            _fact(fact_id=fact_id, valid_until=None), sender_node_id=SENDER, tenant_id="default"
        )

    assert _stored_valid_until(fact_id) == "2027-01-01T00:00:00+00:00"
    assert _rejection_audit(fact_id) is not None


def test_same_instant_different_timezone_noops(fed_node) -> None:
    fact_id = str(uuid.uuid4())
    _seed_fact(fact_id=fact_id, valid_until="2027-01-01T00:00:00Z")

    assert (
        ingest_fact(
            _fact(fact_id=fact_id, valid_until="2027-01-01T04:00:00+04:00"),
            sender_node_id=SENDER, tenant_id="default",
        )
        is False
    )

    assert _stored_valid_until(fact_id) == "2027-01-01T00:00:00Z"
    assert _rejection_audit(fact_id) is None

"""Garden ACL on fact-by-id read surfaces (provenance, verify-cid).

A restricted-garden fact's existence / CID / lineage must not be exposed to a
same-tenant non-member (spec §17.3) — the same gate single-get already had,
applied to its siblings (adversarial PR-boundary review F-A1 / F-A2).
"""

import sqlite3

from fastapi.testclient import TestClient


def _seed_garden_fact(client: TestClient, tmp_db: str) -> str:
    """Write a fact, then promote it into a 'restricted' garden via the
    membership side-table (raw garden_id NULL → projected garden set)."""
    r = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://testnode/agent/secret",
            "relation": "memory:note",
            "value": {"type": "string", "v": "topsecret-prov-value"},
            "source": "stigmem://testnode/agent/secret",
            "scope": "local",
        },
    )
    assert r.status_code == 201, r.text
    fact_id = r.json()["id"]
    conn = sqlite3.connect(tmp_db)
    conn.execute(
        "INSERT INTO fact_garden_membership (fact_id, garden_id, updated_at)"
        " VALUES (?, 'restricted', '2026-01-01T00:00:00Z')",
        (fact_id,),
    )
    conn.commit()
    conn.close()
    return fact_id


def test_provenance_hidden_for_restricted_garden_non_member(
    client: TestClient, tmp_db: str
) -> None:
    fact_id = _seed_garden_fact(client, tmp_db)
    resp = client.get(f"/v1/facts/{fact_id}/provenance")
    assert resp.status_code == 404
    assert "topsecret-prov-value" not in resp.text


def test_verify_cid_hidden_for_restricted_garden_non_member(
    client: TestClient, tmp_db: str
) -> None:
    fact_id = _seed_garden_fact(client, tmp_db)
    resp = client.post(f"/v1/facts/{fact_id}/verify-cid")
    assert resp.status_code == 404

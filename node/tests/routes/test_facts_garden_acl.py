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


def test_provenance_redacts_chain_ref_in_hidden_garden(
    client: TestClient, tmp_db: str
) -> None:
    """A visible root fact whose derived_from ancestor lives in a restricted garden
    must redact that ancestor (no existence / fact_id / entity URI) — audit F-PROV-REF."""
    # Ancestor: a garden-restricted fact (membership-promoted) the caller can't see.
    anc = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://testnode/agent/ancestor-secret",
            "relation": "memory:note",
            "value": {"type": "string", "v": "anc"},
            "source": "stigmem://testnode/agent/ancestor-secret",
            "scope": "local",
        },
    )
    assert anc.status_code == 201
    anc_id = anc.json()["id"]
    conn = sqlite3.connect(tmp_db)
    conn.execute(
        "INSERT INTO fact_garden_membership (fact_id, garden_id, updated_at)"
        " VALUES (?, 'restricted', '2026-01-01T00:00:00Z')",
        (anc_id,),
    )
    conn.commit()
    conn.close()
    # Root: garden-less (visible), derived from the restricted ancestor.
    root = client.post(
        "/v1/facts",
        json={
            "entity": "stigmem://testnode/agent/root",
            "relation": "memory:note",
            "value": {"type": "string", "v": "root"},
            "source": "stigmem://testnode/agent/root",
            "scope": "local",
            "derived_from": [{"fact_id": anc_id}],
        },
    )
    assert root.status_code == 201, root.text
    root_id = root.json()["id"]

    r = client.get(f"/v1/facts/{root_id}/provenance")
    assert r.status_code == 200, r.text  # root itself is visible
    entries = r.json()["derived_from"]
    # The restricted ancestor must still appear as exactly one entry (no count
    # oracle from dropping it) but redacted: existence-hidden, no fact_id/entity.
    assert "ancestor-secret" not in r.text
    assert len(entries) == 1
    assert entries[0]["exists"] is False
    assert entries[0].get("fact_id") is None
    assert entries[0].get("entity") is None

"""Admin API for the DNSSEC first-trust operator-confirm queue (Rev 6 I9 / 3b.8).

Operator-confirm is the SOLE non-DNSSEC first-trust fallback (Rev 6 §2/§15.1):
when the (default-off) first-trust ladder cannot root an unknown origin via an
operator-pin or a DNSSEC binding, the candidate binding is PARKED in
``pending_first_trust`` (migration 055) for an explicit human action. These
routes surface that queue and let an admin act on a parked candidate:

  * ``GET  /v1/federation/dnssec/pending``         — list quarantined candidates
  * ``POST /v1/federation/dnssec/pending/confirm`` — paste-to-confirm (NF-D4-5):
    the operator-supplied ``key_fpr`` MUST byte-equal the stored
    ``candidate_key_fpr`` (never one-click). On match -> derive the canonical
    host (I3), pin the binding (establishing trust), then clear the pending row.
  * ``POST /v1/federation/dnssec/pending/reject``  — clear the pending row
    WITHOUT trusting it.

All three are gated on ``admin:federation`` (403 otherwise — the route exists and
is auth-gated, NOT missing) and each mutating call writes a federation audit
event, mirroring ``patch_peer_policy`` / the origin-pin routes. ``entity_uri``
travels in the JSON body, never the URL — it carries ``://`` and ``/`` (privacy
+ encoding), so a path parameter is never used for it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from ...auth import Identity, resolve_identity
from ...db import db
from ...federation.dnssec.host import host_from_entity_uri
from ...federation.dnssec.pin import get_pin, upsert_pin
from ...federation.dnssec.quarantine import get_pending, list_pending, remove_pending
from .common import _public_module, router

# ---------------------------------------------------------------------------
# Request models — body/JSON contract (entity_uri never sits in a URL)
# ---------------------------------------------------------------------------


class PendingConfirmRequest(BaseModel):
    """Body for POST /v1/federation/dnssec/pending/confirm (paste-to-confirm)."""

    entity_uri: str
    node_id: str
    key_fpr: str


class PendingRejectRequest(BaseModel):
    """Body for POST /v1/federation/dnssec/pending/reject."""

    entity_uri: str
    node_id: str


# ---------------------------------------------------------------------------
# GET /v1/federation/dnssec/pending — list the operator-confirm queue
# ---------------------------------------------------------------------------


@router.get("/v1/federation/dnssec/pending")
def list_dnssec_pending(
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """List quarantined first-trust candidates. Requires admin:federation.

    Each row surfaces the operator-facing fields needed to confirm a binding
    out-of-band: ``entity_uri``, ``node_id``, ``candidate_key_fpr``, ``source``
    (``unsigned`` vs ``insecure-delegation``), ``relay_peer``, and ``seen_at``.
    """
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")
    with db() as conn:
        pending = list_pending(conn)
    return {"pending": pending}


# ---------------------------------------------------------------------------
# POST /v1/federation/dnssec/pending/confirm — friction-proportionate confirm
# ---------------------------------------------------------------------------


@router.post(
    "/v1/federation/dnssec/pending/confirm",
    status_code=status.HTTP_200_OK,
)
def confirm_dnssec_pending(
    req: PendingConfirmRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Confirm a quarantined first-trust candidate (paste-to-confirm, NF-D4-5).

    The operator-supplied ``key_fpr`` MUST byte-equal the stored
    ``candidate_key_fpr`` (never one-click). On match the binding is pinned
    (establishing trust) and the pending row is cleared. On fingerprint mismatch
    the candidate is NOT trusted (422) and the row is left parked. When no such
    pending row exists, returns 404. Requires admin:federation.
    """
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")

    with db() as conn:
        row = get_pending(conn, req.entity_uri, req.node_id)
        if row is None:
            raise HTTPException(status_code=404, detail="no such pending first-trust candidate")

        # Paste-to-confirm (NF-D4-5): the operator MUST reproduce the exact
        # stored candidate fingerprint byte-for-byte. A mismatch never trusts and
        # never clears the row — the candidate stays parked for a correct paste.
        if req.key_fpr != row["candidate_key_fpr"]:
            # A wrong-fingerprint confirm is a MITM/attack signal (the operator
            # was shown a fingerprint that does not match the quarantined
            # candidate). Audit it before failing closed; the row stays parked.
            _public_module().write_audit_log(
                req.entity_uri,
                "dnssec_first_trust_confirm_rejected",
                {
                    "entity_uri": req.entity_uri,
                    "node_id": req.node_id,
                    "reason": "fpr_mismatch",
                    "rejected_by": identity.entity_uri,
                },
            )
            raise HTTPException(
                status_code=422,
                detail="key_fpr does not match the quarantined candidate fingerprint",
            )

        # The DNS query host + pin key are derived from the (signed) entity_uri by
        # the single canonical algorithm (I3), never from a carried manifest.
        host = host_from_entity_uri(req.entity_uri)
        if host is None:
            # operator-confirm is the fallback PRECISELY because the DNSSEC tier
            # was not applicable; the pin still keys on the canonical host, so a
            # non-DNSSEC-capable entity_uri cannot be confirmed this way.
            raise HTTPException(
                status_code=422,
                detail="entity_uri yields no canonical DNS host (not confirmable here)",
            )

        now = datetime.now(UTC)
        # The pending row carries no epoch (it predates DNSSEC validation); the
        # operator-confirmed binding takes epoch 0 with no rotation grace.
        upsert_pin(
            conn,
            entity_uri=req.entity_uri,
            node_id=req.node_id,
            key_fpr=req.key_fpr,
            epoch=0,
            host=host,
            prev_fpr=None,
            prev_until=None,
            now=now,
        )
        remove_pending(conn, req.entity_uri, req.node_id)
        conn.commit()
        pin = get_pin(conn, req.entity_uri, req.node_id)

    _public_module().write_audit_log(
        req.entity_uri,
        "dnssec_first_trust_confirmed",
        {
            "entity_uri": req.entity_uri,
            "node_id": req.node_id,
            "key_fpr": req.key_fpr,
            "host": host,
            "confirmed_by": identity.entity_uri,
        },
    )

    assert pin is not None  # nosec B101 — just upserted in the same transaction
    return {
        "entity_uri": pin.entity_uri,
        "node_id": pin.node_id,
        "key_fpr": pin.key_fpr,
        "epoch": pin.epoch,
        "prev_fpr": pin.prev_fpr,
        "prev_until": pin.prev_until,
        "host": pin.host,
        "last_validated_at": pin.last_validated_at,
    }


# ---------------------------------------------------------------------------
# POST /v1/federation/dnssec/pending/reject — clear without trusting
# ---------------------------------------------------------------------------


@router.post(
    "/v1/federation/dnssec/pending/reject",
    status_code=status.HTTP_200_OK,
)
def reject_dnssec_pending(
    req: PendingRejectRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    """Reject a quarantined first-trust candidate WITHOUT trusting it.

    Clears the pending row; no pin is created. Returns 404 when no such pending
    row exists. Requires admin:federation.
    """
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")

    with db() as conn:
        removed = remove_pending(conn, req.entity_uri, req.node_id)
        if removed:
            conn.commit()
    if not removed:
        raise HTTPException(status_code=404, detail="no such pending first-trust candidate")

    _public_module().write_audit_log(
        req.entity_uri,
        "dnssec_first_trust_rejected",
        {
            "entity_uri": req.entity_uri,
            "node_id": req.node_id,
            "rejected_by": identity.entity_uri,
        },
    )
    return {"entity_uri": req.entity_uri, "node_id": req.node_id, "rejected": True}

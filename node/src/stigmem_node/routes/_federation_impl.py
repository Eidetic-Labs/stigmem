"""Federation route implementations extracted from routes/federation.py.

These functions are the original route handler bodies; they are imported back
into ``routes.federation`` and invoked from thin ``@router``-decorated wrappers.
No behavioural changes — code was moved verbatim from federation.py.

Tests monkey-patch attributes on the ``routes.federation`` module
(``settings``, ``write_audit_log``).  To honour those patches, this module
looks those names up via ``routes.federation`` lazily inside the function
bodies rather than binding them at import time.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import BackgroundTasks, HTTPException, Request, status

from ..auth import Identity
from ..db import db
from ..federation.peer_token import verify_declaration_sig
from ..federation.tls import check_peer_san
from ..identity.capability import CapabilityTokenError, verify_token
from ..identity.manifest import ManifestError, manifest_from_dict, verify_manifest
from ..identity.transparency_log import LogEntry, TransparencyLogUnavailable, make_transparency_log
from ..identity.trust_store import get_peer_manifest, store_peer_manifest
from ..models.federation import (
    PeerApprovalResponse,
    PeerRegisterRequest,
    PeerRegisterResponse,
)
from ..models.tombstones import (
    TombstoneRecord,
    TombstoneRevocationRecord,
)
from ..net_util import assert_safe_url, node_url_is_loopback
from ..plugins import Deny, TenantContext, get_registry

logger = logging.getLogger("stigmem.federation")


def peer_pubkey_fingerprint(pubkey: str) -> str:
    """Return the operator-verifiable fingerprint for a pinned peer public key."""
    return f"sha256:{hashlib.sha256(pubkey.encode()).hexdigest()}"


def _make_federation_client() -> httpx.AsyncClient:
    from . import federation as _fed_mod

    if _fed_mod.settings.mtls_enabled:
        from ..federation.tls import build_client_ssl_context

        ssl_ctx = build_client_ssl_context(
            _fed_mod.settings.tls_cert_path,
            _fed_mod.settings.tls_key_path,
            _fed_mod.settings.tls_ca_bundle,
        )
        return httpx.AsyncClient(verify=ssl_ctx, trust_env=False)
    return httpx.AsyncClient(trust_env=False)


async def register_peer_impl(
    req: PeerRegisterRequest,
    background_tasks: BackgroundTasks,
    identity: Identity,
) -> PeerRegisterResponse:
    """Register a peer. Fetches its well-known doc and verifies declaration_sig (§5.6)."""
    if not identity.can_federate():
        raise HTTPException(status_code=403, detail="federate permission required")
    decision = get_registry().fire_voting(
        "federation_peer_authenticate",
        req=req,
        identity=identity,
        tenant=TenantContext(
            tenant_id=identity.tenant_id,
            metadata={"tenant_context_source": "hook"},
        ),
    )
    if isinstance(decision, Deny):
        raise HTTPException(status_code=403, detail=decision.reason)

    peer_id = str(uuid.uuid4())
    allowed_scopes_json = json.dumps(sorted(req.allowed_scopes))

    with db() as conn:
        existing = conn.execute(
            "SELECT id, status FROM peers WHERE node_id = ?", (req.node_id,)
        ).fetchone()
        if existing:
            raise HTTPException(
                status_code=409,
                detail=f"peer already registered (status={existing['status']})",
            )
        conn.execute(
            """INSERT INTO peers
               (id, node_id, node_url, federation_pubkey, allowed_scopes,
                status, established_at, declaration_sig, signed_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                peer_id,
                req.node_id,
                req.node_url,
                req.federation_pubkey,
                allowed_scopes_json,
                "pending_verification",
                None,
                req.declaration_sig,
                req.signed_at,
            ),
        )

    # Fetch peer's /.well-known/stigmem to retrieve their published pubkey (§5.6 step 1–3)
    # SSRF guard (NF-2): assert_safe_url runs before the GET so the connection is never
    # opened for private/internal addresses.  Skipped only when federation_insecure=True
    # (dev/test mode where the operator has explicitly opted out of URL safety checks).
    # In production (federation_insecure=False) only https:// peer URLs are accepted.
    from . import federation as _fed_mod

    fetched_pubkey: str | None = None
    try:
        if not _fed_mod.settings.federation_insecure:
            assert_safe_url(req.node_url, allow_schemes=frozenset({"https"}))
        async with _make_federation_client() as client:
            wk_resp = await client.get(f"{req.node_url}/.well-known/stigmem")
        if wk_resp.status_code == 200:
            fetched_pubkey = wk_resp.json().get("federation_pubkey")
    except Exception as exc:  # nosec B110 — fetched_pubkey stays None → rejected below
        logger.debug("peer .well-known fetch failed: %s", exc)

    final_status = "rejected"
    verified_at: str | None = None

    if fetched_pubkey and fetched_pubkey == req.federation_pubkey:
        # Signed fields = everything except declaration_sig (spec §6.1 struct "above fields")
        signed_fields: dict[str, Any] = {
            "allowed_scopes": req.allowed_scopes,
            "federation_pubkey": req.federation_pubkey,
            "node_id": req.node_id,
            "node_url": req.node_url,
            "signed_at": req.signed_at,
        }
        if verify_declaration_sig(signed_fields, req.declaration_sig, fetched_pubkey):
            final_status = "pending_approval"

    # Phase 2a — entity_uri is NOT bound here. A fresh peer's manifest is not stored at
    # registration time; the only flow that fetches+stores it is _check_tl_inclusion_for_peer,
    # which runs at approval. The binding lives there (where the manifest exists and where the
    # peer is 'active', matching resolve_origin_key's status filter). See Task 8.
    with db() as conn:
        conn.execute(
            "UPDATE peers SET status = ?, established_at = ? WHERE id = ?",
            (final_status, verified_at, peer_id),
        )

    return PeerRegisterResponse(peer_id=peer_id, status=final_status, verified_at=verified_at)


def approve_peer_impl(
    peer_id: str,
    pubkey_fingerprint: str,
    background_tasks: BackgroundTasks,
    identity: Identity,
) -> PeerApprovalResponse:
    """Approve a verified peer after operator out-of-band key confirmation."""
    if not identity.can_admin_federation():
        raise HTTPException(status_code=403, detail="admin:federation required")

    now = datetime.now(UTC).isoformat()
    fingerprint_mismatch_peer: dict[str, Any] | None = None
    with db() as conn:
        peer = conn.execute("SELECT * FROM peers WHERE id = ?", (peer_id,)).fetchone()
        if peer is None:
            raise HTTPException(status_code=404, detail="peer not found")
        if peer["status"] != "pending_approval":
            raise HTTPException(
                status_code=409,
                detail=f"peer is not pending approval (status={peer['status']})",
            )

        expected = peer_pubkey_fingerprint(peer["federation_pubkey"])
        if pubkey_fingerprint != expected:
            fingerprint_mismatch_peer = dict(peer)
        else:
            fingerprint_mismatch_peer = None

            conn.execute(
                "UPDATE peers SET status = 'active', established_at = ? WHERE id = ?",
                (now, peer["id"]),
            )

    if fingerprint_mismatch_peer is not None:
        from . import federation as _fed_mod

        _fed_mod.write_audit_log(
            fingerprint_mismatch_peer["id"],
            "peer_approval_failed",
            {"node_id": fingerprint_mismatch_peer["node_id"], "reason": "fingerprint_mismatch"},
        )
        raise HTTPException(status_code=400, detail="fingerprint mismatch")

    from . import federation as _fed_mod

    _fed_mod.write_audit_log(
        peer_id,
        "peer_approved",
        {"node_id": peer["node_id"], "approved_by": identity.entity_uri},
    )
    background_tasks.add_task(
        _check_tl_inclusion_for_peer,
        peer["node_id"],
        peer["node_url"],
        peer_id,
    )
    return PeerApprovalResponse(
        peer_id=peer_id,
        node_id=peer["node_id"],
        status="active",
        approved_at=now,
    )


async def _check_tl_inclusion_for_peer(node_id: str, node_url: str, peer_id: str) -> None:
    """Check TL inclusion proof for a newly registered peer (§19.2.3).

    trust_mode=strict  (enforce): no proof → downgrade peer to pending_tl_proof
    trust_mode=relaxed (warn):    no proof → accept + audit warning
    trust_mode=off:               skip entirely
    """
    # Lazy lookup: tests monkey-patch ``federation.write_audit_log`` —
    # accessing via the module preserves those patches.
    from typing import cast as _cast

    from . import federation as _fed_mod

    _fed = _cast(Any, _fed_mod)

    trust_mode = _fed.settings.trust_mode
    if trust_mode == "off":
        return

    # Try to fetch the peer's manifest from their well-known endpoint
    manifest_obj = None
    try:
        # The SSRF guard normally blocks loopback/private addresses. We skip
        # assert_safe_url for this approval-time manifest fetch ONLY under the
        # conjunction (federation_insecure dev mode AND a literal loopback host),
        # so a loopback dev cluster can bind the peer's entity_uri (Phase 2a) —
        # without the skip, assert_safe_url rejects the loopback URL, the binding
        # never fires, resolve_origin_key fails, and no v2 fact federates between
        # loopback nodes. In production (federation_insecure off) the guard is
        # always enforced. Note: the registration-time well-known fetch
        # (register_peer_impl, NF-2) is guarded by assert_safe_url under
        # federation_insecure ALONE (https-only) — NOT flag+loopback-gated like
        # this fetch, so do not treat the two as the same mechanism.
        _loopback_dev = _fed.settings.federation_insecure and node_url_is_loopback(node_url)
        if not _loopback_dev:
            assert_safe_url(node_url, allow_schemes=frozenset({"https", "http"}))
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{node_url}/.well-known/stigmem-manifest.json",
                follow_redirects=False,
            )
        if resp.status_code == 200:
            try:
                manifest_obj = manifest_from_dict(resp.json())
                verify_manifest(manifest_obj, trust_mode=trust_mode)
            except ManifestError as exc:
                logger.warning("peer manifest from %s failed verification: %s", node_url, exc)
                manifest_obj = None
            except ValueError as exc:
                logger.warning("peer manifest from %s was not valid JSON: %s", node_url, exc)
                manifest_obj = None
    except Exception as exc:
        logger.warning("failed to fetch peer manifest from %s: %s", node_url, exc)
        manifest_obj = None

    has_tl_proof = False
    if manifest_obj is not None:
        # Check whether the manifest has a TL entry recorded
        existing = get_peer_manifest(manifest_obj.entity_uri, refresh_if_expired=False)
        if existing is None:
            with contextlib.suppress(ManifestError):
                store_peer_manifest(manifest_obj.entity_uri, manifest_obj, trust_mode=trust_mode)

        # Phase 2a — bind the verified entity_uri now that the manifest is fetched + stored
        # (same key must control node_id AND entity_uri). The peer's manifest must publish
        # public_key == the peer's registered federation_pubkey AND list node_id in its
        # entities. Fail-OPEN: any mismatch/exception leaves entity_uri NULL and approval
        # still completes. The peer is already 'active' here, matching resolve_origin_key.
        try:
            from ..db import db as _bind_db

            with _bind_db() as conn:
                peer_row = conn.execute(
                    "SELECT federation_pubkey FROM peers WHERE id = ?", (peer_id,)
                ).fetchone()
                if (
                    peer_row is not None
                    and manifest_obj.public_key == peer_row["federation_pubkey"]
                    and node_id in manifest_obj.entities
                ):
                    conn.execute(
                        "UPDATE peers SET entity_uri = ? WHERE id = ?",
                        (manifest_obj.entity_uri, peer_id),
                    )
        except Exception as exc:  # nosec B110 — binding failure → entity_uri stays NULL
            logger.debug("peer entity_uri binding at approval failed: %s", exc)

        # Try to verify TL inclusion
        try:
            tl = make_transparency_log()
            from ..db import db as _db

            with _db() as conn:
                row = conn.execute(
                    "SELECT log_entry_json FROM federation_manifests WHERE entity_uri = ?",
                    (manifest_obj.entity_uri,),
                ).fetchone()
            if row and row["log_entry_json"]:
                import json as _json

                le_data = _json.loads(row["log_entry_json"])
                le = LogEntry(
                    log_id=le_data.get("log_id", ""),
                    leaf_hash=le_data.get("leaf_hash", ""),
                    log_index=le_data.get("log_index", -1),
                    integrated_time=le_data.get("integrated_time", 0),
                    inclusion_proof=le_data.get("inclusion_proof", {}),
                )
                tl.verify_inclusion(le)
                has_tl_proof = True
        except TransparencyLogUnavailable as exc:
            logger.debug("transparency log unavailable for TL inclusion check: %s", exc)
        except Exception as exc:  # nosec B110 — TL inclusion check is best-effort
            logger.debug("TL inclusion check failed: %s", exc)

    if not has_tl_proof:
        if trust_mode == "strict":
            _fed.write_audit_log(
                peer_id,
                "tl_proof_missing",
                {"node_id": node_id, "action": "downgraded_to_pending_tl_proof"},
            )
            from ..db import db as _db

            with _db() as conn:
                conn.execute(
                    "UPDATE peers SET status = 'pending_tl_proof' WHERE id = ?",
                    (peer_id,),
                )
        else:
            _fed.write_audit_log(
                peer_id,
                "tl_proof_missing",
                {"node_id": node_id, "action": "accepted_with_warning", "trust_mode": trust_mode},
            )


def _authenticate_tombstone_caller(
    request: Request,
    authorization: str | None,
    x_stigmem_capability: str | None,
    try_peer_token_auth: Any,
    get_mtls_peer_cert: Any,
    fed_settings: Any,
) -> None:
    """F-1 fix: caller must present a valid peer-JWT OR a tombstone-write capability token.

    Raises HTTPException on any auth failure. Returns None on success.
    """
    peer_auth = try_peer_token_auth(authorization)
    if peer_auth is not None:
        if fed_settings.mtls_enabled and request is not None:
            peer_cert = get_mtls_peer_cert(request)
            if not check_peer_san(peer_cert, peer_auth[0]["node_id"]):
                raise HTTPException(
                    status_code=401,
                    detail="peer certificate URI SAN does not match node_id",
                )
        return

    if x_stigmem_capability is None:
        raise HTTPException(status_code=401, detail="peer token or capability token required")

    try:
        verify_token(
            x_stigmem_capability,
            lambda uri: get_peer_manifest(
                uri, refresh_if_expired=True, trust_mode=fed_settings.trust_mode
            ),
            trust_mode=fed_settings.trust_mode,
        )
    except CapabilityTokenError as exc:
        raise HTTPException(status_code=401, detail=f"capability token invalid: {exc}") from exc
    try:
        cap_token = json.loads(x_stigmem_capability)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400, detail=f"malformed capability token JSON: {exc}"
        ) from exc
    if cap_token.get("verb", "") not in ("tombstone:write", "write"):
        raise HTTPException(status_code=403, detail="capability token missing tombstone:write verb")


def _verify_signed_artifact_or_400(
    *,
    record: Any,
    key_id: str,
    artifact_label: str,  # "tombstone" or "revocation"
    missing_manifest_detail: str,  # exact wire-error string for the unknown-signer 401
    signer_uri: str,
    verifier: Any,  # verify_tombstone_signature or verify_revocation_signature
    on_failure: Any | None = None,  # callable(record, reason) emitted on bad signature
) -> None:
    """Look up the signer manifest, resolve the signing key, and verify the signature.

    Raises HTTPException on any verification failure (no-key-id / unknown-signer /
    key-id-not-in-manifest / signature-mismatch). ``missing_manifest_detail`` is
    parameterised because the existing wire contract uses different wording for
    tombstones vs revocations.

    W6.5: the manifest-lookup + key-id-resolve + verify core is the shared
    ``resolve_and_verify_tombstone_issuer`` (also used by the pull client, closing the
    W6.1 gap). This wrapper preserves the EXACT push-route HTTP status codes / wire-error
    strings / audit events by mapping the helper's ``reason`` codes back to them.
    """
    from ..lifecycle.tombstone_signing import (
        IssuerVerificationError,
        resolve_and_verify_tombstone_issuer,
    )

    try:
        resolve_and_verify_tombstone_issuer(
            record, key_id=key_id, signer_uri=signer_uri, verifier=verifier
        )
    except IssuerVerificationError as exc:
        reason = exc.reason
        if reason == "missing_key_id":
            _audit_tombstone_ingest_rejected(
                record, artifact_label, f"{artifact_label}_missing_key_id"
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{artifact_label} missing key_id",
            ) from exc
        if reason == "signer_manifest_missing":
            _audit_tombstone_ingest_rejected(record, artifact_label, "signer_manifest_missing")
            raise HTTPException(status_code=401, detail=missing_manifest_detail) from exc
        if reason == "key_id_not_in_signer_manifest":
            _audit_tombstone_ingest_rejected(
                record, artifact_label, "key_id_not_in_signer_manifest"
            )
            raise HTTPException(status_code=401, detail="key_id not in signer manifest") from exc
        # Signature mismatch (reason is the verifier's ValueError string).
        if on_failure is not None:
            on_failure(record, reason)
        _audit_tombstone_ingest_rejected(record, artifact_label, reason)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{artifact_label}_verification_failed: {reason}",
        ) from exc


def _ingest_revocation(payload: dict[str, Any], fed_settings: Any) -> dict[str, Any]:
    """Parse + verify + apply an inbound revocation. Returns the success response dict."""
    from ..lifecycle.tombstone_signing import verify_revocation_signature
    from ..lifecycle.tombstones import apply_inbound_revocation

    try:
        rev = TombstoneRevocationRecord(**payload)
    except Exception as exc:
        _audit_tombstone_payload_rejected(payload, "revocation", str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    _verify_signed_artifact_or_400(
        record=rev,
        key_id=rev.key_id or "",
        artifact_label="revocation",
        missing_manifest_detail="no manifest for revocation signer",
        signer_uri=rev.signed_by,
        verifier=verify_revocation_signature,
    )

    apply_inbound_revocation(rev)
    return {"status": "ok", "type": "revocation"}


def _ingest_tombstone(payload: dict[str, Any], fed_settings: Any) -> dict[str, Any]:
    """Parse + verify + apply an inbound tombstone. Returns the success response dict."""
    from ..lifecycle.tombstone_signing import verify_tombstone_signature
    from ..lifecycle.tombstones import apply_inbound_tombstone

    try:
        record = TombstoneRecord(**payload)
    except Exception as exc:
        _audit_tombstone_payload_rejected(payload, "tombstone", str(exc))
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    _verify_signed_artifact_or_400(
        record=record,
        key_id=record.key_id or "",
        artifact_label="tombstone",
        missing_manifest_detail="no manifest for signer",
        signer_uri=record.signed_by,
        verifier=verify_tombstone_signature,
        on_failure=_emit_tombstone_verification_failed,
    )

    written = apply_inbound_tombstone(record)
    return {"status": "ok", "written": written}


def federation_ingest_tombstone_impl(
    request: Request,
    payload: dict[str, Any],
    authorization: str | None,
    x_stigmem_capability: str | None,
    try_peer_token_auth: Any,
    get_mtls_peer_cert: Any,
) -> dict[str, Any]:
    """Inbound tombstone push from a federation peer (§23.4.2).

    Auth: peer JWT or capability token with tombstone:write verb (mirrors push_facts).
    Verifies signature against org manifest, writes to local tombstones table.
    """
    # Lazy lookup: tests monkey-patch ``federation.settings``.
    from typing import cast as _cast

    from . import federation as _fed_mod

    fed_settings = _cast(Any, _fed_mod).settings

    _authenticate_tombstone_caller(
        request,
        authorization,
        x_stigmem_capability,
        try_peer_token_auth,
        get_mtls_peer_cert,
        fed_settings,
    )

    if "tombstone_id" in payload:
        return _ingest_revocation(payload, fed_settings)
    return _ingest_tombstone(payload, fed_settings)


def _emit_tombstone_verification_failed(record: TombstoneRecord, reason: str) -> None:
    import logging as _logging

    _logging.getLogger("stigmem.tombstones.ingest").error(
        "tombstone_verification_failed: tombstone_id=%s entity=%s reason=%s",
        record.id,
        record.entity_uri,
        reason,
    )


def _audit_tombstone_ingest_rejected(record: Any, artifact_label: str, reason: str) -> None:
    from ..observability.audit_event import emit_nofail

    artifact_id = str(getattr(record, "id", "") or getattr(record, "tombstone_id", ""))
    signer_uri = str(getattr(record, "signed_by", "") or "system:federation")
    target_entity_uri = str(
        getattr(record, "entity_uri", "") or getattr(record, "tombstone_id", "") or artifact_id
    )
    emit_nofail(
        "tombstone_federation_rejected",
        entity_uri=signer_uri,
        fact_id=artifact_id or None,
        source="federation",
        detail={
            "artifact": artifact_label,
            "artifact_id": artifact_id,
            "target_entity_uri": target_entity_uri,
            "key_id": str(getattr(record, "key_id", "") or ""),
            "reason": reason,
        },
    )


def _audit_tombstone_payload_rejected(
    payload: dict[str, Any],
    artifact_label: str,
    reason: str,
) -> None:
    from ..observability.audit_event import emit_nofail

    artifact_id = str(payload.get("id") or payload.get("tombstone_id") or "")
    signer_uri = str(payload.get("signed_by") or "system:federation")
    target_entity_uri = str(payload.get("entity_uri") or payload.get("tombstone_id") or artifact_id)
    emit_nofail(
        "tombstone_federation_rejected",
        entity_uri=signer_uri,
        fact_id=artifact_id or None,
        source="federation",
        detail={
            "artifact": artifact_label,
            "artifact_id": artifact_id,
            "target_entity_uri": target_entity_uri,
            "key_id": str(payload.get("key_id") or ""),
            "reason": reason,
        },
    )

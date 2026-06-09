"""Lazy instruction discovery — spec §21 (Phase 10).

Routes:
    GET  /v1/agents/{agent_id}/boot-stub                        §21.8.1  MUST
    GET  /v1/agents/{agent_id}/instruction-manifest             §21.8.2  MUST
    PUT  /v1/agents/{agent_id}/instruction-manifest             §21.8.3  MUST
    POST /v1/agents/{agent_id}/recall-instruction               §21.8.4  MUST
    POST /v1/instruction/audit                                  §21.8.5  SHOULD
    GET  /v1/agents/{agent_id}/instruction-manifest/coverage    §21.8.6  SHOULD
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import PlainTextResponse

from ..auth import Identity, resolve_identity
from ..db import db
from ..models.instruction import (
    AuditSubmitRequest,
    ManifestEntry,
    PublishManifestRequest,
    RecallInstructionRequest,
)

logger = logging.getLogger("stigmem.instruction")

router = APIRouter(tags=["instruction"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MANIFEST_TOKEN_LIMIT = 1000
_BOOT_STUB_TOKEN_LIMIT = 500
_GUARANTEE_LOAD_CAP = 5
_AUDIT_TOKEN_PREFIX = "audi_"  # nosec B105 — audit token prefix, not a password
_AUDEVENT_PREFIX = "audevent_"
_AUDIT_TOKEN_TTL_S = 86_400  # 24 hours

# Registered wake-reason enum values used for task_type validation.
# Extend this set when new wake reasons are added to the platform.
_KNOWN_WAKE_REASONS: frozenset[str] = frozenset(
    {
        "issue_assigned",
        "issue_commented",
        "issue_blockers_resolved",
        "issue_children_completed",
        "issue_comment_mentioned",
        "routine_fired",
        "approval_resolved",
        "manual",
    }
)

_ADAPTER_PROFILES = {"paperclip-claude-code", "openai-assistants", "generic"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _approx_tokens(text: str) -> int:
    """Approximate cl100k token count (4 chars ≈ 1 token)."""
    try:
        import tiktoken

        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


def _now_ms() -> int:
    return int(time.time() * 1000)


def _is_admin(identity: Identity) -> bool:
    return identity.is_admin()


def _agent_uri_segments(entity_uri: str) -> set[str]:
    """Split an entity_uri into whole path/scheme segments.

    Used so an agent_id must match a *complete* segment of the caller's
    entity_uri, never a substring (audit H3 / F-4): "cto" must not match
    "cto-shadow".
    """
    return {seg for seg in re.split(r"[/:]+", entity_uri) if seg}


def _check_agent_access(identity: Identity, agent_id: str) -> None:
    """Raise 403 unless caller is the named agent or an admin."""
    if _is_admin(identity):
        return
    # Agent key entity_uri must contain the agent_id as a WHOLE segment
    # (UUID or role slug), not merely a substring (audit H3 / F-4).
    if agent_id and agent_id in _agent_uri_segments(identity.entity_uri):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="instruction_scope_denied",
    )


def _get_current_manifest(conn: Any, agent_id: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT * FROM instruction_manifests WHERE agent_id = ? AND superseded_at IS NULL"
        " ORDER BY created_at DESC LIMIT 1",
        (agent_id,),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def _build_boot_stub(
    agent_id: str,
    agent_role: str,
    manifest_uri: str,
    manifest_version: str,
    adapter_profile: str,
    deployment: str = "default",
) -> str:
    frontmatter = {
        "agent_id": agent_id,
        "agent_role": agent_role,
        "heartbeat_contract": f"instruction:{deployment}/shared/heartbeat-contract/v1",
        "manifest_uri": manifest_uri,
        "stub_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "adapter_profile": adapter_profile,
        "migration_mode": "stigmem",
    }
    recall_schema = {
        "name": "recall_instruction",
        "description": "Retrieve relevant instruction units from the agent manifest.",
        "parameters": {
            "type": "object",
            "properties": {
                "intent": {"type": "string", "description": "What you are about to do"},
                "max_chunks": {"type": "integer", "default": 3},
                "token_budget": {"type": "integer", "default": _BOOT_STUB_TOKEN_LIMIT},
                "manifest_hint": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Explicit unit names to prioritize",
                },
            },
            "required": ["intent"],
        },
    }
    yaml_str = yaml.dump(
        {**frontmatter, "recall_tool_schema": recall_schema},
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
    body = (
        f"# Agent Boot Stub\n\n"
        f"You are **{agent_role}** (id: `{agent_id}`).\n\n"
        f"Your heartbeat procedure is at `{frontmatter['heartbeat_contract']}`.\n"
        f"Your instruction manifest is at `{manifest_uri}`.\n\n"
        f"Call `recall_instruction(intent)` to load relevant instruction sections before\n"
        f"performing any non-trivial task. The manifest lists available sections and their\n"
        f"triggers to help you decide when to load.\n"
    )
    return f"---\n{yaml_str}---\n\n{body}"


def _validate_manifest_entries(entries: list[ManifestEntry]) -> None:
    seen_names: set[str] = set()
    guarantee_count = 0

    for entry in entries:
        # Exactly one of fact_uri / path must be present
        has_fact = bool(entry.fact_uri)
        has_path = bool(entry.path)
        if not has_fact and not has_path:
            raise HTTPException(
                400,
                detail=(f"manifest_entry_invalid: '{entry.name}' has neither fact_uri nor path"),
            )
        if has_fact and has_path:
            raise HTTPException(
                400,
                detail=(f"manifest_entry_invalid: '{entry.name}' has both fact_uri and path"),
            )

        # Unique names
        if entry.name in seen_names:
            raise HTTPException(
                400,
                detail=f"manifest_entry_invalid: duplicate name '{entry.name}'",
            )
        seen_names.add(entry.name)

        # Validate required_by_task_types
        for tt in entry.required_by_task_types:
            if tt not in _KNOWN_WAKE_REASONS:
                raise HTTPException(
                    400,
                    detail=f"task_type_unknown: '{tt}' is not a registered wake-reason",
                )
        if len(entry.required_by_task_types) > 2:
            raise HTTPException(
                400,
                detail=(
                    "task_types_approval_required: entry declares > 2 "
                    "required_by_task_types; admin approval required"
                ),
            )

        if entry.guarantee_load:
            guarantee_count += 1

    if guarantee_count > _GUARANTEE_LOAD_CAP:
        raise HTTPException(
            400,
            detail=(
                f"guarantee_cap_exceeded: at most {_GUARANTEE_LOAD_CAP} entries "
                "may have guarantee_load=true per agent"
            ),
        )


def _score_intent_against_entry(intent: str, entry: ManifestEntry) -> float:
    """Simple BM25-style keyword overlap score for ranking manifest entries."""
    intent_words = set(re.findall(r"\w+", intent.lower()))
    if not intent_words:
        return 0.0
    score = 0.0
    # Check description overlap
    desc_words = set(re.findall(r"\w+", entry.description.lower()))
    score += len(intent_words & desc_words) / max(len(intent_words), 1) * 0.4
    # Check trigger intents
    for trigger_intent in entry.load_triggers.intents:
        trigger_words = set(re.findall(r"\w+", trigger_intent.lower()))
        score += len(intent_words & trigger_words) / max(len(intent_words), 1) * 0.3
    # Check keywords
    for kw in entry.load_triggers.keywords:
        if kw.lower() in intent.lower():
            score += 0.2
    return min(score, 1.0)


def _fetch_instruction_content(entry: ManifestEntry) -> tuple[str, str]:
    """Return (content, source) for a manifest entry. Raises on failure."""
    if entry.fact_uri:
        with db() as conn:
            row = conn.execute(
                "SELECT value_v, valid_until FROM facts"
                " WHERE entity = ? ORDER BY timestamp DESC LIMIT 1",
                (entry.fact_uri,),
            ).fetchone()
            if row:
                return str(row["value_v"]), "stigmem"
    if entry.path:
        try:
            with open(entry.path) as f:
                return f.read(), "fallback_path"
        except OSError as exc:
            raise LookupError(
                f"instruction fallback path '{entry.path}' could not be read"
            ) from exc
    raise LookupError(f"instruction content not found for entry '{entry.name}'")


def _get_fact_valid_until(fact_uri: str) -> str | None:
    with db() as conn:
        row = conn.execute(
            "SELECT valid_until FROM facts WHERE entity = ? ORDER BY timestamp DESC LIMIT 1",
            (fact_uri,),
        ).fetchone()
    if row:
        valid_until: str | None = row["valid_until"]
        return valid_until
    return None


# ---------------------------------------------------------------------------
# 21.8.1 Get Boot Stub
# ---------------------------------------------------------------------------


@router.get("/v1/agents/{agent_id}/boot-stub", response_class=PlainTextResponse)
def get_boot_stub(
    agent_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
    profile: str = "generic",
) -> PlainTextResponse:
    _check_agent_access(identity, agent_id)

    if profile not in _ADAPTER_PROFILES:
        profile = "generic"

    with db() as conn:
        stub_row = conn.execute(
            "SELECT body, token_count, manifest_version FROM boot_stubs"
            " WHERE agent_id = ? AND adapter_profile = ?",
            (agent_id, profile),
        ).fetchone()

        if stub_row is None:
            manifest_row = _get_current_manifest(conn, agent_id)
            if manifest_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="boot_stub_not_found",
                )
            # Generate on the fly from manifest
            agent_role = _derive_agent_role(agent_id, conn)
            manifest_uri = manifest_row["fact_uri"]
            stub_body = _build_boot_stub(
                agent_id=agent_id,
                agent_role=agent_role,
                manifest_uri=manifest_uri,
                manifest_version=manifest_row["version"],
                adapter_profile=profile,
            )
            token_count = _approx_tokens(stub_body)
            if token_count > _BOOT_STUB_TOKEN_LIMIT:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=(
                        f"boot_stub_too_large: {token_count} tokens exceeds "
                        f"{_BOOT_STUB_TOKEN_LIMIT}"
                    ),
                )
            now_ms = _now_ms()
            conn.execute(
                """INSERT OR REPLACE INTO boot_stubs
                   (agent_id, adapter_profile, stub_version, body, token_count,
                    generated_at, manifest_version)
                   VALUES (?,?,?,?,?,?,?)""",
                (agent_id, profile, 1, stub_body, token_count, now_ms, manifest_row["version"]),
            )
            stub_body_out = stub_body
            token_count_out = token_count
            manifest_version_out = manifest_row["version"]
        else:
            stub_body_out = stub_row["body"]
            token_count_out = stub_row["token_count"]
            manifest_version_out = stub_row["manifest_version"]

    return PlainTextResponse(
        content=stub_body_out,
        media_type="text/markdown",
        headers={
            "X-Stub-Version": "1",
            "X-Manifest-Version": manifest_version_out,
            "X-Token-Count": str(token_count_out),
        },
    )


def _derive_agent_role(agent_id: str, conn: Any) -> str:
    """Best-effort: look up a human-readable role for agent_id."""
    row = conn.execute(
        "SELECT entity_uri FROM api_keys WHERE entity_uri LIKE ? LIMIT 1",
        (f"%{agent_id}%",),
    ).fetchone()
    if row:
        uri: str = row["entity_uri"]
        # e.g. "agent:cto" or "stigmem://org/agent/cto"
        parts = uri.replace("//", "/").rstrip("/").split("/")
        if parts:
            return parts[-1].upper()
    return "Agent"


# ---------------------------------------------------------------------------
# 21.8.2 Get Instruction Manifest
# ---------------------------------------------------------------------------


@router.get("/v1/agents/{agent_id}/instruction-manifest")
def get_instruction_manifest(
    agent_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    _check_agent_access(identity, agent_id)

    with db() as conn:
        row = _get_current_manifest(conn, agent_id)

    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="manifest_not_found")

    entries = json.loads(row["body"])
    created_ms: int = row["created_at"]
    last_updated = datetime.fromtimestamp(created_ms / 1000, tz=UTC).isoformat()

    return {
        "manifest_version": row["version"],
        "fact_uri": row["fact_uri"],
        "token_count": row["token_count"],
        "entries": entries,
        "last_updated_at": last_updated,
    }


# ---------------------------------------------------------------------------
# 21.8.3 Publish / Replace Instruction Manifest
# ---------------------------------------------------------------------------


@router.put("/v1/agents/{agent_id}/instruction-manifest", status_code=200)
def publish_instruction_manifest(
    agent_id: str,
    req: PublishManifestRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    if not _is_admin(identity):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin key required")

    _validate_manifest_entries(req.entries)

    # Serialize entries for storage
    entries_json = json.dumps([e.model_dump() for e in req.entries])
    token_count = _approx_tokens(entries_json)
    if token_count > _MANIFEST_TOKEN_LIMIT:
        raise HTTPException(
            400,
            detail=(f"manifest_too_large: {token_count} tokens exceeds {_MANIFEST_TOKEN_LIMIT}"),
        )

    # Build the instruction: URI for this manifest
    fact_uri = f"instruction:default/agent/{agent_id}/manifest/{req.version}"

    with db() as conn:
        # Check version uniqueness
        existing = conn.execute(
            "SELECT id FROM instruction_manifests WHERE agent_id = ? AND version = ?",
            (agent_id, req.version),
        ).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail="manifest_version_conflict")

        # Run coverage gate (simplified: check entry validity; full paraphrase eval is Phase 11)
        coverage_report = []
        for entry in req.entries:
            coverage_pct: float
            if req.skip_coverage_gate:
                coverage_pct = 1.0
                passed = True
            else:
                # Lightweight check: verify fact_uri exists if specified
                # (full N=5 paraphrase eval is Phase 11)
                if entry.fact_uri:
                    row = conn.execute(
                        "SELECT id FROM facts WHERE entity = ? LIMIT 1", (entry.fact_uri,)
                    ).fetchone()
                    # If fact doesn't exist yet (pre-seeding), warn but don't block
                    coverage_pct = 1.0 if row else 0.5
                    passed = coverage_pct >= 0.80
                else:
                    # path-only entries pass coverage (read from filesystem, not stigmem)
                    coverage_pct = 1.0
                    passed = True
            coverage_report.append(
                {
                    "unit": entry.name,
                    "coverage_pct": coverage_pct,
                    "passed": passed,
                }
            )

        failing = [r["unit"] for r in coverage_report if not r["passed"]]
        if failing and not req.skip_coverage_gate:
            raise HTTPException(
                status_code=400,
                detail=f"manifest_coverage_failure: units failed coverage gate: {failing}",
            )

        now_ms = _now_ms()
        manifest_id = str(uuid.uuid4())

        # Supersede previous current version
        conn.execute(
            "UPDATE instruction_manifests SET superseded_at = ?"
            " WHERE agent_id = ? AND superseded_at IS NULL",
            (now_ms, agent_id),
        )

        conn.execute(
            """INSERT INTO instruction_manifests
                 (id, agent_id, version, fact_uri, token_count, body, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (manifest_id, agent_id, req.version, fact_uri, token_count, entries_json, now_ms),
        )

        # Invalidate boot stub cache for all profiles
        conn.execute("DELETE FROM boot_stubs WHERE agent_id = ?", (agent_id,))

        # Store the manifest itself as a fact in the instruction: scope
        fact_id = str(uuid.uuid4())
        ts = datetime.now(UTC).isoformat()
        conn.execute(
            """INSERT INTO facts
               (id, entity, relation, value_type, value_v, source, confidence, scope,
                timestamp, valid_until, garden_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fact_id,
                fact_uri,
                "instruction:manifest",
                "text",
                entries_json,
                identity.entity_uri,
                1.0,
                "local",
                ts,
                None,
                None,
            ),
        )

    logger.info(
        "Instruction manifest published: agent=%s version=%s units=%d",
        agent_id,
        req.version,
        len(req.entries),
    )

    return {
        "fact_uri": fact_uri,
        "token_count": token_count,
        "coverage_report": coverage_report,
    }


# ---------------------------------------------------------------------------
# 21.8.4 Recall Instructions
# ---------------------------------------------------------------------------


def _resolve_hint_chunks(
    entries: list[ManifestEntry],
    hints: list[str],
    token_budget: int,
) -> tuple[list[dict[str, Any]], set[str], list[str], int]:
    """Step 1: resolve manifest_hint entries.

    Returns (chunks, used_names, missed_hints, tokens_used).
    """
    chunks: list[dict[str, Any]] = []
    used_names: set[str] = set()
    missed_hints: list[str] = []
    tokens_used = 0
    for hint_name in hints:
        entry = next((e for e in entries if e.name == hint_name), None)
        if entry is None:
            missed_hints.append(hint_name)
            continue
        try:
            content, source = _fetch_instruction_content(entry)
        except LookupError:
            missed_hints.append(hint_name)
            continue
        tokens = _approx_tokens(content)
        if tokens_used + tokens <= token_budget:
            chunks.append(_make_chunk(entry, content, tokens, source, score=1.0))
            used_names.add(entry.name)
            tokens_used += tokens
    return chunks, used_names, missed_hints, tokens_used


def _resolve_ranked_chunks(
    entries: list[ManifestEntry],
    intent: str,
    used_names: set[str],
    remaining_slots: int,
    token_budget: int,
    tokens_used: int,
) -> tuple[list[dict[str, Any]], int]:
    """Step 2: ranked retrieval for remaining slots. Returns (new_chunks, updated_tokens_used)."""
    if remaining_slots <= 0:
        return [], tokens_used
    scored: list[tuple[float, ManifestEntry]] = []
    for entry in entries:
        if entry.name in used_names or entry.guarantee_load:
            continue  # guaranteed entries handled in step 3
        scored.append((_score_intent_against_entry(intent, entry), entry))
    scored.sort(key=lambda x: -x[0])

    new_chunks: list[dict[str, Any]] = []
    for score, entry in scored[:remaining_slots]:
        try:
            content, source = _fetch_instruction_content(entry)
        except LookupError as exc:
            logger.debug("skipping recall candidate %s: %s", entry.name, exc)
            continue
        tokens = _approx_tokens(content)
        if tokens_used + tokens <= token_budget:
            new_chunks.append(_make_chunk(entry, content, tokens, source, score=score))
            used_names.add(entry.name)
            tokens_used += tokens
    return new_chunks, tokens_used


def _append_guaranteed_chunks(
    entries: list[ManifestEntry],
    used_names: set[str],
    chunks: list[dict[str, Any]],
    tokens_used: int,
    token_budget: int,
) -> tuple[int, bool]:
    """Step 3: insert/append guaranteed entries. Returns (tokens_used, truncated_flag)."""
    truncated = False
    guaranteed = [e for e in entries if e.guarantee_load and e.name not in used_names]

    for entry in [e for e in guaranteed if e.force_position == "prepend"]:
        try:
            content, source = _fetch_instruction_content(entry)
        except LookupError as exc:
            logger.warning("guaranteed prepend instruction %s unavailable: %s", entry.name, exc)
            continue
        tokens = _approx_tokens(content)
        chunks.insert(0, _make_chunk(entry, content, tokens, source, score=1.0))
        used_names.add(entry.name)
        tokens_used += tokens
        if tokens_used > token_budget:
            truncated = True

    for entry in [e for e in guaranteed if e.force_position != "prepend"]:
        try:
            content, source = _fetch_instruction_content(entry)
        except LookupError as exc:
            logger.warning("guaranteed append instruction %s unavailable: %s", entry.name, exc)
            continue
        tokens = _approx_tokens(content)
        chunks.append(_make_chunk(entry, content, tokens, source, score=1.0))
        used_names.add(entry.name)
        tokens_used += tokens
        if tokens_used > token_budget:
            truncated = True

    return tokens_used, truncated


def _write_recall_audit(
    audit_id: str,
    agent_id: str,
    identity: Identity,
    intent: str,
    loaded_chunk_names: list[str],
    audit_token: str,
    now_ms: int,
) -> None:
    """Best-effort INSERT into instruction_audit; failures are logged not raised."""
    try:
        with db() as conn:
            conn.execute(
                """INSERT INTO instruction_audit
                   (id, agent_id, heartbeat_id, session_start, intent, loaded_chunks,
                    used_chunks, missed_chunks, audit_token, audit_closed, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    audit_id,
                    agent_id,
                    identity.entity_uri,
                    now_ms,
                    intent,
                    json.dumps(loaded_chunk_names),
                    "[]",
                    "[]",
                    audit_token,
                    None,
                    now_ms,
                ),
            )
    except Exception as exc:
        logger.warning("audit_write_failed: %s", exc)


@router.post("/v1/agents/{agent_id}/recall-instruction")
def recall_instruction(
    agent_id: str,
    req: RecallInstructionRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    _check_agent_access(identity, agent_id)

    with db() as conn:
        manifest_row = _get_current_manifest(conn, agent_id)
    if manifest_row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="manifest_not_found")

    entries: list[ManifestEntry] = [ManifestEntry(**e) for e in json.loads(manifest_row["body"])]

    chunks, used_names, missed_hints, tokens_used = _resolve_hint_chunks(
        entries,
        req.manifest_hint,
        req.token_budget,
    )

    ranked_chunks, tokens_used = _resolve_ranked_chunks(
        entries,
        req.intent,
        used_names,
        req.max_chunks - len(chunks),
        req.token_budget,
        tokens_used,
    )
    chunks.extend(ranked_chunks)

    tokens_used, truncated = _append_guaranteed_chunks(
        entries,
        used_names,
        chunks,
        tokens_used,
        req.token_budget,
    )

    audit_token = _AUDIT_TOKEN_PREFIX + secrets.token_urlsafe(16)
    now_ms = _now_ms()
    _write_recall_audit(
        _AUDEVENT_PREFIX + str(uuid.uuid4()),
        agent_id,
        identity,
        req.intent,
        [c["name"] for c in chunks],
        audit_token,
        now_ms,
    )

    return {
        "chunks": chunks,
        "total_tokens": tokens_used,
        "truncated": truncated,
        "missed_hints": missed_hints,
        "audit_token": audit_token,
    }


def _make_chunk(
    entry: ManifestEntry, content: str, tokens: int, source: str, score: float
) -> dict[str, Any]:
    valid_until = _get_fact_valid_until(entry.fact_uri) if entry.fact_uri else None
    # Extract version from fact_uri, e.g. "instruction:.../v2" → "v2"
    version = "v1"
    if entry.fact_uri:
        parts = entry.fact_uri.rstrip("/").split("/")
        if parts:
            version = parts[-1]
    return {
        "name": entry.name,
        "fact_uri": entry.fact_uri,
        "content": content,
        "tokens": tokens,
        "valid_until": valid_until,
        "version": version,
        "score": round(score, 4),
        "source": source,
    }


# ---------------------------------------------------------------------------
# 21.8.5 Submit Discovery Audit
# ---------------------------------------------------------------------------


@router.post("/v1/instruction/audit", status_code=status.HTTP_204_NO_CONTENT)
def submit_discovery_audit(
    req: AuditSubmitRequest,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> Response:
    now_ms = _now_ms()

    with db() as conn:
        row = conn.execute(
            "SELECT id, agent_id, created_at, audit_closed FROM instruction_audit"
            " WHERE audit_token = ?",
            (req.audit_token,),
        ).fetchone()

        if row is None:
            raise HTTPException(400, detail="audit_token_invalid")

        # Bind the submitter to the audit's agent (audit F-8): possession of
        # the token is necessary but not sufficient — the caller must be that
        # agent (or an admin), else a leaked token closes another agent's audit.
        _check_agent_access(identity, row["agent_id"])

        # Idempotent: already closed
        if row["audit_closed"] is not None:
            return Response(status_code=status.HTTP_204_NO_CONTENT)

        # TTL check
        age_s = (now_ms - row["created_at"]) / 1000
        if age_s > _AUDIT_TOKEN_TTL_S:
            raise HTTPException(400, detail="audit_token_expired")

        conn.execute(
            "UPDATE instruction_audit"
            " SET used_chunks = ?, missed_chunks = ?, audit_closed = ?"
            " WHERE audit_token = ?",
            (
                json.dumps(req.used_chunks),
                json.dumps(req.missed_chunks),
                now_ms,
                req.audit_token,
            ),
        )

    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ---------------------------------------------------------------------------
# 21.8.6 Get Manifest Coverage Report
# ---------------------------------------------------------------------------


@router.get("/v1/agents/{agent_id}/instruction-manifest/coverage")
def get_manifest_coverage(
    agent_id: str,
    identity: Annotated[Identity, Depends(resolve_identity)],
) -> dict[str, Any]:
    # Scope validation (S9)
    _check_agent_access(identity, agent_id)

    with db() as conn:
        manifest_row = _get_current_manifest(conn, agent_id)
        if manifest_row is None:
            raise HTTPException(status_code=404, detail="manifest_not_found")

        entries_raw: list[dict[str, Any]] = json.loads(manifest_row["body"])
        entries = [ManifestEntry(**e) for e in entries_raw]

        # Compute per-unit metrics from audit log
        cutoff_ms = _now_ms() - 7 * 86_400 * 1000  # 7-day window
        audit_rows = conn.execute(
            "SELECT loaded_chunks, used_chunks FROM instruction_audit"
            " WHERE agent_id = ? AND created_at >= ?",
            (agent_id, cutoff_ms),
        ).fetchall()

    is_admin = _is_admin(identity)
    now_iso = datetime.now(UTC).isoformat()

    unit_stats: dict[str, dict[str, int]] = {}
    for entry in entries:
        unit_stats[entry.name] = {"loaded": 0, "used": 0, "total": len(audit_rows)}

    for row in audit_rows:
        loaded = set(json.loads(row["loaded_chunks"]))
        used = set(json.loads(row["used_chunks"]))
        for name in unit_stats:
            if name in loaded:
                unit_stats[name]["loaded"] += 1
            if name in used:
                unit_stats[name]["used"] += 1

    units_out = []
    for entry in entries:
        stats = unit_stats[entry.name]
        total = stats["total"]
        hit_at_10 = stats["loaded"] / total if total > 0 else 0.0
        coverage_pct = stats["used"] / total if total > 0 else 0.0
        unit_info: dict[str, Any] = {
            "name": entry.name,
            "coverage_pct": round(coverage_pct, 4),
            "hit_at_10": round(hit_at_10, 4),
            "probe_count": total,
            "last_evaluated_at": now_iso,
        }
        # S11: coverage_status only in admin-key responses
        if is_admin:
            if total == 0:
                cs = "not_evaluated"
            elif hit_at_10 >= 0.4:
                cs = "ok"
            else:
                cs = "coverage_critical"
            unit_info["coverage_status"] = cs
        units_out.append(unit_info)

    # Best-effort embedding model version
    from ..settings import settings as _settings_for_model

    emb_model: str = getattr(_settings_for_model, "embed_model_id", "unknown")

    return {
        "manifest_version": manifest_row["version"],
        "embedding_model_version": emb_model,
        "evaluated_at": now_iso,
        "units": units_out,
    }

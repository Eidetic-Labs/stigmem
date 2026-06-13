"""Admin / migration / audit CLI handlers extracted from cli.py.

These handlers are imported back into ``stigmem_node.cli`` so that the public
import surface (``from stigmem_node.cli import _cmd_backfill_cids`` etc.) is
preserved.  No behavioural changes — code was moved verbatim from cli.py.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

logger = logging.getLogger("stigmem.cli")


def _write_owner_only_text(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        file_obj = os.fdopen(fd, "w")
        fd = -1
        with file_obj as f:
            f.write(text)
    finally:
        if fd != -1:
            os.close(fd)
    os.chmod(path, 0o600)


def _resolve_scope_prefix_and_label(
    args: argparse.Namespace,
    deployment: str,
    agent_id: str,
) -> tuple[str, str]:
    """Pick the role/skill scope-prefix builder and produce a human-readable label."""
    from .instruction_migrate import scope_prefix_for_role, scope_prefix_for_skill

    if args.role:
        return scope_prefix_for_role(deployment, agent_id), f"role:{args.role}  agent:{agent_id}"
    return scope_prefix_for_skill(deployment, args.skill), f"skill:{args.skill}  agent:{agent_id}"


def _load_existing_state_from_db(
    db_path: str,
    stub_diff_uris: set[str],
    agent_id: str,
) -> tuple[dict[str, str], set[str]]:
    """Best-effort: read existing fact values + prior manifest entry names from local SQLite."""
    import json as _json
    import sqlite3

    existing_content: dict[str, str] = {}
    prev_names: set[str] = set()
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        for uri in stub_diff_uris:
            row = conn.execute(
                "SELECT value_v FROM facts WHERE entity = ? ORDER BY timestamp DESC LIMIT 1",
                (uri,),
            ).fetchone()
            if row:
                existing_content[uri] = str(row["value_v"])
        row = conn.execute(
            "SELECT body FROM instruction_manifests"
            " WHERE agent_id = ? AND superseded_at IS NULL"
            " ORDER BY created_at DESC LIMIT 1",
            (agent_id,),
        ).fetchone()
        if row:
            prev_names = {e["name"] for e in _json.loads(row["body"])}
        conn.close()
    except Exception as exc:
        print(f"warning: db query failed: {exc}", file=sys.stderr)
    return existing_content, prev_names


def _load_existing_state_from_api(
    node_url: str,
    api_key: str,
    stub_diff_uris: set[str],
    agent_id: str,
) -> tuple[dict[str, str], set[str]]:
    """Best-effort: fetch existing facts + manifest entries via HTTP."""
    try:
        import httpx
    except ImportError:
        print("warning: httpx not installed — skipping idempotency checks", file=sys.stderr)
        return {}, set()

    existing_content: dict[str, str] = {}
    prev_names: set[str] = set()
    headers = {"Authorization": f"Bearer {api_key}"}
    base = node_url.rstrip("/")

    for uri in stub_diff_uris:
        try:
            r = httpx.get(
                f"{base}/v1/facts",
                params={"entity": uri, "limit": 1},
                headers=headers,
                timeout=10.0,
            )
            if r.status_code == 200:
                facts = r.json().get("facts", [])
                if facts:
                    existing_content[uri] = str(facts[0]["value"]["v"])
        except Exception as exc:  # nosec B110 — best-effort pre-flight
            logger.debug("instruction migrate pre-flight fact fetch failed: %s", exc)
    try:
        r = httpx.get(
            f"{base}/v1/agents/{agent_id}/instruction-manifest",
            headers=headers,
            timeout=10.0,
        )
        if r.status_code == 200:
            prev_names = {e["name"] for e in r.json().get("entries", [])}
    except Exception as exc:  # nosec B110 — best-effort pre-flight
        logger.debug("instruction migrate pre-flight manifest fetch failed: %s", exc)
    return existing_content, prev_names


def _load_existing_state(
    args: argparse.Namespace,
    node_url: str,
    api_key: str,
    stub_diff_uris: set[str],
    agent_id: str,
) -> tuple[dict[str, str], set[str]]:
    """Dispatch to the DB-backed or HTTP-backed pre-flight loader, or return empty."""
    if args.db:
        return _load_existing_state_from_db(args.db, stub_diff_uris, agent_id)
    if api_key:
        return _load_existing_state_from_api(node_url, api_key, stub_diff_uris, agent_id)
    return {}, set()


def _confirm_proceed() -> bool:
    """Interactive [y/N] confirmation. Returns False on abort or non-y answer."""
    try:
        answer = input("Proceed? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print("\nAborted.")
        return False
    if answer.lower() not in ("y", "yes"):
        print("Aborted.")
        return False
    return True


def _cmd_instruction_migrate(args: argparse.Namespace) -> int:
    """Migrate markdown instruction files to stigmem facts and publish manifest."""
    import os
    import time
    from pathlib import Path

    from .instruction_migrate import (
        build_fact_uri,
        compute_diff,
        format_preview,
        parse_instruction_chunks,
        publish_manifest,
        write_facts,
    )

    path = Path(args.path)
    if not path.exists():
        print(f"error: path '{args.path}' does not exist", file=sys.stderr)
        return 1

    api_key = args.api_key or os.environ.get("STIGMEM_API_KEY", "")
    node_url = args.node_url
    deployment = args.deployment
    version = args.version
    agent_id = args.agent_id

    scope_prefix, scope_label = _resolve_scope_prefix_and_label(args, deployment, agent_id)

    chunks = parse_instruction_chunks(path)
    if not chunks:
        print(
            "No instruction chunks found. Check that the path contains .md files.",
            file=sys.stderr,
        )
        return 0

    # Idempotency pre-flight: load existing fact content + prior manifest entry names.
    stub_diff_uris = {build_fact_uri(scope_prefix, c.slug, version) for c in chunks}
    existing_content, prev_names = _load_existing_state(
        args,
        node_url,
        api_key,
        stub_diff_uris,
        agent_id,
    )

    diff = compute_diff(chunks, scope_prefix, version, existing_content, prev_names)
    print(format_preview(diff, scope_label, path, version))

    if args.dry_run:
        print("Dry-run mode — no changes written.")
        return 0

    work = [d for d in diff if d.action in ("CREATE", "UPDATE", "TOMBSTONE")]
    if not work:
        print("Nothing to do.")
        return 0

    if not args.yes and not _confirm_proceed():
        return 1

    if not api_key:
        print(
            "error: --api-key or STIGMEM_API_KEY env var required to write facts",
            file=sys.stderr,
        )
        return 1

    written, failed = write_facts(diff, node_url, api_key)
    if failed > 0:
        print(
            f"\n{failed} fact(s) failed to write. Manifest will NOT be published.",
            file=sys.stderr,
        )
        return 1

    # Unique manifest version per run (timestamp suffix)
    manifest_version = f"{version}-{int(time.time())}"
    if not publish_manifest(agent_id, diff, manifest_version, node_url, api_key):
        return 1

    print(f"\nDone. {written} fact(s) written, manifest published as version '{manifest_version}'.")
    print(f"Verify: stigmem recall-instruction via POST /v1/agents/{agent_id}/recall-instruction")
    return 0


def _cmd_instruction_manifest_generate(args: argparse.Namespace) -> int:
    """Generate an instruction manifest JSON from a directory of markdown files."""
    import json
    import re
    from pathlib import Path

    path = Path(args.path)
    if not path.is_dir():
        print(f"error: '{args.path}' is not a directory", file=sys.stderr)
        return 1

    entries = []
    md_files = sorted(path.glob("*.md")) + sorted(path.glob("**/*.md"))

    for md_file in md_files:
        try:
            text = md_file.read_text(encoding="utf-8")
        except Exception as exc:
            print(f"warning: skipping {md_file}: {exc}", file=sys.stderr)
            continue

        # Split at H2/H3 boundaries
        sections = re.split(r"(?m)^(#{2,3}\s+.+)$", text)

        # Merge heading with following content
        chunks: list[tuple[str, str]] = []
        i = 0
        while i < len(sections):
            if re.match(r"^#{2,3}\s+", sections[i].strip()):
                heading = sections[i].strip()
                body = sections[i + 1].strip() if i + 1 < len(sections) else ""
                chunks.append((heading, body))
                i += 2
            else:
                if sections[i].strip():
                    chunks.append(
                        ("# " + md_file.stem.replace("-", " ").title(), sections[i].strip())
                    )
                i += 1

        if not chunks:
            chunks = [("# " + md_file.stem.replace("-", " ").title(), text.strip())]

        for heading, body in chunks:
            heading_text = re.sub(r"^#{2,3}\s+", "", heading).strip()
            slug = re.sub(r"[^a-z0-9]+", "-", heading_text.lower()).strip("-")
            if not slug:
                slug = md_file.stem
            unit_name = f"{md_file.stem}-{slug}" if md_file.stem not in slug else slug

            keywords = list(
                {
                    w.lower()
                    for w in re.findall(r"\b[a-zA-Z]{4,}\b", heading_text + " " + body[:200])
                }
            )[:8]
            token_est = max(1, len(body) // 4)
            fact_uri = (
                f"instruction:{args.deployment}/agent/{args.agent_id}/{unit_name}/{args.version}"
            )

            entries.append(
                {
                    "name": unit_name,
                    "description": heading_text[:120],
                    "required_by_task_types": [],
                    "guarantee_load": False,
                    "load_triggers": {
                        "intents": [heading_text.lower()],
                        "keywords": keywords,
                        "task_types": [],
                    },
                    "fact_uri": fact_uri,
                    "path": str(md_file),
                    "token_estimate": token_est,
                }
            )

    result = {
        "version": args.version,
        "agent_id": args.agent_id,
        "deployment": args.deployment,
        "generated_from": str(path),
        "entries": entries,
    }
    output = json.dumps(result, indent=2)

    if args.out:
        _write_owner_only_text(args.out, output)
        print(f"Wrote {len(entries)} entries to {args.out}")
    else:
        print(output)

    return 0


def _cmd_audit_discovery(args: argparse.Namespace) -> int:
    """Print discovery audit metrics from the local database."""
    import json
    import sqlite3
    from datetime import UTC, datetime, timedelta

    from .settings import settings

    db_path = args.db or settings.db_path

    if args.since:
        try:
            since_dt = datetime.fromisoformat(args.since.replace("Z", "+00:00"))
        except ValueError:
            print(f"error: invalid --since date: {args.since}", file=sys.stderr)
            return 1
    else:
        since_dt = datetime.now(UTC) - timedelta(days=7)
    since_ms = int(since_dt.timestamp() * 1000)

    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
    except Exception as exc:
        print(f"error: cannot open database {db_path}: {exc}", file=sys.stderr)
        return 1

    agent_filter = args.agent
    rows = conn.execute(
        "SELECT * FROM instruction_audit WHERE agent_id LIKE ? AND session_start >= ?",
        (f"%{agent_filter}%", since_ms),
    ).fetchall()

    if not rows:
        print(f"No audit records found for agent '{agent_filter}' since {since_dt.date()}")
        return 0

    total = len(rows)
    recall_at_k_num: float = 0.0
    hit_at_k_num = 0
    total_used = 0
    total_missed = 0

    for row in rows:
        loaded = set(json.loads(row["loaded_chunks"]))
        used = json.loads(row["used_chunks"])
        missed = json.loads(row["missed_chunks"])
        used_set = set(used)
        missed_set = set(missed)

        if used_set:
            recall_at_k = len(used_set & loaded) / len(used_set)
            recall_at_k_num += recall_at_k
            if used_set & loaded:
                hit_at_k_num += 1

        total_used += len(used_set)
        total_missed += len(missed_set)

    recall_at_k_avg = recall_at_k_num / total if total > 0 else 0.0
    hit_at_k_avg = hit_at_k_num / total if total > 0 else 0.0
    miss_rate = (
        total_missed / (total_used + total_missed) if (total_used + total_missed) > 0 else 0.0
    )

    report = {
        "agent": agent_filter,
        "since": since_dt.isoformat(),
        "total_events": total,
        "recall_at_k": round(recall_at_k_avg, 4),
        "hit_at_k": round(hit_at_k_avg, 4),
        "miss_rate": round(miss_rate, 4),
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Discovery audit — agent: {agent_filter}  since: {since_dt.date()}")
        print(f"  Total events : {total}")
        print(f"  Recall@k     : {recall_at_k_avg:.1%}")
        print(f"  Hit@k        : {hit_at_k_avg:.1%}")
        print(f"  Miss rate    : {miss_rate:.1%}")
        if miss_rate > 0.15:
            print("  ALERT: miss_rate > 0.15 — manifest descriptions or triggers need review")

    conn.close()
    return 0


def _cmd_identity_rotate_key(args: argparse.Namespace) -> int:
    """Rotate the node or issuer Ed25519 key (spec §22.2).

    Generates a next-gen keypair, appends a rotation event to the manifest,
    submits updated manifest + KeyRotationLogEntry to the transparency log,
    and prints the new private key seed for injection into your secrets manager.

    The retiring key stays in the dual-trust accept_set for --dual-trust-days
    (default 90), covering all in-flight tokens signed under the old key.
    """
    import json as _json

    from .db import apply_migrations
    from .identity.capability import load_node_private_key
    from .identity.key_rotation import rotate_key
    from .identity.manifest import manifest_from_dict

    if args.db:
        import stigmem_node.settings as settings_module

        from .settings import Settings

        patched = Settings(db_path=args.db)
        settings_module.settings = patched

    from .settings import settings

    apply_migrations(db_path=settings.db_path)

    old_priv = load_node_private_key()
    if old_priv is None:
        print(
            "error: STIGMEM_NODE_PRIVATE_KEY is not configured — cannot rotate",
            file=sys.stderr,
        )
        return 1

    entity_uri = settings.node_url

    from .db import db as _db_ctx

    with _db_ctx() as conn:
        row = conn.execute(
            "SELECT manifest_json FROM federation_manifests WHERE entity_uri = ?",
            (entity_uri,),
        ).fetchone()

    if row is None:
        print(
            f"error: no manifest found for {entity_uri!r} in federation_manifests\n"
            "Publish a manifest first via PUT /v1/federation/manifest",
            file=sys.stderr,
        )
        return 1

    old_manifest = manifest_from_dict(_json.loads(row["manifest_json"]))

    try:
        result = rotate_key(
            entity_uri=entity_uri,
            old_manifest=old_manifest,
            old_private_key=old_priv,
            dual_trust_days=args.dual_trust_days,
            dry_run=args.dry_run,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    tag = "[DRY RUN] " if args.dry_run else ""
    print(f"{tag}Key rotation ({args.kind}) complete")
    print(f"  old key_id : {old_manifest.key_id}")
    print(f"  new key_id : {result.new_manifest.key_id}")
    print(f"  dual-trust : {result.rotation_log_entry.dual_trust_expires_at}")

    if not args.dry_run and result.manifest_log_entry and result.rotation_tl_entry:
        print(f"  manifest TL index  : {result.manifest_log_entry.log_index}")
        print(f"  rotation TL index  : {result.rotation_tl_entry.log_index}")

        from .identity.trust_store import store_peer_manifest

        store_peer_manifest(entity_uri, result.new_manifest, result.manifest_log_entry)
        print("  manifest stored in federation_manifests")

    print()
    print("ACTION REQUIRED — update your secrets manager with the new private key:")
    print(f"  STIGMEM_NODE_PRIVATE_KEY={result.new_private_key_b64}")
    print("Then restart the node.  Keep the old key value until the dual-trust window closes.")
    return 0


def _cmd_backfill_cids(args: argparse.Namespace) -> int:
    """Compute and persist CIDs for facts that pre-date Phase 13 (spec §25.6.3)."""
    import sqlite3 as _sqlite3

    from .cid import compute_cid as _compute_cid
    from .lifecycle.immutability import set_fact_cid_backfill_status

    db_path: str | None = getattr(args, "db", None)
    if db_path is None:
        import os as _os

        db_path = _os.environ.get("STIGMEM_DB_PATH", "stigmem.db")

    batch_size: int = getattr(args, "batch_size", 500)
    quiet: bool = getattr(args, "quiet", False)

    conn = _sqlite3.connect(db_path)
    conn.row_factory = _sqlite3.Row

    total_updated = 0
    collision_skipped = 0

    while True:
        rows = conn.execute(
            "SELECT f.id, f.entity, f.relation, f.value_type, f.value_v, f.source, "
            "f.scope, f.confidence, f.tenant_id"
            " FROM facts f"
            " LEFT JOIN fact_cid_backfill fcb ON fcb.fact_id = f.id"
            " WHERE f.cid IS NULL AND COALESCE(fcb.status, 'pending') != 'complete'"
            " LIMIT ?",
            (batch_size,),
        ).fetchall()
        if not rows:
            break

        for row in rows:
            cid = _compute_cid(
                entity=row["entity"],
                relation=row["relation"],
                value_type=row["value_type"],
                value_v=row["value_v"] or "",
                source=row["source"],
                scope=row["scope"],
                confidence=float(row["confidence"]),
            )
            # Check for CID collision before writing (tenant-scoped: the CID-alias
            # uniqueness is per (cid, tenant_id) after migration 052, F-SBOLA4).
            existing = conn.execute(
                "SELECT fact_id FROM fact_cid_aliases WHERE cid = ? AND tenant_id = ?",
                (cid, row["tenant_id"]),
            ).fetchone()
            if existing and existing["fact_id"] != row["id"]:
                collision_skipped += 1
                continue

            conn.execute(
                "INSERT OR IGNORE INTO fact_cid_aliases (fact_id, cid, tenant_id) VALUES (?, ?, ?)",
                (row["id"], cid, row["tenant_id"]),
            )
            set_fact_cid_backfill_status(conn, fact_id=row["id"], status="complete")

        conn.commit()
        total_updated += len(rows)
        if not quiet:
            print(f"backfill-cids: processed {total_updated} facts…", file=sys.stderr)

    # CID v2 migration: repoint existing facts' aliases to their v2 CID (binds
    # interpret_as). Pre-v2 facts fail read-path verification until this runs.
    from .lifecycle.immutability import rebind_facts_to_cid_v2

    rebind_stats = rebind_facts_to_cid_v2(conn, batch_size=batch_size)

    conn.close()
    if not quiet:
        print(
            f"backfill-cids: done — {total_updated} facts updated"
            + (f", {collision_skipped} CID collisions skipped" if collision_skipped else "")
            + f"; CID v2 rebind: {rebind_stats['rebound']} repointed"
            + (
                f", {rebind_stats['skipped_collision']} collisions skipped"
                if rebind_stats["skipped_collision"]
                else ""
            ),
            file=sys.stderr,
        )
    return 0


def _cmd_auth_bootstrap_key(args: argparse.Namespace) -> int:
    """Register a caller-provided admin-scope API key on a fresh install.

    The caller supplies the key value via `--key` or the
    `STIGMEM_BOOTSTRAP_KEY` env var; we hash and store it. This is by
    design: the system is not the credential-generation surface. The
    user keeps full custody of the raw key from the moment it exists.

    Refuses to run if the api_keys table is non-empty — bootstrap is
    one-shot. After bootstrap, additional keys go through
    `POST /v1/auth/keys` authenticated with the bootstrap key.
    """
    import os

    from .auth import register_api_key
    from .db import db

    # Resolve key material from the caller. We do NOT generate one.
    key_value: str | None = args.key or os.environ.get("STIGMEM_BOOTSTRAP_KEY")
    if not key_value:
        print(
            "ERROR: no key value provided. Generate one externally and pass via\n"
            "  --key VALUE   or   STIGMEM_BOOTSTRAP_KEY=VALUE\n\n"
            "Example:\n"
            "  KEY=$(openssl rand -hex 32)\n"
            '  stigmem auth bootstrap-key --key "$KEY"\n'
            "  # then use $KEY as `Authorization: Bearer $KEY` for API calls",
            file=sys.stderr,
        )
        return 2

    # Minimum-length check. Not a substitute for proper entropy
    # validation — we trust the caller used a CSPRNG — but it catches
    # obvious mistakes like `--key admin` or `--key password`.
    if len(key_value) < 16:
        print(
            f"ERROR: key must be at least 16 characters (got {len(key_value)}). "
            "Use `openssl rand -hex 32` or similar to generate sufficient entropy.",
            file=sys.stderr,
        )
        return 2

    with db() as conn:
        row = conn.execute("SELECT COUNT(*) FROM api_keys").fetchone()
        existing = int(row[0]) if row else 0

    if existing > 0:
        print(
            f"ERROR: api_keys table is not empty ({existing} row(s)). "
            "Bootstrap is one-shot.\n"
            "Mint additional keys via `POST /v1/auth/keys` "
            "authenticated with an existing admin key.",
            file=sys.stderr,
        )
        return 1

    permissions: list[str] = (
        args.permissions.split(",") if args.permissions else ["admin", "write", "read"]
    )

    # Discard the returned row id — it's UUID bookkeeping the adopter has
    # no use for. Suppressing it also avoids tripping CodeQL's name-based
    # heuristic that treats any variable matching `*key*` as a credential
    # candidate. (The actual raw key value never flows here; this is just
    # naming hygiene to prevent false positives on follow-up scans.)
    register_api_key(
        raw_key=key_value,
        entity_uri=args.entity_uri,
        permissions=permissions,
    )

    # Confirmation: entity + permissions only. The raw value is never
    # printed; the caller already has it from their `--key` / env-var input.
    print(
        f"Registered admin API key for entity={args.entity_uri!r} "
        f"with permissions={permissions!r}.\n"
        "Use your provided value as `Authorization: Bearer <value>` "
        "for subsequent requests.",
        file=sys.stderr,
    )
    return 0

"""Maintenance and migration CLI handlers."""

from __future__ import annotations

import argparse
import sys


def _cmd_decay_sweep(args: argparse.Namespace) -> int:
    from ..db import apply_migrations, db
    from ..lifecycle.decay import run_decay_sweep
    from ..settings import settings

    db_path: str = args.db or settings.db_path
    apply_migrations(db_path=db_path)

    if getattr(args, "all_tenants", False):
        # Multi-tenant operators: sweep every tenant so non-default tenants are
        # not silently skipped. Candidate selection inside run_decay_sweep is
        # tenant-scoped, so we iterate the distinct tenants and aggregate counts.
        with db() as conn:
            tenant_ids = [r["tenant_id"] for r in conn.execute(
                "SELECT DISTINCT tenant_id FROM facts"
            ).fetchall()]
        scanned = 0
        decayed = 0
        for tenant_id in tenant_ids:
            result = run_decay_sweep(
                ttl_seconds=args.ttl_seconds,
                min_confidence=args.min_confidence,
                scope=args.scope or None,
                dry_run=args.dry_run,
                tenant_id=tenant_id,
            )
            scanned += result["scanned"]
            decayed += result["decayed"]
    else:
        result = run_decay_sweep(
            ttl_seconds=args.ttl_seconds,
            min_confidence=args.min_confidence,
            scope=args.scope or None,
            dry_run=args.dry_run,
            tenant_id=getattr(args, "tenant", "default") or "default",
        )
        scanned = result["scanned"]
        decayed = result["decayed"]

    if args.dry_run:
        print(f"[dry-run] {scanned} facts would be decayed", file=sys.stderr)
    else:
        print(f"{decayed} facts decayed ({scanned} scanned)", file=sys.stderr)
    return 0


def _cmd_migrate_normalize_entities(args: argparse.Namespace) -> int:
    from ..db import apply_migrations
    from ..migrate import normalize_entities_sweep
    from ..settings import settings

    db_path: str = args.db or settings.db_path
    apply_migrations(db_path=db_path)

    registered, already_present = normalize_entities_sweep(db_path, dry_run=args.dry_run)

    if args.dry_run:
        print(
            f"[dry-run] {registered} aliases would be registered",
            file=sys.stderr,
        )
    else:
        print(
            f"{registered} aliases registered, {already_present} already present",
            file=sys.stderr,
        )
    return 0

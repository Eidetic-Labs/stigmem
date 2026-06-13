"""Maintenance and migration CLI handlers."""

from __future__ import annotations

import argparse
import sys


def _cmd_decay_sweep(args: argparse.Namespace) -> int:
    from ..db import apply_migrations
    from ..lifecycle.decay import run_decay_sweep
    from ..settings import settings

    db_path: str = args.db or settings.db_path
    apply_migrations(db_path=db_path)

    result = run_decay_sweep(
        ttl_seconds=args.ttl_seconds,
        min_confidence=args.min_confidence,
        scope=args.scope or None,
        dry_run=args.dry_run,
        tenant_id=getattr(args, "tenant", "default") or "default",
    )

    if args.dry_run:
        print(f"[dry-run] {result['scanned']} facts would be decayed", file=sys.stderr)
    else:
        print(f"{result['decayed']} facts decayed ({result['scanned']} scanned)", file=sys.stderr)
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

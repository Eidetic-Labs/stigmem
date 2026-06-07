"""Compatibility alias for :mod:`stigmem_node.lifecycle.immutability`."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

__all__ = [
    "rebind_facts_to_cid_v2",
    "set_embedding_status",
    "set_fact_cid_backfill_status",
    "set_fact_garden_membership",
    "set_fact_quarantine_status",
    "set_fact_validity_override",
    "utc_now_iso",
    "write_fact_journal",
]

if TYPE_CHECKING:
    from .lifecycle.immutability import (
        rebind_facts_to_cid_v2,
        set_embedding_status,
        set_fact_cid_backfill_status,
        set_fact_garden_membership,
        set_fact_quarantine_status,
        set_fact_validity_override,
        utc_now_iso,
        write_fact_journal,
    )
else:
    from .lifecycle import immutability as _impl

    sys.modules[__name__] = _impl

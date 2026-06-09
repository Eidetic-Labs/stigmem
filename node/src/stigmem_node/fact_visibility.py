"""Shared fact read-visibility boundary — the single definition of "which facts
may this caller read".

Every fact-returning surface (recall, query, cards, synthesize, intents, entity
resolution, …) must restrict results to facts that are:

  * in the caller's tenant (``f.tenant_id == caller.tenant_id``), and
  * in a garden the caller may see — using the PROJECTED garden
    ``COALESCE(fact_garden_membership.garden_id, facts.garden_id)`` — whenever
    the garden boundary is enforced (``garden_acl_enforced``; fail-closed once
    gardens-with-members exist).

Resolve the caller's scope ONCE per request with :func:`caller_read_scope`
(a single batched membership query), then either splice the SQL fragment into a
``FROM facts f`` query (preferred — push the filter into the DB) or filter loaded
rows in-memory with :meth:`ReadScope.fact_visible`. A CI guard
(``scripts/check_fact_query_tenant_scope.py``) flags any ``FROM facts`` query in
the route layer that does not carry tenant scoping, so a new surface cannot
silently leak.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .memory_garden_acl_gate import caller_visible_gardens, garden_acl_enforced

# SQL building block: callers that splice visible_facts_where() must also join
# fact_garden_membership so the projected-garden predicate resolves.
PROJECTED_GARDEN_JOIN = "LEFT JOIN fact_garden_membership fgm ON fgm.fact_id = f.id"


@dataclass(frozen=True)
class ReadScope:
    """A caller's resolved fact read scope (tenant + visible gardens)."""

    tenant_id: str
    enforce_gardens: bool
    visible_gardens: frozenset[str]

    def garden_allows(self, projected_garden_id: Any) -> bool:
        """Garden half of the visibility check, for surfaces that already enforce
        tenant scoping in SQL (recall ranker, graph edges, synthesize rows).

        True when the garden boundary is not enforced, the fact is garden-less,
        or the caller is a member of the (projected) garden. ``projected_garden_id``
        must be the COALESCE(fgm, facts) value, not raw ``facts.garden_id``.
        """
        if self.enforce_gardens and projected_garden_id is not None:
            return projected_garden_id in self.visible_gardens
        return True

    def fact_visible(self, *, tenant_id: Any, projected_garden_id: Any) -> bool:
        """True if a fact with this tenant + projected garden is readable."""
        if tenant_id != self.tenant_id:
            return False
        return self.garden_allows(projected_garden_id)


def caller_read_scope(identity: Any) -> ReadScope:
    """Resolve the caller's fact read scope with ONE batched membership query."""
    enforce = garden_acl_enforced()
    return ReadScope(
        tenant_id=getattr(identity, "tenant_id", "default") or "default",
        enforce_gardens=enforce,
        visible_gardens=caller_visible_gardens(identity) if enforce else frozenset(),
    )


def visible_facts_where(scope: ReadScope, alias: str = "f") -> tuple[str, list[Any]]:
    """Return a ``(sql_fragment, params)`` enforcing the read scope in SQL.

    The fragment assumes the query joins ``fact_garden_membership fgm`` (see
    :data:`PROJECTED_GARDEN_JOIN`). It always pins ``tenant_id`` and, when the
    garden boundary is enforced, restricts the projected garden to the caller's
    visible set (NULL garden always allowed). The IN-list is built only from
    ``?`` placeholders, so the SQL text stays free of caller input.
    """
    params: list[Any] = [scope.tenant_id]
    fragment = f" AND {alias}.tenant_id = ?"
    if scope.enforce_gardens:
        if scope.visible_gardens:
            placeholders = ",".join("?" for _ in scope.visible_gardens)
            fragment += (
                f" AND (COALESCE(fgm.garden_id, {alias}.garden_id) IS NULL"
                f" OR COALESCE(fgm.garden_id, {alias}.garden_id) IN ({placeholders}))"
            )
            params.extend(sorted(scope.visible_gardens))
        else:
            # Member of no garden → only garden-less facts are visible.
            fragment += f" AND COALESCE(fgm.garden_id, {alias}.garden_id) IS NULL"
    return fragment, params

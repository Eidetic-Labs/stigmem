"""BFS graph traversal — neighbors() implementation, spec §20.2.

Exported surface:
    bfs_neighbors(conn, seed_entity, max_depth, scope, tenant_id, ...) -> list[NeighborEntry]

Invariants honored:
  - Only traverses edges with confidence >= min_confidence and valid_until not expired.
  - Filters garden-tagged edges against caller ACL (§17.3).
  - Blocks federated edges (received_from is not null) if caller lacks federate perm (§19.5.2).
  - Relation filter supports prefix-glob only (e.g. "memory:*"), not full regex.
  - De-duplicates: each neighbor entity appears once at its shortest hop distance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ..auth import Identity

MAX_DEPTH = 3


@dataclass
class NeighborEntry:
    entity: str
    relation: str
    hops: int
    confidence: float
    source_trust: float | None
    path: list[str] = field(default_factory=list)


def bfs_neighbors(
    conn: Any,
    seed_entity: str,
    max_depth: int,
    scope: str,
    tenant_id: str,
    relation_filter: str | None = None,
    min_confidence: float = 0.1,
    min_trust: float = 0.0,
    identity: Identity | None = None,
) -> list[NeighborEntry]:
    """BFS over entity_edges, returning all neighbors within max_depth hops.

    path in each NeighborEntry is the list of traversed entity URIs from the
    seed up to (and including) the seed, excluding the neighbor itself.
    Shortest path is reported when an entity is reachable via multiple routes.
    """
    now = datetime.now(UTC).isoformat()

    results: list[NeighborEntry] = []
    # visited[entity] = path_from_seed_to_entity_not_including_entity
    visited: dict[str, list[str]] = {seed_entity: []}
    frontier: list[str] = [seed_entity]

    for hop in range(1, max_depth + 1):
        if not frontier:
            break

        next_frontier: list[str] = []

        for current_entity in frontier:
            path_to_current = visited[current_entity]
            # Path stored in neighbor = nodes from seed up to and including current
            neighbor_path = [*path_to_current, current_entity]

            edges = _fetch_incident_edges(
                conn,
                current_entity,
                scope,
                tenant_id,
                now,
                min_confidence,
                min_trust,
                relation_filter,
                identity,
            )

            for edge in edges:
                neighbor = edge["object"] if edge["subject"] == current_entity else edge["subject"]
                if neighbor in visited:
                    continue

                entry = NeighborEntry(
                    entity=neighbor,
                    relation=edge["relation"],
                    hops=hop,
                    confidence=edge["confidence"],
                    source_trust=edge["source_trust"],
                    path=neighbor_path,
                )
                results.append(entry)
                visited[neighbor] = neighbor_path
                next_frontier.append(neighbor)

        frontier = next_frontier

    return results


def _match_relation(relation: str, pattern: str) -> bool:
    """Prefix-glob match — 'memory:*' matches any relation starting with 'memory:'."""
    if pattern.endswith("*"):
        return relation.startswith(pattern[:-1])
    return relation == pattern


def _fetch_incident_edges(
    conn: Any,
    entity: str,
    scope: str,
    tenant_id: str,
    now: str,
    min_confidence: float,
    min_trust: float,
    relation_filter: str | None,
    identity: Identity | None,
) -> list[Any]:
    """Fetch and filter edges incident on entity from both traversal directions.

    Pre-filters by confidence + trust in SQL for efficiency.  Garden ACL,
    federation scope, and relation filter are applied in Python after fetch.
    """
    params: list[Any] = [entity, entity, scope, tenant_id, min_confidence, now]
    sql = """
        SELECT id, subject, relation, object, scope, garden_id,
               received_from, confidence, source_trust
        FROM entity_edges
        WHERE (subject = ? OR object = ?)
          AND scope = ?
          AND tenant_id = ?
          AND confidence >= ?
          AND (valid_until IS NULL OR valid_until > ?)
    """

    if min_trust > 0.0:
        # Edges with NULL source_trust pass through (trust not yet computed)
        sql += " AND (source_trust IS NULL OR source_trust >= ?)"
        params.append(min_trust)

    rows = conn.execute(sql, params).fetchall()

    # Garden ACL (§17.3): resolve the caller's read scope ONCE (batched, audit M3
    # secure-path), then filter edges in-memory via the shared predicate.
    # Anonymous (identity is None) callers skip garden filtering, as before.
    from ..fact_visibility import caller_read_scope

    read_scope = caller_read_scope(identity) if identity is not None else None

    filtered: list[Any] = []
    for row in rows:
        # Garden ACL (§17.3): hide edges in gardens the caller cannot see
        garden_id = row["garden_id"]
        if (
            read_scope is not None
            and garden_id is not None
            and not read_scope.garden_allows(garden_id)
        ):
            continue

        # Federation filter (§19.5.2): edges from remote nodes require federate perm
        received_from = row["received_from"]
        if received_from is not None and (identity is None or not identity.can_federate()):
            continue

        # Relation prefix-glob filter
        if relation_filter is not None and not _match_relation(row["relation"], relation_filter):
            continue

        filtered.append(row)

    return filtered

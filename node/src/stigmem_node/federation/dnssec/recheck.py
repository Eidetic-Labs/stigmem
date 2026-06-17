"""Relay-path DNSSEC recency/revocation re-check (Rev 6 I5 / build-phase 3c).

Rev 6 I5: a relayed fact's origin key is honored only if a DNSSEC re-check
within the effective interval confirms the binding. The cadence (3c.1) is
``clamp(record_DNS_TTL, floor, cap)`` — the origin's DNS TTL is its own freshness
signal, the admin sets the bounds — and re-checks are cached PER-ORIGIN, not
per-fact (NF-R5C-5). The asymmetric failure semantics (3c.2) ride on top.

This module owns three pieces:

  * ``effective_interval(ttl, floor, cap)`` — the clamp. A ``None`` TTL (a
    non-SECURE binding has no TTL to clamp) falls back to the floor.
  * ``RecheckCache`` — a per-origin (host-keyed) cache of the last validated
    binding so that, within the effective interval, the binding is NOT
    re-resolved (no DNS egress, no resolver consulted).
  * ``recheck_relay_binding`` — the ASYMMETRIC recency/revocation engine (3c.2).

Asymmetric failure semantics (Rev 6 I5, the recency engine):

  ============================= ============================ ===================
  re-check outcome              disposition                  audit event
  ============================= ============================ ===================
  within cadence                HONOR (no DNS)               —
  no pin on the recheck path    REJECT (contract breach)     —
  ACTIVE, fpr matches pin       HONOR (refresh + mark fresh) —
  ACTIVE, rotation (epoch+ /    HONOR (advance pin + grace)  —
    new fpr matches record)
  ACTIVE, fpr matches NEITHER   REJECT                       relay_origin_key_changed
  ACTIVE, epoch < host floor    REJECT (rollback)            relay_origin_rolled_back
  ACTIVE, aged RRSIG            REJECT (operator-confirm is  relay_origin_recheck_stale
    (FALLTHROUGH/REJECT)          first-trust-only)
  REVOKED (positive tombstone)  REJECT                       relay_origin_revoked
  suppression (BOGUS /          HONOR while within
    UNVALIDATABLE / INSECURE /    min(grace, k*ttl) of the
    ABSENT, incl. transport       pin's last_validated_at;
    SERVFAIL->BOGUS)              else REJECT (unreachable)  relay_origin_recheck_unreachable
  ============================= ============================ ===================

The asymmetry: a POSITIVE answer that withdraws the key (REVOKED / rollback) is
hard-rejected — an attacker cannot forge a withdrawal record, so a positive
answer is always honored as proof. SUPPRESSION (no positive proof of anything)
is time-boxed fail-closed and is NEVER treated as a positive revocation (that
would hand an attacker a revocation primitive) and NEVER extends a compromised
key indefinitely (that would defeat recency).

Cadence / TTL persistence (the seam's chosen approach):

  The cadence is anchored on the PERSISTENT ``pin.last_validated_at`` so
  revocation is detectable within the interval ACROSS RESTARTS. The pin does NOT
  persist the binding TTL (no schema change in 3c.2), so the cadence uses
  ``effective_interval(ttl=None, ...) == floor`` — the most conservative (most
  frequent) cadence: a re-resolution happens at least every ``floor`` seconds
  from the pin's last validation, which only ever IMPROVES recency. The
  unreachable-grace window's ``k*ttl`` term, which also needs a TTL the pin does
  not store, uses the conservative ``recheck_cap_seconds`` as the TTL bound; with
  the maintainer-pinned defaults this yields ``min(86400, 4*3600) = 14400s``,
  tighter than the absolute 24h cap (favoring recency / fail-closed). At most one
  re-resolution per origin per re-check call (the engine resolves once).

No DNSSEC / ``dnspython`` import is reachable from this module at load time (Rev 6
I11): ``resolve_dnssec_binding`` (and the epoch/freshness/pin DB primitives) are
imported function-locally, and the only DNS egress is through the injected
``resolver`` (TX-4 SSRF: ``LiveResolver`` / a system stub resolver only — never a
peer-supplied address; the engine introduces no new egress).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from ..origin_identity import OriginIdentityError, _audit_relay

if TYPE_CHECKING:  # type-checkers only; never imported at runtime (I11).
    from .record import BindingRecord


class RecheckRejected(OriginIdentityError):
    """The relay-path DNSSEC recency/revocation re-check rejected the binding.

    A typed subclass of :class:`OriginIdentityError` so the relay call site maps
    a reject cleanly to its fail-closed verdict. Raised on every asymmetric
    reject branch (revoked / rollback / aged / key-changed / unreachable-past-
    grace / missing-pin contract breach). The accompanying ``relay_origin_*``
    audit event is emitted BEFORE the raise.
    """


def effective_interval(ttl: int | None, *, floor: int, cap: int) -> int:
    """The relay-path re-check cadence ``clamp(ttl, floor, cap)`` (Rev 6 §7/I5).

    The origin's DNS TTL drives the cadence; the admin-set ``floor`` (anti-storm)
    and ``cap`` (DNS-load bound) clamp it. A ``None`` TTL (a binding that did not
    resolve SECURE, so it carries no TTL) has no freshness signal to honor and
    falls back to the ``floor`` — the most conservative cadence. ``floor`` is
    applied after ``cap`` so a (mis)configured ``floor > cap`` still yields the
    floor (never a value below it), keeping the anti-storm guarantee.
    """
    if ttl is None:
        return floor
    return max(floor, min(ttl, cap))


@dataclass
class _CacheEntry:
    """One per-origin cached re-check: the validated binding + when + its TTL."""

    record: BindingRecord
    validated_at: datetime
    ttl: int | None


class RecheckCache:
    """Per-origin (host-keyed) cache of the last validated relay-path re-check.

    Within ``effective_interval(ttl, floor, cap)`` of an origin's last validated
    re-check, the binding is served from this cache and the resolver is NOT
    consulted (NF-R5C-5: re-checks are per-origin, not per-fact — a page of
    relayed facts from one origin triggers at most one DNS re-resolution per
    cadence window). Past the interval, ``get`` returns ``None`` and the caller
    re-resolves.

    Keyed by the canonical host (Rev 6 I3), shared across the ``node_id``s a host
    serves (the binding is a property of the zone). Caller-owned: a request-scoped
    instance threads through the page loop, mirroring the ``resolve_origin_key_for_relay``
    per-request cache so a stale binding never persists across requests.
    """

    def __init__(self) -> None:
        self._entries: dict[str, _CacheEntry] = {}

    def get(
        self,
        host: str,
        *,
        now: datetime,
        floor: int,
        cap: int,
    ) -> BindingRecord | None:
        """Return the cached binding for ``host`` if still within its interval.

        ``None`` when the host is uncached or its entry is past the effective
        interval (the caller must re-resolve). The interval is derived from the
        CACHED entry's own TTL, so a short-TTL origin re-checks sooner.
        """
        entry = self._entries.get(host)
        if entry is None:
            return None
        interval = effective_interval(entry.ttl, floor=floor, cap=cap)
        if (now - entry.validated_at).total_seconds() < interval:
            return entry.record
        return None

    def put(
        self,
        host: str,
        *,
        record: BindingRecord,
        validated_at: datetime,
        ttl: int | None,
    ) -> None:
        """Record a fresh validated re-check for ``host`` (replaces any prior)."""
        self._entries[host] = _CacheEntry(record=record, validated_at=validated_at, ttl=ttl)


def _as_utc(dt: datetime) -> datetime:
    """Normalize a naive datetime to UTC (the engine's wall-clock convention)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _within_cadence(pin: Any, *, now: datetime, settings: Any) -> bool:
    """Whether ``now`` is still within the re-check cadence of the pin.

    Anchored on the PERSISTENT ``pin.last_validated_at`` (recency is detectable
    within the interval across restarts). The TTL is not persisted, so the
    cadence uses ``effective_interval(None, ...) == floor`` — the most
    conservative (most frequent) cadence. An unparseable ``last_validated_at``
    fails closed to "past cadence" so a re-resolution happens (never stale).
    """
    interval = effective_interval(
        None,
        floor=settings.federation_dnssec_recheck_floor_seconds,
        cap=settings.federation_dnssec_recheck_cap_seconds,
    )
    try:
        validated_at = _as_utc(datetime.fromisoformat(pin.last_validated_at))
    except (ValueError, TypeError):
        return False  # indeterminate -> re-resolve (fail toward recency)
    return (_as_utc(now) - validated_at).total_seconds() < interval


def _unreachable_grace_seconds(settings: Any) -> float:
    """The suppression / unreachable grace = ``min(grace, k * ttl)`` (Rev 6 I5).

    The pin does not persist the binding TTL, so the ``k * ttl`` term uses the
    conservative ``recheck_cap_seconds`` as the TTL bound (documented in the
    module docstring): with the maintainer-pinned defaults this is
    ``min(86400, 4 * 3600) = 14400s``, tighter than the 24h absolute cap.
    """
    k = settings.federation_dnssec_unreachable_ttl_multiple
    ttl_bound = settings.federation_dnssec_recheck_cap_seconds
    return float(min(settings.federation_dnssec_unreachable_grace_seconds, k * ttl_bound))


def _suppression_within_grace(pin: Any, *, now: datetime, settings: Any) -> bool:
    """Whether a no-positive-proof re-check is still inside the unreachable grace.

    Measured from the pin's PERSISTENT ``last_validated_at`` (the last time the
    binding was positively proven). An unparseable timestamp fails closed (past
    grace) so suppression never extends a key indefinitely.
    """
    try:
        validated_at = _as_utc(datetime.fromisoformat(pin.last_validated_at))
    except (ValueError, TypeError):
        return False  # indeterminate -> past grace (fail closed, recency wins)
    elapsed = (_as_utc(now) - validated_at).total_seconds()
    return elapsed <= _unreachable_grace_seconds(settings)


# Validator outcomes carrying NO positive proof for a PINNED binding: a transport
# failure (SERVFAIL/timeout) maps to BOGUS (total/fail-closed); UNVALIDATABLE /
# INSECURE / ABSENT_AUTHENTICATED are likewise "no positive proof" on the relay
# path. None is honored as revocation (Rev 6 I5 / NF-R5D-2).
def _is_suppression(outcome: Any) -> bool:
    from .resolve import DnssecResult

    return outcome in (
        DnssecResult.Outcome.BOGUS,
        DnssecResult.Outcome.UNVALIDATABLE,
        DnssecResult.Outcome.INSECURE,
        DnssecResult.Outcome.ABSENT_AUTHENTICATED,
        DnssecResult.Outcome.NOT_APPLICABLE,
    )


def recheck_relay_binding(
    conn: Any,
    *,
    host: str,
    entity_uri: str,
    node_id: str,
    key_fpr: str,
    resolver: Any,
    settings: Any,
    now: datetime,
) -> None:
    """Re-check a pinned DNSSEC binding's recency/revocation (Rev 6 I5).

    Returns ``None`` on HONOR (the relayed key is still current); raises
    :class:`RecheckRejected` (a fail-closed ``OriginIdentityError``) on every
    asymmetric reject branch, after emitting the matching ``relay_origin_*``
    audit event. See the module docstring for the full outcome table.

    The caller (``origin_identity._dnssec_first_trust_keys`` TRUSTED branch) owns
    the transaction; HONOR mutations (pin refresh / rotation advance / fresh
    stamp) are written on ``conn`` and the caller commits.
    """
    from . import epoch as ep
    from . import freshness as fr
    from . import pin as pinstore
    from .resolve import DnssecResult, resolve_dnssec_binding

    # --- step 1: the pin MUST exist (contract breach otherwise) ---------------
    pin = pinstore.get_pin(conn, entity_uri, node_id) if conn is not None else None
    if pin is None:
        # The TRUSTED branch always pins before re-checking; a missing pin on the
        # recheck path is a contract breach -> fail closed (resolver untouched).
        raise RecheckRejected(
            f"relayed origin {node_id!r} ({entity_uri!r}) recheck has no pin (contract breach)"
        )

    # --- step 2: cadence — within interval -> HONOR with no DNS ----------------
    if _within_cadence(pin, now=now, settings=settings):
        return  # the pinned key is current as of its last successful re-check

    # --- step 3: re-resolve (at most once per origin per call) ----------------
    result = resolve_dnssec_binding(entity_uri, resolver=resolver)
    outcome = result.outcome

    # --- REVOKED: positive withdrawal -> hard reject --------------------------
    if outcome is DnssecResult.Outcome.REVOKED:
        _audit_relay(
            "relay_origin_revoked",
            node_id=node_id,
            entity_uri=entity_uri,
            detail_epoch=result.record.epoch if result.record else None,
        )
        raise RecheckRejected(
            f"relayed origin {node_id!r} ({entity_uri!r}) revoked by dnssec record"
        )

    # --- ACTIVE: rotation / rollback / aged / match ---------------------------
    if outcome is DnssecResult.Outcome.ACTIVE:
        record = result.record
        if record is None or not record.fpr:
            # ACTIVE must carry a fingerprint; absence is a contract breach ->
            # treat as suppression (no positive proof), never trust it.
            return _suppression_disposition(
                pin, node_id=node_id, entity_uri=entity_uri, now=now, settings=settings
            )

        # Monotonic epoch (I4): a record epoch below the host floor is a rollback.
        if not ep.accept_epoch(conn, host, record.epoch):
            _audit_relay(
                "relay_origin_rolled_back",
                node_id=node_id,
                entity_uri=entity_uri,
                detail_epoch=record.epoch,
            )
            raise RecheckRejected(
                f"relayed origin {node_id!r} ({entity_uri!r}) epoch rollback "
                f"(record epoch {record.epoch} below host floor)"
            )

        # Aged-RRSIG clamp (I4). On the RELAY path an aged binding is a HARD
        # REJECT — operator-confirm is first-trust-only and cannot run mid-relay,
        # so both FALLTHROUGH_CONFIRM and the previously-fresh REJECT -> reject.
        if _rrsig_is_aged(result, now=now, settings=settings, fr=fr):
            _audit_relay(
                "relay_origin_recheck_stale",
                node_id=node_id,
                entity_uri=entity_uri,
            )
            raise RecheckRejected(
                f"relayed origin {node_id!r} ({entity_uri!r}) aged dnssec signature on relay path"
            )

        # The live record's fingerprint must reconcile with the stored anchor
        # (Rev 6 I4/I6): it HONORS when it matches the pin's current-or-prev-
        # within-grace fpr (steady state), OR when it is a genuine rotation
        # (a NEW fpr at a STRICTLY HIGHER epoch — monotonic-epoch-protected). A
        # record.fpr matching NEITHER (a different key WITHOUT an epoch bump) is
        # an unsanctioned key change -> reject.
        is_steady_or_grace = pinstore.pin_matches(pin, record.fpr, now=now)
        is_rotation = record.fpr != pin.key_fpr and record.epoch > pin.epoch
        if not (is_steady_or_grace or is_rotation):
            _audit_relay(
                "relay_origin_key_changed",
                node_id=node_id,
                entity_uri=entity_uri,
            )
            raise RecheckRejected(
                f"relayed origin {node_id!r} ({entity_uri!r}) live record binds a key matching "
                f"neither the pinned current nor grace-window prior key (no rotation epoch bump)"
            )

        # HONOR: advance the pin to the live record. On a rotation (a new fpr) the
        # OLD pinned key becomes prev_fpr with a live grace window (I6); on steady
        # state the pin is refreshed in place.
        _honor_active(
            conn,
            pin=pin,
            record=record,
            host=host,
            entity_uri=entity_uri,
            node_id=node_id,
            now=now,
            is_rotation=is_rotation,
            settings=settings,
            ep=ep,
            fr=fr,
            pinstore=pinstore,
        )

        # Rotation grace via prev_fpr (Rev 6 I6, 3c.3): the relayed fact's own
        # signing key must be one the (now-refreshed) pin honors — the CURRENT
        # key always, or the committed PRIOR key while inside its grace window.
        # A fact still signed by the retiring key verifies within
        # ``federation_key_rotation_grace_hours`` of the rotation, NOT past it
        # (the shared ``pin_matches`` predicate). Re-read the pin so a rotation
        # this re-check just committed (old key -> prev_fpr) is reflected.
        refreshed = pinstore.get_pin(conn, entity_uri, node_id)
        if refreshed is None or not pinstore.pin_matches(refreshed, key_fpr, now=now):
            _audit_relay(
                "relay_origin_key_changed",
                node_id=node_id,
                entity_uri=entity_uri,
            )
            raise RecheckRejected(
                f"relayed origin {node_id!r} ({entity_uri!r}) signing key is neither the "
                f"current pinned key nor a prior key within rotation grace (I6)"
            )
        return

    # --- suppression (no positive proof) -> time-boxed fail-closed ------------
    if _is_suppression(outcome):
        return _suppression_disposition(
            pin, node_id=node_id, entity_uri=entity_uri, now=now, settings=settings
        )

    # --- defensive: any unmodeled outcome is fail-closed (I10) ----------------
    raise RecheckRejected(
        f"relayed origin {node_id!r} ({entity_uri!r}) recheck unexpected outcome: {outcome.value}"
    )


def _rrsig_is_aged(result: Any, *, now: datetime, settings: Any, fr: Any) -> bool:
    """Whether the ACTIVE binding's RRSIG is aged (relay-path reject signal, I4).

    Reuses ``classify_rrsig_age``: an aged RRSIG that on first-trust would route to
    operator-confirm (FALLTHROUGH_CONFIRM) OR hard-reject (previously-fresh REJECT)
    is, on the RELAY path, a reject either way (operator-confirm cannot run
    mid-relay). A missing inception (contract breach) is treated as aged (fail
    closed; never treat as fresh).
    """
    if result.rrsig_inception is None:
        return True
    age = _as_utc(now).timestamp() - result.rrsig_inception
    # A PINNED binding is by definition a host that previously served a fresh,
    # validated signature (the first-trust ladder stamped ``mark_fresh`` when it
    # pinned). On the relay path the previously-fresh hard-reject therefore
    # always applies — and FALLTHROUGH_CONFIRM is likewise a relay reject
    # (operator-confirm cannot run mid-relay) — so any non-OK age is aged.
    age_class = fr.classify_rrsig_age(
        rrsig_age_seconds=age,
        max_age=settings.federation_dnssec_max_rrsig_age,
        previously_fresh=True,
    )
    return age_class is not fr.AgeClass.OK


def _grace_deadline(record: Any, *, now: datetime, settings: Any) -> datetime | None:
    """The rotation-grace deadline for ``record.prev_fpr`` (Rev 6 I6).

    Uses the record's committed ``prev_until`` when present and parseable; else
    derives ``now + federation_key_rotation_grace_hours``. Returns ``None`` only
    when a ``prev_until`` is present but unparseable (fail-closed: no live grace).
    """
    if record.prev_until:
        try:
            deadline = datetime.fromisoformat(record.prev_until)
        except (ValueError, TypeError):
            return None
        return _as_utc(deadline)
    return _as_utc(now) + timedelta(hours=settings.federation_key_rotation_grace_hours)


def _honor_active(
    conn: Any,
    *,
    pin: Any,
    record: Any,
    host: str,
    entity_uri: str,
    node_id: str,
    now: datetime,
    is_rotation: bool,
    settings: Any,
    ep: Any,
    fr: Any,
    pinstore: Any,
) -> None:
    """HONOR an ACTIVE re-check: advance the pin, set rotation grace (I6), mark fresh.

    On a rotation (``is_rotation`` — a new fpr at a strictly higher epoch) the OLD
    pinned key becomes ``prev_fpr`` with ``prev_until`` = the record's committed
    deadline OR ``now + federation_key_rotation_grace_hours`` (I6, whichever the
    record supplies), so a fact still signed by the retiring key verifies within
    grace (3c.3). On a steady-state match the pin is refreshed in place and any
    record-carried rotation grace is propagated.
    """
    if is_rotation:
        deadline = _grace_deadline(record, now=now, settings=settings)
        prev_fpr = pin.key_fpr
        prev_until = deadline.isoformat() if deadline is not None else None
    elif record.prev_fpr:
        # Steady state, but the live record re-advertises a rotation grace: refresh
        # it from the record (the record is the authoritative grace source).
        deadline = _grace_deadline(record, now=now, settings=settings)
        prev_fpr = record.prev_fpr
        prev_until = deadline.isoformat() if deadline is not None else None
    else:
        # Steady state with no record-carried grace: PRESERVE the existing pin's
        # rotation-grace window (a prior rotation's prev_fpr/prev_until). A
        # steady-state record stops re-advertising prev_fpr once the rotation
        # settles, but the pinned grace window must persist until prev_until so a
        # fact still signed by the retiring key verifies within grace (I6). The
        # window naturally lapses via pin_matches' prev_until check.
        prev_fpr = pin.prev_fpr
        prev_until = pin.prev_until

    pinstore.upsert_pin(
        conn,
        entity_uri=entity_uri,
        node_id=node_id,
        key_fpr=record.fpr,
        epoch=record.epoch,
        host=host,
        prev_fpr=prev_fpr,
        prev_until=prev_until,
        now=now,
    )
    ep.mark_signed_delegation(conn, host)
    fr.mark_fresh(conn, host, now=_as_utc(now).isoformat())


def _suppression_disposition(
    pin: Any, *, node_id: str, entity_uri: str, now: datetime, settings: Any
) -> None:
    """A no-positive-proof re-check: HONOR within grace, else fail-closed (I5).

    NEVER emits ``relay_origin_revoked`` (suppression is not a positive
    revocation primitive); past the unreachable grace it emits
    ``relay_origin_recheck_unreachable`` and raises.
    """
    if _suppression_within_grace(pin, now=now, settings=settings):
        return  # honor the pinned key up to the bounded grace
    _audit_relay(
        "relay_origin_recheck_unreachable",
        node_id=node_id,
        entity_uri=entity_uri,
    )
    raise RecheckRejected(
        f"relayed origin {node_id!r} ({entity_uri!r}) recheck unreachable past grace "
        f"(no positive dnssec proof; fail-closed, NOT revoked)"
    )

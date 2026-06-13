"""First-trust ladder: operator-pin -> DNSSEC -> operator-confirm -> fail-closed.

Rev 6 §2/§5 precedence, invariants I1 (first-trust rooted, never silent
first-seen-wins), I2 (sticky-signedness: an authenticated absence on a host that
has served a signed delegation is an attack), I4 (monotonic epoch + RRSIG-age
clamp -> operator-confirm, with the previously-fresh hard-reject), I9
(operator-confirm queue-bounded), I10 (outcome lattice: every branch exit is a
verified-accept or a raise/reject — no permissive intermediate return).

``resolve_first_trust`` is a PURE resolver. It composes the already-built
primitives (``pin``, ``resolve_dnssec_binding``, ``epoch``, ``freshness``,
``quarantine``) and returns a ``TrustDecision``. It deliberately:

  * does NOT read ``federation_dnssec_trust_enabled`` — that flag gates the CALL
    SITE (a later batch), not the ladder logic itself;
  * does NOT touch the relay path or perform any network egress of its own
    (DNS resolution happens through the injected ``resolver``);
  * is not wired anywhere yet.

Self-certification (Rev 6 I3, plan TB-1): there is NO self-signed shortcut. An
origin block naming this node's own identity goes through the same ladder; trust
is rooted in the pin store or the DNSSEC chain, never in the origin asserting its
own key. The wire ``entity_uri`` is self-certifying — a forged one only selects a
zone the forger controls — and the downstream ``origin_sig`` check (not this
module) closes the loop.

RRSIG-age seam (see the implementer note in the batch report): the frozen 3a
``resolve_dnssec_binding`` does not surface an RRSIG age (the validator is strict:
an out-of-window RRSIG is BOGUS, so a SECURE binding is by construction inside
the validity window). The ladder therefore accepts the RRSIG age as the optional
``rrsig_age_seconds`` parameter, supplied by the call site that parses the live
DNS message (the 3c relay/recheck layer). When it is ``None`` (the 3b default,
before that extraction is wired), a SECURE binding is treated as fresh — which
matches the validator's strict-window guarantee. The age-clamp branches (I4) fire
only when a caller supplies an age.

dnspython stays out of this module's import graph (Rev 6 I11): the only DNSSEC
work is delegated to ``resolve_dnssec_binding``, which imports dnspython lazily.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from . import epoch as ep
from . import freshness as fr
from . import pin as pinstore
from . import quarantine as q
from .host import host_from_entity_uri
from .resolve import DnssecResult, resolve_dnssec_binding

if TYPE_CHECKING:  # type-checkers only; never imported at runtime (I11).
    from .resolver import Resolver


@dataclass(frozen=True)
class TrustDecision:
    """The ladder's verdict for a candidate origin key.

    ``outcome`` is always populated; ``reason`` is a short functional label for
    audit/logging (never operator-education prose).
    """

    class Outcome(enum.Enum):
        TRUSTED = "trusted"
        PENDING_CONFIRM = "pending_confirm"
        REJECTED = "rejected"

    outcome: TrustDecision.Outcome
    reason: str


def _trusted(reason: str) -> TrustDecision:
    return TrustDecision(TrustDecision.Outcome.TRUSTED, reason)


def _rejected(reason: str) -> TrustDecision:
    return TrustDecision(TrustDecision.Outcome.REJECTED, reason)


def _pending(reason: str) -> TrustDecision:
    return TrustDecision(TrustDecision.Outcome.PENDING_CONFIRM, reason)


def _quarantine_or_fail_closed(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
    candidate_key_fpr: str,
    source: str,
    relay_peer: str | None,
    now: datetime,
    settings: Any,
    confirm_source: str,
) -> TrustDecision:
    """Step 3: park the candidate for operator-confirm, or fail closed (I9/I10).

    ``confirm_source`` is the queue-row ``source`` label distinguishing the
    fallthrough kind ("unsigned" / "insecure-delegation" / "absent" /
    "not-applicable"); a full queue (per-peer cap) fails closed -> REJECTED so an
    untrusted relay cannot trade a flood for silent trust.
    """
    parked = q.quarantine(
        conn,
        entity_uri=entity_uri,
        node_id=node_id,
        candidate_key_fpr=candidate_key_fpr,
        source=confirm_source,
        relay_peer=relay_peer,
        now=now,
        cap=settings.federation_dnssec_pending_confirm_cap,
    )
    if parked:
        return _pending(f"operator-confirm queued ({confirm_source})")
    return _rejected("operator-confirm queue full (fail-closed)")


def resolve_first_trust(
    conn: Any,
    *,
    entity_uri: str,
    node_id: str,
    candidate_key_fpr: str,
    resolver: Resolver,
    settings: Any,
    now: datetime,
    relay_peer: str | None = None,
    source: str = "relay",
    rrsig_age_seconds: float | None = None,
) -> TrustDecision:
    """Resolve first-trust for a candidate origin key (Rev 6 ladder, I1/I10).

    Precedence: operator-pin / existing pin -> DNSSEC -> operator-confirm ->
    fail-closed. Returns a ``TrustDecision``. Pure resolver: no flag read, no
    relay-path side effects, no network egress beyond the injected ``resolver``.
    """
    # --- step 1: operator-pin / existing pin (I1) ----------------------------
    existing = pinstore.get_pin(conn, entity_uri, node_id)
    if existing is not None:
        if pinstore.pin_matches(existing, candidate_key_fpr, now=now):
            # Re-validation against an established anchor: refresh the pin's
            # last_validated_at and trust.
            pinstore.upsert_pin(
                conn,
                entity_uri=entity_uri,
                node_id=node_id,
                key_fpr=existing.key_fpr,
                epoch=existing.epoch,
                host=existing.host,
                prev_fpr=existing.prev_fpr,
                prev_until=existing.prev_until,
                now=now,
            )
            return _trusted("matches established pin")
        # An established pin exists and the candidate does NOT match it. This is
        # disagreement with a stored anchor (I8) — an attack, NOT a fresh
        # first-trust. A genuine key change must go through DNSSEC
        # rotation/revocation (higher epoch / prev_fpr grace / revoked record),
        # which updates the pin; it never re-enters first-trust. Do NOT fall
        # through to the DNSSEC tier here.
        return _rejected("candidate disagrees with established pin")

    # --- step 2: DNSSEC (I2/I3/I4) -------------------------------------------
    host = host_from_entity_uri(entity_uri)
    if host is None:
        # Non-DNSSEC-capable entity_uri (non-HTTP scheme, IP-literal, userinfo,
        # port) -> the DNSSEC tier is not applicable; route to operator-confirm
        # (Rev 6 I3 — an expected ladder path, not an error).
        return _quarantine_or_fail_closed(
            conn,
            entity_uri=entity_uri,
            node_id=node_id,
            candidate_key_fpr=candidate_key_fpr,
            source=source,
            relay_peer=relay_peer,
            now=now,
            settings=settings,
            confirm_source="not-applicable",
        )

    result = resolve_dnssec_binding(entity_uri, resolver=resolver)
    outcome = result.outcome

    if outcome is DnssecResult.Outcome.REVOKED:
        # A DNSSEC-validated revocation tombstone: all keys for the host are dead.
        return _rejected("dnssec revoked record")

    if outcome is DnssecResult.Outcome.BOGUS:
        # Forged / broken chain / transport failure -> fail closed.
        return _rejected("dnssec bogus chain")

    if outcome is DnssecResult.Outcome.UNVALIDATABLE:
        # An absence (or answer) with no validatable proof either way -> reject;
        # never fall through to operator-confirm on an unvalidatable result (I2).
        return _rejected("dnssec unvalidatable")

    if outcome in (
        DnssecResult.Outcome.INSECURE,
        DnssecResult.Outcome.ABSENT_AUTHENTICATED,
    ):
        # Authenticated unsigned delegation, or authenticated absence. Both are
        # genuine fall-through-to-operator-confirm signals — EXCEPT when the host
        # has previously served a SIGNED delegation: sticky-signedness (I2) makes
        # a later authenticated "absent"/"insecure" an attack -> reject.
        if ep.signed_delegation_seen(conn, host):
            return _rejected("authenticated-absent on sticky-signed host")
        kind = (
            "insecure-delegation"
            if outcome is DnssecResult.Outcome.INSECURE
            else "absent"
        )
        return _quarantine_or_fail_closed(
            conn,
            entity_uri=entity_uri,
            node_id=node_id,
            candidate_key_fpr=candidate_key_fpr,
            source=source,
            relay_peer=relay_peer,
            now=now,
            settings=settings,
            confirm_source=kind,
        )

    # The only remaining outcome is ACTIVE (NOT_APPLICABLE cannot occur — host
    # is non-None here; resolve_dnssec_binding only returns NOT_APPLICABLE when
    # host derivation yields None, which we already handled). Treat any other
    # value defensively as fail-closed (I10: no permissive default).
    if outcome is not DnssecResult.Outcome.ACTIVE:
        return _rejected(f"dnssec unexpected outcome: {outcome.value}")

    record = result.record
    if record is None or not record.fpr:
        # ACTIVE must carry a non-empty fingerprint; absence is a contract breach.
        return _rejected("dnssec active without fingerprint")

    # The candidate key MUST be the one the validated record binds. A SECURE
    # record binding a DIFFERENT fingerprint than the relayed candidate is a
    # mismatch -> reject (carried bytes are never the key source, I6/I7).
    if record.fpr != candidate_key_fpr:
        return _rejected("dnssec record binds a different fingerprint")

    # Monotonic epoch (I4): a record epoch below the host's floor is a rollback.
    if not ep.accept_epoch(conn, host, record.epoch):
        return _rejected("dnssec epoch rollback")

    # RRSIG-age clamp (I4). See the module docstring: when no age is supplied the
    # SECURE binding is treated as fresh (the validator already enforced the
    # validity window). When an age is supplied, classify it.
    if rrsig_age_seconds is not None:
        age_class = fr.classify_rrsig_age(
            rrsig_age_seconds=rrsig_age_seconds,
            max_age=settings.federation_dnssec_max_rrsig_age,
            previously_fresh=fr.was_previously_fresh(conn, host),
        )
        if age_class is fr.AgeClass.REJECT:
            # Previously-fresh host now serving only aged signatures -> attack (I4).
            return _rejected("aged rrsig on previously-fresh host")
        if age_class is fr.AgeClass.FALLTHROUGH_CONFIRM:
            # Aged RRSIG on a never-fresh host -> slow-resigning zone behind a
            # human gate (operator-confirm), not a hard reject (I4).
            return _quarantine_or_fail_closed(
                conn,
                entity_uri=entity_uri,
                node_id=node_id,
                candidate_key_fpr=candidate_key_fpr,
                source=source,
                relay_peer=relay_peer,
                now=now,
                settings=settings,
                confirm_source="stale-dnssec",
            )

    # SECURE + binds-candidate + epoch-OK + fresh -> TRUSTED. Stamp the host's
    # sticky-signed + fresh markers and pin the identity (I1).
    ep.mark_signed_delegation(conn, host)
    fr.mark_fresh(conn, host, now=now.isoformat())
    pinstore.upsert_pin(
        conn,
        entity_uri=entity_uri,
        node_id=node_id,
        key_fpr=record.fpr,
        epoch=record.epoch,
        host=host,
        prev_fpr=record.prev_fpr or None,
        prev_until=record.prev_until or None,
        now=now,
    )
    return _trusted("dnssec-validated binding")

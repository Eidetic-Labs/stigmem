"""Off-path composition entry point for the DNSSEC first-trust tier (Rev 6 §7/I2/I3).

``resolve_dnssec_binding`` is the single seam the 3b first-trust ladder consumes.
It composes the three self-contained 3a pieces:

  1. ``host_from_entity_uri`` (3a.2 / I3) — derive the canonical query host from
     the *signed wire* ``entity_uri``. A non-DNSSEC-capable URI (non-HTTP
     scheme, IP-literal, userinfo, explicit port) yields ``None`` and the binding
     is ``NOT_APPLICABLE`` — the caller routes to operator-confirm (I3).
  2. ``validate_binding`` (3a.4/5/6 / I2) — walk the chain to the IANA root,
     re-deriving trust from signatures (never the AD bit), and validate the
     binding TXT, its authenticated absence, or its insecure delegation.
  3. The record parse already happened inside the validator (3a.3); its parsed
     ``BindingRecord`` rides on ``SECURE``.

This module is OFF-PATH (Rev 6, build-phase 3a): no resolver is wired into the
relay terminal yet — that is build-phase 3c. Its only contract is total: every
input, including a malformed ``entity_uri`` or any validator outcome, maps to
exactly one ``DnssecResult``. **No exception escapes.**

The ``Validation`` -> ``DnssecResult.Outcome`` mapping is fail-closed (I10):

  ====================== ============================ ==========================
  validator outcome      record                       DnssecResult.Outcome
  ====================== ============================ ==========================
  SECURE                 active                       ACTIVE (+ record)
  SECURE                 revoked (``status=revoked``) REVOKED (+ record)
  INSECURE               —                            INSECURE
  ABSENT_AUTHENTICATED   —                            ABSENT_AUTHENTICATED
  UNVALIDATABLE          —                            UNVALIDATABLE
  BOGUS                  —                            BOGUS
  ====================== ============================ ==========================

dnspython stays function-local (it is only reached through ``validate_binding``,
which imports it lazily), so importing this module never loads the
``[federation-dnssec]`` extra (Rev 6 I11).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .host import host_from_entity_uri
from .record import BindingRecord
from .validator import Validation, validate_binding

if TYPE_CHECKING:  # type-checkers only; never imported at runtime (I11).
    from .resolver import Resolver


@dataclass(frozen=True)
class DnssecResult:
    """The outcome of composing host derivation + chain validation for an origin.

    ``outcome`` is always populated. ``record`` is the parsed, chain-validated
    ``BindingRecord`` for the ``ACTIVE`` and ``REVOKED`` outcomes and ``None``
    for every other outcome (the binding either does not exist, is unsigned, or
    failed validation, so there is no trustworthy record to surface).
    """

    class Outcome(enum.Enum):
        """The seven terminal verdicts the first-trust ladder dispatches on.

        Caller disposition (Rev 6 I3/I10):
          * ``ACTIVE``               -> trust the record's key (subject to epoch
            pin + age clamp in 3b).
          * ``REVOKED``              -> hard-reject the origin's key.
          * ``INSECURE``             -> genuinely-unsigned delegation; fall to
            operator-confirm.
          * ``ABSENT_AUTHENTICATED`` -> proven-absent binding; fall to
            operator-confirm.
          * ``UNVALIDATABLE``        -> reject (no validatable proof either way).
          * ``NOT_APPLICABLE``       -> entity_uri is not DNSSEC-capable; route
            to operator-confirm.
          * ``BOGUS``                -> reject (forged / broken chain).
        """

        ACTIVE = "active"
        REVOKED = "revoked"
        INSECURE = "insecure"
        ABSENT_AUTHENTICATED = "absent_authenticated"
        UNVALIDATABLE = "unvalidatable"
        NOT_APPLICABLE = "not_applicable"
        BOGUS = "bogus"

    outcome: DnssecResult.Outcome
    record: BindingRecord | None = None
    host: str | None = None
    detail: str = ""


# The SECURE-with-record outcomes are decided by the record's revoked flag; every
# other validator status maps 1:1. A status missing from this table is treated
# fail-closed as BOGUS.
_NON_SECURE_MAP: dict[Validation, DnssecResult.Outcome] = {
    Validation.INSECURE: DnssecResult.Outcome.INSECURE,
    Validation.ABSENT_AUTHENTICATED: DnssecResult.Outcome.ABSENT_AUTHENTICATED,
    Validation.UNVALIDATABLE: DnssecResult.Outcome.UNVALIDATABLE,
    Validation.BOGUS: DnssecResult.Outcome.BOGUS,
}


def resolve_dnssec_binding(entity_uri: str, *, resolver: Resolver) -> DnssecResult:
    """Resolve the DNSSEC binding for ``entity_uri`` into a ``DnssecResult``.

    Off-path composition (3a.7): derive host (I3) -> validate chain (I2) -> map.
    Total + fail-closed: any unexpected error maps to ``BOGUS``; no exception
    escapes (Rev 6 I10).
    """
    try:
        host = host_from_entity_uri(entity_uri)
    except Exception:  # noqa: BLE001 — host derivation is fail-closed (I10).
        return DnssecResult(DnssecResult.Outcome.BOGUS, detail="host derivation error")

    if host is None:
        # Not DNSSEC-capable (non-HTTP scheme, IP-literal, userinfo, port). The
        # resolver is never consulted; the caller routes to operator-confirm (I3).
        return DnssecResult(DnssecResult.Outcome.NOT_APPLICABLE)

    try:
        verdict = validate_binding(host, resolver=resolver)
    except Exception:  # noqa: BLE001 — the validator is designed not to raise,
        # but the composition contract is total: any escape is BOGUS (I10).
        return DnssecResult(DnssecResult.Outcome.BOGUS, host=host, detail="validation error")

    if verdict.status is Validation.SECURE:
        record = verdict.record
        if record is None:
            # SECURE must carry a parsed record; absence is a contract breach we
            # treat fail-closed rather than trust.
            return DnssecResult(
                DnssecResult.Outcome.BOGUS, host=host, detail="secure without record"
            )
        outcome = (
            DnssecResult.Outcome.REVOKED if record.revoked else DnssecResult.Outcome.ACTIVE
        )
        return DnssecResult(outcome, record=record, host=host, detail=verdict.detail)

    mapped = _NON_SECURE_MAP.get(verdict.status, DnssecResult.Outcome.BOGUS)
    return DnssecResult(mapped, host=host, detail=verdict.detail)

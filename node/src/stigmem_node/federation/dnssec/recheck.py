"""Relay-path DNSSEC recency/revocation re-check — 3b FAIL-CLOSED stub (plan TB-4).

Rev 6 I5: a relayed fact's origin key is honored only if a DNSSEC re-check
within ``federation_dnssec_recheck_interval`` confirms the binding (rotation =>
honor new key; ``revoked`` / rolled-back epoch => reject; no-answer => time-boxed
fail-closed). That re-check is **build-phase 3c**.

THIS MODULE IS THE 3b SEAM, NOT THE IMPLEMENTATION. The first-trust ladder's
TRUSTED path pins a validated binding into ``dnssec_origin_pins``; a subsequent
relay of the same origin short-circuits at the pin tier (``resolve_first_trust``
step 1) and would otherwise honor that key WITHOUT re-validating recency or
revocation. Per plan TB-4 (strengthened: structural, not doc-gated), 3b must make
that incompleteness EXPLICIT and FAIL-CLOSED rather than silently trusting a pin
indefinitely.

So the relay wiring (``origin_identity.resolve_origin_key_for_relay``) calls
``recheck_relay_binding`` before honoring a DNSSEC-first-trust key, and in 3b
this stub ALWAYS raises :class:`RecheckNotImplemented`. The wiring maps that to a
fail-closed reject. Net effect: a 3b-merged-pre-3c node CANNOT return a
DNSSEC-first-trust key with no revocation path even if an operator flips
``federation_dnssec_trust_enabled`` — the no-recency window is unreachable
*structurally*, not merely undocumented.

3b GUARANTEES (proven by ``test_recheck_stub.py`` + the default-off guard):
  * the seam exists and is the single call site the relay path routes through;
  * it is fail-closed (raises a dedicated typed error, never returns "trusted");
  * it does NO network work in 3b (it raises before touching any resolver), so a
    flag-on 3b node performs zero DNS egress on the pin short-circuit path.

3c MUST FILL IN (Rev 6 I5, task 3c.1/3c.2):
  * the ``clamp(record_DNS_TTL, floor, cap)`` re-check cadence + per-origin cache;
  * the asymmetric failure rule: positive ``revoked``/rollback => hard reject;
    no-answer on a pinned binding => honor up to ``min(grace, k*ttl)`` then
    fail-closed; suppression never honored as a positive revocation;
  * rotation grace via the record's ``prev_fpr``.

No DNSSEC / ``dnspython`` import is reachable from this module (Rev 6 I11): the
3b stub does no DNS work at all, and the 3c implementation will import dnspython
function-locally exactly as ``resolver.LiveResolver`` does.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


class RecheckNotImplemented(Exception):
    """The relay-path DNSSEC recency/revocation re-check (Rev 6 I5) is not wired.

    Raised by the 3b ``recheck_relay_binding`` stub. The relay wiring catches
    exactly this type and fails closed, so a pinned DNSSEC binding is never
    honored on a relay without the 3c re-check. 3c replaces the stub body with
    the real re-check and this exception ceases to be raised on the happy path.
    """


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
    """Re-check a pinned DNSSEC binding's recency/revocation (Rev 6 I5) — 3b stub.

    In 3b this ALWAYS raises :class:`RecheckNotImplemented` BEFORE consulting the
    resolver (no network egress). The argument shape mirrors what the 3c
    implementation needs (the open DB connection, the canonical host + identity
    being re-checked, the injected resolver, settings for the cadence clamp, and
    the wall-clock ``now``) so 3c can fill in the body without changing the relay
    call site or this signature.

    Returns ``None`` on a successful re-check in 3c; in 3b it never returns.
    """
    raise RecheckNotImplemented(
        "DNSSEC relay-path recency/revocation re-check is build-phase 3c (Rev 6 I5); "
        "the 3b DNSSEC first-trust relay path fails closed until it is wired"
    )

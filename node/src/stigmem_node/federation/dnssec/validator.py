"""In-process DNSSEC chain-to-root validator (Rev 6 I2/I3).

This is the security core of Federation Phase 3. Given a host and an injectable
``Resolver``, it walks the DNS hierarchy root -> ... -> zone, validating each
delegation *cryptographically*:

  1. Start from the embedded IANA root trust anchor (``anchor.ROOT_TRUST_ANCHORS``).
  2. At each zone cut, fetch the child's DNSKEY RRset, validate it against the
     parent's DS RRset (the DS digest must match a self-signed DNSKEY), then
     trust that DNSKEY for the next step.
  3. At the leaf zone, validate the binding TXT RRset
     (``_stigmem-fed._key.<host>``) against the zone DNSKEY.

**The AD bit is never read.** Trust is re-derived from signatures every time
(Rev 6 I2). A response that merely *claims* authentication (AD=1) but carries no
validating RRSIGs is ``BOGUS``.

Outcomes (this module, extended in 3a.5/3a.6):
  * ``SECURE`` — the binding TXT validated to the root; ``Validation.record``
    is the parsed ``BindingRecord``.
  * ``BOGUS`` — a signature failed, was forged, was expired/not-yet-valid, the
    DS did not match, or a required record was missing while the chain is
    signed.

dnspython is imported function-locally (Rev 6 I11).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .record import BindingRecord, parse_binding_record

if TYPE_CHECKING:  # import for type-checkers only; never at runtime (I11).
    import dns.message
    import dns.name
    import dns.rdataset
    import dns.rdatatype
    import dns.rrset

    from .resolver import Resolver

_BINDING_PREFIX = "_stigmem-fed._key."


class Validation(enum.Enum):
    """Outcome of a binding validation walk.

    ``SECURE``/``BOGUS`` land in 3a.4; ``ABSENT_AUTHENTICATED``/``UNVALIDATABLE``/
    ``INSECURE`` land in 3a.5 (authenticated denial-of-existence).
    """

    SECURE = "secure"
    BOGUS = "bogus"
    ABSENT_AUTHENTICATED = "absent_authenticated"
    UNVALIDATABLE = "unvalidatable"
    INSECURE = "insecure"


@dataclass(frozen=True)
class ValidationResult:
    """The validator's verdict plus the parsed record on success."""

    status: Validation
    record: BindingRecord | None = None
    detail: str = ""


class _ChainError(Exception):
    """Internal: a chain step failed in a way that maps to BOGUS."""


def validate_binding(host: str, *, resolver: Resolver) -> ValidationResult:
    """Validate the DNSSEC binding for ``host`` to the root.

    ``host`` is the canonical A-label host from ``host_from_entity_uri`` (I3).
    ``resolver`` is any object satisfying the ``Resolver`` protocol.
    """
    import dns.dnssec
    import dns.name
    import dns.rdatatype

    from . import anchor

    try:
        zone_name = dns.name.from_text(host)
    except Exception:  # noqa: BLE001 — any malformed host is fail-closed.
        return ValidationResult(Validation.BOGUS, detail="malformed host")

    now = _validation_now()

    try:
        # 1. Walk the delegation chain from the root down to the leaf zone,
        #    establishing a validated DNSKEY RRset for the zone that should hold
        #    the binding TXT.
        signing_zone, zone_keys = _validate_chain_to_zone(
            zone_name, resolver=resolver, root_ds=anchor.root_ds_rdataset(), now=now
        )
    except _InsecureDelegation as exc:
        # Authenticated absence of a parent DS -> the subtree is unsigned. 3a.5
        # decides whether the caller may fall through; for 3a a bare INSECURE is
        # surfaced (the ladder treats it as operator-confirm, never accept).
        return ValidationResult(Validation.INSECURE, detail=str(exc))
    except _ChainError as exc:
        return ValidationResult(Validation.BOGUS, detail=str(exc))

    # 2. Fetch + validate the binding TXT against the validated zone DNSKEY.
    binding_qname = dns.name.from_text(_BINDING_PREFIX + host)
    try:
        txt_message = resolver.query(binding_qname.to_text(), "TXT")
    except Exception as exc:  # noqa: BLE001 — transport failure is fail-closed.
        return ValidationResult(Validation.BOGUS, detail=f"TXT query failed: {exc}")

    txt_rrset = _find_rrset(txt_message, binding_qname, dns.rdatatype.TXT)
    if txt_rrset is None:
        # No TXT answer. Whether this is an authenticated absence (-> fall
        # through) or an unvalidatable absence (-> reject) is decided by the
        # denial-of-existence logic added in 3a.5.
        return _classify_absence(
            txt_message,
            binding_qname=binding_qname,
            zone_name=signing_zone,
            zone_keys=zone_keys,
            now=now,
        )

    txt_rrsig = _find_rrsig(txt_message, binding_qname, dns.rdatatype.TXT)
    if txt_rrsig is None:
        return ValidationResult(Validation.BOGUS, detail="binding TXT has no RRSIG")

    try:
        dns.dnssec.validate(txt_rrset, txt_rrsig, {signing_zone: zone_keys}, now=now)
    except Exception as exc:  # noqa: BLE001 — forged/expired/wrong-key -> BOGUS.
        return ValidationResult(Validation.BOGUS, detail=f"binding TXT RRSIG invalid: {exc}")

    # 3a.6: reject a binding answer synthesized from a wildcard (an exact-match
    # RRSIG is required for the binding record). Defined in the wildcard module;
    # a no-op until 3a.6 lands.
    wildcard_detail = _reject_if_wildcard_synthesized(txt_rrset, txt_rrsig, binding_qname)
    if wildcard_detail is not None:
        return ValidationResult(Validation.BOGUS, detail=wildcard_detail)

    # 4. Parse the (now cryptographically-validated) record text.
    record = _parse_txt_rrset(txt_rrset)
    if record is None:
        return ValidationResult(Validation.BOGUS, detail="binding TXT failed grammar")

    return ValidationResult(Validation.SECURE, record=record)


# --------------------------------------------------------------------------- #
# Chain walk
# --------------------------------------------------------------------------- #


class _InsecureDelegation(Exception):
    """Internal: an authenticated absence of a parent DS (unsigned subtree)."""


def _validate_chain_to_zone(
    zone_name: dns.name.Name, *, resolver: Resolver, root_ds: dns.rdataset.Rdataset, now: float
) -> tuple[dns.name.Name, dns.rdataset.Rdataset]:
    """Return ``(signing_zone, validated_dnskey_rdataset)`` for ``zone_name``.

    ``signing_zone`` is the deepest zone cut at or above ``zone_name`` (the zone
    that actually signs the binding TXT); ``validated_dnskey_rdataset`` is that
    zone's chain-validated DNSKEY rdataset.

    Walks root -> ... -> zone. The invariant at each step is "we hold the
    parent zone's validated DNSKEY rdataset and the validated DS RRset for the
    child". For each child cut:

      1. Validate the child's DNSKEY RRset: it must be self-signed *and* a SEP
         (KSK) key in it must produce the DS digest the parent published
         (RFC 4035 §5.2 / RFC 4509). This establishes the child's keys.
      2. Fetch + validate the *grandchild's* DS RRset from the child zone
         (signed by the child's now-validated DNSKEY). That DS feeds the next
         iteration.

    The root is the base case: ``root_ds`` is the IANA anchor and the root
    DNSKEY is validated against it like any other cut. Raises ``_ChainError``
    (-> BOGUS) on any signature/match failure; ``_InsecureDelegation``
    (-> INSECURE) on an authenticated absence of a child DS (3a.5).
    """
    import dns.name

    # Descend the name one label at a time from the root toward the host. Not
    # every label is a zone cut: a cut exists only where the parent publishes a
    # DS (a signed delegation). The walk is therefore DS-driven:
    #   * Start at the root with the IANA-anchored DS; validate the root DNSKEY.
    #   * For each descendant name, query its DS. A *present + validated* DS is a
    #     signed delegation -> validate that child's DNSKEY and adopt its keys as
    #     the current zone keys. An *absent* DS means the descendant is not a cut
    #     (its records live in the current zone) -> carry the current keys.
    #
    #   .  ->  example.  ->  acme.example.  ->  memory.acme.example.
    labels = list(zone_name.labels)
    names: list[dns.name.Name] = [
        dns.name.Name(labels[i:]) for i in range(len(labels) - 1, -1, -1)
    ]

    # Base case: validate the root DNSKEY against the embedded anchor DS.
    root_name = names[0]
    current_keys = _validate_dnskey_against_ds(
        root_name, ds_rrset=root_ds, resolver=resolver, now=now
    )
    current_zone = root_name

    for descendant in names[1:]:
        ds_rrset = _fetch_validated_ds(
            descendant, parent_name=current_zone, parent_keys=current_keys,
            resolver=resolver, now=now,
        )
        if ds_rrset is None:
            # No signed delegation at this label: the descendant's records stay
            # in the current zone. Keep the current keys and continue.
            continue
        # Signed delegation: validate the child's DNSKEY against its DS and
        # descend into the child zone.
        current_keys = _validate_dnskey_against_ds(
            descendant, ds_rrset=ds_rrset, resolver=resolver, now=now
        )
        current_zone = descendant

    if current_keys is None:  # pragma: no cover — root always establishes keys.
        raise _ChainError("no zone keys established")
    return current_zone, current_keys


def _validate_dnskey_against_ds(
    zone: dns.name.Name, *, ds_rrset: dns.rdataset.Rdataset, resolver: Resolver, now: float
) -> dns.rdataset.Rdataset:
    """Validate ``zone``'s DNSKEY RRset against ``ds_rrset``; return its rdataset.

    ``ds_rrset`` is the DS the parent published for ``zone`` (the IANA anchor at
    the root). The DNSKEY RRset must be self-signed, and a SEP key in it must
    match a DS digest.
    """
    import dns.dnssec
    import dns.rdatatype

    try:
        dnskey_message = resolver.query(zone.to_text(), "DNSKEY")
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"DNSKEY query for {zone} failed: {exc}") from exc

    dnskey_rrset = _find_rrset(dnskey_message, zone, dns.rdatatype.DNSKEY)
    dnskey_rrsig = _find_rrsig(dnskey_message, zone, dns.rdatatype.DNSKEY)
    if dnskey_rrset is None or dnskey_rrsig is None:
        raise _ChainError(f"{zone} missing DNSKEY/RRSIG")

    if not _ds_matches_dnskey(zone, ds_rrset, dnskey_rrset):
        raise _ChainError(f"{zone} DNSKEY does not match parent DS")

    dnskey_rds = dnskey_rrset.to_rdataset()
    try:
        dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {zone: dnskey_rds}, now=now)
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"{zone} DNSKEY RRSIG invalid: {exc}") from exc

    return dnskey_rds


def _ds_matches_dnskey(
    zone: dns.name.Name, ds_rrset: dns.rdataset.Rdataset, dnskey_rrset: dns.rrset.RRset
) -> bool:
    """True iff some SEP key in ``dnskey_rrset`` produces a DS in ``ds_rrset``."""
    import dns.dnssec

    ds_records = list(ds_rrset)
    if not ds_records:
        return False
    for key in dnskey_rrset:
        # Only SEP/KSK keys (flags bit 0 set) are eligible as a DS target.
        if not (key.flags & 0x0001):
            continue
        for ds in ds_records:
            try:
                candidate = dns.dnssec.make_ds(zone, key, ds.digest_type)
            except Exception:  # noqa: BLE001,S112
                continue  # nosec B112 — unknown DS digest type: skip this DS, try the next.
            if candidate == ds:
                return True
    return False


def _fetch_validated_ds(
    child: dns.name.Name,
    *,
    parent_name: dns.name.Name,
    parent_keys: dns.rdataset.Rdataset,
    resolver: Resolver,
    now: float,
) -> dns.rdataset.Rdataset | None:
    """Fetch + validate the DS RRset for ``child`` from the parent zone.

    Returns the validated DS rdataset when ``child`` is a *signed delegation*,
    or ``None`` when no DS is present at ``child`` (``child`` is not a zone cut;
    its records live in the parent zone — a normal, expected case in real DNS).

    The DS for ``child`` is published at ``child``'s owner name but signed by
    the *parent* zone's keys (``parent_keys`` at ``parent_name``).

    Authenticated-denial discipline (Rev 6 I2): a DS *absence* here is treated as
    "not a cut, continue in the current zone." That is safe for the chain walk —
    if the binding TXT is not actually present in the parent zone, the absence
    of the TXT is what gets classified (``_classify_absence``), and 3a.5 requires
    a validated NSEC3 proof of that TXT absence before the caller may fall
    through. An attacker stripping a DS can only force the name to be sought in a
    zone the attacker does not control, which cannot yield a forged binding.
    """
    import dns.dnssec
    import dns.rdatatype

    try:
        ds_message = resolver.query(child.to_text(), "DS")
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"DS query for {child} failed: {exc}") from exc

    ds_rrset = _find_rrset(ds_message, child, dns.rdatatype.DS)
    if ds_rrset is None:
        return None

    ds_rrsig = _find_rrsig(ds_message, child, dns.rdatatype.DS)
    if ds_rrsig is None:
        raise _ChainError(f"{child} DS has no RRSIG")
    try:
        dns.dnssec.validate(ds_rrset, ds_rrsig, {parent_name: parent_keys}, now=now)
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"{child} DS RRSIG invalid: {exc}") from exc
    return ds_rrset.to_rdataset()


# --------------------------------------------------------------------------- #
# Absence + wildcard hooks (implemented in 3a.5 / 3a.6)
# --------------------------------------------------------------------------- #


def _classify_absence(
    message: dns.message.Message,
    *,
    binding_qname: dns.name.Name,
    zone_name: dns.name.Name,
    zone_keys: dns.rdataset.Rdataset,
    now: float,
) -> ValidationResult:
    """Classify a missing binding TXT.

    3a.4 placeholder: with no authenticated-denial proof checking yet, a missing
    TXT on a signed zone is treated as ``UNVALIDATABLE`` (fail-closed; the caller
    never falls through). 3a.5 replaces this with NSEC3 proof validation.
    """
    return ValidationResult(Validation.UNVALIDATABLE, detail="binding TXT absent (no proof yet)")


def _reject_if_wildcard_synthesized(
    txt_rrset: dns.rrset.RRset, txt_rrsig: dns.rrset.RRset, binding_qname: dns.name.Name
) -> str | None:
    """Return a BOGUS detail string if the answer was wildcard-synthesized.

    3a.4 placeholder: returns ``None`` (no rejection). 3a.6 implements the
    RRSIG-labels check (RFC 4035 §5.3.1) requiring an exact-match RRSIG.
    """
    return None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _validation_now() -> float:
    """Wall-clock seconds used as the RRSIG validity reference.

    A stale/expired RRSIG (inception/expiration outside this instant) fails
    ``dns.dnssec.validate`` -> BOGUS. The age-clamp/operator-confirm nuance is a
    3b concern; 3a is strict (expired == BOGUS).
    """
    import time

    return time.time()


def _name_eq(a: dns.name.Name, b: dns.name.Name) -> bool:
    """Canonical DNS-name equality by lower-cased text.

    Compares ``.to_text()`` rather than ``Name.__eq__`` so the match holds even
    if two ``dns.name.Name`` instances come from different ``dns.name`` module
    objects (``Name.__eq__`` is an ``isinstance`` check that returns
    ``NotImplemented`` across a re-import). DNS names are case-insensitive, so
    lower-casing is the correct canonical comparison regardless.
    """
    return a.to_text().lower() == b.to_text().lower()


def _find_rrset(
    message: dns.message.Message, name: dns.name.Name, rdtype: dns.rdatatype.RdataType
) -> dns.rrset.RRset | None:
    """Return the RRset for ``(name, rdtype)`` from answer/authority, or None."""
    for section in (message.answer, message.authority):
        for rrset in section:
            if _name_eq(rrset.name, name) and rrset.rdtype == rdtype:
                return rrset
    return None


def _find_rrsig(
    message: dns.message.Message, name: dns.name.Name, covers: dns.rdatatype.RdataType
) -> dns.rrset.RRset | None:
    """Return the RRSIG RRset covering ``(name, covers)``, or None."""
    import dns.rdatatype

    for section in (message.answer, message.authority):
        for rrset in section:
            if (
                _name_eq(rrset.name, name)
                and rrset.rdtype == dns.rdatatype.RRSIG
                and rrset.covers == covers
            ):
                return rrset
    return None


def _parse_txt_rrset(txt_rrset: dns.rrset.RRset) -> BindingRecord | None:
    """Concatenate a single TXT record's strings and run the grammar parser.

    Multiple TXT RRs at the binding name are ambiguous -> reject. Within one RR,
    character-strings are concatenated (RFC 1035 long-TXT convention).
    """
    records = list(txt_rrset)
    if len(records) != 1:
        return None
    txt = b"".join(records[0].strings).decode("utf-8", errors="replace")
    return parse_binding_record(txt)

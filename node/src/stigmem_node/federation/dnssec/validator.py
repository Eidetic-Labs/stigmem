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
    import dns.rdata
    import dns.rdataset
    import dns.rdatatype
    import dns.rrset
    from dns.rdtypes.ANY.NSEC3 import NSEC3

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
    the root). RFC 4035 §5.2: a SEP key in the RRset must reproduce a parent DS
    digest, AND the DNSKEY RRset's RRSIG MUST validate using ONLY that
    DS-authenticated key as the keyset — not the whole served RRset. Validating
    against the whole RRset would let an attacker who knows the zone's public KSK
    serve {real KSK, attacker KSK, ...} self-signed by the attacker key and have
    it accepted (the two checks must bind to the SAME key, not merely co-occur).
    """
    import dns.dnssec
    import dns.rdataset
    import dns.rdatatype

    try:
        dnskey_message = resolver.query(zone.to_text(), "DNSKEY")
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"DNSKEY query for {zone} failed: {exc}") from exc

    dnskey_rrset = _find_rrset(dnskey_message, zone, dns.rdatatype.DNSKEY)
    dnskey_rrsig = _find_rrsig(dnskey_message, zone, dns.rdatatype.DNSKEY)
    if dnskey_rrset is None or dnskey_rrsig is None:
        raise _ChainError(f"{zone} missing DNSKEY/RRSIG")

    ds_matched_keys = _ds_matched_keys(zone, ds_rrset, dnskey_rrset)
    if not ds_matched_keys:
        raise _ChainError(f"{zone} DNSKEY does not match parent DS")

    # Build the validation keyset from ONLY the DS-authenticated key(s). The
    # DNSKEY RRset's self-signature is then verified against the keys the parent
    # actually pinned, so a non-DS key signing the RRset raises ValidationFailure
    # -> BOGUS (RFC 4035 §5.2). NOT a key_tag filter: key tags collide and are
    # attacker-spoofable; the keyset itself is restricted.
    trusted_keyset = dns.rdataset.Rdataset(dnskey_rrset.rdclass, dns.rdatatype.DNSKEY)
    trusted_keyset.ttl = dnskey_rrset.ttl
    for key in ds_matched_keys:
        trusted_keyset.add(key)

    try:
        dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {zone: trusted_keyset}, now=now)
    except Exception as exc:  # noqa: BLE001
        raise _ChainError(f"{zone} DNSKEY RRSIG invalid: {exc}") from exc

    # The full RRset (every key in it) becomes the trusted keyset for the *next*
    # step only after its self-signature has been authenticated by the DS-pinned
    # key above — i.e. the parent has vouched (via DS+RRSIG chain) for the whole
    # set, so the zone's ZSKs are now usable for the records it signs.
    return dnskey_rrset.to_rdataset()


def _ds_matched_keys(
    zone: dns.name.Name, ds_rrset: dns.rdataset.Rdataset, dnskey_rrset: dns.rrset.RRset
) -> list[dns.rdata.Rdata]:
    """Return the SEP key(s) in ``dnskey_rrset`` that reproduce a DS in ``ds_rrset``.

    Empty list when no key matches. The returned keys are the only ones the
    parent has authenticated; the DNSKEY RRset's RRSIG must validate against
    exactly these (RFC 4035 §5.2).
    """
    import dns.dnssec

    ds_records = list(ds_rrset)
    if not ds_records:
        return []
    matched: list[dns.rdata.Rdata] = []
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
                matched.append(key)
                break
    return matched


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
        # No DS at the child. Distinguish two authenticated cases (Rev 6 I2):
        #   * insecure delegation — a validated NSEC3 that MATCHES the child and
        #     whose type bitmap shows NS-without-DS proves a signed parent
        #     delegating to an unsigned child. Surface INSECURE so the caller
        #     routes to operator-confirm (never silent-accept).
        #   * not a cut — no such proof; the child's records live in the parent
        #     zone. Carry the current keys (return None).
        if _nsec3_proves_insecure_delegation(
            ds_message, child=child, parent_name=parent_name, parent_keys=parent_keys, now=now
        ):
            raise _InsecureDelegation(f"authenticated unsigned delegation at {child}")
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
# Authenticated denial-of-existence (Rev 6 I2) — 3a.5
# --------------------------------------------------------------------------- #


def _classify_absence(
    message: dns.message.Message,
    *,
    binding_qname: dns.name.Name,
    zone_name: dns.name.Name,
    zone_keys: dns.rdataset.Rdataset,
    now: float,
) -> ValidationResult:
    """Classify a missing binding TXT via authenticated denial-of-existence.

    Rev 6 I2: to treat the binding TXT as "absent" and let the caller fall
    through, the receiver MUST hold a cryptographically-validated NSEC3
    denial-of-existence proof for the qname against the zone DNSKEY. Outcomes:

      * ``ABSENT_AUTHENTICATED`` — a validated NSEC3 closest-encloser proof
        covers the qname. The caller MAY fall through to operator-confirm.
      * ``UNVALIDATABLE`` — no validated proof of absence (the answer is just
        empty, or carries unsigned/forged NSEC3). The caller MUST reject and
        never fall through.

    NSEC3 is REQUIRED (Rev 6 I2): a bare NSEC record, or an NSEC3 with the
    opt-out flag set, is rejected as ``UNVALIDATABLE`` (no insecure-delegation
    fall-through for the binding name).
    """
    import dns.rdatatype

    # A bare NSEC (not NSEC3) authority section does not satisfy the NSEC3
    # requirement -> unvalidatable.
    if _has_rrset_of_type(message, dns.rdatatype.NSEC):
        return ValidationResult(
            Validation.UNVALIDATABLE, detail="bare NSEC denial; NSEC3 required (I2)"
        )

    nsec3s = _collect_validated_nsec3(message, zone_name=zone_name, zone_keys=zone_keys, now=now)
    if nsec3s is None:
        return ValidationResult(
            Validation.UNVALIDATABLE, detail="NSEC3 denial RRSIG invalid"
        )
    if not nsec3s:
        return ValidationResult(
            Validation.UNVALIDATABLE, detail="binding TXT absent with no NSEC3 proof"
        )

    # Reject opt-out NSEC3 (flags bit 0): opt-out weakens the proof to an
    # unsigned-delegation assertion, which Rev 6 I2 forbids for the binding.
    for _owner, rdata in nsec3s:
        if rdata.flags & 0x01:
            return ValidationResult(
                Validation.UNVALIDATABLE, detail="NSEC3 opt-out set; rejected (I2)"
            )

    if _nsec3_proves_absence(binding_qname, zone_name=zone_name, nsec3s=nsec3s):
        return ValidationResult(
            Validation.ABSENT_AUTHENTICATED, detail="authenticated NSEC3 absence"
        )
    return ValidationResult(
        Validation.UNVALIDATABLE, detail="NSEC3 present but does not prove qname absence"
    )


def _has_rrset_of_type(message: dns.message.Message, rdtype: dns.rdatatype.RdataType) -> bool:
    for section in (message.answer, message.authority):
        for rrset in section:
            if rrset.rdtype == rdtype:
                return True
    return False


def _collect_validated_nsec3(
    message: dns.message.Message,
    *,
    zone_name: dns.name.Name,
    zone_keys: dns.rdataset.Rdataset,
    now: float,
) -> list[tuple[dns.name.Name, NSEC3]] | None:
    """Return ``[(owner_name, nsec3_rdata), ...]`` for *validated* NSEC3 RRsets.

    Each NSEC3 RRset in the authority section must carry an RRSIG that validates
    against the zone DNSKEY. Returns ``None`` if any present NSEC3 RRset fails
    validation (treat the whole proof as unvalidatable); an empty list if there
    are no NSEC3 RRsets at all.
    """
    import dns.dnssec
    import dns.rdatatype

    collected: list[tuple[dns.name.Name, NSEC3]] = []
    for rrset in message.authority:
        if rrset.rdtype != dns.rdatatype.NSEC3:
            continue
        rrsig = _find_rrsig(message, rrset.name, dns.rdatatype.NSEC3)
        if rrsig is None:
            return None
        try:
            dns.dnssec.validate(rrset, rrsig, {zone_name: zone_keys}, now=now)
        except Exception:  # noqa: BLE001 — forged/expired NSEC3 -> unvalidatable.
            return None
        for rdata in rrset:
            collected.append((rrset.name, rdata))
    return collected


def _nsec3_owner_hash(owner: dns.name.Name, zone_name: dns.name.Name) -> str:
    """The base32hex NSEC3 hash from an NSEC3 owner name (first label)."""
    return owner.labels[0].decode("ascii").upper()


def _nsec3_next_hash(rdata: NSEC3) -> str:
    """The base32hex-encoded next-hashed-owner of an NSEC3 rdata."""
    import base64

    # dnspython exposes the raw next-owner bytes as ``rdata.next``.
    return base64.b32encode(rdata.next).translate(_B32HEX).decode("ascii").rstrip("=")


# RFC 4648 base32 -> base32hex ("extended hex") alphabet translation table.
_B32HEX = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    b"0123456789ABCDEFGHIJKLMNOPQRSTUV",
)


def _hash_name(name: dns.name.Name, rdata: NSEC3) -> str:
    """NSEC3-hash ``name`` using the NSEC3 rdata's algorithm/salt/iterations."""
    import dns.dnssec

    salt = rdata.salt if rdata.salt is not None else b""
    return dns.dnssec.nsec3_hash(name, salt, rdata.iterations, rdata.algorithm)


def _nsec3_matches(name: dns.name.Name, owner_hash: str, rdata: NSEC3) -> bool:
    """True iff the NSEC3 owner hash equals H(name) (RFC 5155 'matches')."""
    return _hash_name(name, rdata) == owner_hash


def _nsec3_covers(name: dns.name.Name, owner_hash: str, next_hash: str, rdata: NSEC3) -> bool:
    """True iff H(name) falls in the (owner_hash, next_hash] gap (RFC 5155 'covers').

    Handles the zone-apex wraparound where next_hash <= owner_hash.
    """
    target = _hash_name(name, rdata)
    if owner_hash < next_hash:
        return owner_hash < target < next_hash
    # Wraparound interval (covers the largest..smallest gap including the apex).
    return target > owner_hash or target < next_hash


def _nsec3_proves_absence(
    qname: dns.name.Name,
    *,
    zone_name: dns.name.Name,
    nsec3s: list[tuple[dns.name.Name, NSEC3]],
) -> bool:
    """Verify an RFC 5155 closest-encloser proof of ``qname``'s non-existence.

    The proof requires (a) an NSEC3 that *matches* the closest encloser and
    (b) an NSEC3 that *covers* the next-closer name. We search the ancestors of
    ``qname`` (down to the zone apex) for the deepest enclosing name that an
    NSEC3 matches; its immediate child toward ``qname`` (the next-closer) must
    be covered by some NSEC3. This proves no exact match and no wildcard
    synthesis path for the binding name.
    """
    import dns.name

    qlabels = list(qname.labels)
    zlabels = list(zone_name.labels)
    # Candidate closest-encloser names: proper ancestors of the qname that are
    # at or below the zone apex. The apex sits at label-offset
    # ``apex_depth = len(qlabels) - len(zlabels)`` into the qname. The closest
    # encloser is the *deepest* such ancestor an NSEC3 matches, so iterate from
    # the qname's parent (offset 1) down to the apex (offset apex_depth) and take
    # the first match. The next-closer is the immediate child of the CE toward
    # the qname (one label deeper).
    apex_depth = len(qlabels) - len(zlabels)
    for depth in range(1, apex_depth + 1):
        ce = dns.name.Name(qlabels[depth:])
        next_closer = dns.name.Name(qlabels[depth - 1:])
        ce_matched = False
        for owner, rdata in nsec3s:
            owner_hash = _nsec3_owner_hash(owner, zone_name)
            if _nsec3_matches(ce, owner_hash, rdata):
                ce_matched = True
                break
        if not ce_matched:
            continue
        # The closest encloser exists; the next-closer must be covered.
        for owner, rdata in nsec3s:
            owner_hash = _nsec3_owner_hash(owner, zone_name)
            next_hash = _nsec3_next_hash(rdata)
            if _nsec3_covers(next_closer, owner_hash, next_hash, rdata):
                return True
        return False
    return False


def _nsec3_type_present(rdata: NSEC3, rdtype: dns.rdatatype.RdataType) -> bool:
    """True iff ``rdtype`` is set in the NSEC3 type bitmap (RFC 4034 §4.1.2)."""
    for window, bitmap in rdata.windows:
        if window != (rdtype >> 8):
            continue
        byte_index = (rdtype & 0xFF) >> 3
        if byte_index >= len(bitmap):
            continue
        if bitmap[byte_index] & (0x80 >> (rdtype & 0x07)):
            return True
    return False


def _nsec3_proves_insecure_delegation(
    message: dns.message.Message,
    *,
    child: dns.name.Name,
    parent_name: dns.name.Name,
    parent_keys: dns.rdataset.Rdataset,
    now: float,
) -> bool:
    """True iff a validated NSEC3 proves ``child`` is an unsigned delegation.

    RFC 5155 §3.2: a secure parent denying a DS for a delegated child serves an
    NSEC3 that *matches* the child's name whose type bitmap contains ``NS`` but
    not ``DS`` (and not ``SOA`` — i.e. a delegation, not the apex). The NSEC3
    RRset must validate against the parent's DNSKEY. Opt-out NSEC3 is not
    accepted as a proof here (Rev 6 I2 requires opt-out off).
    """
    import dns.rdatatype

    nsec3s = _collect_validated_nsec3(
        message, zone_name=parent_name, zone_keys=parent_keys, now=now
    )
    if not nsec3s:
        return False
    for owner, rdata in nsec3s:
        if rdata.flags & 0x01:  # opt-out -> not an accepted proof (I2)
            continue
        owner_hash = _nsec3_owner_hash(owner, parent_name)
        if not _nsec3_matches(child, owner_hash, rdata):
            continue
        has_ns = _nsec3_type_present(rdata, dns.rdatatype.NS)
        has_ds = _nsec3_type_present(rdata, dns.rdatatype.DS)
        has_soa = _nsec3_type_present(rdata, dns.rdatatype.SOA)
        if has_ns and not has_ds and not has_soa:
            return True
    return False


def _reject_if_wildcard_synthesized(
    txt_rrset: dns.rrset.RRset, txt_rrsig: dns.rrset.RRset, binding_qname: dns.name.Name
) -> str | None:
    """Return a BOGUS detail string if the binding answer was wildcard-synthesized.

    Rev 6 I3: the binding record requires an *exact-match* RRSIG; a record
    synthesized from a ``*`` wildcard is rejected. RFC 4035 §5.3.1: an RRSIG's
    ``labels`` field carries the label count of the *original* owner name the
    signature was generated over. When an answer is synthesized from a wildcard,
    ``RRSIG.labels`` is **less** than the number of (non-root) labels in the
    queried owner name — that gap is the proof of synthesis. (A validly-signed
    wildcard answer still verifies against the zone DNSKEY, so the chain check
    alone does not catch it; this label-count comparison does.)
    """
    # All RRSIGs covering the binding TXT must be exact-match. The owner name's
    # non-root label count is the expected signed-label count.
    owner_label_count = len(binding_qname.labels) - 1  # exclude the root label
    for rrsig in txt_rrsig:
        if rrsig.labels < owner_label_count:
            return (
                "binding TXT synthesized from a wildcard "
                f"(RRSIG labels={rrsig.labels} < owner labels={owner_label_count}); "
                "exact-match RRSIG required (I3)"
            )
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

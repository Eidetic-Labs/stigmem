"""Offline, deterministic DNSSEC fixture harness for the Phase-3 validator.

This builds a fully-signed fake DNS hierarchy *without any network* and exposes
``FixtureResolver`` instances preloaded with the canned DNS messages for each
adversarial scenario in Rev 6 §12. The validator (``validator.py``) queries
these exactly as it would the live resolver, and validates every signature
against the chain — so these fixtures exercise the real crypto path, not a
call-shape mock.

How the hierarchy is built
--------------------------
A ``SignedZone`` per cut (root ``.``, the TLD-ish ``example.``, and the leaf
``memory.acme.example.``) each with its own KSK + ZSK (ECDSA P-256). Records are
assembled as dnspython RRsets and signed with the low-level
``dns.dnssec.sign()`` primitive.

Why ``dns.dnssec.sign()`` and not ``sign_zone``
-----------------------------------------------
dnspython 2.8's ``sign_zone(..., nsec3=...)`` raises
``NotImplementedError("Signing with NSEC3 not yet implemented")`` (verified
against the installed 2.8.0). Rev 6 I2 *requires* NSEC3, so the harness signs
each RRset by hand with ``dns.dnssec.sign()`` and constructs the NSEC3 denial
records explicitly — which is also closer to the wire reality the validator
parses. See the report for this API adaptation.

Trust-anchor patching
----------------------
Each fixture monkeypatches ``stigmem_node.federation.dnssec.anchor`` so the
validator's root trust anchor is this harness's fake root KSK DS — the chain
then validates end-to-end offline.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from stigmem_node.federation.dnssec.resolver import FixtureResolver

# Deterministic signature validity window. Tests pin `time.time()` indirectly
# via the validator's `_validation_now`; we monkeypatch it to NOW so the
# fixtures are stable regardless of wall clock.
INCEPTION = datetime.datetime(2026, 6, 1, tzinfo=datetime.UTC)
EXPIRATION = datetime.datetime(2026, 7, 1, tzinfo=datetime.UTC)
NOW = INCEPTION.timestamp() + 86400.0  # mid-window

# A far-past window for the stale-RRSIG scenario.
STALE_INCEPTION = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
STALE_EXPIRATION = datetime.datetime(2020, 2, 1, tzinfo=datetime.UTC)

ALG = dns.dnssec.Algorithm.ECDSAP256SHA256
HOST = "memory.acme.example."
BINDING_QNAME = "_stigmem-fed._key." + HOST
DEFAULT_RECORD = "v=stigmem1; fpr=abc123def; epoch=7"

# NSEC3 parameters (SHA-1, no opt-out).
NSEC3_ALG = 1
NSEC3_FLAGS = 0
NSEC3_ITERATIONS = 10
NSEC3_SALT = b"\xab\xcd"


def _make_keypair(flags: int):
    priv = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(priv.public_key(), ALG, flags=flags)
    return priv, dnskey


@dataclass
class SignedZone:
    """One signed zone: its KSK/ZSK and a helper to sign arbitrary RRsets."""

    origin: dns.name.Name
    ksk_priv: object
    ksk: object
    zsk_priv: object
    zsk: object
    inception: datetime.datetime = INCEPTION
    expiration: datetime.datetime = EXPIRATION

    @classmethod
    def create(cls, origin_text: str, **kw) -> SignedZone:
        origin = dns.name.from_text(origin_text)
        ksk_priv, ksk = _make_keypair(257)
        zsk_priv, zsk = _make_keypair(256)
        return cls(origin=origin, ksk_priv=ksk_priv, ksk=ksk, zsk_priv=zsk_priv, zsk=zsk, **kw)

    @property
    def dnskey_rrset(self):
        return dns.rrset.from_rdata(self.origin, 3600, self.ksk, self.zsk)

    def sign_with_zsk(self, rrset, *, signer_priv=None, signer_key=None, inception=None,
                      expiration=None):
        return dns.dnssec.sign(
            rrset,
            signer_priv or self.zsk_priv,
            self.origin,
            signer_key or self.zsk,
            inception=inception or self.inception,
            expiration=expiration or self.expiration,
        )

    def sign_with_ksk(self, rrset, *, inception=None, expiration=None):
        return dns.dnssec.sign(
            rrset,
            self.ksk_priv,
            self.origin,
            self.ksk,
            inception=inception or self.inception,
            expiration=expiration or self.expiration,
        )

    def ds_rrset(self, child: SignedZone):
        """The DS RRset this (parent) zone publishes for ``child``, signed here."""
        ds = dns.dnssec.make_ds(child.origin, child.ksk, "SHA256")
        ds_rr = dns.rrset.from_rdata(child.origin, 3600, ds)
        return ds_rr

    def nsec3_hash(self, name: str) -> str:
        return dns.dnssec.nsec3_hash(
            dns.name.from_text(name), NSEC3_SALT, NSEC3_ITERATIONS, NSEC3_ALG
        )


def _rdataset(rrset):
    return rrset.to_rdataset()


def _answer_message(qname: str, rdtype: str, answer_rrsets, authority_rrsets=None):
    """Build a NOERROR response message with the given RRsets."""
    query = dns.message.make_query(dns.name.from_text(qname), dns.rdatatype.from_text(rdtype))
    msg = dns.message.make_response(query)
    msg.set_rcode(dns.rcode.NOERROR)
    for rr in answer_rrsets:
        msg.answer.append(rr)
    if authority_rrsets:
        for rr in authority_rrsets:
            msg.authority.append(rr)
    return msg


def _nsec3_rr(zone: SignedZone, owner_hash: str, next_hash: str, types: list[str]):
    """Build a single NSEC3 RR owned at ``owner_hash.<zone>`` covering a gap."""
    owner = dns.name.from_text(owner_hash.lower() + "." + zone.origin.to_text())
    type_str = " ".join(types)
    text = (
        f"{NSEC3_ALG} {NSEC3_FLAGS} {NSEC3_ITERATIONS} {NSEC3_SALT.hex()} "
        f"{next_hash} {type_str}".strip()
    )
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3, text)
    return dns.rrset.from_rdata(owner, 300, rd)


def _b32_below(h: str) -> str:
    """A base32hex hash strictly lexically below ``h`` (for NSEC3 covering)."""
    # base32hex alphabet: 0-9 A-V. The smallest is all '0'.
    return "0" * len(h)


def _b32_above(h: str) -> str:
    """A base32hex hash strictly lexically above ``h``."""
    return "V" * len(h)


@dataclass
class _Hierarchy:
    """The three signed zones plus the leaf binding TXT material."""

    root: SignedZone
    tld: SignedZone
    leaf: SignedZone
    record_text: str = DEFAULT_RECORD
    leaf_inception: datetime.datetime = INCEPTION
    leaf_expiration: datetime.datetime = EXPIRATION


def _build_hierarchy(**kw) -> _Hierarchy:
    root = SignedZone.create(".")
    tld = SignedZone.create("example.")
    leaf = SignedZone.create(HOST)
    return _Hierarchy(root=root, tld=tld, leaf=leaf, **kw)


def _load_chain(resolver: FixtureResolver, h: _Hierarchy) -> None:
    """Load the DNSKEY + DS messages for the full root->leaf chain."""
    for zone in (h.root, h.tld, h.leaf):
        dnskey_rr = zone.dnskey_rrset
        dnskey_sig = zone.sign_with_ksk(dnskey_rr)
        sig_rr = dns.rrset.from_rdata(zone.origin, 3600, dnskey_sig)
        resolver.add(zone.origin.to_text(), "DNSKEY", _answer_message(
            zone.origin.to_text(), "DNSKEY", [dnskey_rr, sig_rr]))

    # DS records: parent publishes + signs the child's DS.
    for parent, child in ((h.root, h.tld), (h.tld, h.leaf)):
        ds_rr = parent.ds_rrset(child)
        ds_sig = parent.sign_with_zsk(ds_rr)
        sig_rr = dns.rrset.from_rdata(child.origin, 3600, ds_sig)
        resolver.add(child.origin.to_text(), "DS", _answer_message(
            child.origin.to_text(), "DS", [ds_rr, sig_rr]))


def _load_binding_txt(resolver: FixtureResolver, h: _Hierarchy, *,
                      inception=None, expiration=None) -> None:
    """Load the signed binding TXT at the leaf."""
    qname = dns.name.from_text(BINDING_QNAME)
    txt_rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{h.record_text}"')
    txt_rr = dns.rrset.from_rdata(qname, 300, txt_rd)
    txt_sig = h.leaf.sign_with_zsk(txt_rr, inception=inception, expiration=expiration)
    sig_rr = dns.rrset.from_rdata(qname, 300, txt_sig)
    resolver.add(BINDING_QNAME, "TXT", _answer_message(BINDING_QNAME, "TXT", [txt_rr, sig_rr]))


# --------------------------------------------------------------------------- #
# NSEC3 denial-of-existence helpers (3a.5)
# --------------------------------------------------------------------------- #

# base32hex alphabet (RFC 4648 §7), ascending. Smallest/largest hash sentinels.
_B32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_HASH_LEN = 32  # SHA-1 hashes encode to 32 base32hex chars.


def _b32hex_decrement(h: str) -> str:
    """A base32hex string strictly just below ``h`` (for an NSEC3 owner bound)."""
    chars = list(h)
    i = len(chars) - 1
    while i >= 0:
        idx = _B32HEX.index(chars[i])
        if idx > 0:
            chars[i] = _B32HEX[idx - 1]
            return "".join(chars)
        chars[i] = _B32HEX[-1]
        i -= 1
    return "0" * len(h)


def _b32hex_increment(h: str) -> str:
    """A base32hex string strictly just above ``h`` (for an NSEC3 next bound)."""
    chars = list(h)
    i = len(chars) - 1
    while i >= 0:
        idx = _B32HEX.index(chars[i])
        if idx < len(_B32HEX) - 1:
            chars[i] = _B32HEX[idx + 1]
            return "".join(chars)
        chars[i] = _B32HEX[0]
        i -= 1
    return "V" * len(h)


def _signed_nsec3(zone: SignedZone, owner_hash: str, next_hash: str, types: list[str]):
    """Build + ZSK-sign an NSEC3 RRset owned at ``owner_hash.<zone>``.

    Returns ``(nsec3_rrset, rrsig_rrset)``.
    """
    owner = dns.name.from_text(owner_hash.upper() + "." + zone.origin.to_text())
    type_str = " ".join(types)
    text = (
        f"{NSEC3_ALG} {NSEC3_FLAGS} {NSEC3_ITERATIONS} {NSEC3_SALT.hex()} "
        f"{next_hash} {type_str}".strip()
    )
    rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NSEC3, text)
    rrset = dns.rrset.from_rdata(owner, 300, rd)
    sig = zone.sign_with_zsk(rrset)
    sig_rrset = dns.rrset.from_rdata(owner, 300, sig)
    return rrset, sig_rrset


def _closest_encloser_proof(zone: SignedZone, qname: str):
    """Build a valid RFC 5155 closest-encloser NSEC3 proof for ``qname``'s absence.

    Produces two NSEC3s: one MATCHING the zone apex (closest encloser) and one
    COVERING the next-closer name (the qname's immediate-child-of-CE label).
    Returns the list of (nsec3_rrset, rrsig_rrset) pairs.
    """
    apex = zone.origin
    qn = dns.name.from_text(qname)
    # next-closer = the name one label below the closest encloser toward qname.
    qlabels = list(qn.labels)
    alabels = list(apex.labels)
    next_closer = dns.name.from_text(b".".join(qlabels[len(qlabels) - len(alabels) - 1:]).decode())

    ce_hash = zone.nsec3_hash(apex.to_text())
    nc_hash = zone.nsec3_hash(next_closer.to_text())

    pairs = []
    # (1) NSEC3 matching the closest encloser (apex): owner hash == H(apex).
    #     Its type bitmap names the apex's types (SOA/NS/DNSKEY...).
    pairs.append(_signed_nsec3(zone, ce_hash, _b32hex_increment(ce_hash),
                               ["SOA", "NS", "DNSKEY", "NSEC3PARAM", "RRSIG"]))
    # (2) NSEC3 covering the next-closer: owner < H(nc) < next.
    pairs.append(_signed_nsec3(zone, _b32hex_decrement(nc_hash),
                               _b32hex_increment(nc_hash), ["RRSIG"]))
    return pairs


def _nodata_message(qname: str, rdtype: str, nsec3_pairs):
    """An empty-answer NOERROR message carrying NSEC3 proof RRsets in authority."""
    msg = _answer_message(qname, rdtype, [])
    for rrset, sig in nsec3_pairs:
        msg.authority.append(rrset)
        msg.authority.append(sig)
    return msg


# --------------------------------------------------------------------------- #
# Pytest fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _pin_validation_clock(monkeypatch):
    """Pin the validator's RRSIG-validity reference to the deterministic NOW."""
    monkeypatch.setattr(
        "stigmem_node.federation.dnssec.validator._validation_now", lambda: NOW
    )


@pytest.fixture
def patch_anchor(monkeypatch):
    """Return a callable that patches the prod anchor to a fixture root KSK DS."""

    def _patch(h: _Hierarchy) -> None:
        # The validator validates the root DNSKEY against anchor.root_ds_rdataset().
        # Build a DS rdataset for the fake root KSK and patch root_ds_rdataset.
        ds = dns.dnssec.make_ds(h.root.origin, h.root.ksk, "SHA256")
        rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
        rds.ttl = 3600
        rds.add(ds)
        monkeypatch.setattr(
            "stigmem_node.federation.dnssec.anchor.root_ds_rdataset", lambda: rds
        )

    return _patch


@pytest.fixture
def valid_chain(patch_anchor) -> FixtureResolver:
    """A fully-signed, valid chain resolving the binding TXT -> SECURE."""
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)
    _load_binding_txt(resolver, h)
    return resolver


@pytest.fixture
def forged_rrsig_chain(patch_anchor) -> FixtureResolver:
    """Valid chain, but the binding TXT RRSIG is signed by an attacker key."""
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)

    # Sign the TXT with a DIFFERENT (attacker) key that is NOT in the zone DNSKEY.
    attacker_priv, attacker_key = _make_keypair(256)
    qname = dns.name.from_text(BINDING_QNAME)
    txt_rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{DEFAULT_RECORD}"')
    txt_rr = dns.rrset.from_rdata(qname, 300, txt_rd)
    forged_sig = dns.dnssec.sign(
        txt_rr, attacker_priv, h.leaf.origin, attacker_key,
        inception=INCEPTION, expiration=EXPIRATION,
    )
    sig_rr = dns.rrset.from_rdata(qname, 300, forged_sig)
    resolver.add(BINDING_QNAME, "TXT", _answer_message(BINDING_QNAME, "TXT", [txt_rr, sig_rr]))
    return resolver


@pytest.fixture
def stale_rrsig_chain(patch_anchor) -> FixtureResolver:
    """Valid chain, but the binding TXT RRSIG inception/expiration are far past."""
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)
    _load_binding_txt(resolver, h, inception=STALE_INCEPTION, expiration=STALE_EXPIRATION)
    return resolver


# Expose the building blocks for the denial / wildcard fixtures (3a.5 / 3a.6).
@pytest.fixture
def hierarchy_factory(patch_anchor):
    """Factory returning (hierarchy, resolver-with-chain-loaded, patch)."""

    def _make(record_text: str = DEFAULT_RECORD) -> tuple[_Hierarchy, FixtureResolver]:
        h = _build_hierarchy(record_text=record_text)
        patch_anchor(h)
        resolver = FixtureResolver()
        _load_chain(resolver, h)
        return h, resolver

    return _make


@pytest.fixture
def stripped_nsec3(patch_anchor) -> FixtureResolver:
    """Valid chain, binding TXT absent but with a validated NSEC3 absence proof.

    Models authenticated denial-of-existence -> ABSENT_AUTHENTICATED (the caller
    may fall through to operator-confirm).
    """
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)
    proof = _closest_encloser_proof(h.leaf, BINDING_QNAME)
    resolver.add(BINDING_QNAME, "TXT", _nodata_message(BINDING_QNAME, "TXT", proof))
    return resolver


@pytest.fixture
def unvalidatable_absence(patch_anchor) -> FixtureResolver:
    """Valid chain, binding TXT absent with NO denial proof at all.

    Models an unvalidatable absence -> UNVALIDATABLE (the caller MUST reject).
    The FixtureResolver returns an empty NOERROR for the unstaged TXT, so no
    NSEC3 proof is present.
    """
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)
    # Intentionally do not stage a TXT answer.
    return resolver


@pytest.fixture
def unsigned_delegation(patch_anchor) -> FixtureResolver:
    """A signed parent authenticatedly denies a DS for the leaf (NS, no DS).

    Models an insecure delegation -> INSECURE. The leaf zone's DS query returns
    a validated NSEC3 matching the leaf with NS-but-not-DS in its type bitmap.
    """
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    # Load root + TLD DNSKEY/DS, and the leaf DNSKEY, but NOT a leaf DS.
    for zone in (h.root, h.tld, h.leaf):
        dnskey_rr = zone.dnskey_rrset
        sig_rr = dns.rrset.from_rdata(zone.origin, 3600, zone.sign_with_ksk(dnskey_rr))
        resolver.add(zone.origin.to_text(), "DNSKEY",
                     _answer_message(zone.origin.to_text(), "DNSKEY", [dnskey_rr, sig_rr]))
    ds_rr = h.root.ds_rrset(h.tld)
    sig_rr = dns.rrset.from_rdata(h.tld.origin, 3600, h.root.sign_with_zsk(ds_rr))
    resolver.add(h.tld.origin.to_text(), "DS",
                 _answer_message(h.tld.origin.to_text(), "DS", [ds_rr, sig_rr]))

    # Leaf DS query -> authenticated no-DS: NSEC3 (signed by the TLD/parent zone)
    # that MATCHES the leaf name with NS set but DS and SOA unset.
    leaf_hash = h.tld.nsec3_hash(h.leaf.origin.to_text())
    nsec3_pair = _signed_nsec3(h.tld, leaf_hash, _b32hex_increment(leaf_hash), ["NS", "RRSIG"])
    resolver.add(h.leaf.origin.to_text(), "DS",
                 _nodata_message(h.leaf.origin.to_text(), "DS", [nsec3_pair]))
    return resolver


@pytest.fixture
def wildcard_synth(patch_anchor) -> FixtureResolver:
    """The binding answer is synthesized from a ``*`` wildcard, not an exact name.

    The TXT is signed at ``*.memory.acme.example.`` (label count 3, excluding
    root) and served at the binding qname (label count 5). The RRSIG's ``labels``
    field reflects the wildcard's 3, so RRSIG.labels < owner labels -> rejected
    as BOGUS even though the signature itself verifies against the zone DNSKEY.
    """
    h = _build_hierarchy()
    patch_anchor(h)
    resolver = FixtureResolver()
    _load_chain(resolver, h)

    qname = dns.name.from_text(BINDING_QNAME)
    wildcard = dns.name.from_text("*." + HOST)
    txt_rd = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{DEFAULT_RECORD}"')
    # Sign the rrset at the WILDCARD owner; its RRSIG.labels reflects the wildcard.
    wild_rrset = dns.rrset.from_rdata(wildcard, 300, txt_rd)
    wild_sig = h.leaf.sign_with_zsk(wild_rrset)
    # The synthesized answer is served at the qname, carrying the wildcard RRSIG.
    qname_rrset = dns.rrset.from_rdata(qname, 300, txt_rd)
    qname_sig = dns.rrset.from_rdata(qname, 300, wild_sig)
    resolver.add(BINDING_QNAME, "TXT", _answer_message(BINDING_QNAME, "TXT",
                                                       [qname_rrset, qname_sig]))
    return resolver


# Re-export helpers used by sibling test modules (denial / wildcard).
__all__ = [
    "SignedZone",
    "FixtureResolver",
    "HOST",
    "BINDING_QNAME",
    "DEFAULT_RECORD",
    "INCEPTION",
    "EXPIRATION",
    "NOW",
    "NSEC3_ALG",
    "NSEC3_FLAGS",
    "NSEC3_ITERATIONS",
    "NSEC3_SALT",
]

"""IANA DNS root trust anchor for the in-process DNSSEC chain validator.

Rev 6 I2: the validator walks the chain to the root and validates each cut
*cryptographically* — it never trusts a resolver's AD bit. The root DNSKEY
RRset is the only key the validator trusts a priori; everything below it is
proven by signatures chaining up to a root KSK whose DS digest is published by
IANA out-of-band (https://www.iana.org/dnssec/files).

What is embedded
----------------
``ROOT_TRUST_ANCHORS`` is the set of root-zone KSK DS records (the same content
as IANA's ``root-anchors.xml``):

  * **KSK-2017** (key tag 20326, algorithm 8 / RSASHA256, SHA-256 digest) — the
    currently-active root KSK.
  * **KSK-2024** (key tag 38696, algorithm 8 / RSASHA256, SHA-256 digest) — the
    successor KSK published by IANA for the next rollover.

A root DNSKEY RRset validates against this anchor iff one of its KSKs (a DNSKEY
with the SEP/flags-257 bit) produces a DS digest equal to one of these records
(RFC 4509). Holding *both* the active and successor anchors means a root KSK
rollover does not strand the validator between ceremonies.

Rotation note (operator-facing)
--------------------------------
Root KSK rollovers are rare (the 2017 rollover was the first since the root was
signed in 2010) and pre-announced by IANA years ahead. When IANA publishes a
new KSK, add its DS record here and ship it in a release *before* the old anchor
is retired. This module is the single source of truth in production; the
DNSSEC test harness monkeypatches ``ROOT_TRUST_ANCHORS`` to a fake root so the
offline fixture chain validates without touching the live root.

This module has **no top-level dnspython import** (Rev 6 I11): the anchor is
stored as plain text + ints and only materialised into ``dns.*`` rdata inside
``root_ds_rdataset()``, which the validator calls at runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import for type-checkers only; never at runtime (I11).
    import dns.rdataset


@dataclass(frozen=True)
class RootTrustAnchor:
    """One root-zone KSK DS record (RFC 4034 §5.1 / RFC 4509).

    ``key_tag``/``algorithm``/``digest_type`` and the hex ``digest`` are exactly
    the fields of a DS RR; ``label`` is a human tag for logs/operators.
    """

    label: str
    key_tag: int
    algorithm: int
    digest_type: int  # 2 == SHA-256
    digest: str  # hex, uppercase

    def to_ds_text(self) -> str:
        """Render the canonical DS presentation form (``tag alg digtype hex``)."""
        return f"{self.key_tag} {self.algorithm} {self.digest_type} {self.digest}"


# IANA root-zone KSK DS records (root-anchors.xml). SHA-256 digests, RSASHA256.
ROOT_TRUST_ANCHORS: tuple[RootTrustAnchor, ...] = (
    RootTrustAnchor(
        label="KSK-2017",
        key_tag=20326,
        algorithm=8,
        digest_type=2,
        digest="E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    ),
    RootTrustAnchor(
        label="KSK-2024",
        key_tag=38696,
        algorithm=8,
        digest_type=2,
        digest="683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
    ),
)


def root_ds_rdataset() -> dns.rdataset.Rdataset:
    """Materialise ``ROOT_TRUST_ANCHORS`` as a dnspython DS rdataset at the root.

    dnspython is imported here (function-local, Rev 6 I11) so importing this
    module never pulls in the optional ``[federation-dnssec]`` extra.
    """
    import dns.name
    import dns.rdata
    import dns.rdataclass
    import dns.rdataset
    import dns.rdatatype

    rds = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DS)
    rds.ttl = 3600
    for anchor in ROOT_TRUST_ANCHORS:
        rds.add(
            dns.rdata.from_text(
                dns.rdataclass.IN,
                dns.rdatatype.DS,
                anchor.to_ds_text(),
            )
        )
    return rds

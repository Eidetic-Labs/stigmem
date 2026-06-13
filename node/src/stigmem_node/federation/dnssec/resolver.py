"""Injectable resolver seam for the DNSSEC chain validator (Rev 6 I2/I11).

The validator never talks to the network directly: it asks a ``Resolver`` for
the DNS messages it needs (DNSKEY, DS, the binding TXT, and the NSEC3 denial
records), then validates every signature itself. Three concerns are kept apart:

  * ``Resolver`` — the Protocol the validator depends on. ``query(qname,
    rdtype) -> dns.message.Message``. The returned message is treated as
    *untrusted transport*; the validator re-validates every RRset against the
    chain and **never reads the message's AD bit**.
  * ``LiveResolver`` — the production impl. All dnspython imports are
    function-local (Rev 6 I11) so importing this module on a default node does
    not load the optional ``[federation-dnssec]`` extra. It fetches DNSKEY/DS/
    answer records *explicitly* through a stub resolver and asks for DNSSEC
    records (``want_dnssec``) so RRSIGs ride along; it does not delegate
    validation to the upstream resolver.
  * ``FixtureResolver`` — the offline test impl. It is preloaded with canned
    ``dns.message.Message`` answers keyed by ``(qname, rdtype)`` so the harness
    can drive every adversarial scenario without a network.

``LiveResolver`` is the egress seam the 3b/3c SSRF discipline (plan TX-4)
constrains: it MUST use a stub resolver and never a peer-supplied resolver
address. It is intentionally not reachable from the relay path in 3a.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:  # import only for type-checkers; never at runtime (I11).
    import dns.message


@runtime_checkable
class Resolver(Protocol):
    """The validator's only dependency on DNS transport.

    ``query`` returns the DNS response message for ``(qname, rdtype)`` with the
    DNSSEC records (RRSIG / NSEC3 / DS) included. Implementations raise on a
    transport failure (timeout / SERVFAIL); the validator maps that to a
    fail-closed outcome rather than trusting a missing answer.
    """

    def query(self, qname: str, rdtype: str) -> dns.message.Message: ...


class LiveResolver:
    """Production resolver: explicit DNSSEC-record fetch via a stub resolver.

    The AD bit on any response is **ignored** — the validator re-derives trust
    from the signatures. dnspython is imported inside ``query`` (Rev 6 I11).
    """

    def __init__(self, *, timeout: float = 5.0) -> None:
        self._timeout = timeout

    def query(self, qname: str, rdtype: str) -> dns.message.Message:
        import dns.flags
        import dns.message
        import dns.name
        import dns.query
        import dns.rdatatype
        import dns.resolver

        name = dns.name.from_text(qname)
        rtype = dns.rdatatype.from_text(rdtype)

        # Build a query that asks the *server* to include DNSSEC records
        # (RRSIG/NSEC3/DS) so we can validate them ourselves. We do NOT set the
        # checking-disabled bit's inverse to mean "trust the server" — we never
        # read the AD bit on the way back (Rev 6 I2).
        request = dns.message.make_query(name, rtype, want_dnssec=True)

        # Resolve through the system stub resolver's configured nameservers.
        # The address comes from the host resolver config, never from a peer
        # (plan TX-4 SSRF discipline). UDP first, TCP on truncation.
        resolver = dns.resolver.get_default_resolver()
        nameserver = str(resolver.nameservers[0])
        response = dns.query.udp(request, nameserver, timeout=self._timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(request, nameserver, timeout=self._timeout)
        return response


class FixtureResolver:
    """Offline test resolver preloaded with canned DNS messages.

    The harness (``tests/federation/dnssec/conftest.py``) builds a fully signed
    fake hierarchy and loads the per-``(qname, rdtype)`` messages here. The
    validator queries it exactly as it would ``LiveResolver``.
    """

    def __init__(self) -> None:
        # key: (lower-cased absolute qname, upper-cased rdtype) -> Message
        self._answers: dict[tuple[str, str], dns.message.Message] = {}
        self._force_ad_only = False

    @staticmethod
    def _key(qname: str, rdtype: str) -> tuple[str, str]:
        canonical = qname.lower()
        if not canonical.endswith("."):
            canonical += "."
        return (canonical, rdtype.upper())

    def add(self, qname: str, rdtype: str, message: dns.message.Message) -> None:
        """Register a canned response for ``(qname, rdtype)``."""
        self._answers[self._key(qname, rdtype)] = message

    def force_ad_bit_only(self) -> None:
        """Strip every RRSIG/DNSSEC record and set AD=1 on every canned message.

        Used by the AD-bit-ignored test (Rev 6 I2): a validator that trusts the
        AD bit would accept; a validator that re-validates the chain must reject
        because there are no signatures left to verify.
        """
        import dns.flags
        import dns.rdatatype

        dnssec_types = {
            dns.rdatatype.RRSIG,
            dns.rdatatype.NSEC,
            dns.rdatatype.NSEC3,
            dns.rdatatype.NSEC3PARAM,
            dns.rdatatype.DS,
        }
        for message in self._answers.values():
            message.flags |= dns.flags.AD
            for section in (message.answer, message.authority, message.additional):
                section[:] = [rr for rr in section if rr.rdtype not in dnssec_types]
        self._force_ad_only = True

    def force_ad_bit(self) -> None:
        """Set AD=1 on every canned message WITHOUT stripping any RRSIG.

        Companion to ``force_ad_bit_only`` (which strips signatures). This hook
        keeps every RRset — including a present-but-forged binding RRSIG —
        intact, so a test can prove the validator ignores the AD bit even when a
        signature is present to (mis)trust: it must re-validate the signature
        itself and reject the forgery (3AV-3).
        """
        import dns.flags

        for message in self._answers.values():
            message.flags |= dns.flags.AD

    def query(self, qname: str, rdtype: str) -> dns.message.Message:
        import dns.rcode

        key = self._key(qname, rdtype)
        message = self._answers.get(key)
        if message is None:
            # An absent canned answer models a NOERROR/empty (NODATA) response
            # for an rdtype we did not stage. Return an empty NOERROR message so
            # the validator's denial logic (3a.5) — not a KeyError — decides the
            # outcome.
            import dns.message
            import dns.name
            import dns.rdatatype

            empty = dns.message.make_response(
                dns.message.make_query(
                    dns.name.from_text(key[0]),
                    dns.rdatatype.from_text(rdtype),
                )
            )
            empty.set_rcode(dns.rcode.NOERROR)
            return empty
        return message

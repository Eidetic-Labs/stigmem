"""Off-path composition tests for ``resolve_dnssec_binding`` (Rev 6 §7/I2/I3).

Commit 3a.7. This is the single entry point that composes the three 3a pieces:

    host_from_entity_uri (3a.2) -> validate_binding (3a.4/5/6) -> parse record (3a.3)

into a ``DnssecResult`` the first-trust ladder (3b) consumes. It is OFF-PATH —
no resolver is wired into the relay terminal yet (that is 3c). Every input maps
to exactly one result; no exception escapes.

Outcome map (Rev 6 §7/I3):
  * SECURE + active record  -> ACTIVE(record)
  * SECURE + revoked record -> REVOKED(record)
  * INSECURE                -> INSECURE                (caller -> operator-confirm)
  * ABSENT_AUTHENTICATED    -> ABSENT_AUTHENTICATED    (caller -> operator-confirm)
  * UNVALIDATABLE           -> UNVALIDATABLE           (caller rejects)
  * BOGUS                   -> BOGUS                   (caller rejects)
  * host is None            -> NOT_APPLICABLE          (caller -> operator-confirm)
"""

from __future__ import annotations

from stigmem_node.federation.dnssec import DnssecResult, resolve_dnssec_binding
from stigmem_node.federation.dnssec.record import BindingRecord

from .conftest import HOST, INCEPTION

# A DNSSEC-capable entity_uri whose host canonicalizes to the fixture HOST.
ENTITY_URI = "https://" + HOST.rstrip(".") + "/"


def test_active_chain_resolves_to_active(valid_chain):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=valid_chain)
    assert res.outcome is DnssecResult.Outcome.ACTIVE, res
    assert isinstance(res.record, BindingRecord)
    assert res.record.fpr == "abc123def"
    assert res.record.epoch == 7
    assert res.record.revoked is False


def test_active_carries_rrsig_inception(valid_chain):
    # I4: the SECURE binding's RRSIG inception is threaded onto the ACTIVE result
    # so the ladder can derive the signature age.
    res = resolve_dnssec_binding(ENTITY_URI, resolver=valid_chain)
    assert res.outcome is DnssecResult.Outcome.ACTIVE, res
    assert res.rrsig_inception == int(INCEPTION.timestamp())


def test_revoked_chain_resolves_to_revoked(revoked_chain):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=revoked_chain)
    assert res.outcome is DnssecResult.Outcome.REVOKED, res
    assert isinstance(res.record, BindingRecord)
    assert res.record.revoked is True
    assert res.record.fpr == ""


def test_non_secure_outcome_has_no_rrsig_inception(forged_rrsig_chain):
    # A non-SECURE outcome carries no inception (nothing trustworthy to age).
    res = resolve_dnssec_binding(ENTITY_URI, resolver=forged_rrsig_chain)
    assert res.outcome is DnssecResult.Outcome.BOGUS, res
    assert res.rrsig_inception is None


def test_active_carries_binding_ttl(valid_chain):
    # I5/§7 (3c.1): the SECURE binding's DNS TTL is threaded onto the ACTIVE
    # result so the relay-path re-check can clamp its cadence to it (fixture TTL
    # is 300).
    res = resolve_dnssec_binding(ENTITY_URI, resolver=valid_chain)
    assert res.outcome is DnssecResult.Outcome.ACTIVE, res
    assert res.ttl == 300


def test_revoked_carries_binding_ttl(revoked_chain):
    # The TTL rides on the REVOKED outcome too (it is also SECURE-derived).
    res = resolve_dnssec_binding(ENTITY_URI, resolver=revoked_chain)
    assert res.outcome is DnssecResult.Outcome.REVOKED, res
    assert res.ttl == 300


def test_non_secure_outcome_has_no_ttl(forged_rrsig_chain):
    # A non-SECURE outcome carries no TTL.
    res = resolve_dnssec_binding(ENTITY_URI, resolver=forged_rrsig_chain)
    assert res.outcome is DnssecResult.Outcome.BOGUS, res
    assert res.ttl is None


def test_insecure_delegation_resolves_to_insecure(unsigned_delegation):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=unsigned_delegation)
    assert res.outcome is DnssecResult.Outcome.INSECURE, res
    assert res.record is None


def test_authenticated_absence_resolves_to_absent_authenticated(stripped_nsec3):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=stripped_nsec3)
    assert res.outcome is DnssecResult.Outcome.ABSENT_AUTHENTICATED, res
    assert res.record is None


def test_unvalidatable_absence_resolves_to_unvalidatable(unvalidatable_absence):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=unvalidatable_absence)
    assert res.outcome is DnssecResult.Outcome.UNVALIDATABLE, res
    assert res.record is None


def test_forged_chain_resolves_to_bogus(forged_rrsig_chain):
    res = resolve_dnssec_binding(ENTITY_URI, resolver=forged_rrsig_chain)
    assert res.outcome is DnssecResult.Outcome.BOGUS, res
    assert res.record is None


def test_non_dnssec_capable_entity_uri_is_not_applicable(valid_chain):
    # An IP-literal entity_uri yields no host (I3) -> NOT_APPLICABLE, regardless
    # of resolver state (the resolver is never consulted).
    res = resolve_dnssec_binding("https://192.0.2.5/", resolver=valid_chain)
    assert res.outcome is DnssecResult.Outcome.NOT_APPLICABLE, res
    assert res.record is None


def test_no_exception_escapes_on_garbage_uri(valid_chain):
    # Opaque / non-HTTP scheme -> no host -> NOT_APPLICABLE, never raises.
    res = resolve_dnssec_binding("urn:stigmem:node:7", resolver=valid_chain)
    assert res.outcome is DnssecResult.Outcome.NOT_APPLICABLE, res

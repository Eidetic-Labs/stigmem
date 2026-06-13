"""Chain-of-trust binding tests (RFC 4035 §5.2) — 3AV-2.

The DNSKEY RRset's RRSIG MUST be validated using ONLY the DS-authenticated
key(s) as the keyset — not the whole served RRset. These tests close the 3AV-1
blind spot: they fail on a validator that decouples "a DS-matching key exists"
from "the RRset is self-signed by some key in it", and they would also fail if
``dns.dnssec.validate`` were a no-op (each asserts a real cryptographic reject).
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.validator import Validation, validate_binding

from .conftest import HOST


def test_dnskey_self_signed_by_non_ds_key_is_bogus(unbound_dnskey_chain):
    # 3AV-1 regression: the served leaf DNSKEY RRset contains the real DS-pinned
    # KSK but is self-signed by an ATTACKER KSK, and the binding TXT is signed by
    # the attacker's ZSK. A decoupled validator returns SECURE with the
    # attacker's fingerprint; binding the keyset to the DS-authenticated key ->
    # BOGUS.
    res = validate_binding(HOST.rstrip("."), resolver=unbound_dnskey_chain)
    assert res.status is Validation.BOGUS, res.detail
    # And the attacker's record must NOT have leaked through.
    assert res.record is None


def test_dnskey_only_self_sig_not_ds_matched_is_bogus(dnskey_self_signed_by_non_ds_key):
    res = validate_binding(HOST.rstrip("."), resolver=dnskey_self_signed_by_non_ds_key)
    assert res.status is Validation.BOGUS, res.detail


def test_ds_signed_by_non_parent_key_is_bogus(ds_signed_by_non_parent_key):
    res = validate_binding(HOST.rstrip("."), resolver=ds_signed_by_non_parent_key)
    assert res.status is Validation.BOGUS, res.detail


def test_nsec3_absence_signed_by_wrong_key_is_unvalidatable(
    nsec3_absence_signed_by_wrong_key,
):
    res = validate_binding(HOST.rstrip("."), resolver=nsec3_absence_signed_by_wrong_key)
    assert res.status is Validation.UNVALIDATABLE, res.detail


def test_forged_no_ds_nsec3_wrong_key_is_not_insecure(forged_no_ds_nsec3_wrong_key):
    # A wrong-key NS-no-DS NSEC3 must not downgrade the leaf to INSECURE. The
    # leaf DS is absent and the forged proof does not validate, so the walk
    # treats the leaf as "not a cut" and stays in the parent zone; the binding
    # TXT then has no validatable answer.
    res = validate_binding(HOST.rstrip("."), resolver=forged_no_ds_nsec3_wrong_key)
    assert res.status is not Validation.INSECURE, res.detail

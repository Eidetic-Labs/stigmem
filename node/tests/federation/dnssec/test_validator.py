"""Validator chain tests (Rev 6 I2) — commit 3a.4.

Exercises the real crypto path through the offline signed hierarchy:
  * valid chain -> SECURE (+ parsed record)
  * AD bit set but RRSIGs stripped -> BOGUS (proves the AD bit is ignored)
  * forged RRSIG (wrong key) -> BOGUS
  * stale RRSIG (far-past inception/expiration) -> BOGUS
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.validator import Validation, validate_binding

from .conftest import HOST


def test_valid_chain_returns_secure(valid_chain):
    res = validate_binding(HOST.rstrip("."), resolver=valid_chain)
    assert res.status is Validation.SECURE, res.detail
    assert res.record is not None
    assert res.record.fpr == "abc123def"
    assert res.record.epoch == 7
    assert res.record.revoked is False


def test_ad_bit_is_ignored(valid_chain):
    # Strip every RRSIG/DNSSEC record and set AD=1 on every canned message. A
    # validator that trusted the AD bit would accept; we re-validate the chain
    # and find no signatures -> BOGUS.
    valid_chain.force_ad_bit_only()
    res = validate_binding(HOST.rstrip("."), resolver=valid_chain)
    assert res.status is Validation.BOGUS, res.detail


def test_forged_rrsig_is_bogus(forged_rrsig_chain):
    res = validate_binding(HOST.rstrip("."), resolver=forged_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail


def test_stale_rrsig_is_bogus(stale_rrsig_chain):
    # 3a is strict: a far-past/expired binding RRSIG is BOGUS at validation
    # time. The age-clamp -> operator-confirm nuance is a 3b concern.
    res = validate_binding(HOST.rstrip("."), resolver=stale_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail

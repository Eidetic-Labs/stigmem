"""Validator chain tests (Rev 6 I2) — commit 3a.4.

Exercises the real crypto path through the offline signed hierarchy:
  * valid chain -> SECURE (+ parsed record)
  * AD bit set but RRSIGs stripped -> BOGUS (proves the AD bit is ignored)
  * forged RRSIG (wrong key) -> BOGUS
  * stale RRSIG (far-past inception/expiration) -> BOGUS
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.validator import Validation, validate_binding

from .conftest import HOST, INCEPTION, TWO_RRSIG_STALE_INCEPTION


def test_valid_chain_returns_secure(valid_chain):
    res = validate_binding(HOST.rstrip("."), resolver=valid_chain)
    assert res.status is Validation.SECURE, res.detail
    assert res.record is not None
    assert res.record.fpr == "abc123def"
    assert res.record.epoch == 7
    assert res.record.revoked is False


def test_secure_surfaces_binding_rrsig_inception(valid_chain):
    # I4: the validator surfaces the binding RRSIG inception (newest covering
    # signature) so the ladder's age clamp can fire. It is the fixture window
    # inception (epoch seconds).
    res = validate_binding(HOST.rstrip("."), resolver=valid_chain)
    assert res.status is Validation.SECURE, res.detail
    assert res.rrsig_inception == int(INCEPTION.timestamp())


def test_non_secure_has_no_rrsig_inception(forged_rrsig_chain):
    # A non-SECURE path never surfaces an inception (it would be meaningless and
    # must not read as "fresh" downstream).
    res = validate_binding(HOST.rstrip("."), resolver=forged_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail
    assert res.rrsig_inception is None


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


def test_ad_bit_ignored_even_with_present_forged_signature(forged_rrsig_chain):
    # 3AV-3: AD=1 AND a present-but-invalid binding RRSIG. Unlike the
    # stripped-RRSIG case, a signature IS present here — but it is forged. A
    # validator that trusted AD when "a signature exists" would accept; we
    # re-validate the signature itself and reject -> BOGUS.
    forged_rrsig_chain.force_ad_bit()
    res = validate_binding(HOST.rstrip("."), resolver=forged_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail


def test_two_covering_rrsigs_inception_from_validating_only(two_covering_rrsigs_chain):
    # F1 (CRITICAL): a binding TXT served with TWO covering RRSIGs — the real
    # stale-but-valid ZSK signature plus an injected near-now RRSIG signed by a
    # rogue key that does NOT validate. The combined chain check still passes on
    # the real signature, so the verdict is SECURE; but the surfaced
    # `rrsig_inception` MUST be derived from ONLY the individually-validating
    # signature (the stale real one), NOT max() over the served set (which would
    # pick the attacker's fresh-looking value and defeat the I4 age clamp).
    res = validate_binding(HOST.rstrip("."), resolver=two_covering_rrsigs_chain)
    assert res.status is Validation.SECURE, res.detail
    assert res.rrsig_inception == int(TWO_RRSIG_STALE_INCEPTION.timestamp())


def test_stale_rrsig_is_bogus(stale_rrsig_chain):
    # 3a is strict: a far-past/expired binding RRSIG is BOGUS at validation
    # time. The age-clamp -> operator-confirm nuance is a 3b concern.
    res = validate_binding(HOST.rstrip("."), resolver=stale_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail


def test_secure_surfaces_binding_ttl(valid_chain):
    # I5/§7 (3c.1): the validator surfaces the binding TXT RRset's DNS TTL so the
    # relay-path re-check can clamp its cadence to it. The fixture binding TXT is
    # served with TTL 300 (conftest._load_binding_txt).
    res = validate_binding(HOST.rstrip("."), resolver=valid_chain)
    assert res.status is Validation.SECURE, res.detail
    assert res.ttl == 300


def test_non_secure_has_no_ttl(forged_rrsig_chain):
    # A non-SECURE outcome carries no TTL (nothing trustworthy to clamp on).
    res = validate_binding(HOST.rstrip("."), resolver=forged_rrsig_chain)
    assert res.status is Validation.BOGUS, res.detail
    assert res.ttl is None

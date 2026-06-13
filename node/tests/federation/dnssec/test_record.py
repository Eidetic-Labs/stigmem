"""Strict v=stigmem1 binding-record grammar (Rev 6 §7).

The DNSSEC TXT record at ``_stigmem-fed._key.<host>`` carries the origin's key
fingerprint + a monotonic rotation epoch. Two forms:

  active:  ``v=stigmem1; fpr=<key_fpr>; epoch=<n>; prev_fpr=...; prev_until=...``
  revoked: ``v=stigmem1; status=revoked; epoch=<n>; fpr=`` (empty fpr)

Parsing is fail-closed: the first token MUST be ``v=stigmem1`` and ``epoch`` is
required; any violation returns None and no exception escapes.
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.record import BindingRecord, parse_binding_record


def test_active_record():
    r = parse_binding_record(
        "v=stigmem1; fpr=abc123; epoch=7; prev_fpr=old99; prev_until=2026-07-01T00:00:00Z"
    )
    assert isinstance(r, BindingRecord)
    assert r.revoked is False
    assert r.fpr == "abc123"
    assert r.epoch == 7
    assert r.prev_fpr == "old99"
    assert r.prev_until == "2026-07-01T00:00:00Z"


def test_active_record_minimal():
    r = parse_binding_record("v=stigmem1; fpr=abc123; epoch=0")
    assert isinstance(r, BindingRecord)
    assert r.revoked is False
    assert r.fpr == "abc123"
    assert r.epoch == 0
    assert r.prev_fpr == ""
    assert r.prev_until == ""


def test_revoked_record():
    r = parse_binding_record("v=stigmem1; status=revoked; epoch=9; fpr=")
    assert isinstance(r, BindingRecord)
    assert r.revoked is True
    assert r.epoch == 9
    assert r.fpr == ""


def test_revoked_record_without_explicit_empty_fpr():
    # A revoked record may omit fpr entirely; it is still revoked.
    r = parse_binding_record("v=stigmem1; status=revoked; epoch=9")
    assert isinstance(r, BindingRecord)
    assert r.revoked is True
    assert r.epoch == 9
    assert r.fpr == ""


def test_ignores_unknown_keys_forward_compat():
    r = parse_binding_record("v=stigmem1; fpr=abc; epoch=1; future_field=whatever")
    assert isinstance(r, BindingRecord)
    assert r.fpr == "abc"
    assert r.epoch == 1


def test_rejects_missing_version_first():
    # v= present but not the FIRST token -> reject.
    assert parse_binding_record("fpr=abc; v=stigmem1; epoch=1") is None


def test_rejects_unknown_version():
    assert parse_binding_record("v=stigmem2; fpr=abc; epoch=1") is None


def test_rejects_malformed():
    assert parse_binding_record("garbage") is None
    assert parse_binding_record("") is None
    assert parse_binding_record("v=stigmem1; fpr=abc") is None  # no epoch
    assert parse_binding_record("v=stigmem1; epoch=notanint; fpr=abc") is None
    assert parse_binding_record("v=stigmem1; epoch=-1; fpr=abc") is None  # negative epoch
    assert parse_binding_record("v=stigmem1; epoch=3") is None  # active form needs fpr
    assert parse_binding_record("v=stigmem1; fpr=; epoch=3") is None  # active empty fpr


def test_rejects_duplicate_known_key():
    # 3AC-1: a duplicate of any KNOWN key is ambiguous -> reject (not last-write).
    assert parse_binding_record("v=stigmem1; fpr=a; epoch=1; epoch=2") is None
    assert parse_binding_record("v=stigmem1; fpr=a; fpr=b; epoch=1") is None
    # A single occurrence of each known key (no duplicate) still parses.
    assert parse_binding_record("v=stigmem1; status=revoked; epoch=1; fpr=") is not None
    assert parse_binding_record(
        "v=stigmem1; status=revoked; status=revoked; epoch=1; fpr="
    ) is None
    assert parse_binding_record(
        "v=stigmem1; fpr=a; epoch=1; prev_fpr=x; prev_fpr=y"
    ) is None
    assert parse_binding_record(
        "v=stigmem1; fpr=a; epoch=1; prev_until=p; prev_until=q"
    ) is None
    # An unknown key may repeat without rejection (forward-compat).
    assert parse_binding_record(
        "v=stigmem1; fpr=a; epoch=1; x=1; x=2"
    ) is not None


def test_rejects_non_strict_epoch():
    # 3AC-2: epoch must be a plain ASCII non-negative decimal integer.
    assert parse_binding_record("v=stigmem1; fpr=a; epoch=+5") is None  # leading sign
    assert parse_binding_record("v=stigmem1; fpr=a; epoch=1_000") is None  # underscores
    assert parse_binding_record("v=stigmem1; fpr=a; epoch=٠١") is None  # Unicode digits
    assert parse_binding_record("v=stigmem1; fpr=a; epoch= 5; ") is None  # inner whitespace
    # epoch=0 (and a plain positive int) remain valid.
    r0 = parse_binding_record("v=stigmem1; fpr=a; epoch=0")
    assert r0 is not None and r0.epoch == 0

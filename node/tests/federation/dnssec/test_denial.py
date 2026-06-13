"""Authenticated denial-of-existence + insecure-delegation tests (Rev 6 I2).

Commit 3a.5. Exercises the validator's NSEC3 denial path through the offline
signed hierarchy:
  * validated NSEC3 absence proof -> ABSENT_AUTHENTICATED (caller may fall through)
  * absence with NO proof -> UNVALIDATABLE (caller MUST reject)
  * authenticated no-DS (NS, no DS) -> INSECURE (unsigned delegation)
"""

from __future__ import annotations

from stigmem_node.federation.dnssec.validator import Validation, validate_binding

from .conftest import HOST


def test_authenticated_nsec3_absence_is_absent_authenticated(stripped_nsec3):
    res = validate_binding(HOST.rstrip("."), resolver=stripped_nsec3)
    assert res.status is Validation.ABSENT_AUTHENTICATED, res.detail


def test_absence_without_proof_is_unvalidatable(unvalidatable_absence):
    res = validate_binding(HOST.rstrip("."), resolver=unvalidatable_absence)
    assert res.status is Validation.UNVALIDATABLE, res.detail


def test_authenticated_unsigned_delegation_is_insecure(unsigned_delegation):
    res = validate_binding(HOST.rstrip("."), resolver=unsigned_delegation)
    assert res.status is Validation.INSECURE, res.detail

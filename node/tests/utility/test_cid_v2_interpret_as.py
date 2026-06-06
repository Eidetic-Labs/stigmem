"""CID v2: `interpret_as` is bound to the content address (ADR-003 / threat R-23).

Flipping a fact's interpretation between `content` and `instruction` must change
its CID, so a storage/admin-level flip is caught on the read path.
"""

import pytest

from stigmem_node.cid import (
    CidMismatchError,
    compute_cid,
    compute_cid_from_row,
    verify_cid_from_row,
)

_BASE = dict(
    entity="user:1",
    relation="prefers",
    value_type="string",
    value_v="tea",
    source="agent:a",
    scope="company",
    confidence=1.0,
)


def test_interpret_as_changes_cid():
    content = compute_cid(**_BASE, interpret_as="content")
    instruction = compute_cid(**_BASE, interpret_as="instruction")
    assert content != instruction


def test_default_interpret_as_is_content():
    assert compute_cid(**_BASE) == compute_cid(**_BASE, interpret_as="content")


def test_verify_catches_interpret_as_flip():
    # stored CID was computed for content; row now claims instruction → mismatch.
    stored = compute_cid(**_BASE, interpret_as="content")
    row = {**_BASE, "id": "f1", "cid": stored, "interpret_as": "instruction"}
    with pytest.raises(CidMismatchError):
        verify_cid_from_row(row)


def test_verify_passes_when_interpret_as_matches():
    stored = compute_cid(**_BASE, interpret_as="instruction")
    row = {**_BASE, "id": "f1", "cid": stored, "interpret_as": "instruction"}
    verify_cid_from_row(row)  # must not raise


def test_compute_cid_from_row_defaults_to_content_when_missing():
    # A row without an interpret_as column is treated as content.
    row = {**_BASE}
    assert compute_cid_from_row(row) == compute_cid(**_BASE, interpret_as="content")

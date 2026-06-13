"""Strict ``v=stigmem1`` DNSSEC binding-record grammar (Rev 6 §7).

The DNSSEC-signed TXT record at ``_stigmem-fed._key.<canonical-host>`` binds an
origin's key fingerprint to a monotonic rotation epoch. Two forms:

    active:  ``v=stigmem1; fpr=<key_fpr>; epoch=<n>; prev_fpr=<or-empty>; prev_until=<or-empty>``
    revoked: ``v=stigmem1; status=revoked; epoch=<n>; fpr=`` (empty fpr)

The grammar is freeze-safe by construction (Rev 6 §7): unknown ``k=v`` pairs are
ignored, so adding a field later is a routine zone re-sign rather than a
re-sign-of-committed-material break.

Parsing is fail-closed (Rev 6 I10): the FIRST token MUST be ``v=stigmem1``,
``epoch`` is required and is a non-negative int, the active form requires a
non-empty ``fpr``, and the revoked form (``status=revoked``) has an empty
``fpr``. Any violation returns ``None``; no exception escapes.
"""

from __future__ import annotations

from dataclasses import dataclass

# DNS binding-record version sentinel (the required first token), not a
# credential — bandit's B105 heuristic flags the embedded '=' as a hardcoded
# password string.
_VERSION_TOKEN = "v=stigmem1"  # nosec B105

# Keys this grammar assigns meaning to. A DUPLICATE of any of these is ambiguous
# and rejected (fail-closed); duplicates of unknown keys are tolerated for the
# forward-compat path (Rev 6 §7).
_KNOWN_KEYS = frozenset({"v", "fpr", "epoch", "status", "prev_fpr", "prev_until"})


@dataclass(frozen=True)
class BindingRecord:
    """A parsed, structurally-valid DNSSEC binding record.

    Validation of the DNSSEC chain itself happens in the validator (3a.4+);
    this dataclass represents only a record whose *grammar* is well-formed.
    """

    fpr: str
    epoch: int
    prev_fpr: str = ""
    prev_until: str = ""
    revoked: bool = False


def parse_binding_record(txt: str) -> BindingRecord | None:
    """Parse a binding-record TXT string. Returns ``None`` on any violation."""
    if not txt:
        return None

    # Split on ';' into tokens; tolerate surrounding whitespace.
    tokens = [t.strip() for t in txt.split(";")]
    tokens = [t for t in tokens if t]
    if not tokens:
        return None

    # The FIRST token MUST be exactly the version token.
    if tokens[0] != _VERSION_TOKEN:
        return None

    pairs: dict[str, str] = {}
    for tok in tokens[1:]:
        if "=" not in tok:
            return None  # malformed token (not k=v)
        key, _, raw_value = tok.partition("=")
        key = key.strip()
        if not key:
            return None
        # Reject a DUPLICATE of any known key (the grammar assigns it meaning, so
        # a second occurrence is ambiguous -> fail closed). Unknown keys may
        # repeat for forward-compat; their last-write value is harmless.
        if key in _KNOWN_KEYS and key in pairs:
            return None
        # Keep the raw (unstripped) value alongside the stripped one so the
        # strict numeric gate below can reject embedded whitespace (e.g.
        # ``epoch= 5``), which ``int()`` would otherwise silently accept.
        pairs[key] = raw_value.strip()
        if key == "epoch":
            raw_epoch_token = raw_value

    # epoch is required and must be a strict ASCII non-negative decimal integer.
    raw_epoch = pairs.get("epoch")
    if raw_epoch is None:
        return None
    # Gate against the RAW value: ``int()`` accepts ``+5``, ``1_000``, Unicode
    # digits (``٠١``), and surrounding whitespace — none of which are valid here.
    if not raw_epoch_token.isascii() or not raw_epoch_token.isdigit():
        return None
    epoch = int(raw_epoch_token)

    revoked = pairs.get("status") == "revoked"
    fpr = pairs.get("fpr", "")

    if revoked:
        # Revoked tombstone: fpr must be empty (or omitted).
        if fpr:
            return None
        return BindingRecord(fpr="", epoch=epoch, revoked=True)

    # Active form requires a non-empty fingerprint.
    if not fpr:
        return None

    return BindingRecord(
        fpr=fpr,
        epoch=epoch,
        prev_fpr=pairs.get("prev_fpr", ""),
        prev_until=pairs.get("prev_until", ""),
        revoked=False,
    )

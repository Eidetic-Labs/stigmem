"""DNSSEC-rooted origin key trust — Federation Phase 3 validation core.

This package implements the in-process DNSSEC binding-record substrate for the
Phase-3 first-trust ladder (frozen design Rev 6). It is **off-path and
default-inert**: nothing here is reachable from the relay resolver until the
3b ladder wiring lands behind ``federation_dnssec_trust_enabled`` (default
False).

Lazy-import invariant (Rev 6 I11): there is **no top-level ``import dns``**
anywhere in this package. dnspython is supplied by the optional
``[federation-dnssec]`` extra and is imported only inside the functions that
need it, so importing ``stigmem_node`` on a default node never loads the extra.
"""

from __future__ import annotations

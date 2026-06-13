"""Lazy-import guard for the federation-dnssec extra (Rev 6 I11).

Importing the node package — or the dnssec package itself — must NOT pull
dnspython (`dns` / `dns.*`) into ``sys.modules``. All dnspython imports are
function-local so a default node never loads the optional extra at import time.
"""

from __future__ import annotations

import importlib
import sys
from collections.abc import Iterator

import pytest


@pytest.fixture
def purge_dns_modules() -> Iterator[None]:
    """Purge ``dns.*`` from ``sys.modules`` for the test, then RESTORE it.

    The guard asserts the node does not import dnspython at module load. To do
    that it must clear any already-imported ``dns.*`` modules. Restoring them
    afterward is essential: a torn-down ``dns.*`` would force *other* tests in
    the session to re-import dnspython into *new* module objects, and dnspython
    objects built across two ``dns`` imports compare unequal (``Name``/``DS``
    ``__eq__`` are ``isinstance`` checks). That cross-import poisoning would
    spuriously fail the DNSSEC validator suite that runs later in the session.
    """
    saved = {m: sys.modules[m] for m in list(sys.modules) if m == "dns" or m.startswith("dns.")}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        # Drop anything re-imported during the test, then restore the originals
        # so downstream tests see the exact same module objects as before.
        for name in [m for m in list(sys.modules) if m == "dns" or m.startswith("dns.")]:
            del sys.modules[name]
        sys.modules.update(saved)


def test_dnssec_extra_not_imported_on_default_node_load(purge_dns_modules):
    importlib.import_module("stigmem_node")
    assert not any(
        m == "dns" or m.startswith("dns.") for m in sys.modules
    ), "dnspython imported at stigmem_node load — must be function-local (I11)"


def test_dnssec_package_import_does_not_pull_dnspython(purge_dns_modules):
    importlib.import_module("stigmem_node.federation.dnssec")
    assert not any(
        m == "dns" or m.startswith("dns.") for m in sys.modules
    ), "dnspython imported by the dnssec package — must be function-local (I11)"

"""Lazy-import guard for the federation-dnssec extra (Rev 6 I11).

Importing the node package — or the dnssec package itself — must NOT pull
dnspython (`dns` / `dns.*`) into ``sys.modules``. All dnspython imports are
function-local so a default node never loads the optional extra at import time.
"""

from __future__ import annotations

import importlib
import sys


def _purge_dns_modules() -> None:
    for name in [m for m in sys.modules if m == "dns" or m.startswith("dns.")]:
        del sys.modules[name]


def test_dnssec_extra_not_imported_on_default_node_load():
    _purge_dns_modules()
    importlib.import_module("stigmem_node")
    assert not any(
        m == "dns" or m.startswith("dns.") for m in sys.modules
    ), "dnspython imported at stigmem_node load — must be function-local (I11)"


def test_dnssec_package_import_does_not_pull_dnspython():
    _purge_dns_modules()
    importlib.import_module("stigmem_node.federation.dnssec")
    assert not any(
        m == "dns" or m.startswith("dns.") for m in sys.modules
    ), "dnspython imported by the dnssec package — must be function-local (I11)"

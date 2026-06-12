"""Compatibility alias for :mod:`stigmem_node.utility.net_util`."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

__all__ = ["assert_safe_url", "node_url_is_loopback", "resolve_pinned_address"]

if TYPE_CHECKING:
    from .utility.net_util import (
        assert_safe_url,
        node_url_is_loopback,
        resolve_pinned_address,
    )
else:
    from .utility import net_util as _impl

    sys.modules[__name__] = _impl

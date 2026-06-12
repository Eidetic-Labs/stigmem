"""stigmem-conformance: multi-backend behavioral conformance suite.

Run against a stigmem node (all backends)::

    python -m stigmem_conformance --backend sqlite
    python -m stigmem_conformance --backend libsql
    python -m stigmem_conformance --backend postgres --report report.md

The suite exercises every implemented StorageBackend against the same
behavioral contract and emits a Markdown report suitable for embedding
in operator documentation.
"""

__version__ = "0.9.0a11"

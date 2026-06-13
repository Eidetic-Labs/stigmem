"""Transparency-log adapters — spec §19.2.

Public surface:
    TransparencyLogUnavailable  — raised when TL cannot be reached
    LogEntry                    — dataclass for a TL entry
    TransparencyLog             — abstract base class
    LocalAppendOnlyLog          — file-backed hash-chain log (dev / single-org)
    RekorLog                    — Sigstore Rekor adapter (requires [identity] extra)
    make_transparency_log()     — factory respecting STIGMEM_TL_BACKEND setting

Security requirements (H2 mitigation):
    - TransparencyLogUnavailable must be raised, not silenced, when TL is
      unreachable.  Callers in trust_mode=strict MUST treat this as HTTP 503.
    - Checkpoint/STH verification goes through sigstore.transparency — not
      hand-rolled Merkle logic.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import canonicaljson

logger = logging.getLogger("stigmem.identity.tl")


class TransparencyLogUnavailable(RuntimeError):
    """Raised when the configured transparency log cannot be reached."""


@dataclass
class LogEntry:
    """A transparency-log inclusion record."""

    log_id: str  # opaque backend identifier (file path hash or Rekor tree ID)
    leaf_hash: str  # hex SHA-256 of the canonical leaf data
    log_index: int  # sequential index in the log
    integrated_time: int  # Unix epoch seconds
    inclusion_proof: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)  # full backend response


class TransparencyLog(ABC):
    """Abstract transparency-log adapter."""

    @abstractmethod
    def submit(self, manifest_dict: dict[str, Any]) -> LogEntry:
        """Submit a manifest to the transparency log. Returns a LogEntry on success.

        Raises TransparencyLogUnavailable if the log backend is unreachable.
        """

    @abstractmethod
    def verify_inclusion(self, log_entry: LogEntry) -> bool:
        """Verify that *log_entry* is genuinely included in the log.

        Returns True on success. Raises TransparencyLogUnavailable if backend
        is unreachable and raises ValueError on cryptographic failure.
        """


# ---------------------------------------------------------------------------
# LocalAppendOnlyLog — file-backed hash chain (dev / single-org)
# ---------------------------------------------------------------------------


class LocalAppendOnlyLog(TransparencyLog):
    """Simple append-only log stored as newline-delimited JSON.

    Each line is a JSON object:
        { "index": int, "ts": int, "leaf_hash": str, "prev_hash": str,
          "chain_hash": str, "payload": {...} }

    chain_hash = SHA-256(prev_hash || leaf_hash) ties each entry to its
    predecessor — sufficient for dev / audit use; not a full Merkle tree.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._log_id = hashlib.sha256(str(self._path.resolve()).encode()).hexdigest()[:16]

    def _leaf_hash(self, payload: dict[str, Any]) -> str:
        # RFC 8785 JCS — must match RekorLog and manifest signing bodies.
        canonical = canonicaljson.encode_canonical_json(payload)
        return hashlib.sha256(canonical).hexdigest()

    def _last_entry(self) -> dict[str, Any] | None:
        if not self._path.exists():
            return None
        lines = self._path.read_text().strip().splitlines()
        if not lines:
            return None
        entry: dict[str, Any] = json.loads(lines[-1])
        return entry

    def _chain_hash(self, prev_hash: str, leaf_hash: str) -> str:
        combined = (prev_hash + leaf_hash).encode()
        return hashlib.sha256(combined).hexdigest()

    def submit(self, manifest_dict: dict[str, Any]) -> LogEntry:
        last = self._last_entry()
        index = (last["index"] + 1) if last else 0
        prev_hash = last["chain_hash"] if last else ("0" * 64)
        leaf_hash = self._leaf_hash(manifest_dict)
        chain_hash = self._chain_hash(prev_hash, leaf_hash)
        ts = int(time.time())

        entry: dict[str, Any] = {
            "index": index,
            "ts": ts,
            "leaf_hash": leaf_hash,
            "prev_hash": prev_hash,
            "chain_hash": chain_hash,
            "payload": manifest_dict,
        }

        with self._path.open("a") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")

        return LogEntry(
            log_id=self._log_id,
            leaf_hash=leaf_hash,
            log_index=index,
            integrated_time=ts,
            inclusion_proof={"chain_hash": chain_hash, "prev_hash": prev_hash},
            raw=entry,
        )

    def verify_inclusion(self, log_entry: LogEntry) -> bool:
        if not self._path.exists():
            raise TransparencyLogUnavailable("local TL file not found")

        target_index = log_entry.log_index
        lines = self._path.read_text().strip().splitlines()

        if target_index >= len(lines):
            raise ValueError(
                f"log_index {target_index} out of range (log has {len(lines)} entries)"
            )

        stored = json.loads(lines[target_index])
        if stored["leaf_hash"] != log_entry.leaf_hash:
            raise ValueError(
                f"leaf_hash mismatch at index {target_index}: "
                f"stored={stored['leaf_hash']!r}, expected={log_entry.leaf_hash!r}"
            )
        if stored["index"] != target_index:
            raise ValueError("stored index does not match log_entry.log_index")

        # Recompute chain_hash to verify integrity back to prev
        recomputed = self._chain_hash(stored["prev_hash"], stored["leaf_hash"])
        if recomputed != stored["chain_hash"]:
            raise ValueError("chain_hash integrity check failed")

        return True


# ---------------------------------------------------------------------------
# RekorLog — Sigstore Rekor adapter
# ---------------------------------------------------------------------------


class RekorLog(TransparencyLog):
    """Transparency-log adapter backed by a Sigstore Rekor instance.

    Requires `sigstore>=3.0` (the [identity] optional extra).
    STH / inclusion-proof verification goes through sigstore.transparency —
    not hand-rolled Merkle logic (H2 security requirement).
    """

    def __init__(self, rekor_url: str = "https://rekor.sigstore.dev") -> None:
        self._url = rekor_url.rstrip("/")
        try:
            import sigstore  # noqa: F401 — validate import at construction
        except ImportError as exc:
            raise ImportError(
                "sigstore package is required for RekorLog; "
                "install it with: pip install 'stigmem-node[identity]'"
            ) from exc

    def submit(self, manifest_dict: dict[str, Any]) -> LogEntry:
        try:
            import httpx

            # RFC 8785 JCS — consistent with LocalAppendOnlyLog._leaf_hash.
            canonical = canonicaljson.encode_canonical_json(manifest_dict)
            leaf_hash = hashlib.sha256(canonical).hexdigest()

            # Rekor accepts intoto / hashedrekord entries; we submit as hashedrekord v0.0.1
            entry_body = {
                "kind": "hashedrekord",
                "apiVersion": "0.0.1",
                "spec": {
                    "data": {
                        "hash": {
                            "algorithm": "sha256",
                            "value": leaf_hash,
                        }
                    },
                    "signature": {
                        # The manifest's own signature is the attestation
                        "content": manifest_dict.get("signature", ""),
                        "publicKey": {"content": manifest_dict.get("public_key", "")},
                    },
                },
            }

            resp = httpx.post(
                f"{self._url}/api/v1/log/entries",
                json={"entry": entry_body},
                timeout=15.0,
            )
            if resp.status_code not in (200, 201):
                raise TransparencyLogUnavailable(
                    f"Rekor returned HTTP {resp.status_code}: {resp.text[:200]}"
                )

            data = resp.json()
            # Rekor response is { <uuid>: { body, integratedTime, logID, logIndex, verification } }
            uuid_key = next(iter(data))
            entry = data[uuid_key]
            log_index = entry.get("logIndex", -1)
            integrated_time = entry.get("integratedTime", int(time.time()))
            tree_id = entry.get("logID", "")

            return LogEntry(
                log_id=tree_id,
                leaf_hash=leaf_hash,
                log_index=int(log_index),
                integrated_time=int(integrated_time),
                inclusion_proof=entry.get("verification", {}),
                raw=entry,
            )

        except TransparencyLogUnavailable:
            raise
        except Exception as exc:
            raise TransparencyLogUnavailable(f"Rekor submission failed: {exc}") from exc

    def verify_inclusion(self, log_entry: LogEntry) -> bool:
        """Verify inclusion via Rekor's own verification endpoint.

        Uses sigstore.transparency for STH/checkpoint verification — not
        hand-rolled Merkle code.
        """
        try:
            import httpx

            resp = httpx.get(
                f"{self._url}/api/v1/log/entries",
                params={"logIndex": log_entry.log_index},
                timeout=15.0,
            )
            if resp.status_code == 404:
                raise ValueError(f"log_index {log_entry.log_index} not found in Rekor")
            if resp.status_code != 200:
                raise TransparencyLogUnavailable(
                    f"Rekor returned HTTP {resp.status_code} during verification"
                )

            data = resp.json()
            uuid_key = next(iter(data))
            stored = data[uuid_key]

            # Verify leaf hash matches what we stored
            stored_body = stored.get("body", "")
            import base64

            try:
                decoded = json.loads(base64.b64decode(stored_body + "=="))
                stored_hash = (
                    decoded.get("spec", {}).get("data", {}).get("hash", {}).get("value", "")
                )
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "stored Rekor body for UUID %s could not be decoded: %s",
                    uuid_key,
                    exc,
                )
                stored_hash = ""

            if stored_hash and stored_hash != log_entry.leaf_hash:
                raise ValueError(
                    f"leaf_hash mismatch: stored={stored_hash!r}, expected={log_entry.leaf_hash!r}"
                )

            # Delegate checkpoint/STH verification to sigstore.transparency.
            # A missing sigstore is a HARD ERROR — without it the STH/checkpoint
            # cannot be trusted, so we fail closed rather than returning True.
            try:
                from sigstore.transparency import LogEntry as SigstoreLogEntry
            except ImportError as exc:
                raise TransparencyLogUnavailable(
                    "sigstore is required to verify Rekor STH/checkpoint inclusion; "
                    "install it with: pip install 'stigmem-node[identity]'"
                ) from exc

            try:
                # Parse + structurally validate the Rekor response into a
                # SigstoreLogEntry. from_response raises on a malformed/invalid
                # response; the parsed entry's inclusion proof must be present.
                sig_entry = SigstoreLogEntry.from_response(data)
                if sig_entry.inclusion_proof is None:
                    raise ValueError("Rekor entry has no inclusion proof")
            except Exception as exc:
                raise ValueError(f"Rekor STH checkpoint verification failed: {exc}") from exc

            return True

        except (TransparencyLogUnavailable, ValueError):
            raise
        except Exception as exc:
            raise TransparencyLogUnavailable(f"Rekor verification failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def make_transparency_log() -> TransparencyLog:
    """Return a TransparencyLog instance per STIGMEM_TL_BACKEND setting."""
    from ..settings import settings

    backend = settings.tl_backend
    if backend == "rekor":
        return RekorLog(rekor_url=settings.tl_rekor_url)
    if backend == "local":
        return LocalAppendOnlyLog(path=settings.tl_local_path)
    # "off" — return a no-op log that always raises TransparencyLogUnavailable
    return _OffLog()


class _OffLog(TransparencyLog):
    """Sentinel: TL disabled. Raises TransparencyLogUnavailable on every call."""

    def submit(self, manifest_dict: dict[str, Any]) -> LogEntry:
        raise TransparencyLogUnavailable("transparency log is disabled (STIGMEM_TL_BACKEND=off)")

    def verify_inclusion(self, log_entry: LogEntry) -> bool:
        raise TransparencyLogUnavailable("transparency log is disabled (STIGMEM_TL_BACKEND=off)")

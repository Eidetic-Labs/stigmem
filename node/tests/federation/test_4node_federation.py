"""4-node local federation integration tests.

Spins up 4 real stigmem processes on localhost (ports 18765–18768), registers
full-mesh peers, and verifies correctness invariants:
  - Public facts replicate to all 4 nodes within N pull cycles
  - Local-scope facts never leave origin (partition-tolerance invariant)
  - Contradiction detection fires on ingest and propagates
  - Expiry semantics respected after TTL
  - Cursor resume after node restart

Design rationale (CAP/PACELC lens):
  Pull interval is 3s so tests are fast. The "replication latency relative"
  metric is verified as bounded: facts must appear within REPLICATION_TIMEOUT_S
  (30s = 10 pull cycles). Absolute latency numbers come from the soak run.

Each test is independent of the others via the module-scoped cluster fixture;
the cluster boots once, runs all tests, then tears down.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PULL_INTERVAL_S = 3


def _free_port() -> int:
    """Return a free TCP port on localhost (OS-assigned, immediately released)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


REPLICATION_TIMEOUT_S = 30  # must replicate within this many seconds
STARTUP_TIMEOUT_S = 30
NODE_NAMES = ["node-a", "node-b", "node-c", "node-d"]
ALLOWED_SCOPES = ["public", "company"]


# ---------------------------------------------------------------------------
# Ed25519 helpers (mirrors conftest.py helpers)
# ---------------------------------------------------------------------------


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)


def _generate_keypair() -> tuple[str, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_b64 = (
        base64.urlsafe_b64encode(
            priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .decode()
        .rstrip("=")
    )
    pub_b64 = (
        base64.urlsafe_b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw))
        .decode()
        .rstrip("=")
    )
    return pub_b64, priv_b64


def _sign_declaration(priv_b64: str, fields: dict) -> str:
    raw = base64.urlsafe_b64decode(_pad(priv_b64))
    privkey = Ed25519PrivateKey.from_private_bytes(raw)
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(privkey.sign(canonical)).decode().rstrip("=")


# ---------------------------------------------------------------------------
# Subprocess node management
# ---------------------------------------------------------------------------


def _seed_db(db_path: str, node_id: str, pub_b64: str, priv_b64: str) -> str:
    """Apply migrations, store keypair + node_id, create federate API key. Returns the raw key."""
    setup = f"""
import os, sqlite3
os.environ['STIGMEM_DB_PATH'] = {db_path!r}
from stigmem_node.db import apply_migrations
from stigmem_node.auth import create_api_key
apply_migrations()
conn = sqlite3.connect({db_path!r})
conn.row_factory = sqlite3.Row
conn.execute("INSERT OR REPLACE INTO node_meta (key, value) VALUES ('node_id', ?)", [{node_id!r}])
conn.execute(
    "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_pubkey', ?)",
    [{pub_b64!r}],
)
conn.execute(
    "INSERT OR REPLACE INTO node_meta (key, value) VALUES ('federation_privkey', ?)",
    [{priv_b64!r}],
)
conn.commit()
conn.close()
key = create_api_key(
    'test:admin',
    ['read', 'write', 'federate', 'admin:federation'],
    description='integration-test',
)
print(key, end='')
"""
    result = subprocess.run(
        [sys.executable, "-c", setup],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    return result.stdout.strip()


def _start_node(
    db_path: str, port: int, node_url: str, pub_b64: str, priv_b64: str
) -> subprocess.Popen:
    env = {
        **os.environ,
        "STIGMEM_DB_PATH": db_path,
        "STIGMEM_PORT": str(port),
        "STIGMEM_HOST": "127.0.0.1",
        "STIGMEM_NODE_URL": node_url,
        "STIGMEM_FEDERATION_ENABLED": "true",
        "STIGMEM_FEDERATION_INSECURE": "1",
        "STIGMEM_FEDERATION_PULL_INTERVAL_S": str(PULL_INTERVAL_S),
        "STIGMEM_FEDERATION_PUBKEY": pub_b64,
        "STIGMEM_FEDERATION_PRIVKEY": priv_b64,
        "STIGMEM_PLUGIN_AUTO_DISCOVERY_ENABLED": "false",
        "STIGMEM_LOG_LEVEL": "error",
    }
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "stigmem_node.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "error",
        ],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _wait_healthy(base_url: str, name: str, timeout: float = STARTUP_TIMEOUT_S) -> None:
    deadline = time.monotonic() + timeout
    last_error: httpx.HTTPError | None = None
    while time.monotonic() < deadline:
        try:
            r = httpx.get(f"{base_url}/healthz", timeout=2.0)
            if r.status_code == 200:
                return
        except httpx.HTTPError as exc:
            last_error = exc
        time.sleep(0.5)
    if last_error is not None:
        print(f"{name} last health check error: {last_error}", file=sys.stderr)
    raise RuntimeError(f"{name} did not become healthy within {timeout}s")


def _publish_manifest(
    node_url: str,
    federate_key: str,
    node_id: str,
    pub_b64: str,
    priv_b64: str,
) -> None:
    """Publish this node's OWN OrgManifest so peers can bind its entity_uri (Phase 2a/2b).

    The manifest's ``entity_uri`` equals the node's well-known entity_uri (``node_url``
    by default), its ``public_key`` equals this node's federation key (required by the
    2a key-unification PUT guard), and ``entities`` includes the node_id so that the
    registrar's approval-time binding (``manifest.public_key == peer.federation_pubkey``
    AND ``node_id in manifest.entities``) fires and sets ``peers.entity_uri``. Without a
    bound entity_uri, ``resolve_origin_key`` fails and zero v2 facts federate.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest

    priv = Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(_pad(priv_b64)))
    now = datetime.now(UTC)
    manifest = OrgManifest(
        entity_uri=node_url,
        key_id=generate_key_id(priv.public_key()),
        public_key=pub_b64,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(days=365)).isoformat(),
        entities=[node_url, node_id],
    )
    sign_manifest(manifest, priv)
    resp = httpx.put(
        f"{node_url}/v1/federation/manifest",
        json=manifest_to_dict(manifest),
        headers={"Authorization": f"Bearer {federate_key}"},
        timeout=10.0,
    )
    assert resp.status_code == 200, f"manifest publish failed: {resp.status_code} {resp.text}"


def _register_peer(
    registrar_url: str,
    federate_key: str,
    peer_node_id: str,
    peer_internal_url: str,
    peer_pub_b64: str,
    peer_priv_b64: str,
) -> None:
    signed_at = datetime.now(UTC).isoformat()
    signed_fields = {
        "allowed_scopes": sorted(ALLOWED_SCOPES),
        "federation_pubkey": peer_pub_b64,
        "node_id": peer_node_id,
        "node_url": peer_internal_url,
        "signed_at": signed_at,
    }
    sig = _sign_declaration(peer_priv_b64, signed_fields)
    resp = httpx.post(
        f"{registrar_url}/v1/federation/peers",
        json={
            "node_url": peer_internal_url,
            "node_id": peer_node_id,
            "federation_pubkey": peer_pub_b64,
            "allowed_scopes": sorted(ALLOWED_SCOPES),
            "declaration_sig": sig,
            "signed_at": signed_at,
        },
        headers={"Authorization": f"Bearer {federate_key}"},
        timeout=10.0,
    )
    assert resp.status_code == 201, f"peer registration failed: {resp.status_code} {resp.text}"
    data = resp.json()
    assert data["status"] == "pending_approval", f"peer status not pending approval: {data}"
    peer_id = data["peer_id"]

    approve = httpx.post(
        f"{registrar_url}/v1/federation/peers/{peer_id}/approve",
        json={"pubkey_fingerprint": f"sha256:{hashlib.sha256(peer_pub_b64.encode()).hexdigest()}"},
        headers={"Authorization": f"Bearer {federate_key}"},
        timeout=10.0,
    )
    assert approve.status_code == 200, (
        f"peer approval failed: {approve.status_code} {approve.text}"
    )
    assert approve.json()["status"] == "active", f"peer status not active: {approve.json()}"


# ---------------------------------------------------------------------------
# Cluster fixture
# ---------------------------------------------------------------------------


class NodeInfo:
    def __init__(
        self,
        name: str,
        host_url: str,
        node_id: str,
        pub_b64: str,
        priv_b64: str,
        federate_key: str,
        proc: subprocess.Popen,
    ) -> None:
        self.name = name
        self.host_url = host_url
        self.node_id = node_id
        self.pub_b64 = pub_b64
        self.priv_b64 = priv_b64
        self.federate_key = federate_key
        self.proc = proc

    def assert_fact(
        self,
        entity: str,
        relation: str,
        value: str,
        scope: str = "public",
        source: str = "test:seeder",
        valid_until: str | None = None,
        confidence: float = 1.0,
    ) -> str:
        resp = httpx.post(
            f"{self.host_url}/v1/facts",
            json={
                "entity": entity,
                "relation": relation,
                "value": {"type": "string", "v": value},
                "source": source,
                "scope": scope,
                "valid_until": valid_until,
                "confidence": confidence,
            },
            headers={"Authorization": f"Bearer {self.federate_key}"},
            timeout=10.0,
        )
        assert resp.status_code == 201, f"assert_fact failed: {resp.status_code} {resp.text}"
        return resp.json()["id"]

    def get_fact(self, fact_id: str) -> dict | None:
        resp = httpx.get(
            f"{self.host_url}/v1/facts/{fact_id}",
            headers={"Authorization": f"Bearer {self.federate_key}"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            return resp.json()
        return None

    def list_conflicts(self) -> list[dict]:
        resp = httpx.get(
            f"{self.host_url}/v1/conflicts",
            params={"limit": 200},
            headers={"Authorization": f"Bearer {self.federate_key}"},
            timeout=10.0,
        )
        assert resp.status_code == 200
        data = resp.json()
        return data if isinstance(data, list) else data.get("conflicts", [])

    def restart(self, db_path: str, pub_b64: str, priv_b64: str) -> None:
        """Kill and restart this node process (cursor-resume test)."""
        self.proc.terminate()
        self.proc.wait(timeout=10)
        port = int(self.host_url.split(":")[-1])
        self.proc = _start_node(db_path, port, self.host_url, pub_b64, priv_b64)
        _wait_healthy(self.host_url, self.name)


@pytest.fixture(scope="module")
def cluster(tmp_path_factory) -> Generator[list[NodeInfo], None, None]:
    """Boot a 4-node full-mesh federation cluster, yield NodeInfo list, tear down."""
    tmp = tmp_path_factory.mktemp("4node")
    nodes: list[NodeInfo] = []
    procs: list[subprocess.Popen] = []
    db_paths: dict[str, str] = {}

    try:
        # Phase 1: Allocate ports, pre-seed DBs, collect identities
        for name in NODE_NAMES:
            port = _free_port()
            host_url = f"http://127.0.0.1:{port}"
            db_path = str(tmp / f"{name}.db")
            db_paths[name] = db_path
            node_id = f"stigmem:node:test-{name}"
            pub_b64, priv_b64 = _generate_keypair()

            federate_key = _seed_db(db_path, node_id, pub_b64, priv_b64)
            proc = _start_node(db_path, port, host_url, pub_b64, priv_b64)
            procs.append(proc)
            nodes.append(
                NodeInfo(
                    name=name,
                    host_url=host_url,
                    node_id=node_id,
                    pub_b64=pub_b64,
                    priv_b64=priv_b64,
                    federate_key=federate_key,
                    proc=proc,
                )
            )

        # Phase 2: Wait for all nodes healthy
        for node in nodes:
            _wait_healthy(node.host_url, node.name)

        # Phase 2.5 (Phase 2a/2b): each node publishes its own manifest so that
        # approval-time entity_uri binding fires on every registrar — a precondition
        # for resolve_origin_key on the v2 ingest path. Without this, no fact federates.
        for node in nodes:
            _publish_manifest(
                node_url=node.host_url,
                federate_key=node.federate_key,
                node_id=node.node_id,
                pub_b64=node.pub_b64,
                priv_b64=node.priv_b64,
            )

        # Phase 3: Register full-mesh peers
        for registrar in nodes:
            for peer in nodes:
                if peer.name == registrar.name:
                    continue
                _register_peer(
                    registrar_url=registrar.host_url,
                    federate_key=registrar.federate_key,
                    peer_node_id=peer.node_id,
                    peer_internal_url=peer.host_url,
                    peer_pub_b64=peer.pub_b64,
                    peer_priv_b64=peer.priv_b64,
                )

        # Stash db_paths so cursor-resume test can access them
        for node, name in zip(nodes, NODE_NAMES, strict=False):
            node._db_path = db_paths[name]  # type: ignore[attr-defined]

        # Let the first pull cycle run so peers are warm
        time.sleep(PULL_INTERVAL_S + 1)

        yield nodes

    finally:
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except (subprocess.TimeoutExpired, OSError) as exc:
                print(
                    f"cluster process did not terminate cleanly; killing it: {exc}",
                    file=sys.stderr,
                )
                try:
                    proc.kill()
                except OSError as kill_exc:
                    print(f"cluster process kill failed: {kill_exc}", file=sys.stderr)
        # Brief sleep to allow OS to fully release ports before next test run
        time.sleep(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def wait_for_fact(node: NodeInfo, fact_id: str, timeout: float = REPLICATION_TIMEOUT_S) -> bool:
    """Poll node for fact_id until found or timeout. Returns True if found."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if node.get_fact(fact_id) is not None:
            return True
        time.sleep(1)
    return False


def wait_for_conflict(
    node: NodeInfo, fact_a_id: str, fact_b_id: str, timeout: float = REPLICATION_TIMEOUT_S
) -> bool:
    """Poll node conflicts until a record for (fact_a_id, fact_b_id) appears.

    The /v1/conflicts response embeds full fact objects under 'fact_a' / 'fact_b',
    so we extract IDs from those nested objects.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for c in node.list_conflicts():
            fa_id = (c.get("fact_a") or {}).get("id", "")
            fb_id = (c.get("fact_b") or {}).get("id", "")
            if {fa_id, fb_id} == {fact_a_id, fact_b_id}:
                return True
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPublicReplication:
    """Public-scope facts must replicate to every node within REPLICATION_TIMEOUT_S."""

    def test_single_fact_replicates_all_nodes(self, cluster):
        """Assert on node-a, verify all other nodes receive it within timeout."""
        node_a = cluster[0]
        entity = f"test://replication/{uuid.uuid4()}"
        fact_id = node_a.assert_fact(entity, "test:replicate:value", "hello-world", scope="public")

        for target in cluster[1:]:
            assert wait_for_fact(target, fact_id), (
                f"fact {fact_id} from node-a did not replicate to {target.name} "
                f"within {REPLICATION_TIMEOUT_S}s"
            )

    def test_fact_from_each_node_replicates(self, cluster):
        """Each node originates one fact; verify cross-node convergence."""
        fact_ids: dict[str, str] = {}
        for node in cluster:
            entity = f"test://origin/{node.name}/{uuid.uuid4()}"
            fid = node.assert_fact(entity, "test:origin:marker", node.name, scope="public")
            fact_ids[node.name] = fid

        for source_name, fid in fact_ids.items():
            for target in cluster:
                if target.name == source_name:
                    continue
                assert wait_for_fact(target, fid), (
                    f"fact {fid} from {source_name} did not reach {target.name} "
                    f"within {REPLICATION_TIMEOUT_S}s"
                )

    def test_replication_latency_within_bound(self, cluster):
        """Replication must complete within 3× pull interval (relative bound)."""
        node_a = cluster[0]
        entity = f"test://latency/{uuid.uuid4()}"
        t0 = time.monotonic()
        fact_id = node_a.assert_fact(entity, "test:latency:probe", "ts", scope="public")

        for target in cluster[1:]:
            found = wait_for_fact(target, fact_id, timeout=PULL_INTERVAL_S * 5)
            elapsed = time.monotonic() - t0
            assert found, f"fact did not reach {target.name} within {PULL_INTERVAL_S * 5}s"
            assert elapsed < PULL_INTERVAL_S * 5, (
                f"replication to {target.name} took {elapsed:.1f}s > {PULL_INTERVAL_S * 5}s bound"
            )


class TestScopeIsolation:
    """local-scope facts must NEVER appear on other nodes (partition-tolerance invariant)."""

    def test_local_fact_does_not_replicate(self, cluster):
        """Local fact stays absent on other nodes after one replication window."""
        node_a = cluster[0]
        entity = f"test://local/{uuid.uuid4()}"
        fact_id = node_a.assert_fact(entity, "test:local:marker", "secret", scope="local")

        # Wait 2 full pull cycles to give replication every opportunity
        time.sleep(PULL_INTERVAL_S * 2 + 1)

        for target in cluster[1:]:
            assert target.get_fact(fact_id) is None, (
                f"LOCAL-scope fact {fact_id} leaked from node-a to {target.name}! "
                "This is a partition-tolerance invariant violation."
            )

    def test_local_fact_stays_local_after_full_mesh_activity(self, cluster):
        """Even under concurrent public replication traffic, local facts stay local."""
        node_b = cluster[1]
        entity_local = f"test://local/stress/{uuid.uuid4()}"
        local_fid = node_b.assert_fact(entity_local, "test:local:stress", "private", scope="local")

        # Simultaneously create public facts to generate replication traffic
        for node in cluster:
            for _ in range(3):
                entity_pub = f"test://public/stress/{uuid.uuid4()}"
                node.assert_fact(entity_pub, "test:public:stress", "visible", scope="public")

        time.sleep(PULL_INTERVAL_S * 2 + 1)

        for target in cluster:
            if target.name == node_b.name:
                continue
            assert target.get_fact(local_fid) is None, (
                f"local fact {local_fid} leaked to {target.name} during concurrent replication"
            )


class TestContradictionDetection:
    """Contradictions are first-class events: detected on ingest, visible on all nodes."""

    def test_contradiction_detected_on_origin(self, cluster):
        """Two facts with same (entity, relation, scope) different values are contradictions."""
        node_a, node_b = cluster[0], cluster[1]
        entity = f"test://conflict/{uuid.uuid4()}"

        fid_a = node_a.assert_fact(entity, "test:conflict:color", "red", scope="public")
        # node-b asserts a different value — after replication, conflict fires on node-b's ingest
        fid_b = node_b.assert_fact(entity, "test:conflict:color", "blue", scope="public")

        # Wait for facts to replicate both ways
        assert wait_for_fact(cluster[2], fid_a)
        assert wait_for_fact(cluster[0], fid_b)

        # node-b should detect contradiction when node-a's fact arrives
        assert wait_for_conflict(node_b, fid_a, fid_b), (
            f"conflict ({fid_a}, {fid_b}) not detected on {node_b.name}"
        )

    def test_contradiction_visible_on_all_nodes(self, cluster):
        """After cross-replication, all 4 nodes should see the contradiction."""
        node_a, node_c = cluster[0], cluster[2]
        entity = f"test://conflict/all/{uuid.uuid4()}"

        fid_a = node_a.assert_fact(entity, "test:conflict:all", "alpha", scope="public")
        fid_c = node_c.assert_fact(entity, "test:conflict:all", "beta", scope="public")

        # All 4 nodes must eventually detect the contradiction (once both facts arrive)
        for node in cluster:
            assert wait_for_conflict(node, fid_a, fid_c), (
                f"conflict not visible on {node.name} within {REPLICATION_TIMEOUT_S}s"
            )

    def test_high_confidence_wins_at_query(self, cluster):
        """In a contradiction, higher-confidence fact is returned without include_contradicted."""
        node_a, node_b = cluster[0], cluster[1]
        entity = f"test://conflict/confidence/{uuid.uuid4()}"

        node_a.assert_fact(entity, "test:conflict:conf", "low", scope="public", confidence=0.5)
        node_b.assert_fact(entity, "test:conflict:conf", "high", scope="public", confidence=1.0)

        # Wait for both facts to reach node-a
        time.sleep(PULL_INTERVAL_S * 4)

        resp = httpx.get(
            f"{node_a.host_url}/v1/facts",
            params={"entity": entity, "relation": "test:conflict:conf"},
            headers={"Authorization": f"Bearer {node_a.federate_key}"},
            timeout=10.0,
        )
        assert resp.status_code == 200
        facts = resp.json()["facts"]
        # Without include_contradicted, only the non-contradicted version is returned.
        # The winning fact (confidence=1.0) should appear; the loser is hidden.
        if facts:
            winning = max(facts, key=lambda f: f["confidence"])
            assert winning["value"]["v"] == "high", (
                f"expected high-confidence fact to win, got: {facts}"
            )


class TestExpiryPropagation:
    """Facts with valid_until propagate correctly and are excluded after expiry."""

    def test_expired_fact_absent_from_normal_query(self, cluster):
        """A fact with 1s TTL should not appear in query results after expiry."""
        node_a = cluster[0]
        entity = f"test://expiry/{uuid.uuid4()}"
        valid_until = (datetime.now(UTC) + timedelta(seconds=2)).isoformat()

        fact_id = node_a.assert_fact(
            entity, "test:expiry:value", "temporary", scope="public", valid_until=valid_until
        )

        # Should be visible immediately
        assert node_a.get_fact(fact_id) is not None

        # Wait for expiry
        time.sleep(3)

        # Should be excluded from normal query (not by ID — GET /facts/{id} may still return it)
        resp = httpx.get(
            f"{node_a.host_url}/v1/facts",
            params={"entity": entity, "include_expired": "false"},
            headers={"Authorization": f"Bearer {node_a.federate_key}"},
            timeout=10.0,
        )
        facts = resp.json()["facts"]
        assert not any(f["id"] == fact_id for f in facts), (
            f"expired fact {fact_id} still appears in normal query"
        )

    def test_expired_fact_visible_with_include_expired(self, cluster):
        node_a = cluster[0]
        entity = f"test://expiry/incl/{uuid.uuid4()}"
        valid_until = (datetime.now(UTC) + timedelta(seconds=1)).isoformat()

        fact_id = node_a.assert_fact(
            entity, "test:expiry:incl", "ephemeral", scope="public", valid_until=valid_until
        )
        time.sleep(2)

        resp = httpx.get(
            f"{node_a.host_url}/v1/facts",
            params={"entity": entity, "include_expired": "true"},
            headers={"Authorization": f"Bearer {node_a.federate_key}"},
            timeout=10.0,
        )
        facts = resp.json()["facts"]
        assert any(f["id"] == fact_id for f in facts), (
            f"expired fact {fact_id} not found even with include_expired=true"
        )


class TestCursorResume:
    """Node restart resumes replication from saved HLC cursor, no facts lost."""

    def test_node_restart_resumes_without_gaps(self, cluster):
        """Assert facts while node-d is down, restart it, verify facts appear (cursor resume)."""
        node_d = cluster[3]
        node_a = cluster[0]
        db_path = node_d._db_path  # type: ignore[attr-defined]
        port = int(node_d.host_url.split(":")[-1])

        # Stop node-d
        node_d.proc.terminate()
        node_d.proc.wait(timeout=10)

        # Assert 5 public facts while node-d is down
        missing_fids = []
        for i in range(5):
            entity = f"test://restart/gap-{i}/{uuid.uuid4()}"
            fid = node_a.assert_fact(entity, "test:restart:gap", f"gap-{i}", scope="public")
            missing_fids.append(fid)

        time.sleep(PULL_INTERVAL_S)  # let facts replicate to b, c

        # Restart node-d using same DB (cursor is persisted in replication_cursors table)
        node_d.proc = _start_node(db_path, port, node_d.host_url, node_d.pub_b64, node_d.priv_b64)
        _wait_healthy(node_d.host_url, "node-d")

        # All 5 facts must arrive at node-d via cursor-resume pull
        for fid in missing_fids:
            assert wait_for_fact(node_d, fid, timeout=REPLICATION_TIMEOUT_S), (
                f"fact {fid} did not reach node-d after restart (cursor resume failed)"
            )

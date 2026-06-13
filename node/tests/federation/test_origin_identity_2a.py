from stigmem_node.db import db


def test_peers_has_entity_uri_column(client):
    """Migration 043 adds a nullable entity_uri column to peers."""
    with db() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(peers)").fetchall()]
    assert "entity_uri" in cols


def test_existing_peer_row_defaults_entity_uri_null(client):
    """Backward-compat: a peer inserted without entity_uri reads NULL (not '')."""
    with db() as conn:
        # NOTE: declaration_sig + signed_at are NOT NULL in the live peers schema
        # (migration 038). They are supplied here only to satisfy those constraints;
        # entity_uri is deliberately omitted to exercise the NULL-default backward-compat path.
        conn.execute(
            "INSERT INTO peers "
            "(id, node_id, node_url, federation_pubkey, allowed_scopes, status, "
            "declaration_sig, signed_at) "
            "VALUES ('p1', 'stigmem:node:n1', 'http://x', 'PUB', '[]', 'active', "
            "'SIG', '2026-01-01T00:00:00Z')"
        )
        conn.commit()
        row = conn.execute("SELECT entity_uri FROM peers WHERE id='p1'").fetchone()
    assert row["entity_uri"] is None


def test_wellknown_publishes_entity_uri(fed_node):
    """The node advertises its own org entity_uri so peers can record+verify it.

    The entity_uri block is guarded by ``if settings.federation_enabled:`` and the
    default ``client`` fixture leaves federation disabled. We use the suite's existing
    ``fed_node`` fixture (conftest.py) — same mechanism test_well_known.py uses for the
    enabled-node case — which patches a federation_enabled=True Settings via _patch_settings.
    """
    body = fed_node.client.get("/.well-known/stigmem").json()
    assert "entity_uri" in body
    assert body["entity_uri"]  # non-empty (defaults to node_url when unset)


def test_get_node_entity_uri_defaults_to_node_url(monkeypatch):
    """Contract: falls back to node_url when entity_uri is empty, else returns entity_uri.

    Pins the actual field returned (non-tautological): the assertion fails if the
    helper returned the wrong setting.
    """
    from stigmem_node.db import get_node_entity_uri
    from stigmem_node.settings import settings

    # Empty entity_uri -> node_url
    monkeypatch.setattr(settings, "entity_uri", "")
    monkeypatch.setattr(settings, "node_url", "http://fallback-node")
    assert get_node_entity_uri() == "http://fallback-node"

    # Explicit entity_uri -> that value (distinct from node_url so it can't pass by accident)
    monkeypatch.setattr(settings, "entity_uri", "https://explicit.example")
    assert get_node_entity_uri() == "https://explicit.example"


def _store_peer_with_manifest(node_id, entity_uri, pub_b64, priv):
    """Insert an active peer bound to entity_uri and store its self-signed manifest."""
    from stigmem_node.db import db
    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest
    from stigmem_node.identity.trust_store import store_peer_manifest

    key_id = generate_key_id(priv.public_key())
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=key_id,
        public_key=pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(m, priv)
    store_peer_manifest(entity_uri, m, None, trust_mode="relaxed")
    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, entity_uri, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                node_id,
                node_id,
                "http://x",
                pub_b64,
                "[]",
                "active",
                entity_uri,
                "SIG",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()


def test_resolve_origin_key_returns_manifest_pubkey(client):
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from stigmem_node.federation.origin_identity import resolve_origin_key

    priv = Ed25519PrivateKey.generate()
    pub_b64 = (
        base64.urlsafe_b64encode(
            priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    _store_peer_with_manifest("stigmem:node:o1", "https://o1.example", pub_b64, priv)

    keys = resolve_origin_key("stigmem:node:o1")
    assert pub_b64 in keys


def _store_peer_with_manifest_obj(node_id, entity_uri, manifest):
    """Insert an active peer bound to entity_uri and store a pre-built manifest.

    Variant of _store_peer_with_manifest that takes an already-signed OrgManifest
    (e.g. one carrying rotation_events) instead of building a fresh single-key one.
    The peers.federation_pubkey is set to the manifest's current public_key so the
    row is internally consistent.
    """
    from stigmem_node.db import db
    from stigmem_node.identity.trust_store import store_peer_manifest

    store_peer_manifest(entity_uri, manifest, None, trust_mode="relaxed")
    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, entity_uri, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                node_id,
                node_id,
                "http://x",
                manifest.public_key,
                "[]",
                "active",
                entity_uri,
                "SIG",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()


def test_resolve_origin_key_returns_current_and_rotation_window_prior_key(client):
    """Dual-trust: resolve_origin_key returns BOTH the current key AND the prior key
    inside the most-recent rotation window (§22.2).

    Builds a real, valid rotation chain via rotate_key(dry_run=True): the resulting
    manifest is self-signed by the NEW key and its last rotation_event carries
    previous_public_key = the OLD key. The manifest must still pass verify_manifest.
    """
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from stigmem_node.federation.origin_identity import resolve_origin_key
    from stigmem_node.identity.key_rotation import generate_key_id, rotate_key
    from stigmem_node.identity.manifest import OrgManifest, sign_manifest, verify_manifest

    node_id = "stigmem:node:rot"
    entity_uri = "https://rot.example"

    # --- old (retiring) keypair + its signed manifest ---
    old_priv = Ed25519PrivateKey.generate()
    old_pub_b64 = (
        base64.urlsafe_b64encode(
            old_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        )
        .decode()
        .rstrip("=")
    )
    old_manifest = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(old_priv.public_key()),
        public_key=old_pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(old_manifest, old_priv)

    # --- rotate to a new key (dry_run: no TL writes); produces a valid chained manifest ---
    result = rotate_key(
        entity_uri,
        old_manifest,
        old_priv,
        manifest_validity_days=300,  # well within strict 365-day window
        dry_run=True,
    )
    new_manifest = result.new_manifest

    # Sanity: the chain is well-formed — last event carries the retiring key as
    # previous_public_key, and the manifest self-verifies.
    assert new_manifest.rotation_events, "rotate_key must append a rotation event"
    assert new_manifest.rotation_events[-1].previous_public_key == old_pub_b64
    assert verify_manifest(new_manifest, trust_mode="relaxed") is True

    _store_peer_with_manifest_obj(node_id, entity_uri, new_manifest)

    keys = resolve_origin_key(node_id)
    # BOTH the current key and the rotation-window prior key are accepted.
    assert new_manifest.public_key in keys
    assert old_pub_b64 in keys
    assert keys == {new_manifest.public_key, old_pub_b64}


def test_resolve_origin_key_unbound_peer_fails_closed(client):
    import pytest

    from stigmem_node.db import db
    from stigmem_node.federation.origin_identity import (
        OriginIdentityError,
        resolve_origin_key,
    )

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            (
                "p2",
                "stigmem:node:o2",
                "http://x",
                "PUB",
                "[]",
                "active",
                "SIG",
                "2026-01-01T00:00:00Z",
            ),
        )
        conn.commit()
    with pytest.raises(OriginIdentityError):
        resolve_origin_key("stigmem:node:o2")  # entity_uri is NULL -> fail closed


# ---------------------------------------------------------------------------
# Task 5 — bind + verify peers.entity_uri at registration (fail-open to NULL)
# ---------------------------------------------------------------------------


def _build_declaration(node_id, node_url, pub_b64, priv_b64, scopes, signed_at):
    """Build a valid PeerDeclaration body (mirrors test_peer_registration.py)."""
    from conftest import sign_declaration

    fields_to_sign = {
        "allowed_scopes": scopes,
        "federation_pubkey": pub_b64,
        "node_id": node_id,
        "node_url": node_url,
        "signed_at": signed_at,
    }
    sig = sign_declaration(priv_b64, fields_to_sign)
    return {
        "node_id": node_id,
        "node_url": node_url,
        "federation_pubkey": pub_b64,
        "allowed_scopes": scopes,
        "declaration_sig": sig,
        "signed_at": signed_at,
    }


def _mock_well_known(monkeypatch, peer_pub, entity_uri, manifest_json=None):
    """Stub BOTH well-known fetches offline.

    Registration hits ``{node_url}/.well-known/stigmem`` → {federation_pubkey, entity_uri}.
    Approval (``_check_tl_inclusion_for_peer``) hits
    ``{node_url}/.well-known/stigmem-manifest.json`` → the peer's manifest JSON. Both
    fetches go through ``_federation_impl.httpx.AsyncClient``, so one mock handles both;
    the response is selected by the requested URL. When *manifest_json* is None the
    manifest path 404s (mirrors a peer that never published its manifest).
    """
    import httpx as _httpx

    class _MockAsyncClient:
        def __init__(self, **_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def get(self, url, *args, **kwargs):
            if url.endswith("/.well-known/stigmem-manifest.json"):
                if manifest_json is None:
                    return _httpx.Response(404)
                return _httpx.Response(200, json=manifest_json)
            return _httpx.Response(
                200,
                json={"federation_pubkey": peer_pub, "entity_uri": entity_uri},
            )

    monkeypatch.setattr(
        "stigmem_node.routes._federation_impl.httpx.AsyncClient",
        _MockAsyncClient,
    )
    # The approval-time fetch now DNS-PINS the URL (F-SSRF-3, resolve_pinned_address),
    # which does a real DNS lookup (socket.getaddrinfo) of the synthetic test hostname and
    # would raise before the mocked client is reached. We can't let the real pin run, but a
    # bare no-op would silently let ANY URL through and stop proving the pin is even invoked.
    # Instead, install a stub that ASSERTS the pin was called on the peer's node_url with the
    # expected scheme allowlist — so the test still verifies the SSRF pin runs on the right
    # input — and returns a harmless pinned literal that preserves the path the mock matches
    # on. The pin's own block/allow logic stays covered by tests/utility/test_net_util.py.
    from urllib.parse import urlparse as _urlparse

    def _asserting_pin(url, *, allow_schemes=frozenset({"https"})):
        parsed = _urlparse(url)
        # _check_tl_inclusion_for_peer must call this on the peer's node_url, and the
        # production call passes http+https as the allowed schemes.
        assert parsed.scheme in allow_schemes, f"unexpected scheme {parsed.scheme!r} for {url!r}"
        assert allow_schemes == frozenset({"https", "http"}), (
            f"SSRF pin invoked with unexpected allow_schemes {allow_schemes!r}"
        )
        assert parsed.hostname, f"SSRF pin invoked on URL with no host: {url!r}"
        # A genuinely-global literal; _build_pinned_request preserves the original path.
        return "8.8.8.8"

    monkeypatch.setattr(
        "stigmem_node.routes._federation_impl.resolve_pinned_address",
        _asserting_pin,
    )


def _build_peer_manifest_json(entity_uri, node_id, manifest_pub_b64, manifest_priv_b64):
    """Build a self-signed peer manifest dict (what the peer serves at its well-known path)."""
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from stigmem_node.identity.key_rotation import generate_key_id
    from stigmem_node.identity.manifest import OrgManifest, manifest_to_dict, sign_manifest

    raw = base64.urlsafe_b64decode(manifest_priv_b64 + "=" * (-len(manifest_priv_b64) % 4))
    priv = Ed25519PrivateKey.from_private_bytes(raw)
    m = OrgManifest(
        entity_uri=entity_uri,
        key_id=generate_key_id(priv.public_key()),
        public_key=manifest_pub_b64,
        issued_at="2026-01-01T00:00:00Z",
        expires_at="2026-12-01T00:00:00Z",
        entities=[entity_uri, node_id],
    )
    sign_manifest(m, priv)
    return manifest_to_dict(m)


def _register_and_approve(fed_node, node_id, node_url, peer_pub, peer_priv):
    """Register a peer then approve it (the approval triggers _check_tl_inclusion_for_peer).

    TestClient runs the approval background task synchronously before returning, so the
    entity_uri binding has executed by the time the approve POST returns.
    """
    from stigmem_node.auth import create_api_key
    from stigmem_node.routes._federation_impl import peer_pubkey_fingerprint

    body = _build_declaration(
        node_id, node_url, peer_pub, peer_priv, ["public"], "2026-05-02T00:00:00Z"
    )
    r = fed_node.client.post(
        "/v1/federation/peers",
        json=body,
        headers={"Authorization": f"Bearer {fed_node.federate_key}"},
    )
    assert r.status_code == 201, r.text
    assert r.json()["status"] == "pending_approval", r.text
    peer_id = r.json()["peer_id"]

    admin_key = create_api_key("agent:federation-admin", ["admin:federation"])
    approve = fed_node.client.post(
        f"/v1/federation/peers/{peer_id}/approve",
        json={"pubkey_fingerprint": peer_pubkey_fingerprint(peer_pub)},
        headers={"Authorization": f"Bearer {admin_key}"},
    )
    assert approve.status_code == 200, approve.text
    assert approve.json()["status"] == "active"
    return peer_id


def test_approval_binds_entity_uri_when_manifest_consistent(fed_node, monkeypatch):
    """Manifest fetched at approval proves same key controls node_id AND entity_uri -> bound.

    Phase 2a Task 8: binding moved from registration to approval, where the peer manifest is
    actually fetched + verified + stored (_check_tl_inclusion_for_peer). No manifest is
    pre-stored — the approval-time fetch supplies it.
    """
    import uuid

    from conftest import generate_keypair

    from stigmem_node.db import db as node_db

    peer_pub, peer_priv = generate_keypair()
    node_id = f"stigmem://test-bind-{uuid.uuid4()}"
    node_url = "http://test-bind"
    entity_uri = f"https://bind-{uuid.uuid4()}.example"

    # Manifest served at the peer's well-known path: public_key == peer_pub AND entities
    # includes node_id (consistent). Signed by peer_priv so verify_manifest passes.
    manifest_json = _build_peer_manifest_json(entity_uri, node_id, peer_pub, peer_priv)
    _mock_well_known(monkeypatch, peer_pub, entity_uri, manifest_json=manifest_json)

    _register_and_approve(fed_node, node_id, node_url, peer_pub, peer_priv)

    with node_db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
    assert row is not None
    assert row["entity_uri"] == entity_uri


def test_approval_leaves_entity_uri_null_when_manifest_key_mismatch(fed_node, monkeypatch):
    """Manifest signed by a DIFFERENT key than the peer's -> entity_uri stays NULL (fail-open)."""
    import uuid

    from conftest import generate_keypair

    from stigmem_node.db import db as node_db

    peer_pub, peer_priv = generate_keypair()
    other_pub, other_priv = generate_keypair()  # distinct key controls the manifest
    node_id = f"stigmem://test-mismatch-{uuid.uuid4()}"
    node_url = "http://test-mismatch"
    entity_uri = f"https://mismatch-{uuid.uuid4()}.example"

    # Manifest has public_key=other_pub != peer_pub. (Self-signed by other_priv so
    # verify_manifest passes; the binding still fails on the public_key != peer_pub check.)
    manifest_json = _build_peer_manifest_json(entity_uri, node_id, other_pub, other_priv)
    _mock_well_known(monkeypatch, peer_pub, entity_uri, manifest_json=manifest_json)

    _register_and_approve(fed_node, node_id, node_url, peer_pub, peer_priv)

    with node_db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
    assert row is not None
    assert row["entity_uri"] is None


def test_fresh_peer_binds_entity_uri_end_to_end_without_prestored_manifest(fed_node, monkeypatch):
    """Regression guard for the whole bug: a fresh peer binds entity_uri with NO pre-stored
    manifest, the manifest gets STORED at approval, and resolve_origin_key resolves the chain.

    This exercises the production flow end-to-end: register -> approve ->
    _check_tl_inclusion_for_peer fetches the peer manifest from
    /.well-known/stigmem-manifest.json, verifies + stores it, then binds peers.entity_uri.
    """
    import uuid

    from conftest import generate_keypair

    from stigmem_node.db import db as node_db
    from stigmem_node.federation.origin_identity import resolve_origin_key
    from stigmem_node.identity.trust_store import get_peer_manifest

    peer_pub, peer_priv = generate_keypair()
    node_id = f"stigmem://test-e2e-{uuid.uuid4()}"
    node_url = "http://test-e2e"
    entity_uri = f"https://e2e-{uuid.uuid4()}.example"

    # NO pre-stored manifest. The approval-time fetch is the only source.
    manifest_json = _build_peer_manifest_json(entity_uri, node_id, peer_pub, peer_priv)
    _mock_well_known(monkeypatch, peer_pub, entity_uri, manifest_json=manifest_json)

    # Sanity: manifest is genuinely absent before approval.
    assert get_peer_manifest(entity_uri, trust_mode="relaxed") is None

    _register_and_approve(fed_node, node_id, node_url, peer_pub, peer_priv)

    # (1) the manifest got STORED during approval
    stored = get_peer_manifest(entity_uri, trust_mode="relaxed")
    assert stored is not None
    assert stored.public_key == peer_pub

    # (2) peers.entity_uri bound to the manifest entity_uri
    with node_db() as conn:
        row = conn.execute(
            "SELECT entity_uri FROM peers WHERE node_id = ?", (node_id,)
        ).fetchone()
    assert row is not None
    assert row["entity_uri"] == entity_uri

    # (3) the full origin-identity chain now resolves for the fresh peer
    keys = resolve_origin_key(node_id)
    assert peer_pub in keys


def _fed_admin_key() -> str:
    """Mint an admin:federation key so the PATCH route's permission check is satisfied.

    The ``client`` fixture runs with ``auth_required=False`` (its default identity is
    ``_ANON`` with read/write/federate only), but ``patch_peer_policy`` gates on
    ``can_admin_federation()``. ``resolve_identity`` still resolves a real key from the
    Authorization header even in non-required mode, so we pass this key to authorize —
    matching the pattern in test_peer_policy_patch.py. The route's permission check is
    NOT weakened.
    """
    from stigmem_node.auth import create_api_key

    return create_api_key("agent:federation-admin", ["admin:federation", "federate"])


def test_same_domain_rejected_without_verified_entity_uri(client):
    """Binding trust_tier=same_domain to a peer with NULL entity_uri is rejected (422)."""
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            ("pNT", "stigmem:node:nt", "http://x", "PUB", "[]", "active", "SIG",
             "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pNT",
        json={"trust_tier": "same_domain"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 422
    assert "entity_uri" in resp.json()["detail"].lower()


def test_same_domain_allowed_with_verified_entity_uri(client):
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, entity_uri, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?,?)",
            ("pV", "stigmem:node:v", "http://x", "PUB", "[]", "active", "https://v.example",
             "SIG", "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pV",
        json={"trust_tier": "same_domain"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200


def test_cross_org_tier_allowed_without_entity_uri(client):
    """cross_org (the default tier) must NOT require entity_uri — only same_domain is gated."""
    from stigmem_node.db import db

    with db() as conn:
        conn.execute(
            "INSERT INTO peers (id, node_id, node_url, federation_pubkey, allowed_scopes, "
            "status, declaration_sig, signed_at) VALUES (?,?,?,?,?,?,?,?)",
            ("pCO", "stigmem:node:co", "http://x", "PUB", "[]", "active", "SIG",
             "2026-01-01T00:00:00Z"),
        )
        conn.commit()
    resp = client.patch(
        "/v1/federation/peers/pCO",
        json={"trust_tier": "cross_org"},
        headers={"Authorization": f"Bearer {_fed_admin_key()}"},
    )
    assert resp.status_code == 200

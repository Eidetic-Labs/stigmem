"""
Stigmem v1.0 conformance suite.

Loads machine-readable test vectors from data/conformance/v1.0/0*.json and
runs each against a fresh in-process test node. Any regression fails CI.

Vector file schema:
  { "spec_section": "...", "title": "...", "vectors": [ <Vector>, ... ] }

Vector fields:
  id, description, method, path, body?,
  expected_status (or expected_status_in),
  expected_body_contains?, expected_body_has_keys?,
  expected_nested?, expected_body_list_contains?,
  expected_body_value_in?,
  expected_members_contain_role?, expected_response_is_list?,
  requires_setup?,   # id of another vector that must run first (same DB)
  requires_garden?,  # slug of garden to create before this test
  requires_auth?     # bool: requires auth-enabled client (skipped for now)

Adding a new spec feature? Add at least one vector to data/conformance/v1.0/
and ensure the test runner handles any new assertion types.
"""

from __future__ import annotations

import importlib as _importlib
import json
import logging
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import stigmem_node.auth as auth_mod

create_api_key = auth_mod.create_api_key

logger = logging.getLogger(__name__)


_REPO_ROOT = Path(__file__).resolve().parents[3]
_VECTOR_DIR = _REPO_ROOT / "data" / "conformance" / "v1.0"


# ---------------------------------------------------------------------------
# Load vectors — only from the numbered 0*.json files (canonical set)
# ---------------------------------------------------------------------------


def _load_file_groups() -> list[tuple[str, list[dict[str, Any]]]]:
    """Return [(filename, [vector, ...]), ...] for each numbered vector file."""
    groups: list[tuple[str, list[dict[str, Any]]]] = []
    for path in sorted(_VECTOR_DIR.glob("0*.json")):
        with path.open() as f:
            data = json.load(f)
        groups.append((path.name, data.get("vectors", [])))
    return groups


_GROUPS = _load_file_groups()

# Build a flat index: vector_id -> vector (for setup lookups)
_VECTOR_INDEX: dict[str, dict[str, Any]] = {}
for _fname, _vecs in _GROUPS:
    for _v in _vecs:
        _VECTOR_INDEX[_v["id"]] = _v


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------


def _assert_contains(actual: Any, expected: Any, *, path: str) -> None:
    """Recursively assert that actual contains the structure in expected."""
    if isinstance(expected, dict):
        assert isinstance(actual, dict), f"{path}: expected dict, got {type(actual)}"
        for k, v in expected.items():
            assert k in actual, f"{path}: missing key '{k}'"
            _assert_contains(actual[k], v, path=f"{path}.{k}")
    elif isinstance(expected, list):
        assert isinstance(actual, list), f"{path}: expected list, got {type(actual)}"
        for item in expected:
            if isinstance(item, dict):
                match = False
                for candidate in actual:
                    try:
                        _assert_contains(candidate, item, path=f"{path}[]")
                    except AssertionError:
                        continue
                    match = True
                    break
                assert match, f"{path}: list missing item matching {item!r}"
            else:
                assert item in actual, f"{path}: list missing item {item!r}"
    else:
        assert actual == expected, f"{path}: got {actual!r}, expected {expected!r}"


# ---------------------------------------------------------------------------
# Request execution
# ---------------------------------------------------------------------------


def _do_request(client: TestClient, vector: dict[str, Any]) -> Any:
    method = vector["method"].lower()
    path = vector["path"]
    body = vector.get("body")
    kwargs: dict[str, Any] = {}
    if body is not None:
        kwargs["json"] = body
    return getattr(client, method)(path, **kwargs)


def _run_setup_chain(
    client: TestClient,
    vector: dict[str, Any],
    *,
    seen: set[str] | None = None,
) -> None:
    if seen is None:
        seen = set()
    prereq_id = vector.get("requires_setup")
    if not prereq_id or prereq_id in seen:
        return
    prereq = _VECTOR_INDEX.get(prereq_id)
    if prereq is None:
        return
    _run_setup_chain(client, prereq, seen=seen)
    if prereq_id not in seen:
        seen.add(prereq_id)
        resp = _do_request(client, prereq)
        assert resp.status_code < 300, (
            f"Setup vector '{prereq_id}' failed: HTTP {resp.status_code}: {resp.text}"
        )


def _setup_garden(client: TestClient, slug: str) -> None:
    resp = client.post("/v1/gardens", json={"slug": slug, "name": slug, "scope": "local"})
    assert resp.status_code in (201, 409), (
        f"Garden setup for '{slug}' failed: {resp.status_code}: {resp.text}"
    )


# ---------------------------------------------------------------------------
# Parametrised tests — one per file group to allow shared setup within a file
# ---------------------------------------------------------------------------


def _make_vectors_for_file(fname: str, vectors: list[dict[str, Any]]) -> list[Any]:
    return [(fname, v) for v in vectors]


_ALL_PARAMS: list[tuple[str, dict[str, Any]]] = []
for _fname, _vecs in _GROUPS:
    _ALL_PARAMS.extend([(f"{_fname}::{v['id']}", v) for v in _vecs])


def _assert_status(resp: Any, vector: dict[str, Any], ctx: str) -> None:
    expected_status = vector.get("expected_status")
    status_in = vector.get("expected_status_in")
    if expected_status is not None:
        assert resp.status_code == expected_status, (
            f"{ctx}: expected HTTP {expected_status}, got {resp.status_code}. Body: {resp.text}"
        )
    elif status_in is not None:
        assert resp.status_code in status_in, (
            f"{ctx}: expected HTTP in {status_in}, got {resp.status_code}. Body: {resp.text}"
        )


def _assert_nested(body: dict[str, Any], expectations: dict[str, Any], ctx: str) -> None:
    for dotted_path, expected_val in expectations.items():
        current: Any = body
        for part in dotted_path.split("."):
            assert isinstance(current, dict) and part in current, (
                f"{ctx}: path '{dotted_path}' — missing key '{part}'"
            )
            current = current[part]
        assert current == expected_val, (
            f"{ctx}: {dotted_path} = {current!r}, expected {expected_val!r}"
        )


def _assert_list_contains(
    body: dict[str, Any], list_expectations: dict[str, Any], ctx: str
) -> None:
    for list_key, expected_item in list_expectations.items():
        assert list_key in body, f"{ctx}: missing list key '{list_key}'"
        actual_list = body[list_key]
        assert isinstance(actual_list, list), f"{ctx}: '{list_key}' is not a list"
        if isinstance(expected_item, dict):
            assert any(all(a.get(k) == v for k, v in expected_item.items()) for a in actual_list), (
                f"{ctx}: list '{list_key}' missing item matching {expected_item!r}"
            )
        else:
            assert expected_item in actual_list, (
                f"{ctx}: '{expected_item}' not in {list_key}: {actual_list!r}"
            )


def _assert_body_expectations(body: dict[str, Any], vector: dict[str, Any], ctx: str) -> None:
    """Apply every body-shape expectation for a happy-path response."""
    for key in vector.get("expected_body_has_keys", []):
        assert key in body, f"{ctx}: response missing required key '{key}'"

    if "expected_body_contains" in vector:
        _assert_contains(body, vector["expected_body_contains"], path=ctx)

    _assert_nested(body, vector.get("expected_nested", {}), ctx)
    _assert_list_contains(body, vector.get("expected_body_list_contains", {}), ctx)

    if "expected_body_value_in" in vector:
        for field, allowed in vector["expected_body_value_in"].items():
            assert field in body, f"{ctx}: missing field '{field}'"
            assert body[field] in allowed, (
                f"{ctx}: {field} = {body[field]!r}, expected one of {allowed!r}"
            )

    if vector.get("expected_response_is_list"):
        assert isinstance(body, list), f"{ctx}: expected list response, got {type(body)}"

    if "expected_members_contain_role" in vector:
        expected_role = vector["expected_members_contain_role"]
        members = body.get("members", [])
        assert any(m.get("role") == expected_role for m in members), (
            f"{ctx}: no member with role '{expected_role}' in {members!r}"
        )


@pytest.mark.parametrize(
    "vector",
    [p[1] for p in _ALL_PARAMS],
    ids=[p[0] for p in _ALL_PARAMS],
)
def test_conformance_vector(client: TestClient, vector: dict[str, Any]) -> None:
    vec_id = vector["id"]
    ctx = f"[{vec_id}] {vector.get('description', '')}"

    # Skip auth-requiring vectors (auth tests are covered by test_oidc.py etc.)
    if vector.get("requires_auth"):
        pytest.skip(f"{ctx}: skipped (requires_auth — covered by dedicated auth tests)")

    garden_slug = vector.get("requires_garden")
    if garden_slug:
        _setup_garden(client, garden_slug)

    _run_setup_chain(client, vector)

    resp = _do_request(client, vector)
    try:
        body = resp.json()
    except ValueError as exc:
        logger.debug("%s: response body is not JSON: %s", ctx, exc)
        body = {}

    _assert_status(resp, vector, ctx)

    # Short-circuit on error responses
    if resp.status_code >= 400:
        return

    _assert_body_expectations(body, vector, ctx)


# ---------------------------------------------------------------------------
# §5.19–§5.20, §17.3 — Garden ACL with distinct identities (auth required)
# ---------------------------------------------------------------------------

_PATCHABLE_MODULES = [
    "stigmem_node.routes.facts",
    "stigmem_node.routes.gardens",
    "stigmem_node.routes.audit",
    "stigmem_node.federation_pull",
    "stigmem_node.peer_token",
    "stigmem_node.federation_ingest",
    "stigmem_node.routes.federation",
    "stigmem_node.decay",
    "stigmem_node.routes.decay",
    "stigmem_node.routes.lint",
    "stigmem_node.routes.synthesize",
]


def _make_authed_node(
    tmp_path: object,
    suffix: str = "",
    attestation_mode: str = "warn",
) -> tuple[TestClient, Any, list, str]:
    import stigmem_node.auth as am

    create_api_key = am.create_api_key
    import stigmem_node.db as dm

    apply_migrations = dm.apply_migrations
    import stigmem_node.routes.wellknown as wk
    import stigmem_node.settings as sm
    from stigmem_node.main import create_app

    db_file = str(tmp_path) + f"/acl{suffix}.db"
    apply_migrations(db_path=db_file)
    original = sm.settings
    ts = sm.Settings(
        db_path=db_file,
        auth_required=True,
        node_url="http://testnode",
        source_attestation_mode=attestation_mode,
    )
    sm.settings = ts
    am.settings = ts
    dm.settings = ts
    wk.settings = ts

    patched: list[Any] = []
    for name in _PATCHABLE_MODULES:
        try:
            mod = _importlib.import_module(name)
            if hasattr(mod, "settings"):
                mod.settings = ts
                patched.append((mod, "settings", original))
        except ImportError as exc:
            logger.debug("patchable module %s is unavailable in this test process: %s", name, exc)
            continue

    # facts.py also holds a direct module-level binding `_settings` that bypasses
    # the module-attribute patch above; we must replace it explicitly.
    import stigmem_node.routes.facts as _facts_mod

    _facts_orig = _facts_mod._settings
    _facts_mod._settings = ts
    patched.append((_facts_mod, "_settings", _facts_orig))

    raw_key = create_api_key("stigmem://testnode/agent/admin", ["read", "write"])
    app = create_app()
    c = TestClient(app, raise_server_exceptions=True)
    c.__enter__()
    return c, original, patched, raw_key


def _restore_authed(original: Any, patched: list) -> None:
    import stigmem_node.auth as am
    import stigmem_node.db as dm
    import stigmem_node.routes.wellknown as wk
    import stigmem_node.settings as sm

    sm.settings = original
    am.settings = original
    dm.settings = original
    wk.settings = original
    for entry in patched:
        mod, attr_name, orig_val = entry
        setattr(mod, attr_name, orig_val)


class TestGardenFactACLConformance:
    """§5.19–§5.20, §17.3 — non-member 403 enforcement requires distinct API keys."""

    _ADMIN_ENTITY = "stigmem://testnode/agent/admin"
    _OUTSIDER_ENTITY = "stigmem://testnode/agent/outsider"
    _GARDEN_SLUG = "acl-garden"
    _GARDEN_SCOPE = "team"

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_path):
        self._client, self._orig, self._patched, self._admin_key = _make_authed_node(tmp_path)
        self._outsider_key = create_api_key(self._OUTSIDER_ENTITY, ["read", "write"])
        r = self._client.post(
            "/v1/gardens",
            json={"slug": self._GARDEN_SLUG, "name": "ACL Garden", "scope": self._GARDEN_SCOPE},
            headers={"Authorization": f"Bearer {self._admin_key}"},
        )
        assert r.status_code == 201, f"garden setup failed: {r.text}"
        self._garden_uri = r.json()["garden_id"]
        yield
        _restore_authed(self._orig, self._patched)

    def _ah(self) -> dict:
        return {"Authorization": f"Bearer {self._admin_key}"}

    def _oh(self) -> dict:
        return {"Authorization": f"Bearer {self._outsider_key}"}

    def _enc(self) -> str:
        return self._garden_uri.replace(":", "%3A").replace("/", "%2F")

    def test_member_write_garden_fact_returns_201(self) -> None:
        """§5.19 — admin can assert a garden-tagged fact with matching scope."""
        r = self._client.post(
            "/v1/facts",
            json={
                "entity": "stigmem://testnode/project/atlas",
                "relation": "roadmap:status",
                "value": {"type": "string", "v": "in-flight"},
                "source": self._ADMIN_ENTITY,
                "confidence": 1.0,
                "scope": self._GARDEN_SCOPE,
                "garden_id": self._garden_uri,
            },
            headers=self._ah(),
        )
        assert r.status_code == 201, r.text
        assert r.json()["garden_id"] is not None

    def test_scope_mismatch_rejected(self) -> None:
        """§17.3 — fact scope must match garden scope; mismatch → 403 or 422."""
        r = self._client.post(
            "/v1/facts",
            json={
                "entity": "stigmem://testnode/project/atlas",
                "relation": "roadmap:status",
                "value": {"type": "string", "v": "blocked"},
                "source": self._ADMIN_ENTITY,
                "confidence": 1.0,
                "scope": "company",
                "garden_id": self._garden_uri,
            },
            headers=self._ah(),
        )
        assert r.status_code in (403, 422), (
            f"scope mismatch → 403/422 expected, got {r.status_code}: {r.text}"
        )

    def test_nonmember_write_returns_403(self) -> None:
        """§17.3 — non-member principal is rejected on garden-tagged write."""
        r = self._client.post(
            "/v1/facts",
            json={
                "entity": "stigmem://testnode/project/atlas",
                "relation": "roadmap:status",
                "value": {"type": "string", "v": "blocked"},
                "source": self._OUTSIDER_ENTITY,
                "confidence": 1.0,
                "scope": self._GARDEN_SCOPE,
                "garden_id": self._garden_uri,
            },
            headers=self._oh(),
        )
        assert r.status_code == 403, (
            f"non-member write → 403 expected, got {r.status_code}: {r.text}"
        )

    def test_member_query_by_garden_id_returns_200(self) -> None:
        """§5.20 — garden member can filter facts by garden_id."""
        r = self._client.get(f"/v1/facts?garden_id={self._enc()}", headers=self._ah())
        assert r.status_code == 200, r.text
        assert "facts" in r.json()

    def test_nonmember_query_returns_403_not_empty(self) -> None:
        """§5.20, §17.3 — non-member gets 403, not empty list, when querying by garden_id."""
        r = self._client.get(f"/v1/facts?garden_id={self._enc()}", headers=self._oh())
        assert r.status_code == 403, (
            f"non-member garden query → 403 expected, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# §3.5 / §18 — Source Attestation mode behaviour (auth required)
# ---------------------------------------------------------------------------


class TestSourceAttestationConformance:
    """§18 — source ↔ identity attestation is core (graduated): the default
    install flags mismatched sources (attested=False); enforce mode rejects them."""

    def test_default_mismatch_flagged_attested_false(self, tmp_path) -> None:
        """A source not matching the writing principal is flagged (still accepted)."""
        client, orig, patched, key = _make_authed_node(tmp_path, "wm1")
        try:
            r = client.post(
                "/v1/facts",
                json={
                    "entity": "stigmem://testnode/user/alice",
                    "relation": "memory:role",
                    "value": {"type": "string", "v": "viewer"},
                    "source": "stigmem://testnode/user/someone-else",
                    "confidence": 1.0,
                    "scope": "company",
                },
                headers={"Authorization": f"Bearer {key}"},
            )
            assert r.status_code == 201, r.text
            assert r.json().get("attested") is False
        finally:
            _restore_authed(orig, patched)

    def test_default_match_attested_true(self, tmp_path) -> None:
        """A source matching the writing principal is attested."""
        client, orig, patched, key = _make_authed_node(tmp_path, "wm2")
        try:
            r = client.post(
                "/v1/facts",
                json={
                    "entity": "stigmem://testnode/user/alice",
                    "relation": "memory:role",
                    "value": {"type": "string", "v": "writer"},
                    "source": "stigmem://testnode/agent/admin",
                    "confidence": 1.0,
                    "scope": "company",
                },
                headers={"Authorization": f"Bearer {key}"},
            )
            assert r.status_code == 201, r.text
            assert r.json().get("attested") is True
        finally:
            _restore_authed(orig, patched)

    def test_enforce_mismatch_returns_403(self, tmp_path) -> None:
        """With source_attestation_enforce, a mismatched source is rejected."""
        import stigmem_node.settings as sm

        client, orig, patched, key = _make_authed_node(tmp_path, "ef")
        sm.settings.source_attestation_enforce = True
        try:
            r = client.post(
                "/v1/facts",
                json={
                    "entity": "stigmem://testnode/user/alice",
                    "relation": "memory:role",
                    "value": {"type": "string", "v": "impersonator"},
                    "source": "stigmem://testnode/user/victim",
                    "confidence": 1.0,
                    "scope": "company",
                },
                headers={"Authorization": f"Bearer {key}"},
            )
            assert r.status_code == 403, r.text
        finally:
            _restore_authed(orig, patched)

    def test_legacy_mode_field_is_inert(self, tmp_path) -> None:
        """The legacy source_attestation_mode field no longer gates evaluation."""
        client, orig, patched, key = _make_authed_node(tmp_path, "off", "off")
        try:
            r = client.post(
                "/v1/facts",
                json={
                    "entity": "stigmem://testnode/user/alice",
                    "relation": "memory:role",
                    "value": {"type": "string", "v": "viewer"},
                    "source": "stigmem://testnode/user/anyone",
                    "confidence": 1.0,
                    "scope": "company",
                },
                headers={"Authorization": f"Bearer {key}"},
            )
            assert r.status_code == 201, r.text
            assert r.json().get("attested") is False, (
                f"core evaluates regardless of legacy mode, got {r.json()}"
            )
        finally:
            _restore_authed(orig, patched)

    def test_auth_disabled_attested_null(self, tmp_path) -> None:
        """§18.2, §2.7 — auth disabled → attestation cannot run; attested=null."""
        import stigmem_node.auth as am
        import stigmem_node.db as dm

        apply_migrations = dm.apply_migrations
        import stigmem_node.routes.wellknown as wk
        import stigmem_node.settings as sm
        from stigmem_node.main import create_app

        db_file = str(tmp_path) + "/noauth.db"
        apply_migrations(db_path=db_file)
        original = sm.settings
        ts = sm.Settings(
            db_path=db_file,
            auth_required=False,
            node_url="http://testnode",
            source_attestation_mode="warn",
        )
        sm.settings = ts
        am.settings = ts
        dm.settings = ts
        wk.settings = ts
        app = create_app()
        client = TestClient(app, raise_server_exceptions=True)
        with client:
            r = client.post(
                "/v1/facts",
                json={
                    "entity": "stigmem://testnode/user/alice",
                    "relation": "memory:role",
                    "value": {"type": "string", "v": "viewer"},
                    "source": "stigmem://testnode/user/anyone",
                    "confidence": 1.0,
                    "scope": "company",
                },
            )
        sm.settings = original
        am.settings = original
        dm.settings = original
        wk.settings = original
        assert r.status_code == 201, r.text
        assert r.json().get("attested") is None, (
            f"auth-disabled → attested=null expected, got {r.json()}"
        )

    def test_wellknown_advertises_source_attestation(self, tmp_path) -> None:
        """§18.3 — /.well-known/stigmem must expose source_attestation field."""
        client, orig, patched, _ = _make_authed_node(tmp_path, "wk", "warn")
        try:
            r = client.get("/.well-known/stigmem")
            assert r.status_code == 200
            body = r.json()
            assert "source_attestation" in body, "missing source_attestation in well-known"
            assert body["source_attestation"] in ("enforce", "warn", "off")
        finally:
            _restore_authed(orig, patched)

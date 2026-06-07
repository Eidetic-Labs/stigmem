"""Stigmem reference node — FastAPI application factory and entrypoint."""

from __future__ import annotations

import asyncio
import logging
import signal
import ssl
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Annotated, Any, cast
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .auth import Identity, resolve_identity
from .body_limit import BodySizeLimitMiddleware
from .db import apply_migrations
from .rate_limit import RateLimitMiddleware
from .routes.admin_audit import router as admin_audit_router
from .routes.agent_keys import router as agent_keys_router
from .routes.aliases import router as aliases_router
from .routes.audit import router as audit_router
from .routes.auth import router as auth_router
from .routes.cards import router as cards_router
from .routes.cid_admin import router as cid_admin_router
from .routes.decay import router as decay_router
from .routes.facts import router as facts_router
from .routes.federation import router as federation_router
from .routes.gardens import router as gardens_router
from .routes.graph import router as graph_router
from .routes.identity import router as identity_router
from .routes.intents import router as intents_router
from .routes.lint import router as lint_router
from .routes.mcp import router as mcp_router
from .routes.quarantine import router as quarantine_router
from .routes.recall import router as recall_router
from .routes.resolver import router as resolver_router
from .routes.subscriptions import router as subscriptions_router
from .routes.synthesize import router as synthesize_router
from .routes.tombstones import router as tombstones_router
from .routes.wellknown import router as wellknown_router
from .settings import settings

_STATIC_DIR = Path(__file__).parent / "static"

logger = logging.getLogger("stigmem")

_DEV_LOCALHOST_CORS_REGEX = r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$"


def _enforce_federation_transport_security() -> None:
    """Require explicit opt-in for federation without mTLS."""
    federation_active = settings.federation_enabled or settings.federation_push_enabled
    if not federation_active or settings.mtls_enabled:
        return

    if not settings.federation_insecure:
        raise RuntimeError(
            "Federation requires mTLS by default. Configure STIGMEM_TLS_CERT_PATH, "
            "STIGMEM_TLS_KEY_PATH, and STIGMEM_TLS_CA_BUNDLE, or set "
            "STIGMEM_FEDERATION_INSECURE=1 only for local/dev/test federation."
        )

    if not _node_url_is_loopback(settings.node_url) and not (
        settings.local_dev_allow_insecure_non_loopback
    ):
        raise RuntimeError(
            "STIGMEM_FEDERATION_INSECURE=1 is only permitted when node_url is "
            f"bound to 127.0.0.1 or localhost. Got node_url={settings.node_url!r}. "
            "Configure mTLS for any non-loopback deployment, or set "
            "STIGMEM_LOCAL_DEV_ALLOW_INSECURE_NON_LOOPBACK=1 only for local "
            "Docker/dev networks."
        )

    logger.warning(
        "SECURITY WARNING: federation is running without mTLS because "
        "STIGMEM_FEDERATION_INSECURE=1 is set. This is only allowed because "
        "node_url is a loopback address or "
        "STIGMEM_LOCAL_DEV_ALLOW_INSECURE_NON_LOOPBACK=1 is set. Use this only "
        "for local/dev/test."
    )


def _enforce_auth_required_in_production() -> None:
    """Refuse to run unauthenticated outside loopback."""
    if settings.auth_required:
        return
    if not _node_url_is_loopback(settings.node_url) and not (
        settings.local_dev_allow_insecure_non_loopback
    ):
        raise RuntimeError(
            "STIGMEM_AUTH_REQUIRED=false is only permitted when node_url is "
            f"bound to 127.0.0.1 or localhost. Got node_url={settings.node_url!r}. "
            "Anonymous identity has read/write/federate permissions; never expose "
            "this configuration to a network. Set "
            "STIGMEM_LOCAL_DEV_ALLOW_INSECURE_NON_LOOPBACK=1 only for local "
            "Docker/dev networks."
        )
    logger.warning(
        "SECURITY WARNING: STIGMEM_AUTH_REQUIRED=false. Anonymous identity has "
        "full read/write/federate permissions. This is only allowed because "
        "node_url is a loopback address or "
        "STIGMEM_LOCAL_DEV_ALLOW_INSECURE_NON_LOOPBACK=1 is set."
    )


def _enforce_rate_limit_kill_switch_ack() -> None:
    """Refuse boot when quota is fully disabled without an explicit acknowledgement."""
    if settings.rate_limit_write_per_hour != 0 or settings.rate_limit_read_per_hour != 0:
        return
    if not settings.rate_limit_disabled_ack:
        raise RuntimeError(
            "STIGMEM_RATE_LIMIT_WRITE_PER_HOUR=0 and "
            "STIGMEM_RATE_LIMIT_READ_PER_HOUR=0 fully disable quota enforcement. "
            "To proceed, set STIGMEM_RATE_LIMIT_DISABLED_ACK=1 to acknowledge "
            "that this node accepts unbounded read and write traffic."
        )

    logger.warning(
        "SECURITY WARNING: quota enforcement is fully disabled "
        "(write=0, read=0) with explicit operator acknowledgment via "
        "STIGMEM_RATE_LIMIT_DISABLED_ACK=1."
    )


def _warn_if_cors_dev_localhost_enabled() -> None:
    """Log the expanded development CORS posture at startup."""
    if settings.cors_dev_localhost:
        logger.warning(
            "SECURITY WARNING: STIGMEM_CORS_DEV_LOCALHOST=1 enables browser "
            "access from localhost and loopback origins. Use this only for "
            "local development."
        )


def _warn_if_backend_immutability_unenforced() -> None:
    """Warn when the storage backend lacks DB-level facts-immutability triggers.

    P-DESTROY-1 (honesty): the append-only no-UPDATE/no-DELETE triggers
    (ADR-016 L2) are implemented for SQLite only. On libsql/Postgres the facts
    table is mutable by anyone with direct database write access, so tamper
    resistance on those backends rests on the L3+ CID / hash-chain layers, not
    L2 triggers. State that loudly rather than imply uniform immutability.
    """
    backend = getattr(settings, "storage_backend", "sqlite")
    if backend == "sqlite":
        return
    logger.warning(
        "SECURITY WARNING: storage_backend=%r does NOT enforce database-level "
        "facts immutability. The append-only no-UPDATE/no-DELETE triggers "
        "(ADR-016 L2) exist for SQLite only; on %s the facts table is mutable "
        "by anyone with direct DB write access. Tamper-evidence on this backend "
        "relies on the L3+ CID / hash-chain layers, not L2 triggers.",
        backend,
        backend,
    )


def _warn_if_legacy_sha256_acceptance_unbounded() -> None:
    """Warn when legacy SHA-256 API-key hashes are accepted with no cutoff (F-ID-4).

    Unsalted SHA-256 is weaker than the Argon2id default. The acceptance window
    is a v0.9.x migration affordance; leaving it open indefinitely
    (STIGMEM_LEGACY_SHA256_ACCEPT_UNTIL unset) is a standing weakness.
    """
    if settings.legacy_sha256_accept_until is not None:
        return
    logger.warning(
        "SECURITY WARNING: legacy SHA-256 API-key hashes are accepted with no "
        "cutoff (STIGMEM_LEGACY_SHA256_ACCEPT_UNTIL is unset). Unsalted SHA-256 "
        "is weaker than the Argon2id default; set a cutoff date to bound the "
        "migration window and force rotation of any keys not yet rehashed."
    )


def _node_url_is_loopback(node_url: str) -> bool:
    """Return True iff node_url's host is a loopback address."""
    try:
        parsed = urlparse(node_url)
        host = (parsed.hostname or "").lower()
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "::1"}


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        from .plugins import get_registry, register_discovered_plugins

        if settings.trust_mode == "strict" and not settings.node_private_key:
            raise RuntimeError("STIGMEM_NODE_PRIVATE_KEY must be set when trust_mode=strict")
        _enforce_federation_transport_security()
        _enforce_auth_required_in_production()
        _enforce_rate_limit_kill_switch_ack()
        _warn_if_cors_dev_localhost_enabled()
        _warn_if_backend_immutability_unenforced()
        _warn_if_legacy_sha256_acceptance_unbounded()

        discovered_plugins = register_discovered_plugins(freeze=False)
        _include_plugin_routers(app, discovered_plugins)
        apply_migrations()
        from .memory_garden_acl_gate import warn_if_memory_garden_acl_filtering_disabled

        warn_if_memory_garden_acl_filtering_disabled(logger)
        get_registry().freeze()

        if settings.otel_enabled:
            from .observability.tracing import init_tracing

            init_tracing(
                service_name=settings.otel_service_name,
                otlp_endpoint=settings.otel_exporter_otlp_endpoint,
            )

        pull_task: asyncio.Task[None] | None = None
        if settings.federation_enabled:
            from .federation.federation_pull import pull_loop_task
            from .federation.peer_token import init_federation_keys

            init_federation_keys()
            pull_task = asyncio.create_task(pull_loop_task())
            logger.info("Federation enabled — pull %ds", settings.federation_pull_interval_s)

        from .subscription_delivery import sweep_loop as _sub_sweep_loop

        sweep_task: asyncio.Task[None] = asyncio.create_task(_sub_sweep_loop())
        logger.info(
            "Stigmem subscription sweep enabled — interval %ds",
            settings.subscription_delivery_sweep_s,
        )

        logger.info(
            "Stigmem node ready — db=%s auth=%s federation=%s",
            settings.db_path,
            settings.auth_required,
            "enabled" if settings.federation_enabled else "disabled",
        )
        yield

        sweep_task.cancel()
        with suppress(asyncio.CancelledError):
            _unused_result = await cast("asyncio.Task[object]", sweep_task)

        if pull_task is not None:
            pull_task.cancel()
            with suppress(asyncio.CancelledError):
                _unused_result = await cast("asyncio.Task[object]", pull_task)

    app = FastAPI(
        title="Stigmem Reference Node",
        version="0.9.0a10",
        description=(
            "Reference node implementing the Stigmem v0.9.0a10 HTTP API — facts, federation, "
            "gardens, recall, subscriptions, audit, identity, content-addressed fact IDs. "
            "Experimental cross-cutting behavior remains opt-in where plugin-gated; tombstone "
            "admin and federation route contracts are mounted but access-gated."
        ),
        license_info={"name": "Apache-2.0", "url": "https://www.apache.org/licenses/LICENSE-2.0"},
        lifespan=lifespan,
    )

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(BodySizeLimitMiddleware)
    _cors_regex = settings.cors_allowed_origin_regex
    if settings.cors_dev_localhost:
        _cors_regex = _DEV_LOCALHOST_CORS_REGEX
    if settings.cors_allowed_origins or _cors_regex:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_allowed_origins,
            allow_origin_regex=_cors_regex,
            allow_credentials=settings.cors_allow_credentials,
            allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["*"],
            expose_headers=["ETag"],
            max_age=600,
        )

    @app.middleware("http")
    async def unsigned_plugin_override_warning(
        _request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Warn every request while development unsigned-plugin override is active."""
        from .plugins import get_registry

        unsigned_plugins = get_registry().development_unsigned_plugins()
        if unsigned_plugins:
            logger.warning(
                "SECURITY WARNING: unsigned plugins active via "
                "STIGMEM_PLUGIN_SIGNING_REQUIRED=false: %s",
                ", ".join(unsigned_plugins),
            )
        return await call_next(_request)

    if settings.mtls_enabled:

        @app.middleware("http")
        async def mtls_plaintext_guard(
            request: Request,
            call_next: Callable[[Request], Awaitable[Response]],
        ) -> Response:
            """Reject plaintext federation requests when mTLS is configured (§22.1)."""
            if request.method == "OPTIONS" and not request.url.path.startswith("/v1/federation"):
                return await call_next(request)
            if request.url.path.startswith("/v1/federation") and request.url.scheme != "https":
                return JSONResponse(
                    {
                        "error": "mTLS required",
                        "detail": "Federation transport requires mutual TLS (spec §22.1). "
                        "Connect via HTTPS with a valid node certificate.",
                    },
                    status_code=421,
                )
            return await call_next(request)

    app.include_router(admin_audit_router)
    app.include_router(cid_admin_router)
    app.include_router(auth_router)
    app.include_router(agent_keys_router)
    app.include_router(audit_router)
    app.include_router(facts_router)
    app.include_router(gardens_router)
    app.include_router(graph_router)
    app.include_router(identity_router)
    app.include_router(intents_router)
    app.include_router(federation_router)
    app.include_router(quarantine_router)
    app.include_router(lint_router)
    app.include_router(synthesize_router)
    app.include_router(decay_router)
    app.include_router(aliases_router)
    app.include_router(resolver_router)
    app.include_router(cards_router)
    app.include_router(recall_router)
    app.include_router(subscriptions_router)
    app.include_router(tombstones_router)
    app.include_router(mcp_router)
    app.include_router(wellknown_router)

    @app.get("/healthz", tags=["ops"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/v1/doctor", tags=["ops"])
    def doctor() -> dict[str, str]:
        """Return coarse node health and operator posture.

        This endpoint is unauthenticated in v0.9.0a10. The garden ACL posture
        field is accepted as ops-endpoint disclosure and intentionally avoids
        garden names, membership rows, tenant identifiers, or policy subjects.
        """
        from .memory_garden_acl_gate import memory_garden_acl_filtering_state

        return {
            "status": "ok",
            "memory_garden_acl_filtering": memory_garden_acl_filtering_state(),
        }

    @app.get("/metrics", include_in_schema=False, tags=["ops"])
    def prometheus_metrics() -> Response:
        from .observability.metrics import make_metrics_response

        resp = make_metrics_response()
        if resp is None:
            from fastapi.responses import PlainTextResponse

            return PlainTextResponse("# prometheus_client not installed\n", status_code=200)
        return resp

    @app.get("/v1/me", tags=["auth"])
    def whoami(identity: Annotated[Identity, Depends(resolve_identity)]) -> dict[str, Any]:
        return {
            "entity_uri": identity.entity_uri,
            "permissions": sorted(identity.permissions),
            "oidc_sub": identity.oidc_sub,
            "tenant_id": identity.tenant_id,
        }

    @app.get("/ui", include_in_schema=False)
    def ui_index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html", media_type="text/html")

    return app


def _include_plugin_routers(app: FastAPI, discovered_plugins: tuple[Any, ...]) -> None:
    """Include routers declared by installed plugins once per app instance."""
    if getattr(app.state, "stigmem_plugin_routes_included", False):
        return
    for plugin in discovered_plugins:
        for router in plugin.manifest.routes:
            app.include_router(router)
    app.state.stigmem_plugin_routes_included = True


app = create_app()


def run() -> None:
    if not settings.mtls_enabled:
        uvicorn.run(
            "stigmem_node.main:app",
            host=settings.host,
            port=settings.port,
            log_level=settings.log_level,
            reload=False,
        )
        return

    from .federation.tls import cert_watcher_task, reload_tls_cert

    # Let uvicorn build the SSL context from cert/key files, then enforce TLS 1.3
    # floor and mTLS client-cert requirement on the resulting context object.
    config = uvicorn.Config(
        "stigmem_node.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=False,
        ssl_certfile=settings.tls_cert_path,
        ssl_keyfile=settings.tls_key_path,
        ssl_ca_certs=settings.tls_ca_bundle or None,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
    config.load()

    if config.ssl:
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    ssl_ctx = config.ssl

    async def _serve_with_cert_watcher() -> None:
        loop = asyncio.get_running_loop()
        if ssl_ctx is not None:
            loop.add_signal_handler(
                signal.SIGHUP,
                lambda: reload_tls_cert(ssl_ctx),
            )

        server = uvicorn.Server(config)
        watcher_task: asyncio.Task[None] | None = None
        if ssl_ctx is not None:
            watcher_task = asyncio.create_task(cert_watcher_task(ssl_ctx))

        try:
            await server.serve()
        finally:
            if watcher_task is not None:
                watcher_task.cancel()
                with suppress(asyncio.CancelledError):
                    _unused_result = await cast("asyncio.Task[object]", watcher_task)

    asyncio.run(_serve_with_cert_watcher())


if __name__ == "__main__":
    run()

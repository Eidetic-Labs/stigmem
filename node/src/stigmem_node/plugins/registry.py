"""Hook registry dispatch machinery for PR 4-INF.1."""

from __future__ import annotations

import contextlib
import inspect
import logging
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Any, TypeVar, cast

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version

from stigmem_node.observability.metrics import (
    PLUGIN_HANDLER_DURATION,
    PLUGIN_HANDLER_ERROR,
    PLUGIN_HANDLER_INVOCATION,
    PLUGIN_HANDLERS_PER_HOOK,
    PLUGIN_HOOK_DURATION,
    PLUGIN_HOOK_FIRE,
    PLUGIN_REGISTERED_COUNT,
    PLUGIN_REGISTRATION,
    PLUGIN_VOTING_DECISION,
)

from .context import CoreApis, PluginContext
from .errors import ManifestError, PluginExecutionError, RegistryFrozenError, RejectError
from .handlers import (
    ALLOW_SINGLETON,
    Allow,
    AuditEvent,
    Deny,
    Failure,
    PluginHealth,
    PluginHealthReport,
    PluginHealthStatus,
    PluginInfo,
    Success,
    VotingDecision,
)
from .hooks import HOOK_SPECS, HookOrdering, HookSemantic
from .manifest import PluginManifest

logger = logging.getLogger("stigmem.plugins.registry")
_FALLBACK_STIGMEM_VERSION = "0.9.0a12"

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class HandlerEntry:
    hook: str
    handler: Callable[..., Any]
    plugin_name: str
    handler_name: str
    ctx: PluginContext
    is_core: bool
    async_safe: bool
    timeout_seconds: float | None


class HookRegistry:
    """Deterministic in-process hook registry."""

    def __init__(
        self,
        *,
        core_apis: CoreApis | None = None,
        emit_metrics: bool = False,
        handler_timeout_seconds: float | None = None,
    ) -> None:
        if handler_timeout_seconds is not None:
            _validate_timeout_seconds(handler_timeout_seconds)
        self._handlers: dict[str, tuple[HandlerEntry, ...]] = {hook: () for hook in HOOK_SPECS}
        self._plugin_names: set[str] = set()
        self._plugin_order: list[str] = []
        self._plugin_versions: dict[str, str] = {}
        self._plugin_infos: dict[str, PluginInfo] = {}
        self._plugin_signing_metadata: dict[str, dict[str, Any]] = {}
        self._plugin_contexts: dict[str, PluginContext] = {}
        self._plugin_health_checks: dict[str, Callable[..., Any]] = {}
        self._plugin_health_reports: dict[str, PluginHealthReport] = {}
        self._core_apis = core_apis or CoreApis()
        self._emit_metrics = emit_metrics
        self._handler_timeout_seconds = handler_timeout_seconds
        self._timeout_executor: ThreadPoolExecutor | None = None
        self._frozen = False
        self._emitting_registry_audit = False
        self._lock = threading.RLock()

    def register_plugin(
        self,
        manifest: PluginManifest,
        *,
        discovery_source: dict[str, Any] | None = None,
        signing_identity: str = "unsigned",
        signing_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Register all handlers from a manually supplied plugin manifest."""
        audit_metadata = _registration_audit_metadata(
            discovery_source=discovery_source,
            signing_identity=signing_identity,
            signing_metadata=signing_metadata,
        )
        with self._lock:
            self._ensure_mutable()
            if manifest.name in self._plugin_names:
                self._metric_inc(PLUGIN_REGISTRATION, outcome="failure", reason="duplicate")
                self._emit_registry_audit(
                    "plugin.registration_failed",
                    manifest=manifest,
                    reason="duplicate",
                    metadata=audit_metadata,
                )
                raise ManifestError(f"plugin {manifest.name!r} is already registered")
            try:
                self._validate_manifest_compatibility(manifest)
                self._validate_manifest_handler_signatures(manifest)
            except ManifestError as exc:
                self._metric_inc(PLUGIN_REGISTRATION, outcome="failure", reason="manifest_invalid")
                self._emit_registry_audit(
                    "plugin.registration_failed",
                    manifest=manifest,
                    reason="manifest_invalid",
                    validation_failure=str(exc),
                    metadata=audit_metadata,
                )
                raise
            ctx = PluginContext(
                plugin_name=manifest.name,
                plugin_version=manifest.version,
                capabilities=manifest.capabilities,
                core_apis=self._core_apis,
            )
            decision = self.fire_voting("config_validate", plugin=manifest)
            if isinstance(decision, Deny):
                self._metric_inc(PLUGIN_REGISTRATION, outcome="failure", reason="config_validate")
                self._emit_registry_audit(
                    "plugin.registration_failed",
                    manifest=manifest,
                    reason="config_validate",
                    validation_failure=decision.reason,
                    metadata=audit_metadata,
                )
                raise ManifestError(
                    f"plugin {manifest.name!r} failed config validation: {decision.reason}"
                )
            own_config_validator = manifest.hooks.get("config_validate")
            if own_config_validator is not None:
                try:
                    own_decision = own_config_validator(ctx, plugin=manifest)
                except Exception as exc:
                    self._metric_inc(
                        PLUGIN_REGISTRATION, outcome="failure", reason="config_exception"
                    )
                    self._emit_registry_audit(
                        "plugin.registration_failed",
                        manifest=manifest,
                        reason="config_exception",
                        validation_failure=str(exc),
                        metadata=audit_metadata,
                    )
                    raise ManifestError(
                        f"plugin {manifest.name!r} config validator failed: {exc}"
                    ) from exc
                if isinstance(own_decision, Deny):
                    self._metric_inc(
                        PLUGIN_REGISTRATION, outcome="failure", reason="config_validate"
                    )
                    self._emit_registry_audit(
                        "plugin.registration_failed",
                        manifest=manifest,
                        reason="config_validate",
                        validation_failure=own_decision.reason,
                        metadata=audit_metadata,
                    )
                    raise ManifestError(
                        f"plugin {manifest.name!r} failed config validation: {own_decision.reason}"
                    )
                if not isinstance(own_decision, Allow):
                    self._metric_inc(PLUGIN_REGISTRATION, outcome="failure", reason="config_result")
                    self._emit_registry_audit(
                        "plugin.registration_failed",
                        manifest=manifest,
                        reason="config_result",
                        validation_failure=type(own_decision).__name__,
                        metadata=audit_metadata,
                    )
                    raise ManifestError(
                        f"plugin {manifest.name!r} config validator returned "
                        f"{type(own_decision).__name__}; expected Allow or Deny"
                    )
            self._plugin_names.add(manifest.name)
            self._plugin_order.append(manifest.name)
            self._plugin_versions[manifest.name] = manifest.version
            self._plugin_infos[manifest.name] = PluginInfo(
                name=manifest.name,
                version=manifest.version,
                capabilities=tuple(sorted(manifest.capabilities)),
                hooks=tuple(sorted(manifest.hooks)),
                depends_on=tuple(sorted(manifest.depends_on)),
                discovery_source=audit_metadata["discovery_source"],
                signed_by=signing_identity,
            )
            if signing_metadata is not None:
                self._plugin_signing_metadata[manifest.name] = dict(signing_metadata)
            self._plugin_contexts[manifest.name] = ctx
            if manifest.health_check is not None:
                self._plugin_health_checks[manifest.name] = manifest.health_check
            for hook, handler in manifest.hooks.items():
                self._add_handler(
                    hook=hook,
                    handler=handler,
                    plugin_name=manifest.name,
                    handler_name=f"{manifest.name}.{getattr(handler, '__name__', 'handler')}",
                    ctx=ctx,
                    is_core=False,
                    async_safe=manifest.async_safe,
                )
            self._metric_inc(PLUGIN_REGISTRATION, outcome="success", reason="")
            self._metric_set(PLUGIN_REGISTERED_COUNT, len(self._plugin_names))
            self._emit_registry_audit(
                "plugin.registered",
                manifest=manifest,
                metadata=audit_metadata,
            )
            logger.info(
                "registered plugin %r version=%s hooks=%s capabilities=%s",
                manifest.name,
                manifest.version,
                sorted(manifest.hooks),
                sorted(manifest.capabilities),
            )

    def register_core_handler(
        self,
        hook: str,
        handler: Callable[..., Any],
        *,
        name: str,
        capabilities: frozenset[str] | None = None,
    ) -> None:
        """Register a core handler with an explicit sortable name.

        Use names such as ``core.001.sanitize`` and ``core.002.cid`` when
        relative ordering among core handlers matters.
        """
        ctx = PluginContext(
            plugin_name="core",
            plugin_version="0.0.0",
            capabilities=capabilities or frozenset(),
            core_apis=self._core_apis,
        )
        with self._lock:
            self._ensure_mutable()
            self._add_handler(
                hook=hook,
                handler=handler,
                plugin_name="core",
                handler_name=name,
                ctx=ctx,
                is_core=True,
                async_safe=True,
            )

    def fire_voting(self, hook: str, **kwargs: Any) -> VotingDecision:
        self._ensure_semantic(hook, HookSemantic.VOTING)
        with self._observe_hook(hook):
            for entry in self._handlers[hook]:
                try:
                    result = self._invoke_handler(entry, **kwargs)
                except RejectError as exc:
                    self._metric_inc(PLUGIN_VOTING_DECISION, hook=hook, decision="deny")
                    self._emit_handler_denied(entry, reason=exc.reason)
                    return Deny(exc.reason)
                except Exception as exc:
                    self._emit_handler_error(entry, exc)
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} failed for hook {hook!r}: {exc}"
                    ) from exc
                if result is None:
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} returned None; expected VotingDecision"
                    )
                if isinstance(result, Deny):
                    self._metric_inc(PLUGIN_VOTING_DECISION, hook=hook, decision="deny")
                    self._emit_handler_denied(entry, reason=result.reason)
                    return result
                if not isinstance(result, Allow):
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} returned {type(result).__name__}; "
                        "expected Allow or Deny"
                    )
                self._metric_inc(PLUGIN_VOTING_DECISION, hook=hook, decision="allow")
            return ALLOW_SINGLETON

    def fire_filter_chain(self, hook: str, value: T, **kwargs: Any) -> T:
        self._ensure_semantic(hook, HookSemantic.FILTER_CHAIN)
        with self._observe_hook(hook):
            result: T = value
            for entry in self._handlers[hook]:
                try:
                    next_result = self._invoke_handler(entry, result, **kwargs)
                except Exception as exc:
                    self._emit_handler_error(entry, exc)
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} failed for hook {hook!r}: {exc}"
                    ) from exc
                if next_result is None:
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} returned None for "
                        f"filter-chain hook {hook!r}"
                    )
                result = cast(T, next_result)
            return result

    def fire_score_delta(
        self, hook: str, scored_results: list[Any], **kwargs: Any
    ) -> dict[str, float]:
        self._ensure_semantic(hook, HookSemantic.SCORE_DELTA)
        with self._observe_hook(hook):
            combined: dict[str, float] = {}
            for entry in self._handlers[hook]:
                try:
                    deltas = self._invoke_handler(entry, scored_results, **kwargs)
                except Exception as exc:
                    self._emit_handler_error(entry, exc)
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} failed for hook {hook!r}: {exc}"
                    ) from exc
                if not isinstance(deltas, dict):
                    raise PluginExecutionError(
                        f"handler {entry.handler_name!r} returned {type(deltas).__name__}; "
                        "expected dict[str, float]"
                    )
                for fact_id, delta in deltas.items():
                    combined[str(fact_id)] = combined.get(str(fact_id), 0.0) + float(delta)
            return combined

    def fire_fire_and_forget(self, hook: str, **kwargs: Any) -> None:
        spec = self._ensure_semantic(hook, HookSemantic.FIRE_AND_FORGET)
        with self._observe_hook(hook):
            for entry in self._handlers[hook]:
                try:
                    self._invoke_handler(entry, **kwargs)
                except Exception as exc:
                    logger.warning(
                        "handler %r failed for hook %r", entry.handler_name, hook, exc_info=True
                    )
                    self._emit_handler_error(entry, exc)
                    if spec.strict_audit:
                        raise PluginExecutionError(
                            f"handler {entry.handler_name!r} failed for audit hook {hook!r}: {exc}"
                        ) from exc

    def handlers_for(self, hook: str) -> tuple[HandlerEntry, ...]:
        self._require_known_hook(hook)
        return self._handlers[hook]

    def registered_plugins(self) -> frozenset[str]:
        return frozenset(self._plugin_names)

    def plugin_registration_order(self) -> tuple[str, ...]:
        return tuple(self._plugin_order)

    def plugin_versions(self) -> dict[str, str]:
        return dict(self._plugin_versions)

    def plugin_infos(self) -> tuple[PluginInfo, ...]:
        return tuple(self._plugin_infos[name] for name in self._plugin_order)

    def plugin_info(self, name: str) -> PluginInfo | None:
        return self._plugin_infos.get(name)

    def plugin_signing_metadata(self, name: str) -> dict[str, Any]:
        return dict(self._plugin_signing_metadata.get(name, {}))

    def development_unsigned_plugins(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in self._plugin_order
            if self._plugin_signing_metadata.get(name, {}).get("trust_decision")
            == "development_unsigned_override"
        )

    def poll_plugin_health(self) -> tuple[PluginHealthReport, ...]:
        """Run lifecycle health checks and record the latest report per plugin.

        Health is informational for PR 4-INF.2; unhealthy plugins remain
        registered and their handlers stay active until a future policy layer
        chooses otherwise.
        """
        reports = tuple(self._poll_one_plugin_health(name) for name in self._plugin_order)
        self._plugin_health_reports.update({report.plugin_name: report for report in reports})
        return reports

    def plugin_health_reports(self) -> tuple[PluginHealthReport, ...]:
        return tuple(
            report
            for name in self._plugin_order
            if (report := self._plugin_health_reports.get(name)) is not None
        )

    def freeze(self) -> None:
        """Reject subsequent startup-time mutations.

        Handler collections are stored as tuples throughout registration; freeze
        records the startup boundary so runtime dispatch remains read-only.
        """
        with self._lock:
            self._frozen = True
            if self._timeout_executor is None and self._has_timeout_handlers():
                self._timeout_executor = ThreadPoolExecutor(
                    max_workers=max(1, self._timeout_handler_count()),
                    thread_name_prefix="stigmem-plugin-timeout",
                )

    def _add_handler(
        self,
        *,
        hook: str,
        handler: Callable[..., Any],
        plugin_name: str,
        handler_name: str,
        ctx: PluginContext,
        is_core: bool,
        async_safe: bool,
    ) -> None:
        self._require_known_hook(hook)
        entry = HandlerEntry(
            hook=hook,
            handler=handler,
            plugin_name=plugin_name,
            handler_name=handler_name,
            ctx=ctx,
            is_core=is_core,
            async_safe=async_safe,
            timeout_seconds=self._timeout_for_handler(handler),
        )
        existing = list(self._handlers[hook])
        existing.append(entry)
        existing.sort(key=lambda item: self._sort_key(hook, item))
        self._handlers[hook] = tuple(existing)
        self._metric_set(PLUGIN_HANDLERS_PER_HOOK, len(self._handlers[hook]), hook=hook)

    def _invoke_handler(self, entry: HandlerEntry, *args: Any, **kwargs: Any) -> Any:
        timeout_seconds = entry.timeout_seconds
        if timeout_seconds is not None:
            return self._invoke_handler_with_timeout(entry, timeout_seconds, *args, **kwargs)
        if not self._emit_metrics:
            return entry.handler(entry.ctx, *args, **kwargs)
        self._metric_inc(PLUGIN_HANDLER_INVOCATION, hook=entry.hook, plugin=entry.plugin_name)
        start = time.perf_counter()
        try:
            return entry.handler(entry.ctx, *args, **kwargs)
        except Exception as exc:
            self._metric_inc(
                PLUGIN_HANDLER_ERROR,
                hook=entry.hook,
                plugin=entry.plugin_name,
                error_type=type(exc).__name__,
            )
            raise
        finally:
            self._metric_observe(
                PLUGIN_HANDLER_DURATION,
                time.perf_counter() - start,
                hook=entry.hook,
                plugin=entry.plugin_name,
            )

    def _invoke_handler_with_timeout(
        self, entry: HandlerEntry, timeout_seconds: float, *args: Any, **kwargs: Any
    ) -> Any:
        executor = self._timeout_executor
        if executor is None:
            executor = ThreadPoolExecutor(
                max_workers=1,
                thread_name_prefix="stigmem-plugin-timeout",
            )
            self._timeout_executor = executor
        self._metric_inc(PLUGIN_HANDLER_INVOCATION, hook=entry.hook, plugin=entry.plugin_name)
        start = time.perf_counter()
        future = executor.submit(entry.handler, entry.ctx, *args, **kwargs)
        try:
            return future.result(timeout=timeout_seconds)
        except FutureTimeoutError as exc:
            future.cancel()
            timeout_exc = PluginExecutionError(
                f"handler {entry.handler_name!r} timed out for hook {entry.hook!r} "
                f"after {timeout_seconds:.3f}s"
            )
            self._metric_inc(
                PLUGIN_HANDLER_ERROR,
                hook=entry.hook,
                plugin=entry.plugin_name,
                error_type="timeout",
            )
            raise timeout_exc from exc
        except Exception as exc:
            self._metric_inc(
                PLUGIN_HANDLER_ERROR,
                hook=entry.hook,
                plugin=entry.plugin_name,
                error_type=type(exc).__name__,
            )
            raise
        finally:
            self._metric_observe(
                PLUGIN_HANDLER_DURATION,
                time.perf_counter() - start,
                hook=entry.hook,
                plugin=entry.plugin_name,
            )

    @contextlib.contextmanager
    def _observe_hook(self, hook: str) -> Any:
        if not self._emit_metrics:
            yield
            return
        self._metric_inc(PLUGIN_HOOK_FIRE, hook=hook)
        start = time.perf_counter()
        try:
            yield
        finally:
            self._metric_observe(PLUGIN_HOOK_DURATION, time.perf_counter() - start, hook=hook)

    def _metric_inc(self, metric: Any, **labels: str) -> None:
        if not self._emit_metrics:
            return
        try:
            metric.labels(**labels).inc()
        except Exception as exc:
            logger.debug("failed to increment plugin metric %s: %s", metric, exc)

    def _metric_observe(self, metric: Any, value: float, **labels: str) -> None:
        if not self._emit_metrics:
            return
        try:
            metric.labels(**labels).observe(value)
        except Exception as exc:
            logger.debug("failed to observe plugin metric %s: %s", metric, exc)

    def _metric_set(self, metric: Any, value: int, **labels: str) -> None:
        if not self._emit_metrics:
            return
        try:
            if labels:
                metric.labels(**labels).set(value)
            else:
                metric.set(value)
        except Exception as exc:
            logger.debug("failed to set plugin metric %s: %s", metric, exc)

    def _emit_handler_denied(self, entry: HandlerEntry, *, reason: str) -> None:
        self._emit_registry_audit(
            "plugin.handler_denied",
            plugin_name=entry.plugin_name,
            target_uri=f"plugin:{entry.plugin_name}",
            metadata={
                "plugin_name": entry.plugin_name,
                "hook": entry.hook,
                "handler_name": entry.handler_name,
                "reason": reason,
            },
            failure_reason=reason,
        )

    def _emit_handler_error(self, entry: HandlerEntry, exc: Exception) -> None:
        self._emit_registry_audit(
            "plugin.handler_error",
            plugin_name=entry.plugin_name,
            target_uri=f"plugin:{entry.plugin_name}",
            metadata={
                "plugin_name": entry.plugin_name,
                "hook": entry.hook,
                "handler_name": entry.handler_name,
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
            failure_reason=str(exc),
            exception_type=type(exc).__name__,
        )

    def _emit_registry_audit(
        self,
        event_type: str,
        *,
        manifest: PluginManifest | None = None,
        plugin_name: str | None = None,
        target_uri: str | None = None,
        reason: str | None = None,
        validation_failure: str | None = None,
        metadata: dict[str, Any] | None = None,
        failure_reason: str | None = None,
        exception_type: str | None = None,
    ) -> None:
        if self._emitting_registry_audit:
            return
        name = plugin_name or (manifest.name if manifest is not None else "unknown")
        event_metadata = dict(metadata or {})
        if manifest is not None:
            event_metadata.update(
                {
                    "plugin_name": manifest.name,
                    "version": manifest.version,
                    "capabilities": sorted(manifest.capabilities),
                    "hooks": sorted(manifest.hooks),
                    "async_safe": manifest.async_safe,
                    "signed_by": event_metadata.get("signed_by", "unsigned"),
                    "requires_stigmem": manifest.requires_stigmem,
                }
            )
        if reason is not None:
            event_metadata["reason"] = reason
        if validation_failure is not None:
            event_metadata["validation_failure"] = validation_failure
        outcome = (
            Failure(
                reason=failure_reason or reason or "plugin audit event",
                exception_type=exception_type,
            )
            if event_type.endswith("_failed") or failure_reason is not None
            else Success()
        )
        self._emitting_registry_audit = True
        try:
            self.fire_fire_and_forget(
                "audit_emit",
                event=AuditEvent(
                    event_type=event_type,
                    actor_uri="system:plugin-registry",
                    target_uri=target_uri or f"plugin:{name}",
                    tenant_id="system",
                    timestamp=datetime.now(UTC),
                    outcome=outcome,
                    metadata=event_metadata,
                ),
            )
        except Exception:
            logger.warning(
                "failed to emit plugin registry audit event %r", event_type, exc_info=True
            )
        finally:
            self._emitting_registry_audit = False

    def _sort_key(self, hook: str, entry: HandlerEntry) -> tuple[int, str]:
        policy = HOOK_SPECS[hook].ordering
        if policy in (HookOrdering.CORE_FIRST, HookOrdering.CORE_ONLY_DEFAULT):
            partition = 0 if entry.is_core else 1
        elif policy == HookOrdering.PLUGINS_FIRST:
            partition = 1 if entry.is_core else 0
        else:
            partition = 0
        return partition, entry.handler_name

    def _timeout_for_handler(self, handler: Callable[..., Any]) -> float | None:
        timeout = getattr(handler, "__plugin_timeout__", None)
        if timeout is None:
            timeout = self._handler_timeout_seconds
        if timeout is None:
            return None
        return _validate_timeout_seconds(timeout)

    def _has_timeout_handlers(self) -> bool:
        return any(
            entry.timeout_seconds is not None
            for entries in self._handlers.values()
            for entry in entries
        )

    def _timeout_handler_count(self) -> int:
        return sum(
            1
            for entries in self._handlers.values()
            for entry in entries
            if entry.timeout_seconds is not None
        )

    def _poll_one_plugin_health(self, plugin_name: str) -> PluginHealthReport:
        checked_at = datetime.now(UTC)
        version = self._plugin_versions[plugin_name]
        checker = self._plugin_health_checks.get(plugin_name)
        if checker is None:
            return PluginHealthReport(
                plugin_name=plugin_name,
                plugin_version=version,
                status=PluginHealthStatus.UNKNOWN,
                message="no health check registered",
                checked_at=checked_at,
            )
        try:
            result = checker(self._plugin_contexts[plugin_name])
        except Exception as exc:
            return PluginHealthReport(
                plugin_name=plugin_name,
                plugin_version=version,
                status=PluginHealthStatus.UNHEALTHY,
                message=str(exc),
                checked_at=checked_at,
                error_summary=f"{type(exc).__name__}: {exc}",
            )
        if not isinstance(result, PluginHealth):
            return PluginHealthReport(
                plugin_name=plugin_name,
                plugin_version=version,
                status=PluginHealthStatus.UNHEALTHY,
                message=f"health_check returned {type(result).__name__}; expected PluginHealth",
                checked_at=checked_at,
                error_summary=f"invalid result: {type(result).__name__}",
            )
        return PluginHealthReport(
            plugin_name=plugin_name,
            plugin_version=version,
            status=result.status,
            message=result.message,
            checked_at=checked_at,
        )

    def _validate_manifest_compatibility(self, manifest: PluginManifest) -> None:
        try:
            specifier = SpecifierSet(manifest.requires_stigmem)
        except InvalidSpecifier as exc:
            raise ManifestError(
                f"plugin {manifest.name!r} has invalid requires_stigmem "
                f"{manifest.requires_stigmem!r}: {exc}"
            ) from exc
        current_version = Version(_current_stigmem_version())
        if not specifier.contains(current_version, prereleases=True):
            raise ManifestError(
                f"plugin {manifest.name!r} requires stigmem {manifest.requires_stigmem!r}, "
                f"but current version is {current_version}"
            )

    def _validate_manifest_handler_signatures(self, manifest: PluginManifest) -> None:
        for hook, handler in manifest.hooks.items():
            semantic = HOOK_SPECS[hook].semantic
            required_positional = (
                2
                if semantic
                in (
                    HookSemantic.FILTER_CHAIN,
                    HookSemantic.SCORE_DELTA,
                )
                else 1
            )
            if not _accepts_positional_args(handler, required_positional):
                raise ManifestError(
                    f"handler for hook {hook!r} on plugin {manifest.name!r} must accept "
                    f"at least {required_positional} positional argument"
                    f"{'' if required_positional == 1 else 's'}"
                )

    def _ensure_mutable(self) -> None:
        if self._frozen:
            raise RegistryFrozenError("registry is frozen; cannot register handlers")

    def _ensure_semantic(self, hook: str, semantic: HookSemantic) -> Any:
        spec = self._require_known_hook(hook)
        if spec.semantic != semantic:
            raise PluginExecutionError(
                f"hook {hook!r} has semantic {spec.semantic}; cannot fire as {semantic}"
            )
        return spec

    def _require_known_hook(self, hook: str) -> Any:
        try:
            return HOOK_SPECS[hook]
        except KeyError as exc:
            raise ManifestError(f"unknown hook {hook!r}") from exc


_REGISTRY = HookRegistry()


def get_registry() -> HookRegistry:
    return _REGISTRY


def set_registry(registry: HookRegistry) -> HookRegistry:
    """Replace the process registry, returning the previous instance."""
    global _REGISTRY
    previous = _REGISTRY
    _REGISTRY = registry
    return previous


def register_core_handler(
    hook: str,
    handler: Callable[..., Any],
    *,
    name: str,
    capabilities: frozenset[str] | None = None,
) -> None:
    get_registry().register_core_handler(hook, handler, name=name, capabilities=capabilities)


def _current_stigmem_version() -> str:
    try:
        from stigmem_node import __version__

        return __version__
    except ImportError:
        pass
    try:
        return version("stigmem-node")
    except PackageNotFoundError:
        return _FALLBACK_STIGMEM_VERSION


def _registration_audit_metadata(
    *,
    discovery_source: dict[str, Any] | None,
    signing_identity: str,
    signing_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata = {
        "discovery_source": discovery_source or {"type": "manual"},
        "signed_by": signing_identity,
    }
    if signing_metadata is not None:
        metadata["signing"] = dict(signing_metadata)
    return metadata


def _accepts_positional_args(handler: Callable[..., Any], required_count: int) -> bool:
    try:
        signature = inspect.signature(handler)
    except (TypeError, ValueError):
        return False
    positional_count = 0
    for parameter in signature.parameters.values():
        if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
            return True
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        ):
            positional_count += 1
    return positional_count >= required_count


def _validate_timeout_seconds(value: float) -> float:
    timeout = float(value)
    if timeout <= 0:
        raise ValueError("handler timeout must be positive")
    if timeout > 30:
        raise ValueError("handler timeout cannot exceed 30 seconds")
    return timeout

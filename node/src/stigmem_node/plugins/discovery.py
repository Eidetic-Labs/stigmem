"""Plugin package discovery via Python entry points."""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from .errors import PluginDependencyError, PluginDiscoveryError
from .manifest import PluginManifest

logger = logging.getLogger("stigmem.plugins")

ENTRY_POINT_GROUP = "stigmem.plugins"
_State = str
_VISITING: _State = "visiting"
_VISITED: _State = "visited"

# Plugins whose functionality has graduated into core. An installed copy is
# discovered but ignored — its hooks are never registered — so an old package
# cannot shadow, double-run, or fail-open against the now-core implementation.
# Graduated plugins add their distribution name here.
GRADUATED_PLUGINS: frozenset[str] = frozenset({"stigmem-plugin-memory-garden-acl"})


@dataclass(frozen=True, slots=True)
class DiscoveredPlugin:
    """Plugin manifest loaded from a package entry point."""

    manifest: PluginManifest
    entry_point_name: str
    entry_point_value: str
    distribution: str | None = None
    signing_identity: str = "unsigned"
    signature_verified: bool = False


def discover_plugin_manifests(
    *, group: str = ENTRY_POINT_GROUP
) -> tuple[DiscoveredPlugin, ...]:
    """Load plugin manifests declared through Python package entry points.

    Entry points in ``stigmem.plugins`` must resolve to a zero-argument callable
    returning a :class:`PluginManifest`. PR 4-INF.2 keeps discovery separate from
    registration so dependency ordering and startup lifecycle can build on this
    deterministic manifest list.
    """

    discovered: list[DiscoveredPlugin] = []
    seen_names: dict[str, str] = {}
    for entry_point in sorted(_entry_points_for_group(group), key=lambda ep: ep.name):
        factory = _load_entry_point(entry_point)
        if not callable(factory):
            raise PluginDiscoveryError(
                f"plugin entry point {entry_point.name!r} loaded "
                f"{type(factory).__name__}; expected a callable returning PluginManifest"
            )
        manifest = _call_manifest_factory(entry_point, factory)
        if manifest.name in GRADUATED_PLUGINS:
            logger.warning(
                "Ignoring installed plugin %r: its functionality has graduated "
                "into core. Uninstall the package — it is now a no-op.",
                manifest.name,
            )
            continue
        previous_entry_point = seen_names.get(manifest.name)
        if previous_entry_point is not None:
            raise PluginDiscoveryError(
                f"duplicate plugin name {manifest.name!r} discovered from entry points "
                f"{previous_entry_point!r} and {entry_point.name!r}"
            )
        seen_names[manifest.name] = entry_point.name
        discovered.append(
            DiscoveredPlugin(
                manifest=manifest,
                entry_point_name=entry_point.name,
                entry_point_value=entry_point.value,
                distribution=_distribution_name(entry_point),
            )
        )
    return tuple(discovered)


def resolve_plugin_dependencies(
    discovered: Iterable[DiscoveredPlugin],
    *,
    registered_plugins: Iterable[str] = (),
) -> tuple[DiscoveredPlugin, ...]:
    """Return discovered plugins in deterministic dependency-first order.

    Dependencies may be satisfied by other discovered plugins or by names already
    present in the registry. Already-registered dependencies are not returned;
    they simply unlock discovered dependents for follow-on registration.
    """

    by_name: dict[str, DiscoveredPlugin] = {}
    for plugin in discovered:
        name = plugin.manifest.name
        if name in by_name:
            raise PluginDependencyError(f"duplicate discovered plugin name {name!r}")
        by_name[name] = plugin

    registered = frozenset(registered_plugins)
    missing: dict[str, list[str]] = {}
    for name, plugin in sorted(by_name.items()):
        missing_deps = sorted(
            dependency
            for dependency in plugin.manifest.depends_on
            if dependency not in by_name and dependency not in registered
        )
        if missing_deps:
            missing[name] = missing_deps
    if missing:
        details = "; ".join(
            f"{name} missing {', '.join(dependencies)}"
            for name, dependencies in missing.items()
        )
        raise PluginDependencyError(f"missing plugin dependencies: {details}")

    ordered: list[DiscoveredPlugin] = []
    states: dict[str, _State] = {}
    stack: list[str] = []

    def visit(name: str) -> None:
        state = states.get(name)
        if state == _VISITED:
            return
        if state == _VISITING:
            cycle_start = stack.index(name)
            cycle_path = [*stack[cycle_start:], name]
            raise PluginDependencyError(
                f"plugin dependency cycle detected: {' -> '.join(cycle_path)}"
            )

        states[name] = _VISITING
        stack.append(name)
        plugin = by_name[name]
        for dependency in sorted(plugin.manifest.depends_on):
            if dependency in registered:
                continue
            visit(dependency)
        stack.pop()
        states[name] = _VISITED
        ordered.append(plugin)

    for name in sorted(by_name):
        visit(name)

    return tuple(ordered)


def _entry_points_for_group(group: str) -> Iterable[EntryPoint]:
    all_entry_points = entry_points()
    if hasattr(all_entry_points, "select"):
        return all_entry_points.select(group=group)
    return all_entry_points.get(group, ())


def _load_entry_point(entry_point: EntryPoint) -> Any:
    try:
        return entry_point.load()
    except Exception as exc:
        raise PluginDiscoveryError(
            f"failed to load plugin entry point {entry_point.name!r}: {exc}"
        ) from exc


def _call_manifest_factory(entry_point: EntryPoint, factory: Any) -> PluginManifest:
    try:
        manifest = factory()
    except Exception as exc:
        raise PluginDiscoveryError(
            f"plugin entry point {entry_point.name!r} failed while creating "
            f"PluginManifest: {exc}"
        ) from exc
    if not isinstance(manifest, PluginManifest):
        raise PluginDiscoveryError(
            f"plugin entry point {entry_point.name!r} returned "
            f"{type(manifest).__name__}; expected PluginManifest"
        )
    return manifest


def _distribution_name(entry_point: EntryPoint) -> str | None:
    dist = getattr(entry_point, "dist", None)
    if dist is None:
        return None
    metadata = getattr(dist, "metadata", None)
    if metadata is None:
        return None
    name = metadata.get("Name")
    return str(name) if name else None

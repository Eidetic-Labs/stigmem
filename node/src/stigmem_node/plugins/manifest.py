"""Plugin manifest validation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .capabilities import CAPABILITY_ALLOWLIST
from .hooks import KNOWN_HOOKS


class PluginManifest(BaseModel):
    """Minimum manifest accepted by PR 4-INF.1 manual registration."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{2,63}$")
    version: str = Field(
        pattern=r"^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+|[-+][a-zA-Z0-9.-]+)?$"
    )
    requires_stigmem: str = ">=0.9.0a11"
    capabilities: frozenset[str] = frozenset()
    async_safe: bool = True
    hooks: dict[str, Callable[..., Any]] = Field(default_factory=dict)
    routes: tuple[Any, ...] = ()
    health_check: Callable[..., Any] | None = None
    config_schema: type[BaseModel] | None = None
    depends_on: frozenset[str] = frozenset()

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    @field_validator("capabilities")
    @classmethod
    def _validate_capabilities(cls, capabilities: frozenset[str]) -> frozenset[str]:
        unknown = sorted(set(capabilities) - CAPABILITY_ALLOWLIST)
        if unknown:
            raise ValueError(f"unknown plugin capabilities: {', '.join(unknown)}")
        return capabilities

    @field_validator("hooks")
    @classmethod
    def _validate_hook_names(
        cls, hooks: dict[str, Callable[..., Any]]
    ) -> dict[str, Callable[..., Any]]:
        unknown = sorted(set(hooks) - KNOWN_HOOKS)
        if unknown:
            raise ValueError(f"unknown plugin hooks: {', '.join(unknown)}")
        for name, handler in hooks.items():
            if not callable(handler):
                raise ValueError(f"handler for hook {name!r} is not callable")
        return hooks

    @field_validator("health_check")
    @classmethod
    def _validate_health_check(
        cls, health_check: Callable[..., Any] | None
    ) -> Callable[..., Any] | None:
        if health_check is not None and not callable(health_check):
            raise ValueError("health_check must be callable")
        return health_check

    @model_validator(mode="after")
    def _validate_self_dependency(self) -> PluginManifest:
        if self.name in self.depends_on:
            raise ValueError("plugin cannot depend on itself")
        return self

"""Profile contracts. Identity describes validated decoder scope, not a capture claim."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Any


@dataclass(frozen=True)
class Schema:
    """Declarative exact-version route, with optional validated variable lengths."""
    route_id: str
    log_id: int
    version: int
    lengths: frozenset[int]
    family: str
    wrapper: str = "multi-radio-v1"
    unsupported_reason: str | None = None
    variable_min: int | None = None
    variable_max: int = 65535
    decoder: Callable | None = None
    router_peripheral: int = 1
    radio_id: int | None = 1


@dataclass(frozen=True)
class DeviceProfile:
    profile_id: str
    model: str
    codename: str
    aliases: tuple[str, ...]
    chipset: str
    validated_scope: dict[str, str]
    capture_formats: tuple[str, ...]
    signal_names: dict[int, str]
    schemas: tuple[Any, ...]
    adapter_factory: Callable
    limitations: tuple[str, ...]
    manufacturer: str = "Xiaomi"

    def selection_metadata(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "codename": self.codename,
            "selection_mode": "explicit",
            "validated_decoder_scope": dict(self.validated_scope),
            "limitations": list(self.limitations),
        }

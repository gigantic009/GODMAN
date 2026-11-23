"""Capability-oriented endpoint collector adapter contracts."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class AdapterCapability:
    name: str
    platform: str
    available: bool
    detail: str = ""


@runtime_checkable
class EndpointAdapter(Protocol):
    """Adapters must expose bounded, read-only collection operations."""

    @property
    def platform(self) -> str: ...

    def capabilities(self) -> list[AdapterCapability]: ...

    def collect(self, capability: str, *, limit: int = 100) -> list[dict]: ...


class AdapterRegistry:
    """Explicit registry; no auto-discovery or privileged actions."""

    def __init__(self):
        self._adapters: dict[str, EndpointAdapter] = {}

    def register(self, adapter: EndpointAdapter):
        if not isinstance(adapter.platform, str) or not adapter.platform.strip():
            raise ValueError("adapter platform identifier required")
        if adapter.platform in self._adapters:
            raise ValueError("adapter already registered for platform")
        if not callable(adapter.collect) or not callable(adapter.capabilities):
            raise TypeError("adapter must implement collect and capabilities")
        self._adapters[adapter.platform.lower()] = adapter

    def platforms(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, platform: str) -> EndpointAdapter:
        key = platform.lower()
        if key not in self._adapters:
            raise KeyError(f"No endpoint adapter registered for platform: {platform}")
        return self._adapters[key]

    def capabilities(self, platform: str) -> list[AdapterCapability]:
        return self.get(platform).capabilities()

    def collect(self, platform: str, capability: str, *, limit: int = 100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("collection limit must be between 1 and 500")
        adapter = self.get(platform)
        known = {item.name for item in adapter.capabilities() if item.available}
        if capability not in known:
            raise ValueError(f"Capability unavailable or unsupported: {capability}")
        records = adapter.collect(capability, limit=limit)
        if not isinstance(records, list) or len(records) > limit:
            raise ValueError("adapter returned invalid or unbounded records")
        if any(not isinstance(record, dict) for record in records):
            raise TypeError("adapter records must be dictionaries")
        return records

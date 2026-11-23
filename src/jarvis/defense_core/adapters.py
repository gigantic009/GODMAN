"""Capability-oriented endpoint collector contracts and event normalization."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable
from .events import Event, EventBus


@dataclass(frozen=True)
class AdapterCapability:
    name: str
    platform: str
    available: bool
    detail: str = ""

    def __post_init__(self):
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 128:
            raise ValueError("capability name must be non-empty and bounded")
        if not isinstance(self.platform, str) or not self.platform.strip() or len(self.platform) > 64:
            raise ValueError("capability platform must be non-empty and bounded")
        if not isinstance(self.available, bool):
            raise TypeError("available must be a boolean")
        if not isinstance(self.detail, str) or len(self.detail) > 512:
            raise ValueError("capability detail must be bounded")


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
        platform_name = getattr(adapter, "platform", None)
        if not isinstance(platform_name, str) or not platform_name.strip() or len(platform_name) > 64:
            raise ValueError("adapter platform identifier required")
        key = platform_name.strip().lower()
        if key in self._adapters:
            raise ValueError("adapter already registered for platform")
        if not callable(adapter.collect) or not callable(adapter.capabilities):
            raise TypeError("adapter must implement collect and capabilities")
        capabilities = adapter.capabilities()
        if not isinstance(capabilities, list) or len(capabilities) > 100:
            raise ValueError("adapter capability list must be bounded")
        names = set()
        for capability in capabilities:
            if not isinstance(capability, AdapterCapability):
                raise TypeError("adapter capabilities must be AdapterCapability objects")
            if capability.platform.strip().lower() != key:
                raise ValueError("capability platform must match its adapter")
            if capability.name in names:
                raise ValueError("duplicate adapter capability")
            names.add(capability.name)
        self._adapters[key] = adapter

    def platforms(self) -> list[str]:
        return sorted(self._adapters)

    def get(self, platform: str) -> EndpointAdapter:
        if not isinstance(platform, str) or not platform.strip():
            raise ValueError("platform identifier required")
        key = platform.strip().lower()
        if key not in self._adapters:
            raise KeyError(f"No endpoint adapter registered for platform: {platform}")
        return self._adapters[key]

    def capabilities(self, platform: str) -> list[AdapterCapability]:
        return self.get(platform).capabilities()

    def collect(self, platform: str, capability: str, *, limit: int = 100):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError("collection limit must be between 1 and 500")
        if not isinstance(capability, str) or not capability.strip():
            raise ValueError("capability identifier required")
        adapter = self.get(platform)
        available = {item.name for item in adapter.capabilities() if item.available}
        if capability not in available:
            raise ValueError(f"Capability unavailable or unsupported: {capability}")
        records = adapter.collect(capability, limit=limit)
        if not isinstance(records, list) or len(records) > limit:
            raise ValueError("adapter returned invalid or unbounded records")
        if any(not isinstance(record, dict) for record in records):
            raise TypeError("adapter records must be dictionaries")
        return records

    def collect_events(self, platform: str, capability: str, *, limit: int = 100,
                       host_id: str | None = None, event_bus: EventBus | None = None) -> list[Event]:
        records = self.collect(platform, capability, limit=limit)
        platform_name = platform.strip().lower()
        events = [Event(
            event_type=f"endpoint.{capability}",
            source=f"adapter:{platform_name}",
            data={"platform": platform_name, "capability": capability, "record": record},
            host_id=host_id,
        ) for record in records]
        if event_bus is not None:
            if not isinstance(event_bus, EventBus):
                raise TypeError("event_bus must be an EventBus")
            for event in events:
                event_bus.publish(event)
        return events

"""Normalized event model and bounded in-process event bus."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
import uuid
@dataclass(frozen=True)
class Event:
 event_type: str
 source: str
 data: dict[str, Any]
 timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
 event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
 host_id: str | None = None
 schema_version: int = 1
 def __post_init__(self):
  if not self.event_type or len(self.event_type)>128: raise ValueError("event_type must be non-empty and bounded")
  if not self.source or len(self.source)>128: raise ValueError("source must be non-empty and bounded")
  if not isinstance(self.data,dict): raise TypeError("data must be a dictionary")
  if len(self.data)>100: raise ValueError("event data has too many fields")
  if self.schema_version!=1: raise ValueError("unsupported event schema version")
class EventBus:
 """Synchronous fan-out with bounded history; subscriber errors are isolated."""
 def __init__(self,history_limit:int=1000):
  if not isinstance(history_limit,int) or isinstance(history_limit,bool) or history_limit<1: raise ValueError("history_limit must be positive")
  self.history_limit=history_limit; self._history=[]; self._subscribers=[]; self.subscriber_errors=[]
 def subscribe(self,callback:Callable[[Event],None]):
  if not callable(callback): raise TypeError("subscriber must be callable")
  if callback not in self._subscribers: self._subscribers.append(callback)
 def publish(self,event:Event)->Event:
  if not isinstance(event,Event): raise TypeError("only normalized Event instances may be published")
  self._history.append(event)
  if len(self._history)>self.history_limit: self._history=self._history[-self.history_limit:]
  for callback in tuple(self._subscribers):
   try: callback(event)
   except Exception as exc: self.subscriber_errors.append(type(exc).__name__)
  return event
 def history(self,limit:int=100)->list[Event]: return list(self._history[-max(1,min(limit,self.history_limit)):])

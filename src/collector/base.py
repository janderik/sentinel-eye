import abc
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


class CollectEvent:
    def __init__(
        self,
        source: str,
        event_type: str,
        data: dict,
        timestamp: Optional[datetime] = None,
        host: str = "localhost",
    ):
        self.source = source
        self.event_type = event_type
        self.data = data
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.host = host
        self.id: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "event_type": self.event_type,
            "data": self.data,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CollectEvent":
        return cls(
            source=d["source"],
            event_type=d["event_type"],
            data=d.get("data", {}),
            timestamp=datetime.fromisoformat(d["timestamp"]) if "timestamp" in d else None,
            host=d.get("host", "localhost"),
        )

    def __repr__(self) -> str:
        return f"<CollectEvent source={self.source} type={self.event_type} ts={self.timestamp.isoformat()}>"


class BaseCollector(abc.ABC):
    def __init__(self, name: str, config: Optional[dict] = None):
        self.name = name
        self.config = config or {}
        self._running = False
        self._event_hooks: list = []

    @property
    def is_running(self) -> bool:
        return self._running

    def add_hook(self, hook):
        self._event_hooks.append(hook)

    def on_event(self, event: CollectEvent):
        for hook in self._event_hooks:
            try:
                hook(event)
            except Exception:
                logger.exception(f"Hook {hook} failed for event {event}")

    @abc.abstractmethod
    async def start(self):
        ...

    @abc.abstractmethod
    async def stop(self):
        ...

    @abc.abstractmethod
    async def collect(self) -> Optional[CollectEvent]:
        ...

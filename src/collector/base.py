import abc
import asyncio
import inspect
import logging
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


class CollectEvent:
    def __init__(
        self,
        source: str,
        event_type: str,
        data: dict,
        timestamp: datetime | None = None,
        host: str = "localhost",
    ):
        self.source = source
        self.event_type = event_type
        self.data = data
        self.timestamp = timestamp or datetime.now(UTC)
        self.host = host
        self.id: int | None = None

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
    def __init__(self, name: str, config: dict | None = None):
        self.name = name
        self.config = config or {}
        self._running = False
        self._event_hooks: list = []
        self._pending_hooks: set[asyncio.Task] = set()
        self._queue: asyncio.Queue = asyncio.Queue(
            maxsize=int(self.config.get("queue_maxsize", 10_000))
        )

    @property
    def is_running(self) -> bool:
        return self._running

    def add_hook(self, hook):
        self._event_hooks.append(hook)

    def _enqueue(self, event: CollectEvent) -> None:
        """Put an event on the pull queue, dropping the oldest one when full."""
        if self._queue.full():
            self._queue.get_nowait()
            logger.warning("%s queue full; dropping oldest event", self.name)
        self._queue.put_nowait(event)

    async def emit(self, event: CollectEvent) -> None:
        """Run every hook for ``event``, awaiting the ones that are coroutines."""
        for hook in self._event_hooks:
            try:
                result = hook(event)
                if inspect.isawaitable(result):
                    await result
            except Exception:
                logger.exception("Hook %s failed for event %s", hook, event)

    def on_event(self, event: CollectEvent) -> None:
        """Synchronous variant of :meth:`emit` for callers outside a coroutine.

        Async hooks are scheduled on the running event loop, or run to
        completion when no loop is running.
        """
        for hook in self._event_hooks:
            try:
                result = hook(event)
                if inspect.isawaitable(result):
                    self._run_awaitable(result)
            except Exception:
                logger.exception("Hook %s failed for event %s", hook, event)

    def _run_awaitable(self, awaitable) -> None:
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(awaitable)
            return
        task = loop.create_task(awaitable)
        self._pending_hooks.add(task)
        task.add_done_callback(self._pending_hooks.discard)

    @abc.abstractmethod
    async def start(self):
        ...

    @abc.abstractmethod
    async def stop(self):
        ...

    @abc.abstractmethod
    async def collect(self) -> CollectEvent | None:
        ...

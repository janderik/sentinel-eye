from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def level(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def from_level(cls, level: int) -> "Severity":
        mapping = {0: cls.INFO, 1: cls.LOW, 2: cls.MEDIUM, 3: cls.HIGH, 4: cls.CRITICAL}
        return mapping.get(level, cls.INFO)

    def __ge__(self, other: "Severity") -> bool:
        return self.level >= other.level

    def __gt__(self, other: "Severity") -> bool:
        return self.level > other.level

    def __le__(self, other: "Severity") -> bool:
        return self.level <= other.level

    def __lt__(self, other: "Severity") -> bool:
        return self.level < other.level


class AlertStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class Alert:
    def __init__(
        self,
        rule_name: str,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        source_events: Optional[list[Any]] = None,
        event_ids: Optional[list[int]] = None,
        host: str = "unknown",
        metadata: Optional[dict] = None,
    ):
        self.rule_name = rule_name
        self.rule_id = rule_id
        self.severity = severity
        self.title = title
        self.description = description
        self.source_events = source_events or []
        self.event_ids = event_ids or []
        self.host = host
        self.metadata = metadata or {}
        self.timestamp = datetime.now(timezone.utc)
        self.status = AlertStatus.NEW
        self.id: Optional[int] = None
        self.dedup_key = self._compute_dedup_key()

    def _compute_dedup_key(self) -> str:
        raw = f"{self.rule_id}:{self.host}:{self.title}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source_events": self.source_events,
            "event_ids": self.event_ids,
            "host": self.host,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status.value,
            "dedup_key": self.dedup_key,
        }

    def __repr__(self) -> str:
        return f"<Alert {self.severity.value.upper()} {self.title} rule={self.rule_name}>"


class AlertManager:
    def __init__(self, dedup_window_seconds: int = 300):
        self._dedup_cache: dict[str, datetime] = {}
        self.dedup_window_seconds = dedup_window_seconds

    def is_duplicate(self, alert: Alert) -> bool:
        last_seen = self._dedup_cache.get(alert.dedup_key)
        if last_seen is None:
            return False
        elapsed = (datetime.now(timezone.utc) - last_seen).total_seconds()
        return elapsed < self.dedup_window_seconds

    def mark_seen(self, alert: Alert):
        self._dedup_cache[alert.dedup_key] = datetime.now(timezone.utc)

    def create_alert(
        self,
        rule_name: str,
        rule_id: str,
        severity: Severity,
        title: str,
        description: str,
        source_events: Optional[list[Any]] = None,
        event_ids: Optional[list[int]] = None,
        host: str = "unknown",
        metadata: Optional[dict] = None,
    ) -> Optional[Alert]:
        alert = Alert(
            rule_name=rule_name,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            source_events=source_events,
            event_ids=event_ids,
            host=host,
            metadata=metadata,
        )

        if self.is_duplicate(alert):
            logger.debug(f"Deduplicated alert: {alert.dedup_key}")
            return None

        self.mark_seen(alert)
        return alert

    def cleanup_cache(self):
        now = datetime.now(timezone.utc)
        expired = [
            key
            for key, ts in self._dedup_cache.items()
            if (now - ts).total_seconds() > self.dedup_window_seconds
        ]
        for key in expired:
            del self._dedup_cache[key]

import logging
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from src.collector.base import CollectEvent
from src.engine.alert import Alert, AlertManager, Severity

logger = logging.getLogger(__name__)


class CorrelationRule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        event_type: str,
        min_events: int,
        time_window_seconds: int,
        group_by: list[str] | None = None,
        filter_condition: dict | None = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.event_type = event_type
        self.min_events = min_events
        self.time_window_seconds = time_window_seconds
        self.group_by = group_by or ["data.host"]
        self.filter_condition = filter_condition or {}
        self.enabled = True

    def get_group_key(self, event: CollectEvent) -> str:
        parts = []
        for field_path in self.group_by:
            value = self._resolve_field(event, field_path)
            parts.append(str(value or "unknown"))
        return ":".join(parts)

    def _resolve_field(self, event: CollectEvent, field_path: str) -> Any:
        parts = field_path.split(".")
        obj = event.to_dict()
        for part in parts:
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            elif hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return None
        return obj

    def matches_filter(self, event: CollectEvent) -> bool:
        if self.event_type != "*" and event.event_type != self.event_type:
            return False
        for field, expected in self.filter_condition.items():
            value = self._resolve_field(event, field)
            if value != expected:
                return False
        return True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "event_type": self.event_type,
            "min_events": self.min_events,
            "time_window_seconds": self.time_window_seconds,
            "group_by": self.group_by,
            "filter_condition": self.filter_condition,
            "enabled": self.enabled,
        }


class CorrelationEngine:
    def __init__(self, alert_manager: AlertManager | None = None):
        self.rules: list[CorrelationRule] = []
        self.alert_manager = alert_manager or AlertManager()
        self._windows: dict[str, list[tuple[datetime, CollectEvent]]] = defaultdict(list)
        self._alert_hooks: list = []

    def add_rule(self, rule: CorrelationRule):
        existing = [r for r in self.rules if r.rule_id == rule.rule_id]
        if existing:
            self.rules.remove(existing[0])
        self.rules.append(rule)
        logger.info(f"Added correlation rule: {rule.name} ({rule.rule_id})")

    def add_hook(self, hook):
        self._alert_hooks.append(hook)

    def process_event(self, event: CollectEvent) -> Alert | None:
        for rule in self.rules:
            if not rule.enabled:
                continue
            if not rule.matches_filter(event):
                continue

            group_key = rule.get_group_key(event)
            window_key = f"{rule.rule_id}:{group_key}"
            now = datetime.now(UTC)
            cutoff = now - timedelta(seconds=rule.time_window_seconds)

            self._windows[window_key] = [
                (ts, ev) for ts, ev in self._windows[window_key]
                if ts > cutoff
            ]
            self._windows[window_key].append((now, event))

            if len(self._windows[window_key]) >= rule.min_events:
                events = [ev.to_dict() for _, ev in self._windows[window_key]]
                event_ids = [ev.id for _, ev in self._windows[window_key] if ev.id]

                alert = self.alert_manager.create_alert(
                    rule_name=rule.name,
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=f"Correlation match: {rule.name}",
                    description=(
                        f"{rule.description} "
                        f"[{len(self._windows[window_key])} events in "
                        f"{rule.time_window_seconds}s, group: {group_key}]"
                    ),
                    source_events=events,
                    event_ids=event_ids,
                    host=event.host,
                    metadata={
                        "correlation_rule": rule.rule_id,
                        "group_key": group_key,
                        "event_count": len(self._windows[window_key]),
                        "time_window": rule.time_window_seconds,
                    },
                )

                self._windows[window_key] = []

                if alert:
                    logger.warning(
                        f"CORRELATION ALERT [{rule.severity.value.upper()}] "
                        f"{rule.name} ({group_key})"
                    )
                    for hook in self._alert_hooks:
                        try:
                            hook(alert)
                        except Exception:
                            logger.exception("Correlation alert hook failed")
                    return alert
        return None

    def cleanup(self, max_age_seconds: int = 3600):
        now = datetime.now(UTC)
        cutoff = now - timedelta(seconds=max_age_seconds)
        expired = [key for key, events in self._windows.items()
                   if all(ts < cutoff for ts, _ in events)]
        for key in expired:
            del self._windows[key]

    def to_dict_list(self) -> list[dict]:
        return [r.to_dict() for r in self.rules]

    @staticmethod
    def brute_force_detection_rule() -> CorrelationRule:
        return CorrelationRule(
            rule_id="corr-brute-force",
            name="SSH Brute Force Detection",
            description="Multiple failed authentication attempts detected",
            severity=Severity.HIGH,
            event_type="*",
            min_events=5,
            time_window_seconds=60,
            group_by=["host"],
            filter_condition={
                "data.event_type": "syslog",
            },
        )

    @staticmethod
    def port_scan_detection_rule() -> CorrelationRule:
        return CorrelationRule(
            rule_id="corr-port-scan",
            name="Port Scan Detection",
            description="Multiple connection attempts to different ports",
            severity=Severity.MEDIUM,
            event_type="*",
            min_events=20,
            time_window_seconds=120,
            group_by=["host"],
            filter_condition={},
        )

    @staticmethod
    def beaconing_detection_rule() -> CorrelationRule:
        return CorrelationRule(
            rule_id="corr-beaconing",
            name="Malware Beaconing Detection",
            description="Periodic outbound connections detected (potential C2 beaconing)",
            severity=Severity.HIGH,
            event_type="*",
            min_events=5,
            time_window_seconds=300,
            group_by=["host"],
            filter_condition={},
        )

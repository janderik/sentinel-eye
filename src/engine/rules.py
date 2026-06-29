import fnmatch
import hashlib
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import yaml

from src.collector.base import CollectEvent
from src.engine.alert import AlertManager, Severity

logger = logging.getLogger(__name__)

SIGMA_LEVEL_MAP = {
    "informational": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class RuleCondition:
    def __init__(self, field: str, operator: str, value: Any):
        self.field = field
        self.operator = operator
        self.value = value

    def evaluate(self, event: CollectEvent) -> bool:
        actual = self._resolve_field(event)
        try:
            if self.operator == "equals":
                return actual == self.value
            elif self.operator == "not_equals":
                return actual != self.value
            elif self.operator == "contains":
                return isinstance(actual, str) and self.value in actual
            elif self.operator == "not_contains":
                return isinstance(actual, str) and self.value not in actual
            elif self.operator == "regex":
                return isinstance(actual, str) and bool(re.search(self.value, actual))
            elif self.operator == "glob":
                return isinstance(actual, str) and fnmatch.fnmatch(actual, self.value)
            elif self.operator == "gt":
                return actual is not None and actual > self.value
            elif self.operator == "gte":
                return actual is not None and actual >= self.value
            elif self.operator == "lt":
                return actual is not None and actual < self.value
            elif self.operator == "lte":
                return actual is not None and actual <= self.value
            elif self.operator == "in":
                return actual in self.value if isinstance(self.value, (list, tuple)) else False
            elif self.operator == "not_in":
                return actual not in self.value if isinstance(self.value, (list, tuple)) else False
            elif self.operator == "exists":
                return actual is not None
            elif self.operator == "not_exists":
                return actual is None
            else:
                logger.warning(f"Unknown operator: {self.operator}")
                return False
        except Exception:
            return False

    def _resolve_field(self, event: CollectEvent) -> Any:
        parts = self.field.split(".")
        if parts[0] == "event":
            obj = event
            parts = parts[1:]
        elif parts[0] == "data":
            obj = event.data
            parts = parts[1:]
        else:
            obj = event.to_dict()

        current = obj
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, dict) and part.isdigit() and int(part) < len(current):
                if isinstance(current, list):
                    current = current[int(part)]
                else:
                    return None
            elif hasattr(current, part):
                current = getattr(current, part)
            else:
                return None
        return current


class Rule:
    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        source: str,
        event_type: str,
        conditions: list[RuleCondition],
        metadata: Optional[dict] = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.source = source
        self.event_type = event_type
        self.conditions = conditions
        self.metadata = metadata or {}
        self.enabled = self.metadata.get("enabled", True)
        self.created = datetime.now(timezone.utc)

    def matches(self, event: CollectEvent) -> bool:
        if not self.enabled:
            return False
        if self.source != "*" and event.source != self.source:
            return False
        if self.event_type != "*" and event.event_type != self.event_type:
            return False
        return all(cond.evaluate(event) for cond in self.conditions)

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "event_type": self.event_type,
            "conditions": [
                {"field": c.field, "operator": c.operator, "value": c.value}
                for c in self.conditions
            ],
            "metadata": self.metadata,
            "enabled": self.enabled,
            "created": self.created.isoformat(),
        }

    @classmethod
    def from_sigma(cls, sigma_rule: dict) -> "Rule":
        rule_id = sigma_rule.get("id", hashlib.md5(
            sigma_rule.get("title", "unknown").encode()
        ).hexdigest())
        title = sigma_rule.get("title", "Unnamed Rule")
        description = sigma_rule.get("description", "")
        level = sigma_rule.get("level", "medium")
        severity = SIGMA_LEVEL_MAP.get(level, Severity.MEDIUM)
        logsource = sigma_rule.get("logsource", {})
        source = logsource.get("category", logsource.get("product", "*"))
        event_type = logsource.get("service", "*")

        detection = sigma_rule.get("detection", {})
        conditions_list = []
        selection_map = {}
        for key, value in detection.items():
            if key == "condition" or key == "timeframe":
                continue
            if isinstance(value, dict):
                for field, pattern in value.items():
                    if field == "Image" or field == "CommandLine" or field == "EventID":
                        conditions_list.append(RuleCondition(
                            field=f"data.event_data.{field}",
                            operator="equals" if not isinstance(pattern, list) else "in",
                            value=pattern,
                        ))
                    else:
                        conditions_list.append(RuleCondition(
                            field=f"data.{field}",
                            operator="equals" if not isinstance(pattern, list) else "in",
                            value=pattern,
                        ))

        metadata = {
            "sigma": True,
            "author": sigma_rule.get("author", ""),
            "references": sigma_rule.get("references", []),
            "tags": sigma_rule.get("tags", []),
            "false_positives": sigma_rule.get("falsepositives", []),
        }

        return cls(
            rule_id=rule_id,
            name=title,
            description=description,
            severity=severity,
            source=source,
            event_type=event_type,
            conditions=conditions_list,
            metadata=metadata,
        )


class RuleEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: list[Rule] = []
        self.alert_manager = AlertManager()
        self._alert_hooks: list = []

        if rules_dir:
            self.load_rules_from_directory(rules_dir)

    def add_hook(self, hook):
        self._alert_hooks.append(hook)

    def add_rule(self, rule: Rule):
        existing = [r for r in self.rules if r.rule_id == rule.rule_id]
        if existing:
            self.rules.remove(existing[0])
        self.rules.append(rule)
        logger.info(f"Added rule: {rule.name} ({rule.rule_id})")

    def remove_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.rule_id == rule_id:
                self.rules.remove(rule)
                logger.info(f"Removed rule: {rule.name} ({rule_id})")
                return True
        return False

    def load_rules_from_directory(self, directory: str):
        path = Path(directory)
        if not path.is_dir():
            logger.warning(f"Rules directory does not exist: {directory}")
            return

        for yaml_file in sorted(path.glob("**/*.yaml")) + sorted(path.glob("**/*.yml")):
            try:
                content = yaml_file.read_text(encoding="utf-8")
                rules_data = yaml.safe_load_all(content)
                for doc in rules_data:
                    if doc and isinstance(doc, dict):
                        self._load_rule_doc(doc, str(yaml_file))
            except yaml.YAMLError as e:
                logger.error(f"Failed to parse rule file {yaml_file}: {e}")
            except Exception as e:
                logger.exception(f"Error loading rule file {yaml_file}: {e}")

    def _load_rule_doc(self, doc: dict, source: str):
        try:
            if "title" in doc and "detection" in doc:
                rule = Rule.from_sigma(doc)
            elif "name" in doc:
                rule = self._from_native_format(doc)
            else:
                logger.warning(f"Unknown rule format in {source}: {list(doc.keys())}")
                return
            self.add_rule(rule)
        except Exception:
            logger.exception(f"Failed to load rule from {source}")

    def _from_native_format(self, doc: dict) -> Rule:
        rule_id = doc.get("id", doc.get("rule_id", hashlib.md5(
            doc.get("name", "unknown").encode()
        ).hexdigest()))
        conditions = []
        for cond in doc.get("conditions", []):
            conditions.append(RuleCondition(
                field=cond.get("field", ""),
                operator=cond.get("operator", "equals"),
                value=cond.get("value"),
            ))
        severity = SIGMA_LEVEL_MAP.get(doc.get("severity", "medium"), Severity.MEDIUM)
        return Rule(
            rule_id=rule_id,
            name=doc.get("name", "Unnamed"),
            description=doc.get("description", ""),
            severity=severity,
            source=doc.get("source", "*"),
            event_type=doc.get("event_type", "*"),
            conditions=conditions,
            metadata=doc.get("metadata", {}),
        )

    def process_event(self, event: CollectEvent) -> Optional[Any]:
        for rule in self.rules:
            try:
                if rule.matches(event):
                    alert = self.alert_manager.create_alert(
                        rule_name=rule.name,
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=f"Rule match: {rule.name}",
                        description=rule.description,
                        source_events=[event.to_dict()],
                        event_ids=[event.id] if event.id else [],
                        host=event.host,
                        metadata={
                            "event_source": event.source,
                            "event_type": event.event_type,
                            "rule_id": rule.rule_id,
                        },
                    )
                    if alert:
                        logger.warning(
                            f"ALERT [{rule.severity.value.upper()}] {rule.name} "
                            f"on {event.host}"
                        )
                        for hook in self._alert_hooks:
                            try:
                                hook(alert)
                            except Exception:
                                logger.exception(f"Alert hook failed")
                        return alert
            except Exception:
                logger.exception(f"Error processing rule {rule.name} for event")
        return None

    def to_dict_list(self) -> list[dict]:
        return [r.to_dict() for r in self.rules]

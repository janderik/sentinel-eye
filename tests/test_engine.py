import pytest

from src.collector.base import CollectEvent
from src.engine.alert import Alert, AlertManager, Severity
from src.engine.correlator import CorrelationEngine, CorrelationRule
from src.engine.rules import Rule, RuleCondition, RuleEngine


class TestSeverity:
    def test_levels(self):
        assert Severity.INFO.level == 0
        assert Severity.LOW.level == 1
        assert Severity.MEDIUM.level == 2
        assert Severity.HIGH.level == 3
        assert Severity.CRITICAL.level == 4

    def test_comparisons(self):
        assert Severity.LOW < Severity.MEDIUM
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.INFO <= Severity.INFO
        assert Severity.CRITICAL >= Severity.HIGH

    def test_from_level(self):
        assert Severity.from_level(0) == Severity.INFO
        assert Severity.from_level(4) == Severity.CRITICAL


class TestAlert:
    def test_create_alert(self):
        alert = Alert(
            rule_name="test-rule",
            rule_id="rule-001",
            severity=Severity.HIGH,
            title="Test Alert",
            description="A test alert",
            host="server-01",
        )
        assert alert.rule_name == "test-rule"
        assert alert.severity == Severity.HIGH
        assert alert.dedup_key is not None

    def test_alert_to_dict(self):
        alert = Alert(
            rule_name="test", rule_id="r1", severity=Severity.MEDIUM,
            title="Test", description="Desc", host="h1",
        )
        d = alert.to_dict()
        assert d["rule_name"] == "test"
        assert d["severity"] == "medium"
        assert d["status"] == "new"

    def test_different_dedup_keys(self):
        a1 = Alert("r1", "id1", Severity.HIGH, "title", "desc", host="h1")
        a2 = Alert("r2", "id2", Severity.LOW, "title2", "desc2", host="h2")
        assert a1.dedup_key != a2.dedup_key


class TestAlertManager:
    def test_deduplication(self):
        manager = AlertManager(dedup_window_seconds=60)
        alert = Alert("rule", "id", Severity.MEDIUM, "title", "desc", host="h1")
        assert not manager.is_duplicate(alert)
        manager.mark_seen(alert)
        assert manager.is_duplicate(alert)

    def test_create_alert_with_dedup(self):
        manager = AlertManager(dedup_window_seconds=60)
        a1 = manager.create_alert("rule1", "id1", Severity.HIGH, "title", "desc", host="h1")
        assert a1 is not None
        a2 = manager.create_alert("rule1", "id1", Severity.HIGH, "title", "desc", host="h1")
        assert a2 is None

    def test_cleanup_cache(self):
        manager = AlertManager(dedup_window_seconds=0)
        alert = Alert("rule", "id", Severity.INFO, "t", "d", host="h")
        manager.mark_seen(alert)
        manager.cleanup_cache()
        assert alert.dedup_key not in manager._dedup_cache


class TestRuleCondition:
    def make_event(self, **overrides):
        data = {"event_type": "test", "host": "server1", "value": 42, "status": "failed"}
        data.update(overrides)
        return CollectEvent(source="test", event_type="test_event", data=data, host="server1")

    def test_equals(self):
        cond = RuleCondition("data.host", "equals", "server1")
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.host", "equals", "server2")
        assert not cond2.evaluate(self.make_event())

    def test_contains(self):
        cond = RuleCondition("data.status", "contains", "fail")
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.status", "contains", "success")
        assert not cond2.evaluate(self.make_event())

    def test_exists(self):
        cond = RuleCondition("data.value", "exists", None)
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.missing", "exists", None)
        assert not cond2.evaluate(self.make_event())

    def test_greater_than(self):
        cond = RuleCondition("data.value", "gt", 10)
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.value", "gt", 100)
        assert not cond2.evaluate(self.make_event())

    def test_regex(self):
        cond = RuleCondition("data.host", "regex", r"^server\d+$")
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.host", "regex", r"^desktop\d+$")
        assert not cond2.evaluate(self.make_event())

    def test_in_list(self):
        cond = RuleCondition("data.host", "in", ["server1", "server2"])
        assert cond.evaluate(self.make_event())
        cond2 = RuleCondition("data.host", "in", ["server3", "server4"])
        assert not cond2.evaluate(self.make_event())


class TestRuleEngine:
    def make_event(self, source="test", event_type="test_event", **data):
        return CollectEvent(
            source=source,
            event_type=event_type,
            data=data,
            host="server1",
        )

    def test_simple_rule_match(self):
        engine = RuleEngine()
        rule = Rule(
            rule_id="test-1",
            name="Test Rule",
            description="A test rule",
            severity=Severity.MEDIUM,
            source="test",
            event_type="test_event",
            conditions=[RuleCondition("data.host", "equals", "server1")],
        )
        engine.add_rule(rule)
        event = self.make_event(host="server1", extra="data")
        alert = engine.process_event(event)
        assert alert is not None
        assert alert.rule_id == "test-1"
        assert alert.severity == Severity.MEDIUM

    def test_no_match(self):
        engine = RuleEngine()
        rule = Rule(
            rule_id="test-2",
            name="No Match",
            description="Should not match",
            severity=Severity.LOW,
            source="other",
            event_type="*",
            conditions=[],
        )
        engine.add_rule(rule)
        event = self.make_event(source="test")
        alert = engine.process_event(event)
        assert alert is None

    def test_multiple_conditions(self):
        engine = RuleEngine()
        rule = Rule(
            rule_id="test-3",
            name="Multi Condition",
            description="",
            severity=Severity.HIGH,
            source="test",
            event_type="*",
            conditions=[
                RuleCondition("data.host", "equals", "server1"),
                RuleCondition("data.value", "gt", 10),
            ],
        )
        engine.add_rule(rule)

        match_event = self.make_event(host="server1", value=42)
        alert = engine.process_event(match_event)
        assert alert is not None

        no_match_event = self.make_event(host="server1", value=5)
        alert2 = engine.process_event(no_match_event)
        assert alert2 is None

    def test_rule_from_sigma(self):
        sigma = {
            "title": "Test Sigma Rule",
            "id": "sigma-001",
            "description": "Sigma format test",
            "level": "high",
            "logsource": {"category": "process_creation", "product": "windows"},
            "detection": {
                "selection": {"Image": "powershell.exe", "CommandLine": "test"},
                "condition": "selection",
            },
        }
        rule = Rule.from_sigma(sigma)
        assert rule.name == "Test Sigma Rule"
        assert rule.severity == Severity.HIGH
        assert rule.rule_id == "sigma-001"


class TestCorrelationEngine:
    def make_event(self, source="test_source", event_type="login_failed", host="server1"):
        return CollectEvent(
            source=source,
            event_type=event_type,
            data={"host": host, "user": "admin"},
            host=host,
        )

    def test_brute_force_correlation(self):
        engine = CorrelationEngine()
        rule = CorrelationRule(
            rule_id="corr-test",
            name="Test Correlation",
            description="Test",
            severity=Severity.HIGH,
            event_type="login_failed",
            min_events=3,
            time_window_seconds=60,
            group_by=["host"],
        )
        engine.add_rule(rule)

        for _ in range(2):
            alert = engine.process_event(self.make_event())
            assert alert is None

        alert = engine.process_event(self.make_event())
        assert alert is not None
        assert alert.rule_id == "corr-test"
        assert alert.severity == Severity.HIGH

    def test_filter_condition(self):
        engine = CorrelationEngine()
        rule = CorrelationRule(
            rule_id="corr-filter",
            name="Filtered",
            description="",
            severity=Severity.MEDIUM,
            event_type="*",
            min_events=2,
            time_window_seconds=60,
            group_by=["host"],
            filter_condition={"data.user": "admin"},
        )
        engine.add_rule(rule)

        event = self.make_event()
        event.data["user"] = "admin"
        engine.process_event(event)
        alert = engine.process_event(event)
        assert alert is not None

        event2 = self.make_event()
        event2.data["user"] = "guest"
        engine.process_event(event2)
        assert engine.process_event(event2) is None

    def test_default_rules(self):
        br = CorrelationEngine.brute_force_detection_rule()
        assert br.rule_id == "corr-brute-force"
        assert br.min_events == 5
        assert br.time_window_seconds == 60

        ps = CorrelationEngine.port_scan_detection_rule()
        assert ps.rule_id == "corr-port-scan"
        assert ps.min_events == 20

        be = CorrelationEngine.beaconing_detection_rule()
        assert be.rule_id == "corr-beaconing"
        assert be.min_events == 5

from src.storage.database import DatabaseManager, RuleModel


def make_db() -> DatabaseManager:
    db = DatabaseManager("sqlite:///:memory:")
    db.create_tables()
    return db


def test_alert_metadata_roundtrip():
    db = make_db()
    alert_id = db.insert_alert(
        {
            "rule_name": "Brute force",
            "rule_id": "R-001",
            "severity": "high",
            "title": "Multiple failed logins",
            "host": "srv-01",
            "metadata": {"attempts": 12, "user": "admin"},
        }
    )
    alert = db.get_alert(alert_id)
    assert alert is not None
    assert alert["metadata"] == {"attempts": 12, "user": "admin"}


def test_rule_upsert_updates_metadata():
    db = make_db()
    rule = {"rule_id": "R-002", "name": "Test rule", "metadata": {"version": 1}}
    db.insert_rule(rule)
    db.insert_rule({**rule, "metadata": {"version": 2}})

    with db.session() as session:
        stored = session.query(RuleModel).filter_by(rule_id="R-002").one()
        assert stored.to_dict()["metadata"] == {"version": 2}

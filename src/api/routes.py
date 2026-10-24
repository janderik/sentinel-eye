import logging

from fastapi import APIRouter, HTTPException, Query

from src.engine.alert import Severity
from src.engine.rules import Rule, RuleCondition, RuleEngine
from src.storage.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter()
_rule_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _rule_engine
    if _rule_engine is None:
        _rule_engine = RuleEngine()
    return _rule_engine


@router.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "sentinel-eye",
        "version": "0.1.0",
    }


@router.get("/events")
async def list_events(
    source: str | None = Query(None, description="Filter by source"),
    event_type: str | None = Query(None, description="Filter by event type"),
    host: str | None = Query(None, description="Filter by host"),
    limit: int = Query(100, ge=1, le=1000, description="Number of results"),
    offset: int = Query(0, ge=0, description="Result offset"),
):
    db = get_db()
    events = db.query_events(
        source=source,
        event_type=event_type,
        host=host,
        limit=limit,
        offset=offset,
    )
    return {"total": len(events), "events": events}


@router.get("/events/{event_id}")
async def get_event(event_id: int):
    db = get_db()
    event = db.get_event(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/alerts")
async def list_alerts(
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
    rule_id: str | None = Query(None, description="Filter by rule ID"),
    limit: int = Query(100, ge=1, le=1000, description="Number of results"),
    offset: int = Query(0, ge=0, description="Result offset"),
):
    db = get_db()
    alerts = db.query_alerts(
        severity=severity,
        status=status,
        rule_id=rule_id,
        limit=limit,
        offset=offset,
    )
    return {"total": len(alerts), "alerts": alerts}


@router.get("/alerts/{alert_id}")
async def get_alert(alert_id: int):
    db = get_db()
    alert = db.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.put("/alerts/{alert_id}/status")
async def update_alert_status(alert_id: int, status: str = Query(..., description="New status")):
    valid_statuses = {"new", "in_progress", "resolved", "dismissed"}
    if status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}",
        )
    db = get_db()
    success = db.update_alert_status(alert_id, status)
    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "updated", "alert_id": alert_id, "new_status": status}


@router.get("/rules")
async def list_rules():
    engine = get_rule_engine()
    return {"total": len(engine.rules), "rules": engine.to_dict_list()}


@router.post("/rules")
async def create_rule(rule_data: dict):
    required = {"name", "source", "event_type", "conditions"}
    missing = required - set(rule_data.keys())
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing required fields: {', '.join(sorted(missing))}",
        )
    try:
        conditions = []
        for cond in rule_data["conditions"]:
            if not all(k in cond for k in ("field", "operator", "value")):
                raise ValueError("Each condition must have 'field', 'operator', and 'value'")
            conditions.append(RuleCondition(
                field=cond["field"],
                operator=cond["operator"],
                value=cond["value"],
            ))
        rule = Rule(
            rule_id=rule_data.get("rule_id", f"custom-{len(get_rule_engine().rules) + 1}"),
            name=rule_data["name"],
            description=rule_data.get("description", ""),
            severity=Severity(rule_data.get("severity", "medium")),
            source=rule_data["source"],
            event_type=rule_data["event_type"],
            conditions=conditions,
            metadata=rule_data.get("metadata", {}),
        )
        engine = get_rule_engine()
        engine.add_rule(rule)

        db = get_db()
        db.insert_rule(rule.to_dict())

        return {"status": "created", "rule": rule.to_dict()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@router.get("/stats")
async def get_stats():
    db = get_db()
    stats = db.get_stats()
    engine = get_rule_engine()
    stats["active_rules"] = len(engine.rules)
    return stats

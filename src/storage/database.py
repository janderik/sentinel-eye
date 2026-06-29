from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, create_engine
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()


class EventModel(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    source = Column(String(255), nullable=False, index=True)
    event_type = Column(String(255), nullable=False, index=True)
    data = Column(Text, nullable=False, default="{}")
    host = Column(String(255), nullable=False, default="localhost", index=True)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "event_type": self.event_type,
            "data": json.loads(self.data) if isinstance(self.data, str) else self.data,
            "host": self.host,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertModel(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_name = Column(String(255), nullable=False, index=True)
    rule_id = Column(String(255), nullable=False, index=True)
    severity = Column(String(20), nullable=False, default="medium", index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    source_events = Column(Text, nullable=True, default="[]")
    event_ids = Column(Text, nullable=True, default="[]")
    host = Column(String(255), nullable=False, default="unknown", index=True)
    metadata = Column(Text, nullable=True, default="{}")
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String(20), nullable=False, default="new", index=True)
    dedup_key = Column(String(64), nullable=True, index=True)
    resolved_at = Column(DateTime, nullable=True)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_events": json.loads(self.source_events) if isinstance(self.source_events, str) else self.source_events,
            "event_ids": json.loads(self.event_ids) if isinstance(self.event_ids, str) else self.event_ids,
            "host": self.host,
            "metadata": json.loads(self.metadata) if isinstance(self.metadata, str) else self.metadata,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status": self.status,
            "dedup_key": self.dedup_key,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class RuleModel(Base):
    __tablename__ = "rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="medium")
    source = Column(String(255), nullable=False, default="*")
    event_type = Column(String(255), nullable=False, default="*")
    conditions = Column(Text, nullable=False, default="[]")
    metadata = Column(Text, nullable=True, default="{}")
    enabled = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "event_type": self.event_type,
            "conditions": json.loads(self.conditions) if isinstance(self.conditions, str) else self.conditions,
            "metadata": json.loads(self.metadata) if isinstance(self.metadata, str) else self.metadata,
            "enabled": bool(self.enabled),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DatabaseManager:
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv(
            "SENTINEL_DB_URL",
            f"sqlite:///{os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'sentinel.db')}",
        )
        self._engine = create_engine(
            self.db_url,
            echo=False,
            connect_args={"check_same_thread": False} if "sqlite" in self.db_url else {},
        )
        self._session_factory = scoped_session(
            sessionmaker(autocommit=False, autoflush=False, bind=self._engine)
        )

    def create_tables(self):
        Base.metadata.create_all(bind=self._engine)
        logger.info("Database tables created")

    @contextmanager
    def session(self) -> Generator[Any, None, None]:
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def insert_event(self, event_dict: dict) -> int:
        with self.session() as session:
            model = EventModel(
                source=event_dict.get("source", ""),
                event_type=event_dict.get("event_type", ""),
                data=json.dumps(event_dict.get("data", {}), default=str),
                host=event_dict.get("host", "localhost"),
                timestamp=(
                    datetime.fromisoformat(event_dict["timestamp"])
                    if isinstance(event_dict.get("timestamp"), str)
                    else event_dict.get("timestamp", datetime.now(timezone.utc))
                ),
            )
            session.add(model)
            session.flush()
            event_id = model.id
            return event_id

    def insert_alert(self, alert_dict: dict) -> int:
        with self.session() as session:
            model = AlertModel(
                rule_name=alert_dict.get("rule_name", ""),
                rule_id=alert_dict.get("rule_id", ""),
                severity=alert_dict.get("severity", "medium"),
                title=alert_dict.get("title", ""),
                description=alert_dict.get("description"),
                source_events=json.dumps(alert_dict.get("source_events", []), default=str),
                event_ids=json.dumps(alert_dict.get("event_ids", []), default=str),
                host=alert_dict.get("host", "unknown"),
                metadata=json.dumps(alert_dict.get("metadata", {}), default=str),
                timestamp=(
                    datetime.fromisoformat(alert_dict["timestamp"])
                    if isinstance(alert_dict.get("timestamp"), str)
                    else alert_dict.get("timestamp", datetime.now(timezone.utc))
                ),
                status=alert_dict.get("status", "new"),
                dedup_key=alert_dict.get("dedup_key"),
            )
            session.add(model)
            session.flush()
            return model.id

    def insert_rule(self, rule_dict: dict) -> int:
        with self.session() as session:
            existing = session.query(RuleModel).filter_by(
                rule_id=rule_dict.get("rule_id", "")
            ).first()
            if existing:
                for key, value in rule_dict.items():
                    if key == "conditions":
                        value = json.dumps(value, default=str)
                    elif key == "metadata":
                        value = json.dumps(value, default=str)
                    elif key == "enabled":
                        value = 1 if value else 0
                    setattr(existing, key, value)
                session.flush()
                return existing.id
            model = RuleModel(
                rule_id=rule_dict.get("rule_id", ""),
                name=rule_dict.get("name", ""),
                description=rule_dict.get("description"),
                severity=rule_dict.get("severity", "medium"),
                source=rule_dict.get("source", "*"),
                event_type=rule_dict.get("event_type", "*"),
                conditions=json.dumps(rule_dict.get("conditions", []), default=str),
                metadata=json.dumps(rule_dict.get("metadata", {}), default=str),
                enabled=1 if rule_dict.get("enabled", True) else 0,
            )
            session.add(model)
            session.flush()
            return model.id

    def query_events(
        self,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        host: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self.session() as session:
            query = session.query(EventModel)
            if source:
                query = query.filter(EventModel.source == source)
            if event_type:
                query = query.filter(EventModel.event_type == event_type)
            if host:
                query = query.filter(EventModel.host == host)
            query = query.order_by(EventModel.timestamp.desc()).limit(limit).offset(offset)
            return [m.to_dict() for m in query.all()]

    def query_alerts(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        with self.session() as session:
            query = session.query(AlertModel)
            if severity:
                query = query.filter(AlertModel.severity == severity)
            if status:
                query = query.filter(AlertModel.status == status)
            if rule_id:
                query = query.filter(AlertModel.rule_id == rule_id)
            query = query.order_by(AlertModel.timestamp.desc()).limit(limit).offset(offset)
            return [m.to_dict() for m in query.all()]

    def get_alert(self, alert_id: int) -> Optional[dict]:
        with self.session() as session:
            model = session.query(AlertModel).filter_by(id=alert_id).first()
            return model.to_dict() if model else None

    def get_event(self, event_id: int) -> Optional[dict]:
        with self.session() as session:
            model = session.query(EventModel).filter_by(id=event_id).first()
            return model.to_dict() if model else None

    def update_alert_status(self, alert_id: int, status: str) -> bool:
        with self.session() as session:
            model = session.query(AlertModel).filter_by(id=alert_id).first()
            if not model:
                return False
            model.status = status
            if status in ("resolved", "dismissed"):
                model.resolved_at = datetime.now(timezone.utc)
            return True

    def get_stats(self) -> dict:
        with self.session() as session:
            from sqlalchemy import func
            total_events = session.query(func.count(EventModel.id)).scalar() or 0
            total_alerts = session.query(func.count(AlertModel.id)).scalar() or 0
            new_alerts = session.query(func.count(AlertModel.id)).filter(
                AlertModel.status == "new"
            ).scalar() or 0
            critical_alerts = session.query(func.count(AlertModel.id)).filter(
                AlertModel.severity == "critical"
            ).scalar() or 0
            return {
                "total_events": total_events,
                "total_alerts": total_alerts,
                "new_alerts": new_alerts,
                "critical_alerts": critical_alerts,
            }


_db_manager: Optional[DatabaseManager] = None


def get_db() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
        _db_manager.create_tables()
    return _db_manager


@contextmanager
def get_session():
    with get_db().session() as session:
        yield session

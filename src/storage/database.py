from __future__ import annotations

import json
import logging
import os
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Text, create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    scoped_session,
    sessionmaker,
)

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "data", "sentinel.db")


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _loads(value: str | None, default: Any) -> Any:
    return json.loads(value) if value else default


class Base(DeclarativeBase):
    pass


class EventModel(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(255), index=True)
    event_type: Mapped[str] = mapped_column(String(255), index=True)
    data: Mapped[str] = mapped_column(Text, default="{}")
    host: Mapped[str] = mapped_column(String(255), default="localhost", index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source": self.source,
            "event_type": self.event_type,
            "data": _loads(self.data, {}),
            "host": self.host,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class AlertModel(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(String(255), index=True)
    rule_id: Mapped[str] = mapped_column(String(255), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium", index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    source_events: Mapped[str | None] = mapped_column(Text, default="[]")
    event_ids: Mapped[str | None] = mapped_column(Text, default="[]")
    host: Mapped[str] = mapped_column(String(255), default="unknown", index=True)
    # "metadata" is reserved by SQLAlchemy's declarative API; keep the DB column name.
    meta: Mapped[str | None] = mapped_column("metadata", Text, default="{}")
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utcnow, index=True)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    dedup_key: Mapped[str | None] = mapped_column(String(64), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_name": self.rule_name,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_events": _loads(self.source_events, []),
            "event_ids": _loads(self.event_ids, []),
            "host": self.host,
            "metadata": _loads(self.meta, {}),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "status": self.status,
            "dedup_key": self.dedup_key,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


class RuleModel(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    source: Mapped[str] = mapped_column(String(255), default="*")
    event_type: Mapped[str] = mapped_column(String(255), default="*")
    conditions: Mapped[str] = mapped_column(Text, default="[]")
    # "metadata" is reserved by SQLAlchemy's declarative API; keep the DB column name.
    meta: Mapped[str | None] = mapped_column("metadata", Text, default="{}")
    enabled: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "source": self.source,
            "event_type": self.event_type,
            "conditions": _loads(self.conditions, []),
            "metadata": _loads(self.meta, {}),
            "enabled": bool(self.enabled),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class DatabaseManager:
    def __init__(self, db_url: str | None = None):
        self.db_url: str = db_url or os.getenv("SENTINEL_DB_URL") or f"sqlite:///{DEFAULT_DB_PATH}"
        is_sqlite = self.db_url.startswith("sqlite")
        if is_sqlite and self.db_url.startswith("sqlite:///") and ":memory:" not in self.db_url:
            os.makedirs(os.path.dirname(os.path.abspath(self.db_url[len("sqlite:///"):])), exist_ok=True)
        self._engine = create_engine(
            self.db_url,
            echo=False,
            connect_args={"check_same_thread": False} if is_sqlite else {},
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
                    else event_dict.get("timestamp", datetime.now(UTC))
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
                meta=json.dumps(alert_dict.get("metadata", {}), default=str),
                timestamp=(
                    datetime.fromisoformat(alert_dict["timestamp"])
                    if isinstance(alert_dict.get("timestamp"), str)
                    else alert_dict.get("timestamp", datetime.now(UTC))
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
                        key = "meta"
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
                meta=json.dumps(rule_dict.get("metadata", {}), default=str),
                enabled=1 if rule_dict.get("enabled", True) else 0,
            )
            session.add(model)
            session.flush()
            return model.id

    def query_events(
        self,
        source: str | None = None,
        event_type: str | None = None,
        host: str | None = None,
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
        severity: str | None = None,
        status: str | None = None,
        rule_id: str | None = None,
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

    def get_alert(self, alert_id: int) -> dict | None:
        with self.session() as session:
            model = session.query(AlertModel).filter_by(id=alert_id).first()
            return model.to_dict() if model else None

    def get_event(self, event_id: int) -> dict | None:
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
                model.resolved_at = datetime.now(UTC)
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


_db_manager: DatabaseManager | None = None


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

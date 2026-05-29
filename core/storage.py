"""SQLite storage layer for scan results and audit logs."""

import json
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from sqlalchemy import DateTime, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from config.settings import settings
from core.models import AuditLogEntry, ScanResult


class Base(DeclarativeBase):
    """Base class for all ORM models."""

    pass


class ScanRecord(Base):
    """Persisted scan result."""

    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String)
    target: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    started_at: Mapped[datetime] = mapped_column(DateTime)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    result_json: Mapped[str] = mapped_column(Text)
    metadata_json: Mapped[str] = mapped_column(Text)


class AuditRecord(Base):
    """Persisted audit log entry."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime)
    event: Mapped[str] = mapped_column(String)
    target: Mapped[str | None] = mapped_column(String, nullable=True)
    user: Mapped[str] = mapped_column(String)
    details_json: Mapped[str] = mapped_column(Text)


_engine = None


def get_engine():
    """Return a cached SQLAlchemy engine for the configured SQLite database."""
    global _engine
    if _engine is None:
        db_path = Path(settings.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{db_path}", echo=False)
    return _engine


def init_db() -> None:
    """Create all tables if they do not already exist."""
    Base.metadata.create_all(bind=get_engine())


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a transactional SQLAlchemy session with automatic commit/rollback."""
    session = Session(bind=get_engine())
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def save_scan(result: ScanResult) -> None:
    """Persist a ``ScanResult`` to the database."""
    with get_session() as session:
        record = ScanRecord(
            scan_id=result.scan_id,
            scan_type=result.scan_type.value,
            target=result.target,
            status=result.status.value,
            started_at=result.started_at,
            completed_at=result.completed_at,
            result_json=result.model_dump_json(),
            metadata_json=json.dumps(result.metadata),
        )
        session.merge(record)


def get_scan(scan_id: str) -> ScanResult | None:
    """Load a ``ScanResult`` by its primary key, or return ``None``."""
    with get_session() as session:
        record = session.get(ScanRecord, scan_id)
        if record is None:
            return None
        return ScanResult.model_validate_json(record.result_json)


def list_scans(
    limit: int = 50, scan_type: str | None = None
) -> list[ScanResult]:
    """Return the most recent scans, optionally filtered by type."""
    with get_session() as session:
        stmt = (
            select(ScanRecord)
            .order_by(ScanRecord.started_at.desc())
            .limit(limit)
        )
        if scan_type is not None:
            stmt = stmt.where(ScanRecord.scan_type == scan_type)
        records = session.scalars(stmt).all()
        return [ScanResult.model_validate_json(r.result_json) for r in records]


def log_audit(entry: AuditLogEntry) -> None:
    """Append an ``AuditLogEntry`` to the audit log table."""
    with get_session() as session:
        record = AuditRecord(
            timestamp=entry.timestamp,
            event=entry.event,
            target=entry.target,
            user=entry.user,
            details_json=json.dumps(entry.details),
        )
        session.add(record)

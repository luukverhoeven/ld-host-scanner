"""SQLAlchemy database models."""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Index,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class Scan(Base):
    """Scan result record."""

    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), unique=True, nullable=False, index=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(20), nullable=False)  # 'tcp', 'udp', 'full'
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False)  # 'running', 'completed', 'failed'
    host_status = Column(String(20), nullable=True)  # 'up', 'down'
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    ports = relationship("Port", back_populates="scan", cascade="all, delete-orphan")
    changes = relationship("PortChange", back_populates="scan", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scans_target", "target"),
        Index("idx_scans_started", "started_at"),
    )


class Port(Base):
    """Discovered port record."""

    __tablename__ = "ports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)  # 'tcp', 'udp'
    state = Column(String(20), nullable=False)  # 'open', 'filtered', 'closed'
    service = Column(String(100), nullable=True)
    version = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="ports")

    __table_args__ = (
        Index("idx_ports_scan_id", "scan_id"),
        Index("idx_ports_state", "state"),
    )


class PortChange(Base):
    """Port change history for alerting."""

    __tablename__ = "port_changes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), ForeignKey("scans.scan_id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), nullable=False)
    change_type = Column(String(20), nullable=False)  # 'opened', 'closed'
    previous_state = Column(String(20), nullable=True)
    new_state = Column(String(20), nullable=True)
    service = Column(String(100), nullable=True)
    detected_at = Column(DateTime, default=datetime.utcnow)
    notified = Column(Boolean, default=False)

    # Relationships
    scan = relationship("Scan", back_populates="changes")

    __table_args__ = (
        Index("idx_changes_scan_id", "scan_id"),
    )


class Notification(Base):
    """Notification audit log."""

    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(36), nullable=True)
    notification_type = Column(String(20), nullable=False)  # 'email', 'webhook'
    subject = Column(String(255), nullable=True)
    message = Column(Text, nullable=True)
    status = Column(String(20), nullable=False)  # 'sent', 'failed'
    error_message = Column(Text, nullable=True)
    sent_at = Column(DateTime, default=datetime.utcnow)

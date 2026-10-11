import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    String,
    Float,
    Boolean,
    Integer,
    DateTime,
    ForeignKey,
    JSON,
    Index
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from storage.db import Base


class AuditSessionModel(Base):
    __tablename__ = "audit_sessions"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    total_proxies: Mapped[int] = mapped_column(Integer, default=0)
    alive_proxies: Mapped[int] = mapped_column(Integer, default=0)
    ashburn_routes: Mapped[int] = mapped_column(Integer, default=0)
    god_tier_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(32), default="IN_PROGRESS")

    metrics: Mapped[list["ProxyMetricModel"]] = relationship(
        "ProxyMetricModel",
        back_populates="session",
        cascade="all, delete-orphan"
    )


class ProxyMetricModel(Base):
    __tablename__ = "proxy_metrics"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4())
    )
    session_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("audit_sessions.id", ondelete="CASCADE"),
        nullable=False
    )
    proxy_endpoint: Mapped[str] = mapped_column(String(255), nullable=False)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    error_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)

    colo_code: Mapped[str | None] = mapped_column(String(8), nullable=True)
    colo_city: Mapped[str | None] = mapped_column(String(128), nullable=True)
    is_ashburn_route: Mapped[bool] = mapped_column(Boolean, default=False)

    dns_ms: Mapped[float] = mapped_column(Float, default=0.0)
    tcp_ms: Mapped[float] = mapped_column(Float, default=0.0)
    tls_ms: Mapped[float] = mapped_column(Float, default=0.0)
    ttfb_ms: Mapped[float] = mapped_column(Float, default=0.0)
    total_rtt_ms: Mapped[float] = mapped_column(Float, default=0.0)

    asn_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    asn_org: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actual_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_spoofed_residential: Mapped[bool] = mapped_column(Boolean, default=False)

    cidr_24: Mapped[str | None] = mapped_column(String(64), nullable=True)
    pool_concentration_percentage: Mapped[float] = mapped_column(Float, default=0.0)
    cascade_ban_risk_warning: Mapped[bool] = mapped_column(Boolean, default=False)

    quality_score: Mapped[float] = mapped_column(Float, default=0.0)
    tier: Mapped[str] = mapped_column(String(64), default="Discarded")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )

    session: Mapped[AuditSessionModel] = relationship(
        "AuditSessionModel",
        back_populates="metrics"
    )

    __table_args__ = (
        Index("idx_session_tier", "session_id", "tier"),
        Index("idx_proxy_endpoint", "proxy_endpoint"),
    )
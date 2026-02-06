"""
================================================================================
AI_MODULE: Analytics Models
AI_VERSION: 1.0.0
AI_DESCRIPTION: Modelli per aggregazione analytics giornaliere
AI_BUSINESS: Dashboard KPI, trend analysis, reportistica business
AI_TEACHING: Aggregazioni pre-calcolate per query veloci su dashboard

ALTERNATIVE_VALUTATE:
- Query live aggregate: Scartato, troppo lento su grandi dataset
- Time series DB (InfluxDB): Scartato, complessità infrastrutturale

PERCHÉ_QUESTA_SOLUZIONE:
- Tabella PostgreSQL semplice e affidabile
- Job notturno aggrega dati del giorno precedente
- Query dashboard istantanee (pre-aggregato)
================================================================================
"""

import uuid
from datetime import datetime, date
from sqlalchemy import Column, Date, Integer, Float, DateTime, String, Text, Index

from core.database import Base
from models import GUID, JSONBType


class AnalyticsDaily(Base):
    """
    🎯 ANALYTICS: Aggregazioni giornaliere per dashboard e reportistica

    Ogni riga = statistiche di un singolo giorno
    Popolata da daily_analytics_job alle 02:00

    💡 Struttura ottimizzata per:
    - Query rapide per range di date
    - Trend analysis (confronto giorni)
    - Export report CSV/Excel
    """
    __tablename__ = "analytics_daily"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === DATE REFERENCE ===
    # 💡 Date (non DateTime) perché aggreghiamo per giorno intero
    report_date = Column(Date, nullable=False, unique=True, index=True)

    # === USER METRICS ===
    new_users = Column(Integer, default=0, nullable=False)
    active_users = Column(Integer, default=0, nullable=False)  # Utenti con almeno 1 view
    total_users = Column(Integer, default=0, nullable=False)   # Conteggio cumulativo

    # === VIDEO METRICS ===
    total_views = Column(Integer, default=0, nullable=False)
    unique_videos_watched = Column(Integer, default=0, nullable=False)
    total_watch_time_seconds = Column(Integer, default=0, nullable=False)
    completed_videos = Column(Integer, default=0, nullable=False)  # Videos watched to end

    # === DOWNLOAD METRICS ===
    new_downloads = Column(Integer, default=0, nullable=False)
    completed_downloads = Column(Integer, default=0, nullable=False)
    expired_downloads = Column(Integer, default=0, nullable=False)

    # === ADS METRICS ===
    ads_sessions_started = Column(Integer, default=0, nullable=False)
    ads_sessions_completed = Column(Integer, default=0, nullable=False)
    ads_revenue_estimated = Column(Float, default=0.0, nullable=False)

    # === ENGAGEMENT METRICS ===
    push_notifications_sent = Column(Integer, default=0, nullable=False)
    notifications_read = Column(Integer, default=0, nullable=False)

    # === SUBSCRIPTION METRICS ===
    new_subscriptions = Column(Integer, default=0, nullable=False)
    cancelled_subscriptions = Column(Integer, default=0, nullable=False)
    subscription_revenue = Column(Float, default=0.0, nullable=False)

    # === SYSTEM METRICS ===
    api_requests_total = Column(Integer, default=0, nullable=False)
    api_errors_total = Column(Integer, default=0, nullable=False)
    avg_response_time_ms = Column(Float, default=0.0, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, onupdate=datetime.utcnow, nullable=True)

    # 💡 JSON blob per metriche aggiuntive senza modificare schema
    extra_metrics = Column(JSONBType(), default=dict, nullable=False)

    __table_args__ = (
        Index('idx_analytics_date_range', 'report_date'),
    )

    def to_dict(self) -> dict:
        """Serializza per API response."""
        return {
            "id": str(self.id),
            "report_date": self.report_date.isoformat(),
            "users": {
                "new": self.new_users,
                "active": self.active_users,
                "total": self.total_users,
            },
            "videos": {
                "total_views": self.total_views,
                "unique_watched": self.unique_videos_watched,
                "watch_time_hours": round(self.total_watch_time_seconds / 3600, 2),
                "completed": self.completed_videos,
            },
            "downloads": {
                "new": self.new_downloads,
                "completed": self.completed_downloads,
                "expired": self.expired_downloads,
            },
            "ads": {
                "sessions_started": self.ads_sessions_started,
                "sessions_completed": self.ads_sessions_completed,
                "revenue_estimated": round(self.ads_revenue_estimated, 2),
            },
            "engagement": {
                "notifications_sent": self.push_notifications_sent,
                "notifications_read": self.notifications_read,
            },
            "subscriptions": {
                "new": self.new_subscriptions,
                "cancelled": self.cancelled_subscriptions,
                "revenue": round(self.subscription_revenue, 2),
            },
            "system": {
                "api_requests": self.api_requests_total,
                "api_errors": self.api_errors_total,
                "avg_response_ms": round(self.avg_response_time_ms, 2),
            },
            "extra": self.extra_metrics,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SystemHealthLog(Base):
    """
    🎯 HEALTH: Log health check per monitoring storico

    Ogni riga = un health check execution (ogni 5 minuti)

    💡 Utile per:
    - Analisi uptime storico
    - Debug problemi intermittenti
    - Grafici availability su dashboard
    """
    __tablename__ = "system_health_log"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    checked_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === SERVICE STATUS ===
    database_ok = Column(Integer, default=1, nullable=False)  # 1=OK, 0=FAIL
    redis_ok = Column(Integer, default=1, nullable=False)
    storage_ok = Column(Integer, default=1, nullable=False)
    scheduler_ok = Column(Integer, default=1, nullable=False)

    # === RESPONSE TIMES (ms) ===
    database_latency_ms = Column(Float, nullable=True)
    redis_latency_ms = Column(Float, nullable=True)
    storage_latency_ms = Column(Float, nullable=True)

    # === SYSTEM RESOURCES ===
    cpu_percent = Column(Float, nullable=True)
    memory_percent = Column(Float, nullable=True)
    disk_percent = Column(Float, nullable=True)

    # === ERROR DETAILS ===
    error_details = Column(Text, nullable=True)

    __table_args__ = (
        Index('idx_health_checked_at', 'checked_at'),
    )

    @property
    def is_healthy(self) -> bool:
        """True se tutti i servizi critici sono OK."""
        return (
            self.database_ok == 1 and
            self.redis_ok == 1 and
            self.storage_ok == 1
        )

    def to_dict(self) -> dict:
        """Serializza per API response."""
        return {
            "id": str(self.id),
            "checked_at": self.checked_at.isoformat(),
            "healthy": self.is_healthy,
            "services": {
                "database": {"ok": self.database_ok == 1, "latency_ms": self.database_latency_ms},
                "redis": {"ok": self.redis_ok == 1, "latency_ms": self.redis_latency_ms},
                "storage": {"ok": self.storage_ok == 1, "latency_ms": self.storage_latency_ms},
                "scheduler": {"ok": self.scheduler_ok == 1},
            },
            "resources": {
                "cpu_percent": self.cpu_percent,
                "memory_percent": self.memory_percent,
                "disk_percent": self.disk_percent,
            },
            "error": self.error_details,
        }

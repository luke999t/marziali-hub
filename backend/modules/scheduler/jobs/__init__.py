"""
================================================================================
AI_MODULE: Scheduler Jobs Package
AI_VERSION: 1.0.0
AI_DESCRIPTION: Modular job implementations for APScheduler maintenance tasks
AI_BUSINESS: Organized job modules for DRM cleanup, sessions, analytics, backup, health
AI_TEACHING: Package structure for maintainable job organization

PERCHÉ_QUESTA_SOLUZIONE:
- Separazione job in file singoli per manutenibilità
- Ogni job è testabile indipendentemente
- Import espliciti per tracciabilità dipendenze

FIX_2025_01_21: Aggiunto JOB_DEFINITIONS per main.py lifespan
================================================================================
"""

from .cleanup_downloads import (
    cleanup_expired_downloads_job,
    notify_expiring_downloads_job,
)
from .cleanup_sessions import (
    cleanup_expired_sessions_job,
)
from .daily_analytics import (
    daily_analytics_job,
)
from .database_backup import (
    database_backup_job,
)
from .health_check import (
    health_check_job,
)


# ============================================================================
# JOB_DEFINITIONS - Configurazione job per scheduler
# Usato da main.py per registrare automaticamente i job all'avvio
# ============================================================================

JOB_DEFINITIONS = [
    # Health Check - ogni 5 minuti
    {
        "job_id": "health_check",
        "name": "Health Check",
        "description": "Verifica stato sistema e servizi",
        "func": health_check_job,
        "trigger_type": "interval",
        "trigger_args": {"minutes": 5},
        "enabled": True,
    },
    # Cleanup Downloads - ogni ora
    {
        "job_id": "cleanup_expired_downloads",
        "name": "Cleanup Expired Downloads",
        "description": "Rimuove download DRM scaduti",
        "func": cleanup_expired_downloads_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 1},
        "enabled": True,
    },
    # Notify Expiring Downloads - ogni 6 ore
    {
        "job_id": "notify_expiring_downloads",
        "name": "Notify Expiring Downloads",
        "description": "Notifica utenti di download in scadenza",
        "func": notify_expiring_downloads_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 6},
        "enabled": True,
    },
    # Cleanup Sessions - ogni 30 minuti
    {
        "job_id": "cleanup_expired_sessions",
        "name": "Cleanup Expired Sessions",
        "description": "Rimuove sessioni scadute e token invalidi",
        "func": cleanup_expired_sessions_job,
        "trigger_type": "interval",
        "trigger_args": {"minutes": 30},
        "enabled": True,
    },
    # Daily Analytics - ogni giorno alle 02:00
    {
        "job_id": "daily_analytics",
        "name": "Daily Analytics",
        "description": "Genera report analytics giornalieri",
        "func": daily_analytics_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 2, "minute": 0},
        "enabled": True,
    },
    # Database Backup - ogni giorno alle 03:00
    {
        "job_id": "database_backup",
        "name": "Database Backup",
        "description": "Backup automatico database PostgreSQL",
        "func": database_backup_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 3, "minute": 0},
        "enabled": True,
    },
]


__all__ = [
    # Job functions
    "cleanup_expired_downloads_job",
    "notify_expiring_downloads_job",
    "cleanup_expired_sessions_job",
    "daily_analytics_job",
    "database_backup_job",
    "health_check_job",
    # Job definitions for main.py
    "JOB_DEFINITIONS",
]

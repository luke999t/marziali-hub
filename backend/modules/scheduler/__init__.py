"""
AI_MODULE: Scheduler Module
AI_DESCRIPTION: APScheduler-based job scheduling system for maintenance tasks
AI_BUSINESS: Automated background jobs for DRM expiry, cleanup, stats generation
AI_TEACHING: APScheduler integration with FastAPI async patterns
AI_CREATED: 2025-01-17
AI_TASK: CODE 3 - Backend Scheduler Jobs & Maintenance System

FIX_2025_01_21: Corretti nomi import + aggiunto JOB_DEFINITIONS export
"""

from .scheduler_service import (
    SchedulerService,
    JobStatus,
    JobResult,
    JobDefinition,
    get_scheduler,
)
from .jobs import (
    cleanup_expired_downloads_job,
    notify_expiring_downloads_job,
    cleanup_expired_sessions_job,
    daily_analytics_job,
    database_backup_job,
    health_check_job,
    JOB_DEFINITIONS,
)

__all__ = [
    # Service
    "SchedulerService",
    "JobStatus",
    "JobResult",
    "JobDefinition",
    "get_scheduler",
    # Jobs - Nomi corretti da jobs/__init__.py
    "cleanup_expired_downloads_job",
    "notify_expiring_downloads_job",
    "cleanup_expired_sessions_job",
    "daily_analytics_job",
    "database_backup_job",
    "health_check_job",
    # Job definitions for main.py startup
    "JOB_DEFINITIONS",
]

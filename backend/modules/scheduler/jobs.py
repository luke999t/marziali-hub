"""
================================================================================
AI_MODULE: Scheduled Jobs
AI_VERSION: 2.0.0
AI_DESCRIPTION: Maintenance job implementations for scheduler (legacy + new modular jobs)
AI_BUSINESS: DRM expiry, cleanup notifications, cleanup sessions, stats generation,
             analytics, backup, health monitoring
AI_TEACHING: Idempotent job design with async SQLAlchemy
AI_CREATED: 2025-01-17
AI_UPDATED: 2025-01-17
AI_TASK: CODE 1 - Backend Scheduler Jobs & Maintenance System

NUOVI_JOB_AGGIUNTI:
- cleanup_expired_downloads_job: Pulizia file DRM scaduti (6h)
- notify_expiring_downloads_job: Notifiche download in scadenza (1h)
- cleanup_expired_sessions_job: Pulizia sessioni unificate (1h)
- daily_analytics_job: Report analytics giornaliero (02:00)
- database_backup_job: Backup PostgreSQL (03:00)
- health_check_job: Health check servizi (5min)
================================================================================
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict

from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import async_session_maker
from models.download import Download, DownloadStatus
from models.notification import Notification, DeviceToken
from models.ads import AdsSession, AdsSessionStatus
from .scheduler_service import JobResult, JobStatus

# Import new modular jobs
from .jobs.cleanup_downloads import (
    cleanup_expired_downloads_job,
    notify_expiring_downloads_job,
)
from .jobs.cleanup_sessions import cleanup_expired_sessions_job
from .jobs.daily_analytics import daily_analytics_job
from .jobs.database_backup import database_backup_job
from .jobs.health_check import health_check_job

logger = logging.getLogger(__name__)


async def expire_downloads_job() -> JobResult:
    """
    AI_DESCRIPTION: Mark expired DRM downloads as expired
    AI_BUSINESS: DRM enforcement - downloads with passed expiresAt become unplayable
    AI_TEACHING: Idempotent - safe to run multiple times
    AI_SCHEDULE: Every hour (interval: hours=1)
    """
    result = JobResult(
        job_id="expire_downloads",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            async with session.begin():
                # Find downloads that are:
                # 1. Status is COMPLETED (not already expired)
                # 2. expires_at is in the past
                now = datetime.utcnow()

                # Update expired downloads
                stmt = (
                    update(Download)
                    .where(
                        Download.status == DownloadStatus.COMPLETED,
                        Download.expires_at.isnot(None),
                        Download.expires_at < now,
                    )
                    .values(
                        status=DownloadStatus.EXPIRED,
                        updated_at=now,
                    )
                )

                update_result = await session.execute(stmt)
                expired_count = update_result.rowcount

                result.records_processed = expired_count
                result.status = JobStatus.SUCCESS
                result.details = {
                    "expired_downloads": expired_count,
                    "checked_at": now.isoformat(),
                }

                logger.info(f"expire_downloads_job: Marked {expired_count} downloads as expired")

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("expire_downloads_job failed")

    result.finished_at = datetime.now()
    return result


async def cleanup_notifications_job() -> JobResult:
    """
    AI_DESCRIPTION: Delete notifications older than 90 days
    AI_BUSINESS: Database maintenance - reduce storage, improve query performance
    AI_TEACHING: Batch delete with retention policy
    AI_SCHEDULE: Daily at 03:00 (cron: hour=3, minute=0)
    """
    result = JobResult(
        job_id="cleanup_notifications",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            async with session.begin():
                # Calculate cutoff date (90 days ago)
                cutoff_date = datetime.utcnow() - timedelta(days=90)

                # Delete old notifications
                stmt = delete(Notification).where(
                    Notification.created_at < cutoff_date
                )

                delete_result = await session.execute(stmt)
                deleted_count = delete_result.rowcount

                result.records_processed = deleted_count
                result.status = JobStatus.SUCCESS
                result.details = {
                    "deleted_notifications": deleted_count,
                    "cutoff_date": cutoff_date.isoformat(),
                    "retention_days": 90,
                }

                logger.info(f"cleanup_notifications_job: Deleted {deleted_count} old notifications")

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("cleanup_notifications_job failed")

    result.finished_at = datetime.now()
    return result


async def cleanup_abandoned_sessions_job() -> JobResult:
    """
    AI_DESCRIPTION: Clean abandoned ADS sessions (started but never completed)
    AI_BUSINESS: Data hygiene - mark stale ads sessions as abandoned
    AI_TEACHING: Session timeout pattern with configurable threshold
    AI_SCHEDULE: Every 30 minutes (interval: minutes=30)
    """
    result = JobResult(
        job_id="cleanup_abandoned_sessions",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            async with session.begin():
                # Sessions are considered abandoned if:
                # 1. Status is ACTIVE
                # 2. Started more than 1 hour ago
                # 3. Progress < 100%
                cutoff_time = datetime.utcnow() - timedelta(hours=1)

                # Update abandoned sessions
                stmt = (
                    update(AdsSession)
                    .where(
                        AdsSession.status == AdsSessionStatus.ACTIVE,
                        AdsSession.started_at < cutoff_time,
                        AdsSession.progress_percentage < 100.0,
                    )
                    .values(
                        status=AdsSessionStatus.ABANDONED,
                    )
                )

                update_result = await session.execute(stmt)
                abandoned_count = update_result.rowcount

                result.records_processed = abandoned_count
                result.status = JobStatus.SUCCESS
                result.details = {
                    "abandoned_sessions": abandoned_count,
                    "timeout_hours": 1,
                    "cutoff_time": cutoff_time.isoformat(),
                }

                logger.info(f"cleanup_abandoned_sessions_job: Marked {abandoned_count} sessions as abandoned")

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("cleanup_abandoned_sessions_job failed")

    result.finished_at = datetime.now()
    return result


async def daily_stats_job() -> JobResult:
    """
    AI_DESCRIPTION: Generate daily statistics report
    AI_BUSINESS: Monitoring - aggregate metrics for dashboard and alerts
    AI_TEACHING: Aggregation queries with multiple metrics
    AI_SCHEDULE: Daily at 01:00 (cron: hour=1, minute=0)
    """
    result = JobResult(
        job_id="daily_stats",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            # Calculate yesterday's date range
            today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday = today - timedelta(days=1)

            stats: Dict[str, Any] = {
                "period_start": yesterday.isoformat(),
                "period_end": today.isoformat(),
            }

            # Count new downloads
            downloads_stmt = select(func.count(Download.id)).where(
                Download.created_at >= yesterday,
                Download.created_at < today,
            )
            downloads_result = await session.execute(downloads_stmt)
            stats["new_downloads"] = downloads_result.scalar() or 0

            # Count completed downloads
            completed_stmt = select(func.count(Download.id)).where(
                Download.status == DownloadStatus.COMPLETED,
                Download.completed_at >= yesterday,
                Download.completed_at < today,
            )
            completed_result = await session.execute(completed_stmt)
            stats["completed_downloads"] = completed_result.scalar() or 0

            # Count expired downloads
            expired_stmt = select(func.count(Download.id)).where(
                Download.status == DownloadStatus.EXPIRED,
                Download.updated_at >= yesterday,
                Download.updated_at < today,
            )
            expired_result = await session.execute(expired_stmt)
            stats["expired_downloads"] = expired_result.scalar() or 0

            # Count new notifications
            notifications_stmt = select(func.count(Notification.id)).where(
                Notification.created_at >= yesterday,
                Notification.created_at < today,
            )
            notifications_result = await session.execute(notifications_stmt)
            stats["new_notifications"] = notifications_result.scalar() or 0

            # Count ads sessions
            ads_stmt = select(func.count(AdsSession.id)).where(
                AdsSession.created_at >= yesterday,
                AdsSession.created_at < today,
            )
            ads_result = await session.execute(ads_stmt)
            stats["ads_sessions"] = ads_result.scalar() or 0

            # Count completed ads sessions
            ads_completed_stmt = select(func.count(AdsSession.id)).where(
                AdsSession.status == AdsSessionStatus.COMPLETED,
                AdsSession.completed_at >= yesterday,
                AdsSession.completed_at < today,
            )
            ads_completed_result = await session.execute(ads_completed_stmt)
            stats["ads_sessions_completed"] = ads_completed_result.scalar() or 0

            # Count active device tokens
            tokens_stmt = select(func.count(DeviceToken.id)).where(
                DeviceToken.is_active == True,
            )
            tokens_result = await session.execute(tokens_stmt)
            stats["active_device_tokens"] = tokens_result.scalar() or 0

            result.records_processed = 1  # One report generated
            result.status = JobStatus.SUCCESS
            result.details = stats

            logger.info(f"daily_stats_job: Generated stats report: {stats}")

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("daily_stats_job failed")

    result.finished_at = datetime.now()
    return result


async def cleanup_expired_tokens_job() -> JobResult:
    """
    AI_DESCRIPTION: Remove device tokens not used in 90 days
    AI_BUSINESS: Push notification hygiene - inactive tokens cause delivery failures
    AI_TEACHING: Soft delete pattern (mark inactive vs hard delete)
    AI_SCHEDULE: Daily at 04:00 (cron: hour=4, minute=0)
    """
    result = JobResult(
        job_id="cleanup_expired_tokens",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            async with session.begin():
                # Tokens are considered expired if:
                # 1. is_active is True (still marked as active)
                # 2. last_used_at is more than 90 days ago
                cutoff_date = datetime.utcnow() - timedelta(days=90)

                # Mark tokens as inactive (soft delete)
                stmt = (
                    update(DeviceToken)
                    .where(
                        DeviceToken.is_active == True,
                        DeviceToken.last_used_at < cutoff_date,
                    )
                    .values(
                        is_active=False,
                        updated_at=datetime.utcnow(),
                    )
                )

                update_result = await session.execute(stmt)
                deactivated_count = update_result.rowcount

                result.records_processed = deactivated_count
                result.status = JobStatus.SUCCESS
                result.details = {
                    "deactivated_tokens": deactivated_count,
                    "cutoff_date": cutoff_date.isoformat(),
                    "inactivity_days": 90,
                }

                logger.info(f"cleanup_expired_tokens_job: Deactivated {deactivated_count} tokens")

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("cleanup_expired_tokens_job failed")

    result.finished_at = datetime.now()
    return result


# Job definitions for registration
JOB_DEFINITIONS = [
    {
        "job_id": "expire_downloads",
        "name": "Expire Downloads",
        "description": "Mark expired DRM downloads as expired",
        "func": expire_downloads_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 1},
        "enabled": True,
    },
    {
        "job_id": "cleanup_notifications",
        "name": "Cleanup Notifications",
        "description": "Delete notifications older than 90 days",
        "func": cleanup_notifications_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 3, "minute": 0},
        "enabled": True,
    },
    {
        "job_id": "cleanup_abandoned_sessions",
        "name": "Cleanup Abandoned Sessions",
        "description": "Mark abandoned ads sessions after 1 hour timeout",
        "func": cleanup_abandoned_sessions_job,
        "trigger_type": "interval",
        "trigger_args": {"minutes": 30},
        "enabled": True,
    },
    {
        "job_id": "daily_stats",
        "name": "Daily Stats Report",
        "description": "Generate daily statistics report",
        "func": daily_stats_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 1, "minute": 0},
        "enabled": True,
    },
    {
        "job_id": "cleanup_expired_tokens",
        "name": "Cleanup Expired Tokens",
        "description": "Deactivate device tokens not used in 90 days",
        "func": cleanup_expired_tokens_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 4, "minute": 0},
        "enabled": True,
    },
    # === NEW MODULAR JOBS (TASK CODE 1) ===
    {
        "job_id": "cleanup_expired_downloads_drm",
        "name": "Cleanup Expired DRM Downloads",
        "description": "Delete expired DRM download files and records (6h)",
        "func": cleanup_expired_downloads_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 6},
        "enabled": True,
    },
    {
        "job_id": "notify_expiring_downloads",
        "name": "Notify Expiring Downloads",
        "description": "Send notifications for downloads expiring in 24h",
        "func": notify_expiring_downloads_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 1},
        "enabled": True,
    },
    {
        "job_id": "cleanup_sessions_unified",
        "name": "Cleanup Sessions (Unified)",
        "description": "Clean device tokens + ads sessions (1h)",
        "func": cleanup_expired_sessions_job,
        "trigger_type": "interval",
        "trigger_args": {"hours": 1},
        "enabled": True,
    },
    {
        "job_id": "daily_analytics",
        "name": "Daily Analytics Report",
        "description": "Aggregate daily analytics to analytics_daily table (02:00)",
        "func": daily_analytics_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 2, "minute": 0},
        "enabled": True,
    },
    {
        "job_id": "database_backup",
        "name": "Database Backup",
        "description": "PostgreSQL pg_dump backup with 7-day rotation (03:00)",
        "func": database_backup_job,
        "trigger_type": "cron",
        "trigger_args": {"hour": 3, "minute": 30},  # 03:30 to not overlap with cleanup_notifications
        "enabled": True,
    },
    {
        "job_id": "health_check",
        "name": "Health Check",
        "description": "Ping PostgreSQL, Redis, Storage every 5 minutes",
        "func": health_check_job,
        "trigger_type": "interval",
        "trigger_args": {"minutes": 5},
        "enabled": True,
    },
]

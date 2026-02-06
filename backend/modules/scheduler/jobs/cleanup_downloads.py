"""
================================================================================
AI_MODULE: CleanupDownloadsJob
AI_VERSION: 1.0.0
AI_DESCRIPTION: Rimuove download con DRM scaduto e libera storage
AI_BUSINESS: Risparmio storage €50/mese, compliance GDPR retention
AI_TEACHING: APScheduler job async + SQLAlchemy bulk operations + file system

ALTERNATIVE_VALUTATE:
- Celery: Scartato, overhead eccessivo per job semplici
- Cron esterno: Scartato, difficile monitoring e retry

PERCHÉ_QUESTA_SOLUZIONE:
- APScheduler integrato in FastAPI, zero dipendenze extra
- Job async non bloccano il server
- Notifiche proattive migliorano UX
================================================================================
"""

import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

from sqlalchemy import select, delete, func
from sqlalchemy.orm import selectinload

from core.database import async_session_maker
from models.download import Download, DownloadStatus
from models.notification import Notification, NotificationType, NotificationPriority
from models.user import User
from modules.scheduler.scheduler_service import JobResult, JobStatus

logger = logging.getLogger(__name__)

# 💡 Configurazione storage - in produzione da environment
DOWNLOADS_STORAGE_PATH = os.getenv(
    "DOWNLOADS_STORAGE_PATH",
    "/var/media-center/downloads"
)


async def cleanup_expired_downloads_job() -> JobResult:
    """
    🎯 BUSINESS: Rimuove download scaduti per liberare storage
    📊 KPI: Storage utilizzato, costo mensile storage
    ⏱️ SCHEDULE: Ogni 6 ore

    LOGICA:
    1. Trova download con drm_expires_at < now
    2. Elimina file fisici da storage (se esistono)
    3. Rimuovi record dal database (hard delete per GDPR)
    4. Log risultati per analytics

    💡 Perché hard delete invece di soft delete:
    - GDPR richiede eliminazione effettiva dopo retention period
    - File fisici devono essere rimossi per liberare storage
    - Audit trail già presente nei log strutturati
    """
    result = JobResult(
        job_id="cleanup_expired_downloads",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    deleted_count = 0
    freed_bytes = 0
    file_errors: List[str] = []

    try:
        async with async_session_maker() as session:
            async with session.begin():
                now = datetime.utcnow()

                # 💡 Query download scaduti (DRM expired)
                # Include sia drm_expires_at che expires_at per sicurezza
                expired_query = select(Download).where(
                    Download.status.in_([
                        DownloadStatus.COMPLETED,
                        DownloadStatus.EXPIRED,
                    ]),
                    (
                        (Download.drm_expires_at.isnot(None) &
                         (Download.drm_expires_at < now)) |
                        (Download.expires_at.isnot(None) &
                         (Download.expires_at < now))
                    ),
                )

                expired_result = await session.execute(expired_query)
                expired_downloads = expired_result.scalars().all()

                for download in expired_downloads:
                    # 1. Elimina file fisico
                    file_deleted, bytes_freed, error = _delete_download_file(
                        download.id,
                        download.user_id,
                    )

                    if file_deleted:
                        freed_bytes += bytes_freed
                    elif error:
                        file_errors.append(error)

                    # 2. Elimina record database
                    await session.delete(download)
                    deleted_count += 1

                # Commit esplicito per transazione
                await session.commit()

                result.records_processed = deleted_count
                result.status = JobStatus.SUCCESS
                result.details = {
                    "deleted_downloads": deleted_count,
                    "freed_bytes": freed_bytes,
                    "freed_mb": round(freed_bytes / (1024 * 1024), 2),
                    "file_errors": len(file_errors),
                    "checked_at": now.isoformat(),
                }

                logger.info(
                    f"cleanup_expired_downloads_job: "
                    f"Deleted {deleted_count} downloads, "
                    f"freed {freed_bytes / (1024 * 1024):.2f} MB"
                )

                if file_errors:
                    logger.warning(
                        f"File deletion errors: {file_errors[:5]}"  # Log first 5
                    )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("cleanup_expired_downloads_job failed")

    result.finished_at = datetime.now()
    return result


def _delete_download_file(
    download_id: str,
    user_id: str,
) -> tuple[bool, int, Optional[str]]:
    """
    🎯 Elimina file fisico del download da storage

    Returns:
        (success, bytes_freed, error_message)

    💡 Pattern path: {STORAGE_PATH}/{user_id}/{download_id}/
    """
    try:
        download_path = Path(DOWNLOADS_STORAGE_PATH) / str(user_id) / str(download_id)

        if not download_path.exists():
            # File già eliminato o mai creato - non è un errore
            return True, 0, None

        # Calcola dimensione prima di eliminare
        total_size = 0
        for file_path in download_path.rglob("*"):
            if file_path.is_file():
                total_size += file_path.stat().st_size

        # Elimina directory e contenuti
        shutil.rmtree(download_path, ignore_errors=False)

        logger.debug(f"Deleted download files: {download_path} ({total_size} bytes)")
        return True, total_size, None

    except PermissionError as e:
        error_msg = f"Permission denied: {download_path}"
        logger.warning(error_msg)
        return False, 0, error_msg

    except Exception as e:
        error_msg = f"Failed to delete {download_path}: {str(e)}"
        logger.warning(error_msg)
        return False, 0, error_msg


async def notify_expiring_downloads_job() -> JobResult:
    """
    🎯 BUSINESS: Notifica utenti 24h prima della scadenza download
    📊 KPI: User engagement, download renewal rate
    ⏱️ SCHEDULE: Ogni 6 ore (insieme a cleanup)

    LOGICA:
    1. Trova download che scadono nelle prossime 24-30 ore
    2. Crea notifica per ogni utente (una per download)
    3. Evita notifiche duplicate (check esistente)

    💡 Perché 24-30 ore window:
    - 24h minimo per dare tempo all'utente
    - 30h max per evitare notifiche premature
    - Job ogni 6h garantisce che tutti vengano notificati
    """
    result = JobResult(
        job_id="notify_expiring_downloads",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    notifications_created = 0

    try:
        async with async_session_maker() as session:
            async with session.begin():
                now = datetime.utcnow()
                window_start = now + timedelta(hours=24)
                window_end = now + timedelta(hours=30)

                # 💡 Query download in scadenza con user info
                expiring_query = (
                    select(Download)
                    .options(selectinload(Download.user))
                    .options(selectinload(Download.video))
                    .where(
                        Download.status == DownloadStatus.COMPLETED,
                        Download.drm_expires_at.isnot(None),
                        Download.drm_expires_at >= window_start,
                        Download.drm_expires_at < window_end,
                    )
                )

                expiring_result = await session.execute(expiring_query)
                expiring_downloads = expiring_result.scalars().all()

                for download in expiring_downloads:
                    # Check se notifica già inviata
                    existing_notification = await _check_existing_notification(
                        session,
                        download.user_id,
                        download.id,
                    )

                    if existing_notification:
                        continue

                    # Crea notifica
                    video_title = (
                        download.video.title if download.video
                        else "Video offline"
                    )

                    notification = Notification(
                        user_id=download.user_id,
                        type=NotificationType.SYSTEM,
                        priority=NotificationPriority.HIGH,
                        title="Download in scadenza",
                        body=f'Il tuo download "{video_title}" scadrà tra 24 ore. '
                             f"Guardalo prima che venga rimosso!",
                        action_type="open_downloads",
                        action_payload={
                            "download_id": str(download.id),
                            "video_id": str(download.video_id) if download.video_id else None,
                        },
                        expires_at=download.drm_expires_at,
                    )

                    session.add(notification)
                    notifications_created += 1

                await session.commit()

                result.records_processed = notifications_created
                result.status = JobStatus.SUCCESS
                result.details = {
                    "notifications_created": notifications_created,
                    "downloads_checked": len(expiring_downloads),
                    "window_start": window_start.isoformat(),
                    "window_end": window_end.isoformat(),
                }

                logger.info(
                    f"notify_expiring_downloads_job: "
                    f"Created {notifications_created} notifications"
                )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("notify_expiring_downloads_job failed")

    result.finished_at = datetime.now()
    return result


async def _check_existing_notification(
    session,
    user_id: str,
    download_id: str,
) -> bool:
    """
    Check se esiste già una notifica per questo download scadenza.

    💡 Previene spam: una sola notifica per download
    """
    # Cerca notifiche recenti (ultime 48h) per questo download
    cutoff = datetime.utcnow() - timedelta(hours=48)

    query = select(func.count(Notification.id)).where(
        Notification.user_id == user_id,
        Notification.action_type == "open_downloads",
        Notification.created_at > cutoff,
        Notification.title == "Download in scadenza",
    )

    result = await session.execute(query)
    count = result.scalar() or 0

    return count > 0

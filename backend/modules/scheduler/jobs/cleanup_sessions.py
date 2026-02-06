"""
================================================================================
AI_MODULE: CleanupSessionsJob
AI_VERSION: 1.0.0
AI_DESCRIPTION: Pulisce sessioni scadute, token inattivi e ads sessions abbandonate
AI_BUSINESS: Database hygiene, riduzione storage, miglior performance query
AI_TEACHING: Cleanup multipli in singolo job con transaction safety

ALTERNATIVE_VALUTATE:
- Job separati per ogni cleanup: Scartato, overhead scheduling eccessivo
- Cleanup on-demand: Scartato, accumulo garbage tra richieste

PERCHÉ_QUESTA_SOLUZIONE:
- Singolo job orchestrato per tutte le cleanup "session-like"
- Transazioni separate per evitare rollback totale su errore parziale
- Metriche dettagliate per ogni tipo di cleanup
================================================================================
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from sqlalchemy import select, update, delete, func

from core.database import async_session_maker
from models.notification import DeviceToken
from models.ads import AdsSession, AdsSessionStatus
from modules.scheduler.scheduler_service import JobResult, JobStatus

logger = logging.getLogger(__name__)

# 💡 Configurazione retention periods
DEVICE_TOKEN_INACTIVE_DAYS = 90  # Token non usati da 90 giorni
ADS_SESSION_TIMEOUT_HOURS = 2    # Sessioni ads abbandonate dopo 2 ore
ADS_SESSION_RETENTION_DAYS = 30  # Sessioni ads completate/fallite dopo 30 giorni


async def cleanup_expired_sessions_job() -> JobResult:
    """
    🎯 BUSINESS: Pulisce tutte le sessioni scadute dal sistema
    📊 KPI: Database size, query performance, storage cost
    ⏱️ SCHEDULE: Ogni ora

    LOGICA:
    1. Cleanup device tokens inattivi (soft delete → is_active=False)
    2. Cleanup ads sessions abbandonate (status → ABANDONED)
    3. Hard delete vecchie ads sessions (>30 giorni, non ACTIVE)
    4. Cleanup sessioni di autenticazione (se implementato)

    💡 Perché cleanup unificato:
    - Meno job = meno overhead scheduler
    - Transazioni separate per ogni tipo = fault isolation
    - Report unificato per monitoring
    """
    result = JobResult(
        job_id="cleanup_expired_sessions",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    cleanup_stats: Dict[str, Any] = {
        "device_tokens_deactivated": 0,
        "ads_sessions_abandoned": 0,
        "ads_sessions_deleted": 0,
        "errors": [],
    }

    try:
        # === CLEANUP 1: Device Tokens Inattivi ===
        try:
            stats = await _cleanup_inactive_device_tokens()
            cleanup_stats["device_tokens_deactivated"] = stats["deactivated"]
        except Exception as e:
            cleanup_stats["errors"].append(f"device_tokens: {str(e)}")
            logger.exception("Device tokens cleanup failed")

        # === CLEANUP 2: Ads Sessions Abbandonate ===
        try:
            stats = await _cleanup_abandoned_ads_sessions()
            cleanup_stats["ads_sessions_abandoned"] = stats["abandoned"]
        except Exception as e:
            cleanup_stats["errors"].append(f"ads_sessions_abandon: {str(e)}")
            logger.exception("Ads sessions abandon cleanup failed")

        # === CLEANUP 3: Vecchie Ads Sessions (Hard Delete) ===
        try:
            stats = await _cleanup_old_ads_sessions()
            cleanup_stats["ads_sessions_deleted"] = stats["deleted"]
        except Exception as e:
            cleanup_stats["errors"].append(f"ads_sessions_delete: {str(e)}")
            logger.exception("Ads sessions delete cleanup failed")

        # Calcola totale records processati
        total_processed = (
            cleanup_stats["device_tokens_deactivated"] +
            cleanup_stats["ads_sessions_abandoned"] +
            cleanup_stats["ads_sessions_deleted"]
        )

        result.records_processed = total_processed
        result.status = (
            JobStatus.SUCCESS if not cleanup_stats["errors"]
            else JobStatus.FAILED
        )
        result.details = cleanup_stats

        if cleanup_stats["errors"]:
            result.error_message = "; ".join(cleanup_stats["errors"])

        logger.info(
            f"cleanup_expired_sessions_job: "
            f"tokens={cleanup_stats['device_tokens_deactivated']}, "
            f"abandoned={cleanup_stats['ads_sessions_abandoned']}, "
            f"deleted={cleanup_stats['ads_sessions_deleted']}"
        )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("cleanup_expired_sessions_job failed completely")

    result.finished_at = datetime.now()
    return result


async def _cleanup_inactive_device_tokens() -> Dict[str, int]:
    """
    🎯 Disattiva device tokens non usati da 90 giorni

    💡 Soft delete (is_active=False) invece di hard delete perché:
    - Permette riattivazione se utente torna
    - Audit trail per analytics
    - Push notification service gestisce gracefully token inattivi
    """
    async with async_session_maker() as session:
        async with session.begin():
            cutoff_date = datetime.utcnow() - timedelta(days=DEVICE_TOKEN_INACTIVE_DAYS)

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
            deactivated = update_result.rowcount

            logger.debug(
                f"Deactivated {deactivated} device tokens "
                f"(inactive since {cutoff_date.isoformat()})"
            )

            return {"deactivated": deactivated}


async def _cleanup_abandoned_ads_sessions() -> Dict[str, int]:
    """
    🎯 Marca come abbandonate le ads sessions attive da troppo tempo

    💡 Timeout 2 ore perché:
    - Sessione ads normale dura max 10-15 minuti
    - 2 ore dà margine per utenti che pausano
    - Dopo 2 ore è sicuramente abbandonata
    """
    async with async_session_maker() as session:
        async with session.begin():
            cutoff_time = datetime.utcnow() - timedelta(hours=ADS_SESSION_TIMEOUT_HOURS)

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
            abandoned = update_result.rowcount

            logger.debug(
                f"Marked {abandoned} ads sessions as abandoned "
                f"(started before {cutoff_time.isoformat()})"
            )

            return {"abandoned": abandoned}


async def _cleanup_old_ads_sessions() -> Dict[str, int]:
    """
    🎯 Elimina ads sessions vecchie (>30 giorni) che non sono ACTIVE

    💡 Hard delete per GDPR compliance:
    - Dati sessione non più necessari dopo 30 giorni
    - Revenue già calcolata e aggregata in analytics
    - Riduzione significativa spazio database
    """
    async with async_session_maker() as session:
        async with session.begin():
            cutoff_date = datetime.utcnow() - timedelta(days=ADS_SESSION_RETENTION_DAYS)

            stmt = delete(AdsSession).where(
                AdsSession.status != AdsSessionStatus.ACTIVE,
                AdsSession.created_at < cutoff_date,
            )

            delete_result = await session.execute(stmt)
            deleted = delete_result.rowcount

            logger.debug(
                f"Deleted {deleted} old ads sessions "
                f"(created before {cutoff_date.isoformat()})"
            )

            return {"deleted": deleted}

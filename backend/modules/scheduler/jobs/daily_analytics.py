"""
================================================================================
AI_MODULE: DailyAnalyticsJob
AI_VERSION: 1.0.0
AI_DESCRIPTION: Aggrega statistiche giornaliere per dashboard e reportistica
AI_BUSINESS: Dashboard KPI real-time, trend analysis, reportistica mensile
AI_TEACHING: Aggregation queries SQL + upsert pattern per idempotenza

ALTERNATIVE_VALUTATE:
- Aggregazione on-demand: Scartato, troppo lento su milioni di records
- Elasticsearch: Scartato, complessità e costo infrastrutturale

PERCHÉ_QUESTA_SOLUZIONE:
- Pre-aggregazione notturna = query dashboard istantanee
- PostgreSQL già presente = zero costi aggiuntivi
- Upsert = job idempotente e safe da ri-eseguire
================================================================================
"""

import logging
from datetime import datetime, timedelta, date
from typing import Dict, Any

from sqlalchemy import select, func, and_
from sqlalchemy.dialects.postgresql import insert as pg_insert

from core.database import async_session_maker
from models.user import User, ViewingHistory, SubscriptionHistory, SubscriptionStatus
from models.video import Video
from models.download import Download, DownloadStatus
from models.ads import AdsSession, AdsSessionStatus
from models.notification import Notification, DeviceToken
from models.analytics import AnalyticsDaily
from modules.scheduler.scheduler_service import JobResult, JobStatus

logger = logging.getLogger(__name__)


async def daily_analytics_job() -> JobResult:
    """
    🎯 BUSINESS: Genera report analytics giornaliero
    📊 KPI: Tutti i KPI dashboard (users, views, downloads, revenue)
    ⏱️ SCHEDULE: Ogni giorno alle 02:00

    LOGICA:
    1. Calcola range data per giorno precedente
    2. Aggrega metriche da tutte le tabelle
    3. Upsert in analytics_daily (idempotente)
    4. Log risultati per monitoring

    💡 Perché 02:00:
    - Dopo mezzanotte = giorno precedente completo
    - Prima dell'orario lavorativo = dati pronti per mattina
    - Basso traffico = minor impatto sulle performance
    """
    result = JobResult(
        job_id="daily_analytics",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    try:
        async with async_session_maker() as session:
            async with session.begin():
                # 💡 Calcola range giorno precedente (00:00 - 23:59:59)
                today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
                yesterday = today - timedelta(days=1)
                yesterday_date = yesterday.date()

                # === AGGREGA TUTTE LE METRICHE ===
                metrics: Dict[str, Any] = {}

                # 1. User Metrics
                metrics.update(await _get_user_metrics(session, yesterday, today))

                # 2. Video/Viewing Metrics
                metrics.update(await _get_viewing_metrics(session, yesterday, today))

                # 3. Download Metrics
                metrics.update(await _get_download_metrics(session, yesterday, today))

                # 4. Ads Metrics
                metrics.update(await _get_ads_metrics(session, yesterday, today))

                # 5. Notification Metrics
                metrics.update(await _get_notification_metrics(session, yesterday, today))

                # 6. Subscription Metrics
                metrics.update(await _get_subscription_metrics(session, yesterday, today))

                # === UPSERT IN ANALYTICS_DAILY ===
                # 💡 Upsert = INSERT ... ON CONFLICT UPDATE
                # Permette di ri-eseguire il job senza duplicare record
                stmt = pg_insert(AnalyticsDaily).values(
                    report_date=yesterday_date,
                    # User metrics
                    new_users=metrics.get("new_users", 0),
                    active_users=metrics.get("active_users", 0),
                    total_users=metrics.get("total_users", 0),
                    # Video metrics
                    total_views=metrics.get("total_views", 0),
                    unique_videos_watched=metrics.get("unique_videos_watched", 0),
                    total_watch_time_seconds=metrics.get("total_watch_time_seconds", 0),
                    completed_videos=metrics.get("completed_videos", 0),
                    # Download metrics
                    new_downloads=metrics.get("new_downloads", 0),
                    completed_downloads=metrics.get("completed_downloads", 0),
                    expired_downloads=metrics.get("expired_downloads", 0),
                    # Ads metrics
                    ads_sessions_started=metrics.get("ads_sessions_started", 0),
                    ads_sessions_completed=metrics.get("ads_sessions_completed", 0),
                    ads_revenue_estimated=metrics.get("ads_revenue_estimated", 0.0),
                    # Notification metrics
                    push_notifications_sent=metrics.get("push_notifications_sent", 0),
                    notifications_read=metrics.get("notifications_read", 0),
                    # Subscription metrics
                    new_subscriptions=metrics.get("new_subscriptions", 0),
                    cancelled_subscriptions=metrics.get("cancelled_subscriptions", 0),
                    subscription_revenue=metrics.get("subscription_revenue", 0.0),
                    # Extra metrics in JSON
                    extra_metrics=metrics.get("extra", {}),
                )

                # ON CONFLICT = UPDATE all columns
                stmt = stmt.on_conflict_do_update(
                    index_elements=[AnalyticsDaily.report_date],
                    set_={
                        "new_users": stmt.excluded.new_users,
                        "active_users": stmt.excluded.active_users,
                        "total_users": stmt.excluded.total_users,
                        "total_views": stmt.excluded.total_views,
                        "unique_videos_watched": stmt.excluded.unique_videos_watched,
                        "total_watch_time_seconds": stmt.excluded.total_watch_time_seconds,
                        "completed_videos": stmt.excluded.completed_videos,
                        "new_downloads": stmt.excluded.new_downloads,
                        "completed_downloads": stmt.excluded.completed_downloads,
                        "expired_downloads": stmt.excluded.expired_downloads,
                        "ads_sessions_started": stmt.excluded.ads_sessions_started,
                        "ads_sessions_completed": stmt.excluded.ads_sessions_completed,
                        "ads_revenue_estimated": stmt.excluded.ads_revenue_estimated,
                        "push_notifications_sent": stmt.excluded.push_notifications_sent,
                        "notifications_read": stmt.excluded.notifications_read,
                        "new_subscriptions": stmt.excluded.new_subscriptions,
                        "cancelled_subscriptions": stmt.excluded.cancelled_subscriptions,
                        "subscription_revenue": stmt.excluded.subscription_revenue,
                        "extra_metrics": stmt.excluded.extra_metrics,
                        "updated_at": datetime.utcnow(),
                    }
                )

                await session.execute(stmt)
                await session.commit()

                result.records_processed = 1
                result.status = JobStatus.SUCCESS
                result.details = {
                    "report_date": yesterday_date.isoformat(),
                    "metrics_summary": {
                        "new_users": metrics.get("new_users", 0),
                        "active_users": metrics.get("active_users", 0),
                        "total_views": metrics.get("total_views", 0),
                        "new_downloads": metrics.get("new_downloads", 0),
                        "ads_revenue": round(metrics.get("ads_revenue_estimated", 0.0), 2),
                    },
                    "generated_at": datetime.utcnow().isoformat(),
                }

                logger.info(
                    f"daily_analytics_job: Generated report for {yesterday_date}, "
                    f"users={metrics.get('new_users', 0)}, "
                    f"views={metrics.get('total_views', 0)}"
                )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("daily_analytics_job failed")

    result.finished_at = datetime.now()
    return result


async def _get_user_metrics(session, start: datetime, end: datetime) -> Dict[str, int]:
    """
    Calcola metriche utenti per il periodo.

    💡 Active users = utenti con almeno 1 view nel periodo
    """
    # New users (created in period)
    new_users_stmt = select(func.count(User.id)).where(
        User.created_at >= start,
        User.created_at < end,
    )
    new_users_result = await session.execute(new_users_stmt)
    new_users = new_users_result.scalar() or 0

    # Total users (cumulative)
    total_users_stmt = select(func.count(User.id)).where(
        User.created_at < end,
    )
    total_users_result = await session.execute(total_users_stmt)
    total_users = total_users_result.scalar() or 0

    # Active users (with at least 1 view in period)
    active_users_stmt = select(func.count(func.distinct(ViewingHistory.user_id))).where(
        ViewingHistory.watched_at >= start,
        ViewingHistory.watched_at < end,
    )
    active_users_result = await session.execute(active_users_stmt)
    active_users = active_users_result.scalar() or 0

    return {
        "new_users": new_users,
        "total_users": total_users,
        "active_users": active_users,
    }


async def _get_viewing_metrics(session, start: datetime, end: datetime) -> Dict[str, int]:
    """
    Calcola metriche visualizzazioni per il periodo.

    💡 Watch time aggregato per content strategy
    """
    # Total views
    views_stmt = select(func.count(ViewingHistory.id)).where(
        ViewingHistory.watched_at >= start,
        ViewingHistory.watched_at < end,
    )
    views_result = await session.execute(views_stmt)
    total_views = views_result.scalar() or 0

    # Unique videos watched
    unique_videos_stmt = select(func.count(func.distinct(ViewingHistory.video_id))).where(
        ViewingHistory.watched_at >= start,
        ViewingHistory.watched_at < end,
    )
    unique_videos_result = await session.execute(unique_videos_stmt)
    unique_videos = unique_videos_result.scalar() or 0

    # Total watch time (seconds)
    watch_time_stmt = select(func.sum(ViewingHistory.watch_duration)).where(
        ViewingHistory.watched_at >= start,
        ViewingHistory.watched_at < end,
    )
    watch_time_result = await session.execute(watch_time_stmt)
    total_watch_time = watch_time_result.scalar() or 0

    # Completed videos
    completed_stmt = select(func.count(ViewingHistory.id)).where(
        ViewingHistory.watched_at >= start,
        ViewingHistory.watched_at < end,
        ViewingHistory.completed == True,
    )
    completed_result = await session.execute(completed_stmt)
    completed_videos = completed_result.scalar() or 0

    return {
        "total_views": total_views,
        "unique_videos_watched": unique_videos,
        "total_watch_time_seconds": total_watch_time,
        "completed_videos": completed_videos,
    }


async def _get_download_metrics(session, start: datetime, end: datetime) -> Dict[str, int]:
    """
    Calcola metriche download per il periodo.
    """
    # New downloads (requested)
    new_stmt = select(func.count(Download.id)).where(
        Download.requested_at >= start,
        Download.requested_at < end,
    )
    new_result = await session.execute(new_stmt)
    new_downloads = new_result.scalar() or 0

    # Completed downloads
    completed_stmt = select(func.count(Download.id)).where(
        Download.completed_at >= start,
        Download.completed_at < end,
        Download.status == DownloadStatus.COMPLETED,
    )
    completed_result = await session.execute(completed_stmt)
    completed_downloads = completed_result.scalar() or 0

    # Expired downloads (in this period)
    expired_stmt = select(func.count(Download.id)).where(
        Download.status == DownloadStatus.EXPIRED,
        Download.updated_at >= start,
        Download.updated_at < end,
    )
    expired_result = await session.execute(expired_stmt)
    expired_downloads = expired_result.scalar() or 0

    return {
        "new_downloads": new_downloads,
        "completed_downloads": completed_downloads,
        "expired_downloads": expired_downloads,
    }


async def _get_ads_metrics(session, start: datetime, end: datetime) -> Dict[str, Any]:
    """
    Calcola metriche ads per il periodo.

    💡 Revenue stimato basato su CPM medio
    """
    # Sessions started
    started_stmt = select(func.count(AdsSession.id)).where(
        AdsSession.started_at >= start,
        AdsSession.started_at < end,
    )
    started_result = await session.execute(started_stmt)
    sessions_started = started_result.scalar() or 0

    # Sessions completed
    completed_stmt = select(func.count(AdsSession.id)).where(
        AdsSession.completed_at >= start,
        AdsSession.completed_at < end,
        AdsSession.status == AdsSessionStatus.COMPLETED,
    )
    completed_result = await session.execute(completed_stmt)
    sessions_completed = completed_result.scalar() or 0

    # Estimated revenue (sum of estimated_revenue field)
    revenue_stmt = select(func.sum(AdsSession.estimated_revenue)).where(
        AdsSession.completed_at >= start,
        AdsSession.completed_at < end,
        AdsSession.status == AdsSessionStatus.COMPLETED,
    )
    revenue_result = await session.execute(revenue_stmt)
    estimated_revenue = revenue_result.scalar() or 0.0

    return {
        "ads_sessions_started": sessions_started,
        "ads_sessions_completed": sessions_completed,
        "ads_revenue_estimated": float(estimated_revenue),
    }


async def _get_notification_metrics(session, start: datetime, end: datetime) -> Dict[str, int]:
    """
    Calcola metriche notifiche per il periodo.
    """
    # Notifications sent (push_sent=True)
    sent_stmt = select(func.count(Notification.id)).where(
        Notification.push_sent == True,
        Notification.push_sent_at >= start,
        Notification.push_sent_at < end,
    )
    sent_result = await session.execute(sent_stmt)
    notifications_sent = sent_result.scalar() or 0

    # Notifications read
    read_stmt = select(func.count(Notification.id)).where(
        Notification.is_read == True,
        Notification.read_at >= start,
        Notification.read_at < end,
    )
    read_result = await session.execute(read_stmt)
    notifications_read = read_result.scalar() or 0

    return {
        "push_notifications_sent": notifications_sent,
        "notifications_read": notifications_read,
    }


async def _get_subscription_metrics(session, start: datetime, end: datetime) -> Dict[str, Any]:
    """
    Calcola metriche subscription per il periodo.

    💡 Revenue calcolato dalle SubscriptionHistory
    """
    # New subscriptions (status = ACTIVE, created in period)
    new_stmt = select(func.count(SubscriptionHistory.id)).where(
        SubscriptionHistory.created_at >= start,
        SubscriptionHistory.created_at < end,
        SubscriptionHistory.status == SubscriptionStatus.ACTIVE,
    )
    new_result = await session.execute(new_stmt)
    new_subs = new_result.scalar() or 0

    # Cancelled subscriptions
    cancelled_stmt = select(func.count(SubscriptionHistory.id)).where(
        SubscriptionHistory.created_at >= start,
        SubscriptionHistory.created_at < end,
        SubscriptionHistory.status == SubscriptionStatus.CANCELLED,
    )
    cancelled_result = await session.execute(cancelled_stmt)
    cancelled_subs = cancelled_result.scalar() or 0

    # Revenue (sum of amount_paid)
    revenue_stmt = select(func.sum(SubscriptionHistory.amount_paid)).where(
        SubscriptionHistory.created_at >= start,
        SubscriptionHistory.created_at < end,
        SubscriptionHistory.status == SubscriptionStatus.ACTIVE,
    )
    revenue_result = await session.execute(revenue_stmt)
    revenue = revenue_result.scalar() or 0.0

    return {
        "new_subscriptions": new_subs,
        "cancelled_subscriptions": cancelled_subs,
        "subscription_revenue": float(revenue),
    }

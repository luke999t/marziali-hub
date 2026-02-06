"""
🎓 MAESTRO API - Gestional Panel for Teachers
🎓 Endpoints: Dashboard, Videos, Live Events, Earnings, Corrections, Translations
"""
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc
from typing import List, Optional
from datetime import datetime, timedelta
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_user
from models.user import User
from models.maestro import Maestro, MaestroStatus
from models.video import Video, VideoStatus, LiveEvent, LiveEventStatus, LiveEventType
from models.donation import Donation, WithdrawalRequest, WithdrawalStatus, PayoutMethod
from models.communication import CorrectionRequest, TranslationDataset, GlossaryTerm, TranslationProcessingStatus

router = APIRouter()


# ============================
# SCHEMAS
# ============================

class LiveEventCreate(BaseModel):
    title: str
    description: Optional[str] = None
    event_type: str  # LiveEventType enum
    scheduled_start: datetime
    scheduled_end: Optional[datetime] = None
    donations_enabled: bool = True
    chat_enabled: bool = True
    translations_enabled: bool = False
    translation_languages: Optional[List[str]] = None
    fundraising_goal: Optional[int] = None  # Stelline


class WithdrawalCreate(BaseModel):
    stelline_amount: int
    payout_method: str  # PayoutMethod enum
    iban: Optional[str] = None
    paypal_email: Optional[str] = None


class CorrectionFeedback(BaseModel):
    feedback_text: Optional[str] = None
    feedback_video_url: Optional[str] = None
    feedback_annotations: Optional[dict] = None


# ============================
# HELPERS
# ============================

async def get_current_maestro(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> Maestro:
    """Get current user's maestro profile or raise 403."""
    result = await db.execute(select(Maestro).where(Maestro.user_id == current_user.id))
    maestro = result.scalar_one_or_none()

    if not maestro:
        raise HTTPException(status_code=403, detail="User is not a maestro")

    if maestro.status != MaestroStatus.ACTIVE:
        raise HTTPException(status_code=403, detail=f"Maestro account is {maestro.status.value}")

    return maestro


# ============================
# DASHBOARD
# ============================

@router.get("/dashboard")
async def get_maestro_dashboard(
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    📊 Maestro dashboard with key metrics.

    Returns:
    - Total videos, followers, donations received
    - Earnings (last 30 days)
    - Pending correction requests
    - Upcoming live events
    """
    # Get stats
    total_videos = await db.execute(
        select(func.count()).select_from(Video).where(Video.uploaded_by == maestro.user_id)
    )

    # Earnings last 30 days
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    donations_30d = await db.execute(
        select(
            func.count(Donation.id),
            func.sum(Donation.stelline_amount)
        ).where(and_(
            Donation.to_maestro_id == maestro.id,
            Donation.created_at >= thirty_days_ago
        ))
    )
    donation_stats = donations_30d.one()

    # Pending corrections
    pending_corrections = await db.execute(
        select(func.count()).select_from(CorrectionRequest).where(and_(
            CorrectionRequest.maestro_id == maestro.id,
            CorrectionRequest.status.in_(["pending", "in_progress"])
        ))
    )

    # Upcoming live events
    upcoming_events = await db.execute(
        select(func.count()).select_from(LiveEvent).where(and_(
            LiveEvent.maestro_id == maestro.id,
            LiveEvent.status == LiveEventStatus.SCHEDULED,
            LiveEvent.scheduled_start > datetime.utcnow()
        ))
    )

    return {
        "total_videos": total_videos.scalar(),
        "total_followers": maestro.total_followers,
        "total_donations_received_stelline": maestro.total_donations_received,
        "earnings_last_30_days": {
            "donations_count": donation_stats[0] or 0,
            "stelline": donation_stats[1] or 0,
            "eur": round((donation_stats[1] or 0) * 0.01, 2)
        },
        "pending_corrections": pending_corrections.scalar(),
        "upcoming_live_events": upcoming_events.scalar()
    }


# ============================
# VIDEO MANAGEMENT
# ============================

@router.get("/videos")
async def list_maestro_videos(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    🎥 List maestro's videos.

    Args:
        status: Filter by status (pending, processing, ready, failed)
    """
    query = select(Video).where(Video.uploaded_by == maestro.user_id).order_by(desc(Video.created_at))

    if status:
        status_enum = VideoStatus(status)
        query = query.where(Video.status == status_enum)

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    videos = result.scalars().all()

    return {
        "videos": videos,
        "skip": skip,
        "limit": limit
    }


@router.delete("/videos/{video_id}")
async def delete_video(
    video_id: str,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    🗑️ Delete a video.
    """
    result = await db.execute(select(Video).where(and_(
        Video.id == video_id,
        Video.uploaded_by == maestro.user_id
    )))
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    await db.delete(video)
    await db.commit()

    return {"message": "Video deleted successfully", "video_id": video_id}


# ============================
# LIVE EVENTS
# ============================

@router.post("/live-events")
async def create_live_event(
    data: LiveEventCreate,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    📡 Create a new live event.
    """
    import uuid

    # Create stream key (unique)
    stream_key = f"maestro_{maestro.id}_{uuid.uuid4().hex[:12]}"

    event = LiveEvent(
        maestro_id=maestro.id,
        asd_id=maestro.asd_id,
        title=data.title,
        description=data.description,
        event_type=LiveEventType(data.event_type),
        scheduled_start=data.scheduled_start,
        scheduled_end=data.scheduled_end,
        stream_key=stream_key,
        rtmp_url=f"rtmp://live.platform.com/live/{stream_key}",
        donations_enabled=data.donations_enabled,
        chat_enabled=data.chat_enabled,
        translations_enabled=data.translations_enabled,
        translation_languages=data.translation_languages,
        fundraising_goal=data.fundraising_goal
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    return {"message": "Live event created", "event": event}


@router.get("/live-events")
async def list_live_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    upcoming_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    📡 List maestro's live events.
    """
    query = select(LiveEvent).where(LiveEvent.maestro_id == maestro.id).order_by(desc(LiveEvent.scheduled_start))

    if upcoming_only:
        query = query.where(and_(
            LiveEvent.status == LiveEventStatus.SCHEDULED,
            LiveEvent.scheduled_start > datetime.utcnow()
        ))

    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    events = result.scalars().all()

    return {
        "events": events,
        "skip": skip,
        "limit": limit
    }


@router.delete("/live-events/{event_id}")
async def cancel_live_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    ❌ Cancel a live event.
    """
    result = await db.execute(select(LiveEvent).where(and_(
        LiveEvent.id == event_id,
        LiveEvent.maestro_id == maestro.id
    )))
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Live event not found")

    if event.status == LiveEventStatus.LIVE:
        raise HTTPException(status_code=400, detail="Cannot cancel live event that is currently streaming")

    event.status = LiveEventStatus.CANCELLED
    await db.commit()

    return {"message": "Live event cancelled", "event_id": event_id}


# ============================
# EARNINGS & WITHDRAWALS
# ============================

@router.get("/earnings")
async def get_earnings(
    period: str = Query("30d", regex="^(7d|30d|90d|365d|all)$"),
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    💰 Get maestro earnings.

    Returns donations received broken down by period.
    """
    query = select(
        func.count(Donation.id),
        func.sum(Donation.stelline_amount)
    ).where(Donation.to_maestro_id == maestro.id)

    if period != "all":
        days_map = {"7d": 7, "30d": 30, "90d": 90, "365d": 365}
        start_date = datetime.utcnow() - timedelta(days=days_map[period])
        query = query.where(Donation.created_at >= start_date)

    result = await db.execute(query)
    stats = result.one()

    return {
        "period": period,
        "donations_count": stats[0] or 0,
        "total_stelline": stats[1] or 0,
        "total_eur": round((stats[1] or 0) * 0.01, 2)
    }


@router.post("/withdrawals")
async def request_withdrawal(
    data: WithdrawalCreate,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    💸 Request withdrawal of earnings.

    Minimum: 10,000 stelline (€100)
    """
    MIN_WITHDRAWAL = 1000000  # 10,000 stelline = €100

    if data.stelline_amount < MIN_WITHDRAWAL:
        raise HTTPException(status_code=400, detail=f"Minimum withdrawal is {MIN_WITHDRAWAL} stelline (€{MIN_WITHDRAWAL * 0.01})")

    # TODO: Check available balance (not yet withdrawn)

    euro_amount = data.stelline_amount * 0.01

    withdrawal = WithdrawalRequest(
        user_id=maestro.user_id,
        maestro_id=maestro.id,
        stelline_amount=data.stelline_amount,
        euro_amount=euro_amount,
        payout_method=PayoutMethod(data.payout_method),
        iban=data.iban,
        paypal_email=data.paypal_email,
        status=WithdrawalStatus.PENDING
    )

    db.add(withdrawal)
    await db.commit()
    await db.refresh(withdrawal)

    return {"message": "Withdrawal request submitted", "withdrawal": withdrawal}


@router.get("/withdrawals")
async def list_withdrawals(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    💸 List withdrawal requests.
    """
    query = (
        select(WithdrawalRequest)
        .where(WithdrawalRequest.maestro_id == maestro.id)
        .order_by(desc(WithdrawalRequest.requested_at))
        .offset(skip)
        .limit(limit)
    )

    result = await db.execute(query)
    withdrawals = result.scalars().all()

    return {
        "withdrawals": withdrawals,
        "skip": skip,
        "limit": limit
    }


# ============================
# CORRECTION REQUESTS
# ============================

@router.get("/corrections")
async def list_correction_requests(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    ✍️ List student correction requests.
    """
    query = select(CorrectionRequest).where(CorrectionRequest.maestro_id == maestro.id)

    if status:
        query = query.where(CorrectionRequest.status == status)

    query = query.order_by(desc(CorrectionRequest.created_at)).offset(skip).limit(limit)

    result = await db.execute(query)
    requests = result.scalars().all()

    return {
        "correction_requests": requests,
        "skip": skip,
        "limit": limit
    }


@router.post("/corrections/{request_id}/feedback")
async def submit_correction_feedback(
    request_id: str,
    feedback: CorrectionFeedback,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    ✅ Submit feedback for correction request.
    """
    result = await db.execute(select(CorrectionRequest).where(and_(
        CorrectionRequest.id == request_id,
        CorrectionRequest.maestro_id == maestro.id
    )))
    request = result.scalar_one_or_none()

    if not request:
        raise HTTPException(status_code=404, detail="Correction request not found")

    request.complete_review(
        feedback_text=feedback.feedback_text,
        feedback_video_url=feedback.feedback_video_url
    )
    request.feedback_annotations = feedback.feedback_annotations

    await db.commit()

    return {"message": "Feedback submitted", "request_id": request_id}


# ============================
# TRANSLATION DATASETS
# ============================

@router.get("/translations")
async def list_translation_datasets(
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    🌐 List translation datasets.
    """
    result = await db.execute(
        select(TranslationDataset).where(TranslationDataset.maestro_id == maestro.id)
    )
    datasets = result.scalars().all()

    return {"datasets": datasets}


@router.get("/glossary")
async def list_glossary_terms(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    maestro: Maestro = Depends(get_current_maestro)
):
    """
    📖 List glossary terms.
    """
    query = select(GlossaryTerm).where(GlossaryTerm.maestro_id == maestro.id)

    if search:
        query = query.where(GlossaryTerm.term.ilike(f"%{search}%"))

    query = query.order_by(GlossaryTerm.term).offset(skip).limit(limit)

    result = await db.execute(query)
    terms = result.scalars().all()

    return {
        "terms": terms,
        "total": len(terms),
        "skip": skip,
        "limit": limit
    }

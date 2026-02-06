"""
🎓 AI_MODULE: Video Moderation API
🎓 AI_DESCRIPTION: Endpoint per approvazione/rifiuto video da parte dello staff
🎓 AI_BUSINESS: Content moderation workflow
🎓 AI_TEACHING: Admin-only endpoints + state machine transitions

💡 ENDPOINTS:
- GET /moderation/videos/pending - Lista video in moderazione
- POST /moderation/videos/{id}/approve - Approva video
- POST /moderation/videos/{id}/reject - Rifiuta video
- POST /moderation/videos/{id}/request-changes - Richiedi modifiche
- GET /moderation/videos/{id}/history - Storico moderazione
- GET /moderation/stats - Statistiche moderazione
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_admin_user
from core.email import email_service
from models.user import User
from models.video import Video, VideoStatus, VideoModeration
from models.maestro import Maestro
from modules.video_moderation import validate_video_metadata
import logging

logger = logging.getLogger(__name__)


router = APIRouter()


# === SCHEMAS ===

class VideoModerationItem(BaseModel):
    """Video in pending moderation."""
    id: str
    title: str
    description: Optional[str]
    category: str
    difficulty: str
    tags: List[str]
    video_url: str
    thumbnail_url: Optional[str]
    duration: int
    tier_required: str
    uploaded_by: dict  # {id, username, full_name}
    maestro_info: Optional[dict]  # {verification_level, total_videos, total_donations}
    created_at: datetime
    validation: dict  # {valid, score, issues, warnings}

    class Config:
        from_attributes = True


class ApproveVideoRequest(BaseModel):
    """Request to approve video."""
    notes: Optional[str] = None


class RejectVideoRequest(BaseModel):
    """Request to reject video."""
    rejection_reason: str


class RequestChangesRequest(BaseModel):
    """Request changes to video."""
    required_changes: List[str]
    notes: Optional[str] = None


class ModerationHistoryItem(BaseModel):
    """Single moderation action."""
    id: str
    action: str
    moderator: Optional[dict]  # {id, username}
    previous_status: str
    new_status: str
    moderation_notes: Optional[str]
    rejection_reason: Optional[str]
    required_changes: Optional[List[str]]
    metadata_validation: Optional[dict]
    created_at: datetime

    class Config:
        from_attributes = True


class ModerationStats(BaseModel):
    """Moderation statistics."""
    pending_count: int
    approved_today: int
    rejected_today: int
    avg_review_time_minutes: float
    by_moderator: List[dict]


# === ENDPOINTS ===

@router.get(
    "/videos/pending",
    response_model=List[VideoModerationItem],
    summary="Lista video in moderazione",
    description="Ottieni tutti i video in stato PENDING che richiedono moderazione"
)
async def get_pending_videos(
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Lista video pending moderation.

    Ritorna video con:
    - Metadata completi
    - Info maestro (verification_level, stats)
    - Validation automatica (score, issues, warnings)
    """
    # Get pending videos with uploaded_by user info
    result = await db.execute(
        select(Video, User, Maestro)
        .join(User, Video.uploaded_by == User.id)
        .outerjoin(Maestro, Maestro.user_id == User.id)
        .where(Video.status == VideoStatus.PENDING)
        .order_by(Video.created_at.asc())
    )
    rows = result.all()

    pending_videos = []

    for video, user, maestro in rows:
        # Validate metadata
        validation = validate_video_metadata(video)

        # Build maestro info
        maestro_info = None
        if maestro:
            maestro_info = {
                "verification_level": maestro.verification_level,
                "auto_publish_enabled": maestro.auto_publish_enabled,
                "total_videos": maestro.total_videos,
                "total_donations_received": maestro.total_donations_received
            }

        pending_videos.append({
            "id": str(video.id),
            "title": video.title,
            "description": video.description,
            "category": video.category.value if video.category else None,
            "difficulty": video.difficulty.value if video.difficulty else None,
            "tags": video.tags or [],
            "video_url": video.video_url,
            "thumbnail_url": video.thumbnail_url,
            "duration": video.duration,
            "tier_required": video.tier_required,
            "uploaded_by": {
                "id": str(user.id),
                "username": user.username,
                "full_name": user.full_name
            },
            "maestro_info": maestro_info,
            "created_at": video.created_at,
            "validation": validation
        })

    return pending_videos


@router.post(
    "/videos/{video_id}/approve",
    summary="Approva video",
    description="Approva video e pubblica sulla piattaforma"
)
async def approve_video(
    video_id: str,
    request: ApproveVideoRequest,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Approva video.

    Workflow:
    1. Video status: PENDING → READY
    2. is_public: true
    3. published_at: NOW()
    4. Log moderation action
    5. Notifica maestro via email
    """
    # Get video with uploader info
    result = await db.execute(
        select(Video, User)
        .join(User, Video.uploaded_by == User.id)
        .where(Video.id == video_id)
    )
    row = result.first()

    if not row:
        raise HTTPException(status_code=404, detail="Video not found")

    video, uploader = row

    if video.status != VideoStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Video status is {video.status.value}, expected PENDING"
        )

    # Update video
    previous_status = video.status.value
    video.status = VideoStatus.READY
    video.is_public = True
    video.published_at = datetime.utcnow()
    video.approved_by = current_user.id
    video.approved_at = datetime.utcnow()

    # Log moderation
    moderation = VideoModeration(
        video_id=video.id,
        moderator_user_id=current_user.id,
        action="APPROVED",
        previous_status=previous_status,
        new_status=VideoStatus.READY.value,
        moderation_notes=request.notes
    )
    db.add(moderation)

    await db.commit()

    # Send email notification to maestro
    try:
        await email_service.send_video_approved_email(
            to_email=uploader.email,
            maestro_name=uploader.full_name or uploader.username,
            video_title=video.title,
            video_id=str(video.id),
            notes=request.notes
        )
        logger.info(f"Approval email sent to {uploader.email} for video {video.id}")
    except Exception as e:
        logger.error(f"Failed to send approval email: {e}")
        # Don't fail the request if email fails

    return {
        "message": "Video approvato e pubblicato",
        "video_id": str(video.id),
        "published_at": video.published_at
    }


@router.post(
    "/videos/{video_id}/reject",
    summary="Rifiuta video",
    description="Rifiuta video con motivazione"
)
async def reject_video(
    video_id: str,
    request: RejectVideoRequest,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Rifiuta video.

    Workflow:
    1. Video status: PENDING → ARCHIVED
    2. rejection_reason: salvato
    3. Log moderation action
    4. Notifica maestro via email
    """
    # Get video with uploader info
    result = await db.execute(
        select(Video, User)
        .join(User, Video.uploaded_by == User.id)
        .where(Video.id == video_id)
    )
    row = result.first()

    if not row:
        raise HTTPException(status_code=404, detail="Video not found")

    video, uploader = row

    if video.status != VideoStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Video status is {video.status.value}, expected PENDING"
        )

    # Update video
    previous_status = video.status.value
    video.status = VideoStatus.ARCHIVED
    video.rejection_reason = request.rejection_reason

    # Log moderation
    moderation = VideoModeration(
        video_id=video.id,
        moderator_user_id=current_user.id,
        action="REJECTED",
        previous_status=previous_status,
        new_status=VideoStatus.ARCHIVED.value,
        rejection_reason=request.rejection_reason
    )
    db.add(moderation)

    await db.commit()

    # Send email notification to maestro
    try:
        await email_service.send_video_rejected_email(
            to_email=uploader.email,
            maestro_name=uploader.full_name or uploader.username,
            video_title=video.title,
            rejection_reason=request.rejection_reason
        )
        logger.info(f"Rejection email sent to {uploader.email} for video {video.id}")
    except Exception as e:
        logger.error(f"Failed to send rejection email: {e}")
        # Don't fail the request if email fails

    return {
        "message": "Video rifiutato",
        "video_id": str(video.id),
        "reason": request.rejection_reason
    }


@router.post(
    "/videos/{video_id}/request-changes",
    summary="Richiedi modifiche",
    description="Richiedi modifiche al maestro"
)
async def request_changes(
    video_id: str,
    request: RequestChangesRequest,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Richiedi modifiche.

    Workflow:
    1. Video rimane in PENDING
    2. needs_changes_notes: salvato
    3. Log moderation action
    4. Notifica maestro via email con lista modifiche
    """
    # Get video with uploader info
    result = await db.execute(
        select(Video, User)
        .join(User, Video.uploaded_by == User.id)
        .where(Video.id == video_id)
    )
    row = result.first()

    if not row:
        raise HTTPException(status_code=404, detail="Video not found")

    video, uploader = row

    if video.status != VideoStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Video status is {video.status.value}, expected PENDING"
        )

    # Update video
    video.needs_changes_notes = "\n".join(request.required_changes)

    # Log moderation
    moderation = VideoModeration(
        video_id=video.id,
        moderator_user_id=current_user.id,
        action="NEEDS_CHANGES",
        previous_status=VideoStatus.PENDING.value,
        new_status=VideoStatus.PENDING.value,
        required_changes=request.required_changes,
        moderation_notes=request.notes
    )
    db.add(moderation)

    await db.commit()

    # Send email notification to maestro
    try:
        await email_service.send_video_changes_requested_email(
            to_email=uploader.email,
            maestro_name=uploader.full_name or uploader.username,
            video_title=video.title,
            video_id=str(video.id),
            required_changes=request.required_changes,
            notes=request.notes
        )
        logger.info(f"Changes requested email sent to {uploader.email} for video {video.id}")
    except Exception as e:
        logger.error(f"Failed to send changes requested email: {e}")
        # Don't fail the request if email fails

    return {
        "message": "Modifiche richieste",
        "video_id": str(video.id),
        "changes": request.required_changes
    }


@router.get(
    "/videos/{video_id}/history",
    response_model=List[ModerationHistoryItem],
    summary="Storico moderazione video",
    description="Ottieni storico completo moderazioni per un video"
)
async def get_moderation_history(
    video_id: str,
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Storico moderazione video.

    Ritorna tutte le azioni di moderazione effettuate sul video,
    in ordine cronologico.
    """
    # Get moderation history
    result = await db.execute(
        select(VideoModeration, User)
        .outerjoin(User, VideoModeration.moderator_user_id == User.id)
        .where(VideoModeration.video_id == video_id)
        .order_by(VideoModeration.created_at.desc())
    )
    rows = result.all()

    history = []
    for moderation, moderator_user in rows:
        moderator = None
        if moderator_user:
            moderator = {
                "id": str(moderator_user.id),
                "username": moderator_user.username
            }

        history.append({
            "id": str(moderation.id),
            "action": moderation.action,
            "moderator": moderator,
            "previous_status": moderation.previous_status,
            "new_status": moderation.new_status,
            "moderation_notes": moderation.moderation_notes,
            "rejection_reason": moderation.rejection_reason,
            "required_changes": moderation.required_changes,
            "metadata_validation": moderation.metadata_validation,
            "created_at": moderation.created_at
        })

    return history


@router.get(
    "/stats",
    response_model=ModerationStats,
    summary="Statistiche moderazione",
    description="Statistiche aggregate moderazione video"
)
async def get_moderation_stats(
    current_user: User = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Statistiche moderazione.

    Ritorna:
    - Numero video pending
    - Video approvati/rifiutati oggi
    - Tempo medio revisione
    - Stats per moderatore
    """
    # Pending count
    pending_result = await db.execute(
        select(func.count(Video.id)).where(Video.status == VideoStatus.PENDING)
    )
    pending_count = pending_result.scalar() or 0

    # Today's actions
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    approved_today_result = await db.execute(
        select(func.count(VideoModeration.id))
        .where(
            and_(
                VideoModeration.action == "APPROVED",
                VideoModeration.created_at >= today_start
            )
        )
    )
    approved_today = approved_today_result.scalar() or 0

    rejected_today_result = await db.execute(
        select(func.count(VideoModeration.id))
        .where(
            and_(
                VideoModeration.action == "REJECTED",
                VideoModeration.created_at >= today_start
            )
        )
    )
    rejected_today = rejected_today_result.scalar() or 0

    # TODO: Calculate avg review time
    avg_review_time = 45.0  # Placeholder

    # TODO: Stats by moderator
    by_moderator = []

    return {
        "pending_count": pending_count,
        "approved_today": approved_today,
        "rejected_today": rejected_today,
        "avg_review_time_minutes": avg_review_time,
        "by_moderator": by_moderator
    }

"""
🎓 AI_MODULE: LibraryRouter
🎓 AI_DESCRIPTION: Gestione libreria personale utente con video salvati e progressi
🎓 AI_BUSINESS: Retention utente +40%, tracking progressi, gamification
🎓 AI_TEACHING: FastAPI router con SQLAlchemy 2.x async queries per user-specific data

📊 ENDPOINTS:
- GET /saved: Video salvati dall'utente
- GET /in-progress: Video con visione parziale
- GET /completed: Video completati al 100%
- GET /downloaded: Video scaricati offline (premium)
- POST /save/{video_id}: Salva video
- DELETE /save/{video_id}: Rimuovi da salvati
- POST /progress/{video_id}: Aggiorna progresso visione

🎯 BUSINESS_IMPACT:
- Engagement tracking
- Personalized content
- Completion rates analytics

🔄 FIX 2025-01-11:
- Convertito da SQLAlchemy 1.x sync (.query()) a SQLAlchemy 2.x async (select())
- Causa errore: 'AsyncSession' object has no attribute 'query'
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_user
from models.user import User
from models.video import Video, LibraryItem
from models.user_video import UserVideo

router = APIRouter(prefix="/library", tags=["library"])


# ========== SCHEMAS ==========

class LibraryVideoResponse(BaseModel):
    id: int
    title: str
    thumbnail_url: Optional[str]
    duration: int
    progress: int  # percentage 0-100
    style: str
    level: str
    maestro_name: str
    saved_at: Optional[datetime]
    completed_at: Optional[datetime]
    downloaded: bool = False

    class Config:
        from_attributes = True


class ProgressUpdate(BaseModel):
    progress: int  # percentage 0-100


class MessageResponse(BaseModel):
    message: str
    success: bool = True


# ========== HELPER FUNCTIONS ==========

def get_library_video_response(user_video: UserVideo) -> LibraryVideoResponse:
    """
    Convert UserVideo model to response schema.
    
    🎓 AI_TEACHING: Questa funzione gestisce la conversione del modello SQLAlchemy
    in Pydantic response, con fallback per relazioni che potrebbero essere None.
    """
    video = user_video.video
    return LibraryVideoResponse(
        id=video.id,
        title=video.title,
        thumbnail_url=video.thumbnail_url,
        duration=video.duration,
        progress=user_video.progress,
        style=video.style or "General",
        level=video.level or "Principiante",
        maestro_name=video.maestro.name if video.maestro else "Unknown",
        saved_at=user_video.saved_at,
        completed_at=user_video.completed_at,
        downloaded=user_video.downloaded
    )


# ========== ENDPOINTS ==========


@router.get("/stats")
async def get_library_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    🎓 AI_MODULE: Library Stats
    🎓 AI_DESCRIPTION: Ritorna statistiche aggregate della libreria contenuti
    🎓 AI_BUSINESS: Dashboard overview — utente vede attività libreria
    🎓 AI_TEACHING: Aggregazione SQL con func.count() su tabelle Video e LibraryItem
    """
    # Count totale video disponibili (status READY)
    from models.video import VideoStatus
    total_videos_result = await db.execute(
        select(func.count()).select_from(Video).where(Video.status == VideoStatus.READY)
    )
    total_videos = total_videos_result.scalar() or 0

    # Count documenti (LibraryItem = PDF/images)
    total_documents_result = await db.execute(
        select(func.count()).select_from(LibraryItem)
    )
    total_documents = total_documents_result.scalar() or 0

    # Totale items combinato
    total_items = total_videos + total_documents

    # Ultimi 5 video aggiunti
    recent_videos_result = await db.execute(
        select(Video)
        .where(Video.status == VideoStatus.READY)
        .order_by(Video.created_at.desc())
        .limit(5)
    )
    recent_videos = recent_videos_result.scalars().all()

    recent_additions = [
        {
            "id": str(v.id),
            "title": v.title,
            "type": "video",
            "created_at": v.created_at.isoformat() if v.created_at else None
        }
        for v in recent_videos
    ]

    return {
        "total": total_items,
        "total_items": total_items,
        "total_videos": total_videos,
        "total_documents": total_documents,
        "recent_additions": recent_additions
    }


@router.get("/saved", response_model=List[LibraryVideoResponse])
async def get_saved_videos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all videos saved by the current user.
    Returns videos ordered by saved_at date (most recent first).
    
    🎓 AI_TEACHING: Usa select() con and_() per SQLAlchemy 2.x async.
    """
    # SQLAlchemy 2.x: select() invece di .query()
    result = await db.execute(
        select(UserVideo)
        .where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.is_saved == True
            )
        )
        .order_by(UserVideo.saved_at.desc())
    )
    user_videos = result.scalars().all()

    return [get_library_video_response(uv) for uv in user_videos]


@router.get("/in-progress", response_model=List[LibraryVideoResponse])
async def get_in_progress_videos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get videos currently being watched (progress > 0 and < 100).
    Returns videos ordered by last_watched date (most recent first).
    """
    result = await db.execute(
        select(UserVideo)
        .where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.progress > 0,
                UserVideo.progress < 100
            )
        )
        .order_by(UserVideo.last_watched.desc())
    )
    user_videos = result.scalars().all()

    return [get_library_video_response(uv) for uv in user_videos]


@router.get("/completed", response_model=List[LibraryVideoResponse])
async def get_completed_videos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all videos completed by the user (progress = 100).
    Returns videos ordered by completed_at date (most recent first).
    """
    result = await db.execute(
        select(UserVideo)
        .where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.progress == 100
            )
        )
        .order_by(UserVideo.completed_at.desc())
    )
    user_videos = result.scalars().all()

    return [get_library_video_response(uv) for uv in user_videos]


@router.get("/downloaded", response_model=List[LibraryVideoResponse])
async def get_downloaded_videos(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all videos downloaded for offline viewing.
    Premium feature - returns empty list for free users.
    """
    # Check if user has premium subscription
    if current_user.subscription_type == "free":
        return []

    result = await db.execute(
        select(UserVideo)
        .where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.downloaded == True
            )
        )
        .order_by(UserVideo.downloaded_at.desc())
    )
    user_videos = result.scalars().all()

    return [get_library_video_response(uv) for uv in user_videos]


@router.post("/save/{video_id}", response_model=MessageResponse)
async def save_video(
    video_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Save a video to user's library.
    Creates UserVideo record if not exists, or updates is_saved flag.
    """
    # Check video exists
    video_result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = video_result.scalar_one_or_none()
    
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Get or create user_video
    uv_result = await db.execute(
        select(UserVideo).where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.video_id == video_id
            )
        )
    )
    user_video = uv_result.scalar_one_or_none()

    if user_video:
        user_video.is_saved = True
        user_video.saved_at = datetime.utcnow()
    else:
        user_video = UserVideo(
            user_id=current_user.id,
            video_id=video_id,
            is_saved=True,
            saved_at=datetime.utcnow(),
            progress=0
        )
        db.add(user_video)

    await db.commit()

    return MessageResponse(message="Video saved to library")


@router.delete("/save/{video_id}", response_model=MessageResponse)
async def unsave_video(
    video_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remove a video from user's saved list.
    Does not delete progress data.
    """
    result = await db.execute(
        select(UserVideo).where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.video_id == video_id
            )
        )
    )
    user_video = result.scalar_one_or_none()

    if not user_video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not in library"
        )

    user_video.is_saved = False
    user_video.saved_at = None
    await db.commit()

    return MessageResponse(message="Video removed from library")


@router.post("/progress/{video_id}", response_model=MessageResponse)
async def update_progress(
    video_id: int,
    progress_data: ProgressUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update video watching progress.
    Progress is percentage 0-100.
    Marks as completed when progress reaches 100.
    """
    # Validate progress
    if progress_data.progress < 0 or progress_data.progress > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Progress must be between 0 and 100"
        )

    # Check video exists
    video_result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = video_result.scalar_one_or_none()
    
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Get or create user_video
    uv_result = await db.execute(
        select(UserVideo).where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.video_id == video_id
            )
        )
    )
    user_video = uv_result.scalar_one_or_none()

    if user_video:
        user_video.progress = progress_data.progress
        user_video.last_watched = datetime.utcnow()

        # Mark as completed if 100%
        if progress_data.progress == 100 and not user_video.completed_at:
            user_video.completed_at = datetime.utcnow()
    else:
        user_video = UserVideo(
            user_id=current_user.id,
            video_id=video_id,
            progress=progress_data.progress,
            last_watched=datetime.utcnow(),
            completed_at=datetime.utcnow() if progress_data.progress == 100 else None
        )
        db.add(user_video)

    await db.commit()

    return MessageResponse(
        message=f"Progress updated to {progress_data.progress}%"
    )


@router.post("/download/{video_id}", response_model=MessageResponse)
async def download_video(
    video_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Mark video as downloaded for offline viewing.
    Premium feature only.
    """
    # Check premium subscription
    if current_user.subscription_type == "free":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Download is a premium feature"
        )

    # Check video exists
    video_result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = video_result.scalar_one_or_none()
    
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Get or create user_video
    uv_result = await db.execute(
        select(UserVideo).where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.video_id == video_id
            )
        )
    )
    user_video = uv_result.scalar_one_or_none()

    if user_video:
        user_video.downloaded = True
        user_video.downloaded_at = datetime.utcnow()
    else:
        user_video = UserVideo(
            user_id=current_user.id,
            video_id=video_id,
            downloaded=True,
            downloaded_at=datetime.utcnow(),
            progress=0
        )
        db.add(user_video)

    await db.commit()

    return MessageResponse(message="Video marked for download")


@router.delete("/download/{video_id}", response_model=MessageResponse)
async def remove_download(
    video_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remove video from downloads.
    """
    result = await db.execute(
        select(UserVideo).where(
            and_(
                UserVideo.user_id == current_user.id,
                UserVideo.video_id == video_id
            )
        )
    )
    user_video = result.scalar_one_or_none()

    if not user_video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not in library"
        )

    user_video.downloaded = False
    user_video.downloaded_at = None
    await db.commit()

    return MessageResponse(message="Download removed")

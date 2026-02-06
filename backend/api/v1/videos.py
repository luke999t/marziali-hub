"""
🎓 AI_MODULE: Videos API Router
🎓 AI_DESCRIPTION: Video CRUD + streaming + favorites + analytics
🎓 AI_BUSINESS: Core content delivery system
🎓 AI_TEACHING: FastAPI router + file upload + streaming + access control

💡 ENDPOINTS:
- GET /videos - List videos (filtri + pagination)
- GET /videos/{id} - Video details
- POST /videos - Upload video (admin)
- PUT /videos/{id} - Update video (admin)
- DELETE /videos/{id} - Delete video (admin)
- GET /videos/{id}/stream - Get streaming URL + token
- POST /videos/{id}/favorite - Add to My List
- DELETE /videos/{id}/favorite - Remove from My List
- GET /videos/favorites - Get My List
- POST /videos/{id}/progress - Update viewing progress
- GET /videos/continue-watching - Get continue watching
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from typing import Optional, List
from datetime import datetime, timedelta
import uuid
import re
import unicodedata
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

from core.database import get_db
from core.security import get_current_user, get_current_admin_user, get_optional_user
from models.user import User
from models.video import Video, VideoStatus, VideoCategory, Difficulty
from models.user import Favorite, ViewingHistory
from api.v1.schemas import (
    VideoCreateRequest,
    VideoUpdateRequest,
    VideoResponse,
    VideoListResponse,
    MessageResponse,
    VideoProgressUpdate
)


def slugify(text: str) -> str:
    """
    Convert text to URL-friendly slug.

    Production-ready implementation without external dependencies.
    """
    # Normalize unicode characters
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')

    # Convert to lowercase and replace spaces/special chars with hyphens
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)

    # Remove leading/trailing hyphens
    return text.strip('-')


def delete_video_files(video: Video) -> dict:
    """
    Delete video files from storage.

    Handles:
    - Original video file (video_url)
    - Thumbnail (thumbnail_url)
    - HLS playlist and segments (hls_playlist_url)

    Args:
        video: Video model instance

    Returns:
        dict with deleted files and errors
    """
    deleted = []
    errors = []

    def try_delete_file(url: str, file_type: str) -> None:
        """Try to delete a file from a URL path."""
        if not url:
            return

        # Convert URL to local path
        # Handle both absolute paths and relative URLs
        if url.startswith(('http://', 'https://')):
            # Skip remote URLs - handled by CDN/external storage
            logger.info(f"Skipping remote {file_type} URL: {url}")
            return

        # Try as absolute path first
        path = Path(url)
        if not path.is_absolute():
            # Assume relative to storage directory
            storage_base = Path(os.environ.get("STORAGE_PATH", "/storage"))
            path = storage_base / url.lstrip("/")

        if path.exists():
            try:
                if path.is_file():
                    path.unlink()
                    deleted.append(str(path))
                    logger.info(f"Deleted {file_type}: {path}")
                elif path.is_dir():
                    # For HLS, delete entire directory
                    import shutil
                    shutil.rmtree(path)
                    deleted.append(str(path))
                    logger.info(f"Deleted {file_type} directory: {path}")
            except Exception as e:
                errors.append({"file": str(path), "error": str(e)})
                logger.error(f"Failed to delete {file_type} {path}: {e}")
        else:
            logger.debug(f"{file_type} not found at: {path}")

    # Delete main video file
    try_delete_file(video.video_url, "video")

    # Delete thumbnail
    try_delete_file(video.thumbnail_url, "thumbnail")

    # Delete HLS files
    if video.hls_playlist_url:
        # HLS playlist is usually in a directory with segments
        hls_path = Path(video.hls_playlist_url)
        if not hls_path.is_absolute():
            storage_base = Path(os.environ.get("STORAGE_PATH", "/storage"))
            hls_path = storage_base / video.hls_playlist_url.lstrip("/")

        # Delete the playlist directory (contains .m3u8 and .ts files)
        hls_dir = hls_path.parent
        try_delete_file(str(hls_dir), "hls_directory")

    return {"deleted": deleted, "errors": errors}


router = APIRouter()


# === STATS ===

@router.get(
    "/stats",
    summary="Get video stats",
    description="Get aggregate video statistics for dashboard"
)
async def get_video_stats(
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    🎓 AI_MODULE: Video Stats
    🎓 AI_DESCRIPTION: Statistiche aggregate video per dashboard
    🎓 AI_BUSINESS: Dashboard overview — conteggi video, processing, modelli
    🎓 AI_TEACHING: Aggregazione con func.count() e filtri per status
    """
    total_result = await db.execute(
        select(func.count()).select_from(Video)
    )
    total = total_result.scalar() or 0

    ready_result = await db.execute(
        select(func.count()).select_from(Video).where(Video.status == VideoStatus.READY)
    )
    ready = ready_result.scalar() or 0

    processing_result = await db.execute(
        select(func.count()).select_from(Video).where(Video.status == VideoStatus.PROCESSING)
    )
    processing_jobs = processing_result.scalar() or 0

    return {
        "total": total,
        "ready": ready,
        "processing_jobs": processing_jobs,
        "voice_models": 0
    }


# === CATEGORIES ===

@router.get(
    "/categories",
    summary="Get video categories",
    description="Get list of distinct video categories with counts"
)
async def get_video_categories(
    db: AsyncSession = Depends(get_db)
):
    """
    🎓 AI_MODULE: Video Categories
    🎓 AI_DESCRIPTION: Lista categorie video distinte dal DB con conteggio
    🎓 AI_BUSINESS: Navigazione contenuti — utenti filtrano per categoria
    🎓 AI_TEACHING: Query DISTINCT + GROUP BY con func.count()
    """
    result = await db.execute(
        select(
            Video.category,
            func.count(Video.id).label("count")
        )
        .where(Video.status == VideoStatus.READY)
        .group_by(Video.category)
        .order_by(func.count(Video.id).desc())
    )
    rows = result.all()

    categories = [
        {
            "name": row[0].value if row[0] else "other",
            "count": row[1]
        }
        for row in rows
    ]

    # Aggiungi categorie disponibili dall'enum anche se vuote
    existing_names = {c["name"] for c in categories}
    for cat in VideoCategory:
        if cat.value not in existing_names:
            categories.append({"name": cat.value, "count": 0})

    return {"categories": categories}


# === UPLOAD (File Upload) ===

@router.post(
    "/upload",
    summary="Upload video file",
    description="Upload a video file for processing"
)
async def upload_video_file(
    file: UploadFile = File(...),
    title: str = "",
    category: Optional[str] = None,
    difficulty: Optional[str] = None,
    style: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    🎓 AI_MODULE: Video Upload
    🎓 AI_DESCRIPTION: Upload file video con salvataggio su disco e creazione record DB
    🎓 AI_BUSINESS: Admin carica nuovi video per la piattaforma
    🎓 AI_TEACHING: Multipart file upload con UploadFile, salvataggio asincrono
    """
    UPLOAD_DIR = Path(os.environ.get("STORAGE_PATH", "data/uploads"))
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    file_id = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1] if file.filename else ".mp4"
    file_path = UPLOAD_DIR / f"{file_id}{file_ext}"

    # Salva file su disco
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)

    # Crea slug dal titolo o filename
    video_title = title or (file.filename or f"video-{file_id}")
    slug = slugify(video_title)

    # Verifica unicità slug
    existing = await db.execute(
        select(Video).where(Video.slug == slug)
    )
    if existing.scalar_one_or_none():
        slug = f"{slug}-{uuid.uuid4().hex[:8]}"

    # Crea record video nel DB
    video = Video(
        title=video_title,
        slug=slug,
        category=VideoCategory(category) if category and category in [e.value for e in VideoCategory] else VideoCategory.OTHER,
        difficulty=Difficulty(difficulty) if difficulty and difficulty in [e.value for e in Difficulty] else Difficulty.BEGINNER,
        style=style,
        video_url=str(file_path),
        duration=0,
        status=VideoStatus.PENDING,
        uploaded_by=admin.id
    )

    db.add(video)
    await db.commit()
    await db.refresh(video)

    return {
        "id": str(video.id),
        "title": video.title,
        "file_path": str(file_path),
        "file_size": len(content),
        "status": video.status.value,
        "message": f"Video '{video.title}' uploaded successfully"
    }


# === LIST & SEARCH ===

@router.get(
    "/",
    response_model=VideoListResponse,
    summary="List videos",
    description="Get paginated list of videos with filters"
)
@router.get(
    "",
    response_model=VideoListResponse,
    include_in_schema=False,
)
async def list_videos(
    skip: int = Query(0, ge=0, description="Number of items to skip"),
    limit: int = Query(20, ge=1, le=100, description="Number of items to return"),
    category: Optional[VideoCategory] = Query(None, description="Filter by category"),
    difficulty: Optional[Difficulty] = Query(None, description="Filter by difficulty"),
    tier: Optional[str] = Query(None, description="Filter by tier"),
    search: Optional[str] = Query(None, min_length=2, description="Search in title/description"),
    sort_by: str = Query("created_at", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    List videos with filters and pagination.

    **Filters:**
    - category: technique, kata, combat, theory, workout, demo, other
    - difficulty: beginner, intermediate, advanced, expert
    - tier: free, hybrid_light, hybrid_standard, premium, business
    - search: Search in title and description

    **Sorting:**
    - created_at: Newest/oldest first
    - view_count: Most/least viewed
    - title: A-Z or Z-A

    **Access Control:**
    - Logged in: See all available videos for tier
    - Anonymous: See only free public videos
    """
    # Base query
    query = select(Video).where(Video.status == VideoStatus.READY)

    # Public filter (if not logged in)
    if not current_user:
        query = query.where(Video.is_public == True)
        query = query.where(Video.tier_required == "free")

    # Category filter
    if category:
        query = query.where(Video.category == category)

    # Difficulty filter
    if difficulty:
        query = query.where(Video.difficulty == difficulty)

    # Tier filter
    if tier:
        query = query.where(Video.tier_required == tier)

    # Search filter (title/description only - tags are arrays)
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            or_(
                Video.title.ilike(search_pattern),
                Video.description.ilike(search_pattern)
            )
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Sort
    if sort_by == "created_at":
        order_col = Video.created_at
    elif sort_by == "view_count":
        order_col = Video.view_count
    elif sort_by == "title":
        order_col = Video.title
    else:
        order_col = Video.created_at

    if sort_order == "desc":
        query = query.order_by(order_col.desc())
    else:
        query = query.order_by(order_col.asc())

    # Pagination
    query = query.offset(skip).limit(limit)

    # Execute
    result = await db.execute(query)
    videos = result.scalars().all()

    return VideoListResponse(
        videos=[VideoResponse.model_validate(v) for v in videos],
        total=total,
        skip=skip,
        limit=limit
    )


# === SEARCH VIDEOS ===

@router.get(
    "/search",
    response_model=VideoListResponse,
    summary="Search videos",
    description="Search videos by query string"
)
async def search_videos(
    q: str = Query(..., min_length=2, description="Search query"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Search videos by title, description, or tags.

    🔍 SEARCH: Full-text search con ilike
    """
    query = select(Video).where(Video.status == VideoStatus.READY)

    # Apply search filter (title/description only - tags are arrays)
    search_pattern = f"%{q}%"
    query = query.where(
        or_(
            Video.title.ilike(search_pattern),
            Video.description.ilike(search_pattern)
        )
    )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Get paginated results
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    videos = result.scalars().all()

    return VideoListResponse(
        videos=[VideoResponse.model_validate(v) for v in videos],
        total=total,
        skip=skip,
        limit=limit
    )


# === TRENDING VIDEOS ===

@router.get(
    "/trending",
    response_model=List[VideoResponse],
    summary="Get trending videos",
    description="Get most viewed videos from the last 7 days"
)
async def get_trending_videos(
    limit: int = Query(default=10, ge=1, le=50, description="Number of videos to return"),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    🎓 AI_MODULE: Trending Videos
    🎓 AI_DESCRIPTION: Ritorna video piu visti/popolari ultimi 7 giorni
    🎓 AI_BUSINESS: Homepage engagement, discovery

    Returns videos sorted by view_count descending,
    filtered to those created/updated in the last 7 days.
    """
    week_ago = datetime.utcnow() - timedelta(days=7)

    query = select(Video).where(
        and_(
            Video.status == VideoStatus.READY,
            Video.created_at >= week_ago
        )
    ).order_by(Video.view_count.desc()).limit(limit)

    result = await db.execute(query)
    videos = result.scalars().all()

    return [VideoResponse.model_validate(v) for v in videos]


# === HOME FEED (MOBILE) ===

@router.get(
    "/home",
    summary="Get home feed",
    description="Get featured video and categorized content rows for home screen"
)
async def get_home_feed(
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Get home feed for mobile app.

    Returns:
    - featured: Hero video in evidenza
    - rows: Content rows by style/level

    🎯 BUSINESS: Entry point principale, determina engagement
    """
    # Get featured video (most recent premium/highlighted)
    featured_query = select(Video).where(
        and_(
            Video.status == VideoStatus.READY,
            or_(
                Video.is_featured == True,
                Video.tier_required == "premium"
            )
        )
    ).order_by(Video.created_at.desc()).limit(1)

    featured_result = await db.execute(featured_query)
    featured_video = featured_result.scalar_one_or_none()

    # Get content rows by style
    rows = []
    styles = ["Karate", "Judo", "Aikido", "Taekwondo", "Kung Fu"]

    for style in styles:
        style_query = select(Video).where(
            and_(
                Video.status == VideoStatus.READY,
                Video.style == style
            )
        ).order_by(Video.created_at.desc()).limit(10)

        result = await db.execute(style_query)
        videos = result.scalars().all()

        if videos:
            rows.append({
                "title": style,
                "videos": [VideoResponse.model_validate(v) for v in videos]
            })

    # Get continue watching if user is authenticated
    continue_watching = []
    if current_user:
        cw_query = select(Video).join(
            ViewingHistory,
            Video.id == ViewingHistory.video_id
        ).where(
            and_(
                ViewingHistory.user_id == current_user.id,
                ViewingHistory.last_position > 0,
                ViewingHistory.completed == False
            )
        ).order_by(ViewingHistory.watched_at.desc()).limit(10)

        cw_result = await db.execute(cw_query)
        cw_videos = cw_result.scalars().all()

        if cw_videos:
            rows.insert(0, {
                "title": "Continua a guardare",
                "videos": [VideoResponse.model_validate(v) for v in cw_videos]
            })

    return {
        "featured": VideoResponse.model_validate(featured_video) if featured_video else None,
        "rows": rows
    }


# === CONTINUE WATCHING ===

@router.get(
    "/continue-watching",
    response_model=List[VideoResponse],
    summary="Get continue watching",
    description="Get videos user has started but not finished"
)
async def get_continue_watching(
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get continue watching list.

    Returns videos user has started watching but not completed,
    ordered by most recently watched.
    """
    # Get viewing history (not completed, with position > 30s)
    history_result = await db.execute(
        select(ViewingHistory.video_id)
        .where(
            and_(
                ViewingHistory.user_id == current_user.id,
                ViewingHistory.completed == False,
                ViewingHistory.last_position > 30
            )
        )
        .order_by(ViewingHistory.watched_at.desc())
        .limit(limit)
    )
    video_ids = [row[0] for row in history_result.fetchall()]

    if not video_ids:
        return []

    # Get videos
    videos_result = await db.execute(
        select(Video).where(Video.id.in_(video_ids))
    )
    videos = videos_result.scalars().all()

    return [VideoResponse.model_validate(v) for v in videos]


# === SKELETONS LIST ===

@router.get(
    "/skeletons",
    summary="List extracted skeletons",
    description="Get list of all extracted skeleton files"
)
async def list_skeletons():
    """List all extracted skeletons."""
    import json
    from pathlib import Path

    skeleton_dir = Path("data/skeletons")
    if not skeleton_dir.exists():
        return {"skeletons": [], "total": 0}

    skeletons = []
    for skeleton_file in skeleton_dir.glob("*_skeleton.json"):
        try:
            with open(skeleton_file, "r") as f:
                data = json.load(f)

            asset_id = skeleton_file.stem.replace("_skeleton", "")
            skeletons.append({
                "id": asset_id,
                "filename": data.get("video_metadata", {}).get("filename", "unknown"),
                "frames": data.get("extraction_info", {}).get("frames_processed", 0),
                "duration": data.get("video_metadata", {}).get("duration", 0),
                "path": str(skeleton_file),
                "created_at": skeleton_file.stat().st_mtime
            })
        except Exception:
            continue

    # Sort by creation time (newest first)
    skeletons.sort(key=lambda x: x.get("created_at", 0), reverse=True)

    return {"skeletons": skeletons, "total": len(skeletons)}


# === GET SKELETON BY ID ===

@router.get(
    "/skeleton/{asset_id}",
    summary="Get skeleton data by asset ID",
    description="Get skeleton JSON data for a specific asset"
)
async def get_skeleton(asset_id: str):
    """
    Get skeleton data by asset ID.

    Returns the full skeleton JSON including all frames and landmarks.
    """
    import re

    # Sanitize asset_id to prevent path traversal
    if not re.match(r'^[a-zA-Z0-9_-]+$', asset_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid asset ID format"
        )

    skeleton_dir = Path("data/skeletons")
    skeleton_file = skeleton_dir / f"{asset_id}_skeleton.json"

    if not skeleton_file.exists():
        # Try without _skeleton suffix
        skeleton_file = skeleton_dir / f"{asset_id}.json"

    if not skeleton_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Skeleton not found for asset: {asset_id}"
        )

    try:
        with open(skeleton_file, "r") as f:
            data = json.load(f)

        return {
            "asset_id": asset_id,
            "frames": data.get("frames", []),
            "total_frames": len(data.get("frames", [])),
            "metadata": data.get("video_metadata", {}),
            "extraction_info": data.get("extraction_info", {})
        }
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Invalid skeleton data format"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to read skeleton: {str(e)}"
        )


# === FAVORITES - MUST COME BEFORE /{video_id} ===

@router.get(
    "/favorites",
    response_model=VideoListResponse,
    summary="Get My List",
    description="Get user's favorite videos"
)
async def get_favorites(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get user's My List with pagination."""
    # Get favorite video IDs
    favorites_result = await db.execute(
        select(Favorite.video_id)
        .where(Favorite.user_id == current_user.id)
        .order_by(Favorite.added_at.desc())
        .offset(skip)
        .limit(limit)
    )
    video_ids = [row[0] for row in favorites_result.fetchall()]

    if not video_ids:
        return VideoListResponse(videos=[], total=0, skip=skip, limit=limit)

    # Get videos
    videos_result = await db.execute(
        select(Video).where(Video.id.in_(video_ids))
    )
    videos = videos_result.scalars().all()

    # Count total
    count_result = await db.execute(
        select(func.count()).select_from(Favorite).where(
            Favorite.user_id == current_user.id
        )
    )
    total = count_result.scalar()

    return VideoListResponse(
        videos=[VideoResponse.model_validate(v) for v in videos],
        total=total,
        skip=skip,
        limit=limit
    )


# === GET VIDEO DETAILS ===

@router.get(
    "/{video_id}",
    response_model=VideoResponse,
    summary="Get video details",
    description="Get detailed information about a specific video"
)
async def get_video(
    video_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user)
):
    """
    Get video details by ID.

    **Access Control:**
    - Public videos: Anyone can see
    - Private videos: Only logged in users
    - Premium videos: Only users with appropriate tier
    """
    # Validate UUID format to prevent path traversal attacks
    try:
        from uuid import UUID
        UUID(video_id)
    except (ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid video ID format"
        )

    result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Check access
    if not video.is_available_for_user(current_user):
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Login required to view this video"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This video requires {video.tier_required} tier or higher"
            )

    return VideoResponse.model_validate(video)


# === CREATE VIDEO (ADMIN) ===

@router.post(
    "/",
    response_model=VideoResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create video",
    description="Upload new video (admin only)"
)
@router.post(
    "",
    response_model=VideoResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def create_video(
    data: VideoCreateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Create new video entry.

    **Admin only**

    Video will be in PENDING status until processing complete.
    Use separate upload endpoint for video file.
    """
    # Create slug
    slug = slugify(data.title)

    # Check slug unique
    existing = await db.execute(
        select(Video).where(Video.slug == slug)
    )
    if existing.scalar_one_or_none():
        # Add random suffix
        slug = f"{slug}-{uuid.uuid4().hex[:8]}"

    # Create video
    video = Video(
        title=data.title,
        description=data.description,
        slug=slug,
        category=data.category,
        difficulty=data.difficulty,
        style=data.style,
        tags=data.tags,
        tier_required=data.tier_required,
        is_premium=data.is_premium,
        ppv_price=data.ppv_price,
        instructor_name=data.instructor_name,
        video_url="",  # Will be set by upload service
        duration=0,    # Will be set by processing
        status=VideoStatus.PENDING,
        uploaded_by=admin.id
    )

    db.add(video)
    await db.commit()
    await db.refresh(video)

    return VideoResponse.model_validate(video)


# === UPDATE VIDEO (ADMIN) ===

@router.put(
    "/{video_id}",
    response_model=VideoResponse,
    summary="Update video",
    description="Update video metadata (admin only)"
)
async def update_video(
    video_id: str,
    data: VideoUpdateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Update video metadata.

    **Admin only**

    Can update:
    - Title, description
    - Category, difficulty, tags
    - Tier required, premium status
    - PPV price
    """
    result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(video, field, value)

    video.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(video)

    return VideoResponse.model_validate(video)


# === DELETE VIDEO (ADMIN) ===

@router.delete(
    "/{video_id}",
    response_model=MessageResponse,
    summary="Delete video",
    description="Delete video (admin only)"
)
async def delete_video(
    video_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Delete video.

    **Admin only**

    **Warning**: This will permanently delete video and all related data.
    Consider archiving instead (set status=ARCHIVED).
    """
    result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Store video info before deletion
    video_title = video.title

    # Delete video files from storage
    file_result = delete_video_files(video)
    if file_result["errors"]:
        logger.warning(f"Some files could not be deleted for video {video_id}: {file_result['errors']}")

    # Delete from database
    await db.delete(video)
    await db.commit()

    logger.info(f"Video {video_id} deleted. Files removed: {len(file_result['deleted'])}")

    return MessageResponse(
        message=f"Video '{video_title}' deleted successfully",
        success=True
    )


# === GET STREAMING URL ===

@router.get(
    "/{video_id}/stream",
    summary="Get streaming URL",
    description="Get HLS streaming URL with temporary token"
)
@router.get(
    "/{video_id}/streaming",
    summary="Get streaming URL (alias)",
    description="Get HLS streaming URL with temporary token"
)
async def get_stream_url(
    video_id: str,
    quality: Optional[str] = Query(None, description="Preferred quality (360p, 720p, 1080p, 4k)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get streaming URL for video.

    Returns:
    - HLS playlist URL (.m3u8)
    - Temporary streaming token (1h expiry)
    - Available qualities
    - Subtitle URLs

    **Access Control:**
    - Check tier permissions
    - Check ads unlock status
    - Generate streaming token
    """
    result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Check access
    if not video.is_available_for_user(current_user):
        # Check if has ads unlock
        if current_user.has_unlocked_videos():
            # TODO: Check if this specific video is unlocked
            pass
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Upgrade to {video.tier_required} tier or watch ads to unlock"
            )

    # Get best quality for user tier
    if not quality:
        quality = video.get_best_quality_for_tier(current_user.tier.value)

    # Generate streaming token
    from core.security import create_access_token
    streaming_token = create_access_token(
        data={
            "sub": str(current_user.id),
            "video_id": str(video.id),
            "type": "streaming"
        },
        expires_delta=timedelta(hours=1)
    )

    # Get streaming URL
    hls_url = video.hls_playlist_url or video.video_url

    # Add token to URL
    streaming_url = f"{hls_url}?token={streaming_token}&quality={quality}"

    return {
        "streaming_url": streaming_url,
        "token": streaming_token,
        "expires_in": 3600,  # 1 hour
        "quality": quality,
        "available_qualities": video.quality_available,
        "subtitles": video.subtitle_urls if video.has_subtitles else None,
        "duration": video.duration
    }


# === FAVORITES (MY LIST) ===

@router.post(
    "/{video_id}/favorite",
    response_model=MessageResponse,
    summary="Add to My List",
    description="Add video to user's favorites"
)
async def add_to_favorites(
    video_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add video to My List."""
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

    # Check if already in favorites
    existing = await db.execute(
        select(Favorite).where(
            and_(
                Favorite.user_id == current_user.id,
                Favorite.video_id == video.id
            )
        )
    )
    if existing.scalar_one_or_none():
        return MessageResponse(
            message="Video already in My List",
            success=True
        )

    # Add to favorites
    favorite = Favorite(
        user_id=current_user.id,
        video_id=video.id
    )
    db.add(favorite)
    await db.commit()

    return MessageResponse(
        message=f"'{video.title}' added to My List",
        success=True
    )


@router.delete(
    "/{video_id}/favorite",
    response_model=MessageResponse,
    summary="Remove from My List",
    description="Remove video from favorites"
)
async def remove_from_favorites(
    video_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Remove video from My List."""
    result = await db.execute(
        select(Favorite).where(
            and_(
                Favorite.user_id == current_user.id,
                Favorite.video_id == video_id
            )
        )
    )
    favorite = result.scalar_one_or_none()

    if not favorite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not in My List"
        )

    await db.delete(favorite)
    await db.commit()

    return MessageResponse(
        message="Video removed from My List",
        success=True
    )


# === VIEWING PROGRESS ===

@router.post(
    "/{video_id}/progress",
    response_model=MessageResponse,
    summary="Update viewing progress",
    description="Update user's viewing progress for video"
)
async def update_progress(
    video_id: str,
    progress_data: VideoProgressUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update viewing progress.

    Called periodically during playback (every 10-30 seconds).
    Used for:
    - Continue watching feature
    - Analytics tracking
    - Completion rate calculation
    """
    # Get video
    video_result = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = video_result.scalar_one_or_none()

    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Video not found"
        )

    # Check if completed (90%+ watched)
    completed = (progress_data.position_seconds / video.duration) >= 0.9 if video.duration > 0 else False

    # Upsert viewing history
    existing = await db.execute(
        select(ViewingHistory).where(
            and_(
                ViewingHistory.user_id == current_user.id,
                ViewingHistory.video_id == video.id
            )
        ).order_by(ViewingHistory.watched_at.desc()).limit(1)
    )
    history = existing.scalar_one_or_none()

    if history:
        history.last_position = progress_data.position_seconds
        history.watch_duration = progress_data.position_seconds
        history.completed = completed
        history.watched_at = datetime.utcnow()
    else:
        history = ViewingHistory(
            user_id=current_user.id,
            video_id=video.id,
            watch_duration=progress_data.position_seconds,
            last_position=progress_data.position_seconds,
            completed=completed
        )
        db.add(history)

    # Update video analytics
    if completed:
        video.increment_view_count(completed=True)

    await db.commit()

    return MessageResponse(
        message="Progress updated",
        success=True
    )


# === INGEST UPLOAD ===

# Skeleton extractor (lazy load)
_skeleton_extractor = None

def get_skeleton_extractor():
    """Lazy load skeleton extractor to avoid slow startup."""
    global _skeleton_extractor
    if _skeleton_extractor is None:
        try:
            import sys
            sys.path.insert(0, "services/video_studio")
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
            _skeleton_extractor = SkeletonExtractorHolistic(model_complexity=1)
        except ImportError as e:
            import logging
            logging.warning(f"SkeletonExtractor not available: {e}")
            return None
    return _skeleton_extractor


@router.post(
    "/ingest",
    summary="Ingest file upload",
    description="Upload files for processing with optional skeleton extraction"
)
async def ingest_upload(
    files: List[UploadFile] = File(...),
    asset_type: str = "video",
    title: str = "",
    author: str = "",
    language: str = "auto",
    preset: str = "standard",
    extract_skeleton: bool = True,
    db: AsyncSession = Depends(get_db)
):
    """
    Ingest files for processing pipeline.

    Args:
        files: Files to upload
        asset_type: Type of asset (video, audio, image, pdf, skeleton)
        title: Asset title
        author: Asset author
        language: Language code or 'auto'
        preset: Processing preset (standard, skeleton, knowledge, voice)
        extract_skeleton: Whether to extract skeleton from video (default True)
    """
    import os
    import logging
    from pathlib import Path

    logger = logging.getLogger(__name__)

    UPLOAD_DIR = Path("data/uploads")
    SKELETON_DIR = Path("data/skeletons")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    SKELETON_DIR.mkdir(parents=True, exist_ok=True)

    saved_files = []
    skeleton_results = []

    for file in files:
        file_id = str(uuid.uuid4())
        file_ext = os.path.splitext(file.filename)[1] if file.filename else ""
        file_path = UPLOAD_DIR / f"{file_id}{file_ext}"

        # Save uploaded file
        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        file_info = {
            "id": file_id,
            "filename": file.filename,
            "path": str(file_path),
            "size": len(content),
            "asset_type": asset_type
        }
        saved_files.append(file_info)

        # Extract skeleton if video and enabled
        if extract_skeleton and asset_type == "video" and file_ext.lower() in [".mp4", ".mov", ".avi", ".mkv", ".webm"]:
            try:
                extractor = get_skeleton_extractor()
                if extractor:
                    logger.info(f"Starting skeleton extraction for {file.filename}")

                    # Extract skeleton (this runs synchronously)
                    skeleton_data = extractor.extract_from_video(str(file_path))

                    # Save skeleton JSON
                    skeleton_path = SKELETON_DIR / f"{file_id}_skeleton.json"
                    extractor.save_json(skeleton_data, str(skeleton_path))

                    skeleton_results.append({
                        "file_id": file_id,
                        "skeleton_path": str(skeleton_path),
                        "frames": skeleton_data.get("extraction_info", {}).get("frames_processed", 0),
                        "status": "completed"
                    })
                    logger.info(f"Skeleton extraction completed: {skeleton_path}")
                else:
                    skeleton_results.append({
                        "file_id": file_id,
                        "status": "skipped",
                        "reason": "Extractor not available"
                    })
            except Exception as e:
                logger.error(f"Skeleton extraction failed: {e}")
                skeleton_results.append({
                    "file_id": file_id,
                    "status": "failed",
                    "error": str(e)
                })

    return {
        "asset_id": saved_files[0]["id"] if saved_files else None,
        "job_id": str(uuid.uuid4()),
        "message": f"Uploaded {len(saved_files)} files",
        "status_url": f"/api/v1/videos/ingest/status/{saved_files[0]['id']}" if saved_files else None,
        "files": saved_files,
        "skeleton_extraction": skeleton_results if skeleton_results else None
    }


@router.get(
    "/ingest/status/{asset_id}",
    summary="Get ingest status",
    description="Get status of an ingest job"
)
async def get_ingest_status(asset_id: str):
    """Get ingest job status."""
    import os
    from pathlib import Path

    # Check if skeleton exists
    skeleton_path = Path("data/skeletons") / f"{asset_id}_skeleton.json"
    video_path = None

    # Find video file
    upload_dir = Path("data/uploads")
    for ext in [".mp4", ".mov", ".avi", ".mkv", ".webm"]:
        potential_path = upload_dir / f"{asset_id}{ext}"
        if potential_path.exists():
            video_path = str(potential_path)
            break

    return {
        "asset_id": asset_id,
        "status": "completed" if skeleton_path.exists() else "pending",
        "progress": 100 if skeleton_path.exists() else 0,
        "message": "Processing completed" if skeleton_path.exists() else "Processing pending",
        "video_path": video_path,
        "skeleton_path": str(skeleton_path) if skeleton_path.exists() else None
    }

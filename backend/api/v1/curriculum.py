"""
================================================================================
    CURRICULUM API - Learning Path Management Endpoints
================================================================================

AI_MODULE: Curriculum REST API
AI_DESCRIPTION: Complete CRUD + enrollment + progress + exams + certificates
AI_BUSINESS: Primary revenue channel through curriculum subscriptions
AI_TEACHING: FastAPI dependency injection + async database ops + role-based access

ENDPOINT GROUPS:
    /curricula          - CRUD operations for curricula
    /enrollments        - User enrollment management
    /progress           - Learning progress tracking
    /exams              - Exam submission and review
    /certificates       - Certificate generation and verification
    /invite-codes       - Invitation code management

================================================================================
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload, joinedload
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field, validator
from enum import Enum
import uuid
import logging

from core.database import get_db
from core.auth import get_current_user, get_current_maestro, require_admin
from models import User, Maestro, ASD, ASDMember, Video, Course
from models.curriculum import (
    Curriculum, CurriculumLevel, CurriculumEnrollment, LevelProgress,
    ExamSubmission, Certificate, CurriculumInviteCode,
    CurriculumDiscipline, CurriculumOwnerType, CurriculumVisibility,
    CurriculumPricingModel, ExamType, LevelStatus, EnrollmentAccessType,
    ExamStatus, CertificateIssuerType
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/curricula", tags=["Curriculum"])


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class CurriculumSettingsSchema(BaseModel):
    """Parametrizable settings for curriculum."""
    sequential_progression: bool = True
    min_days_between_levels: int = 30
    exam_required_for_promotion: bool = True
    ai_feedback_enabled: bool = True
    teacher_review_required: bool = False
    allow_level_skip: bool = False
    max_exam_attempts: int = 3
    exam_cooldown_days: int = 7
    certificate_auto_issue: bool = True
    show_leaderboard: bool = False
    notify_on_completion: bool = True


class CurriculumCreate(BaseModel):
    """Schema for creating a curriculum."""
    name: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    discipline: CurriculumDiscipline
    style_variant: Optional[str] = None
    visibility: CurriculumVisibility = CurriculumVisibility.PUBLIC
    pricing_model: CurriculumPricingModel = CurriculumPricingModel.FREE
    price: Optional[float] = None
    settings: Optional[CurriculumSettingsSchema] = None
    thumbnail_url: Optional[str] = None
    banner_url: Optional[str] = None


class CurriculumUpdate(BaseModel):
    """Schema for updating a curriculum."""
    name: Optional[str] = None
    description: Optional[str] = None
    style_variant: Optional[str] = None
    visibility: Optional[CurriculumVisibility] = None
    pricing_model: Optional[CurriculumPricingModel] = None
    price: Optional[float] = None
    settings: Optional[CurriculumSettingsSchema] = None
    thumbnail_url: Optional[str] = None
    banner_url: Optional[str] = None
    is_active: Optional[bool] = None
    is_featured: Optional[bool] = None


class CurriculumLevelCreate(BaseModel):
    """Schema for creating a curriculum level."""
    name: str = Field(..., min_length=1, max_length=255)
    belt_color: Optional[str] = None
    description: Optional[str] = None
    requirements: List[str] = []
    exam_type: ExamType = ExamType.VIDEO_SUBMISSION
    exam_instructions: Optional[str] = None
    passing_score: int = Field(70, ge=0, le=100)
    reference_video_ids: List[str] = []
    is_free: bool = False
    level_price: Optional[float] = None
    estimated_hours: Optional[int] = None
    min_practice_hours: Optional[int] = None


class CurriculumLevelUpdate(BaseModel):
    """Schema for updating a curriculum level."""
    name: Optional[str] = None
    belt_color: Optional[str] = None
    description: Optional[str] = None
    requirements: Optional[List[str]] = None
    exam_type: Optional[ExamType] = None
    exam_instructions: Optional[str] = None
    passing_score: Optional[int] = None
    reference_video_ids: Optional[List[str]] = None
    is_free: Optional[bool] = None
    level_price: Optional[float] = None
    estimated_hours: Optional[int] = None
    min_practice_hours: Optional[int] = None


class EnrollmentCreate(BaseModel):
    """Schema for enrolling in a curriculum."""
    curriculum_id: str
    invitation_code: Optional[str] = None


class ExamSubmissionCreate(BaseModel):
    """Schema for submitting an exam."""
    video_url: str
    video_duration: Optional[int] = None


class TeacherReviewCreate(BaseModel):
    """Schema for teacher exam review."""
    score: float = Field(..., ge=0, le=100)
    feedback: str
    passed: bool
    notes: Optional[dict] = None


class InviteCodeCreate(BaseModel):
    """Schema for creating invite codes."""
    max_uses: Optional[int] = None
    expires_days: Optional[int] = None


class LevelContentAdd(BaseModel):
    """Schema for adding content to a level."""
    course_ids: List[str] = []
    video_ids: List[str] = []


class ProgressUpdate(BaseModel):
    """Schema for updating progress."""
    video_id: Optional[str] = None
    video_progress_seconds: Optional[int] = None
    video_completed: bool = False
    course_id: Optional[str] = None
    course_score: Optional[int] = None
    practice_minutes: Optional[int] = None


# ==============================================================================
# RESPONSE SCHEMAS
# ==============================================================================

class CurriculumResponse(BaseModel):
    """
    Curriculum response schema.
    
    🎓 AI_TEACHING: I campi level, difficulty, lessons, videos sono
    calcolati a runtime dal backend per fornire al frontend una
    vista aggregata senza query aggiuntive.
    - level: numero totale livelli (alias di total_levels)
    - difficulty: derivata dal pricing_model + total_levels
    - lessons: lista semplificata dei livelli come "lezioni"
    - videos: lista ID video associati ai livelli del curriculum
    """
    id: str
    name: str
    slug: str
    description: Optional[str]
    discipline: str
    style_variant: Optional[str]
    owner_type: str
    visibility: str
    pricing_model: str
    price: Optional[float]
    settings: dict
    thumbnail_url: Optional[str]
    banner_url: Optional[str]
    total_levels: int
    total_enrollments: int
    total_completions: int
    is_active: bool
    is_featured: bool
    created_at: datetime
    # FIX BUG #2: Campi aggiuntivi per compatibilità frontend/test
    level: Optional[int] = None  # Alias di total_levels per backward compat
    difficulty: Optional[str] = None  # beginner/intermediate/advanced
    lessons: Optional[List[dict]] = []  # Lista livelli come lezioni
    videos: Optional[List[str]] = []  # ID video associati

    class Config:
        from_attributes = True


class CurriculumLevelResponse(BaseModel):
    """Level response schema."""
    id: str
    name: str
    order: int
    belt_color: Optional[str]
    description: Optional[str]
    requirements: List[str]
    exam_type: str
    passing_score: int
    estimated_hours: Optional[int]
    is_free: bool

    class Config:
        from_attributes = True


class EnrollmentResponse(BaseModel):
    """Enrollment response schema."""
    id: str
    curriculum_id: str
    current_level_id: Optional[str]
    access_type: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    is_active: bool
    progress_percent: float

    class Config:
        from_attributes = True


class LevelProgressResponse(BaseModel):
    """Level progress response schema."""
    id: str
    level_id: str
    status: str
    progress_percent: int
    videos_watched: dict
    courses_completed: dict
    total_practice_minutes: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    can_take_exam: bool
    exam_reason: str

    class Config:
        from_attributes = True


class ExamSubmissionResponse(BaseModel):
    """Exam submission response schema."""
    id: str
    video_url: str
    status: str
    ai_score: Optional[float]
    ai_feedback: Optional[str]
    teacher_score: Optional[float]
    teacher_feedback: Optional[str]
    final_score: Optional[float]
    passed: Optional[bool]
    created_at: datetime

    class Config:
        from_attributes = True


class CertificateResponse(BaseModel):
    """Certificate response schema."""
    id: str
    certificate_number: str
    title: str
    issued_at: datetime
    pdf_url: Optional[str]
    is_valid: bool
    verification_url: str

    class Config:
        from_attributes = True


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def compute_difficulty(total_levels: int, pricing_model: str) -> str:
    """
    🎓 AI_BUSINESS: Calcola difficoltà curriculum per UX frontend.
    - 1-3 livelli o FREE = beginner
    - 4-7 livelli = intermediate
    - 8+ livelli o PREMIUM = advanced
    """
    if pricing_model in ("premium", "PREMIUM") or total_levels >= 8:
        return "advanced"
    elif total_levels >= 4:
        return "intermediate"
    return "beginner"


def generate_slug(name: str) -> str:
    """Generate URL-friendly slug from name."""
    import re
    slug = name.lower()
    slug = re.sub(r'[^a-z0-9\s-]', '', slug)
    slug = re.sub(r'[\s_-]+', '-', slug)
    slug = slug.strip('-')
    return f"{slug}-{uuid.uuid4().hex[:8]}"


async def check_curriculum_access(
    curriculum: Curriculum,
    user: User,
    db: AsyncSession
) -> bool:
    """Check if user can access curriculum."""
    if user.is_admin:
        return True

    if curriculum.visibility == CurriculumVisibility.PUBLIC:
        return True

    if curriculum.visibility == CurriculumVisibility.MEMBERS_ONLY:
        if curriculum.owner_asd_id:
            membership = await db.execute(
                select(ASDMember).where(
                    ASDMember.user_id == user.id,
                    ASDMember.asd_id == curriculum.owner_asd_id,
                    ASDMember.is_active == True
                )
            )
            return membership.scalar_one_or_none() is not None
        return True

    # INVITE_ONLY requires enrollment check
    return False


async def check_curriculum_owner(
    curriculum: Curriculum,
    user: User,
    maestro: Optional[Maestro],
    db: AsyncSession
) -> bool:
    """Check if user owns the curriculum."""
    if user.is_admin:
        return True

    if curriculum.owner_type == CurriculumOwnerType.PLATFORM:
        return user.is_admin

    if curriculum.owner_type == CurriculumOwnerType.MAESTRO:
        return maestro and str(curriculum.owner_maestro_id) == str(maestro.id)

    if curriculum.owner_type == CurriculumOwnerType.ASD:
        if not maestro:
            return False
        # Check if maestro belongs to ASD
        membership = await db.execute(
            select(ASDMember).where(
                ASDMember.maestro_id == maestro.id,
                ASDMember.asd_id == curriculum.owner_asd_id,
                ASDMember.role.in_(['admin', 'owner'])
            )
        )
        return membership.scalar_one_or_none() is not None

    return False


# ==============================================================================
# CURRICULUM CRUD ENDPOINTS
# ==============================================================================

# FIX BUG-CURRICULA-401: Doppia route per supportare sia /curricula che /curricula/
# Con redirect_slashes=False in main.py, serve definire entrambi i path
@router.get("", response_model=List[CurriculumResponse])
@router.get("/", response_model=List[CurriculumResponse])
async def list_curricula(
    discipline: Optional[CurriculumDiscipline] = None,
    visibility: Optional[CurriculumVisibility] = None,
    owner_type: Optional[CurriculumOwnerType] = None,
    featured: Optional[bool] = None,
    search: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List curricula with filters.

    GET /api/v1/curricula
    """
    query = select(Curriculum).where(Curriculum.is_active == True)

    if discipline:
        query = query.where(Curriculum.discipline == discipline)

    if visibility:
        query = query.where(Curriculum.visibility == visibility)

    if owner_type:
        query = query.where(Curriculum.owner_type == owner_type)

    if featured is not None:
        query = query.where(Curriculum.is_featured == featured)

    if search:
        query = query.where(
            or_(
                Curriculum.name.ilike(f"%{search}%"),
                Curriculum.description.ilike(f"%{search}%")
            )
        )

    # Filter by visibility access
    # FIX BUG-CURRICULA-403: Controlla sia is_admin (database) che is_superuser (token JWT)
    # L'utente admin potrebbe avere is_admin=False nel DB ma is_superuser=True nel token
    is_admin_user = getattr(current_user, 'is_admin', False) or getattr(current_user, 'is_superuser', False)
    if not is_admin_user:
        query = query.where(
            or_(
                Curriculum.visibility == CurriculumVisibility.PUBLIC,
                Curriculum.owner_maestro_id.in_(
                    select(Maestro.id).where(Maestro.user_id == current_user.id)
                )
            )
        )

    query = query.offset(skip).limit(limit).order_by(Curriculum.created_at.desc())

    result = await db.execute(query)
    curricula = result.scalars().all()

    return [
        CurriculumResponse(
            id=str(c.id),
            name=c.name,
            slug=c.slug,
            description=c.description,
            discipline=c.discipline.value,
            style_variant=c.style_variant,
            owner_type=c.owner_type.value,
            visibility=c.visibility.value,
            pricing_model=c.pricing_model.value,
            price=c.price,
            settings=c.settings or {},
            thumbnail_url=c.thumbnail_url,
            banner_url=c.banner_url,
            total_levels=c.total_levels,
            total_enrollments=c.total_enrollments,
            total_completions=c.total_completions,
            is_active=c.is_active,
            is_featured=c.is_featured,
            created_at=c.created_at,
            # FIX BUG #2: Popola campi aggregati
            level=c.total_levels,
            difficulty=compute_difficulty(c.total_levels, c.pricing_model.value),
            lessons=[],  # Popolato in detail, qui lista vuota per performance
            videos=[],
        )
        for c in curricula
    ]


@router.get("/{curriculum_id}", response_model=CurriculumResponse)
async def get_curriculum(
    curriculum_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get curriculum details.

    GET /api/v1/curricula/{id}
    """
    result = await db.execute(
        select(Curriculum)
        .options(selectinload(Curriculum.levels))
        .where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_access(curriculum, current_user, db):
        raise HTTPException(status_code=403, detail="Access denied")

    # FIX BUG #2: Costruisci lessons[] e videos[] dai livelli caricati
    lessons_list = []
    videos_list = []
    if hasattr(curriculum, 'levels') and curriculum.levels:
        for lvl in sorted(curriculum.levels, key=lambda x: x.order):
            lessons_list.append({
                "id": str(lvl.id),
                "name": lvl.name,
                "order": lvl.order,
                "belt_color": lvl.belt_color,
            })
            if lvl.reference_video_ids:
                videos_list.extend(lvl.reference_video_ids)

    return CurriculumResponse(
        id=str(curriculum.id),
        name=curriculum.name,
        slug=curriculum.slug,
        description=curriculum.description,
        discipline=curriculum.discipline.value,
        style_variant=curriculum.style_variant,
        owner_type=curriculum.owner_type.value,
        visibility=curriculum.visibility.value,
        pricing_model=curriculum.pricing_model.value,
        price=curriculum.price,
        settings=curriculum.settings or {},
        thumbnail_url=curriculum.thumbnail_url,
        banner_url=curriculum.banner_url,
        total_levels=curriculum.total_levels,
        total_enrollments=curriculum.total_enrollments,
        total_completions=curriculum.total_completions,
        is_active=curriculum.is_active,
        is_featured=curriculum.is_featured,
        created_at=curriculum.created_at,
        level=curriculum.total_levels,
        difficulty=compute_difficulty(curriculum.total_levels, curriculum.pricing_model.value),
        lessons=lessons_list,
        videos=videos_list,
    )


@router.post("/", response_model=CurriculumResponse, status_code=status.HTTP_201_CREATED)
async def create_curriculum(
    data: CurriculumCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Create a new curriculum.

    POST /api/v1/curricula
    """
    if not current_user.is_admin and not current_maestro:
        raise HTTPException(
            status_code=403,
            detail="Only admins or maestros can create curricula"
        )

    # Determine owner type
    if current_user.is_admin:
        owner_type = CurriculumOwnerType.PLATFORM
        owner_maestro_id = None
        owner_asd_id = None
    else:
        owner_type = CurriculumOwnerType.MAESTRO
        owner_maestro_id = current_maestro.id
        owner_asd_id = None

    curriculum = Curriculum(
        id=uuid.uuid4(),
        name=data.name,
        slug=generate_slug(data.name),
        description=data.description,
        discipline=data.discipline,
        style_variant=data.style_variant,
        owner_type=owner_type,
        owner_maestro_id=owner_maestro_id,
        owner_asd_id=owner_asd_id,
        visibility=data.visibility,
        pricing_model=data.pricing_model,
        price=data.price,
        settings=data.settings.dict() if data.settings else {},
        thumbnail_url=data.thumbnail_url,
        banner_url=data.banner_url
    )

    db.add(curriculum)
    await db.commit()
    await db.refresh(curriculum)

    logger.info(f"Created curriculum: {curriculum.id} by user {current_user.id}")

    return CurriculumResponse(
        id=str(curriculum.id),
        name=curriculum.name,
        slug=curriculum.slug,
        description=curriculum.description,
        discipline=curriculum.discipline.value,
        style_variant=curriculum.style_variant,
        owner_type=curriculum.owner_type.value,
        visibility=curriculum.visibility.value,
        pricing_model=curriculum.pricing_model.value,
        price=curriculum.price,
        settings=curriculum.settings or {},
        thumbnail_url=curriculum.thumbnail_url,
        banner_url=curriculum.banner_url,
        total_levels=curriculum.total_levels,
        total_enrollments=curriculum.total_enrollments,
        total_completions=curriculum.total_completions,
        is_active=curriculum.is_active,
        is_featured=curriculum.is_featured,
        created_at=curriculum.created_at,
        level=curriculum.total_levels,
        difficulty=compute_difficulty(curriculum.total_levels, curriculum.pricing_model.value),
        lessons=[],
        videos=[],
    )


@router.put("/{curriculum_id}", response_model=CurriculumResponse)
async def update_curriculum(
    curriculum_id: str,
    data: CurriculumUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Update a curriculum.

    PUT /api/v1/curricula/{id}
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized to update this curriculum")

    # Update fields
    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        if field == "settings" and value:
            setattr(curriculum, field, value.dict() if hasattr(value, 'dict') else value)
        else:
            setattr(curriculum, field, value)

    curriculum.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(curriculum)

    logger.info(f"Updated curriculum: {curriculum.id}")

    return CurriculumResponse(
        id=str(curriculum.id),
        name=curriculum.name,
        slug=curriculum.slug,
        description=curriculum.description,
        discipline=curriculum.discipline.value,
        style_variant=curriculum.style_variant,
        owner_type=curriculum.owner_type.value,
        visibility=curriculum.visibility.value,
        pricing_model=curriculum.pricing_model.value,
        price=curriculum.price,
        settings=curriculum.settings or {},
        thumbnail_url=curriculum.thumbnail_url,
        banner_url=curriculum.banner_url,
        total_levels=curriculum.total_levels,
        total_enrollments=curriculum.total_enrollments,
        total_completions=curriculum.total_completions,
        is_active=curriculum.is_active,
        is_featured=curriculum.is_featured,
        created_at=curriculum.created_at,
        level=curriculum.total_levels,
        difficulty=compute_difficulty(curriculum.total_levels, curriculum.pricing_model.value),
        lessons=[],
        videos=[],
    )


@router.delete("/{curriculum_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_curriculum(
    curriculum_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Delete (deactivate) a curriculum.

    DELETE /api/v1/curricula/{id}
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized to delete this curriculum")

    curriculum.is_active = False
    curriculum.updated_at = datetime.utcnow()

    await db.commit()

    logger.info(f"Deleted curriculum: {curriculum.id}")


# ==============================================================================
# LEVEL MANAGEMENT ENDPOINTS
# ==============================================================================

@router.get("/{curriculum_id}/levels", response_model=List[CurriculumLevelResponse])
async def list_curriculum_levels(
    curriculum_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List all levels in a curriculum.

    GET /api/v1/curricula/{id}/levels
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_access(curriculum, current_user, db):
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(CurriculumLevel)
        .where(CurriculumLevel.curriculum_id == curriculum_id)
        .order_by(CurriculumLevel.order)
    )
    levels = result.scalars().all()

    return [
        CurriculumLevelResponse(
            id=str(l.id),
            name=l.name,
            order=l.order,
            belt_color=l.belt_color,
            description=l.description,
            requirements=l.requirements or [],
            exam_type=l.exam_type.value,
            passing_score=l.passing_score,
            estimated_hours=l.estimated_hours,
            is_free=l.is_free
        )
        for l in levels
    ]


@router.post("/{curriculum_id}/levels", response_model=CurriculumLevelResponse, status_code=status.HTTP_201_CREATED)
async def create_curriculum_level(
    curriculum_id: str,
    data: CurriculumLevelCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Create a new level in curriculum.

    POST /api/v1/curricula/{id}/levels
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get next order
    result = await db.execute(
        select(func.max(CurriculumLevel.order))
        .where(CurriculumLevel.curriculum_id == curriculum_id)
    )
    max_order = result.scalar() or -1
    next_order = max_order + 1

    level = CurriculumLevel(
        id=uuid.uuid4(),
        curriculum_id=curriculum.id,
        order=next_order,
        name=data.name,
        belt_color=data.belt_color,
        description=data.description,
        requirements=data.requirements,
        exam_type=data.exam_type,
        exam_instructions=data.exam_instructions,
        passing_score=data.passing_score,
        reference_video_ids=data.reference_video_ids,
        is_free=data.is_free,
        level_price=data.level_price,
        estimated_hours=data.estimated_hours,
        min_practice_hours=data.min_practice_hours
    )

    db.add(level)
    curriculum.total_levels = next_order + 1

    await db.commit()
    await db.refresh(level)

    logger.info(f"Created level: {level.id} in curriculum {curriculum_id}")

    return CurriculumLevelResponse(
        id=str(level.id),
        name=level.name,
        order=level.order,
        belt_color=level.belt_color,
        description=level.description,
        requirements=level.requirements or [],
        exam_type=level.exam_type.value,
        passing_score=level.passing_score,
        estimated_hours=level.estimated_hours,
        is_free=level.is_free
    )


@router.put("/{curriculum_id}/levels/{level_id}", response_model=CurriculumLevelResponse)
async def update_curriculum_level(
    curriculum_id: str,
    level_id: str,
    data: CurriculumLevelUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Update a curriculum level.

    PUT /api/v1/curricula/{id}/levels/{level_id}
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(CurriculumLevel).where(
            CurriculumLevel.id == level_id,
            CurriculumLevel.curriculum_id == curriculum_id
        )
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    update_data = data.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(level, field, value)

    level.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(level)

    return CurriculumLevelResponse(
        id=str(level.id),
        name=level.name,
        order=level.order,
        belt_color=level.belt_color,
        description=level.description,
        requirements=level.requirements or [],
        exam_type=level.exam_type.value,
        passing_score=level.passing_score,
        estimated_hours=level.estimated_hours,
        is_free=level.is_free
    )


@router.post("/{curriculum_id}/levels/{level_id}/content")
async def add_level_content(
    curriculum_id: str,
    level_id: str,
    data: LevelContentAdd,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Add courses/videos to a level.

    POST /api/v1/curricula/{id}/levels/{level_id}/content
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    result = await db.execute(
        select(CurriculumLevel)
        .options(selectinload(CurriculumLevel.courses), selectinload(CurriculumLevel.videos))
        .where(CurriculumLevel.id == level_id, CurriculumLevel.curriculum_id == curriculum_id)
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    # Add courses
    for course_id in data.course_ids:
        course_result = await db.execute(select(Course).where(Course.id == course_id))
        course = course_result.scalar_one_or_none()
        if course and course not in level.courses:
            level.courses.append(course)

    # Add videos
    for video_id in data.video_ids:
        video_result = await db.execute(select(Video).where(Video.id == video_id))
        video = video_result.scalar_one_or_none()
        if video and video not in level.videos:
            level.videos.append(video)

    await db.commit()

    return {"message": "Content added successfully", "courses_added": len(data.course_ids), "videos_added": len(data.video_ids)}


# ==============================================================================
# ENROLLMENT ENDPOINTS
# ==============================================================================

@router.post("/{curriculum_id}/enroll", response_model=EnrollmentResponse, status_code=status.HTTP_201_CREATED)
async def enroll_in_curriculum(
    curriculum_id: str,
    invitation_code: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Enroll current user in a curriculum.

    POST /api/v1/curricula/{id}/enroll
    """
    result = await db.execute(
        select(Curriculum)
        .options(selectinload(Curriculum.levels))
        .where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not curriculum.is_active:
        raise HTTPException(status_code=400, detail="Curriculum is not active")

    # Check existing enrollment
    existing = await db.execute(
        select(CurriculumEnrollment).where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == curriculum_id
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Already enrolled")

    # Determine access type
    access_type = EnrollmentAccessType.PLATFORM_ONLY
    asd_id = None

    # Handle invite-only
    if curriculum.visibility == CurriculumVisibility.INVITE_ONLY:
        if not invitation_code:
            raise HTTPException(status_code=400, detail="Invitation code required")

        code_result = await db.execute(
            select(CurriculumInviteCode).where(
                CurriculumInviteCode.curriculum_id == curriculum_id,
                CurriculumInviteCode.code == invitation_code
            )
        )
        invite_code = code_result.scalar_one_or_none()

        if not invite_code:
            raise HTTPException(status_code=400, detail="Invalid invitation code")

        is_valid, reason = invite_code.is_valid()
        if not is_valid:
            raise HTTPException(status_code=400, detail=reason)

        invite_code.use()
        access_type = EnrollmentAccessType.INVITED

    # Handle members-only
    elif curriculum.visibility == CurriculumVisibility.MEMBERS_ONLY:
        if curriculum.owner_asd_id:
            membership = await db.execute(
                select(ASDMember).where(
                    ASDMember.user_id == current_user.id,
                    ASDMember.asd_id == curriculum.owner_asd_id,
                    ASDMember.is_active == True
                )
            )
            member = membership.scalar_one_or_none()
            if not member:
                raise HTTPException(status_code=403, detail="Must be ASD member to enroll")

            access_type = EnrollmentAccessType.SCHOOL_ONLY
            asd_id = curriculum.owner_asd_id

    # Create enrollment
    first_level = curriculum.get_first_level()

    enrollment = CurriculumEnrollment(
        id=uuid.uuid4(),
        user_id=current_user.id,
        curriculum_id=curriculum.id,
        access_type=access_type,
        asd_id=asd_id,
        invitation_code=invitation_code,
        current_level_id=first_level.id if first_level else None,
        started_at=datetime.utcnow()
    )

    db.add(enrollment)
    curriculum.total_enrollments += 1

    # Create initial level progress if first level exists
    if first_level:
        progress = LevelProgress(
            id=uuid.uuid4(),
            enrollment_id=enrollment.id,
            level_id=first_level.id,
            status=LevelStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        db.add(progress)

    await db.commit()
    await db.refresh(enrollment)

    logger.info(f"User {current_user.id} enrolled in curriculum {curriculum_id}")

    return EnrollmentResponse(
        id=str(enrollment.id),
        curriculum_id=str(enrollment.curriculum_id),
        current_level_id=str(enrollment.current_level_id) if enrollment.current_level_id else None,
        access_type=enrollment.access_type.value,
        started_at=enrollment.started_at,
        completed_at=enrollment.completed_at,
        is_active=enrollment.is_active,
        progress_percent=enrollment.get_progress_percent()
    )


@router.get("/me/enrollments", response_model=List[EnrollmentResponse])
async def get_my_enrollments(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get current user's enrollments.

    GET /api/v1/curricula/me/enrollments
    """
    result = await db.execute(
        select(CurriculumEnrollment)
        .options(selectinload(CurriculumEnrollment.level_progress))
        .where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.is_active == True
        )
        .order_by(CurriculumEnrollment.created_at.desc())
    )
    enrollments = result.scalars().all()

    return [
        EnrollmentResponse(
            id=str(e.id),
            curriculum_id=str(e.curriculum_id),
            current_level_id=str(e.current_level_id) if e.current_level_id else None,
            access_type=e.access_type.value,
            started_at=e.started_at,
            completed_at=e.completed_at,
            is_active=e.is_active,
            progress_percent=e.get_progress_percent()
        )
        for e in enrollments
    ]


# ==============================================================================
# PROGRESS ENDPOINTS
# ==============================================================================

@router.get("/me/curricula/{curriculum_id}/progress", response_model=List[LevelProgressResponse])
async def get_my_progress(
    curriculum_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get current user's progress in a curriculum.

    GET /api/v1/curricula/me/curricula/{id}/progress
    """
    # Get enrollment
    result = await db.execute(
        select(CurriculumEnrollment)
        .options(selectinload(CurriculumEnrollment.level_progress))
        .where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == curriculum_id
        )
    )
    enrollment = result.scalar_one_or_none()

    if not enrollment:
        raise HTTPException(status_code=404, detail="Not enrolled in this curriculum")

    progress_list = []
    for lp in enrollment.level_progress:
        can_take, reason = lp.can_take_exam()
        progress_list.append(
            LevelProgressResponse(
                id=str(lp.id),
                level_id=str(lp.level_id),
                status=lp.status.value,
                progress_percent=lp.progress_percent,
                videos_watched=lp.videos_watched or {},
                courses_completed=lp.courses_completed or {},
                total_practice_minutes=lp.total_practice_minutes,
                started_at=lp.started_at,
                completed_at=lp.completed_at,
                can_take_exam=can_take,
                exam_reason=reason
            )
        )

    return progress_list


@router.post("/levels/{level_id}/start")
async def start_level(
    level_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Start a level (unlock it).

    POST /api/v1/curricula/levels/{level_id}/start
    """
    # Get level
    result = await db.execute(
        select(CurriculumLevel)
        .options(selectinload(CurriculumLevel.curriculum))
        .where(CurriculumLevel.id == level_id)
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    # Get enrollment
    enrollment_result = await db.execute(
        select(CurriculumEnrollment).where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == level.curriculum_id
        )
    )
    enrollment = enrollment_result.scalar_one_or_none()

    if not enrollment:
        raise HTTPException(status_code=400, detail="Not enrolled in this curriculum")

    # Check if progress exists
    progress_result = await db.execute(
        select(LevelProgress).where(
            LevelProgress.enrollment_id == enrollment.id,
            LevelProgress.level_id == level_id
        )
    )
    progress = progress_result.scalar_one_or_none()

    if progress:
        if progress.status != LevelStatus.LOCKED:
            return {"message": "Level already started", "status": progress.status.value}
        progress.unlock()
    else:
        # Check sequential progression
        if level.curriculum.is_sequential() and level.order > 0:
            prev_level = level.get_previous_level()
            if prev_level:
                prev_progress_result = await db.execute(
                    select(LevelProgress).where(
                        LevelProgress.enrollment_id == enrollment.id,
                        LevelProgress.level_id == prev_level.id
                    )
                )
                prev_progress = prev_progress_result.scalar_one_or_none()
                if not prev_progress or prev_progress.status != LevelStatus.COMPLETED:
                    raise HTTPException(status_code=400, detail="Must complete previous level first")

        progress = LevelProgress(
            id=uuid.uuid4(),
            enrollment_id=enrollment.id,
            level_id=level.id,
            status=LevelStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        db.add(progress)

    enrollment.current_level_id = level.id

    await db.commit()

    return {"message": "Level started", "status": "in_progress"}


@router.post("/levels/{level_id}/progress", response_model=LevelProgressResponse)
async def update_progress(
    level_id: str,
    data: ProgressUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Update progress in a level (video watched, course completed, practice time).

    POST /api/v1/curricula/levels/{level_id}/progress
    """
    # Get level
    result = await db.execute(
        select(CurriculumLevel).where(CurriculumLevel.id == level_id)
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    # Get enrollment
    enrollment_result = await db.execute(
        select(CurriculumEnrollment).where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == level.curriculum_id
        )
    )
    enrollment = enrollment_result.scalar_one_or_none()

    if not enrollment:
        raise HTTPException(status_code=400, detail="Not enrolled")

    # Get progress
    progress_result = await db.execute(
        select(LevelProgress).where(
            LevelProgress.enrollment_id == enrollment.id,
            LevelProgress.level_id == level_id
        )
    )
    progress = progress_result.scalar_one_or_none()

    if not progress:
        raise HTTPException(status_code=404, detail="Level not started")

    if progress.status != LevelStatus.IN_PROGRESS:
        raise HTTPException(status_code=400, detail="Level is not in progress")

    # Update progress
    if data.video_id and data.video_progress_seconds is not None:
        progress.mark_video_watched(data.video_id, data.video_progress_seconds, data.video_completed)

    if data.course_id:
        progress.mark_course_completed(data.course_id, data.course_score)

    if data.practice_minutes:
        progress.add_practice_time(data.practice_minutes)

    await db.commit()
    await db.refresh(progress)

    can_take, reason = progress.can_take_exam()

    return LevelProgressResponse(
        id=str(progress.id),
        level_id=str(progress.level_id),
        status=progress.status.value,
        progress_percent=progress.progress_percent,
        videos_watched=progress.videos_watched or {},
        courses_completed=progress.courses_completed or {},
        total_practice_minutes=progress.total_practice_minutes,
        started_at=progress.started_at,
        completed_at=progress.completed_at,
        can_take_exam=can_take,
        exam_reason=reason
    )


# ==============================================================================
# EXAM ENDPOINTS
# ==============================================================================

@router.post("/levels/{level_id}/submit-exam", response_model=ExamSubmissionResponse, status_code=status.HTTP_201_CREATED)
async def submit_exam(
    level_id: str,
    data: ExamSubmissionCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Submit exam video for evaluation.

    POST /api/v1/curricula/levels/{level_id}/submit-exam
    """
    # Get level
    result = await db.execute(
        select(CurriculumLevel)
        .options(selectinload(CurriculumLevel.curriculum))
        .where(CurriculumLevel.id == level_id)
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    # Get enrollment
    enrollment_result = await db.execute(
        select(CurriculumEnrollment).where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == level.curriculum_id
        )
    )
    enrollment = enrollment_result.scalar_one_or_none()

    if not enrollment:
        raise HTTPException(status_code=400, detail="Not enrolled")

    # Get progress
    progress_result = await db.execute(
        select(LevelProgress)
        .options(selectinload(LevelProgress.exam_submissions))
        .where(
            LevelProgress.enrollment_id == enrollment.id,
            LevelProgress.level_id == level_id
        )
    )
    progress = progress_result.scalar_one_or_none()

    if not progress:
        raise HTTPException(status_code=404, detail="Level not started")

    can_take, reason = progress.can_take_exam()
    if not can_take:
        raise HTTPException(status_code=400, detail=reason)

    # Create exam submission
    submission = ExamSubmission(
        id=uuid.uuid4(),
        level_progress_id=progress.id,
        video_url=data.video_url,
        video_duration=data.video_duration,
        status=ExamStatus.SUBMITTED
    )

    db.add(submission)
    progress.status = LevelStatus.EXAM_PENDING

    await db.commit()
    await db.refresh(submission)

    # Schedule AI analysis in background
    if level.curriculum.ai_enabled():
        background_tasks.add_task(
            analyze_exam_submission,
            str(submission.id),
            data.video_url,
            level.reference_video_ids or []
        )

    logger.info(f"Exam submitted: {submission.id} for level {level_id}")

    return ExamSubmissionResponse(
        id=str(submission.id),
        video_url=submission.video_url,
        status=submission.status.value,
        ai_score=submission.ai_score,
        ai_feedback=submission.ai_feedback,
        teacher_score=submission.teacher_score,
        teacher_feedback=submission.teacher_feedback,
        final_score=submission.final_score,
        passed=submission.passed,
        created_at=submission.created_at
    )


async def analyze_exam_submission(submission_id: str, video_url: str, reference_video_ids: List[str]):
    """Background task to analyze exam submission with AI."""
    from services.curriculum.exam_analyzer import ExamAnalyzer

    try:
        analyzer = ExamAnalyzer()
        result = await analyzer.analyze_submission(video_url, reference_video_ids)

        # Update submission with results (need new db session)
        from core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as db:
            submission_result = await db.execute(
                select(ExamSubmission).where(ExamSubmission.id == submission_id)
            )
            submission = submission_result.scalar_one_or_none()

            if submission:
                submission.set_ai_analysis(
                    analysis=result.get('analysis', {}),
                    score=result.get('score', 0),
                    feedback=result.get('feedback', '')
                )
                await db.commit()

        logger.info(f"AI analysis completed for submission {submission_id}")

    except Exception as e:
        logger.error(f"Failed to analyze submission {submission_id}: {e}")


@router.post("/submissions/{submission_id}/review", response_model=ExamSubmissionResponse)
async def review_exam(
    submission_id: str,
    data: TeacherReviewCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Maestro = Depends(get_current_maestro)
):
    """
    Teacher review of exam submission.

    POST /api/v1/curricula/submissions/{submission_id}/review
    """
    if not current_maestro:
        raise HTTPException(status_code=403, detail="Only maestros can review exams")

    result = await db.execute(
        select(ExamSubmission)
        .options(
            selectinload(ExamSubmission.level_progress).selectinload(LevelProgress.level),
            selectinload(ExamSubmission.level_progress).selectinload(LevelProgress.enrollment)
        )
        .where(ExamSubmission.id == submission_id)
    )
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Set teacher review
    submission.set_teacher_review(
        maestro_id=str(current_maestro.id),
        score=data.score,
        feedback=data.feedback,
        notes=data.notes
    )

    # Finalize
    level = submission.level_progress.level
    submission.finalize(passing_score=level.passing_score)

    # Update progress if passed
    if submission.passed:
        progress = submission.level_progress
        progress.complete_level()

        # Advance enrollment if possible
        enrollment = progress.enrollment
        can_advance, _ = enrollment.can_advance_to_next_level()
        if can_advance:
            enrollment.advance_to_next_level()

    await db.commit()
    await db.refresh(submission)

    logger.info(f"Exam {submission_id} reviewed by maestro {current_maestro.id}: passed={submission.passed}")

    return ExamSubmissionResponse(
        id=str(submission.id),
        video_url=submission.video_url,
        status=submission.status.value,
        ai_score=submission.ai_score,
        ai_feedback=submission.ai_feedback,
        teacher_score=submission.teacher_score,
        teacher_feedback=submission.teacher_feedback,
        final_score=submission.final_score,
        passed=submission.passed,
        created_at=submission.created_at
    )


@router.get("/submissions/{submission_id}", response_model=ExamSubmissionResponse)
async def get_exam_submission(
    submission_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get exam submission details.

    GET /api/v1/curricula/submissions/{submission_id}
    """
    result = await db.execute(
        select(ExamSubmission)
        .options(
            selectinload(ExamSubmission.level_progress).selectinload(LevelProgress.enrollment)
        )
        .where(ExamSubmission.id == submission_id)
    )
    submission = result.scalar_one_or_none()

    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    # Check access
    if submission.level_progress.enrollment.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Access denied")

    return ExamSubmissionResponse(
        id=str(submission.id),
        video_url=submission.video_url,
        status=submission.status.value,
        ai_score=submission.ai_score,
        ai_feedback=submission.ai_feedback,
        teacher_score=submission.teacher_score,
        teacher_feedback=submission.teacher_feedback,
        final_score=submission.final_score,
        passed=submission.passed,
        created_at=submission.created_at
    )


# ==============================================================================
# CERTIFICATE ENDPOINTS
# ==============================================================================

@router.get("/me/certificates", response_model=List[CertificateResponse])
async def get_my_certificates(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get current user's certificates.

    GET /api/v1/curricula/me/certificates
    """
    result = await db.execute(
        select(Certificate)
        .options(selectinload(Certificate.curriculum))
        .where(Certificate.user_id == current_user.id)
        .order_by(Certificate.issued_at.desc())
    )
    certificates = result.scalars().all()

    return [
        CertificateResponse(
            id=str(c.id),
            certificate_number=c.certificate_number,
            title=c.title,
            issued_at=c.issued_at,
            pdf_url=c.pdf_url,
            is_valid=c.is_valid,
            verification_url=c.get_verification_url("https://api.example.com")
        )
        for c in certificates
    ]


@router.get("/certificates/verify/{verification_code}")
async def verify_certificate(
    verification_code: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Public certificate verification endpoint.

    GET /api/v1/curricula/certificates/verify/{code}
    """
    result = await db.execute(
        select(Certificate)
        .options(selectinload(Certificate.curriculum), selectinload(Certificate.level))
        .where(Certificate.verification_code == verification_code)
    )
    certificate = result.scalar_one_or_none()

    if not certificate:
        raise HTTPException(status_code=404, detail="Certificate not found")

    return certificate.to_verification_dict()


@router.post("/levels/{level_id}/issue-certificate", response_model=CertificateResponse)
async def issue_certificate(
    level_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Issue certificate for completed level.

    POST /api/v1/curricula/levels/{level_id}/issue-certificate
    """
    # Get level
    result = await db.execute(
        select(CurriculumLevel)
        .options(selectinload(CurriculumLevel.curriculum))
        .where(CurriculumLevel.id == level_id)
    )
    level = result.scalar_one_or_none()

    if not level:
        raise HTTPException(status_code=404, detail="Level not found")

    # Get enrollment and progress
    enrollment_result = await db.execute(
        select(CurriculumEnrollment).where(
            CurriculumEnrollment.user_id == current_user.id,
            CurriculumEnrollment.curriculum_id == level.curriculum_id
        )
    )
    enrollment = enrollment_result.scalar_one_or_none()

    if not enrollment:
        raise HTTPException(status_code=400, detail="Not enrolled")

    progress_result = await db.execute(
        select(LevelProgress).where(
            LevelProgress.enrollment_id == enrollment.id,
            LevelProgress.level_id == level_id
        )
    )
    progress = progress_result.scalar_one_or_none()

    if not progress or progress.status != LevelStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Level not completed")

    # Check existing certificate
    existing = await db.execute(
        select(Certificate).where(
            Certificate.user_id == current_user.id,
            Certificate.level_id == level_id
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Certificate already issued")

    # Determine issuer
    curriculum = level.curriculum
    if curriculum.owner_type == CurriculumOwnerType.PLATFORM:
        issuer_type = CertificateIssuerType.PLATFORM
        issuer_asd_id = None
        issuer_maestro_id = None
    elif curriculum.owner_type == CurriculumOwnerType.ASD:
        issuer_type = CertificateIssuerType.ASD
        issuer_asd_id = curriculum.owner_asd_id
        issuer_maestro_id = None
    else:
        issuer_type = CertificateIssuerType.MAESTRO
        issuer_asd_id = None
        issuer_maestro_id = curriculum.owner_maestro_id

    # Create certificate
    certificate = Certificate(
        id=uuid.uuid4(),
        user_id=current_user.id,
        curriculum_id=curriculum.id,
        level_id=level.id,
        certificate_number=Certificate.generate_certificate_number(),
        title=f"{level.name} - {curriculum.name}",
        description=f"Certificate of completion for {level.name} in {curriculum.name}",
        issued_by_type=issuer_type,
        issued_by_asd_id=issuer_asd_id,
        issued_by_maestro_id=issuer_maestro_id,
        verification_code=Certificate.generate_verification_code()
    )

    db.add(certificate)
    await db.commit()
    await db.refresh(certificate)

    logger.info(f"Certificate issued: {certificate.id} for user {current_user.id}")

    return CertificateResponse(
        id=str(certificate.id),
        certificate_number=certificate.certificate_number,
        title=certificate.title,
        issued_at=certificate.issued_at,
        pdf_url=certificate.pdf_url,
        is_valid=certificate.is_valid,
        verification_url=certificate.get_verification_url("https://api.example.com")
    )


# ==============================================================================
# INVITE CODE ENDPOINTS
# ==============================================================================

@router.post("/{curriculum_id}/invite-codes", status_code=status.HTTP_201_CREATED)
async def create_invite_code(
    curriculum_id: str,
    data: InviteCodeCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Create invite code for curriculum.

    POST /api/v1/curricula/{id}/invite-codes
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    expires_at = None
    if data.expires_days:
        from datetime import timedelta
        expires_at = datetime.utcnow() + timedelta(days=data.expires_days)

    invite_code = CurriculumInviteCode(
        id=uuid.uuid4(),
        curriculum_id=curriculum.id,
        code=CurriculumInviteCode.generate_code(),
        created_by_maestro_id=current_maestro.id if current_maestro else None,
        max_uses=data.max_uses,
        expires_at=expires_at
    )

    db.add(invite_code)
    await db.commit()
    await db.refresh(invite_code)

    return {
        "code": invite_code.code,
        "max_uses": invite_code.max_uses,
        "expires_at": invite_code.expires_at
    }


@router.get("/{curriculum_id}/invite-codes")
async def list_invite_codes(
    curriculum_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    List invite codes for curriculum.

    GET /api/v1/curricula/{id}/invite-codes
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    codes_result = await db.execute(
        select(CurriculumInviteCode)
        .where(CurriculumInviteCode.curriculum_id == curriculum_id)
        .order_by(CurriculumInviteCode.created_at.desc())
    )
    codes = codes_result.scalars().all()

    return [
        {
            "id": str(c.id),
            "code": c.code,
            "max_uses": c.max_uses,
            "current_uses": c.current_uses,
            "expires_at": c.expires_at,
            "is_active": c.is_active
        }
        for c in codes
    ]


@router.delete("/{curriculum_id}/invite-codes/{code}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_invite_code(
    curriculum_id: str,
    code: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    current_maestro: Optional[Maestro] = Depends(get_current_maestro)
):
    """
    Deactivate an invite code.

    DELETE /api/v1/curricula/{id}/invite-codes/{code}
    """
    result = await db.execute(
        select(Curriculum).where(Curriculum.id == curriculum_id)
    )
    curriculum = result.scalar_one_or_none()

    if not curriculum:
        raise HTTPException(status_code=404, detail="Curriculum not found")

    if not await check_curriculum_owner(curriculum, current_user, current_maestro, db):
        raise HTTPException(status_code=403, detail="Not authorized")

    code_result = await db.execute(
        select(CurriculumInviteCode).where(
            CurriculumInviteCode.curriculum_id == curriculum_id,
            CurriculumInviteCode.code == code
        )
    )
    invite_code = code_result.scalar_one_or_none()

    if not invite_code:
        raise HTTPException(status_code=404, detail="Invite code not found")

    invite_code.deactivate()
    await db.commit()

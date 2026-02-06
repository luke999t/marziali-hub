# POSIZIONE: backend/api/v1/content_classification.py
"""
🎓 AI_MODULE: Content Classification Router
🎓 AI_DESCRIPTION: API endpoints per classificazione contenuti video e gestione sezioni
🎓 AI_BUSINESS: Permette organizzazione gerarchica contenuti, filtering per tipo, tagging sezioni video
🎓 AI_TEACHING: FastAPI router con CRUD completo, query filtering, async SQLAlchemy, proper error handling

🔄 ALTERNATIVE_VALUTATE:
- Aggiungere a ingest_projects.py: Scartato perché file già 1500+ righe, separation of concerns
- GraphQL: Scartato perché REST sufficiente, complessità non necessaria
- gRPC: Scartato perché UI è web-based, REST più semplice da debuggare

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Separation of concerns: Router dedicato per content classification
- RESTful: Standard HTTP verbs (GET, POST, PATCH, DELETE)
- Filtering: Query params per filtrare sezioni
- Validation: Pydantic schemas per input/output

📊 ENDPOINTS:
- GET    /api/v1/content-types              - Lista tipi contenuto disponibili
- POST   /api/v1/sections                   - Crea sezione video
- GET    /api/v1/sections                   - Lista sezioni con filtri
- GET    /api/v1/sections/{id}              - Dettaglio sezione
- PATCH  /api/v1/sections/{id}              - Modifica sezione
- DELETE /api/v1/sections/{id}              - Elimina sezione
- GET    /api/v1/videos/{id}/sections       - Sezioni di un video
- PATCH  /api/v1/projects/{id}/content-type - Aggiorna tipo progetto

📊 BUSINESS_IMPACT:
- Ricerca: Filtrare contenuti per tipo ("mostrami solo le forme complete")
- Tagging: Taggare porzioni di video con metadata
- Analytics: Statistiche per tipo di contenuto

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: VideoSection model, ContentType enum, schemas_content
- Downstream: Frontend, mobile app, skeleton extraction pipeline
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload
from typing import Optional, List
from uuid import UUID
import logging

from core.database import get_db
from core.security import get_current_user, get_current_active_user
from models.user import User
from models.video import Video
from models.video_section import VideoSection
from models.ingest_project import IngestProject
from models.content_type import ContentType

from api.v1.schemas_content import (
    ContentTypeChoice,
    ContentTypeListResponse,
    ContentTypeEnum,
    VideoSectionCreate,
    VideoSectionUpdate,
    VideoSectionResponse,
    VideoSectionListResponse,
    ProjectContentTypeUpdate,
    ProjectContentTypeResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["Content Classification"]
)


# ═══════════════════════════════════════════════════════════════
# CONTENT TYPES ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/content-types",
    response_model=ContentTypeListResponse,
    summary="Lista tipi contenuto disponibili",
    description="Ritorna tutti i tipi di contenuto disponibili per classificazione video"
)
async def list_content_types():
    """
    Lista tutti i tipi di contenuto disponibili.

    🎯 USE CASE: Popolare dropdown in UI per selezione tipo contenuto.

    Returns:
        Lista di {value, label} per ogni ContentType
    """
    choices = ContentType.get_choices()
    return ContentTypeListResponse(
        types=[ContentTypeChoice(**c) for c in choices],
        count=len(choices)
    )


# ═══════════════════════════════════════════════════════════════
# VIDEO SECTIONS CRUD
# ═══════════════════════════════════════════════════════════════

@router.post(
    "/sections",
    response_model=VideoSectionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crea nuova sezione video",
    description="Tagga una porzione temporale di un video con tipo contenuto"
)
async def create_section(
    section_data: VideoSectionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Crea nuova sezione video.

    🎯 USE CASE: Utente guarda video e tagga porzione come "movimento singolo"
       dalle 00:30 alle 01:15 con nome "Nuvola che spinge".

    Args:
        section_data: Dati sezione (video_id, content_type, start/end time, name)

    Returns:
        Sezione creata con ID assegnato

    Raises:
        404: Video non trovato
        400: Dati non validi (es. end_time < start_time)
    """
    # Verifica che il video esista
    video_query = await db.execute(
        select(Video).where(Video.id == section_data.video_id)
    )
    video = video_query.scalar_one_or_none()
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Video con id {section_data.video_id} non trovato"
        )

    # Verifica che il progetto esista (se specificato)
    if section_data.project_id:
        project_query = await db.execute(
            select(IngestProject).where(IngestProject.id == section_data.project_id)
        )
        project = project_query.scalar_one_or_none()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Progetto con id {section_data.project_id} non trovato"
            )

    # Crea sezione
    new_section = VideoSection(
        video_id=section_data.video_id,
        project_id=section_data.project_id,
        content_type=section_data.content_type.value,
        start_time=section_data.start_time,
        end_time=section_data.end_time,
        name=section_data.name,
        style=section_data.style,
        notes=section_data.notes,
        created_by=current_user.id
    )

    db.add(new_section)
    await db.commit()
    await db.refresh(new_section)

    logger.info(
        f"Created VideoSection {new_section.id}: {new_section.name} "
        f"({new_section.content_type}) for video {section_data.video_id}"
    )

    return VideoSectionResponse(
        id=new_section.id,
        video_id=new_section.video_id,
        project_id=new_section.project_id,
        content_type=new_section.content_type,
        start_time=new_section.start_time,
        end_time=new_section.end_time,
        duration=new_section.duration,
        name=new_section.name,
        style=new_section.style,
        notes=new_section.notes,
        skeleton_extracted=new_section.skeleton_extracted,
        skeleton_path=new_section.skeleton_path,
        created_at=new_section.created_at,
        updated_at=new_section.updated_at,
        created_by=new_section.created_by
    )


@router.get(
    "/sections",
    response_model=VideoSectionListResponse,
    summary="Lista sezioni con filtri",
    description="Cerca sezioni video con filtri opzionali per tipo, stile, video, progetto"
)
async def list_sections(
    video_id: Optional[UUID] = Query(None, description="Filtra per video"),
    project_id: Optional[UUID] = Query(None, description="Filtra per progetto"),
    content_type: Optional[ContentTypeEnum] = Query(None, description="Filtra per tipo contenuto"),
    style: Optional[str] = Query(None, description="Filtra per stile (case-insensitive, partial match)"),
    min_duration: Optional[float] = Query(None, ge=0, description="Durata minima in secondi"),
    skeleton_extracted: Optional[int] = Query(None, ge=-1, le=2, description="Stato skeleton: 0=no, 1=in corso, 2=ok, -1=errore"),
    limit: int = Query(100, ge=1, le=1000, description="Max risultati"),
    offset: int = Query(0, ge=0, description="Offset per paginazione"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Lista sezioni video con filtri opzionali.

    🎯 USE CASES:
    - "Mostrami tutti i movimenti singoli": ?content_type=movimento_singolo
    - "Sezioni di questo video": ?video_id=xxx
    - "Tutto il Tai Chi Chen": ?style=chen
    - "Sezioni con skeleton pronto": ?skeleton_extracted=2

    Returns:
        Lista paginata di sezioni matching i filtri
    """
    # Build query
    query = select(VideoSection)
    conditions = []

    if video_id:
        conditions.append(VideoSection.video_id == video_id)
    if project_id:
        conditions.append(VideoSection.project_id == project_id)
    if content_type:
        conditions.append(VideoSection.content_type == content_type.value)
    if style:
        conditions.append(VideoSection.style.ilike(f"%{style}%"))
    if min_duration is not None:
        conditions.append(
            (VideoSection.end_time - VideoSection.start_time) >= min_duration
        )
    if skeleton_extracted is not None:
        conditions.append(VideoSection.skeleton_extracted == skeleton_extracted)

    if conditions:
        query = query.where(and_(*conditions))

    # Order by video_id, then start_time
    query = query.order_by(VideoSection.video_id, VideoSection.start_time)

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar()

    # Apply pagination
    query = query.limit(limit).offset(offset)

    # Execute
    result = await db.execute(query)
    sections = result.scalars().all()

    return VideoSectionListResponse(
        sections=[
            VideoSectionResponse(
                id=s.id,
                video_id=s.video_id,
                project_id=s.project_id,
                content_type=s.content_type,
                start_time=s.start_time,
                end_time=s.end_time,
                duration=s.duration,
                name=s.name,
                style=s.style,
                notes=s.notes,
                skeleton_extracted=s.skeleton_extracted,
                skeleton_path=s.skeleton_path,
                created_at=s.created_at,
                updated_at=s.updated_at,
                created_by=s.created_by
            )
            for s in sections
        ],
        total=total,
        video_id=video_id,
        content_type_filter=content_type.value if content_type else None
    )


@router.get(
    "/sections/{section_id}",
    response_model=VideoSectionResponse,
    summary="Dettaglio sezione",
    description="Ritorna dettagli di una singola sezione"
)
async def get_section(
    section_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Ritorna dettagli di una singola sezione.

    Args:
        section_id: ID della sezione

    Returns:
        Dettaglio sezione

    Raises:
        404: Sezione non trovata
    """
    result = await db.execute(
        select(VideoSection).where(VideoSection.id == section_id)
    )
    section = result.scalar_one_or_none()

    if not section:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sezione con id {section_id} non trovata"
        )

    return VideoSectionResponse(
        id=section.id,
        video_id=section.video_id,
        project_id=section.project_id,
        content_type=section.content_type,
        start_time=section.start_time,
        end_time=section.end_time,
        duration=section.duration,
        name=section.name,
        style=section.style,
        notes=section.notes,
        skeleton_extracted=section.skeleton_extracted,
        skeleton_path=section.skeleton_path,
        created_at=section.created_at,
        updated_at=section.updated_at,
        created_by=section.created_by
    )


@router.patch(
    "/sections/{section_id}",
    response_model=VideoSectionResponse,
    summary="Modifica sezione",
    description="Aggiorna campi di una sezione esistente"
)
async def update_section(
    section_id: int,
    updates: VideoSectionUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Aggiorna una sezione esistente.

    Solo i campi forniti vengono aggiornati (partial update).

    Args:
        section_id: ID della sezione
        updates: Campi da aggiornare

    Returns:
        Sezione aggiornata

    Raises:
        404: Sezione non trovata
        400: Dati non validi
    """
    result = await db.execute(
        select(VideoSection).where(VideoSection.id == section_id)
    )
    section = result.scalar_one_or_none()

    if not section:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sezione con id {section_id} non trovata"
        )

    # Apply updates
    update_data = updates.model_dump(exclude_unset=True)

    # Validate time range if partially updating
    new_start = update_data.get('start_time', section.start_time)
    new_end = update_data.get('end_time', section.end_time)
    if new_end <= new_start:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"end_time ({new_end}) deve essere maggiore di start_time ({new_start})"
        )

    for key, value in update_data.items():
        if key == 'content_type' and value:
            setattr(section, key, value.value)
        else:
            setattr(section, key, value)

    await db.commit()
    await db.refresh(section)

    logger.info(f"Updated VideoSection {section_id}: {update_data.keys()}")

    return VideoSectionResponse(
        id=section.id,
        video_id=section.video_id,
        project_id=section.project_id,
        content_type=section.content_type,
        start_time=section.start_time,
        end_time=section.end_time,
        duration=section.duration,
        name=section.name,
        style=section.style,
        notes=section.notes,
        skeleton_extracted=section.skeleton_extracted,
        skeleton_path=section.skeleton_path,
        created_at=section.created_at,
        updated_at=section.updated_at,
        created_by=section.created_by
    )


@router.delete(
    "/sections/{section_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Elimina sezione",
    description="Rimuove una sezione video"
)
async def delete_section(
    section_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Elimina una sezione.

    Args:
        section_id: ID della sezione

    Raises:
        404: Sezione non trovata
    """
    result = await db.execute(
        select(VideoSection).where(VideoSection.id == section_id)
    )
    section = result.scalar_one_or_none()

    if not section:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sezione con id {section_id} non trovata"
        )

    await db.delete(section)
    await db.commit()

    logger.info(f"Deleted VideoSection {section_id}")


# ═══════════════════════════════════════════════════════════════
# VIDEO-SPECIFIC ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@router.get(
    "/videos/{video_id}/sections",
    response_model=VideoSectionListResponse,
    summary="Sezioni di un video",
    description="Ritorna tutte le sezioni di un video specifico"
)
async def get_video_sections(
    video_id: UUID,
    content_type: Optional[ContentTypeEnum] = Query(None, description="Filtra per tipo"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Ritorna tutte le sezioni di un video.

    🎯 USE CASE: Mostrare timeline del video con sezioni taggate.

    Args:
        video_id: ID del video
        content_type: Filtro opzionale per tipo

    Returns:
        Lista sezioni ordinate per start_time
    """
    # Verifica video esiste
    video_query = await db.execute(
        select(Video).where(Video.id == video_id)
    )
    video = video_query.scalar_one_or_none()
    if not video:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Video con id {video_id} non trovato"
        )

    # Query sezioni
    query = select(VideoSection).where(VideoSection.video_id == video_id)

    if content_type:
        query = query.where(VideoSection.content_type == content_type.value)

    query = query.order_by(VideoSection.start_time)

    result = await db.execute(query)
    sections = result.scalars().all()

    return VideoSectionListResponse(
        sections=[
            VideoSectionResponse(
                id=s.id,
                video_id=s.video_id,
                project_id=s.project_id,
                content_type=s.content_type,
                start_time=s.start_time,
                end_time=s.end_time,
                duration=s.duration,
                name=s.name,
                style=s.style,
                notes=s.notes,
                skeleton_extracted=s.skeleton_extracted,
                skeleton_path=s.skeleton_path,
                created_at=s.created_at,
                updated_at=s.updated_at,
                created_by=s.created_by
            )
            for s in sections
        ],
        total=len(sections),
        video_id=video_id,
        content_type_filter=content_type.value if content_type else None
    )


# ═══════════════════════════════════════════════════════════════
# PROJECT CONTENT TYPE
# ═══════════════════════════════════════════════════════════════

@router.patch(
    "/projects/{project_id}/content-type",
    response_model=ProjectContentTypeResponse,
    summary="Aggiorna tipo contenuto progetto",
    description="Imposta/modifica il content_type principale di un progetto"
)
async def update_project_content_type(
    project_id: UUID,
    data: ProjectContentTypeUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Aggiorna il content_type di un progetto.

    🎯 USE CASE: Classificare un progetto come "forma_completa" o "movimento_singolo".

    Args:
        project_id: ID del progetto
        data: Nuovo content_type e style opzionale

    Returns:
        Progetto con content_type aggiornato

    Raises:
        404: Progetto non trovato
    """
    result = await db.execute(
        select(IngestProject).where(IngestProject.id == project_id)
    )
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Progetto con id {project_id} non trovato"
        )

    project.content_type = data.content_type.value
    if data.style:
        project.style = data.style

    await db.commit()
    await db.refresh(project)

    logger.info(
        f"Updated IngestProject {project_id} content_type to {data.content_type.value}"
    )

    return ProjectContentTypeResponse(
        project_id=project.id,
        content_type=project.content_type,
        style=project.style,
        updated_at=project.updated_at
    )


@router.get(
    "/projects/{project_id}/content-type",
    response_model=ProjectContentTypeResponse,
    summary="Ottieni tipo contenuto progetto",
    description="Ritorna il content_type di un progetto"
)
async def get_project_content_type(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Ritorna il content_type di un progetto.

    Args:
        project_id: ID del progetto

    Returns:
        content_type e style del progetto

    Raises:
        404: Progetto non trovato
    """
    result = await db.execute(
        select(IngestProject).where(IngestProject.id == project_id)
    )
    project = result.scalar_one_or_none()

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Progetto con id {project_id} non trovato"
        )

    return ProjectContentTypeResponse(
        project_id=project.id,
        content_type=project.content_type,
        style=project.style,
        updated_at=project.updated_at
    )

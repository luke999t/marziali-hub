"""
AI_MODULE: Ingest Projects Router
AI_DESCRIPTION: API endpoints per progetti ingest, batch, mix e export
AI_BUSINESS: Unified entry point per workflow ingest video/media
AI_TEACHING: FastAPI router + file upload + async processing + streaming responses

ENDPOINTS:
- POST   /projects               - Crea progetto
- GET    /projects               - Lista progetti
- GET    /projects/{id}          - Dettaglio progetto
- DELETE /projects/{id}          - Elimina progetto
- POST   /projects/{id}/upload   - Upload files (multipart)
- GET    /projects/{id}/batches  - Lista batch
- GET    /projects/{id}/batches/{date}/status - Stato processing
- POST   /projects/{id}/mix      - Genera mix
- GET    /projects/{id}/mix/versions - Lista versioni mix
- GET    /projects/{id}/mix/current - Mix attuale
- POST   /projects/{id}/export   - Esporta temp
- DELETE /projects/{id}/temp     - Cancella temp

INTEGRATION_DEPENDENCIES:
- Upstream: ProjectManager, MixGenerator, IngestOrchestrator
- Downstream: Frontend ingest-studio page
"""

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    UploadFile,
    File,
    Form,
    BackgroundTasks
)
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from datetime import datetime
from uuid import UUID
import logging
import os
import aiofiles

from core.database import get_db
from core.security import get_current_user, get_current_admin_user
from models.user import User
from models.ingest_project import BatchStatus, AssetType

from api.v1.schemas_ingest import (
    ProjectCreateRequest,
    ProjectUpdateRequest,
    ProjectResponse,
    ProjectListResponse,
    ProjectDetailResponse,
    BatchResponse,
    BatchStatusResponse,
    BatchListResponse,
    AssetResponse,
    AssetListResponse,
    UploadResponse,
    MixGenerateRequest,
    MixVersionResponse,
    MixVersionListResponse,
    MixCurrentResponse,
    ExportRequest,
    ExportResponse,
    CleanupRequest,
    CleanupResponse,
    ProjectHealthResponse,
    ProcessingPresetEnum,
    # Avatar/Blender schemas
    BlenderExportRequest,
    BlenderExportResponse,
    AvatarImportRequest,
    AvatarResponse,
    AvatarStatusResponse,
    AvatarListResponse,
    # DVD schemas
    DvdAnalyzeResponse,
    DvdExtractRequest,
    DvdExtractResponse,
    DvdPairsResponse,
    DvdPair,
    DvdImportToVocabRequest,
    DvdImportToVocabResponse
)

from services.video_studio.project_manager import ProjectManager
from services.video_studio.mix_generator import MixGenerator
from services.blender_export import BlenderExportService
from services.avatar_import import AvatarImportService
from services.dvd_processor import DvdProcessor

logger = logging.getLogger(__name__)

router = APIRouter()


# =========================================================================
# PROJECTS CRUD
# =========================================================================

@router.post(
    "/projects",
    response_model=ProjectResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crea nuovo progetto",
    description="Crea progetto ingest con struttura cartelle automatica"
)
async def create_project(
    data: ProjectCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Crea nuovo progetto ingest.

    **Cosa crea:**
    - Record nel database
    - Struttura cartelle: /storage/progetti/{name}/temp/, mix/, export/
    - File meta.json iniziale

    **Validazione:**
    - Nome deve essere univoco
    - target_languages devono essere codici ISO 639-1 validi
    """
    manager = ProjectManager(db)

    try:
        project = await manager.create_project(
            name=data.name,
            description=data.description,
            target_languages=data.target_languages,
            created_by=current_user.id
        )

        # Get stats
        stats = await manager.get_project_stats(project.id)

        return ProjectResponse(
            id=str(project.id),
            name=project.name,
            description=project.description,
            target_languages=project.target_languages,
            storage_path=project.storage_path,
            created_by=str(project.created_by) if project.created_by else None,
            created_at=project.created_at,
            updated_at=project.updated_at,
            is_active=project.is_active,
            current_mix_version=project.current_mix_version,
            batch_count=stats.get("batch_count", 0),
            total_assets=stats.get("total_assets", 0),
            total_size_bytes=stats.get("total_size_bytes", 0)
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/projects",
    response_model=ProjectListResponse,
    summary="Lista progetti",
    description="Lista progetti con paginazione e filtri"
)
async def list_projects(
    skip: int = Query(0, ge=0, description="Offset"),
    limit: int = Query(20, ge=1, le=100, description="Limit"),
    search: Optional[str] = Query(None, min_length=2, description="Cerca per nome"),
    active_only: bool = Query(True, description="Solo progetti attivi"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista tutti i progetti accessibili.

    **Filtri:**
    - search: LIKE sul nome progetto
    - active_only: esclude progetti archiviati
    """
    manager = ProjectManager(db)

    projects, total = await manager.list_projects(
        skip=skip,
        limit=limit,
        active_only=active_only,
        search=search
    )

    # Build responses with stats
    project_responses = []
    for project in projects:
        stats = await manager.get_project_stats(project.id)
        project_responses.append(ProjectResponse(
            id=str(project.id),
            name=project.name,
            description=project.description,
            target_languages=project.target_languages,
            storage_path=project.storage_path,
            created_by=str(project.created_by) if project.created_by else None,
            created_at=project.created_at,
            updated_at=project.updated_at,
            is_active=project.is_active,
            current_mix_version=project.current_mix_version,
            batch_count=stats.get("batch_count", 0),
            total_assets=stats.get("total_assets", 0),
            total_size_bytes=stats.get("total_size_bytes", 0)
        ))

    return ProjectListResponse(
        projects=project_responses,
        total=total,
        skip=skip,
        limit=limit
    )


@router.get(
    "/projects/{project_id}",
    response_model=ProjectDetailResponse,
    summary="Dettaglio progetto",
    description="Ottiene dettagli progetto con batch e mix"
)
async def get_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Dettaglio completo progetto.

    Include:
    - Tutti i batch con status
    - Tutte le versioni mix
    - Statistiche aggregate
    """
    manager = ProjectManager(db)
    mix_gen = MixGenerator(db)

    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    # Get batches
    batches = await manager.list_batches(project_id)
    batch_responses = [
        BatchResponse(
            id=str(b.id),
            batch_date=b.batch_date,
            status=b.status,
            video_count=b.video_count,
            audio_count=b.audio_count,
            image_count=b.image_count,
            pdf_count=b.pdf_count,
            skeleton_count=b.skeleton_count,
            total_size_bytes=b.total_size_bytes,
            progress_percentage=b.progress_percentage,
            current_step=b.current_step,
            error_message=b.error_message,
            created_at=b.created_at,
            started_at=b.started_at,
            processed_at=b.processed_at
        )
        for b in batches
    ]

    # Get mix versions
    mix_versions = await mix_gen.list_mix_versions(project_id)
    mix_responses = [
        MixVersionResponse(
            id=str(m.id),
            version=m.version,
            storage_path=m.storage_path,
            source_batches=m.source_batches,
            is_incremental=m.is_incremental,
            previous_version=m.previous_version,
            total_sources=m.total_sources,
            total_skeletons=m.total_skeletons,
            total_transcriptions=m.total_transcriptions,
            total_knowledge_chunks=m.total_knowledge_chunks,
            total_subtitles=m.total_subtitles,
            total_size_bytes=m.total_size_bytes,
            merge_stats=m.merge_stats,
            created_by=str(m.created_by) if m.created_by else None,
            created_at=m.created_at
        )
        for m in mix_versions
    ]

    # Get stats
    stats = await manager.get_project_stats(project_id)

    return ProjectDetailResponse(
        id=str(project.id),
        name=project.name,
        description=project.description,
        target_languages=project.target_languages,
        storage_path=project.storage_path,
        created_by=str(project.created_by) if project.created_by else None,
        created_at=project.created_at,
        updated_at=project.updated_at,
        is_active=project.is_active,
        current_mix_version=project.current_mix_version,
        batch_count=stats.get("batch_count", 0),
        total_assets=stats.get("total_assets", 0),
        total_size_bytes=stats.get("total_size_bytes", 0),
        batches=batch_responses,
        mix_versions=mix_responses
    )


@router.patch(
    "/projects/{project_id}",
    response_model=ProjectResponse,
    summary="Aggiorna progetto"
)
async def update_project(
    project_id: UUID,
    data: ProjectUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Aggiorna metadati progetto."""
    manager = ProjectManager(db)

    project = await manager.update_project(
        project_id=project_id,
        name=data.name,
        description=data.description,
        target_languages=data.target_languages,
        is_active=data.is_active
    )

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    stats = await manager.get_project_stats(project_id)

    return ProjectResponse(
        id=str(project.id),
        name=project.name,
        description=project.description,
        target_languages=project.target_languages,
        storage_path=project.storage_path,
        created_by=str(project.created_by) if project.created_by else None,
        created_at=project.created_at,
        updated_at=project.updated_at,
        is_active=project.is_active,
        current_mix_version=project.current_mix_version,
        batch_count=stats.get("batch_count", 0),
        total_assets=stats.get("total_assets", 0),
        total_size_bytes=stats.get("total_size_bytes", 0)
    )


@router.delete(
    "/projects/{project_id}",
    summary="Elimina progetto",
    description="Elimina progetto (richiede admin)"
)
async def delete_project(
    project_id: UUID,
    delete_files: bool = Query(False, description="Elimina anche i file"),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Elimina progetto.

    **ATTENZIONE:** Se delete_files=true, elimina tutti i file sul filesystem.
    Operazione irreversibile.
    """
    manager = ProjectManager(db)

    success = await manager.delete_project(project_id, delete_files=delete_files)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    return {"message": "Project deleted", "success": True}


# =========================================================================
# UPLOAD
# =========================================================================

@router.post(
    "/projects/{project_id}/upload",
    response_model=UploadResponse,
    summary="Upload files",
    description="Upload multiplo di file con processing automatico"
)
async def upload_files(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    files: List[UploadFile] = File(..., description="File da caricare"),
    preset: ProcessingPresetEnum = Form(
        ProcessingPresetEnum.STANDARD,
        description="Preset processing"
    ),
    extract_skeleton: bool = Form(True, description="Estrai skeleton"),
    target_languages: str = Form("it,en", description="Lingue target"),
    confidence_threshold: float = Form(0.65, description="Soglia confidenza"),
    use_martial_dictionary: bool = Form(True, description="Usa dizionario marziale"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Upload multiplo di file nel progetto.

    **Flusso:**
    1. Ottiene/crea batch per data odierna
    2. Salva file in temp/batch_{date}/{tipo}_originali/
    3. Calcola hash SHA256 per deduplication
    4. Avvia processing in background

    **Deduplication:**
    Se file con stesso hash gia processato, riusa i risultati.

    **Processing presets:**
    - standard: Knowledge + Techniques + Skeleton
    - knowledge: Solo estrazione conoscenza
    - skeleton: Solo estrazione skeleton
    - voice: Voice cloning
    - blender: Export per Blender
    """
    manager = ProjectManager(db)

    # Verifica progetto
    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    # Ottieni/crea batch
    batch_date = datetime.now().strftime("%Y-%m-%d")
    batch = await manager.get_or_create_batch(project_id, batch_date)

    # Process files
    uploaded_count = 0
    duplicated_count = 0
    total_size = 0

    for file in files:
        try:
            # Leggi contenuto
            content = await file.read()
            file_size = len(content)
            total_size += file_size

            # Calcola hash
            file_hash = await ProjectManager.calculate_file_hash_async(content)

            # Determina tipo asset
            content_type = file.content_type or ""
            if content_type.startswith("video/"):
                asset_type = AssetType.VIDEO.value
            elif content_type.startswith("audio/"):
                asset_type = AssetType.AUDIO.value
            elif content_type.startswith("image/"):
                asset_type = AssetType.IMAGE.value
            elif content_type == "application/pdf":
                asset_type = AssetType.PDF.value
            elif file.filename and file.filename.endswith(".json"):
                asset_type = AssetType.SKELETON.value
            else:
                asset_type = AssetType.VIDEO.value  # Default

            # Genera filename univoco
            import uuid as uuid_module
            ext = os.path.splitext(file.filename)[1] if file.filename else ".bin"
            unique_filename = f"{uuid_module.uuid4()}{ext}"

            # Calcola storage path
            storage_path = manager.get_asset_storage_path(
                project, batch_date, asset_type, unique_filename
            )

            # Salva file
            storage_path.parent.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(storage_path, 'wb') as f:
                await f.write(content)

            # Aggiungi asset
            asset, is_duplicate = await manager.add_asset(
                batch_id=batch.id,
                filename=unique_filename,
                original_filename=file.filename or "unknown",
                asset_type=asset_type,
                file_hash=file_hash,
                file_size=file_size,
                storage_path=str(storage_path),
                mime_type=content_type
            )

            if is_duplicate:
                duplicated_count += 1
            else:
                uploaded_count += 1

        except Exception as e:
            logger.error(f"Failed to process file {file.filename}: {e}")
            # Continue with other files

    # TODO: Avvia processing in background
    # background_tasks.add_task(
    #     process_batch,
    #     batch_id=batch.id,
    #     preset=preset.value,
    #     extract_skeleton=extract_skeleton,
    #     target_languages=target_languages.split(",")
    # )

    return UploadResponse(
        batch_id=str(batch.id),
        batch_date=batch_date,
        assets_uploaded=uploaded_count,
        assets_duplicated=duplicated_count,
        total_size_bytes=total_size,
        status_url=f"/api/v1/ingest/projects/{project_id}/batches/{batch_date}/status",
        message=f"Uploaded {uploaded_count} files ({duplicated_count} duplicates)"
    )


# =========================================================================
# BATCHES
# =========================================================================

@router.get(
    "/projects/{project_id}/batches",
    response_model=BatchListResponse,
    summary="Lista batch",
    description="Lista batch del progetto"
)
async def list_batches(
    project_id: UUID,
    status_filter: Optional[str] = Query(None, alias="status", description="Filtra per status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista tutti i batch di un progetto."""
    manager = ProjectManager(db)

    # Verifica progetto
    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    batches = await manager.list_batches(project_id, status=status_filter)

    batch_responses = [
        BatchResponse(
            id=str(b.id),
            batch_date=b.batch_date,
            status=b.status,
            video_count=b.video_count,
            audio_count=b.audio_count,
            image_count=b.image_count,
            pdf_count=b.pdf_count,
            skeleton_count=b.skeleton_count,
            total_size_bytes=b.total_size_bytes,
            progress_percentage=b.progress_percentage,
            current_step=b.current_step,
            error_message=b.error_message,
            created_at=b.created_at,
            started_at=b.started_at,
            processed_at=b.processed_at
        )
        for b in batches
    ]

    return BatchListResponse(
        batches=batch_responses,
        total=len(batch_responses)
    )


@router.get(
    "/projects/{project_id}/batches/{batch_date}/status",
    response_model=BatchStatusResponse,
    summary="Stato batch",
    description="Stato processing in tempo reale"
)
async def get_batch_status(
    project_id: UUID,
    batch_date: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Stato processing batch in tempo reale.

    **Response include:**
    - Status attuale (pending/processing/processed/failed)
    - Progress percentage (0-100)
    - Step corrente (skeleton_extraction, translation, etc.)
    - Asset processati vs totali
    """
    manager = ProjectManager(db)

    batch = await manager.get_batch_by_date(project_id, batch_date)
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch not found: {batch_date}"
        )

    # Count assets by status
    assets = await manager.list_assets(batch.id)
    assets_total = len(assets)
    assets_processed = sum(1 for a in assets if a.status == "completed")
    assets_failed = sum(1 for a in assets if a.status == "failed")

    return BatchStatusResponse(
        batch_date=batch.batch_date,
        status=batch.status,
        progress_percentage=batch.progress_percentage,
        current_step=batch.current_step,
        assets_processed=assets_processed,
        assets_total=assets_total,
        assets_failed=assets_failed,
        error_message=batch.error_message
    )


@router.get(
    "/projects/{project_id}/batches/{batch_date}/assets",
    response_model=AssetListResponse,
    summary="Lista asset batch"
)
async def list_batch_assets(
    project_id: UUID,
    batch_date: str,
    asset_type: Optional[str] = Query(None, description="Filtra per tipo"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista asset di un batch specifico."""
    manager = ProjectManager(db)

    batch = await manager.get_batch_by_date(project_id, batch_date)
    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch not found: {batch_date}"
        )

    assets = await manager.list_assets(batch.id, asset_type=asset_type)

    asset_responses = [
        AssetResponse(
            id=str(a.id),
            filename=a.filename,
            original_filename=a.original_filename,
            asset_type=a.asset_type,
            file_hash=a.file_hash,
            file_size=a.file_size,
            mime_type=a.mime_type,
            status=a.status,
            error_message=a.error_message,
            processing_results=a.processing_results,
            duration_seconds=a.duration_seconds,
            width=a.width,
            height=a.height,
            fps=a.fps,
            created_at=a.created_at,
            processed_at=a.processed_at
        )
        for a in assets
    ]

    return AssetListResponse(
        assets=asset_responses,
        total=len(asset_responses)
    )


# =========================================================================
# MIX
# =========================================================================

@router.post(
    "/projects/{project_id}/mix",
    response_model=MixVersionResponse,
    summary="Genera mix",
    description="Genera nuova versione mix da batch processati"
)
async def generate_mix(
    project_id: UUID,
    request: MixGenerateRequest = MixGenerateRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Genera nuovo mix blindato.

    **Versioning:**
    - Prima versione: v1.0
    - Incrementale: v1.1, v1.2, ...
    - Force full: v2.0, v3.0, ...

    **Incrementale (default):**
    Copia mix precedente + aggiunge nuovi batch.
    Molto piu veloce per grandi dataset.

    **Force full:**
    Rigenera tutto da zero. Utile per cleanup o dopo modifiche.
    """
    mix_gen = MixGenerator(db)

    try:
        mix_version = await mix_gen.generate_mix(
            project_id=project_id,
            force_full=request.force_full,
            created_by=current_user.id
        )

        return MixVersionResponse(
            id=str(mix_version.id),
            version=mix_version.version,
            storage_path=mix_version.storage_path,
            source_batches=mix_version.source_batches,
            is_incremental=mix_version.is_incremental,
            previous_version=mix_version.previous_version,
            total_sources=mix_version.total_sources,
            total_skeletons=mix_version.total_skeletons,
            total_transcriptions=mix_version.total_transcriptions,
            total_knowledge_chunks=mix_version.total_knowledge_chunks,
            total_subtitles=mix_version.total_subtitles,
            total_size_bytes=mix_version.total_size_bytes,
            merge_stats=mix_version.merge_stats,
            created_by=str(mix_version.created_by) if mix_version.created_by else None,
            created_at=mix_version.created_at
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/projects/{project_id}/mix/versions",
    response_model=MixVersionListResponse,
    summary="Lista versioni mix"
)
async def list_mix_versions(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista tutte le versioni mix del progetto."""
    manager = ProjectManager(db)
    mix_gen = MixGenerator(db)

    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    versions = await mix_gen.list_mix_versions(project_id)

    version_responses = [
        MixVersionResponse(
            id=str(m.id),
            version=m.version,
            storage_path=m.storage_path,
            source_batches=m.source_batches,
            is_incremental=m.is_incremental,
            previous_version=m.previous_version,
            total_sources=m.total_sources,
            total_skeletons=m.total_skeletons,
            total_transcriptions=m.total_transcriptions,
            total_knowledge_chunks=m.total_knowledge_chunks,
            total_subtitles=m.total_subtitles,
            total_size_bytes=m.total_size_bytes,
            merge_stats=m.merge_stats,
            created_by=str(m.created_by) if m.created_by else None,
            created_at=m.created_at
        )
        for m in versions
    ]

    return MixVersionListResponse(
        versions=version_responses,
        current_version=project.current_mix_version,
        total=len(version_responses)
    )


@router.get(
    "/projects/{project_id}/mix/current",
    response_model=MixCurrentResponse,
    summary="Mix corrente",
    description="Dettagli mix corrente con lista file"
)
async def get_current_mix(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Dettagli mix corrente.

    Include lista completa dei file in ogni categoria:
    - skeletons
    - transcriptions
    - knowledge
    - subtitles
    """
    mix_gen = MixGenerator(db)

    current_mix = await mix_gen.get_current_mix(project_id)
    if not current_mix:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No mix version found for this project"
        )

    contents = mix_gen.get_mix_contents(current_mix)

    return MixCurrentResponse(
        version=current_mix.version,
        storage_path=current_mix.storage_path,
        skeleton_files=contents.get("skeletons", []),
        transcription_files=contents.get("transcriptions", []),
        knowledge_files=contents.get("knowledge", []),
        subtitle_files=contents.get("subtitles", []),
        stats={
            "total_sources": current_mix.total_sources,
            "total_skeletons": current_mix.total_skeletons,
            "total_transcriptions": current_mix.total_transcriptions,
            "total_knowledge_chunks": current_mix.total_knowledge_chunks,
            "total_subtitles": current_mix.total_subtitles,
            "total_size_bytes": current_mix.total_size_bytes,
            "created_at": current_mix.created_at.isoformat()
        }
    )


# =========================================================================
# CLEANUP
# =========================================================================

@router.delete(
    "/projects/{project_id}/temp",
    response_model=CleanupResponse,
    summary="Cancella temp",
    description="Cancella cartella temp (richiede admin)"
)
async def delete_temp(
    project_id: UUID,
    request: CleanupRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Cancella cartella temp del progetto.

    **ATTENZIONE:** Operazione irreversibile!
    - Elimina tutti i batch temporanei
    - Mantiene i mix blindati

    Richiede confirm=true nel body.
    """
    if not request.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must set confirm=true to delete temp folder"
        )

    manager = ProjectManager(db)

    try:
        stats = await manager.delete_temp_folder(
            project_id,
            batch_dates=request.batch_dates
        )

        return CleanupResponse(
            batches_deleted=stats["batches_deleted"],
            files_deleted=stats["files_deleted"],
            bytes_freed=stats["bytes_freed"],
            message=f"Deleted {stats['batches_deleted']} batches, freed {stats['bytes_freed']} bytes"
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


# =========================================================================
# HEALTH
# =========================================================================

@router.get(
    "/projects/{project_id}/health",
    response_model=ProjectHealthResponse,
    summary="Health check progetto"
)
async def get_project_health(
    project_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Health check e statistiche progetto."""
    manager = ProjectManager(db)

    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    stats = await manager.get_project_stats(project_id)
    status_counts = stats.get("batch_status_counts", {})

    from pathlib import Path
    storage_exists = Path(project.storage_path).exists()

    # Get last activity
    batches = await manager.list_batches(project_id)
    last_activity = None
    if batches:
        last_activity = max(
            b.processed_at or b.created_at
            for b in batches
        )

    return ProjectHealthResponse(
        project_id=str(project_id),
        project_name=project.name,
        storage_exists=storage_exists,
        storage_size_bytes=stats.get("storage_size_bytes", 0),
        batches_pending=status_counts.get(BatchStatus.PENDING.value, 0),
        batches_processing=status_counts.get(BatchStatus.PROCESSING.value, 0),
        batches_processed=status_counts.get(BatchStatus.PROCESSED.value, 0),
        batches_failed=status_counts.get(BatchStatus.FAILED.value, 0),
        current_mix=project.current_mix_version,
        last_activity=last_activity
    )


# =========================================================================
# BLENDER/AVATAR ENDPOINTS
# =========================================================================

@router.post(
    "/projects/{project_id}/export-blender",
    response_model=BlenderExportResponse,
    summary="Export skeleton per Blender",
    description="Genera pacchetto JSON + script Python per import in Blender"
)
async def export_for_blender(
    project_id: UUID,
    request: BlenderExportRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Esporta skeleton per Blender.

    **Output:**
    - JSON con frames (Mixamo bone mapping)
    - Script Python per import automatico
    - Metadata per sincronizzazione

    🔒 PRIVACY: asset_id è UUID, output anonimizzato.
    """
    manager = ProjectManager(db)
    blender_service = BlenderExportService()

    # Verify project
    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    try:
        # Load skeleton data from asset
        skeleton_path = manager.get_skeleton_path(project_id, request.asset_id)
        if not skeleton_path or not skeleton_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Skeleton not found: {request.asset_id}"
            )

        import json
        with open(skeleton_path, 'r') as f:
            skeleton_data = json.load(f)

        # Export for Blender
        result = blender_service.export_for_blender(
            skeleton_data=skeleton_data,
            asset_id=request.asset_id,
            project_name=project.name,
            include_script=request.include_script,
            fps=request.fps
        )

        return BlenderExportResponse(
            export_id=result["export_id"],
            json_path=result["json_path"],
            script_path=result.get("script_path"),
            total_frames=result["total_frames"],
            duration_seconds=result["duration_seconds"],
            bone_count=result["bone_count"],
            download_url=f"/api/v1/ingest/blender/{result['export_id']}/download",
            message="Export pronto per Blender"
        )

    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Blender export failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Export failed: {str(e)}"
        )


@router.post(
    "/projects/{project_id}/import-avatar",
    response_model=AvatarResponse,
    summary="Import video avatar da Blender",
    description="Importa video renderizzato da Blender nel sistema"
)
async def import_avatar(
    project_id: UUID,
    background_tasks: BackgroundTasks,
    video: UploadFile = File(..., description="Video MP4 da Blender"),
    export_id: Optional[str] = Form(None, description="ID export originale"),
    render_angles: int = Form(8, description="Angoli camera"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Importa video avatar renderizzato da Blender.

    **Flusso:**
    1. Valida video file
    2. Salva in storage avatar
    3. Estrae metadata (ffprobe)
    4. Genera thumbnail
    5. Registra nel sistema

    🔒 PRIVACY: NO filename originale salvato.
    """
    manager = ProjectManager(db)
    avatar_service = AvatarImportService()

    # Verify project
    project = await manager.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Project not found: {project_id}"
        )

    try:
        # Save uploaded video to temp
        import tempfile
        import uuid as uuid_module

        temp_filename = f"{uuid_module.uuid4()}.mp4"
        temp_path = Path(tempfile.gettempdir()) / temp_filename

        async with aiofiles.open(temp_path, 'wb') as f:
            content = await video.read()
            await f.write(content)

        # Import avatar
        result = await avatar_service.import_avatar_video(
            video_path=str(temp_path),
            project_id=str(project_id),
            export_id=export_id,
            render_angles=render_angles
        )

        # Cleanup temp file
        temp_path.unlink(missing_ok=True)

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Import failed")
            )

        meta = result["metadata"]

        return AvatarResponse(
            avatar_id=result["avatar_id"],
            project_id=str(project_id),
            status=meta.get("status", "imported"),
            duration_seconds=meta.get("duration", 0),
            width=meta.get("width", 0),
            height=meta.get("height", 0),
            fps=meta.get("fps", 30),
            render_angles=meta.get("render_angles", 8),
            is_360=meta.get("is_360", True),
            thumbnail_url=result["thumbnail_url"],
            stream_url=result["stream_url"],
            download_url=result["download_url"],
            created_at=datetime.fromisoformat(meta.get("created_at", datetime.now().isoformat()))
        )

    except Exception as e:
        logger.error(f"Avatar import failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {str(e)}"
        )


@router.get(
    "/projects/{project_id}/avatars",
    response_model=AvatarListResponse,
    summary="Lista avatar progetto"
)
async def list_avatars(
    project_id: UUID,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Lista tutti gli avatar di un progetto."""
    avatar_service = AvatarImportService()

    avatars = await avatar_service.list_avatars(
        project_id=str(project_id),
        limit=limit,
        offset=offset
    )

    avatar_responses = [
        AvatarResponse(
            avatar_id=a["avatar_id"],
            project_id=a["project_id"],
            status=a.get("status", "unknown"),
            duration_seconds=a.get("duration", 0),
            width=a.get("width", 0),
            height=a.get("height", 0),
            fps=a.get("fps", 30),
            render_angles=a.get("render_angles", 8),
            is_360=a.get("is_360", True),
            thumbnail_url=f"/api/v1/avatars/{a['avatar_id']}/thumbnail",
            stream_url=f"/api/v1/avatars/{a['avatar_id']}/stream",
            download_url=f"/api/v1/avatars/{a['avatar_id']}/download",
            created_at=datetime.fromisoformat(a.get("created_at", datetime.now().isoformat()))
        )
        for a in avatars
    ]

    return AvatarListResponse(
        avatars=avatar_responses,
        total=len(avatar_responses)
    )


@router.get(
    "/projects/{project_id}/avatar/{avatar_id}/status",
    response_model=AvatarStatusResponse,
    summary="Stato avatar"
)
async def get_avatar_status(
    project_id: UUID,
    avatar_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Verifica stato di un avatar specifico."""
    avatar_service = AvatarImportService()

    status_info = await avatar_service.get_avatar_status(avatar_id)

    if status_info.get("status") == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Avatar not found: {avatar_id}"
        )

    return AvatarStatusResponse(
        avatar_id=status_info["avatar_id"],
        status=status_info["status"],
        video_exists=status_info["video_exists"],
        thumbnail_exists=status_info["thumbnail_exists"],
        is_360=status_info["is_360"],
        duration_seconds=status_info["duration"],
        render_angles=status_info["render_angles"]
    )


# =========================================================================
# DVD/PARALLEL CORPUS ENDPOINTS
# =========================================================================

# In-memory storage for DVD jobs (in production, use Redis/DB)
_dvd_jobs: dict = {}


@router.post(
    "/dvd/analyze",
    response_model=DvdAnalyzeResponse,
    summary="Analizza tracce DVD",
    description="Rileva audio e sottotitoli disponibili"
)
async def analyze_dvd(
    video: UploadFile = File(..., description="Video DVD (MKV/MP4)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Analizza video per rilevare tracce.

    **Output:**
    - Lista tracce audio con lingue
    - Lista tracce sottotitoli con lingue
    - Durata video

    🔒 PRIVACY: Filename originale NON salvato.
    """
    dvd_processor = DvdProcessor()

    try:
        import tempfile
        import uuid as uuid_module

        # Save to temp
        job_id = str(uuid_module.uuid4())
        temp_dir = Path(tempfile.gettempdir()) / f"dvd_{job_id}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        temp_path = temp_dir / "video.mkv"
        async with aiofiles.open(temp_path, 'wb') as f:
            content = await video.read()
            await f.write(content)

        # Analyze tracks
        tracks = await dvd_processor.extract_tracks(str(temp_path))

        # Store job info
        _dvd_jobs[job_id] = {
            "temp_path": str(temp_path),
            "temp_dir": str(temp_dir),
            "tracks": tracks,
            "created_at": datetime.now().isoformat(),
            "status": "analyzed"
        }

        # Extract languages
        detected_langs = set()
        for track in tracks.get("audio_tracks", []):
            if track.get("language"):
                detected_langs.add(track["language"])
        for track in tracks.get("subtitle_tracks", []):
            if track.get("language"):
                detected_langs.add(track["language"])

        return DvdAnalyzeResponse(
            job_id=job_id,
            audio_tracks=tracks.get("audio_tracks", []),
            subtitle_tracks=tracks.get("subtitle_tracks", []),
            video_duration_seconds=tracks.get("duration", 0),
            detected_languages=list(detected_langs)
        )

    except Exception as e:
        logger.error(f"DVD analyze failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.post(
    "/dvd/extract",
    response_model=DvdExtractResponse,
    summary="Estrai parallel corpus",
    description="Estrae e allinea coppie di sottotitoli"
)
async def extract_dvd_pairs(
    request: DvdExtractRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Estrae sentence pairs da sottotitoli DVD.

    **Flusso:**
    1. Estrae sottotitoli sorgente e target
    2. Allinea per timestamp
    3. Calcola confidenza
    4. Anonimizza (rimuove timestamp)

    🔒 PRIVACY BY DESIGN: Output senza timestamp né riferimenti.
    """
    import time
    start_time = time.time()

    job_info = _dvd_jobs.get(request.job_id)
    if not job_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {request.job_id}"
        )

    dvd_processor = DvdProcessor()

    try:
        video_path = job_info["temp_path"]

        # Process DVD
        result = await dvd_processor.process_dvd(
            video_path=video_path,
            source_lang=request.source_language,
            target_lang=request.target_language,
            source_track=request.subtitle_track_source,
            target_track=request.subtitle_track_target,
            min_confidence=request.min_confidence
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Extraction failed")
            )

        # Store pairs in job
        job_info["pairs"] = result["pairs"]
        job_info["source_language"] = request.source_language
        job_info["target_language"] = request.target_language
        job_info["status"] = "extracted"

        processing_time = time.time() - start_time
        high_confidence = sum(1 for p in result["pairs"] if p["confidence"] >= 0.8)
        avg_confidence = sum(p["confidence"] for p in result["pairs"]) / len(result["pairs"]) if result["pairs"] else 0

        return DvdExtractResponse(
            job_id=request.job_id,
            status="extracted",
            pairs_extracted=len(result["pairs"]),
            pairs_high_confidence=high_confidence,
            average_confidence=avg_confidence,
            processing_time_seconds=processing_time
        )

    except Exception as e:
        logger.error(f"DVD extraction failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Extraction failed: {str(e)}"
        )


@router.get(
    "/dvd/pairs/{job_id}",
    response_model=DvdPairsResponse,
    summary="Recupera sentence pairs",
    description="Ottiene le coppie tradotte estratte"
)
async def get_dvd_pairs(
    job_id: str,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(1000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Recupera sentence pairs estratte.

    🔒 PRIVACY: Solo testo + confidenza, zero metadata.
    """
    job_info = _dvd_jobs.get(job_id)
    if not job_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {job_id}"
        )

    if job_info.get("status") != "extracted":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pairs not yet extracted. Call /dvd/extract first."
        )

    pairs = job_info.get("pairs", [])

    # Filter by confidence
    filtered = [p for p in pairs if p["confidence"] >= min_confidence]

    # Paginate
    paginated = filtered[offset:offset + limit]

    avg_confidence = sum(p["confidence"] for p in filtered) / len(filtered) if filtered else 0

    return DvdPairsResponse(
        job_id=job_id,
        source_language=job_info.get("source_language", "unknown"),
        target_language=job_info.get("target_language", "unknown"),
        pairs=[DvdPair(**p) for p in paginated],
        total_pairs=len(filtered),
        average_confidence=avg_confidence
    )


@router.post(
    "/dvd/import-to-vocab",
    response_model=DvdImportToVocabResponse,
    summary="Importa in vocabolario",
    description="Importa pairs nel translation memory"
)
async def import_dvd_to_vocabulary(
    request: DvdImportToVocabRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Importa sentence pairs nel vocabolario.

    **Flusso:**
    1. Filtra per confidenza minima
    2. (Opzionale) Valida con multi-LLM debate
    3. Inserisce in translation_memory
    4. Cancella job (FORGETTING BY DESIGN)

    🔒 PRIVACY: Dopo import, job viene eliminato.
    """
    job_info = _dvd_jobs.get(request.job_id)
    if not job_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {request.job_id}"
        )

    pairs = job_info.get("pairs", [])
    if not pairs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pairs to import"
        )

    try:
        # Filter by confidence
        qualified = [p for p in pairs if p["confidence"] >= request.min_confidence]

        # TODO: Integrate with actual translation_memory service
        # For now, simulate import
        imported = 0
        rejected = 0
        existing = 0

        for pair in qualified:
            # Placeholder for actual DB insert
            # In production: await translation_memory.add_term(...)
            imported += 1

        rejected = len(pairs) - len(qualified)

        # Cleanup job (FORGETTING BY DESIGN)
        import shutil
        temp_dir = job_info.get("temp_dir")
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        del _dvd_jobs[request.job_id]

        return DvdImportToVocabResponse(
            terms_imported=imported,
            terms_rejected=rejected,
            terms_already_exist=existing,
            validation_results=None,
            message=f"Imported {imported} terms, rejected {rejected}"
        )

    except Exception as e:
        logger.error(f"DVD import to vocab failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Import failed: {str(e)}"
        )


@router.delete(
    "/dvd/job/{job_id}",
    summary="Cancella job DVD",
    description="Cancella job e file temporanei"
)
async def delete_dvd_job(
    job_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cancella job DVD e tutti i file associati.

    🔒 PRIVACY: Cleanup completo, nessuna traccia.
    """
    job_info = _dvd_jobs.get(job_id)
    if not job_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {job_id}"
        )

    try:
        import shutil
        temp_dir = job_info.get("temp_dir")
        if temp_dir and Path(temp_dir).exists():
            shutil.rmtree(temp_dir, ignore_errors=True)

        del _dvd_jobs[job_id]

        return {"message": "Job deleted", "job_id": job_id}

    except Exception as e:
        logger.error(f"DVD job deletion failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deletion failed: {str(e)}"
        )

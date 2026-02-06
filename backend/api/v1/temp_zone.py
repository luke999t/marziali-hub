"""
AI_MODULE: Temp Zone API Router
AI_DESCRIPTION: API endpoints per gestione temp zone con file sensibili
AI_BUSINESS: Admin interface per monitoraggio e cleanup dati temporanei
AI_TEACHING: FastAPI router, dependency injection, admin-only endpoints

ENDPOINTS:
- GET    /temp-zone/stats              - Statistiche temp zone
- GET    /temp-zone/batches            - Lista batch con filtri
- GET    /temp-zone/batches/{id}       - Dettaglio singolo batch
- DELETE /temp-zone/batches/{id}       - Cancella batch
- POST   /temp-zone/cleanup            - Cleanup bulk (admin)
- GET    /temp-zone/expiring           - Batch in scadenza
- GET    /temp-zone/audit              - Audit log (admin)
- PATCH  /temp-zone/config             - Aggiorna configurazione (admin)

SECURITY:
- Tutti gli endpoint richiedono autenticazione
- DELETE e config richiedono ruolo ADMIN
- Audit log per tutte le operazioni sensibili

INTEGRATION_DEPENDENCIES:
- Upstream: TempZoneManager service
- Downstream: Admin dashboard frontend
"""

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
    Query,
    BackgroundTasks
)
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field
import logging

from core.security import get_current_user, get_current_admin_user
from models.user import User
from services.temp_zone_manager import (
    get_temp_zone_manager,
    TempZoneManager,
    TempBatch,
    BatchStatus,
    BatchType,
    TempZoneConfig
)

logger = logging.getLogger(__name__)

router = APIRouter()


# === PYDANTIC SCHEMAS ===

class BatchResponse(BaseModel):
    """Response per singolo batch."""
    id: str
    batch_type: str
    created_at: datetime
    status: str
    size_bytes: int
    size_formatted: str
    file_count: int
    created_by: str
    updated_at: Optional[datetime]
    expires_at: Optional[datetime]
    output_summary: Dict[str, Any]
    error_message: Optional[str]


class BatchListResponse(BaseModel):
    """Response per lista batch."""
    batches: List[BatchResponse]
    total: int
    filtered: int


class StatsResponse(BaseModel):
    """Response statistiche temp zone."""
    total_batches: int
    total_size_bytes: int
    total_size_formatted: str
    total_files: int
    oldest_batch_days: int
    expiring_soon: int
    by_status: Dict[str, int]
    by_type: Dict[str, int]
    config: Dict[str, Any]
    limits: Dict[str, float]


class CleanupRequest(BaseModel):
    """Request per cleanup bulk."""
    delete_completed: bool = Field(
        default=False,
        description="Cancella tutti i batch completati"
    )
    delete_failed: bool = Field(
        default=False,
        description="Cancella tutti i batch falliti"
    )
    older_than_days: Optional[int] = Field(
        None,
        ge=0,
        le=365,
        description="Solo batch più vecchi di X giorni"
    )
    confirm: bool = Field(
        ...,
        description="Conferma operazione (deve essere true)"
    )


class CleanupResponse(BaseModel):
    """Response cleanup."""
    deleted_count: int
    freed_bytes: int
    freed_formatted: str
    message: str


class ConfigUpdateRequest(BaseModel):
    """Request per aggiornare configurazione."""
    auto_cleanup_enabled: Optional[bool] = None
    delete_after_days: Optional[int] = Field(None, ge=1, le=365)
    warn_before_days: Optional[int] = Field(None, ge=1, le=30)
    secure_delete: Optional[bool] = None


class ConfigResponse(BaseModel):
    """Response configurazione."""
    auto_cleanup_enabled: bool
    delete_after_days: int
    warn_before_days: int
    secure_delete: bool
    temp_base_path: str
    max_batch_size_gb: float
    max_total_size_gb: float


class AuditEntryResponse(BaseModel):
    """Response singola entry audit."""
    timestamp: datetime
    action: str
    target_id: str
    user_id: str
    details: Dict[str, Any]


class AuditLogResponse(BaseModel):
    """Response audit log."""
    entries: List[AuditEntryResponse]
    total: int


# === HELPER FUNCTIONS ===

def _format_size(size_bytes: int) -> str:
    """Formatta size in human readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


def _batch_to_response(batch: TempBatch) -> BatchResponse:
    """Converte TempBatch in response."""
    return BatchResponse(
        id=batch.id,
        batch_type=batch.batch_type.value,
        created_at=batch.created_at,
        status=batch.status.value,
        size_bytes=batch.size_bytes,
        size_formatted=_format_size(batch.size_bytes),
        file_count=batch.file_count,
        created_by=batch.created_by,
        updated_at=batch.updated_at,
        expires_at=batch.expires_at,
        output_summary=batch.output_summary,
        error_message=batch.error_message
    )


# === DEPENDENCY ===

async def get_temp_manager() -> TempZoneManager:
    """Dependency per ottenere TempZoneManager."""
    return await get_temp_zone_manager()


# === ENDPOINTS ===

@router.get(
    "/stats",
    response_model=StatsResponse,
    summary="Statistiche Temp Zone",
    description="Recupera statistiche aggregate della temp zone"
)
async def get_stats(
    manager: TempZoneManager = Depends(get_temp_manager),
    current_user: User = Depends(get_current_user)
):
    """
    Statistiche temp zone.

    Include:
    - Conteggi totali
    - Dimensioni
    - Breakdown per status e tipo
    - Configurazione corrente
    - Utilizzo limiti
    """
    stats = await manager.get_stats()

    return StatsResponse(
        total_batches=stats["total_batches"],
        total_size_bytes=stats["total_size_bytes"],
        total_size_formatted=stats["total_size_formatted"],
        total_files=stats["total_files"],
        oldest_batch_days=stats["oldest_batch_days"],
        expiring_soon=stats["expiring_soon"],
        by_status=stats["by_status"],
        by_type=stats["by_type"],
        config=stats["config"],
        limits=stats["limits"]
    )


@router.get(
    "/batches",
    response_model=BatchListResponse,
    summary="Lista Batch",
    description="Lista batch con filtri e paginazione"
)
async def list_batches(
    status_filter: Optional[str] = Query(
        None,
        alias="status",
        description="Filtra per status (processing, completed, failed, expired)"
    ),
    batch_type: Optional[str] = Query(
        None,
        description="Filtra per tipo batch"
    ),
    created_by: Optional[str] = Query(
        None,
        description="Filtra per creatore"
    ),
    limit: int = Query(50, ge=1, le=500, description="Max risultati"),
    offset: int = Query(0, ge=0, description="Offset paginazione"),
    manager: TempZoneManager = Depends(get_temp_manager),
    current_user: User = Depends(get_current_user)
):
    """
    Lista batch con filtri.

    Ordinati per data creazione DESC.
    """
    # Parse enums
    status_enum = None
    if status_filter:
        try:
            status_enum = BatchStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}"
            )

    batch_type_enum = None
    if batch_type:
        try:
            batch_type_enum = BatchType(batch_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid batch_type: {batch_type}"
            )

    # Get all for total count
    all_batches = await manager.list_batches(
        status=status_enum,
        batch_type=batch_type_enum,
        created_by=created_by,
        limit=10000,
        offset=0
    )

    # Get paginated
    batches = await manager.list_batches(
        status=status_enum,
        batch_type=batch_type_enum,
        created_by=created_by,
        limit=limit,
        offset=offset
    )

    return BatchListResponse(
        batches=[_batch_to_response(b) for b in batches],
        total=len(all_batches),
        filtered=len(batches)
    )


@router.get(
    "/batches/{batch_id}",
    response_model=BatchResponse,
    summary="Dettaglio Batch",
    description="Recupera dettagli di un singolo batch"
)
async def get_batch(
    batch_id: str,
    manager: TempZoneManager = Depends(get_temp_manager),
    current_user: User = Depends(get_current_user)
):
    """Dettaglio singolo batch."""
    batch = await manager.get_batch(batch_id)

    if not batch:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch not found: {batch_id}"
        )

    return _batch_to_response(batch)


@router.delete(
    "/batches/{batch_id}",
    summary="Cancella Batch",
    description="Cancella un batch e tutti i suoi file (richiede ADMIN)"
)
async def delete_batch(
    batch_id: str,
    manager: TempZoneManager = Depends(get_temp_manager),
    admin: User = Depends(get_current_admin_user)
):
    """
    Cancella batch.

    ATTENZIONE: Operazione irreversibile.
    Richiede ruolo ADMIN.
    """
    success = await manager.delete_batch(
        batch_id=batch_id,
        deleted_by=str(admin.id)
    )

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Batch not found: {batch_id}"
        )

    return {"message": "Batch deleted", "batch_id": batch_id}


@router.post(
    "/cleanup",
    response_model=CleanupResponse,
    summary="Cleanup Bulk",
    description="Cancella batch in bulk (richiede ADMIN)"
)
async def cleanup_bulk(
    request: CleanupRequest,
    manager: TempZoneManager = Depends(get_temp_manager),
    admin: User = Depends(get_current_admin_user)
):
    """
    Cleanup bulk.

    ATTENZIONE: Operazione irreversibile!
    Richiede confirm=true nel body.
    """
    if not request.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must set confirm=true to perform cleanup"
        )

    # Get stats before
    stats_before = await manager.get_stats()
    size_before = stats_before["total_size_bytes"]

    deleted_count = 0

    if request.delete_completed:
        count = await manager.delete_all_completed(
            deleted_by=str(admin.id),
            older_than_days=request.older_than_days
        )
        deleted_count += count

    if request.delete_failed:
        count = await manager.delete_all_failed(
            deleted_by=str(admin.id)
        )
        deleted_count += count

    # Get stats after
    stats_after = await manager.get_stats()
    size_after = stats_after["total_size_bytes"]

    freed_bytes = size_before - size_after

    return CleanupResponse(
        deleted_count=deleted_count,
        freed_bytes=freed_bytes,
        freed_formatted=_format_size(freed_bytes),
        message=f"Deleted {deleted_count} batches, freed {_format_size(freed_bytes)}"
    )


@router.get(
    "/expiring",
    response_model=List[BatchResponse],
    summary="Batch in Scadenza",
    description="Lista batch che scadranno entro il periodo di warning"
)
async def get_expiring_batches(
    manager: TempZoneManager = Depends(get_temp_manager),
    current_user: User = Depends(get_current_user)
):
    """Batch in scadenza (entro warn_before_days)."""
    batches = await manager.get_expiring_batches()

    return [_batch_to_response(b) for b in batches]


@router.get(
    "/audit",
    response_model=AuditLogResponse,
    summary="Audit Log",
    description="Recupera audit log delle operazioni (richiede ADMIN)"
)
async def get_audit_log(
    action: Optional[str] = Query(
        None,
        description="Filtra per action (CREATE, DELETE, CONFIG_CHANGE, etc.)"
    ),
    target_id: Optional[str] = Query(
        None,
        description="Filtra per target ID"
    ),
    limit: int = Query(100, ge=1, le=1000),
    manager: TempZoneManager = Depends(get_temp_manager),
    admin: User = Depends(get_current_admin_user)
):
    """
    Audit log.

    Traccia tutte le operazioni sensibili:
    - CREATE: Creazione batch
    - DELETE: Cancellazione
    - CONFIG_CHANGE: Modifiche configurazione
    - COMPLETE/FAIL: Cambio status
    """
    entries = await manager.get_audit_log(
        limit=limit,
        action=action,
        target_id=target_id
    )

    return AuditLogResponse(
        entries=[
            AuditEntryResponse(
                timestamp=datetime.fromisoformat(e["timestamp"]),
                action=e["action"],
                target_id=e["target_id"],
                user_id=e["user_id"],
                details=e["details"]
            )
            for e in entries
        ],
        total=len(entries)
    )


@router.get(
    "/config",
    response_model=ConfigResponse,
    summary="Configurazione Corrente",
    description="Recupera configurazione temp zone"
)
async def get_config(
    manager: TempZoneManager = Depends(get_temp_manager),
    current_user: User = Depends(get_current_user)
):
    """Configurazione corrente."""
    config = manager.config

    return ConfigResponse(
        auto_cleanup_enabled=config.auto_cleanup_enabled,
        delete_after_days=config.delete_after_days,
        warn_before_days=config.warn_before_days,
        secure_delete=config.secure_delete,
        temp_base_path=config.temp_base_path,
        max_batch_size_gb=config.max_batch_size_gb,
        max_total_size_gb=config.max_total_size_gb
    )


@router.patch(
    "/config",
    response_model=ConfigResponse,
    summary="Aggiorna Configurazione",
    description="Modifica configurazione temp zone (richiede ADMIN)"
)
async def update_config(
    request: ConfigUpdateRequest,
    manager: TempZoneManager = Depends(get_temp_manager),
    admin: User = Depends(get_current_admin_user)
):
    """
    Aggiorna configurazione.

    Modifiche loggate in audit.
    Richiede ruolo ADMIN.
    """
    updated = await manager.update_config(
        updated_by=str(admin.id),
        auto_cleanup_enabled=request.auto_cleanup_enabled,
        delete_after_days=request.delete_after_days,
        warn_before_days=request.warn_before_days,
        secure_delete=request.secure_delete
    )

    return ConfigResponse(
        auto_cleanup_enabled=updated.auto_cleanup_enabled,
        delete_after_days=updated.delete_after_days,
        warn_before_days=updated.warn_before_days,
        secure_delete=updated.secure_delete,
        temp_base_path=updated.temp_base_path,
        max_batch_size_gb=updated.max_batch_size_gb,
        max_total_size_gb=updated.max_total_size_gb
    )


# === BATCH TYPES INFO ===

@router.get(
    "/batch-types",
    summary="Tipi Batch Supportati",
    description="Lista dei tipi di batch supportati"
)
async def get_batch_types():
    """Lista tipi batch supportati."""
    return {
        "batch_types": [
            {
                "value": bt.value,
                "name": bt.name,
                "description": _get_batch_type_description(bt)
            }
            for bt in BatchType
        ]
    }


def _get_batch_type_description(bt: BatchType) -> str:
    """Descrizione per tipo batch."""
    descriptions = {
        BatchType.BILINGUAL_BOOK: "Processing libri bilingui con testo a fronte",
        BatchType.MANGA_PROCESSING: "Estrazione dialoghi da manga bilingui",
        BatchType.DVD_EXTRACTION: "Estrazione sottotitoli da DVD",
        BatchType.AUDIO_PROCESSING: "Processing audio per TTS/voice clone",
        BatchType.PDF_OCR: "OCR e estrazione testo da PDF",
        BatchType.SKELETON_EXTRACTION: "Estrazione skeleton da video",
        BatchType.VOICE_CLONE: "Training voice clone",
        BatchType.GENERIC: "Batch generico",
    }
    return descriptions.get(bt, "")

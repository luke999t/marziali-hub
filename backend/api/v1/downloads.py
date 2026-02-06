"""
================================================================================
AI_MODULE: Downloads API Router
AI_VERSION: 1.0.0
AI_DESCRIPTION: REST API per gestione download offline con DRM e tier limits
AI_BUSINESS: Feature differenziante, +15% conversioni PREMIUM
AI_TEACHING: FastAPI router con dependency injection, async handlers

ENDPOINT_OVERVIEW:
POST   /request           - Richiedi nuovo download
GET    /url/{id}          - Ottieni URL firmato per download
PATCH  /progress/{id}     - Aggiorna progresso download
GET    /list              - Lista download utente
DELETE /{id}              - Elimina download
POST   /refresh-drm/{id}  - Rinnova token DRM
POST   /offline-view/{id} - Registra view offline
GET    /limits            - Limiti tier utente
GET    /storage           - Statistiche storage

INTEGRATION_DEPENDENCIES:
- Upstream: modules/downloads/download_service.py
- Auth: core/auth.py (get_current_user)
================================================================================
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

from core.database import get_db
from core.auth import get_current_user
from models.user import User
from models.download import DownloadStatus, DownloadQuality
from modules.downloads.download_service import (
    DownloadService,
    DownloadError,
    TierLimitError,
    StorageLimitError,
    DownloadNotFoundError,
    DRMExpiredError
)

router = APIRouter(prefix="/downloads", tags=["Downloads"])


# ==============================================================================
# SCHEMAS
# ==============================================================================

class DownloadRequestSchema(BaseModel):
    """Schema per richiesta download."""
    video_id: str = Field(..., description="UUID del video da scaricare")
    device_id: str = Field(..., description="ID univoco dispositivo", max_length=100)
    device_name: Optional[str] = Field(None, description="Nome dispositivo", max_length=100)
    quality: Optional[str] = Field(None, description="Qualita: 360p, 720p, 1080p, 4K")

    class Config:
        json_schema_extra = {
            "example": {
                "video_id": "550e8400-e29b-41d4-a716-446655440000",
                "device_id": "iphone-15-abc123",
                "device_name": "iPhone 15 Pro",
                "quality": "1080p"
            }
        }


class ProgressUpdateSchema(BaseModel):
    """Schema per aggiornamento progresso."""
    downloaded_bytes: int = Field(..., ge=0, description="Bytes scaricati finora")
    completed: bool = Field(False, description="True se download completato")

    class Config:
        json_schema_extra = {
            "example": {
                "downloaded_bytes": 524288000,
                "completed": False
            }
        }


class OfflineViewSchema(BaseModel):
    """Schema per registrazione view offline."""
    drm_token: str = Field(..., description="Token DRM per verifica")

    class Config:
        json_schema_extra = {
            "example": {
                "drm_token": "drm_abc123xyz..."
            }
        }


class DownloadResponseSchema(BaseModel):
    """Schema response download."""
    download_id: str
    status: str
    quality: Optional[str] = None
    progress_percent: Optional[int] = None
    file_size_bytes: Optional[int] = None
    downloaded_bytes: Optional[int] = None
    drm_expires_at: Optional[str] = None
    offline_views_remaining: Optional[int] = None
    is_playable: Optional[bool] = None
    needs_refresh: Optional[bool] = None
    message: Optional[str] = None


class StorageStatsSchema(BaseModel):
    """Schema statistiche storage."""
    used_bytes: int
    used_human: str
    max_bytes: int
    max_human: str
    percentage: float
    downloads_count: int
    downloads_limit: int


class LimitsResponseSchema(BaseModel):
    """Schema limiti tier."""
    tier: str
    max_concurrent_downloads: int
    max_stored_downloads: int
    max_quality: Optional[str]
    drm_validity_days: int
    offline_views_per_download: int
    max_storage_bytes: Optional[int]


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def _parse_quality(quality_str: Optional[str]) -> Optional[DownloadQuality]:
    """Parse quality string to enum."""
    if not quality_str:
        return None
    mapping = {
        "360p": DownloadQuality.LOW,
        "720p": DownloadQuality.MEDIUM,
        "1080p": DownloadQuality.HIGH,
        "4k": DownloadQuality.ULTRA,
        "4K": DownloadQuality.ULTRA
    }
    return mapping.get(quality_str)


def _parse_uuid(id_str: str) -> uuid.UUID:
    """Parse string to UUID with validation."""
    try:
        return uuid.UUID(id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid UUID: {id_str}"
        )


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@router.post(
    "/request",
    response_model=DownloadResponseSchema,
    summary="Richiedi nuovo download",
    description="""
    Richiede un nuovo download per un video.

    **Limiti per tier:**
    - FREE: Nessun download (errore 403)
    - BASIC: Max 3 download, 720p
    - PREMIUM: Max 10 download, 1080p
    - VIP: Max 25 download, 4K

    **Errori possibili:**
    - 403: Tier non permette download / limite raggiunto
    - 507: Storage insufficiente
    """
)
async def request_download(
    request: DownloadRequestSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        video_id = _parse_uuid(request.video_id)
        quality = _parse_quality(request.quality)

        result = await service.request_download(
            user_id=current_user.id,
            video_id=video_id,
            device_id=request.device_id,
            device_name=request.device_name,
            quality=quality
        )
        return result

    except TierLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except StorageLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_507_INSUFFICIENT_STORAGE,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/url/{download_id}",
    summary="Ottieni URL download firmato",
    description="""
    Genera URL firmato per scaricare il file.
    URL valido per 24 ore.
    Supporta resume da ultimo byte scaricato.
    """
)
async def get_download_url(
    download_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        dl_id = _parse_uuid(download_id)
        result = await service.get_download_url(dl_id, current_user.id)
        return result

    except DownloadNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.patch(
    "/progress/{download_id}",
    response_model=DownloadResponseSchema,
    summary="Aggiorna progresso download",
    description="""
    Aggiorna il progresso di un download in corso.
    Quando completed=true, genera token DRM.
    """
)
async def update_progress(
    download_id: str,
    request: ProgressUpdateSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        dl_id = _parse_uuid(download_id)
        result = await service.update_progress(
            download_id=dl_id,
            user_id=current_user.id,
            downloaded_bytes=request.downloaded_bytes,
            completed=request.completed
        )
        return result

    except DownloadNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/list",
    summary="Lista download utente",
    description="""
    Ritorna lista di tutti i download dell'utente.
    Filtrabile per dispositivo e stato.
    """
)
async def list_downloads(
    device_id: Optional[str] = Query(None, description="Filtra per dispositivo"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filtra per stato"),
    include_expired: bool = Query(False, description="Includi download scaduti"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    # Parse status if provided
    dl_status = None
    if status_filter:
        try:
            dl_status = DownloadStatus(status_filter)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {status_filter}. Valid: pending, downloading, completed, expired, revoked, failed"
            )

    downloads = await service.get_user_downloads(
        user_id=current_user.id,
        device_id=device_id,
        status=dl_status,
        include_expired=include_expired
    )

    return {
        "downloads": downloads,
        "count": len(downloads)
    }


@router.delete(
    "/{download_id}",
    summary="Elimina download",
    description="""
    Elimina un download e libera lo spazio.
    Il file locale sul dispositivo deve essere eliminato dal client.
    """
)
async def delete_download(
    download_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        dl_id = _parse_uuid(download_id)
        result = await service.delete_download(dl_id, current_user.id)
        return result

    except DownloadNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/refresh-drm/{download_id}",
    summary="Rinnova token DRM",
    description="""
    Rinnova il token DRM per un download completato.
    Richiede connessione online.
    Verifica che l'abbonamento sia ancora attivo.

    **Importante:** Se l'utente ha fatto downgrade a FREE,
    il download viene revocato.
    """
)
async def refresh_drm_token(
    download_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        dl_id = _parse_uuid(download_id)
        result = await service.refresh_drm_token(dl_id, current_user.id)
        return result

    except DownloadNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except TierLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/offline-view/{download_id}",
    summary="Registra view offline",
    description="""
    Registra una visualizzazione offline.
    Il client deve chiamare questo endpoint periodicamente
    durante la riproduzione offline.

    Decrementa le views rimanenti e segnala se serve refresh.
    """
)
async def record_offline_view(
    download_id: str,
    request: OfflineViewSchema,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        dl_id = _parse_uuid(download_id)
        result = await service.record_offline_view(
            download_id=dl_id,
            user_id=current_user.id,
            drm_token=request.drm_token
        )
        return result

    except DownloadNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except DRMExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/limits",
    response_model=LimitsResponseSchema,
    summary="Limiti download per tier",
    description="""
    Ritorna i limiti di download per il tier dell'utente corrente.
    Utile per mostrare all'utente cosa puo fare e incentivare upgrade.
    """
)
async def get_limits(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)
    limits = await service.get_download_limits(current_user.tier)
    return limits


@router.get(
    "/storage",
    response_model=StorageStatsSchema,
    summary="Statistiche storage",
    description="""
    Ritorna statistiche sull'uso dello storage per download.
    Include spazio usato, limite, e percentuale.
    """
)
async def get_storage_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    service = DownloadService(db)

    try:
        stats = await service.get_storage_stats(current_user.id)
        return stats
    except DownloadError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


# ==============================================================================
# ADMIN ENDPOINTS
# ==============================================================================

@router.post(
    "/admin/expire-check",
    summary="[Admin] Esegui check scadenza",
    description="""
    Esegue il job di check scadenza download.
    Normalmente eseguito da scheduler, disponibile per trigger manuale.
    Richiede permessi admin.
    """
)
async def admin_expire_check(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )

    service = DownloadService(db)
    result = await service.check_and_expire_downloads()
    return result

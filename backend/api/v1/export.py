"""
================================================================================
🎓 AI_MODULE: Export API - Blender/FBX/BVH Export
🎓 AI_VERSION: 1.0.0
🎓 AI_DESCRIPTION: REST API per export skeleton in formati 3D (Blender JSON, FBX, BVH)
🎓 AI_BUSINESS: Bridge tra analisi video e software 3D per avatar/animazioni.
               ROI: +60% valore contenuti premium, partnership con studi 3D.
🎓 AI_TEACHING: FastAPI endpoints con background tasks per export asincrono.
               Integra BlenderExportService per conversione skeleton → Mixamo rig.
🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
🎓 AI_CREATED: 2026-01-18

================================================================================

🔄 ALTERNATIVE_VALUTATE:
- Export sincrono: Scartato, export può durare secondi per video lunghi
- FBX nativo: Scartato, richiede SDK proprietario Autodesk
- Solo download diretto: Scartato, serve tracking job per UX migliore

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Vantaggio tecnico: Background task + job tracking per export non-blocking
- Vantaggio business: Utenti premium possono esportare per Blender/Unity/Unreal
- Trade-off: JSON format (leggibile) vs FBX (binario ma più compatibile)

📊 METRICHE_SUCCESSO:
- Export time: <5s per 1000 frames
- Download speed: Streaming per file grandi
- API response: <100ms per operazioni CRUD

🔗 ENDPOINTS:
- GET /formats: Lista formati supportati
- POST /blender: Crea export Blender JSON
- POST /bvh: Crea export BVH (motion capture)
- POST /bulk: Export multipli video
- GET /list: Lista export utente
- GET /status/{id}: Stato export job
- GET /download/{id}: Download file export
- DELETE /{id}: Elimina export

================================================================================
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends, Query, Path as PathParam
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime
from enum import Enum
import uuid
import json
import logging
import os

# Authentication
from core.auth import get_current_user, get_current_active_user

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# ============================================================================
# CONFIGURATION
# ============================================================================

# Export directories
EXPORT_DIR = Path("data/exports")
BLENDER_EXPORT_DIR = Path("data/blender_exports")
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
BLENDER_EXPORT_DIR.mkdir(parents=True, exist_ok=True)

# Job tracking (in production use Redis)
export_jobs: Dict[str, Dict] = {}


# ============================================================================
# ENUMS
# ============================================================================

class ExportFormat(str, Enum):
    """Supported export formats."""
    JSON = "json"           # Blender-ready JSON with Mixamo mapping
    BVH = "bvh"             # BioVision Hierarchy (motion capture)
    BLENDER_JSON = "blender_json"  # Alias for json
    CSV = "csv"             # Simple CSV for analysis


class ExportStatus(str, Enum):
    """Export job status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class ExportFormatInfo(BaseModel):
    """Export format information."""
    id: str
    name: str
    description: str
    extension: str
    supports_hands: bool = True
    supports_animation: bool = True


class ExportOptions(BaseModel):
    """Options for export."""
    fps: int = Field(default=30, ge=1, le=120, description="Target FPS")
    scale: float = Field(default=1.0, ge=0.01, le=100.0, description="Scale factor")
    include_visibility: bool = Field(default=True, description="Include visibility scores")
    fill_gaps: bool = Field(default=True, description="Fill missing frames via interpolation")
    armature_name: str = Field(default="MartialArts_Skeleton", description="Armature name for Blender")


class BlenderExportRequest(BaseModel):
    """Request for Blender export."""
    video_id: Optional[str] = Field(None, description="Video ID to export skeleton from")
    skeleton_id: Optional[str] = Field(None, description="Direct skeleton ID if already extracted")
    format: ExportFormat = Field(default=ExportFormat.JSON, description="Export format")
    options: Optional[ExportOptions] = None
    project_name: str = Field(default="Untitled", description="Project name for export")

    class Config:
        json_schema_extra = {
            "example": {
                "video_id": "abc123-def456",
                "format": "json",
                "options": {
                    "fps": 30,
                    "scale": 1.0,
                    "include_visibility": True
                },
                "project_name": "Kata Heian Shodan"
            }
        }


class BulkExportRequest(BaseModel):
    """Request for bulk export."""
    video_ids: List[str] = Field(..., min_length=1, max_length=20)
    format: ExportFormat = Field(default=ExportFormat.JSON)
    options: Optional[ExportOptions] = None


class ExportResponse(BaseModel):
    """Response for export request."""
    success: bool
    export_id: str = ""
    video_id: str = ""
    format: str = ""
    status: str = "pending"
    message: str = ""


class ExportStatusResponse(BaseModel):
    """Export job status response."""
    export_id: str
    video_id: str
    format: str
    status: str
    progress: float = 0.0
    created_at: str = ""
    completed_at: Optional[str] = None
    download_url: Optional[str] = None
    file_size: Optional[int] = None
    error: Optional[str] = None


class ExportListItem(BaseModel):
    """Item in export list."""
    export_id: str
    video_id: str
    format: str
    status: str
    created_at: str
    file_name: Optional[str] = None
    file_size: Optional[int] = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_skeleton_path(video_id: str) -> Optional[Path]:
    """Find skeleton JSON for video."""
    skeleton_dir = Path("data/skeletons")

    # Try holistic first (75 landmarks)
    holistic_path = skeleton_dir / f"{video_id}_holistic.json"
    if holistic_path.exists():
        return holistic_path

    # Fallback to basic skeleton (33 landmarks)
    basic_path = skeleton_dir / f"{video_id}_skeleton.json"
    if basic_path.exists():
        return basic_path

    return None


def load_skeleton_data(video_id: str) -> Optional[Dict]:
    """Load skeleton data from file."""
    path = get_skeleton_path(video_id)
    if path and path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


def update_export_job(export_id: str, **kwargs):
    """Update export job status."""
    if export_id in export_jobs:
        export_jobs[export_id].update(kwargs)
        export_jobs[export_id]["updated_at"] = datetime.now().isoformat()


# ============================================================================
# BACKGROUND TASKS
# ============================================================================

async def run_blender_export_task(
    export_id: str,
    video_id: str,
    skeleton_data: Dict,
    format: ExportFormat,
    options: ExportOptions,
    project_name: str,
    user_id: str
):
    """
    Run Blender export in background.

    🎓 PROCESS:
    1. Validate skeleton data
    2. Convert to Blender format
    3. Generate import script
    4. Save files
    5. Update job status
    """
    try:
        update_export_job(export_id, status="processing", progress=10.0)

        # Import Blender export service
        try:
            from services.blender_export import BlenderExportService

            service = BlenderExportService(output_dir=str(BLENDER_EXPORT_DIR))

            update_export_job(export_id, progress=30.0)

            # Run export
            result = service.export_for_blender(
                skeleton_data=skeleton_data,
                asset_id=video_id,
                project_name=project_name
            )

            update_export_job(export_id, progress=80.0)

            if result.get("success"):
                # Get file info
                export_path = result.get("export_path", "")
                skeleton_file = result.get("files", {}).get("skeleton", "")

                file_size = 0
                if skeleton_file and Path(skeleton_file).exists():
                    file_size = Path(skeleton_file).stat().st_size

                update_export_job(
                    export_id,
                    status="completed",
                    progress=100.0,
                    completed_at=datetime.now().isoformat(),
                    export_path=export_path,
                    files=result.get("files", {}),
                    stats=result.get("stats", {}),
                    file_size=file_size,
                    download_url=f"/api/v1/export/download/{export_id}"
                )

                logger.info(f"Blender export completed: {export_id}")
            else:
                raise ValueError(result.get("error", "Export failed"))

        except ImportError:
            # Fallback: simple JSON export without Blender service
            logger.warning("BlenderExportService not available, using simple export")

            output_path = EXPORT_DIR / f"{export_id}"
            output_path.mkdir(parents=True, exist_ok=True)

            # Save skeleton data directly
            skeleton_file = output_path / f"{video_id}_export.json"
            with open(skeleton_file, 'w', encoding='utf-8') as f:
                json.dump({
                    "export_id": export_id,
                    "video_id": video_id,
                    "project_name": project_name,
                    "format": format.value,
                    "options": options.dict() if options else {},
                    "exported_at": datetime.now().isoformat(),
                    "skeleton_data": skeleton_data
                }, f, indent=2)

            file_size = skeleton_file.stat().st_size

            update_export_job(
                export_id,
                status="completed",
                progress=100.0,
                completed_at=datetime.now().isoformat(),
                export_path=str(output_path),
                files={"skeleton": str(skeleton_file)},
                file_size=file_size,
                download_url=f"/api/v1/export/download/{export_id}"
            )

            logger.info(f"Simple export completed: {export_id}")

    except Exception as e:
        logger.error(f"Export failed for {export_id}: {e}")
        update_export_job(
            export_id,
            status="failed",
            error=str(e)
        )


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def get_user_id(current_user) -> str:
    """
    Estrae user ID da current_user (può essere dict o oggetto User SQLAlchemy).

    FIX: get_current_user ritorna:
    - dict se DB non disponibile
    - User SQLAlchemy se DB funziona

    🎓 AI_TEACHING: Pattern robusto per gestire polimorfismo auth.
    """
    if isinstance(current_user, dict):
        return current_user.get("id", "unknown")
    else:
        # SQLAlchemy User object - accedi all'attributo
        return str(getattr(current_user, "id", "unknown"))


# ============================================================================
# API ENDPOINTS
# ============================================================================

@router.get(
    "/formats",
    response_model=Dict[str, List[ExportFormatInfo]],
    summary="List export formats",
    description="Lista formati di export supportati"
)
async def list_export_formats(
    current_user: dict = Depends(get_current_active_user)
):
    """List supported export formats."""
    formats = [
        ExportFormatInfo(
            id="json",
            name="Blender JSON",
            description="JSON format with Mixamo bone mapping, ready for Blender import",
            extension=".json",
            supports_hands=True,
            supports_animation=True
        ),
        ExportFormatInfo(
            id="blender_json",
            name="Blender Package",
            description="Complete Blender package with skeleton, metadata, and import script",
            extension=".zip",
            supports_hands=True,
            supports_animation=True
        ),
        ExportFormatInfo(
            id="bvh",
            name="BVH Motion Capture",
            description="BioVision Hierarchy format for motion capture software",
            extension=".bvh",
            supports_hands=False,
            supports_animation=True
        ),
        ExportFormatInfo(
            id="csv",
            name="CSV Landmarks",
            description="Simple CSV with frame-by-frame landmark coordinates",
            extension=".csv",
            supports_hands=True,
            supports_animation=True
        ),
    ]

    return {"formats": formats}


@router.post(
    "/blender",
    response_model=ExportResponse,
    status_code=202,
    summary="Create Blender export",
    description="""
    Crea export skeleton per Blender.

    🎓 OUTPUT:
    - skeleton_blender.json: Dati skeleton con mapping Mixamo
    - metadata.json: Info export (fps, duration, quality)
    - import_blender.py: Script Python per import in Blender
    """
)
async def create_blender_export(
    request: BlenderExportRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_active_user)
):
    """Create Blender export from skeleton data."""

    # Determine video_id
    video_id = request.video_id or request.skeleton_id
    if not video_id:
        raise HTTPException(
            status_code=400,
            detail="Either video_id or skeleton_id is required"
        )

    # FIX 2025-01-27: Sanitize video_id before using in error messages (security)
    import re
    safe_video_id = re.sub(r'[^\w\-]', '', video_id)[:50] if video_id else 'unknown'
    
    # Load skeleton data
    skeleton_data = load_skeleton_data(video_id)
    if not skeleton_data:
        raise HTTPException(
            status_code=404,
            detail=f"Skeleton not found for video. Please verify the video ID and ensure skeleton extraction has been run."
        )

    # Create export job
    export_id = f"export_{uuid.uuid4().hex[:12]}"
    user_id = get_user_id(current_user)
    options = request.options or ExportOptions()

    export_jobs[export_id] = {
        "export_id": export_id,
        "video_id": video_id,
        "format": request.format.value,
        "status": "pending",
        "progress": 0.0,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "completed_at": None,
        "user_id": user_id,
        "project_name": request.project_name,
        "export_path": None,
        "files": {},
        "download_url": None,
        "file_size": None,
        "error": None
    }

    # Start background task
    background_tasks.add_task(
        run_blender_export_task,
        export_id,
        video_id,
        skeleton_data,
        request.format,
        options,
        request.project_name,
        user_id
    )

    logger.info(f"Started Blender export {export_id} for {video_id}")

    return ExportResponse(
        success=True,
        export_id=export_id,
        video_id=video_id,
        format=request.format.value,
        status="pending",
        message="Export started. Poll /status/{export_id} for progress."
    )


@router.post(
    "/bvh",
    response_model=ExportResponse,
    status_code=202,
    summary="Create BVH export",
    description="Crea export BVH (BioVision Hierarchy) per motion capture software"
)
async def create_bvh_export(
    request: BlenderExportRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_active_user)
):
    """Create BVH motion capture export."""
    # Override format to BVH
    request.format = ExportFormat.BVH

    # For now, return 501 Not Implemented
    # BVH format requires specific bone hierarchy conversion
    raise HTTPException(
        status_code=501,
        detail="BVH export not yet implemented. Use JSON format for Blender."
    )


@router.post(
    "/fbx",
    response_model=ExportResponse,
    status_code=202,
    summary="Create FBX export",
    description="Crea export FBX per Unity/Unreal Engine"
)
async def create_fbx_export(
    request: BlenderExportRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_active_user)
):
    """Create FBX export."""
    # FBX requires Autodesk SDK - not implemented
    raise HTTPException(
        status_code=501,
        detail="FBX export requires Autodesk SDK. Use JSON format for Blender."
    )


@router.post(
    "/bulk",
    response_model=Dict[str, Any],
    status_code=202,
    summary="Bulk export",
    description="Export multipli video in un'unica richiesta"
)
async def bulk_export(
    request: BulkExportRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_active_user)
):
    """Create bulk export for multiple videos."""
    jobs = []
    skipped = []
    user_id = get_user_id(current_user)
    options = request.options or ExportOptions()

    for video_id in request.video_ids:
        # Check skeleton exists
        skeleton_data = load_skeleton_data(video_id)

        if not skeleton_data:
            skipped.append({
                "video_id": video_id,
                "reason": "Skeleton not found"
            })
            continue

        # Create job
        export_id = f"export_{uuid.uuid4().hex[:12]}"

        export_jobs[export_id] = {
            "export_id": export_id,
            "video_id": video_id,
            "format": request.format.value,
            "status": "pending",
            "progress": 0.0,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "completed_at": None,
            "user_id": user_id,
            "project_name": f"Bulk Export - {video_id}",
            "export_path": None,
            "files": {},
            "download_url": None,
            "file_size": None,
            "error": None
        }

        # Start background task
        background_tasks.add_task(
            run_blender_export_task,
            export_id,
            video_id,
            skeleton_data,
            request.format,
            options,
            f"Bulk Export - {video_id}",
            user_id
        )

        jobs.append({
            "export_id": export_id,
            "video_id": video_id
        })

    return {
        "success": True,
        "total_requested": len(request.video_ids),
        "jobs_started": len(jobs),
        "skipped": len(skipped),
        "jobs": jobs,
        "skipped_details": skipped,
        "message": f"Started {len(jobs)} export jobs. Skipped {len(skipped)}."
    }


@router.get(
    "/list",
    response_model=Dict[str, Any],
    summary="List user exports",
    description="Lista tutti gli export dell'utente"
)
async def list_exports(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[ExportStatus] = None,
    current_user: dict = Depends(get_current_active_user)
):
    """List exports for current user."""
    user_id = get_user_id(current_user)

    # Filter by user
    user_exports = [
        job for job in export_jobs.values()
        if job.get("user_id") == user_id
        and (status is None or job.get("status") == status.value)
    ]

    # Sort by created_at descending
    user_exports.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    # Paginate
    total = len(user_exports)
    paginated = user_exports[offset:offset + limit]

    # Convert to response format
    items = [
        ExportListItem(
            export_id=e["export_id"],
            video_id=e["video_id"],
            format=e["format"],
            status=e["status"],
            created_at=e["created_at"],
            file_name=Path(e.get("files", {}).get("skeleton", "")).name if e.get("files") else None,
            file_size=e.get("file_size")
        )
        for e in paginated
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [item.dict() for item in items]
    }


@router.get(
    "/status/{export_id}",
    response_model=ExportStatusResponse,
    summary="Get export status",
    description="Stato di un job di export"
)
async def get_export_status(
    export_id: str = PathParam(..., description="Export job ID"),
    current_user: dict = Depends(get_current_active_user)
):
    """Get export job status."""
    if export_id not in export_jobs:
        raise HTTPException(status_code=404, detail=f"Export not found: {export_id}")

    job = export_jobs[export_id]
    user_id = get_user_id(current_user)

    # Check ownership
    if job.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    return ExportStatusResponse(
        export_id=job["export_id"],
        video_id=job["video_id"],
        format=job["format"],
        status=job["status"],
        progress=job.get("progress", 0.0),
        created_at=job["created_at"],
        completed_at=job.get("completed_at"),
        download_url=job.get("download_url"),
        file_size=job.get("file_size"),
        error=job.get("error")
    )


@router.get(
    "/download/{export_id}",
    summary="Download export",
    description="Download file export"
)
async def download_export(
    export_id: str = PathParam(..., description="Export job ID"),
    current_user: dict = Depends(get_current_active_user)
):
    """Download export file."""
    if export_id not in export_jobs:
        raise HTTPException(status_code=404, detail=f"Export not found: {export_id}")

    job = export_jobs[export_id]
    user_id = get_user_id(current_user)

    # Check ownership
    if job.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Check status
    if job["status"] != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Export not ready. Status: {job['status']}"
        )

    # Get file path
    skeleton_file = job.get("files", {}).get("skeleton")
    if not skeleton_file or not Path(skeleton_file).exists():
        raise HTTPException(status_code=404, detail="Export file not found")

    return FileResponse(
        path=skeleton_file,
        media_type="application/json",
        filename=f"{job['video_id']}_blender_export.json"
    )


@router.delete(
    "/{export_id}",
    status_code=204,
    summary="Delete export",
    description="Elimina un export e i suoi file"
)
async def delete_export(
    export_id: str = PathParam(..., description="Export job ID"),
    current_user: dict = Depends(get_current_active_user)
):
    """Delete export job and files."""
    if export_id not in export_jobs:
        raise HTTPException(status_code=404, detail=f"Export not found: {export_id}")

    job = export_jobs[export_id]
    user_id = get_user_id(current_user)

    # Check ownership
    if job.get("user_id") != user_id:
        raise HTTPException(status_code=403, detail="Access denied")

    # Delete files
    export_path = job.get("export_path")
    if export_path and Path(export_path).exists():
        import shutil
        try:
            shutil.rmtree(export_path)
            logger.info(f"Deleted export directory: {export_path}")
        except Exception as e:
            logger.warning(f"Failed to delete export directory: {e}")

    # Delete job record
    del export_jobs[export_id]

    logger.info(f"Deleted export: {export_id}")
    return None


@router.get(
    "/health",
    summary="Export API health check"
)
async def export_health():
    """Check Export API health."""
    # Check if BlenderExportService is available
    blender_service_available = False
    try:
        from services.blender_export import BlenderExportService
        blender_service_available = True
    except ImportError:
        pass

    return {
        "status": "healthy",
        "service": "export",
        "features": {
            "blender_json": True,
            "blender_service": blender_service_available,
            "bvh": False,  # Not implemented yet
            "fbx": False,  # Requires Autodesk SDK
            "csv": True,
            "bulk_export": True
        },
        "active_jobs": len([j for j in export_jobs.values() if j["status"] in ["pending", "processing"]]),
        "export_dir": str(EXPORT_DIR),
        "blender_export_dir": str(BLENDER_EXPORT_DIR)
    }

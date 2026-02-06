"""
🎓 AI_MODULE: Overlay API Endpoints
🎓 AI_DESCRIPTION: REST API per gestione annotazioni didattiche
🎓 AI_BUSINESS: Interfaccia per frontend editor overlay
🎓 AI_TEACHING: FastAPI router, dependency injection, async endpoints

📁 POSIZIONE: backend/api/v1/overlays.py
"""

from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from typing import List, Optional, Dict, Any
from pathlib import Path
import os

from services.overlay import (
    OverlayService,
    get_overlay_service,
    OverlayProject,
    RenderFrameRequest,
    RenderFrameResponse,
    AutoAnnotateRequest,
    AutoAnnotateResponse,
    AnnotationType,
    AnchorPoint,
)

router = APIRouter(tags=["Overlay Didattici"])


# ═══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY
# ═══════════════════════════════════════════════════════════════════════════════

async def get_service() -> OverlayService:
    """Dependency injection per OverlayService"""
    return get_overlay_service()


# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/projects", response_model=Dict[str, Any])
async def create_project(
    name: str,
    skeleton_id: Optional[str] = None,
    video_id: Optional[str] = None,
    width: int = 1920,
    height: int = 1080,
    description: Optional[str] = None,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Crea nuovo progetto overlay per annotare un video.
    
    📚 USAGE:
    POST /api/v1/overlays/projects?name=mio_progetto&skeleton_id=xxx
    """
    project = await service.create_project(
        name=name,
        skeleton_id=skeleton_id,
        video_id=video_id,
        width=width,
        height=height,
        description=description
    )
    
    return project.model_dump()


@router.get("/projects", response_model=List[Dict[str, Any]])
async def list_projects(
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Lista tutti i progetti overlay.
    """
    return await service.list_projects()


@router.get("/projects/{project_id}", response_model=Dict[str, Any])
async def get_project(
    project_id: str,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Recupera progetto con tutte le annotazioni.
    """
    project = await service.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return project.model_dump()


@router.put("/projects/{project_id}", response_model=Dict[str, Any])
async def update_project(
    project_id: str,
    data: Dict[str, Any],
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Aggiorna progetto (nome, descrizione, annotazioni).
    """
    project = await service.get_project(project_id)
    
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Aggiorna campi
    if "name" in data:
        project.name = data["name"]
    if "description" in data:
        project.description = data["description"]
    if "annotations" in data:
        project.annotations = data["annotations"]
    
    updated = await service.update_project(project)
    return updated.model_dump()


@router.delete("/projects/{project_id}")
async def delete_project(
    project_id: str,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Elimina progetto.
    """
    success = await service.delete_project(project_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"status": "deleted", "project_id": project_id}


# ═══════════════════════════════════════════════════════════════════════════════
# ANNOTATION ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/projects/{project_id}/annotations", response_model=Dict[str, str])
async def add_annotation(
    project_id: str,
    annotation: Dict[str, Any],
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Aggiunge annotazione a progetto.
    
    📚 BODY EXAMPLE (angle):
    {
        "type": "angle",
        "frame_index": 0,
        "point_a": "left_shoulder",
        "vertex": "left_elbow",
        "point_b": "left_wrist",
        "show_degrees": true
    }
    """
    annotation_id = await service.add_annotation(project_id, annotation)
    
    if not annotation_id:
        raise HTTPException(status_code=404, detail="Project not found")
    
    return {"annotation_id": annotation_id}


@router.put("/projects/{project_id}/annotations/{annotation_id}")
async def update_annotation(
    project_id: str,
    annotation_id: str,
    annotation: Dict[str, Any],
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Aggiorna annotazione esistente.
    """
    success = await service.update_annotation(project_id, annotation_id, annotation)
    
    if not success:
        raise HTTPException(status_code=404, detail="Annotation not found")
    
    return {"status": "updated"}


@router.delete("/projects/{project_id}/annotations/{annotation_id}")
async def delete_annotation(
    project_id: str,
    annotation_id: str,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Rimuove annotazione.
    """
    success = await service.delete_annotation(project_id, annotation_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="Annotation not found")
    
    return {"status": "deleted"}


# ═══════════════════════════════════════════════════════════════════════════════
# RENDER ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/render/frame", response_model=RenderFrameResponse)
async def render_frame(
    request: RenderFrameRequest,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Renderizza singolo frame con annotazioni.
    
    📚 USAGE: Preview real-time nell'editor.
    
    📚 BODY:
    {
        "skeleton_id": "xxx",
        "frame_index": 42,
        "annotations": [...],
        "include_skeleton": true,
        "include_video_frame": true
    }
    """
    return await service.render_frame(request)


@router.get("/frames/{filename}")
async def get_rendered_frame(filename: str):
    """
    🎯 BUSINESS: Serve frame renderizzato.
    """
    # Determina storage path
    storage_path = Path("./storage/overlays/frames")
    file_path = storage_path / filename
    
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Frame not found")
    
    # Determina media type
    ext = file_path.suffix.lower()
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".webp": "image/webp"
    }
    media_type = media_types.get(ext, "image/png")
    
    return FileResponse(file_path, media_type=media_type)


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-ANNOTATE
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/auto-annotate", response_model=AutoAnnotateResponse)
async def auto_annotate(
    request: AutoAnnotateRequest,
    service: OverlayService = Depends(get_service)
):
    """
    🎯 BUSINESS: Genera annotazioni automatiche basate su skeleton.
    
    📚 USAGE: Utente clicca "Auto-rileva" e ottiene suggerimenti.
    
    📚 BODY:
    {
        "skeleton_id": "xxx",
        "frame_index": 0,
        "detect_angles": true,
        "detect_key_points": false
    }
    """
    return await service.auto_annotate(request)


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS INFO (per frontend)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/types")
async def get_annotation_types():
    """
    🎯 BUSINESS: Lista tipi annotazione disponibili (per dropdown frontend).
    """
    return {
        "annotation_types": [t.value for t in AnnotationType],
        "anchor_points": [a.value for a in AnchorPoint]
    }


@router.get("/joint-angles")
async def get_common_joint_angles():
    """
    🎯 BUSINESS: Lista angoli articolazioni comuni.
    """
    from services.overlay.schemas import COMMON_JOINT_ANGLES
    
    return [
        {
            "name": name,
            "point_a": a.value,
            "vertex": v.value,
            "point_b": b.value
        }
        for name, a, v, b in COMMON_JOINT_ANGLES
    ]

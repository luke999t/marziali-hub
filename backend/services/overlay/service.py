"""
🎓 AI_MODULE: Overlay Service
🎓 AI_DESCRIPTION: Service principale per gestione annotazioni didattiche
🎓 AI_BUSINESS: Coordina rendering, storage, auto-annotazione
🎓 AI_TEACHING: Service layer pattern, async I/O, integrazione skeleton service

📁 POSIZIONE: backend/services/overlay/service.py
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid
import cv2
import numpy as np

from .schemas import (
    AnnotationType, AnchorPoint, Annotation,
    OverlayProject, ColorRGBA,
    RenderFrameRequest, RenderFrameResponse,
    RenderVideoRequest, RenderVideoResponse,
    AutoAnnotateRequest, AutoAnnotateResponse,
    AngleAnnotation, TextAnnotation, HighlightAnnotation,
    COMMON_JOINT_ANGLES
)
from .calculator import OverlayCalculator
from .renderer import OverlayRenderer


class OverlayService:
    """
    🎓 AI_MODULE: Overlay Service
    
    Responsabilità:
    - CRUD progetti overlay
    - Rendering frame singoli e batch
    - Auto-generazione annotazioni
    - Export video con overlay
    """
    
    def __init__(
        self,
        storage_path: str = "./storage/overlays",
        skeleton_service: Any = None  # Injection del skeleton service
    ):
        """
        Args:
            storage_path: Path per salvare progetti e output
            skeleton_service: Reference al SkeletonService per accesso landmarks
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Sottocartelle
        (self.storage_path / "projects").mkdir(exist_ok=True)
        (self.storage_path / "frames").mkdir(exist_ok=True)
        (self.storage_path / "videos").mkdir(exist_ok=True)
        
        self.skeleton_service = skeleton_service
        
        # Cache renderer per dimensioni diverse
        self._renderers: Dict[tuple, OverlayRenderer] = {}
        
        # Projects in memoria (cache)
        self._projects_cache: Dict[str, OverlayProject] = {}
    
    def _get_renderer(self, width: int, height: int) -> OverlayRenderer:
        """Ottiene renderer per dimensioni specifiche (con caching)"""
        key = (width, height)
        if key not in self._renderers:
            self._renderers[key] = OverlayRenderer(width, height)
        return self._renderers[key]
    
    # ═══════════════════════════════════════════════════════════════════════════
    # PROJECT CRUD
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def create_project(
        self,
        name: str,
        skeleton_id: Optional[str] = None,
        video_id: Optional[str] = None,
        width: int = 1920,
        height: int = 1080,
        description: Optional[str] = None
    ) -> OverlayProject:
        """
        Crea nuovo progetto overlay.
        """
        project = OverlayProject(
            name=name,
            description=description,
            skeleton_id=skeleton_id,
            video_id=video_id,
            width=width,
            height=height
        )
        
        # Salva su disco
        await self._save_project(project)
        
        # Cache
        self._projects_cache[project.id] = project
        
        return project
    
    async def get_project(self, project_id: str) -> Optional[OverlayProject]:
        """
        Recupera progetto per ID.
        """
        # Check cache
        if project_id in self._projects_cache:
            return self._projects_cache[project_id]
        
        # Carica da disco
        project = await self._load_project(project_id)
        
        if project:
            self._projects_cache[project_id] = project
        
        return project
    
    async def update_project(self, project: OverlayProject) -> OverlayProject:
        """
        Aggiorna progetto esistente.
        """
        project.updated_at = datetime.utcnow()
        await self._save_project(project)
        self._projects_cache[project.id] = project
        return project
    
    async def delete_project(self, project_id: str) -> bool:
        """
        Elimina progetto.
        """
        project_path = self.storage_path / "projects" / f"{project_id}.json"
        
        if project_path.exists():
            project_path.unlink()
            self._projects_cache.pop(project_id, None)
            return True
        
        return False
    
    async def list_projects(self) -> List[Dict[str, Any]]:
        """
        Lista tutti i progetti (solo metadata, non annotazioni complete).
        """
        projects = []
        projects_dir = self.storage_path / "projects"
        
        for path in projects_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding='utf-8'))
                projects.append({
                    "id": data.get("id"),
                    "name": data.get("name"),
                    "description": data.get("description"),
                    "skeleton_id": data.get("skeleton_id"),
                    "video_id": data.get("video_id"),
                    "annotations_count": len(data.get("annotations", [])),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at")
                })
            except Exception as e:
                print(f"[OverlayService] Error reading project {path}: {e}")
        
        return sorted(projects, key=lambda p: p.get("updated_at", ""), reverse=True)
    
    async def _save_project(self, project: OverlayProject):
        """Salva progetto su disco"""
        path = self.storage_path / "projects" / f"{project.id}.json"
        path.write_text(
            project.model_dump_json(indent=2),
            encoding='utf-8'
        )
    
    async def _load_project(self, project_id: str) -> Optional[OverlayProject]:
        """Carica progetto da disco"""
        path = self.storage_path / "projects" / f"{project_id}.json"
        
        if not path.exists():
            return None
        
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
            return OverlayProject(**data)
        except Exception as e:
            print(f"[OverlayService] Error loading project {project_id}: {e}")
            return None
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ANNOTATION MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def add_annotation(
        self,
        project_id: str,
        annotation_data: Dict[str, Any]
    ) -> Optional[str]:
        """
        Aggiunge annotazione a progetto.
        
        Returns:
            ID annotazione creata o None se errore
        """
        project = await self.get_project(project_id)
        if not project:
            return None
        
        # Genera ID se mancante
        if "id" not in annotation_data:
            annotation_data["id"] = str(uuid.uuid4())
        
        project.annotations.append(annotation_data)
        await self.update_project(project)
        
        return annotation_data["id"]
    
    async def update_annotation(
        self,
        project_id: str,
        annotation_id: str,
        annotation_data: Dict[str, Any]
    ) -> bool:
        """
        Aggiorna annotazione esistente.
        """
        project = await self.get_project(project_id)
        if not project:
            return False
        
        for i, ann in enumerate(project.annotations):
            if ann.get("id") == annotation_id or (hasattr(ann, 'id') and ann.id == annotation_id):
                annotation_data["id"] = annotation_id
                project.annotations[i] = annotation_data
                await self.update_project(project)
                return True
        
        return False
    
    async def delete_annotation(
        self,
        project_id: str,
        annotation_id: str
    ) -> bool:
        """
        Rimuove annotazione da progetto.
        """
        project = await self.get_project(project_id)
        if not project:
            return False
        
        original_count = len(project.annotations)
        project.annotations = [
            ann for ann in project.annotations
            if ann.get("id") != annotation_id and 
               (not hasattr(ann, 'id') or ann.id != annotation_id)
        ]
        
        if len(project.annotations) < original_count:
            await self.update_project(project)
            return True
        
        return False
    
    # ═══════════════════════════════════════════════════════════════════════════
    # FRAME RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def render_frame(
        self,
        request: RenderFrameRequest
    ) -> RenderFrameResponse:
        """
        Renderizza singolo frame con annotazioni.
        
        🎓 AI_BUSINESS: Endpoint principale per preview real-time nell'editor.
        """
        start_time = time.time()
        
        # Ottieni landmarks dallo skeleton service
        landmarks = await self._get_frame_landmarks(
            request.skeleton_id, request.frame_index
        )
        
        # Ottieni frame video se richiesto
        if request.include_video_frame:
            background = await self._get_video_frame(
                request.skeleton_id, request.frame_index
            )
        else:
            # Frame nero
            w = request.width or 1920
            h = request.height or 1080
            background = np.zeros((h, w, 3), dtype=np.uint8)
        
        h, w = background.shape[:2]
        
        # Renderer
        renderer = self._get_renderer(w, h)
        
        # Converti dict a Annotation objects
        annotations = self._parse_annotations(request.annotations)
        
        # Disegna skeleton se richiesto
        if request.include_skeleton and landmarks:
            overlay = np.zeros((h, w, 4), dtype=np.uint8)
            renderer.render_skeleton(overlay, landmarks)
            background = cv2.cvtColor(background, cv2.COLOR_BGR2BGRA)
            background = renderer._alpha_blend(background, overlay)
            background = cv2.cvtColor(background, cv2.COLOR_BGRA2BGR)
        
        # Renderizza annotazioni
        result = renderer.render_annotations(background, annotations, landmarks)
        
        # Salva immagine
        output_filename = f"{request.skeleton_id}_{request.frame_index}_{uuid.uuid4().hex[:8]}.{request.output_format}"
        output_path = self.storage_path / "frames" / output_filename
        
        encode_params = []
        if request.output_format == "jpg":
            encode_params = [cv2.IMWRITE_JPEG_QUALITY, request.quality]
        elif request.output_format == "png":
            encode_params = [cv2.IMWRITE_PNG_COMPRESSION, 9 - (request.quality // 12)]
        elif request.output_format == "webp":
            encode_params = [cv2.IMWRITE_WEBP_QUALITY, request.quality]
        
        cv2.imwrite(str(output_path), result, encode_params)
        
        render_time = (time.time() - start_time) * 1000
        
        return RenderFrameResponse(
            image_url=f"/api/v1/overlays/frames/{output_filename}",
            width=w,
            height=h,
            frame_index=request.frame_index,
            annotations_count=len(annotations),
            render_time_ms=round(render_time, 2)
        )
    
    def _parse_annotations(self, annotations_data: List[Dict[str, Any]]) -> List[Any]:
        """
        Converte dict in Annotation objects tipizzati.
        """
        parsed = []
        
        for data in annotations_data:
            ann_type = data.get("type", "")
            
            try:
                if ann_type == AnnotationType.ANGLE.value:
                    parsed.append(AngleAnnotation(**data))
                elif ann_type == AnnotationType.TEXT.value:
                    parsed.append(TextAnnotation(**data))
                elif ann_type == AnnotationType.HIGHLIGHT.value:
                    parsed.append(HighlightAnnotation(**data))
                # ... altri tipi
                else:
                    # Fallback: usa raw dict (renderer gestisce)
                    parsed.append(data)
            except Exception as e:
                print(f"[OverlayService] Error parsing annotation: {e}")
                parsed.append(data)
        
        return parsed
    
    async def _get_frame_landmarks(
        self,
        skeleton_id: str,
        frame_index: int
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Ottiene landmarks da skeleton service.
        
        🎓 AI_TEACHING: Decoupling - service non sa come sono salvati i dati.
        """
        if not self.skeleton_service:
            return None
        
        try:
            # Assumiamo che skeleton_service abbia questo metodo
            skeleton = await self.skeleton_service.get_skeleton(skeleton_id)
            
            if not skeleton or not skeleton.get("frames"):
                return None
            
            frames = skeleton["frames"]
            
            if frame_index < 0 or frame_index >= len(frames):
                return None
            
            return frames[frame_index].get("landmarks", [])
        except Exception as e:
            print(f"[OverlayService] Error getting landmarks: {e}")
            return None
    
    async def _get_video_frame(
        self,
        skeleton_id: str,
        frame_index: int
    ) -> np.ndarray:
        """
        Ottiene frame video originale.
        """
        # TODO: Implementare recupero frame da video
        # Per ora ritorna frame nero 1920x1080
        return np.zeros((1080, 1920, 3), dtype=np.uint8)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # AUTO-ANNOTATE
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def auto_annotate(
        self,
        request: AutoAnnotateRequest
    ) -> AutoAnnotateResponse:
        """
        Genera automaticamente annotazioni basate su skeleton.
        
        🎓 AI_BUSINESS: Risparmia tempo all'utente, suggerisce punti chiave.
        """
        landmarks = await self._get_frame_landmarks(
            request.skeleton_id, request.frame_index
        )
        
        if not landmarks:
            return AutoAnnotateResponse(annotations=[], detected_angles={})
        
        annotations = []
        detected_angles = {}
        
        calculator = OverlayCalculator()
        
        # Rileva angoli articolazioni
        if request.detect_angles:
            for name, anchor_a, anchor_v, anchor_b in COMMON_JOINT_ANGLES:
                angle = calculator.calculate_angle_from_landmarks(
                    landmarks, anchor_a, anchor_v, anchor_b
                )
                
                if angle is not None:
                    detected_angles[name] = round(angle, 1)
                    
                    # Crea annotazione angolo
                    annotations.append({
                        "id": str(uuid.uuid4()),
                        "type": AnnotationType.ANGLE.value,
                        "frame_index": request.frame_index,
                        "point_a": anchor_a.value,
                        "vertex": anchor_v.value,
                        "point_b": anchor_b.value,
                        "show_degrees": True,
                        "arc_radius": 35,
                        "color": {"r": 255, "g": 165, "b": 0, "a": 1.0},
                        "label": name.replace("_", " ").title()
                    })
        
        # Rileva punti chiave
        if request.detect_key_points:
            key_anchors = [
                AnchorPoint.LEFT_WRIST, AnchorPoint.RIGHT_WRIST,
                AnchorPoint.LEFT_ANKLE, AnchorPoint.RIGHT_ANKLE
            ]
            
            for anchor in key_anchors:
                pos = calculator.get_landmark_position(landmarks, anchor)
                
                if pos:
                    annotations.append({
                        "id": str(uuid.uuid4()),
                        "type": AnnotationType.HIGHLIGHT.value,
                        "frame_index": request.frame_index,
                        "anchor": anchor.value,
                        "shape": "circle",
                        "radius": 20,
                        "filled": False,
                        "color": {"r": 0, "g": 255, "b": 255, "a": 0.8}
                    })
        
        return AutoAnnotateResponse(
            annotations=annotations,
            detected_angles=detected_angles
        )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # VIDEO RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    async def render_video(
        self,
        request: RenderVideoRequest
    ) -> RenderVideoResponse:
        """
        Avvia job per rendering video completo con overlay.
        
        🎓 AI_TEACHING: Operazione lunga → job asincrono.
        """
        job_id = str(uuid.uuid4())
        
        # TODO: Implementare job queue per rendering video
        # Per ora ritorna placeholder
        
        return RenderVideoResponse(
            job_id=job_id,
            status="queued",
            video_url=None,
            progress=0.0,
            total_frames=0
        )


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

_overlay_service: Optional[OverlayService] = None


def get_overlay_service(
    storage_path: str = "./storage/overlays",
    skeleton_service: Any = None
) -> OverlayService:
    """
    Factory per OverlayService (singleton pattern).
    """
    global _overlay_service
    
    if _overlay_service is None:
        _overlay_service = OverlayService(storage_path, skeleton_service)
    
    return _overlay_service

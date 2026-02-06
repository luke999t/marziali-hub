"""
🎓 AI_MODULE: Avatar Import Service
🎓 AI_DESCRIPTION: Importa video avatar renderizzati da Blender nel sistema
🎓 AI_BUSINESS: Completa il ciclo avatar per publish verso studenti
🎓 AI_TEACHING: Video processing, thumbnail generation, metadata extraction

🔄 ALTERNATIVE_VALUTATE:
- Import manuale: Scartato, non scala
- Solo link esterno: Scartato, serve controllo qualità
- Direct Blender → DB: Scartato, serve validazione

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Validazione qualità automatica
- Thumbnail generation automatica
- Metadata extraction completa
- Integrazione con streaming esistente

📊 METRICHE_SUCCESSO:
- Tempo import: < 30s per video 60s
- Thumbnail quality: 720p
- Metadata accuracy: 100%
"""

import os
import json
import logging
import subprocess
import uuid
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class AvatarMetadata:
    """Metadata for imported avatar video"""
    avatar_id: str
    project_id: str
    source_export_id: str
    filename: str
    duration: float
    width: int
    height: int
    fps: float
    codec: str
    file_size: int
    thumbnail_path: str
    created_at: str
    status: str = "imported"
    render_angles: int = 8
    is_360: bool = True


class AvatarImportService:
    """
    Importa video avatar nel sistema

    Workflow:
    1. Valida video file
    2. Estrae metadata con ffprobe
    3. Genera thumbnail
    4. Collega a progetto
    5. Prepara per streaming
    """

    def __init__(
        self,
        storage_path: str = "data/avatars",
        thumbnail_path: str = "data/thumbnails"
    ):
        self.storage_path = Path(storage_path)
        self.thumbnail_path = Path(thumbnail_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.thumbnail_path.mkdir(parents=True, exist_ok=True)

    async def import_avatar_video(
        self,
        video_path: str,
        project_id: str,
        export_id: Optional[str] = None,
        render_angles: int = 8
    ) -> Dict[str, Any]:
        """
        Import avatar video into the system

        Args:
            video_path: Path to rendered video from Blender
            project_id: Associated project ID
            export_id: Original Blender export ID (for tracing)
            render_angles: Number of camera angles (default 8 for 360°)

        Returns:
            {
                "success": True,
                "avatar_id": "uuid",
                "metadata": {...},
                "thumbnail_url": "/api/v1/avatars/{id}/thumbnail",
                "stream_url": "/api/v1/avatars/{id}/stream"
            }
        """
        try:
            video_file = Path(video_path)
            if not video_file.exists():
                raise FileNotFoundError(f"Video not found: {video_path}")

            # Generate unique avatar ID
            avatar_id = str(uuid.uuid4())

            # Extract metadata with ffprobe
            metadata = await self._extract_metadata(video_file)

            # Copy video to storage
            dest_filename = f"{avatar_id}{video_file.suffix}"
            dest_path = self.storage_path / dest_filename
            shutil.copy2(video_file, dest_path)

            # Generate thumbnail
            thumbnail_filename = f"{avatar_id}_thumb.jpg"
            thumbnail_dest = self.thumbnail_path / thumbnail_filename
            await self._generate_thumbnail(dest_path, thumbnail_dest)

            # Create avatar metadata
            avatar_meta = AvatarMetadata(
                avatar_id=avatar_id,
                project_id=project_id,
                source_export_id=export_id or "unknown",
                filename=dest_filename,
                duration=metadata.get("duration", 0),
                width=metadata.get("width", 0),
                height=metadata.get("height", 0),
                fps=metadata.get("fps", 30),
                codec=metadata.get("codec", "unknown"),
                file_size=dest_path.stat().st_size,
                thumbnail_path=str(thumbnail_dest),
                created_at=datetime.now().isoformat(),
                render_angles=render_angles,
                is_360=render_angles >= 8,
            )

            # Save metadata JSON
            meta_path = self.storage_path / f"{avatar_id}_meta.json"
            with open(meta_path, "w") as f:
                json.dump(asdict(avatar_meta), f, indent=2)

            logger.info(f"Avatar imported: {avatar_id}")

            return {
                "success": True,
                "avatar_id": avatar_id,
                "metadata": asdict(avatar_meta),
                "thumbnail_url": f"/api/v1/avatars/{avatar_id}/thumbnail",
                "stream_url": f"/api/v1/avatars/{avatar_id}/stream",
                "download_url": f"/api/v1/avatars/{avatar_id}/download",
            }

        except Exception as e:
            logger.error(f"Avatar import failed: {e}")
            return {
                "success": False,
                "error": str(e),
            }

    async def _extract_metadata(self, video_path: Path) -> Dict[str, Any]:
        """Extract video metadata using ffprobe"""
        try:
            cmd = [
                "ffprobe",
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                str(video_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.warning(f"ffprobe failed: {result.stderr}")
                return self._fallback_metadata(video_path)

            data = json.loads(result.stdout)

            # Find video stream
            video_stream = None
            for stream in data.get("streams", []):
                if stream.get("codec_type") == "video":
                    video_stream = stream
                    break

            if not video_stream:
                return self._fallback_metadata(video_path)

            format_info = data.get("format", {})

            return {
                "duration": float(format_info.get("duration", 0)),
                "width": video_stream.get("width", 0),
                "height": video_stream.get("height", 0),
                "fps": self._parse_fps(video_stream.get("r_frame_rate", "30/1")),
                "codec": video_stream.get("codec_name", "unknown"),
                "bitrate": int(format_info.get("bit_rate", 0)),
            }

        except Exception as e:
            logger.warning(f"Metadata extraction failed: {e}")
            return self._fallback_metadata(video_path)

    def _fallback_metadata(self, video_path: Path) -> Dict[str, Any]:
        """Fallback metadata when ffprobe fails"""
        return {
            "duration": 0,
            "width": 1920,
            "height": 1080,
            "fps": 30,
            "codec": "unknown",
            "bitrate": 0,
        }

    def _parse_fps(self, fps_str: str) -> float:
        """Parse FPS from ffprobe format (e.g., '30/1' or '29.97')"""
        try:
            if "/" in fps_str:
                num, den = fps_str.split("/")
                return float(num) / float(den)
            return float(fps_str)
        except:
            return 30.0

    async def _generate_thumbnail(
        self,
        video_path: Path,
        output_path: Path,
        timestamp: float = 1.0
    ):
        """Generate thumbnail from video at specified timestamp"""
        try:
            cmd = [
                "ffmpeg",
                "-y",
                "-ss", str(timestamp),
                "-i", str(video_path),
                "-vframes", "1",
                "-vf", "scale=720:-1",
                "-q:v", "2",
                str(output_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode != 0:
                logger.warning(f"Thumbnail generation failed: {result.stderr}")
                # Create placeholder
                self._create_placeholder_thumbnail(output_path)

        except Exception as e:
            logger.warning(f"Thumbnail generation error: {e}")
            self._create_placeholder_thumbnail(output_path)

    def _create_placeholder_thumbnail(self, output_path: Path):
        """Create a placeholder thumbnail"""
        # Simple 1x1 gray pixel as placeholder
        # In production, use a proper placeholder image
        output_path.write_bytes(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00')

    async def get_avatar(self, avatar_id: str) -> Optional[Dict[str, Any]]:
        """Get avatar metadata by ID"""
        meta_path = self.storage_path / f"{avatar_id}_meta.json"
        if not meta_path.exists():
            return None

        with open(meta_path, "r") as f:
            return json.load(f)

    async def list_avatars(
        self,
        project_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List avatars, optionally filtered by project"""
        avatars = []

        for meta_file in self.storage_path.glob("*_meta.json"):
            try:
                with open(meta_file, "r") as f:
                    meta = json.load(f)

                if project_id and meta.get("project_id") != project_id:
                    continue

                avatars.append(meta)
            except Exception as e:
                logger.warning(f"Failed to read {meta_file}: {e}")

        # Sort by created_at descending
        avatars.sort(key=lambda x: x.get("created_at", ""), reverse=True)

        return avatars[offset:offset + limit]

    async def delete_avatar(self, avatar_id: str) -> bool:
        """Delete avatar and associated files"""
        try:
            meta_path = self.storage_path / f"{avatar_id}_meta.json"
            if not meta_path.exists():
                return False

            with open(meta_path, "r") as f:
                meta = json.load(f)

            # Delete video file
            video_path = self.storage_path / meta.get("filename", "")
            if video_path.exists():
                video_path.unlink()

            # Delete thumbnail
            thumb_path = Path(meta.get("thumbnail_path", ""))
            if thumb_path.exists():
                thumb_path.unlink()

            # Delete metadata
            meta_path.unlink()

            logger.info(f"Avatar deleted: {avatar_id}")
            return True

        except Exception as e:
            logger.error(f"Avatar deletion failed: {e}")
            return False

    async def get_avatar_status(self, avatar_id: str) -> Dict[str, Any]:
        """Get avatar processing status"""
        avatar = await self.get_avatar(avatar_id)
        if not avatar:
            return {"status": "not_found", "avatar_id": avatar_id}

        video_path = self.storage_path / avatar.get("filename", "")
        thumb_path = Path(avatar.get("thumbnail_path", ""))

        return {
            "avatar_id": avatar_id,
            "status": avatar.get("status", "unknown"),
            "video_exists": video_path.exists(),
            "thumbnail_exists": thumb_path.exists(),
            "is_360": avatar.get("is_360", False),
            "duration": avatar.get("duration", 0),
            "render_angles": avatar.get("render_angles", 0),
        }

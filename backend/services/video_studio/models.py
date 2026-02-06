"""
Database Models for Video Studio
SQLAlchemy models for maestri projects, videos, and skeleton data
"""

from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field
from pathlib import Path
import json


# Enums

class MartialArtStyle(str, Enum):
    """Martial art styles"""
    TAI_CHI = "tai_chi"
    KUNG_FU = "kung_fu"
    KARATE = "karate"
    JUDO = "judo"
    BJJ = "bjj"
    KRAV_MAGA = "krav_maga"
    MUAY_THAI = "muay_thai"
    TAEKWONDO = "taekwondo"
    AIKIDO = "aikido"
    WING_CHUN = "wing_chun"
    OTHER = "other"


class VideoStatus(str, Enum):
    """Video processing status"""
    UPLOADED = "uploaded"
    VALIDATING = "validating"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ProjectStatus(str, Enum):
    """Project status"""
    DRAFT = "draft"
    ACTIVE = "active"
    PROCESSING = "processing"
    COMPLETED = "completed"
    ARCHIVED = "archived"


# Pydantic Models

class MaestroInfo(BaseModel):
    """Maestro information"""
    name: str = Field(..., description="Maestro name")
    style: MartialArtStyle = Field(..., description="Primary martial art style")
    experience_years: Optional[int] = Field(None, description="Years of experience")
    certification: Optional[str] = Field(None, description="Certification/rank")
    bio: Optional[str] = Field(None, description="Biography")
    photo_url: Optional[str] = Field(None, description="Photo URL")


class VideoMetadata(BaseModel):
    """Video file metadata"""
    filename: str
    filepath: str
    size_bytes: int
    duration_seconds: float
    width: int
    height: int
    fps: float
    total_frames: int
    codec: Optional[str] = None
    bitrate: Optional[int] = None
    uploaded_at: datetime = Field(default_factory=datetime.now)


class SkeletonData(BaseModel):
    """Skeleton extraction data"""
    skeleton_filepath: str
    total_landmarks: int = 75
    frames_processed: int
    detection_rates: dict  # body, left_hand, right_hand
    avg_confidence: float
    quality_assessment: str
    processing_time_seconds: float
    extracted_at: datetime = Field(default_factory=datetime.now)


class VideoItem(BaseModel):
    """Single video item in a project"""
    id: str
    project_id: str
    maestro: MaestroInfo
    metadata: VideoMetadata
    skeleton: Optional[SkeletonData] = None
    status: VideoStatus = VideoStatus.UPLOADED
    status_message: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class Project(BaseModel):
    """Maestri video project"""
    id: str
    name: str
    description: Optional[str] = None
    style: MartialArtStyle
    videos: List[VideoItem] = Field(default_factory=list)
    status: ProjectStatus = ProjectStatus.DRAFT
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)

    def add_video(self, video: VideoItem):
        """Add video to project"""
        self.videos.append(video)
        self.updated_at = datetime.now()

    def get_video(self, video_id: str) -> Optional[VideoItem]:
        """Get video by ID"""
        for video in self.videos:
            if video.id == video_id:
                return video
        return None

    def update_video_status(self, video_id: str, status: VideoStatus, message: Optional[str] = None):
        """Update video processing status"""
        video = self.get_video(video_id)
        if video:
            video.status = status
            video.status_message = message
            video.updated_at = datetime.now()
            self.updated_at = datetime.now()

    def get_statistics(self) -> dict:
        """Get project statistics"""
        total_videos = len(self.videos)
        completed = sum(1 for v in self.videos if v.status == VideoStatus.COMPLETED)
        failed = sum(1 for v in self.videos if v.status == VideoStatus.FAILED)
        processing = sum(1 for v in self.videos if v.status == VideoStatus.PROCESSING)

        total_duration = sum(v.metadata.duration_seconds for v in self.videos)
        total_frames = sum(v.metadata.total_frames for v in self.videos)

        return {
            "total_videos": total_videos,
            "completed": completed,
            "failed": failed,
            "processing": processing,
            "pending": total_videos - completed - failed - processing,
            "completion_rate": completed / total_videos if total_videos > 0 else 0,
            "total_duration_seconds": total_duration,
            "total_frames": total_frames
        }


# Storage Manager

class ProjectStorage:
    """File-based project storage (for MVP, replace with database later)"""

    def __init__(self, storage_dir: str = "./projects"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_project_file(self, project_id: str) -> Path:
        """Get project file path"""
        return self.storage_dir / f"{project_id}.json"

    def save_project(self, project: Project):
        """Save project to file"""
        filepath = self._get_project_file(project.id)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(project.model_dump(), f, indent=2, default=str)

    def load_project(self, project_id: str) -> Optional[Project]:
        """Load project from file"""
        filepath = self._get_project_file(project_id)
        if not filepath.exists():
            return None

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return Project(**data)

    def list_projects(self) -> List[Project]:
        """List all projects"""
        projects = []
        for filepath in self.storage_dir.glob("*.json"):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    projects.append(Project(**data))
            except Exception as e:
                print(f"Error loading project {filepath}: {e}")
        return projects

    def delete_project(self, project_id: str) -> bool:
        """Delete project"""
        filepath = self._get_project_file(project_id)
        if filepath.exists():
            filepath.unlink()
            return True
        return False


# Example usage
if __name__ == '__main__':
    # Create storage
    storage = ProjectStorage()

    # Create project
    project = Project(
        id="proj_001",
        name="Tai Chi Chen Style - Laojia Yilu",
        description="Project for analyzing Tai Chi Chen style first form",
        style=MartialArtStyle.TAI_CHI,
        created_by="staff_user_1"
    )

    # Create maestro
    maestro = MaestroInfo(
        name="Master Chen",
        style=MartialArtStyle.TAI_CHI,
        experience_years=30,
        certification="19th Generation Chen Family",
        bio="Master of Chen Style Tai Chi"
    )

    # Create video metadata
    video_meta = VideoMetadata(
        filename="chen_laojia_demo.mp4",
        filepath="/uploads/chen_laojia_demo.mp4",
        size_bytes=50_000_000,
        duration_seconds=120.0,
        width=1920,
        height=1080,
        fps=30.0,
        total_frames=3600
    )

    # Create video item
    video = VideoItem(
        id="vid_001",
        project_id=project.id,
        maestro=maestro,
        metadata=video_meta,
        tags=["demo", "laojia", "complete_form"]
    )

    # Add video to project
    project.add_video(video)

    # Save project
    storage.save_project(project)
    print(f"Project saved: {project.id}")

    # Load project
    loaded = storage.load_project(project.id)
    print(f"Project loaded: {loaded.name}")
    print(f"Videos: {len(loaded.videos)}")
    print(f"Statistics: {loaded.get_statistics()}")

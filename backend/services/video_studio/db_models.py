from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
import uuid

class DBProject(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    style = Column(String, nullable=False, index=True)
    status = Column(String, default="draft", index=True)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    videos = relationship("DBVideo", back_populates="project", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "style": self.style,
            "status": self.status,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "videos_count": len(self.videos),
            "statistics": self.get_statistics()
        }

    def get_statistics(self):
        total = len(self.videos)
        completed = sum(1 for v in self.videos if v.status == "completed")
        failed = sum(1 for v in self.videos if v.status == "failed")
        processing = sum(1 for v in self.videos if v.status == "processing")
        avg_quality = sum(v.quality_score or 0 for v in self.videos) / total if total > 0 else 0

        return {
            "total": total,
            "completed": completed,
            "failed": failed,
            "processing": processing,
            "pending": total - completed - failed - processing,
            "avg_quality": avg_quality
        }


class DBVideo(Base):
    __tablename__ = "videos"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False)
    filepath = Column(String, nullable=False)
    project_id = Column(String, ForeignKey("projects.id"), nullable=False, index=True)
    status = Column(String, default="uploaded", index=True)
    status_message = Column(String, nullable=True)
    maestro_data = Column(JSON, nullable=True)
    video_metadata = Column(JSON, nullable=True)
    tags = Column(JSON, nullable=True)
    notes = Column(String, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow, index=True)
    quality_score = Column(Float, nullable=True)

    project = relationship("DBProject", back_populates="videos")
    skeleton_data = relationship("DBSkeletonData", back_populates="video", uselist=False, cascade="all, delete-orphan")
    techniques = relationship("DBTechnique", back_populates="video", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "filepath": self.filepath,
            "project_id": self.project_id,
            "status": self.status,
            "status_message": self.status_message,
            "maestro": self.maestro_data,
            "metadata": self.video_metadata,
            "tags": self.tags or [],
            "notes": self.notes,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
            "quality_score": self.quality_score,
            "skeleton": self.skeleton_data.to_dict() if self.skeleton_data else None,
            "techniques_count": len(self.techniques)
        }


class DBSkeletonData(Base):
    __tablename__ = "skeleton_data"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    video_id = Column(String, ForeignKey("videos.id"), nullable=False, unique=True, index=True)
    skeleton_filepath = Column(String, nullable=False)
    total_landmarks = Column(Integer, default=75)
    frames_processed = Column(Integer, nullable=False)
    detection_rates = Column(JSON, nullable=True)
    avg_confidence = Column(Float, nullable=True)
    quality_assessment = Column(String, nullable=True)
    processing_time_seconds = Column(Float, nullable=True)
    extracted_at = Column(DateTime, default=datetime.utcnow)

    video = relationship("DBVideo", back_populates="skeleton_data")

    def to_dict(self):
        return {
            "id": self.id,
            "video_id": self.video_id,
            "skeleton_filepath": self.skeleton_filepath,
            "total_landmarks": self.total_landmarks,
            "frames_processed": self.frames_processed,
            "detection_rates": self.detection_rates,
            "avg_confidence": self.avg_confidence,
            "quality_assessment": self.quality_assessment,
            "processing_time_seconds": self.processing_time_seconds,
            "extracted_at": self.extracted_at.isoformat() if self.extracted_at else None
        }


class DBTechnique(Base):
    __tablename__ = "techniques"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    video_id = Column(String, ForeignKey("videos.id"), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    start_frame = Column(Integer, nullable=False)
    end_frame = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    style = Column(String, nullable=False, index=True)
    technique_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    video = relationship("DBVideo", back_populates="techniques")

    def to_dict(self):
        return {
            "id": self.id,
            "video_id": self.video_id,
            "name": self.name,
            "start_frame": self.start_frame,
            "end_frame": self.end_frame,
            "confidence": self.confidence,
            "style": self.style,
            "metadata": self.technique_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class DBUser(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }

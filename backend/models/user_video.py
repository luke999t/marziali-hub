"""
🎓 AI_MODULE: UserVideo Model
🎓 AI_DESCRIPTION: Relazione many-to-many tra User e Video con metadati
🎓 AI_BUSINESS: Tracking progressi, libreria personale, analytics engagement
🎓 AI_TEACHING: SQLAlchemy association object pattern con campi aggiuntivi

📊 FIELDS:
- user_id, video_id: FK per relazione
- progress: percentuale visione 0-100
- is_saved: flag per libreria salvati
- downloaded: flag per offline (premium)
- timestamps: saved_at, completed_at, last_watched, downloaded_at
"""

from sqlalchemy import Column, Integer, ForeignKey, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid

from core.database import Base
from models import GUID


class UserVideo(Base):
    """
    Association table between User and Video with additional metadata.
    Tracks user's interaction with videos (progress, saved, downloaded).
    """
    __tablename__ = "user_videos"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(GUID(), ForeignKey("users.id"), nullable=False, index=True)
    video_id = Column(GUID(), ForeignKey("videos.id"), nullable=False, index=True)

    # Progress tracking
    progress = Column(Integer, default=0)  # 0-100 percentage
    last_watched = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    # Library management
    is_saved = Column(Boolean, default=False)
    saved_at = Column(DateTime, nullable=True)

    # Offline download (premium feature)
    downloaded = Column(Boolean, default=False)
    downloaded_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    # FIXME: Removed back_populates because User.video_progress is commented out
    user = relationship("User")
    video = relationship("Video", back_populates="user_progress")

    def __repr__(self):
        return f"<UserVideo user={self.user_id} video={self.video_id} progress={self.progress}%>"

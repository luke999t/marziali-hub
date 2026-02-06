"""
🎓 AI_MODULE: Video Models
🎓 AI_DESCRIPTION: Video, Course, LiveEvent, LibraryItem
🎓 AI_BUSINESS: Content catalog + streaming metadata
🎓 AI_TEACHING: Polymorphic models + HLS metadata + analytics

💡 RELATIONSHIPS:
Video N ────── 1 User (uploaded_by)
Video 1 ────── N ViewingHistory
Video 1 ────── N Favorite
Course 1 ────── N CourseItem ────── N Video
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, Enum, Index, ARRAY, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, ArrayType, JSONBType


# === ENUMS ===

class VideoStatus(str, enum.Enum):
    """Video processing status."""
    PENDING = "pending"          # Upload completato, processing non iniziato
    PROCESSING = "processing"    # FFmpeg sta processando
    READY = "ready"             # Pronto per streaming
    FAILED = "failed"           # Processing fallito
    ARCHIVED = "archived"       # Archiviato (non visibile)


class VideoCategory(str, enum.Enum):
    """Video categories."""
    TECHNIQUE = "technique"
    KATA = "kata"
    COMBAT = "combat"
    THEORY = "theory"
    WORKOUT = "workout"
    DEMO = "demo"
    OTHER = "other"


class LiveEventType(str, enum.Enum):
    """Tipologia evento live."""
    LIVE_CLASS = "live_class"  # Lezione regolare
    WORKSHOP = "workshop"  # Workshop tecnica specifica
    SEMINAR = "seminar"  # Seminario con ospite
    COMPETITION = "competition"  # Gara/esibizione
    QNA = "qna"  # Q&A con maestro
    FUNDRAISING = "fundraising"  # Evento raccolta fondi


class LiveEventStatus(str, enum.Enum):
    """Status evento live."""
    SCHEDULED = "scheduled"
    LIVE = "live"
    ENDED = "ended"
    CANCELLED = "cancelled"


class Difficulty(str, enum.Enum):
    """Difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


# === MODELS ===

class Video(Base):
    """
    Video model con HLS metadata.

    🎯 CORE CONTENT: Singolo video streamable
    """
    __tablename__ = "videos"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    slug = Column(String(255), unique=True, nullable=False, index=True)

    # === CATEGORIZATION ===
    category = Column(Enum(VideoCategory, values_callable=lambda x: [e.value for e in x]), nullable=False, index=True)
    style = Column(String(100))  # Karate, Judo, BJJ, etc.
    difficulty = Column(Enum(Difficulty, values_callable=lambda x: [e.value for e in x]), nullable=False, index=True)
    tags = Column(ArrayType(String), default=list)

    # === MEDIA FILES ===
    thumbnail_url = Column(Text, nullable=True)
    video_url = Column(Text, nullable=False)  # Original video URL
    hls_playlist_url = Column(Text, nullable=True)  # .m3u8 master playlist

    # === VIDEO METADATA ===
    duration = Column(Integer, nullable=False)  # seconds
    file_size = Column(Integer, nullable=True)  # bytes
    original_filename = Column(String(255), nullable=True)

    # === QUALITY & FORMATS ===
    quality_available = Column(ArrayType(String), default=["360p", "720p", "1080p"])
    hls_variants = Column(JSONBType(), nullable=True)  # {"360p": "url", "720p": "url", ...}

    # === SUBTITLES ===
    has_subtitles = Column(Boolean, default=False, nullable=False)
    available_languages = Column(ArrayType(String), default=["it", "en"])
    subtitle_urls = Column(JSONBType(), nullable=True)  # {"it": "url.vtt", "en": "url.vtt"}

    # === ANALYTICS ===
    view_count = Column(Integer, default=0, nullable=False, index=True)
    unique_viewers = Column(Integer, default=0, nullable=False)
    avg_watch_time = Column(Integer, default=0, nullable=False)  # seconds
    completion_rate = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0
    likes_count = Column(Integer, default=0, nullable=False)
    dislikes_count = Column(Integer, default=0, nullable=False)

    # === ACCESS CONTROL ===
    tier_required = Column(String(50), default="free", nullable=False, index=True)
    is_premium = Column(Boolean, default=False, nullable=False, index=True)
    is_public = Column(Boolean, default=True, nullable=False)
    is_featured = Column(Boolean, default=False, nullable=False, index=True)  # Per home feed
    ppv_price = Column(Float, nullable=True)  # Pay-per-view price (EUR)

    # === INSTRUCTOR ===
    instructor_name = Column(String(255))
    instructor_bio = Column(Text)
    instructor_avatar_url = Column(Text)

    # === PROCESSING ===
    status = Column(Enum(VideoStatus, values_callable=lambda x: [e.value for e in x]), default=VideoStatus.PENDING, nullable=False, index=True)
    processing_error = Column(Text, nullable=True)

    # === MODERATION ===
    approved_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    needs_changes_notes = Column(Text, nullable=True)

    # === METADATA ===
    uploaded_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    published_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    # viewing_history = relationship("ViewingHistory", back_populates="video")
    user_progress = relationship("UserVideo", back_populates="video")
    downloads = relationship("Download", back_populates="video", lazy="dynamic")
    sections = relationship(
        "VideoSection",
        back_populates="video",
        cascade="all, delete-orphan",
        lazy="dynamic",
        order_by="VideoSection.start_time"
    )

    # === INDEXES ===
    __table_args__ = (
        Index('idx_videos_tier_status', 'tier_required', 'status'),
        Index('idx_videos_category_difficulty', 'category', 'difficulty'),
        Index('idx_videos_published', 'published_at', postgresql_where=(status == VideoStatus.READY)),
    )

    # === BUSINESS METHODS ===

    def is_available_for_user(self, user) -> bool:
        """
        Check se video disponibile per user.

        🎯 ACCESS CONTROL: Tier + status + public check
        """
        if self.status != VideoStatus.READY:
            return False

        if not self.is_public and user is None:
            return False

        if user and user.is_admin:
            return True

        if self.tier_required == "free":
            return True

        if user:
            return user.can_watch_video(self.tier_required)

        return False

    def get_best_quality_for_tier(self, user_tier: str) -> str:
        """
        Get best quality per tier.

        Returns: "720p" | "1080p" | "4k"
        """
        tier_quality_map = {
            "free": "720p",
            "hybrid_light": "1080p",
            "hybrid_standard": "1080p",
            "premium": "4k",
            "business": "4k",
        }

        max_quality = tier_quality_map.get(user_tier, "720p")

        # Filter available qualities
        available = self.quality_available or []

        quality_order = ["360p", "480p", "720p", "1080p", "4k"]
        max_index = quality_order.index(max_quality) if max_quality in quality_order else 2

        for q in reversed(quality_order[:max_index + 1]):
            if q in available:
                return q

        return "720p"  # Fallback

    def increment_view_count(self, completed: bool = False):
        """
        Increment analytics counters.

        🎯 ANALYTICS: Update dopo ogni view
        """
        self.view_count += 1

        if completed:
            # Update completion rate
            total_views = self.view_count
            completed_views = int(total_views * self.completion_rate) + 1
            self.completion_rate = completed_views / total_views

    def __repr__(self):
        return f"<Video {self.title} ({self.status.value})>"


class Course(Base):
    """
    Course (percorso) che raggruppa più video.

    🎯 LEARNING PATH: Sequenza strutturata di video
    """
    __tablename__ = "courses"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    slug = Column(String(255), unique=True, nullable=False, index=True)

    thumbnail_url = Column(Text)
    difficulty = Column(Enum(Difficulty, values_callable=lambda x: [e.value for e in x]), nullable=False)

    # === PRICING ===
    tier_required = Column(String(50), default="free", nullable=False)
    ppv_price = Column(Float, nullable=True)

    # === METADATA ===
    total_duration = Column(Integer, default=0, nullable=False)  # Sum of all videos
    video_count = Column(Integer, default=0, nullable=False)

    created_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    items = relationship("CourseItem", back_populates="course", order_by="CourseItem.order", cascade="all, delete-orphan")


class CourseItem(Base):
    """
    Junction table Course <-> Video.

    🎯 ORDERING: Video in sequenza specifica
    """
    __tablename__ = "course_items"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    course_id = Column(GUID(), ForeignKey("courses.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False)

    order = Column(Integer, nullable=False)  # Position in course
    is_free_preview = Column(Boolean, default=False, nullable=False)  # Free sample

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    course = relationship("Course", back_populates="items")

    __table_args__ = (
        Index('idx_course_items_course', 'course_id', 'order'),
    )


class LiveEvent(Base):
    """
    Live streaming event.

    🎯 LIVE STREAMING: WebRTC/RTMP per eventi live + donazioni + AI translations
    """
    __tablename__ = "live_events"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === OWNERSHIP ===
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=False)
    asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)
    instructor_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)  # Backward compat

    # === EVENT INFO ===
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    event_type = Column(Enum(LiveEventType, values_callable=lambda x: [e.value for e in x]), nullable=False, index=True)

    # === STREAMING ===
    stream_key = Column(String(255), unique=True, nullable=False)
    rtmp_url = Column(Text, nullable=False)
    hls_url = Column(Text, nullable=True)

    # === STATUS ===
    status = Column(Enum(LiveEventStatus, values_callable=lambda x: [e.value for e in x]), default=LiveEventStatus.SCHEDULED, nullable=False, index=True)
    is_active = Column(Boolean, default=False, nullable=False, index=True)  # Backward compat

    # === SCHEDULING ===
    scheduled_start = Column(DateTime, nullable=False, index=True)
    scheduled_end = Column(DateTime, nullable=True)
    actual_start = Column(DateTime, nullable=True)
    actual_end = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)  # Backward compat (same as actual_start)
    ended_at = Column(DateTime, nullable=True)  # Backward compat (same as actual_end)

    # === ACCESS ===
    tier_required = Column(String(50), default="free", nullable=False)
    access_tier = Column(String(50), default="FREE", nullable=False)  # Backward compat
    requires_registration = Column(Boolean, default=False, nullable=False)
    max_participants = Column(Integer, nullable=True)  # Null = unlimited
    max_viewers = Column(Integer, nullable=True)  # Backward compat (same as max_participants)

    # === FEATURES ===
    donations_enabled = Column(Boolean, default=True, nullable=False)
    chat_enabled = Column(Boolean, default=True, nullable=False)
    translations_enabled = Column(Boolean, default=False, nullable=False)
    translation_languages = Column(ARRAY(String), nullable=True)  # ['en', 'zh', 'es']

    # === DONATION SETTINGS ===
    custom_donation_split = Column(JSONBType(), nullable=True)
    fundraising_goal = Column(Integer, nullable=True)  # Stelline goal (for fundraising events)

    # === ANALYTICS ===
    current_viewers = Column(Integer, default=0, nullable=False)
    peak_viewers = Column(Integer, default=0, nullable=False)
    total_unique_viewers = Column(Integer, default=0, nullable=False)
    total_donations_stelline = Column(Integer, default=0, nullable=False)
    total_messages = Column(Integer, default=0, nullable=False)

    # === RECORDING ===
    recording_enabled = Column(Boolean, default=True, nullable=False)
    recording_url = Column(Text, nullable=True)
    replay_video_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)

    # === THUMBNAIL ===
    thumbnail_url = Column(Text, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    maestro = relationship("Maestro", back_populates="live_events")
    asd = relationship("ASD", foreign_keys=[asd_id])
    replay_video = relationship("Video", foreign_keys=[replay_video_id])
    translation_dataset = relationship("TranslationDataset", back_populates="event", uselist=False)

    __table_args__ = (
        Index('idx_live_active_scheduled', 'is_active', 'scheduled_start'),
        Index('idx_live_event_status_start', 'status', 'scheduled_start'),
        Index('idx_live_event_maestro', 'maestro_id', 'scheduled_start'),
        Index('idx_live_event_type', 'event_type', 'scheduled_start'),
    )

    # === BUSINESS METHODS ===

    def is_live_now(self) -> bool:
        """Check if event is currently live."""
        return self.status == LiveEventStatus.LIVE or self.is_active

    def can_start(self) -> bool:
        """Check if event can be started."""
        return (
            self.status == LiveEventStatus.SCHEDULED
            and datetime.utcnow() >= self.scheduled_start
        )

    def duration_minutes(self) -> int:
        """Get event duration in minutes."""
        start = self.actual_start or self.started_at
        end = self.actual_end or self.ended_at
        if not start or not end:
            return 0
        delta = end - start
        return int(delta.total_seconds() / 60)

    def fundraising_progress_percent(self) -> float:
        """Get fundraising progress percentage."""
        if not self.fundraising_goal or self.fundraising_goal == 0:
            return 0.0
        return min(100.0, (self.total_donations_stelline / self.fundraising_goal) * 100)


class LibraryItem(Base):
    """
    PDF/Image library item (anti-piracy protected).

    🎯 PROTECTED CONTENT: PDF/Images con watermark e DRM
    """
    __tablename__ = "library_items"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    description = Column(Text)

    # === FILE ===
    file_type = Column(String(20), nullable=False)  # pdf | image
    file_url = Column(Text, nullable=False)
    file_size = Column(Integer, nullable=True)
    thumbnail_url = Column(Text, nullable=True)

    # === ACCESS ===
    tier_required = Column(String(50), default="premium", nullable=False)
    is_downloadable = Column(Boolean, default=False, nullable=False)

    # === ANALYTICS ===
    view_count = Column(Integer, default=0, nullable=False)
    download_count = Column(Integer, default=0, nullable=False)

    # === METADATA ===
    uploaded_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_library_tier_type', 'tier_required', 'file_type'),
    )


class VideoModeration(Base):
    """
    Video moderation history.

    🎯 CONTENT MODERATION: Storico approvazioni/rifiuti video
    """
    __tablename__ = "video_moderation"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False)

    # === WHO ===
    moderator_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # === ACTION ===
    action = Column(String(20), nullable=False)
    # Values: 'APPROVED', 'REJECTED', 'NEEDS_CHANGES', 'AUTO_APPROVED'

    # === STATE TRANSITION ===
    previous_status = Column(String(20), nullable=False)
    new_status = Column(String(20), nullable=False)

    # === NOTES ===
    moderation_notes = Column(Text, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    required_changes = Column(ARRAY(Text), nullable=True)

    # === VALIDATION ===
    metadata_validation = Column(JSONBType(), nullable=True)
    # Example: {"valid": true, "score": 95, "issues": [], "warnings": ["No tags"]}

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_video_moderation_video', 'video_id', 'created_at'),
        Index('idx_video_moderation_moderator', 'moderator_user_id'),
        Index('idx_video_moderation_action', 'action', 'created_at'),
    )

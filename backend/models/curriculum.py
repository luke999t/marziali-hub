"""
================================================================================
    CURRICULUM MODELS - Learning Path System
================================================================================

AI_MODULE: Curriculum & Certification System
AI_DESCRIPTION: Complete learning path management with levels, exams, certificates
AI_BUSINESS: Monetization via curriculum subscriptions + certification value
AI_TEACHING: Complex multi-entity relationships + progress tracking + AI evaluation

RELATIONSHIPS:
    Curriculum 1 ────── N CurriculumLevel (ordered progression)
    Curriculum 1 ────── N CurriculumEnrollment
    CurriculumLevel N ──── M Course (junction: CurriculumLevelCourse)
    CurriculumLevel N ──── M Video (junction: CurriculumLevelVideo)
    CurriculumEnrollment 1 ────── N LevelProgress
    LevelProgress 1 ────── N ExamSubmission
    User 1 ────── N Certificate

OWNERSHIP MODEL:
    - Platform: Global curricula visible to all
    - ASD: School-specific curricula (members only or invite)
    - Maestro: Personal teaching paths

ACCESS CONTROL:
    - Public: Anyone can see and enroll
    - Members Only: Requires ASD membership
    - Invite Only: Requires invitation code

================================================================================
"""

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Float,
    Enum, ForeignKey, Text, Index, UniqueConstraint, Table
)
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum
import secrets
import hashlib

from core.database import Base
from models import GUID, JSONBType, ArrayType


# ==============================================================================
# ENUMS
# ==============================================================================

class CurriculumDiscipline(str, enum.Enum):
    """Martial arts disciplines for curricula."""
    KARATE = "karate"
    JUDO = "judo"
    TAEKWONDO = "taekwondo"
    KUNG_FU = "kung_fu"
    TAI_CHI = "tai_chi"
    AIKIDO = "aikido"
    MUAY_THAI = "muay_thai"
    BJJ = "bjj"
    WING_CHUN = "wing_chun"
    KRAV_MAGA = "krav_maga"
    HAPKIDO = "hapkido"
    CAPOEIRA = "capoeira"
    KENDO = "kendo"
    IAIDO = "iaido"
    WUSHU = "wushu"
    MMA = "mma"
    BOXING = "boxing"
    KICKBOXING = "kickboxing"
    WRESTLING = "wrestling"
    SAMBO = "sambo"
    OTHER = "other"


class CurriculumOwnerType(str, enum.Enum):
    """Who owns/created the curriculum."""
    PLATFORM = "platform"
    ASD = "asd"
    MAESTRO = "maestro"


class CurriculumVisibility(str, enum.Enum):
    """Who can see and access the curriculum."""
    PUBLIC = "public"
    MEMBERS_ONLY = "members_only"
    INVITE_ONLY = "invite_only"


class CurriculumPricingModel(str, enum.Enum):
    """How the curriculum is monetized."""
    FREE = "free"
    INCLUDED_IN_SUBSCRIPTION = "included_in_subscription"
    SEPARATE_PURCHASE = "separate_purchase"


class ExamType(str, enum.Enum):
    """Type of exam for level promotion."""
    VIDEO_SUBMISSION = "video_submission"
    LIVE_EVALUATION = "live_evaluation"
    QUIZ = "quiz"
    NONE = "none"


class LevelStatus(str, enum.Enum):
    """Status of a level for a user."""
    LOCKED = "locked"
    IN_PROGRESS = "in_progress"
    EXAM_PENDING = "exam_pending"
    COMPLETED = "completed"


class EnrollmentAccessType(str, enum.Enum):
    """How user accesses the curriculum."""
    SCHOOL_ONLY = "school_only"
    PLATFORM_ONLY = "platform_only"
    SCHOOL_PLUS_PLATFORM = "school_plus_platform"
    INVITED = "invited"


class SubscriptionType(str, enum.Enum):
    """Type of curriculum subscription."""
    SINGLE = "single"
    DUAL = "dual"


class ExamStatus(str, enum.Enum):
    """Status of an exam submission."""
    SUBMITTED = "submitted"
    AI_ANALYZED = "ai_analyzed"
    TEACHER_REVIEWING = "teacher_reviewing"
    PASSED = "passed"
    FAILED = "failed"
    REVISION_REQUESTED = "revision_requested"


class CertificateIssuerType(str, enum.Enum):
    """Who issued the certificate."""
    PLATFORM = "platform"
    ASD = "asd"
    MAESTRO = "maestro"


# ==============================================================================
# JUNCTION TABLES
# ==============================================================================

curriculum_level_courses = Table(
    'curriculum_level_courses',
    Base.metadata,
    Column('level_id', GUID(), ForeignKey('curriculum_levels.id', ondelete='CASCADE'), primary_key=True),
    Column('course_id', GUID(), ForeignKey('courses.id', ondelete='CASCADE'), primary_key=True),
    Column('order', Integer, default=0),
    Column('is_required', Boolean, default=True),
    Column('created_at', DateTime, default=datetime.utcnow)
)


curriculum_level_videos = Table(
    'curriculum_level_videos',
    Base.metadata,
    Column('level_id', GUID(), ForeignKey('curriculum_levels.id', ondelete='CASCADE'), primary_key=True),
    Column('video_id', GUID(), ForeignKey('videos.id', ondelete='CASCADE'), primary_key=True),
    Column('order', Integer, default=0),
    Column('is_required', Boolean, default=True),
    Column('is_reference', Boolean, default=False),  # Reference video for exam comparison
    Column('created_at', DateTime, default=datetime.utcnow)
)


# ==============================================================================
# CURRICULUM MODEL
# ==============================================================================

class Curriculum(Base):
    """
    Main curriculum/learning path model.

    A curriculum represents a complete learning journey through martial arts,
    with multiple levels (belt ranks), content, and certification.

    OWNERSHIP:
        - Platform curricula are global and managed by admins
        - ASD curricula are school-specific
        - Maestro curricula are personal teaching paths
    """
    __tablename__ = "curricula"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)

    # === DISCIPLINE ===
    discipline = Column(Enum(CurriculumDiscipline), nullable=False, index=True)
    style_variant = Column(String(100), nullable=True)  # "Shotokan", "Wado-Ryu", etc.

    # === OWNERSHIP ===
    owner_type = Column(Enum(CurriculumOwnerType), nullable=False, index=True)
    owner_asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)
    owner_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)

    # === VISIBILITY ===
    visibility = Column(Enum(CurriculumVisibility), default=CurriculumVisibility.PUBLIC, nullable=False, index=True)

    # === PRICING ===
    pricing_model = Column(Enum(CurriculumPricingModel), default=CurriculumPricingModel.FREE, nullable=False)
    price = Column(Float, nullable=True)  # EUR for separate_purchase
    currency = Column(String(3), default="EUR", nullable=False)

    # === SETTINGS (Parametrizzabile) ===
    settings = Column(JSONBType(), default=dict, nullable=False)
    """
    Settings structure:
    {
        "sequential_progression": true,      # Must complete levels in order
        "min_days_between_levels": 30,       # Minimum days between promotions
        "exam_required_for_promotion": true, # Exam required to advance
        "ai_feedback_enabled": true,         # Enable AI pose analysis
        "teacher_review_required": false,    # Require maestro approval
        "allow_level_skip": false,           # Allow skipping levels (for experienced)
        "max_exam_attempts": 3,              # Max attempts per level exam
        "exam_cooldown_days": 7,             # Days between exam attempts
        "certificate_auto_issue": true,      # Auto-issue certificates
        "show_leaderboard": false,           # Show progress leaderboard
        "notify_on_completion": true         # Email on level completion
    }
    """

    # === BRANDING ===
    thumbnail_url = Column(Text, nullable=True)
    banner_url = Column(Text, nullable=True)

    # === STATS (Denormalized) ===
    total_levels = Column(Integer, default=0, nullable=False)
    total_enrollments = Column(Integer, default=0, nullable=False)
    total_completions = Column(Integer, default=0, nullable=False)
    avg_completion_days = Column(Float, nullable=True)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_featured = Column(Boolean, default=False, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    published_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    levels = relationship(
        "CurriculumLevel",
        back_populates="curriculum",
        order_by="CurriculumLevel.order",
        cascade="all, delete-orphan"
    )
    enrollments = relationship(
        "CurriculumEnrollment",
        back_populates="curriculum",
        cascade="all, delete-orphan"
    )
    owner_asd = relationship("ASD", foreign_keys=[owner_asd_id])
    owner_maestro = relationship("Maestro", foreign_keys=[owner_maestro_id])
    invite_codes = relationship(
        "CurriculumInviteCode",
        back_populates="curriculum",
        cascade="all, delete-orphan"
    )
    certificates = relationship("Certificate", back_populates="curriculum")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_curriculum_owner_type', 'owner_type', 'is_active'),
        Index('idx_curriculum_visibility', 'visibility', 'is_active'),
        Index('idx_curriculum_discipline', 'discipline', 'is_active'),
        Index('idx_curriculum_asd', 'owner_asd_id'),
        Index('idx_curriculum_maestro', 'owner_maestro_id'),
    )

    # === BUSINESS METHODS ===

    def get_setting(self, key: str, default=None):
        """Get a setting value with fallback."""
        if not self.settings:
            return default
        return self.settings.get(key, default)

    def is_sequential(self) -> bool:
        """Check if levels must be completed in order."""
        return self.get_setting("sequential_progression", True)

    def requires_exam(self) -> bool:
        """Check if exams are required for promotion."""
        return self.get_setting("exam_required_for_promotion", True)

    def ai_enabled(self) -> bool:
        """Check if AI feedback is enabled."""
        return self.get_setting("ai_feedback_enabled", True)

    def get_first_level(self):
        """Get the first level (order=0)."""
        for level in self.levels:
            if level.order == 0:
                return level
        return self.levels[0] if self.levels else None

    def get_level_by_order(self, order: int):
        """Get level by order number."""
        for level in self.levels:
            if level.order == order:
                return level
        return None

    def can_user_access(self, user, asd_membership=None) -> bool:
        """
        Check if user can access this curriculum.

        Args:
            user: User model
            asd_membership: ASDMember model if user is member of an ASD

        Returns:
            True if user can access
        """
        if not self.is_active:
            return False

        if user and user.is_admin:
            return True

        if self.visibility == CurriculumVisibility.PUBLIC:
            return True

        if self.visibility == CurriculumVisibility.MEMBERS_ONLY:
            if not self.owner_asd_id:
                return True
            if asd_membership and asd_membership.asd_id == self.owner_asd_id:
                return asd_membership.is_membership_valid()
            return False

        if self.visibility == CurriculumVisibility.INVITE_ONLY:
            # Must check enrollment separately
            return False

        return False

    def __repr__(self):
        return f"<Curriculum {self.name} ({self.discipline.value})>"


# ==============================================================================
# CURRICULUM LEVEL MODEL
# ==============================================================================

class CurriculumLevel(Base):
    """
    A level within a curriculum (e.g., belt rank).

    Levels are ordered and contain courses/videos required to complete.
    Each level can have an exam requirement before promotion.
    """
    __tablename__ = "curriculum_levels"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    curriculum_id = Column(GUID(), ForeignKey("curricula.id", ondelete="CASCADE"), nullable=False)

    # === ORDERING ===
    order = Column(Integer, nullable=False)  # 0 = first level

    # === INFO ===
    name = Column(String(255), nullable=False)  # "10° KYU", "White Belt", "Beginner"
    belt_color = Column(String(50), nullable=True)  # "white", "yellow", "orange", etc.
    description = Column(Text, nullable=True)

    # === REQUIREMENTS ===
    requirements = Column(JSONBType(), default=list, nullable=False)
    """
    Requirements list:
    [
        "Complete Kata Heian Shodan",
        "Master basic stances (kihon)",
        "50 hours minimum practice",
        "Pass written theory test"
    ]
    """

    # === EXAM ===
    exam_type = Column(Enum(ExamType), default=ExamType.VIDEO_SUBMISSION, nullable=False)
    exam_instructions = Column(Text, nullable=True)
    passing_score = Column(Integer, default=70, nullable=False)  # 0-100

    # === REFERENCE VIDEOS (for AI comparison) ===
    reference_video_ids = Column(JSONBType(), default=list, nullable=False)
    """List of video IDs to use as reference for exam comparison."""

    # === PRICING OVERRIDE ===
    is_free = Column(Boolean, default=False, nullable=False)  # Override for free trial
    level_price = Column(Float, nullable=True)  # If sold separately

    # === TIME ESTIMATES ===
    estimated_hours = Column(Integer, nullable=True)
    min_practice_hours = Column(Integer, nullable=True)  # Required before exam

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    curriculum = relationship("Curriculum", back_populates="levels")
    courses = relationship(
        "Course",
        secondary=curriculum_level_courses,
        backref="curriculum_levels"
    )
    videos = relationship(
        "Video",
        secondary=curriculum_level_videos,
        backref="curriculum_levels"
    )
    progress_records = relationship(
        "LevelProgress",
        back_populates="level",
        cascade="all, delete-orphan"
    )

    # === INDEXES ===
    __table_args__ = (
        Index('idx_level_curriculum_order', 'curriculum_id', 'order'),
        UniqueConstraint('curriculum_id', 'order', name='uq_curriculum_level_order'),
    )

    # === BUSINESS METHODS ===

    def get_next_level(self):
        """Get the next level in the curriculum."""
        if not self.curriculum:
            return None
        return self.curriculum.get_level_by_order(self.order + 1)

    def get_previous_level(self):
        """Get the previous level in the curriculum."""
        if not self.curriculum or self.order == 0:
            return None
        return self.curriculum.get_level_by_order(self.order - 1)

    def is_first_level(self) -> bool:
        """Check if this is the first level."""
        return self.order == 0

    def is_last_level(self) -> bool:
        """Check if this is the last level."""
        if not self.curriculum:
            return True
        return self.order == len(self.curriculum.levels) - 1

    def requires_exam(self) -> bool:
        """Check if this level requires an exam."""
        return self.exam_type != ExamType.NONE

    def get_total_content_count(self) -> dict:
        """Get count of all content in this level."""
        return {
            "courses": len(self.courses) if self.courses else 0,
            "videos": len(self.videos) if self.videos else 0,
            "total": (len(self.courses) if self.courses else 0) + (len(self.videos) if self.videos else 0)
        }

    def __repr__(self):
        return f"<CurriculumLevel {self.name} (order={self.order})>"


# ==============================================================================
# CURRICULUM ENROLLMENT MODEL
# ==============================================================================

class CurriculumEnrollment(Base):
    """
    User enrollment in a curriculum.

    Tracks how a user accesses the curriculum (direct, via school, invite)
    and their overall progress through the learning path.
    """
    __tablename__ = "curriculum_enrollments"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    curriculum_id = Column(GUID(), ForeignKey("curricula.id", ondelete="CASCADE"), nullable=False)

    # === ACCESS TYPE ===
    access_type = Column(Enum(EnrollmentAccessType), nullable=False)

    # === SCHOOL ACCESS ===
    asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)
    invited_by_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)
    invitation_code = Column(String(50), nullable=True)

    # === PROGRESS ===
    current_level_id = Column(GUID(), ForeignKey("curriculum_levels.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # === SUBSCRIPTION ===
    subscription_type = Column(Enum(SubscriptionType), default=SubscriptionType.SINGLE, nullable=False)

    # === PAYMENT ===
    purchase_id = Column(GUID(), ForeignKey("purchases.id", ondelete="SET NULL"), nullable=True)
    paid_amount = Column(Float, nullable=True)
    paid_at = Column(DateTime, nullable=True)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="curriculum_enrollments")
    curriculum = relationship("Curriculum", back_populates="enrollments")
    current_level = relationship("CurriculumLevel", foreign_keys=[current_level_id])
    asd = relationship("ASD", foreign_keys=[asd_id])
    invited_by_maestro = relationship("Maestro", foreign_keys=[invited_by_maestro_id])
    level_progress = relationship(
        "LevelProgress",
        back_populates="enrollment",
        cascade="all, delete-orphan"
    )

    # === INDEXES ===
    __table_args__ = (
        Index('idx_enrollment_user_curriculum', 'user_id', 'curriculum_id'),
        Index('idx_enrollment_active', 'is_active', 'created_at'),
        Index('idx_enrollment_asd', 'asd_id'),
        UniqueConstraint('user_id', 'curriculum_id', name='uq_user_curriculum_enrollment'),
    )

    # === BUSINESS METHODS ===

    def start_curriculum(self):
        """Start the curriculum from the first level."""
        if self.started_at:
            return False

        self.started_at = datetime.utcnow()
        first_level = self.curriculum.get_first_level()
        if first_level:
            self.current_level_id = first_level.id
        return True

    def get_progress_percent(self) -> float:
        """Calculate overall progress percentage."""
        if not self.curriculum or not self.curriculum.levels:
            return 0.0

        total_levels = len(self.curriculum.levels)
        completed = sum(1 for lp in self.level_progress if lp.status == LevelStatus.COMPLETED)

        return (completed / total_levels) * 100

    def get_current_level_progress(self):
        """Get progress record for current level."""
        if not self.current_level_id:
            return None

        for lp in self.level_progress:
            if lp.level_id == self.current_level_id:
                return lp
        return None

    def can_advance_to_next_level(self) -> tuple:
        """
        Check if user can advance to next level.

        Returns:
            (can_advance: bool, reason: str)
        """
        current_progress = self.get_current_level_progress()
        if not current_progress:
            return False, "No progress on current level"

        if current_progress.status != LevelStatus.COMPLETED:
            return False, "Current level not completed"

        current_level = self.current_level
        if not current_level:
            return False, "No current level"

        next_level = current_level.get_next_level()
        if not next_level:
            return False, "Already at last level"

        # Check min days between levels
        min_days = self.curriculum.get_setting("min_days_between_levels", 0)
        if min_days > 0 and current_progress.completed_at:
            days_since = (datetime.utcnow() - current_progress.completed_at).days
            if days_since < min_days:
                return False, f"Must wait {min_days - days_since} more days"

        return True, "Can advance"

    def advance_to_next_level(self) -> bool:
        """Advance to the next level."""
        can_advance, reason = self.can_advance_to_next_level()
        if not can_advance:
            return False

        current_level = self.current_level
        next_level = current_level.get_next_level()

        if next_level:
            self.current_level_id = next_level.id
            return True
        return False

    def mark_completed(self):
        """Mark the entire curriculum as completed."""
        self.completed_at = datetime.utcnow()
        self.curriculum.total_completions += 1

    def __repr__(self):
        return f"<CurriculumEnrollment user={self.user_id} curriculum={self.curriculum_id}>"


# ==============================================================================
# LEVEL PROGRESS MODEL
# ==============================================================================

class LevelProgress(Base):
    """
    User progress within a specific curriculum level.

    Tracks videos watched, courses completed, practice time,
    and exam status for a single level.
    """
    __tablename__ = "level_progress"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    enrollment_id = Column(GUID(), ForeignKey("curriculum_enrollments.id", ondelete="CASCADE"), nullable=False)
    level_id = Column(GUID(), ForeignKey("curriculum_levels.id", ondelete="CASCADE"), nullable=False)

    # === STATUS ===
    status = Column(Enum(LevelStatus), default=LevelStatus.LOCKED, nullable=False, index=True)

    # === TIMING ===
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # === PROGRESS ===
    progress_percent = Column(Integer, default=0, nullable=False)  # 0-100

    # === CONTENT PROGRESS ===
    videos_watched = Column(JSONBType(), default=dict, nullable=False)
    """
    Structure: {
        "video_id_1": {"watched": true, "progress_seconds": 300, "completed": true},
        "video_id_2": {"watched": true, "progress_seconds": 150, "completed": false}
    }
    """

    courses_completed = Column(JSONBType(), default=dict, nullable=False)
    """
    Structure: {
        "course_id_1": {"completed": true, "score": 85, "completed_at": "2024-01-15"},
        "course_id_2": {"completed": false, "progress_percent": 60}
    }
    """

    # === PRACTICE TIME ===
    total_practice_minutes = Column(Integer, default=0, nullable=False)
    last_practice_at = Column(DateTime, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    enrollment = relationship("CurriculumEnrollment", back_populates="level_progress")
    level = relationship("CurriculumLevel", back_populates="progress_records")
    exam_submissions = relationship(
        "ExamSubmission",
        back_populates="level_progress",
        cascade="all, delete-orphan"
    )

    # === INDEXES ===
    __table_args__ = (
        Index('idx_progress_enrollment_level', 'enrollment_id', 'level_id'),
        Index('idx_progress_status', 'status'),
        UniqueConstraint('enrollment_id', 'level_id', name='uq_enrollment_level_progress'),
    )

    # === BUSINESS METHODS ===

    def start_level(self):
        """Start this level."""
        if self.status != LevelStatus.LOCKED:
            return False

        self.status = LevelStatus.IN_PROGRESS
        self.started_at = datetime.utcnow()
        return True

    def unlock(self):
        """Unlock this level for access."""
        if self.status == LevelStatus.LOCKED:
            self.status = LevelStatus.IN_PROGRESS
            self.started_at = datetime.utcnow()
            return True
        return False

    def mark_video_watched(self, video_id: str, progress_seconds: int, completed: bool = False):
        """Record video watch progress."""
        if not self.videos_watched:
            self.videos_watched = {}

        self.videos_watched[video_id] = {
            "watched": True,
            "progress_seconds": progress_seconds,
            "completed": completed,
            "last_watched": datetime.utcnow().isoformat()
        }
        self._recalculate_progress()

    def mark_course_completed(self, course_id: str, score: int = None):
        """Record course completion."""
        if not self.courses_completed:
            self.courses_completed = {}

        self.courses_completed[course_id] = {
            "completed": True,
            "score": score,
            "completed_at": datetime.utcnow().isoformat()
        }
        self._recalculate_progress()

    def add_practice_time(self, minutes: int):
        """Add practice time."""
        self.total_practice_minutes += minutes
        self.last_practice_at = datetime.utcnow()

    def _recalculate_progress(self):
        """Recalculate overall progress percentage."""
        if not self.level:
            return

        total_items = 0
        completed_items = 0

        # Count videos
        if self.level.videos:
            total_items += len(self.level.videos)
            completed_items += sum(
                1 for v in self.videos_watched.values()
                if v.get("completed", False)
            )

        # Count courses
        if self.level.courses:
            total_items += len(self.level.courses)
            completed_items += sum(
                1 for c in self.courses_completed.values()
                if c.get("completed", False)
            )

        if total_items > 0:
            self.progress_percent = int((completed_items / total_items) * 100)

    def is_content_complete(self) -> bool:
        """Check if all content is completed."""
        return self.progress_percent >= 100

    def can_take_exam(self) -> tuple:
        """
        Check if user can take the exam.

        Returns:
            (can_take: bool, reason: str)
        """
        if not self.is_content_complete():
            return False, "Complete all content first"

        # Check minimum practice hours
        if self.level.min_practice_hours:
            required_minutes = self.level.min_practice_hours * 60
            if self.total_practice_minutes < required_minutes:
                remaining = required_minutes - self.total_practice_minutes
                return False, f"Need {remaining} more minutes of practice"

        # Check exam cooldown
        if self.exam_submissions:
            last_submission = max(self.exam_submissions, key=lambda x: x.created_at)
            cooldown_days = self.enrollment.curriculum.get_setting("exam_cooldown_days", 7)
            days_since = (datetime.utcnow() - last_submission.created_at).days
            if days_since < cooldown_days:
                return False, f"Wait {cooldown_days - days_since} more days"

        # Check max attempts
        max_attempts = self.enrollment.curriculum.get_setting("max_exam_attempts", 3)
        attempts = len(self.exam_submissions)
        if attempts >= max_attempts:
            return False, f"Maximum {max_attempts} attempts reached"

        return True, "Can take exam"

    def complete_level(self):
        """Mark level as completed."""
        self.status = LevelStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress_percent = 100

    def __repr__(self):
        return f"<LevelProgress enrollment={self.enrollment_id} level={self.level_id} status={self.status.value}>"


# ==============================================================================
# EXAM SUBMISSION MODEL
# ==============================================================================

class ExamSubmission(Base):
    """
    Exam submission for level promotion.

    Stores video submission, AI analysis results, and teacher review.
    The AI analyzer uses comparison_engine and realtime_pose_corrector.
    """
    __tablename__ = "exam_submissions"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    level_progress_id = Column(GUID(), ForeignKey("level_progress.id", ondelete="CASCADE"), nullable=False)

    # === VIDEO SUBMISSION ===
    video_url = Column(Text, nullable=False)
    video_uploaded_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    video_duration = Column(Integer, nullable=True)  # seconds

    # === AI ANALYSIS ===
    ai_analysis = Column(JSONBType(), nullable=True)
    """
    AI Analysis structure:
    {
        "skeleton_data": {...},
        "comparison_results": {
            "overall_score": 85.5,
            "timing_score": 90.0,
            "form_score": 82.0,
            "technique_scores": {
                "punch": 88.0,
                "stance": 80.0
            }
        },
        "pose_corrections": [
            {
                "timestamp": 5.2,
                "body_part": "left_elbow",
                "issue": "Elbow too high",
                "suggestion": "Keep elbow closer to body"
            }
        ],
        "strengths": ["Good timing", "Strong stances"],
        "improvements": ["Work on hip rotation", "More power in punches"]
    }
    """
    ai_score = Column(Float, nullable=True)  # 0-100
    ai_feedback = Column(Text, nullable=True)
    ai_analyzed_at = Column(DateTime, nullable=True)

    # === TEACHER REVIEW ===
    reviewed_by_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)
    teacher_score = Column(Float, nullable=True)  # 0-100
    teacher_feedback = Column(Text, nullable=True)
    teacher_notes = Column(JSONBType(), nullable=True)  # Private notes
    reviewed_at = Column(DateTime, nullable=True)

    # === FINAL RESULT ===
    status = Column(Enum(ExamStatus), default=ExamStatus.SUBMITTED, nullable=False, index=True)
    final_score = Column(Float, nullable=True)  # 0-100
    passed = Column(Boolean, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    level_progress = relationship("LevelProgress", back_populates="exam_submissions")
    reviewed_by_maestro = relationship("Maestro", foreign_keys=[reviewed_by_maestro_id])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_exam_progress', 'level_progress_id', 'created_at'),
        Index('idx_exam_status', 'status'),
        Index('idx_exam_maestro', 'reviewed_by_maestro_id'),
    )

    # === BUSINESS METHODS ===

    def set_ai_analysis(self, analysis: dict, score: float, feedback: str):
        """Set AI analysis results."""
        self.ai_analysis = analysis
        self.ai_score = score
        self.ai_feedback = feedback
        self.ai_analyzed_at = datetime.utcnow()
        self.status = ExamStatus.AI_ANALYZED

    def set_teacher_review(self, maestro_id: str, score: float, feedback: str, notes: dict = None):
        """Set teacher review."""
        self.reviewed_by_maestro_id = maestro_id
        self.teacher_score = score
        self.teacher_feedback = feedback
        self.teacher_notes = notes
        self.reviewed_at = datetime.utcnow()
        self.status = ExamStatus.TEACHER_REVIEWING

    def calculate_final_score(self, ai_weight: float = 0.4, teacher_weight: float = 0.6) -> float:
        """
        Calculate weighted final score.

        Args:
            ai_weight: Weight for AI score (default 40%)
            teacher_weight: Weight for teacher score (default 60%)
        """
        if self.ai_score is not None and self.teacher_score is not None:
            return (self.ai_score * ai_weight) + (self.teacher_score * teacher_weight)
        elif self.teacher_score is not None:
            return self.teacher_score
        elif self.ai_score is not None:
            return self.ai_score
        return None

    def finalize(self, passing_score: int = 70):
        """Finalize the exam result."""
        self.final_score = self.calculate_final_score()

        if self.final_score is not None:
            self.passed = self.final_score >= passing_score
            self.status = ExamStatus.PASSED if self.passed else ExamStatus.FAILED

        return self.passed

    def request_revision(self, notes: str):
        """Request revision from student."""
        self.status = ExamStatus.REVISION_REQUESTED
        if not self.teacher_notes:
            self.teacher_notes = {}
        self.teacher_notes["revision_request"] = {
            "notes": notes,
            "requested_at": datetime.utcnow().isoformat()
        }

    def __repr__(self):
        return f"<ExamSubmission {self.id} status={self.status.value}>"


# ==============================================================================
# CERTIFICATE MODEL
# ==============================================================================

class Certificate(Base):
    """
    Certificate issued upon level completion.

    Supports PDF generation and future NFT/blockchain verification.
    """
    __tablename__ = "certificates"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    curriculum_id = Column(GUID(), ForeignKey("curricula.id", ondelete="CASCADE"), nullable=False)
    level_id = Column(GUID(), ForeignKey("curriculum_levels.id", ondelete="SET NULL"), nullable=True)

    # === CERTIFICATE INFO ===
    certificate_number = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)  # "10° KYU Karate Certificate"
    description = Column(Text, nullable=True)

    # === ISSUER ===
    issued_by_type = Column(Enum(CertificateIssuerType), nullable=False)
    issued_by_asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)
    issued_by_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)
    issued_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === DIGITAL CERTIFICATE ===
    pdf_url = Column(Text, nullable=True)
    pdf_generated_at = Column(DateTime, nullable=True)

    # === BLOCKCHAIN (Future) ===
    nft_token_id = Column(String(100), nullable=True)
    blockchain_tx = Column(String(100), nullable=True)
    blockchain_network = Column(String(50), nullable=True)  # "ethereum", "polygon"

    # === VERIFICATION ===
    verification_code = Column(String(32), unique=True, nullable=False)
    is_valid = Column(Boolean, default=True, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(Text, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="certificates")
    curriculum = relationship("Curriculum", back_populates="certificates")
    level = relationship("CurriculumLevel", foreign_keys=[level_id])
    issued_by_asd = relationship("ASD", foreign_keys=[issued_by_asd_id])
    issued_by_maestro = relationship("Maestro", foreign_keys=[issued_by_maestro_id])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_certificate_user', 'user_id', 'issued_at'),
        Index('idx_certificate_curriculum', 'curriculum_id'),
        Index('idx_certificate_valid', 'is_valid'),
    )

    # === CLASS METHODS ===

    @classmethod
    def generate_certificate_number(cls, prefix: str = "CERT") -> str:
        """Generate unique certificate number."""
        timestamp = datetime.utcnow().strftime("%Y%m%d")
        random_part = secrets.token_hex(4).upper()
        return f"{prefix}-{timestamp}-{random_part}"

    @classmethod
    def generate_verification_code(cls) -> str:
        """Generate verification code for public verification."""
        return secrets.token_hex(16)

    # === BUSINESS METHODS ===

    def revoke(self, reason: str):
        """Revoke the certificate."""
        self.is_valid = False
        self.revoked_at = datetime.utcnow()
        self.revocation_reason = reason

    def get_verification_url(self, base_url: str) -> str:
        """Get public verification URL."""
        return f"{base_url}/certificates/verify/{self.verification_code}"

    def to_verification_dict(self) -> dict:
        """Get data for public verification display."""
        return {
            "certificate_number": self.certificate_number,
            "title": self.title,
            "issued_at": self.issued_at.isoformat(),
            "is_valid": self.is_valid,
            "curriculum_name": self.curriculum.name if self.curriculum else None,
            "level_name": self.level.name if self.level else None,
            "revoked": self.revoked_at is not None,
        }

    def __repr__(self):
        return f"<Certificate {self.certificate_number} valid={self.is_valid}>"


# ==============================================================================
# INVITE CODE MODEL
# ==============================================================================

class CurriculumInviteCode(Base):
    """
    Invitation codes for invite-only curricula.

    Maestros can generate codes to invite students to their curricula.
    """
    __tablename__ = "curriculum_invite_codes"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    curriculum_id = Column(GUID(), ForeignKey("curricula.id", ondelete="CASCADE"), nullable=False)

    # === CODE ===
    code = Column(String(20), unique=True, nullable=False, index=True)

    # === CREATOR ===
    created_by_maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="SET NULL"), nullable=True)

    # === LIMITS ===
    max_uses = Column(Integer, nullable=True)  # None = unlimited
    current_uses = Column(Integer, default=0, nullable=False)
    expires_at = Column(DateTime, nullable=True)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    curriculum = relationship("Curriculum", back_populates="invite_codes")
    created_by_maestro = relationship("Maestro", foreign_keys=[created_by_maestro_id])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_invite_curriculum', 'curriculum_id', 'is_active'),
        Index('idx_invite_code', 'code'),
    )

    # === CLASS METHODS ===

    @classmethod
    def generate_code(cls, length: int = 8) -> str:
        """Generate random invite code."""
        return secrets.token_urlsafe(length)[:length].upper()

    # === BUSINESS METHODS ===

    def is_valid(self) -> tuple:
        """
        Check if code is valid.

        Returns:
            (is_valid: bool, reason: str)
        """
        if not self.is_active:
            return False, "Code is deactivated"

        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False, "Code has expired"

        if self.max_uses and self.current_uses >= self.max_uses:
            return False, "Code has reached max uses"

        return True, "Valid"

    def use(self) -> bool:
        """Use the code (increment counter)."""
        is_valid, _ = self.is_valid()
        if not is_valid:
            return False

        self.current_uses += 1
        return True

    def deactivate(self):
        """Deactivate the code."""
        self.is_active = False

    def __repr__(self):
        return f"<CurriculumInviteCode {self.code}>"

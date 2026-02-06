"""
🎓 AI_MODULE: Minors Protection Models
🎓 AI_DESCRIPTION: Minors safety, parental controls, activity monitoring
🎓 AI_BUSINESS: GDPR/COPPA compliance for minors
🎓 AI_TEACHING: Child safety requirements + parental consent workflows

💡 RELATIONSHIPS:
Minor 1 ───────── 1 User
Minor 1 ───────── 1 Parent (User)
ParentalApproval N ── 1 Minor
ParentalApproval N ── 1 Maestro (optional)
ActivityLog N ──── 1 User
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Enum, ForeignKey, Text, Index, ARRAY, Date
from sqlalchemy.orm import relationship
from datetime import datetime, date
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class ConsentStatus(str, enum.Enum):
    """Status consenso genitoriale."""
    PENDING = "pending"
    GRANTED = "granted"
    DENIED = "denied"
    REVOKED = "revoked"


class AgeBracket(str, enum.Enum):
    """Fasce età minori."""
    UNDER_13 = "under_13"  # <13 anni: Account NON consentito (COPPA)
    AGE_13_15 = "13_15"  # 13-15: Consenso genitore obbligatorio
    AGE_16_17 = "16_17"  # 16-17: Notifica genitore
    ADULT = "18+"  # 18+: Account standard


# === MODELS ===

class Minor(Base):
    """
    Profilo minore con consenso genitoriale.

    🎯 CHILD SAFETY: COPPA/GDPR compliance
    """
    __tablename__ = "minors"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)

    # === PARENT INFO ===
    parent_email = Column(String(255), nullable=False)
    parent_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # === AGE INFO ===
    birth_date = Column(Date, nullable=False)
    age_bracket = Column(Enum(AgeBracket), nullable=False)

    # === CONSENT ===
    consent_status = Column(Enum(ConsentStatus), default=ConsentStatus.PENDING, nullable=False, index=True)
    consent_date = Column(DateTime, nullable=True)
    consent_signature = Column(Text, nullable=True)  # Digital signature parent
    consent_ip = Column(String(50), nullable=True)

    # === ANONYMIZATION ===
    anonymization_enabled = Column(Boolean, default=True, nullable=False)
    random_username_seed = Column(String(50), nullable=True)  # Seed per generare user_x1de3f

    # === PARENTAL CONTROLS ===
    chat_enabled = Column(Boolean, default=False, nullable=False)
    private_messaging_enabled = Column(Boolean, default=False, nullable=False)
    donation_enabled = Column(Boolean, default=False, nullable=False)
    monthly_donation_limit_stelline = Column(Integer, default=0, nullable=False)  # 0 = disabled

    # === AUTHORIZED MAESTROS ===
    authorized_maestro_ids = Column(ARRAY(String), nullable=True)  # Lista UUID maestri autorizzati

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", foreign_keys=[user_id], backref="minor_profile")
    parent = relationship("User", foreign_keys=[parent_user_id])

    __table_args__ = (
        Index('idx_minor_consent', 'consent_status', 'created_at'),
        Index('idx_minor_parent', 'parent_user_id'),
    )

    # === BUSINESS METHODS ===

    def calculate_age(self) -> int:
        """Calculate current age."""
        today = date.today()
        return today.year - self.birth_date.year - (
            (today.month, today.day) < (self.birth_date.month, self.birth_date.day)
        )

    def update_age_bracket(self) -> None:
        """Update age bracket based on current age."""
        age = self.calculate_age()
        if age < 13:
            self.age_bracket = AgeBracket.UNDER_13
        elif 13 <= age <= 15:
            self.age_bracket = AgeBracket.AGE_13_15
        elif 16 <= age <= 17:
            self.age_bracket = AgeBracket.AGE_16_17
        else:
            self.age_bracket = AgeBracket.ADULT

    def is_consent_valid(self) -> bool:
        """Check if parental consent is valid."""
        if self.age_bracket == AgeBracket.ADULT:
            return True  # Adult, no consent needed
        if self.age_bracket == AgeBracket.UNDER_13:
            return False  # <13 not allowed
        return self.consent_status == ConsentStatus.GRANTED

    def can_use_chat(self) -> bool:
        """Check if minor can use chat."""
        return (
            self.is_consent_valid()
            and self.chat_enabled
            and self.age_bracket != AgeBracket.UNDER_13
        )

    def can_donate(self, amount_stelline: int) -> bool:
        """Check if minor can donate amount."""
        if not self.donation_enabled or self.age_bracket.value in ["under_13", "13_15"]:
            return False
        return amount_stelline <= self.monthly_donation_limit_stelline

    def is_maestro_authorized(self, maestro_id: str) -> bool:
        """Check if maestro is authorized for this minor."""
        if not self.authorized_maestro_ids:
            return False
        return str(maestro_id) in self.authorized_maestro_ids

    def generate_anonymous_username(self, session_id: str = None) -> str:
        """
        Generate anonymous username for chat/public display.

        Args:
            session_id: Optional session ID for per-session uniqueness

        Returns:
            Anonymous username like "user_x1de3f"
        """
        import hashlib
        if session_id:
            # Different username per session (live)
            data = f"{self.user_id}{session_id}{self.random_username_seed}"
        else:
            # Same username always
            data = f"{self.user_id}{self.random_username_seed}"

        hash_obj = hashlib.md5(data.encode())
        suffix = hash_obj.hexdigest()[:6]
        return f"user_{suffix}"

    def __repr__(self):
        return f"<Minor {self.user_id} - {self.age_bracket.value}>"


class ParentalApproval(Base):
    """
    Richieste approvazione genitore (video corrections, chat requests).

    🎯 PARENTAL CONTROL: Genitore approva azioni minore
    """
    __tablename__ = "parental_approvals"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    minor_id = Column(GUID(), ForeignKey("minors.id", ondelete="CASCADE"), nullable=False)
    parent_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === REQUEST INFO ===
    request_type = Column(String(50), nullable=False)  # 'video_correction', 'chat_request', 'maestro_follow'
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=True)

    # === REQUEST DATA ===
    request_data = Column(JSONBType(), nullable=True)
    # Example video_correction: {"video_url": "...", "message": "..."}
    # Example chat_request: {"maestro_id": "...", "reason": "..."}

    # === STATUS ===
    status = Column(String(50), default="pending", nullable=False, index=True)  # pending, approved, denied
    approved_at = Column(DateTime, nullable=True)
    denial_reason = Column(Text, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    minor = relationship("Minor", foreign_keys=[minor_id])
    parent = relationship("User", foreign_keys=[parent_user_id])
    maestro = relationship("Maestro", foreign_keys=[maestro_id])

    __table_args__ = (
        Index('idx_parental_approval_status', 'status', 'created_at'),
        Index('idx_parental_approval_minor', 'minor_id'),
    )

    def __repr__(self):
        return f"<ParentalApproval {self.request_type} - {self.status}>"


class ActivityLog(Base):
    """
    Activity log per monitoring genitori.

    🎯 PARENTAL MONITORING: Track attività minori
    """
    __tablename__ = "activity_logs"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === ACTIVITY ===
    activity_type = Column(String(50), nullable=False, index=True)
    # Types: video_view, message_sent, comment, donation, live_join, live_chat

    # === REFERENCES ===
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)
    message_id = Column(GUID(), nullable=True)
    live_event_id = Column(GUID(), ForeignKey("live_events.id", ondelete="SET NULL"), nullable=True)
    donation_id = Column(GUID(), ForeignKey("donations.id", ondelete="SET NULL"), nullable=True)

    # === METADATA ===
    activity_metadata = Column(JSONBType(), nullable=True)
    # Example: {"duration_seconds": 120, "maestro_id": "...", "content": "..."}

    # === TIMESTAMP ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === RELATIONSHIPS ===
    user = relationship("User", foreign_keys=[user_id])
    video = relationship("Video", foreign_keys=[video_id])
    live_event = relationship("LiveEvent", foreign_keys=[live_event_id])
    donation = relationship("Donation", foreign_keys=[donation_id])

    __table_args__ = (
        Index('idx_activity_user_type', 'user_id', 'activity_type', 'created_at'),
        Index('idx_activity_date', 'created_at'),
    )

    def __repr__(self):
        return f"<ActivityLog {self.activity_type} - user={self.user_id}>"

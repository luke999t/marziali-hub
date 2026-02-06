"""
🎓 AI_MODULE: Communication & Translation Models
🎓 AI_DESCRIPTION: Messages, corrections, translations, glossary
🎓 AI_BUSINESS: Student-maestro communication + AI translation system
🎓 AI_TEACHING: Real-time messaging + dataset management + fine-tuning

💡 RELATIONSHIPS:
Message N ────── 1 User (from)
Message N ────── 1 User (to)
CorrectionRequest N ── 1 Student (User)
CorrectionRequest N ── 1 Maestro
TranslationDataset 1 ─ 1 LiveEvent
GlossaryTerm N ─────── 1 Maestro
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Enum, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class MessageAttachmentType(str, enum.Enum):
    """Tipo allegato messaggio."""
    VIDEO = "video"
    IMAGE = "image"
    DOCUMENT = "document"


class CorrectionRequestStatus(str, enum.Enum):
    """Status richiesta correzione."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"


class TranslationProcessingStatus(str, enum.Enum):
    """Status processing dataset traduzione."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


# === MODELS ===

class Message(Base):
    """
    Messaggi privati studente-maestro.

    🎯 PRIVATE MESSAGING: Chat 1-to-1 per domande/supporto
    """
    __tablename__ = "messages"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    from_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    to_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === CONTENT ===
    content = Column(Text, nullable=False)

    # === ATTACHMENTS ===
    attachment_type = Column(Enum(MessageAttachmentType), nullable=True)
    attachment_url = Column(Text, nullable=True)
    attachment_metadata = Column(JSONBType(), nullable=True)  # Size, duration, etc.

    # === STATUS ===
    is_read = Column(Boolean, default=False, nullable=False, index=True)
    read_at = Column(DateTime, nullable=True)

    # === MODERATION ===
    is_flagged = Column(Boolean, default=False, nullable=False)
    flagged_reason = Column(Text, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === RELATIONSHIPS ===
    # FIXME: Removed back_populates because User.messages_sent/messages_received are commented out
    from_user = relationship("User", foreign_keys=[from_user_id])
    to_user = relationship("User", foreign_keys=[to_user_id])

    __table_args__ = (
        Index('idx_message_conversation', 'from_user_id', 'to_user_id', 'created_at'),
        Index('idx_message_to_user_unread', 'to_user_id', 'is_read', 'created_at'),
    )

    def mark_as_read(self) -> None:
        """Mark message as read."""
        if not self.is_read:
            self.is_read = True
            self.read_at = datetime.utcnow()

    def __repr__(self):
        return f"<Message from={self.from_user_id} to={self.to_user_id}>"


class CorrectionRequest(Base):
    """
    Richieste correzione video da studenti a maestri.

    🎯 FEEDBACK SYSTEM: Studenti inviano video per feedback tecnico
    """
    __tablename__ = "correction_requests"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    student_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=False)

    # === STUDENT VIDEO ===
    video_url = Column(Text, nullable=False)
    video_duration_seconds = Column(Integer, nullable=True)
    message = Column(Text, nullable=True)  # Domanda/contesto studente

    # === STATUS ===
    status = Column(
        Enum(CorrectionRequestStatus),
        default=CorrectionRequestStatus.PENDING,
        nullable=False,
        index=True
    )

    # === FEEDBACK MAESTRO ===
    feedback_text = Column(Text, nullable=True)
    feedback_video_url = Column(Text, nullable=True)  # Video annotato maestro
    feedback_audio_url = Column(Text, nullable=True)  # Voice feedback
    feedback_annotations = Column(JSONBType(), nullable=True)
    # Example: [{"timestamp": 5.2, "text": "Gomito troppo alto", "type": "error"}]

    # === PARENTAL (se student è minore) ===
    parent_approval_required = Column(Boolean, default=False, nullable=False)
    parent_approved = Column(Boolean, nullable=True)
    parent_approved_at = Column(DateTime, nullable=True)
    parental_approval_id = Column(
        GUID(),
        ForeignKey("parental_approvals.id", ondelete="SET NULL"),
        nullable=True
    )

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)  # Maestro inizia review
    completed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    student = relationship("User", foreign_keys=[student_id])
    maestro = relationship("Maestro", foreign_keys=[maestro_id])
    parental_approval = relationship("ParentalApproval", foreign_keys=[parental_approval_id])

    __table_args__ = (
        Index('idx_correction_maestro_status', 'maestro_id', 'status', 'created_at'),
        Index('idx_correction_student', 'student_id', 'created_at'),
    )

    # === BUSINESS METHODS ===

    def can_send(self) -> bool:
        """Check if request can be sent to maestro."""
        if not self.parent_approval_required:
            return True
        return self.parent_approved == True

    def start_review(self) -> None:
        """Maestro starts reviewing."""
        if self.status == CorrectionRequestStatus.PENDING:
            self.status = CorrectionRequestStatus.IN_PROGRESS
            self.started_at = datetime.utcnow()

    def complete_review(self, feedback_text: str = None, feedback_video_url: str = None) -> None:
        """Maestro completes review."""
        self.status = CorrectionRequestStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if feedback_text:
            self.feedback_text = feedback_text
        if feedback_video_url:
            self.feedback_video_url = feedback_video_url

    def __repr__(self):
        return f"<CorrectionRequest student={self.student_id} maestro={self.maestro_id} - {self.status.value}>"


class TranslationDataset(Base):
    """
    Dataset custom per traduzioni AI (eventi live).

    🎯 AI TRANSLATIONS: Upload glossari/documenti pre-evento
    """
    __tablename__ = "translation_datasets"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    event_id = Column(GUID(), ForeignKey("live_events.id", ondelete="CASCADE"), nullable=False, unique=True)
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=False)

    # === FILES ===
    files = Column(JSONBType(), nullable=True)
    # Example: [{"filename": "glossario.pdf", "url": "s3://...", "type": "glossary", "size": 12345}]

    # === PROCESSING ===
    processing_status = Column(
        Enum(TranslationProcessingStatus),
        default=TranslationProcessingStatus.PENDING,
        nullable=False,
        index=True
    )
    chunks_count = Column(Integer, default=0, nullable=False)
    embedding_complete = Column(Boolean, default=False, nullable=False)

    # === FINE-TUNING (opzionale se >10k words) ===
    fine_tune_job_id = Column(String(255), nullable=True)  # OpenAI fine-tune job ID
    fine_tune_model_id = Column(String(255), nullable=True)  # Custom model ID
    fine_tune_status = Column(String(50), nullable=True)  # succeeded, failed, running

    # === VECTOR DB ===
    chromadb_collection_id = Column(String(255), nullable=True)

    # === ERROR HANDLING ===
    error_message = Column(Text, nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    processed_at = Column(DateTime, nullable=True)
    fine_tune_started_at = Column(DateTime, nullable=True)
    fine_tune_completed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    event = relationship("LiveEvent", back_populates="translation_dataset")
    maestro = relationship("Maestro", foreign_keys=[maestro_id])
    glossary_terms = relationship("GlossaryTerm", back_populates="dataset", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_dataset_status', 'processing_status', 'created_at'),
        Index('idx_dataset_maestro', 'maestro_id'),
    )

    # === BUSINESS METHODS ===

    def is_ready(self) -> bool:
        """Check if dataset is ready for use."""
        return (
            self.processing_status == TranslationProcessingStatus.COMPLETED
            and self.embedding_complete
        )

    def needs_fine_tuning(self) -> bool:
        """Check if dataset is large enough for fine-tuning."""
        return self.chunks_count >= 100  # Arbitrary threshold

    def __repr__(self):
        return f"<TranslationDataset event={self.event_id} - {self.processing_status.value}>"


class GlossaryTerm(Base):
    """
    Termini tecnici glossario per traduzioni.

    🎯 TRANSLATION ACCURACY: Terminologia specifica arti marziali
    """
    __tablename__ = "glossary_terms"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    maestro_id = Column(GUID(), ForeignKey("maestros.id", ondelete="CASCADE"), nullable=False)
    dataset_id = Column(GUID(), ForeignKey("translation_datasets.id", ondelete="SET NULL"), nullable=True)

    # === TERM ===
    term = Column(String(255), nullable=False, index=True)
    original_language = Column(String(10), default="it", nullable=False)

    # === TRANSLATIONS ===
    translation_en = Column(Text, nullable=True)  # English
    translation_zh = Column(Text, nullable=True)  # Chinese (中文)
    translation_es = Column(Text, nullable=True)  # Spanish (Español)
    translation_fr = Column(Text, nullable=True)  # French (Français)
    translation_de = Column(Text, nullable=True)  # German (Deutsch)
    translation_ja = Column(Text, nullable=True)  # Japanese (日本語)

    # === CONTEXT ===
    context = Column(Text, nullable=True)  # Usage example
    discipline = Column(String(100), nullable=True)  # tai_chi, wing_chun, etc.
    category = Column(String(100), nullable=True)  # technique, form, concept, etc.

    # === METADATA ===
    usage_count = Column(Integer, default=0, nullable=False)  # Tracking usage
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    maestro = relationship("Maestro", foreign_keys=[maestro_id])
    dataset = relationship("TranslationDataset", back_populates="glossary_terms")

    __table_args__ = (
        Index('idx_glossary_term', 'term', 'original_language'),
        Index('idx_glossary_maestro', 'maestro_id'),
        Index('idx_glossary_dataset', 'dataset_id'),
        Index('idx_glossary_discipline', 'discipline'),
    )

    # === BUSINESS METHODS ===

    def get_translation(self, target_language: str) -> str:
        """
        Get translation for target language.

        Args:
            target_language: Language code (en, zh, es, fr, de, ja)

        Returns:
            Translation or original term if not found
        """
        translation_map = {
            "en": self.translation_en,
            "zh": self.translation_zh,
            "es": self.translation_es,
            "fr": self.translation_fr,
            "de": self.translation_de,
            "ja": self.translation_ja,
        }

        translation = translation_map.get(target_language)
        return translation if translation else self.term

    def increment_usage(self) -> None:
        """Increment usage counter."""
        self.usage_count += 1

    def __repr__(self):
        return f"<GlossaryTerm {self.term} ({self.original_language})>"


class LiveChatMessage(Base):
    """
    Messaggi chat durante live streaming.

    🎯 LIVE INTERACTION: Chat pubblica eventi live
    """
    __tablename__ = "live_chat_messages"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    live_event_id = Column(GUID(), ForeignKey("live_events.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # === CONTENT ===
    message = Column(Text, nullable=False)

    # === DISPLAY (per minori anonymized) ===
    display_name = Column(String(255), nullable=False)  # "MarioRossi94" o "user_x1de3f"
    is_anonymous = Column(Boolean, default=False, nullable=False)

    # === MODERATION ===
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_by_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    deleted_reason = Column(Text, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(50), nullable=True)

    # === RELATIONSHIPS ===
    live_event = relationship("LiveEvent", foreign_keys=[live_event_id])
    user = relationship("User", foreign_keys=[user_id])
    deleted_by = relationship("User", foreign_keys=[deleted_by_user_id])

    __table_args__ = (
        Index('idx_live_chat_event', 'live_event_id', 'created_at'),
        Index('idx_live_chat_user', 'user_id'),
    )

    def soft_delete(self, moderator_id: str, reason: str = None) -> None:
        """Soft delete message (moderator action)."""
        self.is_deleted = True
        self.deleted_by_user_id = moderator_id
        self.deleted_reason = reason

    def __repr__(self):
        return f"<LiveChatMessage event={self.live_event_id} user={self.display_name}>"

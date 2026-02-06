"""
AI_MODULE: Special Projects Database Models
AI_DESCRIPTION: SQLAlchemy models per progetti speciali e votazioni
AI_BUSINESS: Persistenza dati votazione, audit trail completo, analytics ready
AI_TEACHING: SQLAlchemy ORM, composite indexes, soft delete, audit columns

ALTERNATIVE_VALUTATE:
- MongoDB: Scartato, less suited for transactional voting
- Raw SQL: Scartato, maintainability issues
- NoSQL voting: Scartato, ACID required for vote integrity

PERCHE_QUESTA_SOLUZIONE:
- PostgreSQL: ACID transactions for vote integrity
- Composite indexes: Fast queries on user+cycle+project
- Audit columns: Full traceability for compliance
- Soft delete: Projects never truly deleted

METRICHE_SUCCESSO:
- Query vote status: <10ms
- Query eligibility: <20ms
- Vote transaction: <50ms
"""

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Float,
    ForeignKey, Text, Index, UniqueConstraint,
    CheckConstraint
)
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# ======================== ENUMS ========================

class ProjectStatus(enum.StrEnum):
    """
    Status progetto speciale.

    DRAFT: In preparazione, non visibile
    ACTIVE: Aperto alle votazioni
    VOTING_CLOSED: Votazione chiusa, in valutazione
    APPROVED: Approvato, in sviluppo
    IN_PROGRESS: Sviluppo in corso
    COMPLETED: Completato
    REJECTED: Rifiutato dopo votazione
    ARCHIVED: Archiviato
    """
    DRAFT = "draft"
    ACTIVE = "active"
    VOTING_CLOSED = "voting_closed"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class VoteWeight(int, enum.Enum):
    """
    Pesi voto predefiniti.

    Valori default, override da config.
    """
    PREMIUM_FULL = 3
    PREMIUM_HYBRID = 2
    FREE_WITH_ADS = 1
    NO_VOTE = 0


class EligibilityStatus(enum.StrEnum):
    """
    Status eligibilita voto utente.

    ELIGIBLE: Puo votare
    NOT_ELIGIBLE: Non puo votare (requisiti non soddisfatti)
    PENDING: In valutazione (free user near threshold)
    SUSPENDED: Sospeso (violazioni)
    """
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"
    PENDING = "pending"
    SUSPENDED = "suspended"


# ======================== MODELS ========================

class SpecialProject(Base):
    """
    Progetto speciale proposto per votazione.

    Rappresenta un'idea/feature che la community
    puo votare per prioritizzare lo sviluppo.
    """
    __tablename__ = "special_projects"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === CONTENT ===
    title = Column(String(200), nullable=False, index=True)
    slug = Column(String(200), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=False)
    short_description = Column(String(500), nullable=True)

    # === MEDIA ===
    image_url = Column(Text, nullable=True)
    video_url = Column(Text, nullable=True)

    # === BUDGET & TIMELINE ===
    estimated_budget_cents = Column(Integer, nullable=True)
    estimated_days = Column(Integer, nullable=True)
    funding_goal_cents = Column(Integer, nullable=True)
    current_funding_cents = Column(Integer, default=0, nullable=False)

    # === STATUS ===
    status = Column(
        String(50),
        default=ProjectStatus.DRAFT.value,  # Store the string value
        nullable=False,
        index=True
    )

    # === VOTING PERIOD ===
    voting_start_date = Column(DateTime, nullable=True)
    voting_end_date = Column(DateTime, nullable=True)

    # === VOTE STATS (denormalized) ===
    total_votes = Column(Integer, default=0, nullable=False)
    total_weighted_votes = Column(Integer, default=0, nullable=False)
    unique_voters = Column(Integer, default=0, nullable=False)

    # === CREATOR ===
    created_by = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    published_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # === SOFT DELETE ===
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    # === EXTRA DATA ===
    metadata_json = Column(JSONBType(), nullable=True)
    tags = Column(JSONBType(), nullable=True)  # ["feature", "mobile", "ai"]

    # === RELATIONSHIPS ===
    votes = relationship("ProjectVote", back_populates="project", cascade="all, delete-orphan")
    creator = relationship("User", backref="created_special_projects")

    __table_args__ = (
        Index('idx_project_status_voting', 'status', 'voting_start_date', 'voting_end_date'),
        Index('idx_project_votes', 'total_weighted_votes', 'status'),
        CheckConstraint('total_votes >= 0', name='check_positive_votes'),
    )

    # === BUSINESS METHODS ===

    def is_voting_open(self) -> bool:
        """Check se votazione aperta."""
        if self.status != ProjectStatus.ACTIVE:
            return False
        now = datetime.utcnow()
        if self.voting_start_date and now < self.voting_start_date:
            return False
        if self.voting_end_date and now > self.voting_end_date:
            return False
        return True

    def days_until_voting_ends(self) -> int:
        """Giorni rimanenti per votare."""
        if not self.voting_end_date:
            return -1
        delta = self.voting_end_date - datetime.utcnow()
        return max(0, delta.days)

    def __repr__(self):
        return f"<SpecialProject {self.slug} - {self.status.value}>"


class ProjectVote(Base):
    """
    Voto utente su progetto speciale.

    Traccia il voto con peso basato su subscription.
    Un utente puo avere UN voto attivo per ciclo.
    """
    __tablename__ = "special_project_votes"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === REFERENCES ===
    user_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    project_id = Column(
        GUID(),
        ForeignKey("special_projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # === VOTE DATA ===
    vote_weight = Column(Integer, nullable=False)
    subscription_tier_at_vote = Column(String(50), nullable=False)

    # === CYCLE ===
    vote_cycle = Column(String(20), nullable=False, index=True)  # "2024-01", "2024-02"

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # === TIMESTAMPS ===
    voted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # === PREVIOUS VOTE (for tracking changes) ===
    previous_project_id = Column(GUID(), nullable=True)
    changed_from_previous = Column(Boolean, default=False, nullable=False)

    # === RELATIONSHIPS ===
    project = relationship("SpecialProject", back_populates="votes")
    user = relationship("User", backref="special_project_votes")

    __table_args__ = (
        # Un solo voto attivo per utente per ciclo
        UniqueConstraint(
            'user_id', 'vote_cycle', 'is_active',
            name='uq_user_cycle_active_vote'
        ),
        Index('idx_vote_project_cycle', 'project_id', 'vote_cycle', 'is_active'),
        Index('idx_vote_user_active', 'user_id', 'is_active'),
    )

    def __repr__(self):
        return f"<ProjectVote user={self.user_id} project={self.project_id} weight={self.vote_weight}>"


class VotingEligibility(Base):
    """
    Eligibilita voto utente calcolata.

    Cached calculation of user's voting eligibility
    based on subscription and engagement metrics.
    Ricalcolata periodicamente.
    """
    __tablename__ = "special_projects_eligibility"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # === ELIGIBILITY ===
    status = Column(
        String(50),
        default=EligibilityStatus.NOT_ELIGIBLE.value,  # Store the string value
        nullable=False,
        index=True
    )
    vote_weight = Column(Integer, default=0, nullable=False)
    subscription_tier = Column(String(50), nullable=False)

    # === METRICS (for free users) ===
    watch_minutes_current = Column(Integer, default=0, nullable=False)
    ads_watched_current = Column(Integer, default=0, nullable=False)
    videos_completed_current = Column(Integer, default=0, nullable=False)

    # === THRESHOLDS (snapshot at calculation) ===
    watch_minutes_required = Column(Integer, nullable=True)
    ads_watched_required = Column(Integer, nullable=True)
    videos_completed_required = Column(Integer, nullable=True)

    # === PROGRESS (for UI) ===
    progress_percent = Column(Float, default=0.0, nullable=False)

    # === CYCLE ===
    vote_cycle = Column(String(20), nullable=False, index=True)

    # === TIMESTAMPS ===
    calculated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    valid_until = Column(DateTime, nullable=True)

    # === REASON ===
    ineligibility_reason = Column(String(255), nullable=True)

    __table_args__ = (
        UniqueConstraint('user_id', 'vote_cycle', name='uq_user_eligibility_cycle'),
        Index('idx_eligibility_status', 'status', 'vote_cycle'),
    )

    def is_eligible(self) -> bool:
        """Check se attualmente eligible."""
        return self.status == EligibilityStatus.ELIGIBLE and self.vote_weight > 0

    def __repr__(self):
        return f"<VotingEligibility user={self.user_id} status={self.status.value} weight={self.vote_weight}>"


class SpecialProjectsConfigDB(Base):
    """
    Configurazione sistema salvata in database.

    Permette override runtime della config
    senza restart server.
    """
    __tablename__ = "special_projects_config"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    config_key = Column(String(100), nullable=False, unique=True, index=True)

    # === VALUE ===
    config_value = Column(JSONBType(), nullable=False)
    value_type = Column(String(20), nullable=False)  # int, float, bool, json, string

    # === METADATA ===
    description = Column(Text, nullable=True)
    updated_by = Column(GUID(), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === AUDIT ===
    previous_value = Column(JSONBType(), nullable=True)
    change_reason = Column(Text, nullable=True)

    def get_typed_value(self):
        """Ottiene valore con tipo corretto."""
        if self.value_type == "int":
            return int(self.config_value)
        elif self.value_type == "float":
            return float(self.config_value)
        elif self.value_type == "bool":
            return bool(self.config_value)
        elif self.value_type == "json":
            return self.config_value
        else:
            return str(self.config_value)

    def __repr__(self):
        return f"<Config {self.config_key}={self.config_value}>"


class VoteHistory(Base):
    """
    Storico cambi voto per analytics.

    Traccia ogni cambio voto per analisi
    comportamento utenti.
    """
    __tablename__ = "special_projects_vote_history"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), nullable=False, index=True)

    # === CHANGE DETAILS ===
    from_project_id = Column(GUID(), nullable=True)
    to_project_id = Column(GUID(), nullable=False)
    vote_cycle = Column(String(20), nullable=False, index=True)

    # === CONTEXT ===
    vote_weight = Column(Integer, nullable=False)
    subscription_tier = Column(String(50), nullable=False)

    # === TIMESTAMP ===
    changed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index('idx_vote_history_user_cycle', 'user_id', 'vote_cycle'),
    )

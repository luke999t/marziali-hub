"""
AI_MODULE: Special Projects Pydantic Schemas
AI_DESCRIPTION: Validazione API request/response per sistema votazione
AI_BUSINESS: Type-safe APIs, auto-documentation, input sanitization
AI_TEACHING: Pydantic v2, computed fields, field validators

ALTERNATIVE_VALUTATE:
- Marshmallow: Scartato, meno integrato con FastAPI
- TypedDict: Scartato, no runtime validation
- Manual validation: Scartato, error-prone

PERCHE_QUESTA_SOLUZIONE:
- Pydantic v2: 17x faster, better validation
- FastAPI native: Auto OpenAPI docs
- Computed fields: Derived values on-the-fly

METRICHE_SUCCESSO:
- Validation time: <1ms
- Schema coverage: 100%
- Type errors: 0 runtime
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from uuid import UUID
from pydantic import BaseModel, Field, field_validator, computed_field
from enum import Enum


# ======================== ENUMS ========================

class ProjectStatusEnum(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    VOTING_CLOSED = "voting_closed"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class EligibilityStatusEnum(str, Enum):
    ELIGIBLE = "eligible"
    NOT_ELIGIBLE = "not_eligible"
    PENDING = "pending"
    SUSPENDED = "suspended"


# ======================== BASE ========================

class BaseSchema(BaseModel):
    class Config:
        from_attributes = True
        populate_by_name = True


# ======================== PROJECT SCHEMAS ========================

class SpecialProjectCreate(BaseSchema):
    """Schema creazione progetto speciale (admin)."""
    title: str = Field(..., min_length=5, max_length=200)
    description: str = Field(..., min_length=100, max_length=5000)
    short_description: Optional[str] = Field(None, max_length=500)
    image_url: Optional[str] = Field(None)
    video_url: Optional[str] = Field(None)
    estimated_budget_cents: Optional[int] = Field(None, ge=0)
    estimated_days: Optional[int] = Field(None, ge=1)
    funding_goal_cents: Optional[int] = Field(None, ge=0)
    tags: Optional[List[str]] = Field(default_factory=list)
    voting_start_date: Optional[datetime] = None
    voting_end_date: Optional[datetime] = None

    @field_validator('title')
    @classmethod
    def sanitize_title(cls, v):
        return v.strip()

    @field_validator('tags')
    @classmethod
    def validate_tags(cls, v):
        if v:
            return [tag.lower().strip() for tag in v if tag.strip()]
        return []


class SpecialProjectUpdate(BaseSchema):
    """Schema update progetto (admin)."""
    title: Optional[str] = Field(None, min_length=5, max_length=200)
    description: Optional[str] = Field(None, min_length=100, max_length=5000)
    short_description: Optional[str] = Field(None, max_length=500)
    image_url: Optional[str] = None
    video_url: Optional[str] = None
    estimated_budget_cents: Optional[int] = Field(None, ge=0)
    estimated_days: Optional[int] = Field(None, ge=1)
    funding_goal_cents: Optional[int] = Field(None, ge=0)
    status: Optional[ProjectStatusEnum] = None
    tags: Optional[List[str]] = None
    voting_start_date: Optional[datetime] = None
    voting_end_date: Optional[datetime] = None


class SpecialProjectResponse(BaseSchema):
    """Schema response progetto."""
    id: UUID
    title: str
    slug: str
    description: str
    short_description: Optional[str]
    image_url: Optional[str]
    video_url: Optional[str]
    status: ProjectStatusEnum
    estimated_budget_cents: Optional[int]
    estimated_days: Optional[int]
    funding_goal_cents: Optional[int]
    current_funding_cents: int
    total_votes: int
    total_weighted_votes: int
    unique_voters: int
    voting_start_date: Optional[datetime]
    voting_end_date: Optional[datetime]
    tags: Optional[List[str]]
    created_at: datetime
    published_at: Optional[datetime]

    @computed_field
    @property
    def estimated_budget_eur(self) -> Optional[float]:
        if self.estimated_budget_cents:
            return self.estimated_budget_cents / 100
        return None

    @computed_field
    @property
    def is_voting_open(self) -> bool:
        if self.status != ProjectStatusEnum.ACTIVE:
            return False
        now = datetime.utcnow()
        if self.voting_start_date and now < self.voting_start_date:
            return False
        if self.voting_end_date and now > self.voting_end_date:
            return False
        return True

    @computed_field
    @property
    def days_until_voting_ends(self) -> int:
        if not self.voting_end_date:
            return -1
        delta = self.voting_end_date - datetime.utcnow()
        return max(0, delta.days)


class SpecialProjectListResponse(BaseSchema):
    """Schema lista progetti con paginazione."""
    projects: List[SpecialProjectResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


# ======================== VOTE SCHEMAS ========================

class ProjectVoteCreate(BaseSchema):
    """Schema creazione voto."""
    project_id: UUID = Field(..., description="ID progetto da votare")

    # Optional: for changing vote
    confirm_change: bool = Field(
        False,
        description="Conferma cambio voto (required se ha gia votato)"
    )


class ProjectVoteResponse(BaseSchema):
    """Schema response voto."""
    id: UUID
    user_id: UUID
    project_id: UUID
    project_title: Optional[str] = None
    vote_weight: int
    subscription_tier_at_vote: str
    vote_cycle: str
    is_active: bool
    voted_at: datetime
    changed_from_previous: bool
    previous_project_id: Optional[UUID]

    @computed_field
    @property
    def vote_cycle_display(self) -> str:
        """Formatta ciclo per display (es: 'Gennaio 2024')."""
        try:
            year, month = self.vote_cycle.split("-")
            months = [
                "", "Gennaio", "Febbraio", "Marzo", "Aprile",
                "Maggio", "Giugno", "Luglio", "Agosto",
                "Settembre", "Ottobre", "Novembre", "Dicembre"
            ]
            return f"{months[int(month)]} {year}"
        except:
            return self.vote_cycle


class MyVoteResponse(BaseSchema):
    """Schema voto corrente utente."""
    has_voted: bool
    current_vote: Optional[ProjectVoteResponse] = None
    can_change: bool
    next_change_available: Optional[datetime] = None
    vote_weight: int
    eligibility_status: EligibilityStatusEnum


# ======================== ELIGIBILITY SCHEMAS ========================

class EligibilityResponse(BaseSchema):
    """Schema risposta eligibilita."""
    user_id: UUID
    status: EligibilityStatusEnum
    vote_weight: int
    subscription_tier: str
    can_vote: bool
    vote_cycle: str

    # Progress for free users
    watch_minutes_current: int
    watch_minutes_required: Optional[int]
    ads_watched_current: int
    ads_watched_required: Optional[int]
    videos_completed_current: int
    videos_completed_required: Optional[int]
    progress_percent: float

    # Reason if not eligible
    ineligibility_reason: Optional[str]

    @computed_field
    @property
    def is_free_user(self) -> bool:
        return self.subscription_tier in ["free_with_ads", "free_no_ads"]

    @computed_field
    @property
    def requirements_met(self) -> Dict[str, bool]:
        """Status requisiti individuali."""
        return {
            "watch_minutes": (
                self.watch_minutes_required is None or
                self.watch_minutes_current >= self.watch_minutes_required
            ),
            "ads_watched": (
                self.ads_watched_required is None or
                self.ads_watched_current >= self.ads_watched_required
            ),
            "videos_completed": (
                self.videos_completed_required is None or
                self.videos_completed_current >= self.videos_completed_required
            )
        }


class EligibilityCheckRequest(BaseSchema):
    """Schema richiesta check eligibilita."""
    force_recalculate: bool = Field(
        False,
        description="Forza ricalcolo anche se cache valida"
    )


# ======================== STATS SCHEMAS ========================

class VotingStatsResponse(BaseSchema):
    """Schema statistiche votazione."""
    vote_cycle: str
    total_eligible_voters: int
    total_votes_cast: int
    participation_rate: float

    # By tier
    votes_by_tier: Dict[str, int]
    weighted_votes_by_tier: Dict[str, int]

    # Top projects
    top_projects: List[Dict[str, Any]]

    # Time series
    votes_per_day: List[Dict[str, Any]]


class ProjectStatsResponse(BaseSchema):
    """Schema statistiche singolo progetto."""
    project_id: UUID
    project_title: str
    total_votes: int
    total_weighted_votes: int
    unique_voters: int
    rank: int
    rank_change: int  # vs previous cycle

    # Breakdown
    votes_by_tier: Dict[str, int]
    votes_by_day: List[Dict[str, Any]]


# ======================== CONFIG SCHEMAS ========================

class ConfigResponse(BaseSchema):
    """Schema response configurazione."""
    vote_weights: Dict[str, int]
    free_user_requirements: Dict[str, int]
    voting_rules: Dict[str, Any]
    project_settings: Dict[str, Any]


class ConfigUpdateRequest(BaseSchema):
    """Schema update configurazione (admin)."""
    config_key: str = Field(..., description="Chiave config da aggiornare")
    config_value: Any = Field(..., description="Nuovo valore")
    change_reason: Optional[str] = Field(None, max_length=500)

    @field_validator('config_key')
    @classmethod
    def validate_key(cls, v):
        valid_keys = [
            "vote_weight_premium_full",
            "vote_weight_premium_hybrid",
            "vote_weight_free_with_ads",
            "vote_weight_free_no_ads",
            "free_min_watch_minutes",
            "free_min_ads_watched",
            "free_min_videos_completed",
            "votes_per_user_per_cycle",
            "can_change_vote_same_cycle",
            "vote_persists_next_cycle"
        ]
        if v not in valid_keys:
            raise ValueError(f"Invalid config key. Valid keys: {valid_keys}")
        return v


class BulkConfigUpdateRequest(BaseSchema):
    """Schema bulk update configurazione."""
    updates: List[ConfigUpdateRequest]
    change_reason: Optional[str] = Field(None, max_length=500)


# ======================== ANALYTICS SCHEMAS ========================

class AnalyticsSummary(BaseSchema):
    """Schema summary analytics."""
    period_start: datetime
    period_end: datetime

    # Participation
    total_users: int
    eligible_users: int
    users_voted: int
    participation_rate: float

    # Conversion
    free_to_eligible_conversions: int
    eligible_to_voted_conversions: int

    # Engagement
    avg_time_to_vote_hours: float
    vote_changes_count: int

    # Projects
    active_projects: int
    total_weighted_votes: int
    winner_project_id: Optional[UUID]
    winner_margin_percent: float


class UserVotingHistory(BaseSchema):
    """Schema storico voti utente."""
    user_id: UUID
    votes: List[ProjectVoteResponse]
    total_cycles_participated: int
    current_streak: int
    longest_streak: int

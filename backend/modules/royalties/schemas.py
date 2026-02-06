"""
AI_MODULE: Royalty Pydantic Schemas
AI_DESCRIPTION: Schemas validazione API per sistema royalties
AI_BUSINESS: Type-safe API contracts, validazione automatica input
AI_TEACHING: Pydantic v2, Field validators, computed properties

ALTERNATIVE_VALUTATE:
- Marshmallow: Scartato, meno integrato con FastAPI
- Dataclasses: Scartato, meno features validazione
- TypedDict: Scartato, no runtime validation

PERCHE_QUESTA_SOLUZIONE:
- Pydantic v2: Performance 17x migliori di v1
- FastAPI integration: Automatic OpenAPI docs
- Field validators: Business logic validation
- Computed properties: Derived fields on-the-fly

METRICHE_SUCCESSO:
- Validation time: <1ms per request
- Schema coverage: 100% endpoints
- Type errors: 0 at runtime
"""

from datetime import datetime
from typing import Optional, Dict, List, Any
from uuid import UUID
from pydantic import BaseModel, Field, field_validator, computed_field
from enum import Enum


# ======================== ENUMS ========================

class PricingModelEnum(str, Enum):
    """Modello pricing."""
    FREE = "free"
    INCLUDED = "included"
    PREMIUM = "premium"
    CUSTOM = "custom"


class PayoutMethodEnum(str, Enum):
    """Metodo payout."""
    BLOCKCHAIN = "blockchain"
    STRIPE = "stripe"
    BANK = "bank"
    PAYPAL = "paypal"


class PayoutStatusEnum(str, Enum):
    """Status payout."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SubscriptionTypeEnum(str, Enum):
    """Tipo subscription."""
    PLATFORM = "platform"
    MASTER = "master"
    PER_VIDEO = "per_video"


class RoyaltyMilestoneEnum(str, Enum):
    """Milestone view."""
    STARTED = "started"
    PERCENT_25 = "25"
    PERCENT_50 = "50"
    PERCENT_75 = "75"
    COMPLETED = "completed"


# ======================== BASE SCHEMAS ========================

class BaseSchema(BaseModel):
    """Base schema con config comune."""

    class Config:
        from_attributes = True
        populate_by_name = True


# ======================== MASTER PROFILE SCHEMAS ========================

class MasterProfileCreate(BaseSchema):
    """
    Schema creazione profilo maestro royalties.

    Richiede solo user_id, resto ha defaults.
    """
    user_id: UUID = Field(..., description="ID utente maestro")
    maestro_id: Optional[UUID] = Field(None, description="ID profilo Maestro esistente")
    pricing_model: PricingModelEnum = Field(
        PricingModelEnum.INCLUDED,
        description="Modello pricing contenuti"
    )
    payout_method: PayoutMethodEnum = Field(
        PayoutMethodEnum.STRIPE,
        description="Metodo pagamento preferito"
    )
    wallet_address: Optional[str] = Field(
        None,
        max_length=42,
        description="Wallet address per pagamenti crypto"
    )

    @field_validator('wallet_address')
    @classmethod
    def validate_wallet(cls, v):
        """Valida formato Ethereum address."""
        if v is not None:
            if not v.startswith('0x') or len(v) != 42:
                raise ValueError('Invalid Ethereum address format')
        return v


class MasterProfileUpdate(BaseSchema):
    """
    Schema update profilo maestro.

    Tutti i campi optional per partial update.
    """
    pricing_model: Optional[PricingModelEnum] = None
    custom_prices: Optional[Dict[str, int]] = Field(
        None,
        description="Override prezzi per subscription type"
    )
    royalty_override: Optional[Dict[str, int]] = Field(
        None,
        description="Override % royalty split"
    )
    milestone_override: Optional[Dict[str, float]] = Field(
        None,
        description="Override importi milestone"
    )
    payout_method: Optional[PayoutMethodEnum] = None
    wallet_address: Optional[str] = Field(None, max_length=42)
    min_payout_override: Optional[int] = Field(None, ge=100)
    iban: Optional[str] = Field(None, max_length=34)
    paypal_email: Optional[str] = Field(None, max_length=255)

    @field_validator('royalty_override')
    @classmethod
    def validate_royalty_split(cls, v):
        """Valida che split = 100%."""
        if v is not None:
            platform = v.get('platform_fee_percent', 0)
            master = v.get('master_share_percent', 0)
            if platform + master != 100:
                raise ValueError(f'Royalty split must equal 100%, got {platform + master}%')
        return v


class MasterProfileResponse(BaseSchema):
    """
    Schema response profilo maestro.

    Include stats denormalizzati per dashboard.
    """
    id: UUID
    user_id: UUID
    maestro_id: Optional[UUID]
    pricing_model: PricingModelEnum
    custom_prices: Optional[Dict[str, int]]
    royalty_override: Optional[Dict[str, int]]
    milestone_override: Optional[Dict[str, float]]
    payout_method: PayoutMethodEnum
    wallet_address: Optional[str]
    min_payout_override: Optional[int]
    is_active: bool
    verified_for_payouts: bool
    verification_date: Optional[datetime]

    # Stats
    total_views: int
    total_royalties_cents: int
    total_paid_out_cents: int
    pending_payout_cents: int
    total_subscribers: int

    created_at: datetime
    updated_at: datetime
    last_payout_at: Optional[datetime]

    @computed_field
    @property
    def total_royalties_eur(self) -> float:
        """Royalties totali in EUR."""
        return self.total_royalties_cents / 100

    @computed_field
    @property
    def pending_payout_eur(self) -> float:
        """Payout pendente in EUR."""
        return self.pending_payout_cents / 100


# ======================== SUBSCRIPTION SCHEMAS ========================

class StudentSubscriptionCreate(BaseSchema):
    """
    Schema creazione abbonamento studente.
    """
    student_id: UUID = Field(..., description="ID studente")
    master_id: Optional[UUID] = Field(
        None,
        description="ID maestro (null = abbonamento piattaforma)"
    )
    subscription_type: SubscriptionTypeEnum = Field(
        ...,
        description="Tipo abbonamento"
    )
    subscription_tier: str = Field(
        ...,
        description="Tier (monthly/yearly/lifetime/per_video)"
    )
    video_id: Optional[UUID] = Field(
        None,
        description="ID video (solo per per_video)"
    )
    auto_renew: bool = Field(True, description="Rinnovo automatico")

    @field_validator('subscription_tier')
    @classmethod
    def validate_tier(cls, v):
        """Valida tier valido."""
        valid_tiers = ['monthly', 'yearly', 'lifetime', 'per_video']
        if v not in valid_tiers:
            raise ValueError(f'Invalid tier. Must be one of: {valid_tiers}')
        return v


class StudentSubscriptionResponse(BaseSchema):
    """
    Schema response abbonamento.
    """
    id: UUID
    student_id: UUID
    master_id: Optional[UUID]
    subscription_type: SubscriptionTypeEnum
    subscription_tier: str
    price_paid_cents: int
    currency: str
    started_at: datetime
    expires_at: Optional[datetime]
    cancelled_at: Optional[datetime]
    auto_renew: bool
    is_active: bool
    video_id: Optional[UUID]
    created_at: datetime

    @computed_field
    @property
    def price_paid_eur(self) -> float:
        """Prezzo pagato in EUR."""
        return self.price_paid_cents / 100

    @computed_field
    @property
    def is_expired(self) -> bool:
        """Check se scaduto."""
        if self.expires_at is None:
            return False
        return self.expires_at < datetime.utcnow()

    @computed_field
    @property
    def days_remaining(self) -> int:
        """Giorni rimanenti (-1 = lifetime)."""
        if self.expires_at is None:
            return -1
        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.days)


# ======================== VIEW ROYALTY SCHEMAS ========================

class TrackViewRequest(BaseSchema):
    """
    Schema richiesta tracking view.

    Chiamato dal video player ai milestone.
    """
    video_id: UUID = Field(..., description="ID video")
    view_session_id: UUID = Field(..., description="ID sessione view")
    milestone: str = Field(..., description="Milestone raggiunto (started, 25, 50, 75, completed)")
    watch_time_seconds: int = Field(..., ge=0, description="Secondi guardati")
    video_duration_seconds: int = Field(..., ge=1, description="Durata totale video")

    # Context (per fraud detection)
    device_fingerprint: Optional[str] = Field(None, max_length=64)

    @field_validator('milestone')
    @classmethod
    def validate_milestone(cls, v):
        """Valida milestone value."""
        valid_milestones = ['started', '25', '50', '75', 'completed']
        if v.lower() not in valid_milestones:
            raise ValueError(f'milestone must be one of: {", ".join(valid_milestones)}')
        return v.lower()

    @field_validator('watch_time_seconds')
    @classmethod
    def validate_watch_time(cls, v, info):
        """Valida watch_time <= duration."""
        duration = info.data.get('video_duration_seconds', 0)
        if duration > 0 and v > duration * 1.1:  # 10% tolerance
            raise ValueError('watch_time cannot exceed video duration')
        return v


class TrackViewResponse(BaseSchema):
    """
    Schema response tracking view.
    """
    success: bool
    royalty_id: Optional[UUID]
    milestone: RoyaltyMilestoneEnum
    amount_cents: int
    message: str

    @computed_field
    @property
    def amount_eur(self) -> float:
        """Importo in EUR."""
        return self.amount_cents / 100


class ViewRoyaltyCreate(BaseSchema):
    """
    Schema creazione royalty (internal use).
    """
    video_id: UUID
    master_id: UUID
    student_id: Optional[UUID]
    view_session_id: UUID
    milestone: RoyaltyMilestoneEnum
    gross_amount_cents: int
    platform_fee_cents: int
    master_amount_cents: int
    video_duration_seconds: Optional[int]
    watch_time_seconds: Optional[int]
    ip_hash: Optional[str]
    device_fingerprint: Optional[str]
    country_code: Optional[str]


class ViewRoyaltyResponse(BaseSchema):
    """
    Schema response royalty view.
    """
    id: UUID
    video_id: Optional[UUID]
    master_id: UUID
    student_id: Optional[UUID]
    view_session_id: UUID
    milestone: RoyaltyMilestoneEnum
    gross_amount_cents: int
    platform_fee_cents: int
    master_amount_cents: int
    blockchain_tx_hash: Optional[str]
    blockchain_verified: bool
    settled: bool
    settled_at: Optional[datetime]
    fraud_score: float
    flagged_suspicious: bool
    created_at: datetime

    @computed_field
    @property
    def master_amount_eur(self) -> float:
        """Importo maestro in EUR."""
        return self.master_amount_cents / 100


# ======================== PAYOUT SCHEMAS ========================

class PayoutRequestCreate(BaseSchema):
    """
    Schema richiesta payout da maestro.
    """
    master_id: UUID = Field(..., description="ID profilo maestro")
    method: Optional[PayoutMethodEnum] = Field(
        None,
        description="Metodo payout (null = usa default profilo)"
    )
    notes: Optional[str] = Field(None, max_length=500)


class RoyaltyPayoutResponse(BaseSchema):
    """
    Schema response payout.
    """
    id: UUID
    master_id: UUID
    gross_amount_cents: int
    fees_cents: int
    net_amount_cents: int
    currency: str
    period_start: datetime
    period_end: datetime
    views_count: int
    method: PayoutMethodEnum
    status: PayoutStatusEnum
    blockchain_tx_hash: Optional[str]
    blockchain_network: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    requested_at: Optional[datetime]
    completed_at: Optional[datetime]

    @computed_field
    @property
    def net_amount_eur(self) -> float:
        """Importo netto in EUR."""
        return self.net_amount_cents / 100


# ======================== DASHBOARD SCHEMAS ========================

class RoyaltyDashboard(BaseSchema):
    """
    Schema dashboard royalties maestro.

    Aggregazione dati per UI dashboard.
    """
    master_id: UUID
    period_start: datetime
    period_end: datetime

    # Totals
    total_views: int
    total_royalties_cents: int
    pending_payout_cents: int
    last_payout_amount_cents: int
    last_payout_date: Optional[datetime]

    # Breakdown by milestone
    milestone_breakdown: Dict[str, int]  # milestone -> count

    # Daily trend (last 30 days)
    daily_views: List[Dict[str, Any]]  # [{date, views, amount}]

    # Top videos
    top_videos: List[Dict[str, Any]]  # [{video_id, title, views, amount}]

    # Subscriber count
    total_subscribers: int
    new_subscribers_period: int

    # Payout status
    can_request_payout: bool
    min_payout_cents: int
    next_auto_payout_date: Optional[datetime]

    @computed_field
    @property
    def total_royalties_eur(self) -> float:
        """Royalties totali in EUR."""
        return self.total_royalties_cents / 100

    @computed_field
    @property
    def pending_payout_eur(self) -> float:
        """Payout pendente in EUR."""
        return self.pending_payout_cents / 100


class RoyaltyStats(BaseSchema):
    """
    Schema statistiche globali royalties (admin).
    """
    period_start: datetime
    period_end: datetime

    # Platform totals
    total_views: int
    total_royalties_cents: int
    total_platform_fees_cents: int
    total_paid_out_cents: int
    total_pending_cents: int

    # Masters
    active_masters: int
    masters_with_pending: int
    avg_payout_cents: int

    # Subscriptions
    total_active_subscriptions: int
    new_subscriptions_period: int
    subscription_revenue_cents: int

    # Blockchain
    blockchain_batches: int
    blockchain_verified_views: int
    total_gas_cost_cents: int


# ======================== CONFIG SCHEMAS ========================

class RoyaltyConfigResponse(BaseSchema):
    """
    Schema response configurazione royalties.
    """
    student_master_mode: str
    max_masters_per_student: int
    master_switch_cooldown_days: int

    subscription_types: Dict[str, Dict[str, Any]]

    royalty_milestones: Dict[str, float]
    revenue_split: Dict[str, int]

    min_payout_cents: int
    payout_frequency: str
    payout_processing_days: int

    blockchain_enabled: bool
    blockchain_network: str

    fraud_detection_enabled: bool
    max_views_per_user_per_video_per_day: int


class RoyaltyConfigUpdate(BaseSchema):
    """
    Schema update configurazione (admin only).
    """
    student_master_mode: Optional[str] = None
    max_masters_per_student: Optional[int] = Field(None, ge=1)
    master_switch_cooldown_days: Optional[int] = Field(None, ge=0)

    royalty_milestones: Optional[Dict[str, float]] = None
    revenue_split: Optional[Dict[str, int]] = None

    min_payout_cents: Optional[int] = Field(None, ge=100)
    payout_frequency: Optional[str] = None

    blockchain_enabled: Optional[bool] = None
    fraud_detection_enabled: Optional[bool] = None

    @field_validator('revenue_split')
    @classmethod
    def validate_split(cls, v):
        """Valida split = 100%."""
        if v is not None:
            total = v.get('platform_fee_percent', 0) + v.get('master_share_percent', 0)
            if total != 100:
                raise ValueError(f'Revenue split must equal 100%, got {total}%')
        return v


# ======================== VERIFICATION SCHEMAS ========================

class BlockchainVerifyRequest(BaseSchema):
    """
    Schema richiesta verifica blockchain.
    """
    view_id: UUID = Field(..., description="ID view royalty da verificare")


class BlockchainVerifyResponse(BaseSchema):
    """
    Schema response verifica blockchain.
    """
    verified: bool
    view_id: UUID
    batch_id: Optional[UUID]
    tx_hash: Optional[str]
    merkle_root: Optional[str]
    merkle_proof: Optional[List[str]]
    ipfs_hash: Optional[str]
    block_number: Optional[int]
    confirmations: int
    error: Optional[str]


# ======================== AVAILABLE MASTERS SCHEMA ========================

class AvailableMasterResponse(BaseSchema):
    """
    Schema maestro disponibile per subscription.
    """
    master_id: UUID
    user_id: UUID
    name: str
    avatar_url: Optional[str]
    pricing_model: PricingModelEnum
    disciplines: List[str]
    bio: Optional[str]
    total_videos: int
    total_subscribers: int

    # Pricing per questo maestro
    monthly_price_cents: Optional[int]
    yearly_price_cents: Optional[int]
    lifetime_price_cents: Optional[int]

    # Rating
    avg_rating: Optional[float]
    total_reviews: int

    @computed_field
    @property
    def monthly_price_eur(self) -> Optional[float]:
        """Prezzo mensile in EUR."""
        if self.monthly_price_cents:
            return self.monthly_price_cents / 100
        return None

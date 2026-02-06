"""
🎓 AI_MODULE: Events Pydantic Schemas
🎓 AI_DESCRIPTION: Schemas validazione per eventi/stage ASD - Pydantic v2
🎓 AI_BUSINESS: Validazione input/output API eventi, prevendita, pagamenti
🎓 AI_TEACHING: Pydantic v2, field_validator, model_validator, ConfigDict

🔄 ALTERNATIVE_VALUTATE:
- Marshmallow: Scartato, Pydantic v2 più integrato con FastAPI
- dataclasses: Scartato, meno validazione built-in
- attrs: Scartato, meno supporto JSON serialization

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Pydantic v2: Performance migliori, ConfigDict, pattern (non regex)
- Validators: Cross-field validation per date, prezzi
- Optional computed: Per response con campi calcolati
"""

from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, date
from uuid import UUID
from decimal import Decimal
import re

from modules.events.models import (
    EventStatus,
    SubscriptionStatus,
    RefundStatus,
    AlertType,
    NotificationChannel,
    PresaleCriteriaType,
    RefundApprovalMode
)


# ======================== BASE SCHEMA ========================

class BaseSchema(BaseModel):
    """Base schema con configurazione comune."""
    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True
    )


# ======================== ASD PARTNER SCHEMAS ========================

class ASDPartnerCreate(BaseSchema):
    """Schema creazione ASD Partner."""
    name: str = Field(..., min_length=2, max_length=255)
    slug: Optional[str] = Field(None, max_length=100, pattern=r'^[a-z0-9-]+$')
    description: Optional[str] = None
    logo_url: Optional[str] = None
    website: Optional[str] = None

    # Contact
    email: str = Field(..., max_length=255)
    phone: Optional[str] = Field(None, max_length=50)
    address: Optional[str] = None
    city: Optional[str] = Field(None, max_length=100)
    province: Optional[str] = Field(None, max_length=10)
    postal_code: Optional[str] = Field(None, max_length=10)
    country: str = Field(default="Italia", max_length=100)

    # Legal
    fiscal_code: Optional[str] = Field(None, max_length=16)
    vat_number: Optional[str] = Field(None, max_length=20)

    # Config
    default_split_percentage: float = Field(default=85.0, ge=0, le=100)
    refund_approval_mode: RefundApprovalMode = RefundApprovalMode.PER_EVENT

    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        """Validate email format."""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('Invalid email format')
        return v.lower()

    @field_validator('slug')
    @classmethod
    def generate_slug(cls, v: Optional[str], info) -> str:
        """Generate slug from name if not provided."""
        if v:
            return v.lower()
        # Will be generated in service if None
        return v


class ASDPartnerUpdate(BaseSchema):
    """Schema aggiornamento ASD Partner."""
    name: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = None
    logo_url: Optional[str] = None
    website: Optional[str] = None

    email: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=50)
    address: Optional[str] = None
    city: Optional[str] = Field(None, max_length=100)
    province: Optional[str] = Field(None, max_length=10)
    postal_code: Optional[str] = Field(None, max_length=10)

    default_split_percentage: Optional[float] = Field(None, ge=0, le=100)
    refund_approval_mode: Optional[RefundApprovalMode] = None
    is_active: Optional[bool] = None


class ASDPartnerResponse(BaseSchema):
    """Schema response ASD Partner."""
    id: UUID
    name: str
    slug: str
    description: Optional[str]
    logo_url: Optional[str]
    website: Optional[str]

    email: str
    phone: Optional[str]
    city: Optional[str]
    country: str

    stripe_account_id: Optional[str]
    stripe_account_status: str
    stripe_onboarding_complete: bool

    default_split_percentage: float
    refund_approval_mode: RefundApprovalMode

    is_active: bool
    is_verified: bool

    created_at: datetime
    updated_at: datetime


class ASDPartnerPublicResponse(BaseSchema):
    """Schema response pubblico ASD Partner (no dati sensibili)."""
    id: UUID
    name: str
    slug: str
    description: Optional[str]
    logo_url: Optional[str]
    website: Optional[str]
    city: Optional[str]
    country: str
    is_verified: bool


# ======================== EVENT SCHEMAS ========================

class PresaleCriteriaSchema(BaseSchema):
    """Schema criteri prevendita."""
    type: PresaleCriteriaType
    emails: Optional[List[str]] = None  # Per EMAIL_LIST
    subscription_types: Optional[List[str]] = None  # Per SUBSCRIPTION_ACTIVE
    course_ids: Optional[List[UUID]] = None  # Per COURSE_PURCHASED
    learning_path_ids: Optional[List[UUID]] = None  # Per LEARNING_PATH
    min_tier: Optional[str] = None  # Per TIER_MINIMUM

    @model_validator(mode='after')
    def validate_criteria(self):
        """Validate criteria based on type."""
        if self.type == PresaleCriteriaType.EMAIL_LIST and not self.emails:
            raise ValueError('emails required for EMAIL_LIST type')
        if self.type == PresaleCriteriaType.SUBSCRIPTION_ACTIVE and not self.subscription_types:
            raise ValueError('subscription_types required for SUBSCRIPTION_ACTIVE type')
        if self.type == PresaleCriteriaType.COURSE_PURCHASED and not self.course_ids:
            raise ValueError('course_ids required for COURSE_PURCHASED type')
        if self.type == PresaleCriteriaType.LEARNING_PATH and not self.learning_path_ids:
            raise ValueError('learning_path_ids required for LEARNING_PATH type')
        if self.type == PresaleCriteriaType.TIER_MINIMUM and not self.min_tier:
            raise ValueError('min_tier required for TIER_MINIMUM type')
        return self


class LocationSchema(BaseSchema):
    """Schema location evento."""
    name: Optional[str] = Field(None, max_length=255)
    address: Optional[str] = None
    city: Optional[str] = Field(None, max_length=100)
    country: str = Field(default="Italia", max_length=100)
    coordinates: Optional[Dict[str, float]] = None  # {"lat": x, "lng": y}


class AlertConfigOverrideSchema(BaseSchema):
    """Schema override config alert per evento."""
    reminder_days: Optional[List[int]] = None  # [7, 3, 1]
    threshold_warning_enabled: Optional[bool] = None
    low_capacity_threshold: Optional[int] = None  # Notifica quando restano N posti
    channels: Optional[Dict[str, bool]] = None  # {"email": true, "push": true}


class EventCreate(BaseSchema):
    """Schema creazione evento."""
    asd_id: UUID
    title: str = Field(..., min_length=3, max_length=255)
    slug: Optional[str] = Field(None, max_length=150, pattern=r'^[a-z0-9-]+$')
    description: Optional[str] = None
    short_description: Optional[str] = Field(None, max_length=500)
    cover_image_url: Optional[str] = None

    # Dates
    start_date: date
    end_date: date

    # Presale
    presale_start: Optional[datetime] = None
    presale_end: Optional[datetime] = None
    sale_start: Optional[datetime] = None
    presale_enabled: bool = False
    presale_criteria: Optional[PresaleCriteriaSchema] = None

    # Capacity
    total_capacity: int = Field(..., gt=0)
    min_threshold: Optional[int] = Field(None, ge=0)

    # Location
    location: Optional[LocationSchema] = None

    # Bundle
    bundle_course_id: Optional[UUID] = None
    bundle_discount_percent: float = Field(default=0, ge=0, le=100)

    # Payment
    split_percentage: Optional[float] = Field(None, ge=0, le=100)

    # Refund
    requires_refund_approval: Optional[bool] = None

    # Alert override
    alert_config_override: Optional[AlertConfigOverrideSchema] = None

    # Metadata
    discipline: Optional[str] = Field(None, max_length=100)
    instructor_name: Optional[str] = Field(None, max_length=255)
    instructor_bio: Optional[str] = None

    @model_validator(mode='after')
    def validate_dates(self):
        """Validate event dates."""
        if self.end_date < self.start_date:
            raise ValueError('end_date must be >= start_date')

        if self.presale_enabled and not self.presale_start:
            raise ValueError('presale_start required when presale_enabled')

        if self.presale_start and self.presale_end:
            if self.presale_end <= self.presale_start:
                raise ValueError('presale_end must be > presale_start')

        if self.sale_start and self.presale_end:
            if self.sale_start < self.presale_end:
                raise ValueError('sale_start must be >= presale_end')

        if self.min_threshold and self.min_threshold > self.total_capacity:
            raise ValueError('min_threshold cannot exceed total_capacity')

        return self


class EventUpdate(BaseSchema):
    """Schema aggiornamento evento."""
    title: Optional[str] = Field(None, min_length=3, max_length=255)
    description: Optional[str] = None
    short_description: Optional[str] = Field(None, max_length=500)
    cover_image_url: Optional[str] = None

    start_date: Optional[date] = None
    end_date: Optional[date] = None

    presale_start: Optional[datetime] = None
    presale_end: Optional[datetime] = None
    sale_start: Optional[datetime] = None
    presale_enabled: Optional[bool] = None
    presale_criteria: Optional[PresaleCriteriaSchema] = None

    total_capacity: Optional[int] = Field(None, gt=0)
    min_threshold: Optional[int] = Field(None, ge=0)

    location: Optional[LocationSchema] = None

    bundle_course_id: Optional[UUID] = None
    bundle_discount_percent: Optional[float] = Field(None, ge=0, le=100)

    split_percentage: Optional[float] = Field(None, ge=0, le=100)
    requires_refund_approval: Optional[bool] = None

    alert_config_override: Optional[AlertConfigOverrideSchema] = None

    discipline: Optional[str] = Field(None, max_length=100)
    instructor_name: Optional[str] = Field(None, max_length=255)
    instructor_bio: Optional[str] = None


class EventOptionResponse(BaseSchema):
    """Schema response opzione evento."""
    id: UUID
    name: str
    description: Optional[str]
    start_date: date
    end_date: date
    price_cents: int
    early_bird_price_cents: Optional[int]
    early_bird_deadline: Optional[datetime]
    current_price_cents: int
    includes_bundle: bool
    duration_days: int
    is_active: bool


class EventResponse(BaseSchema):
    """Schema response evento."""
    id: UUID
    asd_id: UUID
    asd_partner: Optional[ASDPartnerPublicResponse] = None

    title: str
    slug: str
    description: Optional[str]
    short_description: Optional[str]
    cover_image_url: Optional[str]

    start_date: date
    end_date: date
    duration_days: int

    presale_start: Optional[datetime]
    presale_end: Optional[datetime]
    sale_start: Optional[datetime]
    presale_enabled: bool

    total_capacity: int
    current_subscriptions: int
    available_spots: int
    min_threshold: Optional[int]
    is_sold_out: bool
    is_below_threshold: bool

    location_name: Optional[str]
    location_city: Optional[str]
    location_country: str

    bundle_course_id: Optional[UUID]
    bundle_discount_percent: float

    discipline: Optional[str]
    instructor_name: Optional[str]
    instructor_bio: Optional[str]

    status: EventStatus
    published_at: Optional[datetime]

    options: List[EventOptionResponse] = []

    created_at: datetime
    updated_at: datetime


class EventListResponse(BaseSchema):
    """Schema response lista eventi (senza dettagli)."""
    id: UUID
    asd_id: UUID
    title: str
    slug: str
    short_description: Optional[str]
    cover_image_url: Optional[str]
    start_date: date
    end_date: date
    location_city: Optional[str]
    total_capacity: int
    available_spots: int
    is_sold_out: bool
    status: EventStatus
    discipline: Optional[str]
    min_price_cents: Optional[int] = None  # Prezzo minimo tra opzioni


# ======================== EVENT OPTION SCHEMAS ========================

class EventOptionCreate(BaseSchema):
    """Schema creazione opzione evento."""
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    start_date: date
    end_date: date
    price_cents: int = Field(..., gt=0)
    early_bird_price_cents: Optional[int] = Field(None, gt=0)
    early_bird_deadline: Optional[datetime] = None
    includes_bundle: bool = True
    sort_order: int = 0

    @model_validator(mode='after')
    def validate_option(self):
        """Validate option dates and prices."""
        if self.end_date < self.start_date:
            raise ValueError('end_date must be >= start_date')

        if self.early_bird_price_cents and not self.early_bird_deadline:
            raise ValueError('early_bird_deadline required with early_bird_price')

        if self.early_bird_price_cents and self.early_bird_price_cents >= self.price_cents:
            raise ValueError('early_bird_price must be < regular price')

        return self


class EventOptionUpdate(BaseSchema):
    """Schema aggiornamento opzione evento."""
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    description: Optional[str] = None
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    price_cents: Optional[int] = Field(None, gt=0)
    early_bird_price_cents: Optional[int] = Field(None, gt=0)
    early_bird_deadline: Optional[datetime] = None
    includes_bundle: Optional[bool] = None
    is_active: Optional[bool] = None
    sort_order: Optional[int] = None


# ======================== SUBSCRIPTION SCHEMAS ========================

class ParticipantInfoSchema(BaseSchema):
    """Schema info partecipante (se diverso da user)."""
    name: Optional[str] = Field(None, max_length=255)
    email: Optional[str] = Field(None, max_length=255)
    phone: Optional[str] = Field(None, max_length=50)
    dietary_requirements: Optional[str] = None
    notes: Optional[str] = None


class EventSubscriptionCreate(BaseSchema):
    """Schema creazione iscrizione (checkout)."""
    event_id: UUID
    option_id: UUID
    participant_info: Optional[ParticipantInfoSchema] = None

    # Per checkout Stripe
    success_url: str
    cancel_url: str


class EventSubscriptionResponse(BaseSchema):
    """Schema response iscrizione."""
    id: UUID
    event_id: UUID
    option_id: UUID
    user_id: UUID

    amount_cents: int
    currency: str
    asd_amount_cents: int
    platform_amount_cents: int

    status: SubscriptionStatus

    participant_name: Optional[str]
    participant_email: Optional[str]

    bundle_course_granted: bool

    confirmed_at: Optional[datetime]
    cancelled_at: Optional[datetime]
    refunded_at: Optional[datetime]

    created_at: datetime

    # Nested
    event: Optional[EventListResponse] = None
    option: Optional[EventOptionResponse] = None


class CheckoutResponse(BaseSchema):
    """Schema response checkout Stripe."""
    subscription_id: UUID
    checkout_url: str
    stripe_session_id: str


# ======================== WAITING LIST SCHEMAS ========================

class WaitingListJoinRequest(BaseSchema):
    """Schema richiesta join waiting list."""
    event_id: UUID
    preferred_option_id: Optional[UUID] = None


class WaitingListResponse(BaseSchema):
    """Schema response waiting list."""
    id: UUID
    event_id: UUID
    user_id: UUID
    preferred_option_id: Optional[UUID]
    position: Optional[int] = None  # Posizione in lista
    is_active: bool
    notified_at: Optional[datetime]
    notification_count: int
    created_at: datetime


# ======================== REFUND SCHEMAS ========================

class RefundRequestCreate(BaseSchema):
    """Schema creazione richiesta rimborso."""
    subscription_id: UUID
    reason: str = Field(..., min_length=10, max_length=1000)
    requested_amount_cents: Optional[int] = Field(None, gt=0)  # null = full


class RefundRequestResponse(BaseSchema):
    """Schema response richiesta rimborso."""
    id: UUID
    subscription_id: UUID
    asd_id: UUID

    reason: str
    requested_amount_cents: Optional[int]

    status: RefundStatus
    requires_approval: bool

    approved_at: Optional[datetime]
    rejection_reason: Optional[str]

    processed_at: Optional[datetime]
    processed_amount_cents: Optional[int]

    created_at: datetime
    updated_at: datetime


class RefundApprovalRequest(BaseSchema):
    """Schema approvazione/rifiuto rimborso."""
    approved: bool
    rejection_reason: Optional[str] = None
    notes: Optional[str] = None

    @model_validator(mode='after')
    def validate_rejection(self):
        """Validate rejection reason required if not approved."""
        if not self.approved and not self.rejection_reason:
            raise ValueError('rejection_reason required when not approved')
        return self


# ======================== ALERT CONFIG SCHEMAS ========================

class AlertChannelConfig(BaseSchema):
    """Schema config canali alert."""
    email: bool = True
    push: bool = True
    dashboard: bool = True
    sms: bool = False


class AlertConfigUpdate(BaseSchema):
    """Schema aggiornamento config alert piattaforma."""
    enabled: Optional[bool] = None
    days_before: Optional[List[int]] = None
    channels: Optional[AlertChannelConfig] = None
    email_template_id: Optional[str] = None
    push_template: Optional[str] = None


class AlertConfigResponse(BaseSchema):
    """Schema response config alert."""
    id: UUID
    alert_type: AlertType
    enabled: bool
    days_before: Optional[List[int]]
    email_enabled: bool
    push_enabled: bool
    dashboard_enabled: bool
    sms_enabled: bool
    email_template_id: Optional[str]
    updated_at: datetime


# ======================== DASHBOARD SCHEMAS ========================

class ASDDashboardStats(BaseSchema):
    """Schema stats dashboard ASD."""
    total_events: int
    active_events: int
    upcoming_events: int
    completed_events: int

    total_subscriptions: int
    confirmed_subscriptions: int
    pending_refunds: int

    total_revenue_cents: int
    asd_revenue_cents: int

    waiting_list_count: int


class EventParticipantResponse(BaseSchema):
    """Schema partecipante evento (per ASD)."""
    subscription_id: UUID
    user_id: UUID
    user_email: str
    user_name: Optional[str]

    option_name: str
    amount_cents: int
    status: SubscriptionStatus

    participant_name: Optional[str]
    participant_email: Optional[str]
    participant_phone: Optional[str]
    dietary_requirements: Optional[str]
    notes: Optional[str]

    confirmed_at: Optional[datetime]
    created_at: datetime


# ======================== NOTIFICATION SCHEMAS ========================

class NotificationCreateRequest(BaseSchema):
    """Schema creazione notifica manuale."""
    event_id: UUID
    alert_type: AlertType
    scheduled_for: datetime
    recipient_type: str = Field(..., pattern=r'^(all_subscribers|waiting_list|specific_user)$')
    recipient_user_id: Optional[UUID] = None
    channels: List[NotificationChannel]
    subject: Optional[str] = None
    body: Optional[str] = None


class NotificationResponse(BaseSchema):
    """Schema response notifica."""
    id: UUID
    event_id: UUID
    alert_type: AlertType
    scheduled_for: datetime
    recipient_type: str
    channels: List[str]
    subject: Optional[str]
    sent: bool
    sent_at: Optional[datetime]
    created_at: datetime


# ======================== STRIPE SCHEMAS ========================

class StripeOnboardingResponse(BaseSchema):
    """Schema response onboarding Stripe Connect."""
    onboarding_url: str
    stripe_account_id: str


class StripeAccountStatus(BaseSchema):
    """Schema status account Stripe."""
    account_id: str
    status: str
    onboarding_complete: bool
    charges_enabled: bool
    payouts_enabled: bool
    details_submitted: bool

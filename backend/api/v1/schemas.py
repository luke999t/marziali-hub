"""
🎓 AI_MODULE: Pydantic Schemas
🎓 AI_DESCRIPTION: Request/Response validation schemas
🎓 AI_BUSINESS: Type safety + auto validation + OpenAPI docs
🎓 AI_TEACHING: Pydantic models per FastAPI
"""

from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field, validator, field_serializer, field_validator
from typing import Optional, List, Union
from datetime import datetime
from enum import Enum
from uuid import UUID


# === BASE SCHEMAS ===

class MessageResponse(BaseModel):
    """Standard message response."""
    message: str
    success: bool = True


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    message: str
    details: Optional[dict] = None


# === AUTH SCHEMAS ===

class UserRegisterRequest(BaseModel):
    """User registration request."""
    email: EmailStr = Field(..., description="Valid email address")
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    password: str = Field(..., min_length=8, max_length=100, description="Strong password")
    full_name: Optional[str] = Field(None, max_length=255, description="Full name")

    @validator('password')
    def validate_password(cls, v):
        """
        Validate password strength.

        🎯 SECURITY: Require strong passwords
        """
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v

    @validator('username')
    def validate_username(cls, v):
        """Validate username format."""
        if not v.isalnum() and '_' not in v:
            raise ValueError('Username can only contain letters, numbers, and underscores')
        return v


class UserLoginRequest(BaseModel):
    """User login request."""
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., description="Password")


class UserResponse(BaseModel):
    """User response model."""
    id: Union[str, UUID]
    email: EmailStr
    username: str
    full_name: Optional[str]
    tier: str
    is_active: bool
    is_admin: bool
    email_verified: bool
    created_at: datetime
    subscription_end: Optional[datetime] = None
    last_login: Optional[datetime] = None

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Expiry time in seconds")
    user: UserResponse


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""
    refresh_token: str = Field(..., description="Valid refresh token")


class VideoProgressUpdate(BaseModel):
    """Video progress update request."""
    position_seconds: int = Field(..., ge=0, description="Current playback position in seconds")
    quality: Optional[str] = Field(None, description="Current quality setting")


# === VIDEO SCHEMAS ===

class VideoCategory(str, Enum):
    """Video categories."""
    TECHNIQUE = "technique"
    KATA = "kata"
    COMBAT = "combat"
    THEORY = "theory"
    WORKOUT = "workout"
    DEMO = "demo"
    OTHER = "other"


class Difficulty(str, Enum):
    """Difficulty levels."""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class VideoCreateRequest(BaseModel):
    """Video creation request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    category: VideoCategory
    difficulty: Difficulty
    style: Optional[str] = Field(None, max_length=100)
    tags: List[str] = Field(default_factory=list)
    tier_required: str = Field(default="free")
    is_premium: bool = Field(default=False)
    ppv_price: Optional[float] = Field(None, ge=0, description="Pay-per-view price in EUR")
    instructor_name: Optional[str] = None


class VideoUpdateRequest(BaseModel):
    """Video update request."""
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[VideoCategory] = None
    difficulty: Optional[Difficulty] = None
    tags: Optional[List[str]] = None
    tier_required: Optional[str] = None
    is_premium: Optional[bool] = None
    ppv_price: Optional[float] = Field(None, ge=0)


class VideoResponse(BaseModel):
    """Video response model."""
    id: Union[str, UUID]
    title: str
    description: Optional[str]
    slug: str
    category: str
    difficulty: str
    style: Optional[str]
    tags: List[str] = []
    thumbnail_url: Optional[str]
    video_url: str
    hls_playlist_url: Optional[str]
    duration: int
    quality_available: List[str] = []
    has_subtitles: bool
    available_languages: List[str] = []
    view_count: int
    tier_required: str
    is_premium: bool
    ppv_price: Optional[float]
    status: str
    created_at: datetime
    published_at: Optional[datetime]

    @field_validator('tags', 'quality_available', 'available_languages', mode='before')
    @classmethod
    def convert_none_to_list(cls, v):
        """Convert None to empty list."""
        return v if v is not None else []

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


class VideoListResponse(BaseModel):
    """Video list response with pagination."""
    videos: List[VideoResponse]
    total: int
    skip: int
    limit: int


# === SUBSCRIPTION SCHEMAS ===

class SubscriptionTier(str, Enum):
    """Subscription tiers."""
    FREE = "free"
    HYBRID_LIGHT = "hybrid_light"
    HYBRID_STANDARD = "hybrid_standard"
    PREMIUM = "premium"
    BUSINESS = "business"


class SubscriptionCreateRequest(BaseModel):
    """Create subscription request."""
    tier: SubscriptionTier
    payment_method_id: str = Field(..., description="Stripe payment method ID")


class SubscriptionResponse(BaseModel):
    """Subscription response."""
    tier: str
    status: str
    started_at: datetime
    ends_at: Optional[datetime]
    price_paid: float
    currency: str
    auto_renew: bool

    class Config:
        from_attributes = True


# === ADS SCHEMAS ===

class AdsBatchType(str, Enum):
    """Ads batch types."""
    BATCH_3 = "3_video"
    BATCH_5 = "5_video"
    BATCH_10 = "10_video"


class AdsSessionStartRequest(BaseModel):
    """Start ads session request."""
    batch_type: AdsBatchType


class AdsSessionResponse(BaseModel):
    """Ads session response."""
    id: Union[str, UUID]
    batch_type: str
    ads_required_duration: int
    videos_to_unlock: int
    validity_hours: int
    status: str
    total_duration_watched: int
    progress_percentage: float
    estimated_revenue: float
    created_at: datetime

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


class AdsProgressUpdate(BaseModel):
    """Ads progress update."""
    ad_id: str
    duration_watched: int  # seconds


# === ADMIN SCHEMAS ===

class UserAdminResponse(BaseModel):
    """User response for admin."""
    id: Union[str, UUID]
    email: EmailStr
    username: str
    full_name: Optional[str]
    tier: str
    is_active: bool
    is_admin: bool
    email_verified: bool
    subscription_end: Optional[datetime]
    created_at: datetime
    last_login: Optional[datetime]
    last_seen: Optional[datetime]

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


class AnalyticsDashboardResponse(BaseModel):
    """Analytics dashboard data."""
    total_users: int
    active_users_7d: int
    total_videos: int
    total_views_7d: int
    total_revenue_7d: float
    tier_distribution: dict
    top_videos: List[dict]
    blockchain_status: dict


# === BLOCKCHAIN SCHEMAS ===

class BlockchainBatchResponse(BaseModel):
    """Blockchain batch response."""
    id: Union[str, UUID]
    batch_date: datetime
    total_views: int
    total_revenue: float
    consensus_status: str
    consensus_threshold: float
    validations_received: int
    published_to_blockchain: bool
    blockchain_tx_hash: Optional[str]
    published_at: Optional[datetime]

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


# === LIVE STREAMING SCHEMAS ===

class LiveEventCreateRequest(BaseModel):
    """Create live event request."""
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    scheduled_start: datetime
    scheduled_end: Optional[datetime] = None
    tier_required: str = Field(default="free")
    max_viewers: Optional[int] = Field(None, gt=0)
    recording_enabled: bool = Field(default=True)


class LiveEventResponse(BaseModel):
    """Live event response."""
    id: Union[str, UUID]
    title: str
    description: Optional[str]
    stream_key: str
    rtmp_url: str
    hls_url: Optional[str]
    is_active: bool
    scheduled_start: datetime
    current_viewers: int
    tier_required: str

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        """Convert UUID to string."""
        return str(id)

    class Config:
        from_attributes = True


# === PAUSE ADS SCHEMAS ===

class SuggestedVideoSchema(BaseModel):
    """
    Video suggerito per pause ad overlay (lato sinistro).

    BUSINESS_PURPOSE: Incrementare engagement mostrando contenuti rilevanti
    """
    id: str = Field(..., description="UUID del video")
    title: str = Field(..., description="Titolo del video")
    thumbnail_url: str = Field(..., description="URL thumbnail 16:9")
    duration: int = Field(..., ge=0, description="Durata in secondi")
    maestro_name: str = Field(default="", description="Nome del maestro/istruttore")
    style: str = Field(default="", description="Stile arte marziale")
    category: str = Field(default="other", description="Categoria video")


class SponsorAdSchema(BaseModel):
    """
    Sponsor ad per pause ad overlay (lato destro).

    BUSINESS_PURPOSE: Monetizzazione tramite advertising non intrusivo
    """
    id: str = Field(..., description="UUID del pause ad")
    advertiser: str = Field(..., description="Nome advertiser")
    title: str = Field(..., description="Titolo ad")
    description: str = Field(default="", description="Descrizione opzionale")
    image_url: str = Field(..., description="URL immagine 600x400")
    click_url: str = Field(..., description="URL destinazione su click")


class PauseAdResponse(BaseModel):
    """
    Response per GET /pause-ad endpoint.

    BUSINESS_PURPOSE: Dati completi per overlay 50/50 Netflix-style
    TECHNICAL_EXPLANATION: Frontend riceve tutto necessario per render overlay
    """
    suggested_video: Optional[SuggestedVideoSchema] = Field(
        None,
        description="Video suggerito (lato sinistro overlay)"
    )
    sponsor_ad: Optional[SponsorAdSchema] = Field(
        None,
        description="Sponsor ad (lato destro overlay)"
    )
    impression_id: str = Field(
        ...,
        description="UUID per tracking impression/click"
    )
    show_overlay: bool = Field(
        default=False,
        description="True se almeno uno tra suggested/ad disponibile"
    )


class PauseAdImpressionRequest(BaseModel):
    """
    Request per POST /pause-ad/impression.

    BUSINESS_PURPOSE: Conferma che overlay e stato effettivamente mostrato
    """
    impression_id: str = Field(..., description="UUID impression da confermare")
    video_id: str = Field(..., description="UUID video in cui e apparso overlay")


class PauseAdClickRequest(BaseModel):
    """
    Request per POST /pause-ad/click.

    BUSINESS_PURPOSE: Tracking click per revenue bonus e analytics
    """
    impression_id: str = Field(..., description="UUID impression")
    click_type: str = Field(
        ...,
        description="Tipo click: 'ad' (sponsor) o 'suggested' (video)"
    )

    @validator('click_type')
    def validate_click_type(cls, v):
        """Validate click_type is valid."""
        if v not in ['ad', 'suggested']:
            raise ValueError("click_type must be 'ad' or 'suggested'")
        return v


class PauseAdStatsImpressionsSchema(BaseModel):
    """Statistiche impressions per PauseAdStatsResponse."""
    total: int = Field(..., ge=0, description="Totale impressions")
    unique_users: int = Field(..., ge=0, description="Utenti unici")
    per_user_avg: float = Field(..., ge=0, description="Media per utente")


class PauseAdStatsClicksSchema(BaseModel):
    """Statistiche clicks per PauseAdStatsResponse."""
    total: int = Field(..., ge=0, description="Totale clicks")
    ad_clicks: int = Field(..., ge=0, description="Click su sponsor ad")
    suggested_clicks: int = Field(..., ge=0, description="Click su video suggerito")
    ctr_percentage: float = Field(..., ge=0, description="Click-Through Rate %")


class PauseAdStatsRevenueSchema(BaseModel):
    """Statistiche revenue per PauseAdStatsResponse."""
    impression_revenue_eur: float = Field(..., ge=0, description="Revenue da impressions")
    click_revenue_eur: float = Field(..., ge=0, description="Revenue da clicks")
    total_revenue_eur: float = Field(..., ge=0, description="Revenue totale")
    effective_cpm: float = Field(..., ge=0, description="CPM effettivo")


class PauseAdStatsPeriodSchema(BaseModel):
    """Periodo per PauseAdStatsResponse."""
    start: str = Field(..., description="Data inizio ISO format")
    end: str = Field(..., description="Data fine ISO format")


class PauseAdStatsResponse(BaseModel):
    """
    Response per GET /pause-ad/stats endpoint (admin only).

    BUSINESS_PURPOSE: Dashboard analytics per pause ads performance
    """
    period: PauseAdStatsPeriodSchema = Field(..., description="Periodo analisi")
    impressions: PauseAdStatsImpressionsSchema = Field(..., description="Stats impressions")
    clicks: PauseAdStatsClicksSchema = Field(..., description="Stats clicks")
    revenue: PauseAdStatsRevenueSchema = Field(..., description="Stats revenue")


# === NOTIFICATION SCHEMAS ===

class NotificationType(str, Enum):
    """Notification types."""
    SYSTEM = "system"
    VIDEO_NEW = "video_new"
    LIVE_START = "live_start"
    ACHIEVEMENT = "achievement"
    SUBSCRIPTION = "subscription"
    SOCIAL = "social"
    PROMO = "promo"


class NotificationPriority(str, Enum):
    """Notification priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class DeviceType(str, Enum):
    """Device types for push notifications."""
    IOS = "ios"
    ANDROID = "android"
    WEB = "web"


class NotificationResponse(BaseModel):
    """
    Notification response model.

    BUSINESS_PURPOSE: Single notification data for display
    """
    id: str = Field(..., description="Notification UUID")
    type: str = Field(..., description="Notification type")
    priority: str = Field(..., description="Priority level")
    title: str = Field(..., description="Notification title")
    body: str = Field(..., description="Notification body")
    image_url: Optional[str] = Field(None, description="Optional image URL")
    action_type: Optional[str] = Field(None, description="Action type on click")
    action_payload: Optional[dict] = Field(None, description="Action payload JSON")
    is_read: bool = Field(..., description="Read status")
    read_at: Optional[str] = Field(None, description="When read (ISO format)")
    created_at: str = Field(..., description="Creation time (ISO format)")
    expires_at: Optional[str] = Field(None, description="Expiration time (ISO format)")


class NotificationListResponse(BaseModel):
    """
    Paginated notification list response.

    BUSINESS_PURPOSE: Notification feed with pagination
    """
    items: List[dict] = Field(..., description="List of notifications")
    total: int = Field(..., ge=0, description="Total notifications count")
    page: int = Field(..., ge=1, description="Current page")
    page_size: int = Field(..., ge=1, description="Items per page")
    has_more: bool = Field(..., description="Has more pages")


class UnreadCountResponse(BaseModel):
    """
    Unread notification count response.

    BUSINESS_PURPOSE: Badge count for notification icon
    """
    count: int = Field(..., ge=0, description="Unread notifications count")


class DeviceTokenRequest(BaseModel):
    """
    Device token registration request.

    BUSINESS_PURPOSE: Enable push notifications for device
    """
    token: str = Field(..., min_length=10, max_length=500, description="FCM/APNS token")
    device_type: str = Field(..., description="Device type: ios, android, web")
    device_name: Optional[str] = Field(None, max_length=255, description="Device name")
    device_model: Optional[str] = Field(None, max_length=100, description="Device model")
    os_version: Optional[str] = Field(None, max_length=50, description="OS version")
    app_version: Optional[str] = Field(None, max_length=20, description="App version")


class DeviceTokenResponse(BaseModel):
    """
    Device token response.

    BUSINESS_PURPOSE: Confirm token registration
    """
    id: str = Field(..., description="Device token UUID")
    device_type: str = Field(..., description="Device type")
    device_name: Optional[str] = Field(None, description="Device name")
    device_model: Optional[str] = Field(None, description="Device model")
    os_version: Optional[str] = Field(None, description="OS version")
    app_version: Optional[str] = Field(None, description="App version")
    is_active: bool = Field(..., description="Active status")
    last_used_at: Optional[str] = Field(None, description="Last used time")
    created_at: str = Field(..., description="Creation time")


class DeviceTokenListResponse(BaseModel):
    """
    Device token list response.

    BUSINESS_PURPOSE: List user's registered devices
    """
    items: List[dict] = Field(..., description="List of device tokens")
    total: int = Field(..., ge=0, description="Total tokens count")


class NotificationPreferencesResponse(BaseModel):
    """
    Notification preferences response.

    BUSINESS_PURPOSE: User notification settings
    """
    # In-app notification toggles
    system_enabled: bool = Field(True, description="System notifications enabled")
    video_new_enabled: bool = Field(True, description="New video notifications enabled")
    live_start_enabled: bool = Field(True, description="Live start notifications enabled")
    achievement_enabled: bool = Field(True, description="Achievement notifications enabled")
    subscription_enabled: bool = Field(True, description="Subscription notifications enabled")
    social_enabled: bool = Field(True, description="Social notifications enabled")
    promo_enabled: bool = Field(False, description="Promo notifications enabled")

    # Push notification toggles
    push_enabled: bool = Field(True, description="Push notifications globally enabled")
    push_system: bool = Field(True, description="Push for system notifications")
    push_video_new: bool = Field(True, description="Push for new video notifications")
    push_live_start: bool = Field(True, description="Push for live start notifications")
    push_achievement: bool = Field(True, description="Push for achievement notifications")
    push_subscription: bool = Field(True, description="Push for subscription notifications")
    push_social: bool = Field(False, description="Push for social notifications")
    push_promo: bool = Field(False, description="Push for promo notifications")

    # Quiet hours
    quiet_hours_enabled: bool = Field(False, description="Quiet hours enabled")
    quiet_hours_start: str = Field("22:00", description="Quiet hours start (HH:MM)")
    quiet_hours_end: str = Field("08:00", description="Quiet hours end (HH:MM)")


class NotificationPreferencesUpdate(BaseModel):
    """
    Notification preferences update request.

    BUSINESS_PURPOSE: Allow users to update notification settings
    """
    # In-app notification toggles (all optional for partial updates)
    system_enabled: Optional[bool] = None
    video_new_enabled: Optional[bool] = None
    live_start_enabled: Optional[bool] = None
    achievement_enabled: Optional[bool] = None
    subscription_enabled: Optional[bool] = None
    social_enabled: Optional[bool] = None
    promo_enabled: Optional[bool] = None

    # Push notification toggles
    push_enabled: Optional[bool] = None
    push_system: Optional[bool] = None
    push_video_new: Optional[bool] = None
    push_live_start: Optional[bool] = None
    push_achievement: Optional[bool] = None
    push_subscription: Optional[bool] = None
    push_social: Optional[bool] = None
    push_promo: Optional[bool] = None

    # Quiet hours
    quiet_hours_enabled: Optional[bool] = None
    quiet_hours_start: Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")
    quiet_hours_end: Optional[str] = Field(None, pattern=r"^\d{2}:\d{2}$")


class BroadcastNotificationRequest(BaseModel):
    """
    Broadcast notification request (admin only).

    BUSINESS_PURPOSE: Send notifications to multiple users
    """
    user_ids: List[str] = Field(..., min_length=1, description="List of user UUIDs")
    notification_type: str = Field(..., description="Notification type")
    title: str = Field(..., min_length=1, max_length=255, description="Notification title")
    body: str = Field(..., min_length=1, max_length=1000, description="Notification body")
    priority: Optional[str] = Field(None, description="Priority level")
    image_url: Optional[str] = Field(None, max_length=500, description="Optional image URL")
    action_type: Optional[str] = Field(None, max_length=50, description="Action type")
    action_payload: Optional[dict] = Field(None, description="Action payload JSON")
    send_push: bool = Field(True, description="Send push notifications")

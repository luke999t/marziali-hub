"""
🎓 AI_MODULE: User Models
🎓 AI_DESCRIPTION: User, Subscription, Viewing history, Favorites
🎓 AI_BUSINESS: Core user data + tier management + tracking
🎓 AI_TEACHING: SQLAlchemy relationships + enum types + business methods

💡 RELATIONSHIPS:
User 1 ────── N SubscriptionHistory
User 1 ────── N ViewingHistory
User 1 ────── N Favorite
User 1 ────── N Purchase
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, Enum, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class UserTier(str, enum.Enum):
    """
    Subscription tiers.

    🎯 MONETIZATION MODEL:
    - FREE: Ads ogni video, 720p max
    - HYBRID_LIGHT: Ads ogni 3 video, 1080p
    - HYBRID_STANDARD: Ads ogni 5 video, 1080p, download limitati
    - PREMIUM: No ads, 4K, download unlimited
    - PAY_PER_VIEW: Acquisti singoli
    - BUSINESS: Multi-user, analytics, API access
    """
    FREE = "free"
    HYBRID_LIGHT = "hybrid_light"
    HYBRID_STANDARD = "hybrid_standard"
    PREMIUM = "premium"
    PAY_PER_VIEW = "pay_per_view"
    BUSINESS = "business"


class SubscriptionStatus(str, enum.Enum):
    """Subscription status."""
    ACTIVE = "active"
    CANCELED = "canceled"
    EXPIRED = "expired"
    PAST_DUE = "past_due"


# === MODELS ===

class User(Base):
    """
    User model con tier logic.

    🎯 CORE ENTITY: Tutto ruota attorno all'utente
    """
    __tablename__ = "users"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    email_verified = Column(Boolean, default=False, nullable=False)

    # === SUBSCRIPTION ===
    tier = Column(
        Enum(UserTier, values_callable=lambda x: [e.value for e in x], name='usertier', create_type=False),
        default=UserTier.FREE, nullable=False, index=True
    )
    subscription_end = Column(DateTime, nullable=True)  # None = expired/free
    auto_renew = Column(Boolean, default=True, nullable=False)
    stripe_customer_id = Column(String(100), unique=True, nullable=True)

    # === ADS BATCH UNLOCK ===
    ads_unlocked_videos = Column(Integer, default=0, nullable=False)
    ads_unlock_valid_until = Column(DateTime, nullable=True)

    # === PREFERENCES ===
    language_preference = Column(String(10), default="it", nullable=False)
    subtitle_preference = Column(String(10), nullable=True)
    quality_preference = Column(String(10), default="auto", nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    # FIXME: Temporarily commented out ALL relationships to fix admin endpoint 403 issue
    # Root cause: Missing/broken relationship models causing SQLAlchemy to fail loading User object
    # This prevents get_current_admin_user from working
    # subscriptions = relationship("SubscriptionHistory", back_populates="user", cascade="all, delete-orphan")
    # viewing_history = relationship("ViewingHistory", back_populates="user", cascade="all, delete-orphan")
    # favorites = relationship("Favorite", back_populates="user", cascade="all, delete-orphan")
    # purchases = relationship("Purchase", back_populates="user", cascade="all, delete-orphan")
    # subscription = relationship("Subscription", back_populates="user", uselist=False, cascade="all, delete-orphan")
    # messages_sent = relationship("Message", foreign_keys="Message.from_user_id", back_populates="from_user", overlaps="messages_received")
    # messages_received = relationship("Message", foreign_keys="Message.to_user_id", back_populates="to_user", overlaps="messages_sent")

    # Downloads relationship (lazy="dynamic" per evitare caricamento immediato che causa 403)
    downloads = relationship("Download", back_populates="user", lazy="dynamic")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_users_tier_active', 'tier', 'is_active'),
        Index('idx_users_email', 'email'),
    )

    # === BUSINESS METHODS ===

    def is_subscription_active(self) -> bool:
        """
        Check se subscription attiva.

        Returns: True se PREMIUM/BUSINESS con data futura
        """
        if self.tier in [UserTier.FREE, UserTier.PAY_PER_VIEW]:
            return False

        if not self.subscription_end:
            return False

        return self.subscription_end > datetime.utcnow()

    def can_watch_video(self, video_tier) -> bool:
        """
        Check se può guardare video di un certo tier.

        🎯 BUSINESS LOGIC: Hierarchy check

        Args:
            video_tier: Can be UserTier enum or string (e.g., "premium")
        """
        tier_hierarchy = {
            UserTier.FREE: 0,
            UserTier.HYBRID_LIGHT: 1,
            UserTier.HYBRID_STANDARD: 2,
            UserTier.PREMIUM: 3,
            UserTier.BUSINESS: 3,
            UserTier.PAY_PER_VIEW: 0  # Special case
        }

        # Convert string to UserTier if needed
        if isinstance(video_tier, str):
            try:
                video_tier = UserTier(video_tier)
            except ValueError:
                # Unknown tier, default to free (allow access)
                return True

        user_level = tier_hierarchy.get(self.tier, 0)
        required_level = tier_hierarchy.get(video_tier, 0)

        return user_level >= required_level

    def has_unlocked_videos(self) -> bool:
        """Check se ha video sbloccati con ads batch."""
        if self.ads_unlocked_videos > 0 and self.ads_unlock_valid_until:
            return self.ads_unlock_valid_until > datetime.utcnow()
        return False

    def get_max_quality(self) -> str:
        """
        Get max quality per tier.

        Returns: "720p" | "1080p" | "4k"
        """
        quality_map = {
            UserTier.FREE: "720p",
            UserTier.HYBRID_LIGHT: "1080p",
            UserTier.HYBRID_STANDARD: "1080p",
            UserTier.PREMIUM: "4k",
            UserTier.PAY_PER_VIEW: "1080p",
            UserTier.BUSINESS: "4k",
        }
        return quality_map.get(self.tier, "720p")

    def requires_ads(self) -> bool:
        """Check se deve guardare ads."""
        return self.tier in [UserTier.FREE, UserTier.HYBRID_LIGHT, UserTier.HYBRID_STANDARD]

    def __repr__(self):
        return f"<User {self.email} ({self.tier.value})>"


class SubscriptionHistory(Base):
    """
    Subscription history per user.

    🎯 AUDIT TRAIL: Track tutte le subscription
    """
    __tablename__ = "subscription_history"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    tier = Column(
        Enum(UserTier, values_callable=lambda x: [e.value for e in x], name='usertier', create_type=False),
        nullable=False
    )
    status = Column(
        Enum(SubscriptionStatus, values_callable=lambda x: [e.value for e in x], name='subscriptionstatus', create_type=False),
        nullable=False
    )

    started_at = Column(DateTime, nullable=False)
    ends_at = Column(DateTime, nullable=True)
    canceled_at = Column(DateTime, nullable=True)

    price_paid = Column(Float, nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)

    stripe_subscription_id = Column(String(100), unique=True, nullable=True)
    stripe_invoice_id = Column(String(100), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User")  # FIXME: removed back_populates due to commented relationships in User

    __table_args__ = (
        Index('idx_subscription_user_status', 'user_id', 'status'),
    )


class ViewingHistory(Base):
    """
    Viewing history con blockchain tracking.

    🎯 ANALYTICS + BLOCKCHAIN: Track ogni view per royalty
    """
    __tablename__ = "viewing_history"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False)

    watched_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    watch_duration = Column(Integer, nullable=False)  # seconds
    completed = Column(Boolean, default=False, nullable=False)

    # === PROGRESS TRACKING ===
    last_position = Column(Integer, default=0, nullable=False)  # seconds

    # === BLOCKCHAIN ===
    blockchain_batch_id = Column(GUID(), nullable=True)  # Quale batch include questa view
    blockchain_published = Column(Boolean, default=False, nullable=False)

    # === METADATA ===
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    device_info = Column(JSONBType(), nullable=True)

    # === RELATIONSHIPS ===
    user = relationship("User")  # FIXME: removed back_populates

    __table_args__ = (
        Index('idx_viewing_user_video', 'user_id', 'video_id'),
        Index('idx_viewing_watched_at', 'watched_at'),
        Index('idx_viewing_blockchain', 'blockchain_published', 'watched_at'),
    )


class Favorite(Base):
    """
    User favorites (My List).

    🎯 NETFLIX FEATURE: My List / Watchlist
    """
    __tablename__ = "favorites"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False)

    added_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User")  # FIXME: removed back_populates

    __table_args__ = (
        Index('idx_favorites_user', 'user_id', 'added_at'),
    )


class Purchase(Base):
    """
    Pay-per-view purchases.

    🎯 PPV MODEL: Acquisto singolo video/corso
    """
    __tablename__ = "purchases"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)

    price_paid = Column(Float, nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)

    purchased_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # None = lifetime access

    stripe_payment_intent_id = Column(String(100), unique=True, nullable=True)

    # === RELATIONSHIPS ===
    user = relationship("User")  # FIXME: removed back_populates

    __table_args__ = (
        Index('idx_purchases_user', 'user_id', 'purchased_at'),
    )

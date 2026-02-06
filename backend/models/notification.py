"""
🎓 AI_MODULE: Notification Models
🎓 AI_DESCRIPTION: Notifications, Device Tokens for push notifications
🎓 AI_BUSINESS: User notifications + push notification management
🎓 AI_TEACHING: SQLAlchemy relationships + enum types + JSONB payload

💡 RELATIONSHIPS:
User 1 ────── N Notification
User 1 ────── N DeviceToken
"""

from sqlalchemy import Column, String, Boolean, DateTime, Enum, ForeignKey, Text, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class NotificationType(str, enum.Enum):
    """
    Notification types.

    🎯 NOTIFICATION CATEGORIES:
    - SYSTEM: System updates, maintenance
    - VIDEO_NEW: New video from followed maestro
    - LIVE_START: Live stream started
    - ACHIEVEMENT: Badge/achievement unlocked
    - SUBSCRIPTION: Subscription expiring/renewed
    - SOCIAL: Comments, likes, follows
    - PROMO: Promotions, discounts
    """
    SYSTEM = "system"
    VIDEO_NEW = "video_new"
    LIVE_START = "live_start"
    ACHIEVEMENT = "achievement"
    SUBSCRIPTION = "subscription"
    SOCIAL = "social"
    PROMO = "promo"


class NotificationPriority(str, enum.Enum):
    """Notification priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class DeviceType(str, enum.Enum):
    """Device types for push notifications."""
    IOS = "ios"
    ANDROID = "android"
    WEB = "web"


# === MODELS ===

class Notification(Base):
    """
    User notification model.

    🎯 CORE ENTITY: In-app notifications for users
    """
    __tablename__ = "notifications"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === NOTIFICATION DATA ===
    type = Column(
        Enum(NotificationType, values_callable=lambda x: [e.value for e in x], name='notificationtype', create_type=False),
        nullable=False, index=True
    )
    priority = Column(
        Enum(NotificationPriority, values_callable=lambda x: [e.value for e in x], name='notificationpriority', create_type=False),
        default=NotificationPriority.NORMAL, nullable=False
    )

    # === CONTENT ===
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    image_url = Column(String(500), nullable=True)  # Optional notification image

    # === ACTION ===
    action_type = Column(String(50), nullable=True)  # "open_video", "open_live", "open_profile", etc.
    action_payload = Column(JSONBType(), nullable=True)  # {"video_id": "...", "maestro_id": "..."}

    # === STATUS ===
    is_read = Column(Boolean, default=False, nullable=False, index=True)
    read_at = Column(DateTime, nullable=True)

    # === PUSH STATUS ===
    push_sent = Column(Boolean, default=False, nullable=False)
    push_sent_at = Column(DateTime, nullable=True)
    push_error = Column(Text, nullable=True)  # Error message if push failed

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration for time-sensitive notifications

    # === RELATIONSHIPS ===
    user = relationship("User")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_notifications_user_read', 'user_id', 'is_read'),
        Index('idx_notifications_user_created', 'user_id', 'created_at'),
        Index('idx_notifications_type_created', 'type', 'created_at'),
        Index('idx_notifications_expires', 'expires_at'),
    )

    # === BUSINESS METHODS ===

    def mark_as_read(self) -> None:
        """Mark notification as read."""
        self.is_read = True
        self.read_at = datetime.utcnow()

    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": str(self.id),
            "type": self.type.value,
            "priority": self.priority.value,
            "title": self.title,
            "body": self.body,
            "image_url": self.image_url,
            "action_type": self.action_type,
            "action_payload": self.action_payload,
            "is_read": self.is_read,
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }

    def __repr__(self):
        return f"<Notification {self.id} ({self.type.value}) for User {self.user_id}>"


class DeviceToken(Base):
    """
    Device token for push notifications (FCM/APNS).

    🎯 PUSH NOTIFICATIONS: Store device tokens for Firebase/APNS
    """
    __tablename__ = "device_tokens"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === TOKEN DATA ===
    token = Column(String(500), nullable=False, index=True)  # FCM/APNS token
    device_type = Column(
        Enum(DeviceType, values_callable=lambda x: [e.value for e in x], name='devicetype', create_type=False),
        nullable=False
    )

    # === DEVICE INFO ===
    device_name = Column(String(255), nullable=True)  # "iPhone 15 Pro", "Samsung Galaxy S24"
    device_model = Column(String(100), nullable=True)  # "iPhone15,2", "SM-S924B"
    os_version = Column(String(50), nullable=True)  # "iOS 17.2", "Android 14"
    app_version = Column(String(20), nullable=True)  # "1.2.3"

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    last_used_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_device_tokens_user_active', 'user_id', 'is_active'),
        Index('idx_device_tokens_token', 'token'),
    )

    def update_last_used(self) -> None:
        """Update last used timestamp."""
        self.last_used_at = datetime.utcnow()

    def deactivate(self) -> None:
        """Deactivate device token (invalid/unregistered)."""
        self.is_active = False

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": str(self.id),
            "device_type": self.device_type.value,
            "device_name": self.device_name,
            "device_model": self.device_model,
            "os_version": self.os_version,
            "app_version": self.app_version,
            "is_active": self.is_active,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat(),
        }

    def __repr__(self):
        return f"<DeviceToken {self.device_type.value} for User {self.user_id}>"


class NotificationPreference(Base):
    """
    User notification preferences.

    🎯 USER SETTINGS: Allow users to control which notifications they receive
    """
    __tablename__ = "notification_preferences"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)

    # === NOTIFICATION TOGGLES ===
    # In-app notifications
    system_enabled = Column(Boolean, default=True, nullable=False)
    video_new_enabled = Column(Boolean, default=True, nullable=False)
    live_start_enabled = Column(Boolean, default=True, nullable=False)
    achievement_enabled = Column(Boolean, default=True, nullable=False)
    subscription_enabled = Column(Boolean, default=True, nullable=False)
    social_enabled = Column(Boolean, default=True, nullable=False)
    promo_enabled = Column(Boolean, default=False, nullable=False)  # Default OFF for marketing

    # === PUSH NOTIFICATION TOGGLES ===
    push_enabled = Column(Boolean, default=True, nullable=False)
    push_system = Column(Boolean, default=True, nullable=False)
    push_video_new = Column(Boolean, default=True, nullable=False)
    push_live_start = Column(Boolean, default=True, nullable=False)
    push_achievement = Column(Boolean, default=True, nullable=False)
    push_subscription = Column(Boolean, default=True, nullable=False)
    push_social = Column(Boolean, default=False, nullable=False)  # Default OFF
    push_promo = Column(Boolean, default=False, nullable=False)  # Default OFF

    # === QUIET HOURS ===
    quiet_hours_enabled = Column(Boolean, default=False, nullable=False)
    quiet_hours_start = Column(String(5), default="22:00", nullable=False)  # HH:MM format
    quiet_hours_end = Column(String(5), default="08:00", nullable=False)  # HH:MM format

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User")

    # === BUSINESS METHODS ===

    def is_notification_enabled(self, notification_type: NotificationType) -> bool:
        """Check if a specific notification type is enabled."""
        type_map = {
            NotificationType.SYSTEM: self.system_enabled,
            NotificationType.VIDEO_NEW: self.video_new_enabled,
            NotificationType.LIVE_START: self.live_start_enabled,
            NotificationType.ACHIEVEMENT: self.achievement_enabled,
            NotificationType.SUBSCRIPTION: self.subscription_enabled,
            NotificationType.SOCIAL: self.social_enabled,
            NotificationType.PROMO: self.promo_enabled,
        }
        return type_map.get(notification_type, True)

    def is_push_enabled_for_type(self, notification_type: NotificationType) -> bool:
        """Check if push notification is enabled for a specific type."""
        if not self.push_enabled:
            return False

        type_map = {
            NotificationType.SYSTEM: self.push_system,
            NotificationType.VIDEO_NEW: self.push_video_new,
            NotificationType.LIVE_START: self.push_live_start,
            NotificationType.ACHIEVEMENT: self.push_achievement,
            NotificationType.SUBSCRIPTION: self.push_subscription,
            NotificationType.SOCIAL: self.push_social,
            NotificationType.PROMO: self.push_promo,
        }
        return type_map.get(notification_type, False)

    def is_in_quiet_hours(self) -> bool:
        """Check if current time is within quiet hours."""
        if not self.quiet_hours_enabled:
            return False

        from datetime import datetime
        now = datetime.utcnow().strftime("%H:%M")

        # Handle overnight quiet hours (e.g., 22:00 - 08:00)
        if self.quiet_hours_start > self.quiet_hours_end:
            return now >= self.quiet_hours_start or now < self.quiet_hours_end
        else:
            return self.quiet_hours_start <= now < self.quiet_hours_end

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "system_enabled": self.system_enabled,
            "video_new_enabled": self.video_new_enabled,
            "live_start_enabled": self.live_start_enabled,
            "achievement_enabled": self.achievement_enabled,
            "subscription_enabled": self.subscription_enabled,
            "social_enabled": self.social_enabled,
            "promo_enabled": self.promo_enabled,
            "push_enabled": self.push_enabled,
            "push_system": self.push_system,
            "push_video_new": self.push_video_new,
            "push_live_start": self.push_live_start,
            "push_achievement": self.push_achievement,
            "push_subscription": self.push_subscription,
            "push_social": self.push_social,
            "push_promo": self.push_promo,
            "quiet_hours_enabled": self.quiet_hours_enabled,
            "quiet_hours_start": self.quiet_hours_start,
            "quiet_hours_end": self.quiet_hours_end,
        }

    def __repr__(self):
        return f"<NotificationPreference for User {self.user_id}>"

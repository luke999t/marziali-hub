"""
🎓 AI_MODULE: Payment & Subscription Models
🎓 AI_DESCRIPTION: Stripe payments, subscriptions, stelline purchases
🎓 AI_BUSINESS: Monetization core - handles all financial transactions
🎓 AI_TEACHING: Payment flows, subscription lifecycle, transaction history

💡 RELATIONSHIPS:
Payment 1 ────── 1 User (buyer)
Subscription 1 ── 1 User (subscriber)
StelllinePurchase 1 ── 1 User (buyer)
VideoPurchase 1 ── 1 User + 1 Video (PPV)
"""

from sqlalchemy import Column, String, Integer, DateTime, Enum, ForeignKey, Text, Boolean, Index
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class PaymentStatus(str, enum.Enum):
    """Payment transaction status."""
    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"
    REFUNDED = "refunded"


class PaymentProvider(str, enum.Enum):
    """Payment provider."""
    STRIPE = "stripe"
    PAYPAL = "paypal"
    CRYPTO = "crypto"  # Polygon blockchain


class SubscriptionStatus(str, enum.Enum):
    """Subscription status."""
    ACTIVE = "active"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    INCOMPLETE_EXPIRED = "incomplete_expired"
    TRIALING = "trialing"
    UNPAID = "unpaid"


class TransactionType(str, enum.Enum):
    """Type of financial transaction."""
    STELLINE_PURCHASE = "stelline_purchase"
    SUBSCRIPTION = "subscription"
    VIDEO_PURCHASE = "video_purchase"  # PPV
    DONATION = "donation"
    WITHDRAWAL = "withdrawal"
    REFUND = "refund"


# === MODELS ===

class Payment(Base):
    """
    Payment Transaction Record.

    🎯 FINANCIAL RECORD: Track all payment transactions
    """
    __tablename__ = "payments"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === PAYMENT DETAILS ===
    provider = Column(Enum(PaymentProvider), nullable=False, default=PaymentProvider.STRIPE)
    transaction_type = Column(Enum(TransactionType), nullable=False)

    amount_eur = Column(Integer, nullable=False)  # Amount in EUR cents
    currency = Column(String(3), default="EUR", nullable=False)

    status = Column(Enum(PaymentStatus), default=PaymentStatus.PENDING, nullable=False, index=True)

    # === PROVIDER IDS ===
    stripe_payment_intent_id = Column(String(255), unique=True, nullable=True, index=True)
    stripe_charge_id = Column(String(255), nullable=True)
    paypal_order_id = Column(String(255), unique=True, nullable=True)
    blockchain_tx_hash = Column(String(255), unique=True, nullable=True)

    # === METADATA ===
    stelline_amount = Column(Integer, nullable=True)  # If stelline purchase
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)  # If PPV
    subscription_id = Column(GUID(), ForeignKey("subscriptions.id", ondelete="SET NULL"), nullable=True)

    description = Column(Text, nullable=True)
    extra_metadata = Column(JSONBType(), nullable=True)  # Extra provider data (renamed from 'metadata' to avoid SQLAlchemy conflict)

    # === ERROR HANDLING ===
    failure_code = Column(String(50), nullable=True)
    failure_message = Column(Text, nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    refunded_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    # FIXME: Removed back_populates because User.payments is commented out
    user = relationship("User")
    video = relationship("Video", backref="purchases")
    subscription = relationship("Subscription", back_populates="payments")

    __table_args__ = (
        Index('idx_payment_user_status', 'user_id', 'status'),
        Index('idx_payment_type_status', 'transaction_type', 'status'),
        Index('idx_payment_created', 'created_at'),
    )

    def __repr__(self):
        return f"<Payment {self.id} - {self.transaction_type.value} - {self.status.value}>"


class Subscription(Base):
    """
    User Subscription Record.

    🎯 RECURRING PAYMENT: Track active subscriptions and billing
    """
    __tablename__ = "subscriptions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    # NOTE: One active subscription per user

    # === SUBSCRIPTION DETAILS ===
    tier = Column(String(50), nullable=False)  # HYBRID_LIGHT, HYBRID_STANDARD, PREMIUM, BUSINESS
    status = Column(Enum(SubscriptionStatus), default=SubscriptionStatus.INCOMPLETE, nullable=False, index=True)

    # === STRIPE IDS ===
    stripe_subscription_id = Column(String(255), unique=True, nullable=True, index=True)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_price_id = Column(String(255), nullable=True)

    # === BILLING ===
    amount_eur_cents = Column(Integer, nullable=False)  # Monthly cost in cents
    interval = Column(String(20), default="month", nullable=False)  # month, year

    # === TRIAL ===
    trial_start = Column(DateTime, nullable=True)
    trial_end = Column(DateTime, nullable=True)

    # === BILLING PERIOD ===
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)

    # === CANCELLATION ===
    cancel_at_period_end = Column(Boolean, default=False, nullable=False)
    canceled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(Text, nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    # FIXME: Removed back_populates because User.subscription is commented out
    user = relationship("User")
    payments = relationship("Payment", back_populates="subscription", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_subscription_user', 'user_id'),
        Index('idx_subscription_status', 'status', 'created_at'),
        Index('idx_subscription_stripe', 'stripe_subscription_id'),
    )

    def is_active(self) -> bool:
        """Check if subscription is currently active."""
        return self.status in [SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING]

    def days_until_renewal(self) -> int:
        """Calculate days until next billing."""
        if not self.current_period_end:
            return 0
        delta = self.current_period_end - datetime.utcnow()
        return max(0, delta.days)

    def __repr__(self):
        return f"<Subscription {self.user_id} - {self.tier} - {self.status.value}>"


class StellinePurchase(Base):
    """
    Stelline Purchase Record.

    🎯 VIRTUAL CURRENCY: Track stelline purchases for donation system
    """
    __tablename__ = "stelline_purchases"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    payment_id = Column(GUID(), ForeignKey("payments.id", ondelete="CASCADE"), nullable=False)

    # === PURCHASE DETAILS ===
    package_type = Column(String(20), nullable=False)  # small, medium, large
    stelline_amount = Column(Integer, nullable=False)
    price_eur_cents = Column(Integer, nullable=False)

    # === STATUS ===
    delivered = Column(Boolean, default=False, nullable=False)
    delivered_at = Column(DateTime, nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="stelline_purchases")
    payment = relationship("Payment", backref="stelline_purchase", uselist=False)

    __table_args__ = (
        Index('idx_stelline_purchase_user', 'user_id', 'created_at'),
        Index('idx_stelline_purchase_payment', 'payment_id'),
    )

    def __repr__(self):
        return f"<StellinePurchase {self.user_id} - {self.stelline_amount} stelline>"


class VideoPurchase(Base):
    """
    Pay-Per-View Purchase Record.

    🎯 PPV: Track individual video purchases
    """
    __tablename__ = "video_purchases"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False)
    payment_id = Column(GUID(), ForeignKey("payments.id", ondelete="CASCADE"), nullable=False)

    # === PURCHASE DETAILS ===
    price_stelline = Column(Integer, nullable=False)  # Price paid in stelline

    # === ACCESS ===
    access_granted = Column(Boolean, default=False, nullable=False)
    access_expires_at = Column(DateTime, nullable=True)  # NULL = lifetime access

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="video_purchases")
    video = relationship("Video", backref="ppv_purchases")
    payment = relationship("Payment", backref="video_purchase", uselist=False)

    __table_args__ = (
        Index('idx_video_purchase_user_video', 'user_id', 'video_id'),
        Index('idx_video_purchase_payment', 'payment_id'),
    )

    def has_access(self) -> bool:
        """Check if user still has access to video."""
        if not self.access_granted:
            return False
        if self.access_expires_at is None:
            return True  # Lifetime access
        return datetime.utcnow() < self.access_expires_at

    def __repr__(self):
        return f"<VideoPurchase {self.user_id} - Video {self.video_id}>"

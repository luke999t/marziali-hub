"""
🎓 AI_MODULE: Payments API
🎓 AI_DESCRIPTION: Stripe payment intents, stelline purchases, subscriptions, PPV
🎓 AI_BUSINESS: Core monetization - handles all payment flows
🎓 AI_TEACHING: Payment Intent creation, webhook handling, subscription lifecycle

💡 ENDPOINTS:
- POST /payments/stelline/purchase - Create payment intent for stelline
- POST /payments/stelline/confirm - Confirm stelline purchase after payment
- POST /payments/subscription/create - Create subscription
- POST /payments/subscription/cancel - Cancel subscription
- GET /payments/history - Get user payment history
- POST /payments/video/{id}/purchase - Purchase video with stelline (PPV)
- POST /payments/webhook - Stripe webhook handler
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel

from core.database import get_db
from core.security import get_current_user
from core.stripe_config import (
    STELLINE_PACKAGES,
    SUBSCRIPTION_PLANS,
    create_payment_intent,
    create_subscription,
    cancel_subscription,
    create_customer,
    verify_webhook_signature,
    get_or_create_price
)
from models.user import User, UserTier
from models.payment import (
    Payment,
    Subscription,
    StellinePurchase,
    VideoPurchase,
    PaymentStatus,
    PaymentProvider,
    TransactionType,
    SubscriptionStatus
)
from models.donation import StellineWallet
from models.video import Video


router = APIRouter()


# === SCHEMAS ===

class StellinePurchaseRequest(BaseModel):
    """Request to purchase stelline."""
    package: str  # small, medium, large


class StellinePurchaseResponse(BaseModel):
    """Response after creating payment intent."""
    payment_intent_id: str
    client_secret: str
    amount_eur: float
    stelline_amount: int
    payment_id: str


class ConfirmStellinePurchaseRequest(BaseModel):
    """Confirm purchase after payment succeeded."""
    payment_intent_id: str


class SubscriptionCreateRequest(BaseModel):
    """Request to create subscription."""
    tier: str  # HYBRID_LIGHT, HYBRID_STANDARD, PREMIUM, BUSINESS


class SubscriptionCreateResponse(BaseModel):
    """Response after creating subscription."""
    subscription_id: str
    client_secret: str
    amount_eur: float


class PaymentHistoryItem(BaseModel):
    """Payment history item."""
    id: str
    type: str
    amount_eur: float
    status: str
    description: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class VideoPurchaseRequest(BaseModel):
    """Request to purchase video with stelline."""
    video_id: str


# === STELLINE PURCHASE ENDPOINTS ===

@router.post(
    "/stelline/purchase",
    response_model=StellinePurchaseResponse,
    summary="Create payment intent for stelline purchase",
    description="Step 1: Create Stripe Payment Intent for buying stelline"
)
async def purchase_stelline(
    request: StellinePurchaseRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create Stripe Payment Intent for stelline purchase.

    Workflow:
    1. Validate package type
    2. Create Payment record in DB
    3. Create Stripe Payment Intent
    4. Return client_secret for frontend
    """
    # Validate package
    if request.package not in STELLINE_PACKAGES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid package. Choose from: {', '.join(STELLINE_PACKAGES.keys())}"
        )

    package = STELLINE_PACKAGES[request.package]

    # Create Payment record
    payment = Payment(
        user_id=current_user.id,
        provider=PaymentProvider.STRIPE,
        transaction_type=TransactionType.STELLINE_PURCHASE,
        amount_eur=package["price_cents"],
        currency="EUR",
        status=PaymentStatus.PENDING,
        stelline_amount=package["stelline"],
        description=package["description"]
    )
    db.add(payment)
    await db.commit()
    await db.refresh(payment)

    # Create Stripe Payment Intent
    try:
        payment_intent = create_payment_intent(
            amount_cents=package["price_cents"],
            currency="eur",
            metadata={
                "user_id": str(current_user.id),
                "payment_id": str(payment.id),
                "package": request.package,
                "stelline_amount": package["stelline"]
            }
        )

        # Update payment with Stripe ID
        payment.stripe_payment_intent_id = payment_intent.id
        payment.status = PaymentStatus.PROCESSING
        await db.commit()

        return {
            "payment_intent_id": payment_intent.id,
            "client_secret": payment_intent.client_secret,
            "amount_eur": package["price_eur"],
            "stelline_amount": package["stelline"],
            "payment_id": str(payment.id)
        }

    except Exception as e:
        payment.status = PaymentStatus.FAILED
        payment.failure_message = str(e)
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Payment intent creation failed: {e}")


@router.post(
    "/stelline/confirm",
    summary="Confirm stelline purchase",
    description="Step 2: Confirm payment succeeded and deliver stelline to wallet"
)
async def confirm_stelline_purchase(
    request: ConfirmStellinePurchaseRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Confirm stelline purchase and credit wallet.

    Called after frontend confirms payment succeeded.
    Webhook will also handle this, but this provides immediate feedback.
    """
    # Get payment by payment_intent_id
    result = await db.execute(
        select(Payment).where(
            Payment.stripe_payment_intent_id == request.payment_intent_id,
            Payment.user_id == current_user.id
        )
    )
    payment = result.scalar_one_or_none()

    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    if payment.status == PaymentStatus.SUCCEEDED:
        return {"message": "Payment already confirmed", "payment_id": str(payment.id)}

    if payment.status != PaymentStatus.PROCESSING:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot confirm payment in status: {payment.status.value}"
        )

    # Mark as succeeded
    payment.status = PaymentStatus.SUCCEEDED
    payment.completed_at = datetime.utcnow()

    # Create StellinePurchase record
    stelline_purchase = StellinePurchase(
        user_id=current_user.id,
        payment_id=payment.id,
        package_type=payment.extra_metadata.get("package", "unknown") if payment.extra_metadata else "unknown",
        stelline_amount=payment.stelline_amount,
        price_eur_cents=payment.amount_eur,
        delivered=False
    )
    db.add(stelline_purchase)

    # Credit wallet
    wallet_result = await db.execute(
        select(StellineWallet).where(StellineWallet.user_id == current_user.id)
    )
    wallet = wallet_result.scalar_one_or_none()

    if not wallet:
        # Create wallet if doesn't exist
        wallet = StellineWallet(user_id=current_user.id, balance_stelline=0)
        db.add(wallet)

    wallet.balance_stelline += payment.stelline_amount
    stelline_purchase.delivered = True
    stelline_purchase.delivered_at = datetime.utcnow()

    await db.commit()

    return {
        "message": "Stelline credited successfully",
        "payment_id": str(payment.id),
        "stelline_added": payment.stelline_amount,
        "new_balance": wallet.balance_stelline
    }


# === SUBSCRIPTION ENDPOINTS ===

@router.post(
    "/subscription/create",
    response_model=SubscriptionCreateResponse,
    summary="Create subscription",
    description="Create Stripe subscription for tier upgrade"
)
async def create_user_subscription(
    request: SubscriptionCreateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create Stripe subscription for user.

    Workflow:
    1. Validate tier
    2. Check no active subscription
    3. Create/get Stripe customer
    4. Create Stripe subscription
    5. Create Subscription record in DB
    """
    # Validate tier
    if request.tier not in SUBSCRIPTION_PLANS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tier. Choose from: {', '.join(SUBSCRIPTION_PLANS.keys())}"
        )

    plan = SUBSCRIPTION_PLANS[request.tier]

    # Check for existing active subscription
    existing_result = await db.execute(
        select(Subscription).where(
            Subscription.user_id == current_user.id,
            Subscription.status.in_([SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING])
        )
    )
    existing_sub = existing_result.scalar_one_or_none()

    if existing_sub:
        raise HTTPException(
            status_code=400,
            detail=f"User already has active subscription: {existing_sub.tier}"
        )

    # Create/get Stripe customer
    if not current_user.stripe_customer_id:
        customer = create_customer(
            email=current_user.email,
            name=current_user.full_name,
            metadata={"user_id": str(current_user.id)}
        )
        current_user.stripe_customer_id = customer.id
        await db.commit()

    # Get or create Stripe Price for this tier
    try:
        price_id = get_or_create_price(request.tier)
    except ValueError as e:
        raise HTTPException(status_code=500, detail=str(e))

    # Create subscription record in DB first
    subscription_record = Subscription(
        user_id=current_user.id,
        tier=request.tier,
        status=SubscriptionStatus.INCOMPLETE,
        amount_eur_cents=plan["price_cents"],
        interval=plan["interval"]
    )
    db.add(subscription_record)
    await db.commit()
    await db.refresh(subscription_record)

    try:
        # Create Stripe subscription
        stripe_sub = create_subscription(
            customer_id=current_user.stripe_customer_id,
            price_id=price_id,
            metadata={
                "user_id": str(current_user.id),
                "subscription_id": str(subscription_record.id),
                "tier": request.tier
            }
        )

        subscription_record.stripe_subscription_id = stripe_sub.id
        subscription_record.stripe_customer_id = current_user.stripe_customer_id
        await db.commit()

        return {
            "subscription_id": str(subscription_record.id),
            "client_secret": stripe_sub.latest_invoice.payment_intent.client_secret,
            "amount_eur": plan["price_eur"]
        }

    except Exception as e:
        subscription_record.status = SubscriptionStatus.INCOMPLETE_EXPIRED
        await db.commit()
        raise HTTPException(status_code=500, detail=f"Subscription creation failed: {e}")


@router.post(
    "/subscription/cancel",
    summary="Cancel subscription",
    description="Cancel user's active subscription"
)
async def cancel_user_subscription(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel user's subscription.

    Subscription remains active until end of billing period.
    """
    # Get active subscription
    result = await db.execute(
        select(Subscription).where(
            Subscription.user_id == current_user.id,
            Subscription.status.in_([SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING])
        )
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        raise HTTPException(status_code=404, detail="No active subscription found")

    # Cancel in Stripe
    if subscription.stripe_subscription_id:
        try:
            canceled_sub = cancel_subscription(subscription.stripe_subscription_id)

            subscription.cancel_at_period_end = True
            subscription.canceled_at = datetime.utcnow()
            await db.commit()

            return {
                "message": "Subscription canceled",
                "subscription_id": str(subscription.id),
                "active_until": subscription.current_period_end
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Cancellation failed: {e}")
    else:
        # No Stripe subscription, just mark as canceled
        subscription.status = SubscriptionStatus.CANCELED
        subscription.canceled_at = datetime.utcnow()
        await db.commit()

        return {
            "message": "Subscription canceled",
            "subscription_id": str(subscription.id)
        }


# === PAYMENT HISTORY ===

@router.get(
    "/history",
    response_model=List[PaymentHistoryItem],
    summary="Get payment history",
    description="Get user's payment transaction history"
)
async def get_payment_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = 50
):
    """Get user's payment history."""
    result = await db.execute(
        select(Payment)
        .where(Payment.user_id == current_user.id)
        .order_by(Payment.created_at.desc())
        .limit(limit)
    )
    payments = result.scalars().all()

    return [
        {
            "id": str(p.id),
            "type": p.transaction_type.value,
            "amount_eur": p.amount_eur / 100,
            "status": p.status.value,
            "description": p.description,
            "created_at": p.created_at
        }
        for p in payments
    ]


# === PAY-PER-VIEW ===

@router.post(
    "/video/{video_id}/purchase",
    summary="Purchase video with stelline (PPV)",
    description="Buy access to premium video using stelline from wallet"
)
async def purchase_video(
    video_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Purchase video access with stelline.

    Workflow:
    1. Check video exists and has PPV price
    2. Check user wallet balance
    3. Check not already purchased
    4. Deduct stelline from wallet
    5. Create VideoPurchase record
    6. Grant access
    """
    # Get video
    video_result = await db.execute(select(Video).where(Video.id == video_id))
    video = video_result.scalar_one_or_none()

    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    if not video.ppv_price or video.ppv_price <= 0:
        raise HTTPException(status_code=400, detail="Video is not available for PPV purchase")

    # Check already purchased
    existing_result = await db.execute(
        select(VideoPurchase).where(
            VideoPurchase.user_id == current_user.id,
            VideoPurchase.video_id == video_id
        )
    )
    if existing_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Video already purchased")

    # Check wallet balance
    wallet_result = await db.execute(
        select(StellineWallet).where(StellineWallet.user_id == current_user.id)
    )
    wallet = wallet_result.scalar_one_or_none()

    if not wallet or wallet.balance_stelline < video.ppv_price:
        raise HTTPException(
            status_code=400,
            detail=f"Insufficient stelline. Need {video.ppv_price}, have {wallet.balance_stelline if wallet else 0}"
        )

    # Deduct stelline
    wallet.balance_stelline -= video.ppv_price

    # Create Payment record
    payment = Payment(
        user_id=current_user.id,
        provider=PaymentProvider.STRIPE,  # Using stelline from Stripe purchase
        transaction_type=TransactionType.VIDEO_PURCHASE,
        amount_eur=0,  # Paid with stelline, not EUR
        status=PaymentStatus.SUCCEEDED,
        video_id=video_id,
        stelline_amount=video.ppv_price,
        description=f"PPV: {video.title}",
        completed_at=datetime.utcnow()
    )
    db.add(payment)
    await db.flush()

    # Create VideoPurchase record
    video_purchase = VideoPurchase(
        user_id=current_user.id,
        video_id=video_id,
        payment_id=payment.id,
        price_stelline=video.ppv_price,
        access_granted=True,
        access_expires_at=None  # Lifetime access
    )
    db.add(video_purchase)

    await db.commit()

    return {
        "message": "Video purchased successfully",
        "video_id": video_id,
        "stelline_spent": video.ppv_price,
        "new_balance": wallet.balance_stelline
    }


# === STRIPE WEBHOOK ===

@router.post(
    "/webhook",
    summary="Stripe webhook handler",
    description="Handle Stripe events (payment_intent.succeeded, subscription updates, etc.)",
    include_in_schema=False  # Hide from public API docs
)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="Stripe-Signature"),
    db: AsyncSession = Depends(get_db)
):
    """
    Stripe webhook handler.

    Handles events:
    - payment_intent.succeeded: Credit stelline to wallet
    - payment_intent.payment_failed: Mark payment as failed
    - customer.subscription.created: Activate subscription
    - customer.subscription.updated: Update subscription status
    - customer.subscription.deleted: Cancel subscription
    - invoice.payment_succeeded: Renew subscription
    - invoice.payment_failed: Suspend subscription
    """
    # Get raw body
    body = await request.body()

    # Verify webhook signature
    try:
        event = verify_webhook_signature(body, stripe_signature)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    event_type = event.type
    event_data = event.data.object

    # Handle different event types
    try:
        if event_type == "payment_intent.succeeded":
            await handle_payment_intent_succeeded(event_data, db)

        elif event_type == "payment_intent.payment_failed":
            await handle_payment_intent_failed(event_data, db)

        elif event_type == "customer.subscription.created":
            await handle_subscription_created(event_data, db)

        elif event_type == "customer.subscription.updated":
            await handle_subscription_updated(event_data, db)

        elif event_type == "customer.subscription.deleted":
            await handle_subscription_deleted(event_data, db)

        elif event_type == "invoice.payment_succeeded":
            await handle_invoice_payment_succeeded(event_data, db)

        elif event_type == "invoice.payment_failed":
            await handle_invoice_payment_failed(event_data, db)

        else:
            print(f"[WEBHOOK] Unhandled event type: {event_type}")

        return {"status": "success", "event_type": event_type}

    except Exception as e:
        print(f"[WEBHOOK ERROR] {event_type}: {e}")
        raise HTTPException(status_code=500, detail=f"Webhook processing failed: {e}")


# === WEBHOOK EVENT HANDLERS ===

async def handle_payment_intent_succeeded(payment_intent, db: AsyncSession):
    """Handle payment_intent.succeeded event."""
    payment_intent_id = payment_intent.id
    metadata = payment_intent.metadata

    # Get payment record
    result = await db.execute(
        select(Payment).where(Payment.stripe_payment_intent_id == payment_intent_id)
    )
    payment = result.scalar_one_or_none()

    if not payment:
        print(f"[WEBHOOK] Payment not found for intent: {payment_intent_id}")
        return

    if payment.status == PaymentStatus.SUCCEEDED:
        print(f"[WEBHOOK] Payment already processed: {payment_intent_id}")
        return

    # Mark payment as succeeded
    payment.status = PaymentStatus.SUCCEEDED
    payment.completed_at = datetime.utcnow()
    payment.stripe_charge_id = payment_intent.latest_charge if hasattr(payment_intent, 'latest_charge') else None

    # If stelline purchase, credit wallet
    if payment.transaction_type == TransactionType.STELLINE_PURCHASE:
        # Check if StellinePurchase already exists
        stelline_result = await db.execute(
            select(StellinePurchase).where(StellinePurchase.payment_id == payment.id)
        )
        stelline_purchase = stelline_result.scalar_one_or_none()

        if not stelline_purchase:
            # Create StellinePurchase record
            stelline_purchase = StellinePurchase(
                user_id=payment.user_id,
                payment_id=payment.id,
                package_type=metadata.get("package", "unknown") if metadata else "unknown",
                stelline_amount=payment.stelline_amount,
                price_eur_cents=payment.amount_eur,
                delivered=False
            )
            db.add(stelline_purchase)

        # Credit wallet if not already delivered
        if not stelline_purchase.delivered:
            wallet_result = await db.execute(
                select(StellineWallet).where(StellineWallet.user_id == payment.user_id)
            )
            wallet = wallet_result.scalar_one_or_none()

            if not wallet:
                wallet = StellineWallet(user_id=payment.user_id, balance_stelline=0)
                db.add(wallet)

            wallet.balance_stelline += payment.stelline_amount
            stelline_purchase.delivered = True
            stelline_purchase.delivered_at = datetime.utcnow()

            print(f"[WEBHOOK] Credited {payment.stelline_amount} stelline to user {payment.user_id}")

    await db.commit()
    print(f"[WEBHOOK] Payment succeeded: {payment_intent_id}")


async def handle_payment_intent_failed(payment_intent, db: AsyncSession):
    """Handle payment_intent.payment_failed event."""
    payment_intent_id = payment_intent.id

    result = await db.execute(
        select(Payment).where(Payment.stripe_payment_intent_id == payment_intent_id)
    )
    payment = result.scalar_one_or_none()

    if not payment:
        return

    payment.status = PaymentStatus.FAILED
    payment.failure_code = payment_intent.last_payment_error.code if hasattr(payment_intent, 'last_payment_error') and payment_intent.last_payment_error else None
    payment.failure_message = payment_intent.last_payment_error.message if hasattr(payment_intent, 'last_payment_error') and payment_intent.last_payment_error else "Payment failed"

    await db.commit()
    print(f"[WEBHOOK] Payment failed: {payment_intent_id}")


async def handle_subscription_created(subscription_obj, db: AsyncSession):
    """Handle customer.subscription.created event."""
    stripe_subscription_id = subscription_obj.id
    metadata = subscription_obj.metadata

    # Get subscription record
    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_subscription_id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        print(f"[WEBHOOK] Subscription not found: {stripe_subscription_id}")
        return

    # Update subscription details
    subscription.status = SubscriptionStatus(subscription_obj.status)
    subscription.current_period_start = datetime.fromtimestamp(subscription_obj.current_period_start)
    subscription.current_period_end = datetime.fromtimestamp(subscription_obj.current_period_end)

    if subscription_obj.trial_start:
        subscription.trial_start = datetime.fromtimestamp(subscription_obj.trial_start)
    if subscription_obj.trial_end:
        subscription.trial_end = datetime.fromtimestamp(subscription_obj.trial_end)

    # Update user tier if subscription is active
    if subscription.status == SubscriptionStatus.ACTIVE:
        user_result = await db.execute(
            select(User).where(User.id == subscription.user_id)
        )
        user = user_result.scalar_one_or_none()

        if user:
            # Map subscription tier to UserTier
            tier_mapping = {
                "HYBRID_LIGHT": UserTier.HYBRID_LIGHT,
                "HYBRID_STANDARD": UserTier.HYBRID_STANDARD,
                "PREMIUM": UserTier.PREMIUM,
                "BUSINESS": UserTier.BUSINESS
            }
            if subscription.tier in tier_mapping:
                user.tier = tier_mapping[subscription.tier]
                print(f"[WEBHOOK] Updated user {user.id} tier to {subscription.tier}")

    await db.commit()
    print(f"[WEBHOOK] Subscription created: {stripe_subscription_id}")


async def handle_subscription_updated(subscription_obj, db: AsyncSession):
    """Handle customer.subscription.updated event."""
    stripe_subscription_id = subscription_obj.id

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_subscription_id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        return

    # Update subscription status
    subscription.status = SubscriptionStatus(subscription_obj.status)
    subscription.current_period_start = datetime.fromtimestamp(subscription_obj.current_period_start)
    subscription.current_period_end = datetime.fromtimestamp(subscription_obj.current_period_end)
    subscription.cancel_at_period_end = subscription_obj.cancel_at_period_end

    if subscription_obj.canceled_at:
        subscription.canceled_at = datetime.fromtimestamp(subscription_obj.canceled_at)

    await db.commit()
    print(f"[WEBHOOK] Subscription updated: {stripe_subscription_id} - Status: {subscription.status.value}")


async def handle_subscription_deleted(subscription_obj, db: AsyncSession):
    """Handle customer.subscription.deleted event."""
    stripe_subscription_id = subscription_obj.id

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == stripe_subscription_id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        return

    subscription.status = SubscriptionStatus.CANCELED
    subscription.canceled_at = datetime.utcnow()

    # Downgrade user to FREE tier
    user_result = await db.execute(
        select(User).where(User.id == subscription.user_id)
    )
    user = user_result.scalar_one_or_none()

    if user:
        user.tier = UserTier.FREE
        print(f"[WEBHOOK] Downgraded user {user.id} to FREE tier")

    await db.commit()
    print(f"[WEBHOOK] Subscription deleted: {stripe_subscription_id}")


async def handle_invoice_payment_succeeded(invoice, db: AsyncSession):
    """Handle invoice.payment_succeeded event."""
    subscription_id = invoice.subscription

    if not subscription_id:
        return

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        return

    # Create payment record for recurring payment
    payment = Payment(
        user_id=subscription.user_id,
        provider=PaymentProvider.STRIPE,
        transaction_type=TransactionType.SUBSCRIPTION,
        amount_eur=invoice.amount_paid,
        currency=invoice.currency.upper(),
        status=PaymentStatus.SUCCEEDED,
        stripe_payment_intent_id=invoice.payment_intent if hasattr(invoice, 'payment_intent') else None,
        subscription_id=subscription.id,
        description=f"Subscription renewal: {subscription.tier}",
        completed_at=datetime.utcnow()
    )
    db.add(payment)

    await db.commit()
    print(f"[WEBHOOK] Invoice payment succeeded for subscription: {subscription_id}")


async def handle_invoice_payment_failed(invoice, db: AsyncSession):
    """Handle invoice.payment_failed event."""
    subscription_id = invoice.subscription

    if not subscription_id:
        return

    result = await db.execute(
        select(Subscription).where(Subscription.stripe_subscription_id == subscription_id)
    )
    subscription = result.scalar_one_or_none()

    if not subscription:
        return

    # Mark subscription as past_due
    subscription.status = SubscriptionStatus.PAST_DUE

    # Create failed payment record
    payment = Payment(
        user_id=subscription.user_id,
        provider=PaymentProvider.STRIPE,
        transaction_type=TransactionType.SUBSCRIPTION,
        amount_eur=invoice.amount_due,
        currency=invoice.currency.upper(),
        status=PaymentStatus.FAILED,
        stripe_payment_intent_id=invoice.payment_intent if hasattr(invoice, 'payment_intent') else None,
        subscription_id=subscription.id,
        description=f"Subscription renewal failed: {subscription.tier}",
        failure_message="Invoice payment failed"
    )
    db.add(payment)

    await db.commit()
    print(f"[WEBHOOK] Invoice payment failed for subscription: {subscription_id}")

"""SUBSCRIPTIONS API"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from datetime import datetime, timedelta

from core.database import get_db
from core.security import get_current_user
from models.user import User, UserTier, SubscriptionHistory, SubscriptionStatus
from api.v1.schemas import MessageResponse

router = APIRouter()

@router.post("/upgrade/{tier}")
async def upgrade_subscription(
    tier: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upgrade subscription."""
    tier_prices = {
        "hybrid_light": 2.99,
        "hybrid_standard": 5.99,
        "premium": 9.99,
        "business": 49.99
    }

    if tier not in tier_prices:
        raise HTTPException(status_code=400, detail="Invalid tier")

    # Re-fetch user in current session to avoid detached instance error
    result = await db.execute(select(User).where(User.id == current_user.id))
    user = result.scalar_one()

    # Update user tier
    user.tier = UserTier(tier)
    user.subscription_end = datetime.utcnow() + timedelta(days=30)

    # Create history
    history = SubscriptionHistory(
        user_id=user.id,
        tier=UserTier(tier),
        status=SubscriptionStatus.ACTIVE,
        started_at=datetime.utcnow(),
        ends_at=user.subscription_end,
        price_paid=tier_prices[tier],
        currency="EUR"
    )

    db.add(history)
    await db.commit()

    return MessageResponse(message=f"Upgraded to {tier}!", success=True)

"""
================================================================================
AI_MODULE: Users API
AI_VERSION: 1.1.0
AI_DESCRIPTION: User profile endpoints with async-safe response construction
AI_BUSINESS: User self-service profile management
AI_TEACHING: Explicit ORM-to-Pydantic conversion to avoid MissingGreenlet

FIX 1.1.0: Replace model_validate() with explicit construction to fix
           MissingGreenlet: greenlet_spawn has not been called error
================================================================================
"""
from fastapi import APIRouter, Depends, Body
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional

from core.database import get_db
from core.security import get_current_user
from models.user import User
from api.v1.schemas import UserResponse, MessageResponse

router = APIRouter()


def _user_to_response(user: User) -> UserResponse:
    """
    Convert User ORM model to UserResponse.

    🎯 FIX: Explicit construction avoids MissingGreenlet error
    that occurs when Pydantic's model_validate() tries to access
    lazy-loaded attributes outside async context.
    """
    return UserResponse(
        id=str(user.id),
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        tier=user.tier.value if hasattr(user.tier, 'value') else str(user.tier),
        is_active=user.is_active,
        is_admin=user.is_admin,
        email_verified=user.email_verified,
        created_at=user.created_at,
        subscription_end=user.subscription_end,
        last_login=user.last_login
    )


@router.get("/me", response_model=UserResponse)
async def get_profile(current_user: User = Depends(get_current_user)):
    """Get user profile."""
    return _user_to_response(current_user)


@router.put("/me", response_model=UserResponse)
async def update_profile(
    full_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update profile (PUT - full_name only)."""
    current_user.full_name = full_name
    await db.commit()
    await db.refresh(current_user)
    return _user_to_response(current_user)


@router.patch("/me", response_model=UserResponse)
async def patch_profile(
    full_name: Optional[str] = Body(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update profile (PATCH - partial update)."""
    if full_name is not None:
        current_user.full_name = full_name
    await db.commit()
    await db.refresh(current_user)
    return _user_to_response(current_user)

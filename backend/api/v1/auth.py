"""
🎓 AI_MODULE: Auth API Router
🎓 AI_DESCRIPTION: Authentication endpoints (register, login, refresh)
🎓 AI_BUSINESS: Gateway per accesso piattaforma
🎓 AI_TEACHING: FastAPI router + dependency injection + error handling

💡 ENDPOINTS:
- POST /auth/register - Create new user
- POST /auth/login - Get JWT tokens
- POST /auth/refresh - Refresh access token
- GET /auth/me - Get current user profile
- POST /auth/logout - Logout (client-side)
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import get_current_user
from models.user import User
from modules.auth.auth_service import AuthService
from api.v1.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserResponse,
    MessageResponse
)

router = APIRouter()


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create new user account and return JWT tokens",
    responses={
        201: {"description": "User created successfully"},
        400: {"description": "Invalid input data"},
        409: {"description": "Email or username already exists"}
    }
)
async def register(
    data: UserRegisterRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Register new user.

    Creates user account with FREE tier by default.
    Returns JWT access token and refresh token for immediate login.

    - **email**: Valid email address (will send verification email)
    - **username**: Unique username (3-50 chars, alphanumeric + underscore)
    - **password**: Strong password (min 8 chars, 1 upper, 1 lower, 1 digit)
    - **full_name**: Optional full name
    """
    auth_service = AuthService(db)

    try:
        # Register user
        user = await auth_service.register_user(
            email=data.email,
            username=data.username,
            password=data.password,
            full_name=data.full_name
        )

        # Auto-login: create tokens
        login_result = await auth_service.login(
            email=data.email,
            password=data.password
        )

        # Build complete response with user info
        return TokenResponse(
            access_token=login_result["access_token"],
            refresh_token=login_result["refresh_token"],
            token_type=login_result["token_type"],
            expires_in=1800,  # 30 minutes in seconds
            user=UserResponse(
                id=str(user.id),
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                tier=user.tier.value,
                is_active=user.is_active,
                is_admin=user.is_admin,
                email_verified=user.email_verified,
                created_at=user.created_at,
                subscription_end=user.subscription_end,
                last_login=user.last_login
            )
        )

    except ValueError as e:
        # Handle duplicate email/username
        error_msg = str(e)
        if "already registered" in error_msg or "already taken" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=error_msg
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login user",
    description="Authenticate user and return JWT tokens",
    responses={
        200: {"description": "Login successful"},
        401: {"description": "Invalid credentials"},
        400: {"description": "Account disabled"}
    }
)
async def login(
    data: UserLoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Login user.

    Returns JWT access token (30 min expiry) and refresh token (7 days).

    - **email**: Registered email address
    - **password**: User password

    **Note**: Store refresh_token securely (HttpOnly cookie recommended).
    """
    auth_service = AuthService(db)

    try:
        result = await auth_service.login(
            email=data.email,
            password=data.password
        )

        # Get user for response (case-insensitive come auth_service)
        from sqlalchemy import select, func
        user_result = await db.execute(
            select(User).where(func.lower(User.email) == data.email.lower())
        )
        user = user_result.scalar_one_or_none()

        if user is None:
            raise ValueError("User not found after login")

        # Build complete response
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            token_type=result["token_type"],
            expires_in=1800,  # 30 minutes in seconds
            user=UserResponse(
                id=str(user.id),
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                tier=user.tier.value,
                is_active=user.is_active,
                is_admin=user.is_admin,
                email_verified=user.email_verified,
                created_at=user.created_at,
                subscription_end=user.subscription_end,
                last_login=user.last_login
            )
        )

    except ValueError as e:
        error_msg = str(e)

        if "disabled" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=error_msg
            )

        # Invalid credentials
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh access token",
    description="Use refresh token to get new access token",
    responses={
        200: {"description": "Token refreshed successfully"},
        401: {"description": "Invalid or expired refresh token"}
    }
)
async def refresh_token(
    data: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token.

    Use when access token expires (30 min).
    Returns new access token + new refresh token (token rotation).

    - **refresh_token**: Valid refresh token from login

    **Security**: Old refresh token invalidated after use.
    """
    auth_service = AuthService(db)

    try:
        result = await auth_service.refresh_access_token(data.refresh_token)

        # Decode token to get user email
        import jwt
        from core.security import SECRET_KEY, ALGORITHM
        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")

        # Get user for response
        from sqlalchemy import select
        user_result = await db.execute(
            select(User).where(User.email == email)
        )
        user = user_result.scalar_one()

        # Build complete response with user info
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=result["refresh_token"],
            token_type=result["token_type"],
            expires_in=1800,  # 30 minutes in seconds
            user=UserResponse(
                id=str(user.id),
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                tier=user.tier.value,
                is_active=user.is_active,
                is_admin=user.is_admin,
                email_verified=user.email_verified,
                created_at=user.created_at,
                subscription_end=user.subscription_end,
                last_login=user.last_login
            )
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get current user profile",
    description="Get authenticated user information",
    responses={
        200: {"description": "User profile retrieved"},
        401: {"description": "Not authenticated"}
    }
)
async def get_me(
    current_user: User = Depends(get_current_user)
):
    """
    Get current user profile.

    Returns full user information for authenticated user.

    **Requires**: Valid JWT access token in Authorization header.
    """
    return UserResponse(
        id=str(current_user.id),
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        tier=current_user.tier.value,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        email_verified=current_user.email_verified,
        created_at=current_user.created_at
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout user",
    description="Logout user (client-side token deletion)",
    responses={
        200: {"description": "Logout successful"}
    }
)
async def logout():
    """
    Logout user.

    **Note**: JWT tokens are stateless, so logout is handled client-side.
    Client should delete access_token and refresh_token from storage.

    Server-side logout (token blacklist) can be implemented with Redis.
    """
    return MessageResponse(
        message="Logout successful. Please delete tokens from client storage.",
        success=True
    )


@router.post(
    "/verify-email/{token}",
    response_model=MessageResponse,
    summary="Verify email",
    description="Verify user email with token",
    responses={
        200: {"description": "Email verified"},
        400: {"description": "Invalid or expired token"}
    }
)
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify email address.

    User receives verification email with token after registration.

    - **token**: Email verification token from email link
    """
    auth_service = AuthService(db)

    try:
        await auth_service.verify_email(token)
        return MessageResponse(
            message="Email verified successfully! You can now access all features.",
            success=True
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.post(
    "/forgot-password",
    response_model=MessageResponse,
    summary="Request password reset",
    description="Send password reset email",
    responses={
        200: {"description": "Reset email sent"},
        404: {"description": "Email not found"}
    }
)
async def forgot_password(
    email: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Request password reset.

    Sends email with reset token to user.

    - **email**: Registered email address
    """
    auth_service = AuthService(db)

    try:
        await auth_service.request_password_reset(email)
        return MessageResponse(
            message="If the email exists, a password reset link has been sent.",
            success=True
        )

    except Exception as e:
        # Always return success to prevent email enumeration
        return MessageResponse(
            message="If the email exists, a password reset link has been sent.",
            success=True
        )


@router.post(
    "/reset-password/{token}",
    response_model=MessageResponse,
    summary="Reset password",
    description="Reset password with token",
    responses={
        200: {"description": "Password reset successful"},
        400: {"description": "Invalid or expired token"}
    }
)
async def reset_password(
    token: str,
    new_password: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Reset password.

    User clicks link in reset email with token.

    - **token**: Password reset token from email
    - **new_password**: New password (same requirements as registration)
    """
    auth_service = AuthService(db)

    try:
        await auth_service.reset_password(token, new_password)
        return MessageResponse(
            message="Password reset successfully! You can now login with your new password.",
            success=True
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

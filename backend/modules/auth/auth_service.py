"""
Authentication Service
Handles user registration, login, and token management
"""

from datetime import datetime, timedelta
from typing import Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from models.user import User, UserTier
from core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    decode_access_token,
    SECRET_KEY,
    ALGORITHM
)
import jwt


class AuthService:
    """Authentication service for user management"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def register_user(
        self,
        email: str,
        username: str,
        password: str,
        full_name: Optional[str] = None
    ) -> User:
        """
        Register a new user

        Args:
            email: User email
            username: Unique username
            password: Plain text password
            full_name: Optional full name

        Returns:
            Created User object

        Raises:
            ValueError: If email or username already exists
        """
        # Check if email exists (case-insensitive)
        result = await self.db.execute(
            select(User).where(func.lower(User.email) == email.lower())
        )
        if result.scalar_one_or_none():
            raise ValueError("Email already registered")

        # Check if username exists
        result = await self.db.execute(
            select(User).where(User.username == username)
        )
        if result.scalar_one_or_none():
            raise ValueError("Username already taken")

        # Create user
        user = User(
            id=uuid.uuid4(),
            email=email,
            username=username,
            hashed_password=get_password_hash(password),
            full_name=full_name,
            tier=UserTier.FREE,
            is_active=True,
            is_admin=False,
            email_verified=False,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        return user

    async def login(self, email: str, password: str) -> dict:
        """
        Authenticate user and return tokens

        Args:
            email: User email
            password: Plain text password

        Returns:
            Dict with access_token, refresh_token, token_type

        Raises:
            ValueError: If credentials are invalid or user is disabled
        """
        # Find user
        result = await self.db.execute(
            select(User).where(func.lower(User.email) == email.lower())
        )
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("Invalid email or password")

        # Verify password
        if not verify_password(password, user.hashed_password):
            raise ValueError("Invalid email or password")

        # Check if user is active
        if not user.is_active:
            raise ValueError("User account is disabled")

        # Update last login
        user.last_login = datetime.utcnow()
        await self.db.commit()

        # Create tokens
        access_token = create_access_token(
            data={
                "sub": user.username,
                "email": user.email,
                "user_id": str(user.id),
                "is_superuser": user.is_admin
            }
        )

        refresh_token = create_access_token(
            data={
                "sub": user.username,
                "email": user.email,
                "user_id": str(user.id),
                "type": "refresh"
            },
            expires_delta=timedelta(days=7)
        )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    async def refresh_access_token(self, refresh_token: str) -> dict:
        """
        Refresh access token using refresh token

        Args:
            refresh_token: Valid refresh token

        Returns:
            Dict with new access_token, refresh_token, token_type

        Raises:
            ValueError: If refresh token is invalid or expired
        """
        try:
            # Decode refresh token
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

            # Verify it's a refresh token
            if payload.get("type") != "refresh":
                raise ValueError("Invalid token type")

            username = payload.get("sub")
            email = payload.get("email")
            user_id = payload.get("user_id")

            if not username or not email:
                raise ValueError("Invalid token payload")

            # Get user from database
            result = await self.db.execute(
                select(User).where(func.lower(User.email) == email.lower())
            )
            user = result.scalar_one_or_none()

            if not user:
                raise ValueError("User not found")

            if not user.is_active:
                raise ValueError("User account is disabled")

            # Create new tokens
            access_token = create_access_token(
                data={
                    "sub": user.username,
                    "email": user.email,
                    "user_id": str(user.id),
                    "is_superuser": user.is_admin
                }
            )

            new_refresh_token = create_access_token(
                data={
                    "sub": user.username,
                    "email": user.email,
                    "user_id": str(user.id),
                    "type": "refresh"
                },
                expires_delta=timedelta(days=7)
            )

            return {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "bearer"
            }

        except jwt.ExpiredSignatureError:
            raise ValueError("Refresh token has expired")
        except jwt.PyJWTError:
            raise ValueError("Invalid refresh token")

    async def verify_email(self, token: str) -> bool:
        """
        Verify user email with token

        Args:
            token: Email verification token

        Returns:
            True if verified successfully

        Raises:
            ValueError: If token is invalid or expired
        """
        try:
            # Decode token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            # Check token type
            if payload.get("type") != "email_verification":
                raise ValueError("Invalid token type")

            user_id = payload.get("user_id")
            email = payload.get("email")

            if not user_id or not email:
                raise ValueError("Invalid token payload")

            # Get user
            result = await self.db.execute(
                select(User).where(User.id == uuid.UUID(user_id))
            )
            user = result.scalar_one_or_none()

            if not user:
                raise ValueError("User not found")

            if user.email != email:
                raise ValueError("Email mismatch")

            # Mark as verified
            user.email_verified = True
            user.updated_at = datetime.utcnow()
            await self.db.commit()

            return True

        except jwt.ExpiredSignatureError:
            raise ValueError("Verification link has expired. Please request a new one.")
        except jwt.PyJWTError:
            raise ValueError("Invalid verification token")

    async def request_password_reset(self, email: str) -> bool:
        """
        Request password reset (send email with reset token)

        Args:
            email: User email address

        Returns:
            True if email was sent

        Raises:
            ValueError: If user not found
        """
        # Find user
        result = await self.db.execute(
            select(User).where(func.lower(User.email) == email.lower())
        )
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("User not found")

        # Generate reset token (1 hour expiry)
        reset_token = create_access_token(
            data={
                "sub": user.username,
                "email": user.email,
                "user_id": str(user.id),
                "type": "password_reset"
            },
            expires_delta=timedelta(hours=1)
        )

        # Send email
        from core.email import email_service
        await email_service.send_password_reset_email(
            to_email=user.email,
            username=user.username,
            reset_token=reset_token
        )

        return True

    async def reset_password(self, token: str, new_password: str) -> bool:
        """
        Reset password with token

        Args:
            token: Password reset token
            new_password: New password

        Returns:
            True if reset successfully

        Raises:
            ValueError: If token is invalid or expired
        """
        try:
            # Decode token
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            # Check token type
            if payload.get("type") != "password_reset":
                raise ValueError("Invalid token type")

            user_id = payload.get("user_id")
            email = payload.get("email")

            if not user_id or not email:
                raise ValueError("Invalid token payload")

            # Get user
            result = await self.db.execute(
                select(User).where(User.id == uuid.UUID(user_id))
            )
            user = result.scalar_one_or_none()

            if not user:
                raise ValueError("User not found")

            if user.email != email:
                raise ValueError("Email mismatch")

            # Update password
            user.hashed_password = get_password_hash(new_password)
            user.updated_at = datetime.utcnow()
            await self.db.commit()

            return True

        except jwt.ExpiredSignatureError:
            raise ValueError("Reset link has expired. Please request a new one.")
        except jwt.PyJWTError:
            raise ValueError("Invalid reset token")

    async def send_verification_email(self, user_id: uuid.UUID) -> bool:
        """
        Send email verification link to user

        Args:
            user_id: User ID

        Returns:
            True if email sent successfully

        Raises:
            ValueError: If user not found
        """
        # Get user
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            raise ValueError("User not found")

        # Generate verification token (24 hour expiry)
        verification_token = create_access_token(
            data={
                "sub": user.username,
                "email": user.email,
                "user_id": str(user.id),
                "type": "email_verification"
            },
            expires_delta=timedelta(hours=24)
        )

        # Send email
        from core.email import email_service
        await email_service.send_verification_email(
            to_email=user.email,
            username=user.username,
            verification_token=verification_token
        )

        return True

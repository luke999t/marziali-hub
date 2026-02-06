"""
🔒 Security and Authentication
JWT token handling, password hashing, and authentication dependencies
"""

from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt import PyJWTError, DecodeError, InvalidTokenError
from passlib.context import CryptContext
from fastapi import HTTPException, Security, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from pydantic import BaseModel
import os
import uuid

# NOTE: get_db and get_db_optional imports removed - all auth functions now create
# their own sessions to avoid async generator conflicts

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "martial_arts_secret_key_change_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# HTTP Bearer token scheme
security = HTTPBearer()


class TokenData(BaseModel):
    """Token payload data"""
    username: str
    email: str
    user_id: Optional[str] = None
    is_superuser: bool = False


# === Password Hashing ===

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a password using bcrypt
    """
    return pwd_context.hash(password)


# === JWT Token Management ===

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token

    Args:
        data: Token payload (should include 'sub' for username)
        expires_delta: Optional custom expiration time

    Returns:
        Encoded JWT token string
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    # Add unique jti (JWT ID) for token rotation - ensures each token is unique
    to_encode.update({
        "exp": expire,
        "jti": str(uuid.uuid4())
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> TokenData:
    """
    Decode and validate a JWT token

    Args:
        token: JWT token string

    Returns:
        TokenData with decoded payload

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        email: str = payload.get("email")
        user_id: str = payload.get("user_id")
        is_superuser: bool = payload.get("is_superuser", False)

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")

        return TokenData(
            username=username,
            email=email,
            user_id=user_id,
            is_superuser=is_superuser
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except (PyJWTError, DecodeError, InvalidTokenError):
        raise HTTPException(status_code=401, detail="Could not validate credentials")


# === Authentication Dependencies ===

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    """
    FastAPI dependency to get the current authenticated user

    Returns:
        User object from database

    Raises:
        HTTPException: If token is invalid or user not found

    Usage:
        @app.get("/protected")
        async def protected_route(current_user: User = Depends(get_current_user)):
            return {"user": current_user.email}

    FIX 2026-01-26: Create own DB session to avoid 'generator didn't stop after athrow()'
    error caused by mixing async generator dependencies.
    """
    # Import here to avoid circular import
    from models.user import User
    from sqlalchemy.orm import load_only
    from core.database import AsyncSessionLocal
    import sys

    sys.stderr.write(f"\n=== GET_CURRENT_USER CALLED ===\n")
    sys.stderr.flush()

    # Decode JWT token
    token = credentials.credentials
    token_data = decode_access_token(token)

    sys.stderr.write(f"Token decoded: email={token_data.email}, user_id={token_data.user_id}\n")
    sys.stderr.flush()

    # FIX: Create own session instead of using Depends(get_db_optional)
    async with AsyncSessionLocal() as db:
        sys.stderr.write("DB session created\n")
        sys.stderr.flush()

        # Load ONLY essential columns to avoid triggering broken relationships
        # This prevents SQLAlchemy from trying to load Payment, Subscription, etc.
        result = await db.execute(
            select(User).options(
                load_only(
                    User.id, User.email, User.username, User.hashed_password,
                    User.full_name, User.is_active, User.is_admin, User.tier,
                    User.email_verified, User.created_at, User.updated_at,
                    User.last_login, User.subscription_end, User.auto_renew,
                    User.stripe_customer_id, User.ads_unlocked_videos,
                    User.ads_unlock_valid_until, User.language_preference,
                    User.subtitle_preference, User.quality_preference, User.last_seen
                )
            ).where(
                or_(User.email == token_data.email, User.username == token_data.username)
            )
        )
        user = result.scalar_one_or_none()

        sys.stderr.write(f"User query result: {user}\n")
        sys.stderr.flush()

        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        sys.stderr.write(f"Returning user: id={user.id}, email={user.email}\n")
        sys.stderr.flush()

        return user


async def get_current_admin_user(
    current_user = Depends(get_current_user)
):
    """
    FastAPI dependency to get the current authenticated admin user

    Returns:
        User object with admin privileges

    Raises:
        HTTPException: If user is not an admin

    Usage:
        @app.post("/admin/users")
        async def create_user(admin: User = Depends(get_current_admin_user)):
            # Only admins can access this
            pass

    FIX 2026-01-26: Create own DB session to avoid async generator conflicts.
    """
    from sqlalchemy import text
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        query = text("SELECT is_admin FROM users WHERE id = :user_id")
        result = await db.execute(query, {"user_id": str(current_user.id)})
        row = result.fetchone()

        if not row:
            raise HTTPException(status_code=401, detail="User not found")

        is_admin = row[0]

        if not is_admin:
            raise HTTPException(status_code=403, detail="Not enough permissions")

        return current_user


async def get_current_active_user(
    current_user = Depends(get_current_user)
):
    """
    FastAPI dependency to get current active (non-disabled) user

    Returns:
        Active user object

    Raises:
        HTTPException: If user is disabled
    """
    if getattr(current_user, 'is_active', True) is False:
        raise HTTPException(status_code=400, detail="Inactive user")

    return current_user


async def get_current_maestro(
    current_user = Depends(get_current_user)
):
    """
    FastAPI dependency to get the current authenticated Maestro.

    Returns:
        Maestro object if user has a maestro profile

    Raises:
        HTTPException 403: If user is not a maestro

    FIX 2026-01-26: Create own DB session to avoid async generator conflicts.
    """
    from models.maestro import Maestro
    from sqlalchemy import select
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Maestro).where(Maestro.user_id == current_user.id)
        )
        maestro = result.scalar_one_or_none()

        if not maestro:
            raise HTTPException(
                status_code=403,
                detail="Maestro access required"
            )

        return maestro


async def require_admin(
    current_user = Depends(get_current_admin_user)
):
    """
    FastAPI dependency that requires admin access.
    Alias for get_current_admin_user for semantic clarity.

    Returns:
        User object with admin privileges
    """
    return current_user



# Optional bearer for optional authentication
optional_security = HTTPBearer(auto_error=False)

async def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(optional_security)
):
    """
    Get user if authenticated, None otherwise.

    FIX 2026-01-26: Create own DB session to avoid async generator conflicts.
    """
    if not credentials:
        return None
    try:
        from models.user import User
        from sqlalchemy.orm import load_only
        from core.database import AsyncSessionLocal

        token = credentials.credentials
        token_data = decode_access_token(token)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(User).options(
                    load_only(
                        User.id, User.email, User.username, User.hashed_password,
                        User.full_name, User.is_active, User.is_admin, User.tier,
                        User.email_verified, User.created_at, User.updated_at,
                        User.last_login, User.subscription_end, User.auto_renew,
                        User.stripe_customer_id, User.ads_unlocked_videos,
                        User.ads_unlock_valid_until, User.language_preference,
                        User.subtitle_preference, User.quality_preference, User.last_seen
                    )
                ).where(
                    or_(User.email == token_data.email, User.username == token_data.username)
                )
            )
            user = result.scalar_one_or_none()
            return user
    except:
        return None

# === Optional: Token without database lookup ===

async def get_token_data(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> TokenData:
    """
    Get token data without database lookup
    Useful for lightweight authentication checks

    Returns:
        TokenData (not full User object)
    """
    token = credentials.credentials
    return decode_access_token(token)

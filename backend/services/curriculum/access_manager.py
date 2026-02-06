"""
================================================================================
    ACCESS MANAGER - Curriculum Access Control & Invite Codes
================================================================================

AI_MODULE: AccessManager Service
AI_DESCRIPTION: Manages invite codes, access control, and enrollment authorization
AI_BUSINESS: Enables monetization via invite-only curricula and ASD memberships
AI_TEACHING: Role-based access control + time-based token validation

ACCESS MODES:
    PUBLIC          - Anyone can view and enroll
    MEMBERS_ONLY    - Requires ASD membership
    INVITE_ONLY     - Requires valid invitation code

INVITE CODE FEATURES:
    - Configurable max uses (or unlimited)
    - Expiration dates
    - Per-maestro tracking
    - Usage analytics

SETTINGS (from curriculum.settings):
    allow_level_skip: bool
    invite_code_lifetime_days: int
    max_active_invite_codes: int

================================================================================
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
import logging
import secrets
import hashlib
import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_

logger = logging.getLogger(__name__)


@dataclass
class AccessCheckResult:
    """Result of an access check."""
    allowed: bool
    reason: str
    access_type: str  # 'public', 'member', 'invited', 'owner', 'denied'
    requires_payment: bool = False
    enrollment_id: Optional[str] = None


@dataclass
class InviteCodeInfo:
    """Information about an invite code."""
    code: str
    curriculum_id: str
    curriculum_name: str
    max_uses: Optional[int]
    current_uses: int
    expires_at: Optional[datetime]
    is_valid: bool
    created_by_name: Optional[str]


class AccessManager:
    """
    Manages curriculum access control and invitation codes.

    RESPONSIBILITIES:
    - Check user access to curricula
    - Generate and validate invite codes
    - Track code usage
    - Handle ASD membership checks
    - Manage enrollment authorization

    USAGE:
        manager = AccessManager(db_session)
        result = await manager.check_access(user_id, curriculum_id)
        code = await manager.generate_invite_code(curriculum_id, maestro_id)
        is_valid = await manager.validate_invite_code(code, curriculum_id)
    """

    def __init__(self, db: Optional[AsyncSession] = None):
        """
        Initialize AccessManager.

        Args:
            db: Optional database session (can be set later)
        """
        self.db = db

        # Settings defaults
        self.settings = {
            'invite_code_length': 8,
            'default_expiry_days': 30,
            'max_active_codes_per_curriculum': 50,
            'code_prefix': '',  # Optional prefix like 'KARATE-'
        }

        logger.info("AccessManager initialized")

    def set_db(self, db: AsyncSession):
        """Set database session."""
        self.db = db

    # ==========================================================================
    # ACCESS CHECK METHODS
    # ==========================================================================

    async def check_access(
        self,
        user_id: str,
        curriculum_id: str,
        invitation_code: Optional[str] = None
    ) -> AccessCheckResult:
        """
        Check if user can access a curriculum.

        Args:
            user_id: User ID
            curriculum_id: Curriculum ID
            invitation_code: Optional invite code

        Returns:
            AccessCheckResult with access decision
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import (
            Curriculum, CurriculumEnrollment, CurriculumInviteCode,
            CurriculumVisibility, CurriculumOwnerType
        )
        from models import User, ASDMember

        # Load curriculum
        result = await self.db.execute(
            select(Curriculum).where(Curriculum.id == curriculum_id)
        )
        curriculum = result.scalar_one_or_none()

        if not curriculum:
            return AccessCheckResult(
                allowed=False,
                reason="Curriculum not found",
                access_type="denied"
            )

        if not curriculum.is_active:
            return AccessCheckResult(
                allowed=False,
                reason="Curriculum is not active",
                access_type="denied"
            )

        # Load user
        user_result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = user_result.scalar_one_or_none()

        if not user:
            return AccessCheckResult(
                allowed=False,
                reason="User not found",
                access_type="denied"
            )

        # Admin bypass
        if user.is_admin:
            return AccessCheckResult(
                allowed=True,
                reason="Admin access",
                access_type="owner"
            )

        # Check if already enrolled
        enrollment_result = await self.db.execute(
            select(CurriculumEnrollment).where(
                CurriculumEnrollment.user_id == user_id,
                CurriculumEnrollment.curriculum_id == curriculum_id,
                CurriculumEnrollment.is_active == True
            )
        )
        enrollment = enrollment_result.scalar_one_or_none()

        if enrollment:
            return AccessCheckResult(
                allowed=True,
                reason="Already enrolled",
                access_type="member",
                enrollment_id=str(enrollment.id)
            )

        # Check visibility rules
        if curriculum.visibility == CurriculumVisibility.PUBLIC:
            return AccessCheckResult(
                allowed=True,
                reason="Public curriculum",
                access_type="public",
                requires_payment=curriculum.pricing_model.value == "separate_purchase"
            )

        if curriculum.visibility == CurriculumVisibility.MEMBERS_ONLY:
            # Check ASD membership
            if curriculum.owner_asd_id:
                membership_result = await self.db.execute(
                    select(ASDMember).where(
                        ASDMember.user_id == user_id,
                        ASDMember.asd_id == curriculum.owner_asd_id,
                        ASDMember.is_active == True
                    )
                )
                membership = membership_result.scalar_one_or_none()

                if membership:
                    return AccessCheckResult(
                        allowed=True,
                        reason="ASD member",
                        access_type="member"
                    )
                else:
                    return AccessCheckResult(
                        allowed=False,
                        reason="Requires ASD membership",
                        access_type="denied"
                    )
            else:
                # No specific ASD, allow
                return AccessCheckResult(
                    allowed=True,
                    reason="Members-only curriculum (no ASD restriction)",
                    access_type="member"
                )

        if curriculum.visibility == CurriculumVisibility.INVITE_ONLY:
            if invitation_code:
                # Validate invite code
                code_valid, code_reason = await self.validate_invite_code(
                    invitation_code,
                    curriculum_id
                )
                if code_valid:
                    return AccessCheckResult(
                        allowed=True,
                        reason="Valid invitation code",
                        access_type="invited"
                    )
                else:
                    return AccessCheckResult(
                        allowed=False,
                        reason=code_reason,
                        access_type="denied"
                    )
            else:
                return AccessCheckResult(
                    allowed=False,
                    reason="Requires invitation code",
                    access_type="denied"
                )

        return AccessCheckResult(
            allowed=False,
            reason="Access denied",
            access_type="denied"
        )

    async def check_level_access(
        self,
        user_id: str,
        curriculum_id: str,
        level_id: str
    ) -> AccessCheckResult:
        """
        Check if user can access a specific level.

        Args:
            user_id: User ID
            curriculum_id: Curriculum ID
            level_id: Level ID

        Returns:
            AccessCheckResult
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import (
            Curriculum, CurriculumLevel, CurriculumEnrollment,
            LevelProgress, LevelStatus
        )

        # First check curriculum access
        curriculum_access = await self.check_access(user_id, curriculum_id)
        if not curriculum_access.allowed:
            return curriculum_access

        # Get enrollment
        enrollment_result = await self.db.execute(
            select(CurriculumEnrollment).where(
                CurriculumEnrollment.user_id == user_id,
                CurriculumEnrollment.curriculum_id == curriculum_id,
                CurriculumEnrollment.is_active == True
            )
        )
        enrollment = enrollment_result.scalar_one_or_none()

        if not enrollment:
            return AccessCheckResult(
                allowed=False,
                reason="Not enrolled in curriculum",
                access_type="denied"
            )

        # Get level
        level_result = await self.db.execute(
            select(CurriculumLevel).where(CurriculumLevel.id == level_id)
        )
        level = level_result.scalar_one_or_none()

        if not level or str(level.curriculum_id) != str(curriculum_id):
            return AccessCheckResult(
                allowed=False,
                reason="Level not found",
                access_type="denied"
            )

        # Check if level is free
        if level.is_free:
            return AccessCheckResult(
                allowed=True,
                reason="Free level",
                access_type="member",
                enrollment_id=str(enrollment.id)
            )

        # Get curriculum settings
        curriculum_result = await self.db.execute(
            select(Curriculum).where(Curriculum.id == curriculum_id)
        )
        curriculum = curriculum_result.scalar_one_or_none()

        # Check sequential progression
        if curriculum and curriculum.get_setting('sequential_progression', True):
            if level.order > 0:
                # Check if previous level is completed
                prev_level = level.get_previous_level() if hasattr(level, 'get_previous_level') else None

                if prev_level:
                    prev_progress_result = await self.db.execute(
                        select(LevelProgress).where(
                            LevelProgress.enrollment_id == enrollment.id,
                            LevelProgress.level_id == prev_level.id
                        )
                    )
                    prev_progress = prev_progress_result.scalar_one_or_none()

                    if not prev_progress or prev_progress.status != LevelStatus.COMPLETED:
                        # Check if skip is allowed
                        if curriculum.get_setting('allow_level_skip', False):
                            return AccessCheckResult(
                                allowed=True,
                                reason="Level skip allowed",
                                access_type="member",
                                enrollment_id=str(enrollment.id)
                            )
                        else:
                            return AccessCheckResult(
                                allowed=False,
                                reason="Must complete previous level first",
                                access_type="denied"
                            )

        return AccessCheckResult(
            allowed=True,
            reason="Access granted",
            access_type="member",
            enrollment_id=str(enrollment.id)
        )

    # ==========================================================================
    # INVITE CODE METHODS
    # ==========================================================================

    async def generate_invite_code(
        self,
        curriculum_id: str,
        maestro_id: Optional[str] = None,
        max_uses: Optional[int] = None,
        expires_days: Optional[int] = None,
        custom_code: Optional[str] = None
    ) -> str:
        """
        Generate a new invitation code.

        Args:
            curriculum_id: Curriculum to invite to
            maestro_id: Maestro creating the code
            max_uses: Maximum uses (None = unlimited)
            expires_days: Days until expiration
            custom_code: Optional custom code

        Returns:
            Generated invite code string
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import Curriculum, CurriculumInviteCode

        # Verify curriculum exists
        result = await self.db.execute(
            select(Curriculum).where(Curriculum.id == curriculum_id)
        )
        curriculum = result.scalar_one_or_none()

        if not curriculum:
            raise ValueError("Curriculum not found")

        # Check max active codes
        active_codes_result = await self.db.execute(
            select(func.count()).select_from(CurriculumInviteCode).where(
                CurriculumInviteCode.curriculum_id == curriculum_id,
                CurriculumInviteCode.is_active == True
            )
        )
        active_count = active_codes_result.scalar() or 0

        max_codes = self.settings.get('max_active_codes_per_curriculum', 50)
        if active_count >= max_codes:
            raise ValueError(f"Maximum {max_codes} active codes allowed")

        # Generate code
        if custom_code:
            code = custom_code.upper()
        else:
            code = self._generate_code()

        # Check uniqueness
        existing = await self.db.execute(
            select(CurriculumInviteCode).where(CurriculumInviteCode.code == code)
        )
        if existing.scalar_one_or_none():
            # Regenerate
            code = self._generate_code()

        # Calculate expiration
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        elif self.settings.get('default_expiry_days'):
            expires_at = datetime.utcnow() + timedelta(
                days=self.settings['default_expiry_days']
            )

        # Create invite code
        invite_code = CurriculumInviteCode(
            id=uuid.uuid4(),
            curriculum_id=curriculum_id,
            code=code,
            created_by_maestro_id=maestro_id,
            max_uses=max_uses,
            expires_at=expires_at,
            is_active=True
        )

        self.db.add(invite_code)
        await self.db.commit()

        logger.info(f"Generated invite code: {code} for curriculum {curriculum_id}")

        return code

    def _generate_code(self) -> str:
        """Generate random invite code."""
        length = self.settings.get('invite_code_length', 8)
        prefix = self.settings.get('code_prefix', '')

        code = secrets.token_urlsafe(length)[:length].upper()

        if prefix:
            code = f"{prefix}{code}"

        return code

    async def validate_invite_code(
        self,
        code: str,
        curriculum_id: str
    ) -> Tuple[bool, str]:
        """
        Validate an invitation code.

        Args:
            code: The invite code to validate
            curriculum_id: Curriculum to validate for

        Returns:
            Tuple of (is_valid, reason)
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode

        result = await self.db.execute(
            select(CurriculumInviteCode).where(
                CurriculumInviteCode.code == code.upper(),
                CurriculumInviteCode.curriculum_id == curriculum_id
            )
        )
        invite_code = result.scalar_one_or_none()

        if not invite_code:
            return False, "Invalid code"

        is_valid, reason = invite_code.is_valid()
        return is_valid, reason

    async def use_invite_code(
        self,
        code: str,
        curriculum_id: str,
        user_id: str
    ) -> Tuple[bool, str]:
        """
        Use an invitation code.

        Args:
            code: The invite code
            curriculum_id: Curriculum ID
            user_id: User using the code

        Returns:
            Tuple of (success, message)
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode

        result = await self.db.execute(
            select(CurriculumInviteCode).where(
                CurriculumInviteCode.code == code.upper(),
                CurriculumInviteCode.curriculum_id == curriculum_id
            )
        )
        invite_code = result.scalar_one_or_none()

        if not invite_code:
            return False, "Invalid code"

        is_valid, reason = invite_code.is_valid()
        if not is_valid:
            return False, reason

        # Use the code
        success = invite_code.use()
        if success:
            await self.db.commit()
            logger.info(f"Invite code {code} used by user {user_id}")
            return True, "Code applied successfully"
        else:
            return False, "Failed to use code"

    async def get_invite_code_info(self, code: str) -> Optional[InviteCodeInfo]:
        """
        Get information about an invite code.

        Args:
            code: The invite code

        Returns:
            InviteCodeInfo or None if not found
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode, Curriculum
        from models import Maestro

        result = await self.db.execute(
            select(CurriculumInviteCode)
            .where(CurriculumInviteCode.code == code.upper())
        )
        invite_code = result.scalar_one_or_none()

        if not invite_code:
            return None

        # Get curriculum name
        curriculum_result = await self.db.execute(
            select(Curriculum).where(Curriculum.id == invite_code.curriculum_id)
        )
        curriculum = curriculum_result.scalar_one_or_none()

        # Get creator name
        creator_name = None
        if invite_code.created_by_maestro_id:
            maestro_result = await self.db.execute(
                select(Maestro).where(Maestro.id == invite_code.created_by_maestro_id)
            )
            maestro = maestro_result.scalar_one_or_none()
            if maestro:
                creator_name = maestro.display_name or "Maestro"

        is_valid, _ = invite_code.is_valid()

        return InviteCodeInfo(
            code=invite_code.code,
            curriculum_id=str(invite_code.curriculum_id),
            curriculum_name=curriculum.name if curriculum else "Unknown",
            max_uses=invite_code.max_uses,
            current_uses=invite_code.current_uses,
            expires_at=invite_code.expires_at,
            is_valid=is_valid,
            created_by_name=creator_name
        )

    async def list_curriculum_codes(
        self,
        curriculum_id: str,
        include_expired: bool = False
    ) -> List[InviteCodeInfo]:
        """
        List all invite codes for a curriculum.

        Args:
            curriculum_id: Curriculum ID
            include_expired: Whether to include expired codes

        Returns:
            List of InviteCodeInfo
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode, Curriculum
        from models import Maestro

        query = select(CurriculumInviteCode).where(
            CurriculumInviteCode.curriculum_id == curriculum_id
        )

        if not include_expired:
            query = query.where(CurriculumInviteCode.is_active == True)

        result = await self.db.execute(query.order_by(CurriculumInviteCode.created_at.desc()))
        codes = result.scalars().all()

        # Get curriculum
        curriculum_result = await self.db.execute(
            select(Curriculum).where(Curriculum.id == curriculum_id)
        )
        curriculum = curriculum_result.scalar_one_or_none()
        curriculum_name = curriculum.name if curriculum else "Unknown"

        infos = []
        for code in codes:
            creator_name = None
            if code.created_by_maestro_id:
                maestro_result = await self.db.execute(
                    select(Maestro).where(Maestro.id == code.created_by_maestro_id)
                )
                maestro = maestro_result.scalar_one_or_none()
                if maestro:
                    creator_name = maestro.display_name or "Maestro"

            is_valid, _ = code.is_valid()

            infos.append(InviteCodeInfo(
                code=code.code,
                curriculum_id=str(code.curriculum_id),
                curriculum_name=curriculum_name,
                max_uses=code.max_uses,
                current_uses=code.current_uses,
                expires_at=code.expires_at,
                is_valid=is_valid,
                created_by_name=creator_name
            ))

        return infos

    async def deactivate_code(self, code: str) -> bool:
        """
        Deactivate an invite code.

        Args:
            code: The invite code

        Returns:
            True if deactivated, False if not found
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode

        result = await self.db.execute(
            select(CurriculumInviteCode).where(CurriculumInviteCode.code == code.upper())
        )
        invite_code = result.scalar_one_or_none()

        if not invite_code:
            return False

        invite_code.deactivate()
        await self.db.commit()

        logger.info(f"Deactivated invite code: {code}")
        return True

    async def bulk_generate_codes(
        self,
        curriculum_id: str,
        count: int,
        maestro_id: Optional[str] = None,
        max_uses: Optional[int] = 1,
        expires_days: Optional[int] = None
    ) -> List[str]:
        """
        Generate multiple invite codes at once.

        Args:
            curriculum_id: Curriculum ID
            count: Number of codes to generate
            maestro_id: Maestro creating the codes
            max_uses: Max uses per code
            expires_days: Days until expiration

        Returns:
            List of generated codes
        """
        codes = []
        for _ in range(count):
            code = await self.generate_invite_code(
                curriculum_id=curriculum_id,
                maestro_id=maestro_id,
                max_uses=max_uses,
                expires_days=expires_days
            )
            codes.append(code)

        logger.info(f"Bulk generated {count} codes for curriculum {curriculum_id}")
        return codes

    # ==========================================================================
    # ANALYTICS METHODS
    # ==========================================================================

    async def get_code_usage_stats(self, curriculum_id: str) -> Dict[str, Any]:
        """
        Get usage statistics for invite codes.

        Args:
            curriculum_id: Curriculum ID

        Returns:
            Dict with usage statistics
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode

        # Total codes
        total_result = await self.db.execute(
            select(func.count()).select_from(CurriculumInviteCode).where(
                CurriculumInviteCode.curriculum_id == curriculum_id
            )
        )
        total_codes = total_result.scalar() or 0

        # Active codes
        active_result = await self.db.execute(
            select(func.count()).select_from(CurriculumInviteCode).where(
                CurriculumInviteCode.curriculum_id == curriculum_id,
                CurriculumInviteCode.is_active == True
            )
        )
        active_codes = active_result.scalar() or 0

        # Total uses
        uses_result = await self.db.execute(
            select(func.sum(CurriculumInviteCode.current_uses)).where(
                CurriculumInviteCode.curriculum_id == curriculum_id
            )
        )
        total_uses = uses_result.scalar() or 0

        return {
            'total_codes': total_codes,
            'active_codes': active_codes,
            'expired_codes': total_codes - active_codes,
            'total_uses': total_uses,
            'average_uses_per_code': total_uses / total_codes if total_codes > 0 else 0
        }

    async def cleanup_expired_codes(self, curriculum_id: Optional[str] = None) -> int:
        """
        Deactivate expired codes.

        Args:
            curriculum_id: Optional curriculum ID to limit cleanup

        Returns:
            Number of codes deactivated
        """
        if not self.db:
            raise RuntimeError("Database session not set")

        from models.curriculum import CurriculumInviteCode

        query = select(CurriculumInviteCode).where(
            CurriculumInviteCode.is_active == True,
            CurriculumInviteCode.expires_at < datetime.utcnow()
        )

        if curriculum_id:
            query = query.where(CurriculumInviteCode.curriculum_id == curriculum_id)

        result = await self.db.execute(query)
        expired_codes = result.scalars().all()

        count = 0
        for code in expired_codes:
            code.deactivate()
            count += 1

        if count > 0:
            await self.db.commit()
            logger.info(f"Cleaned up {count} expired invite codes")

        return count

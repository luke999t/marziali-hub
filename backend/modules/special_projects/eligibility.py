"""
AI_MODULE: Voting Eligibility Calculator
AI_DESCRIPTION: Calcolo eligibilita e peso voto basato su subscription/engagement
AI_BUSINESS: Democratizzazione voto con peso meritocratico, +15% conversioni
AI_TEACHING: Strategy pattern, caching, async DB queries, metrics aggregation

ALTERNATIVE_VALUTATE:
- Real-time calculation: Scartato, troppo lento per ogni request
- Daily batch: Scartato, eligibilita non aggiornata
- Simple tier check: Scartato, non incentiva engagement free users

PERCHE_QUESTA_SOLUZIONE:
- Cached + on-demand: Balance performance/freshness
- Multi-factor scoring: watch_time + ads + completions
- Progressive unlock: Free users vedono progresso verso voto

METRICHE_SUCCESSO:
- Eligibility check: <20ms (cached), <200ms (fresh)
- Free user conversion to eligible: +30%
- Accuracy: 100% (no false positives)
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from uuid import UUID

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from .config import (
    SpecialProjectsConfig,
    get_special_projects_config,
    SubscriptionTier
)
from .models import VotingEligibility, EligibilityStatus

logger = logging.getLogger(__name__)


class EligibilityCalculator:
    """
    Calcola eligibilita voto per utente.

    Considera:
    - Subscription tier (premium -> peso alto)
    - Engagement metrics (per free users)
    - Storico comportamento
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[SpecialProjectsConfig] = None
    ):
        self.db = db
        self.config = config or get_special_projects_config()

    def get_current_vote_cycle(self) -> str:
        """
        Ottiene ciclo voto corrente.

        Returns:
            String formato "YYYY-MM" (es: "2024-01")
        """
        now = datetime.utcnow()
        return f"{now.year}-{now.month:02d}"

    async def check_eligibility(
        self,
        user_id: UUID,
        force_recalculate: bool = False
    ) -> VotingEligibility:
        """
        Verifica eligibilita utente per votare.

        Args:
            user_id: ID utente
            force_recalculate: Forza ricalcolo anche se cache valida

        Returns:
            VotingEligibility con status e peso
        """
        current_cycle = self.get_current_vote_cycle()

        # Check cache
        if not force_recalculate:
            cached = await self._get_cached_eligibility(user_id, current_cycle)
            if cached and self._is_cache_valid(cached):
                return cached

        # Calculate fresh eligibility
        eligibility = await self._calculate_eligibility(user_id, current_cycle)

        # Save to cache
        await self._save_eligibility(eligibility)

        return eligibility

    async def _get_cached_eligibility(
        self,
        user_id: UUID,
        cycle: str
    ) -> Optional[VotingEligibility]:
        """Ottiene eligibilita cached dal database."""
        result = await self.db.execute(
            select(VotingEligibility).where(
                VotingEligibility.user_id == user_id,
                VotingEligibility.vote_cycle == cycle
            )
        )
        return result.scalar_one_or_none()

    def _is_cache_valid(self, eligibility: VotingEligibility) -> bool:
        """Verifica se cache ancora valida."""
        if not eligibility.valid_until:
            return False
        return datetime.utcnow() < eligibility.valid_until

    async def _calculate_eligibility(
        self,
        user_id: UUID,
        cycle: str
    ) -> VotingEligibility:
        """
        Calcola eligibilita fresh.

        Steps:
        1. Get user subscription tier
        2. If premium -> eligible with full weight
        3. If free -> check engagement metrics
        4. Calculate progress and status
        """
        # Get user info
        user_tier, user_data = await self._get_user_subscription_info(user_id)

        # Premium users are always eligible
        if user_tier in [SubscriptionTier.PREMIUM_FULL, SubscriptionTier.PREMIUM_HYBRID]:
            return self._create_premium_eligibility(user_id, cycle, user_tier)

        # Free users need engagement check
        if user_tier == SubscriptionTier.FREE_NO_ADS:
            return self._create_ineligible_eligibility(
                user_id, cycle, user_tier,
                "Subscription tier does not include voting rights"
            )

        # Free with ads - check engagement
        return await self._calculate_free_user_eligibility(user_id, cycle)

    async def _get_user_subscription_info(
        self,
        user_id: UUID
    ) -> Tuple[SubscriptionTier, Dict[str, Any]]:
        """
        Ottiene info subscription utente.

        Mappa user.tier a SubscriptionTier per calcolo peso.
        """
        # Query user from database
        from models import User, UserTier

        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()

        if not user:
            return SubscriptionTier.FREE_NO_ADS, {}

        # Map UserTier to SubscriptionTier
        tier_mapping = {
            UserTier.PREMIUM: SubscriptionTier.PREMIUM_FULL,
            UserTier.BUSINESS: SubscriptionTier.PREMIUM_FULL,
            UserTier.HYBRID_STANDARD: SubscriptionTier.PREMIUM_HYBRID,
            UserTier.HYBRID_LIGHT: SubscriptionTier.PREMIUM_HYBRID,
            UserTier.FREE: SubscriptionTier.FREE_WITH_ADS,
            UserTier.PAY_PER_VIEW: SubscriptionTier.FREE_WITH_ADS
        }

        subscription_tier = tier_mapping.get(user.tier, SubscriptionTier.FREE_NO_ADS)

        return subscription_tier, {
            "email": user.email,
            "tier": user.tier.value if user.tier else "free"
        }

    def _create_premium_eligibility(
        self,
        user_id: UUID,
        cycle: str,
        tier: SubscriptionTier
    ) -> VotingEligibility:
        """Crea eligibilita per utente premium."""
        weight = self.config.vote_weights.get_weight(tier)

        return VotingEligibility(
            user_id=user_id,
            vote_cycle=cycle,
            status=EligibilityStatus.ELIGIBLE,
            vote_weight=weight,
            subscription_tier=tier.value,
            progress_percent=100.0,
            calculated_at=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(hours=24)
        )

    def _create_ineligible_eligibility(
        self,
        user_id: UUID,
        cycle: str,
        tier: SubscriptionTier,
        reason: str
    ) -> VotingEligibility:
        """Crea eligibilita negativa."""
        return VotingEligibility(
            user_id=user_id,
            vote_cycle=cycle,
            status=EligibilityStatus.NOT_ELIGIBLE,
            vote_weight=0,
            subscription_tier=tier.value,
            progress_percent=0.0,
            ineligibility_reason=reason,
            calculated_at=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(hours=1)  # Shorter cache for ineligible
        )

    async def _calculate_free_user_eligibility(
        self,
        user_id: UUID,
        cycle: str
    ) -> VotingEligibility:
        """
        Calcola eligibilita per utente free con ads.

        Verifica requisiti engagement:
        - Minuti guardati
        - Ads viste
        - Video completati
        """
        requirements = self.config.free_user_requirements
        lookback_date = datetime.utcnow() - timedelta(days=requirements.lookback_days)

        # Get engagement metrics
        metrics = await self._get_user_engagement_metrics(user_id, lookback_date)

        watch_minutes = metrics.get("watch_minutes", 0)
        ads_watched = metrics.get("ads_watched", 0)
        videos_completed = metrics.get("videos_completed", 0)

        # Calculate progress
        progress_items = []

        if requirements.min_watch_minutes > 0:
            progress_items.append(
                min(100, (watch_minutes / requirements.min_watch_minutes) * 100)
            )

        if requirements.min_ads_watched > 0:
            progress_items.append(
                min(100, (ads_watched / requirements.min_ads_watched) * 100)
            )

        if requirements.min_videos_completed > 0:
            progress_items.append(
                min(100, (videos_completed / requirements.min_videos_completed) * 100)
            )

        progress_percent = sum(progress_items) / len(progress_items) if progress_items else 0

        # Check if all requirements met
        meets_watch = watch_minutes >= requirements.min_watch_minutes
        meets_ads = ads_watched >= requirements.min_ads_watched
        meets_videos = videos_completed >= requirements.min_videos_completed

        all_met = meets_watch and meets_ads and meets_videos

        # Build reason if not eligible
        reason = None
        if not all_met:
            missing = []
            if not meets_watch:
                missing.append(f"watch_minutes: {watch_minutes}/{requirements.min_watch_minutes}")
            if not meets_ads:
                missing.append(f"ads_watched: {ads_watched}/{requirements.min_ads_watched}")
            if not meets_videos:
                missing.append(f"videos_completed: {videos_completed}/{requirements.min_videos_completed}")
            reason = f"Requirements not met: {', '.join(missing)}"

        # Determine status
        if all_met:
            status = EligibilityStatus.ELIGIBLE
            weight = self.config.vote_weights.free_with_ads
        elif progress_percent >= 75:
            status = EligibilityStatus.PENDING  # Almost there!
            weight = 0
        else:
            status = EligibilityStatus.NOT_ELIGIBLE
            weight = 0

        return VotingEligibility(
            user_id=user_id,
            vote_cycle=cycle,
            status=status,
            vote_weight=weight,
            subscription_tier=SubscriptionTier.FREE_WITH_ADS.value,
            watch_minutes_current=watch_minutes,
            ads_watched_current=ads_watched,
            videos_completed_current=videos_completed,
            watch_minutes_required=requirements.min_watch_minutes,
            ads_watched_required=requirements.min_ads_watched,
            videos_completed_required=requirements.min_videos_completed,
            progress_percent=progress_percent,
            ineligibility_reason=reason,
            calculated_at=datetime.utcnow(),
            valid_until=datetime.utcnow() + timedelta(hours=6)  # Refresh more often for free users
        )

    async def _get_user_engagement_metrics(
        self,
        user_id: UUID,
        since: datetime
    ) -> Dict[str, int]:
        """
        Ottiene metriche engagement utente.

        Queries:
        - ViewingHistory per watch_minutes e completions
        - AdsSession per ads_watched
        """
        from models import ViewingHistory

        # Watch time and completions
        viewing_result = await self.db.execute(
            select(
                func.coalesce(func.sum(ViewingHistory.watch_duration), 0).label("total_seconds"),
                func.count(ViewingHistory.id).filter(ViewingHistory.completed == True).label("completed")
            ).where(
                ViewingHistory.user_id == user_id,
                ViewingHistory.watched_at >= since
            )
        )
        viewing_data = viewing_result.one()

        watch_minutes = int(viewing_data.total_seconds / 60) if viewing_data.total_seconds else 0
        videos_completed = viewing_data.completed or 0

        # Ads watched (from AdsSession if exists)
        ads_watched = 0
        try:
            from models import AdsSession, AdsSessionStatus
            ads_result = await self.db.execute(
                select(func.count(AdsSession.id)).where(
                    AdsSession.user_id == user_id,
                    AdsSession.status == AdsSessionStatus.COMPLETED,
                    AdsSession.created_at >= since
                )
            )
            ads_watched = ads_result.scalar() or 0
        except Exception as e:
            logger.warning(f"Could not query ads: {e}")
            ads_watched = 0

        return {
            "watch_minutes": watch_minutes,
            "ads_watched": ads_watched,
            "videos_completed": videos_completed
        }

    async def _save_eligibility(self, eligibility: VotingEligibility):
        """Salva/aggiorna eligibilita in database."""
        # Check if exists
        existing = await self._get_cached_eligibility(
            eligibility.user_id,
            eligibility.vote_cycle
        )

        if existing:
            # Update
            existing.status = eligibility.status
            existing.vote_weight = eligibility.vote_weight
            existing.subscription_tier = eligibility.subscription_tier
            existing.watch_minutes_current = eligibility.watch_minutes_current
            existing.ads_watched_current = eligibility.ads_watched_current
            existing.videos_completed_current = eligibility.videos_completed_current
            existing.progress_percent = eligibility.progress_percent
            existing.ineligibility_reason = eligibility.ineligibility_reason
            existing.calculated_at = eligibility.calculated_at
            existing.valid_until = eligibility.valid_until
        else:
            # Insert
            self.db.add(eligibility)

        await self.db.flush()

    async def get_eligible_users_count(self, cycle: Optional[str] = None) -> int:
        """Conta utenti eligible per ciclo."""
        cycle = cycle or self.get_current_vote_cycle()

        result = await self.db.execute(
            select(func.count(VotingEligibility.id)).where(
                VotingEligibility.vote_cycle == cycle,
                VotingEligibility.status == EligibilityStatus.ELIGIBLE
            )
        )
        return result.scalar() or 0

    async def recalculate_all_eligibilities(self, cycle: Optional[str] = None):
        """
        Ricalcola eligibilita per tutti gli utenti.

        Usato per batch job notturno o dopo cambio config.
        """
        from models import User

        cycle = cycle or self.get_current_vote_cycle()

        # Get all active users
        users_result = await self.db.execute(
            select(User.id).where(User.is_active == True)
        )
        user_ids = [row[0] for row in users_result.all()]

        logger.info(f"Recalculating eligibility for {len(user_ids)} users")

        for user_id in user_ids:
            try:
                await self.check_eligibility(user_id, force_recalculate=True)
            except Exception as e:
                logger.error(f"Failed to calculate eligibility for {user_id}: {e}")

        await self.db.commit()
        logger.info("Eligibility recalculation complete")

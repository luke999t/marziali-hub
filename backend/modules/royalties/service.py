"""
AI_MODULE: Royalty Service Layer
AI_DESCRIPTION: Business logic per gestione royalties, views, payouts
AI_BUSINESS: Orchestrazione completa flusso royalties dal tracking al payout
AI_TEACHING: Service pattern, transaction management, async operations

ALTERNATIVE_VALUTATE:
- Fat controllers: Scartato, logica dispersa negli endpoint
- Repository pattern puro: Scartato, over-engineering per questo caso
- Event sourcing: Scartato, complessita non giustificata

PERCHE_QUESTA_SOLUZIONE:
- Service layer: Centralizza business logic, testabile
- Transaction boundaries: Gestione esplicita commit/rollback
- Dependency injection: DB session iniettata, mockable
- Async native: Performance ottimali per I/O

METRICHE_SUCCESSO:
- Transaction success rate: >99.9%
- Service method coverage: 100%
- Error handling: Tutte le eccezioni gestite
"""

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging

from sqlalchemy import select, func, and_, or_, update, cast, String, literal, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import RoyaltyConfig, get_royalty_config
from .models import (
    MasterProfile,
    StudentSubscription,
    ViewRoyalty,
    RoyaltyPayout,
    RoyaltyBlockchainBatch,
    MasterSwitchHistory,
    PricingModel,
    PayoutMethod,
    PayoutStatus,
    SubscriptionType,
    RoyaltyMilestone
)
from .schemas import (
    MasterProfileCreate,
    MasterProfileUpdate,
    StudentSubscriptionCreate,
    TrackViewRequest,
    RoyaltyDashboard,
    PayoutRequestCreate
)
from .blockchain_tracker import RoyaltyBlockchainTracker, RoyaltyViewData

logger = logging.getLogger(__name__)


class RoyaltyService:
    """
    Service layer per gestione royalties.

    Gestisce:
    - Profili maestri e configurazioni
    - Abbonamenti studenti
    - Tracking views e calcolo royalties
    - Payout management
    - Fraud detection
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[RoyaltyConfig] = None,
        blockchain_tracker: Optional[RoyaltyBlockchainTracker] = None
    ):
        """
        Inizializza service.

        Args:
            db: Sessione database async
            config: Configurazione royalties
            blockchain_tracker: Tracker blockchain (lazy init se None)
        """
        self.db = db
        self.config = config or get_royalty_config()
        self._blockchain_tracker = blockchain_tracker

    @property
    def blockchain(self) -> RoyaltyBlockchainTracker:
        """Lazy initialization blockchain tracker."""
        if self._blockchain_tracker is None:
            self._blockchain_tracker = RoyaltyBlockchainTracker(self.config)
        return self._blockchain_tracker

    # ======================== MASTER PROFILE ========================

    async def create_master_profile(
        self,
        data: MasterProfileCreate
    ) -> MasterProfile:
        """
        Crea profilo maestro per royalties.

        Args:
            data: Dati creazione profilo

        Returns:
            MasterProfile creato

        Raises:
            ValueError: Se profilo esiste gia
        """
        # Check se esiste gia
        existing = await self.db.execute(
            select(MasterProfile).where(MasterProfile.user_id == data.user_id)
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"Profile already exists for user {data.user_id}")

        profile = MasterProfile(
            user_id=data.user_id,
            maestro_id=data.maestro_id,
            pricing_model=PricingModel(data.pricing_model),
            payout_method=PayoutMethod(data.payout_method),
            wallet_address=data.wallet_address
        )

        self.db.add(profile)
        await self.db.flush()

        logger.info(f"Created master profile {profile.id} for user {data.user_id}")
        return profile

    async def get_master_profile(
        self,
        profile_id: Optional[UUID] = None,
        user_id: Optional[UUID] = None
    ) -> Optional[MasterProfile]:
        """
        Ottiene profilo maestro.

        Args:
            profile_id: ID profilo
            user_id: ID utente

        Returns:
            MasterProfile o None
        """
        query = select(MasterProfile)

        if profile_id:
            query = query.where(MasterProfile.id == profile_id)
        elif user_id:
            query = query.where(MasterProfile.user_id == user_id)
        else:
            return None

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def update_master_profile(
        self,
        profile_id: UUID,
        data: MasterProfileUpdate
    ) -> Optional[MasterProfile]:
        """
        Aggiorna profilo maestro.

        Args:
            profile_id: ID profilo
            data: Dati update

        Returns:
            MasterProfile aggiornato o None
        """
        profile = await self.get_master_profile(profile_id=profile_id)
        if not profile:
            return None

        update_data = data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if value is not None:
                if field == 'pricing_model':
                    value = PricingModel(value)
                elif field == 'payout_method':
                    value = PayoutMethod(value)
                setattr(profile, field, value)

        profile.updated_at = datetime.utcnow()
        await self.db.flush()

        logger.info(f"Updated master profile {profile_id}")
        return profile

    async def get_available_masters(
        self,
        student_id: UUID,
        discipline: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Ottiene maestri disponibili per subscription.

        Args:
            student_id: ID studente
            discipline: Filtro disciplina
            limit: Max risultati

        Returns:
            Lista maestri con info subscription
        """
        # Get masters with profiles
        query = select(MasterProfile).where(
            MasterProfile.is_active == True,
            MasterProfile.pricing_model != str(PricingModel.FREE.value)
        ).limit(limit)

        result = await self.db.execute(query)
        profiles = result.scalars().all()

        # Get existing subscriptions for student
        existing_subs = await self.db.execute(
            select(StudentSubscription.master_id).where(
                StudentSubscription.student_id == student_id,
                StudentSubscription.is_active == True
            )
        )
        subscribed_master_ids = set(r[0] for r in existing_subs.all())

        masters = []
        for profile in profiles:
            # Get prices
            sub_types = self.config.subscription_types
            monthly = profile.get_effective_pricing('monthly', sub_types)
            yearly = profile.get_effective_pricing('yearly', sub_types)
            lifetime = profile.get_effective_pricing('lifetime', sub_types)

            masters.append({
                'master_id': profile.id,
                'user_id': profile.user_id,
                'pricing_model': profile.pricing_model.value,
                'total_subscribers': profile.total_subscribers,
                'monthly_price_cents': monthly,
                'yearly_price_cents': yearly,
                'lifetime_price_cents': lifetime,
                'already_subscribed': profile.id in subscribed_master_ids
            })

        return masters

    # ======================== SUBSCRIPTIONS ========================

    async def create_subscription(
        self,
        data: StudentSubscriptionCreate,
        price_cents: int
    ) -> StudentSubscription:
        """
        Crea abbonamento studente.

        Args:
            data: Dati subscription
            price_cents: Prezzo pagato

        Returns:
            StudentSubscription creato

        Raises:
            ValueError: Se subscription non valida
        """
        # Validate master mode
        if data.master_id:
            await self._validate_master_subscription(data.student_id, data.master_id)

        # Calculate expiry
        expires_at = None
        sub_config = self.config.subscription_types.get(data.subscription_tier)
        if sub_config and sub_config.period_days:
            expires_at = datetime.utcnow() + timedelta(days=sub_config.period_days)

        subscription = StudentSubscription(
            student_id=data.student_id,
            master_id=data.master_id,
            subscription_type=SubscriptionType(data.subscription_type),
            subscription_tier=data.subscription_tier,
            price_paid_cents=price_cents,
            expires_at=expires_at,
            auto_renew=data.auto_renew,
            video_id=data.video_id
        )

        self.db.add(subscription)
        await self.db.flush()

        # Update master stats
        if data.master_id:
            await self._increment_master_subscribers(data.master_id)

        logger.info(f"Created subscription {subscription.id} for student {data.student_id}")
        return subscription

    async def _validate_master_subscription(
        self,
        student_id: UUID,
        master_id: UUID
    ):
        """
        Valida subscription a maestro.

        Checks:
        - Max masters per student
        - Cooldown period
        """
        # Check max masters
        if self.config.student_master_mode == 'single':
            # Cancel existing master subscriptions
            await self.db.execute(
                update(StudentSubscription)
                .where(
                    StudentSubscription.student_id == student_id,
                    StudentSubscription.subscription_type == str(SubscriptionType.MASTER.value),
                    StudentSubscription.is_active == True
                )
                .values(is_active=False, cancelled_at=datetime.utcnow())
            )
        else:
            # Check limit
            count_result = await self.db.execute(
                select(func.count(StudentSubscription.id)).where(
                    StudentSubscription.student_id == student_id,
                    StudentSubscription.subscription_type == str(SubscriptionType.MASTER.value),
                    StudentSubscription.is_active == True
                )
            )
            current_count = count_result.scalar() or 0

            if current_count >= self.config.max_masters_per_student:
                raise ValueError(
                    f"Max masters limit reached ({self.config.max_masters_per_student})"
                )

        # Check cooldown
        if self.config.master_switch_cooldown_days > 0:
            cooldown_date = datetime.utcnow() - timedelta(
                days=self.config.master_switch_cooldown_days
            )
            recent_switch = await self.db.execute(
                select(MasterSwitchHistory).where(
                    MasterSwitchHistory.student_id == student_id,
                    MasterSwitchHistory.switched_at > cooldown_date
                )
            )
            if recent_switch.scalar_one_or_none():
                raise ValueError(
                    f"Cooldown period active ({self.config.master_switch_cooldown_days} days)"
                )

    async def _increment_master_subscribers(self, master_id: UUID):
        """Incrementa contatore subscribers maestro."""
        await self.db.execute(
            update(MasterProfile)
            .where(MasterProfile.id == master_id)
            .values(total_subscribers=MasterProfile.total_subscribers + 1)
        )

    async def get_student_subscriptions(
        self,
        student_id: UUID,
        active_only: bool = True
    ) -> List[StudentSubscription]:
        """
        Ottiene subscriptions studente.

        Args:
            student_id: ID studente
            active_only: Solo attive

        Returns:
            Lista subscriptions
        """
        query = select(StudentSubscription).where(
            StudentSubscription.student_id == student_id
        )

        if active_only:
            query = query.where(StudentSubscription.is_active == True)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def cancel_subscription(
        self,
        subscription_id: UUID,
        student_id: UUID
    ) -> bool:
        """
        Cancella subscription.

        Args:
            subscription_id: ID subscription
            student_id: ID studente (per verifica ownership)

        Returns:
            True se cancellata
        """
        result = await self.db.execute(
            update(StudentSubscription)
            .where(
                StudentSubscription.id == subscription_id,
                StudentSubscription.student_id == student_id,
                StudentSubscription.is_active == True
            )
            .values(
                is_active=False,
                cancelled_at=datetime.utcnow(),
                auto_renew=False
            )
        )

        if result.rowcount > 0:
            logger.info(f"Cancelled subscription {subscription_id}")
            return True
        return False

    # ======================== VIEW TRACKING ========================

    async def track_view(
        self,
        request: TrackViewRequest,
        student_id: Optional[UUID],
        master_id: UUID,
        ip_address: Optional[str] = None
    ) -> Tuple[Optional[ViewRoyalty], str]:
        """
        Traccia view video e calcola royalty.

        Args:
            request: Dati tracking
            student_id: ID studente (None se anonimo)
            master_id: ID profilo maestro proprietario video
            ip_address: IP per fraud detection

        Returns:
            Tuple (ViewRoyalty, messaggio)
        """
        # milestone is now a string (already lowercase from Pydantic validator)
        milestone_str = request.milestone

        # Check duplicati
        stmt = select(ViewRoyalty.id).where(
            and_(
                ViewRoyalty.view_session_id == request.view_session_id,
                ViewRoyalty.milestone == milestone_str
            )
        ).limit(1)
        existing = await self.db.execute(stmt)
        if existing.first():
            return None, "Milestone already tracked for this session"

        # Fraud detection
        fraud_score, flag_reason = await self._check_fraud(
            student_id=student_id,
            video_id=request.video_id,
            watch_time=request.watch_time_seconds,
            video_duration=request.video_duration_seconds,
            ip_address=ip_address
        )

        if fraud_score > 0.8:
            logger.warning(f"Suspicious view detected: {flag_reason}")

        # Get master profile
        profile = await self.get_master_profile(profile_id=master_id)
        if not profile:
            return None, "Master profile not found"

        # Calculate amounts
        milestone_config = self.config.royalty_milestones
        gross_amount = profile.get_effective_milestone_amount(
            request.milestone,
            milestone_config
        )
        gross_cents = int(gross_amount * 100)

        split = profile.get_effective_royalty_split(
            self.config.revenue_split.model_dump()
        )
        platform_fee = int(gross_cents * split['platform_fee_percent'] / 100)
        master_amount = gross_cents - platform_fee

        # Create royalty record
        royalty = ViewRoyalty(
            video_id=request.video_id,
            master_id=master_id,
            student_id=student_id,
            view_session_id=request.view_session_id,
            milestone=milestone_str,
            gross_amount_cents=gross_cents,
            platform_fee_cents=platform_fee,
            master_amount_cents=master_amount,
            video_duration_seconds=request.video_duration_seconds,
            watch_time_seconds=request.watch_time_seconds,
            fraud_score=fraud_score,
            flagged_suspicious=fraud_score > 0.8,
            flag_reason=flag_reason if fraud_score > 0.8 else None,
            ip_hash=self._hash_ip(ip_address) if ip_address else None,
            device_fingerprint=request.device_fingerprint
        )

        self.db.add(royalty)
        await self.db.flush()

        # Update master stats
        await self.db.execute(
            update(MasterProfile)
            .where(MasterProfile.id == master_id)
            .values(
                total_views=MasterProfile.total_views + 1,
                total_royalties_cents=MasterProfile.total_royalties_cents + master_amount,
                pending_payout_cents=MasterProfile.pending_payout_cents + master_amount
            )
        )

        # Add to blockchain batch (non-blocking)
        if self.config.blockchain.enabled and not royalty.flagged_suspicious:
            view_data = RoyaltyViewData(
                royalty_id=str(royalty.id),
                video_id=str(request.video_id),
                master_id=str(master_id),
                student_id=str(student_id) if student_id else None,
                view_session_id=str(request.view_session_id),
                milestone=milestone_str,
                amount_cents=master_amount,
                timestamp=royalty.created_at
            )
            await self.blockchain.add_view_for_batch(view_data)

        logger.info(f"Tracked view {royalty.id} - {request.milestone} - {master_amount}c")
        return royalty, "View tracked successfully"

    async def _check_fraud(
        self,
        student_id: Optional[UUID],
        video_id: UUID,
        watch_time: int,
        video_duration: int,
        ip_address: Optional[str]
    ) -> Tuple[float, Optional[str]]:
        """
        Calcola fraud score per view.

        Returns:
            Tuple (score 0-1, reason se sospetta)
        """
        if not self.config.fraud_detection_enabled:
            return 0.0, None

        score = 0.0
        reasons = []

        # Check watch speed
        if watch_time > 0 and video_duration > 0:
            speed = video_duration / watch_time
            if speed > self.config.suspicious_speed_multiplier:
                score += 0.3
                reasons.append(f"Suspicious speed: {speed:.1f}x")

        # Check min watch time
        if watch_time < self.config.min_watch_time_seconds:
            score += 0.2
            reasons.append(f"Watch time too short: {watch_time}s")

        # Check daily view limit
        if student_id:
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0)
            daily_count = await self.db.execute(
                select(func.count(ViewRoyalty.id)).where(
                    ViewRoyalty.student_id == student_id,
                    ViewRoyalty.video_id == video_id,
                    ViewRoyalty.created_at >= today_start
                )
            )
            count = daily_count.scalar() or 0

            if count >= self.config.max_views_per_user_per_video_per_day:
                score += 0.5
                reasons.append(f"Daily limit exceeded: {count} views")

        return min(score, 1.0), "; ".join(reasons) if reasons else None

    def _hash_ip(self, ip: str) -> str:
        """Hash IP per privacy."""
        return hashlib.sha256(ip.encode()).hexdigest()

    # ======================== PAYOUTS ========================

    async def request_payout(
        self,
        request: PayoutRequestCreate
    ) -> Tuple[Optional[RoyaltyPayout], str]:
        """
        Richiede payout royalties.

        Args:
            request: Dati richiesta

        Returns:
            Tuple (RoyaltyPayout, messaggio)
        """
        profile = await self.get_master_profile(profile_id=request.master_id)
        if not profile:
            return None, "Master profile not found"

        if not profile.verified_for_payouts:
            return None, "Profile not verified for payouts"

        # Check minimum
        min_payout = profile.get_effective_min_payout(self.config.min_payout_cents)
        if profile.pending_payout_cents < min_payout:
            return None, f"Minimum payout not reached ({min_payout / 100:.2f} EUR)"

        # Get unsettled royalties
        unsettled = await self.db.execute(
            select(ViewRoyalty).where(
                ViewRoyalty.master_id == request.master_id,
                ViewRoyalty.settled == False,
                ViewRoyalty.flagged_suspicious == False
            ).order_by(ViewRoyalty.created_at)
        )
        royalties = list(unsettled.scalars().all())

        if not royalties:
            return None, "No unsettled royalties"

        # Calculate totals
        total_gross = sum(r.gross_amount_cents for r in royalties)
        total_master = sum(r.master_amount_cents for r in royalties)

        # Determine period
        period_start = min(r.created_at for r in royalties)
        period_end = max(r.created_at for r in royalties)

        # Create payout
        method = PayoutMethod(request.method) if request.method else profile.payout_method

        payout = RoyaltyPayout(
            master_id=request.master_id,
            gross_amount_cents=total_gross,
            fees_cents=0,  # Can add processing fees here
            net_amount_cents=total_master,
            period_start=period_start,
            period_end=period_end,
            views_count=len(royalties),
            method=method,
            status=str(PayoutStatus.PENDING.value),
            requested_at=datetime.utcnow(),
            wallet_address=profile.wallet_address if method == str(PayoutMethod.BLOCKCHAIN.value) else None,
            iban=profile.iban if method == str(PayoutMethod.BANK.value) else None,
            notes=request.notes
        )

        self.db.add(payout)
        await self.db.flush()

        # Mark royalties as settled
        for royalty in royalties:
            royalty.settled = True
            royalty.settled_at = datetime.utcnow()
            royalty.payout_id = payout.id

        # Update master pending
        await self.db.execute(
            update(MasterProfile)
            .where(MasterProfile.id == request.master_id)
            .values(
                pending_payout_cents=0,
                last_payout_at=datetime.utcnow()
            )
        )

        logger.info(f"Created payout {payout.id} - {total_master}c")
        return payout, "Payout request created successfully"

    async def process_payout(
        self,
        payout_id: UUID,
        approved_by: Optional[UUID] = None
    ) -> Tuple[bool, str]:
        """
        Processa payout (admin action).

        Args:
            payout_id: ID payout
            approved_by: ID admin che approva

        Returns:
            Tuple (success, message)
        """
        payout_result = await self.db.execute(
            select(RoyaltyPayout).where(RoyaltyPayout.id == payout_id)
        )
        payout = payout_result.scalar_one_or_none()

        if not payout:
            return False, "Payout not found"

        if payout.status != str(PayoutStatus.PENDING.value):
            return False, f"Payout not pending (status: {payout.status})"

        payout.mark_processing()
        payout.approved_by = approved_by

        # TODO: Integrate actual payment processing
        # - Blockchain: Call _blockchain_tracker
        # - Stripe: Call Stripe Connect transfer
        # - Bank: Create bank transfer

        # For now, mark as completed (simulate)
        payout.mark_completed()

        # Update master total paid
        await self.db.execute(
            update(MasterProfile)
            .where(MasterProfile.id == payout.master_id)
            .values(
                total_paid_out_cents=MasterProfile.total_paid_out_cents + payout.net_amount_cents
            )
        )

        logger.info(f"Processed payout {payout_id}")
        return True, "Payout processed successfully"

    async def get_master_payouts(
        self,
        master_id: UUID,
        limit: int = 50
    ) -> List[RoyaltyPayout]:
        """Ottiene storico payouts maestro."""
        result = await self.db.execute(
            select(RoyaltyPayout)
            .where(RoyaltyPayout.master_id == master_id)
            .order_by(RoyaltyPayout.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    # ======================== DASHBOARD ========================

    async def get_master_dashboard(
        self,
        master_id: UUID,
        days: int = 30
    ) -> RoyaltyDashboard:
        """
        Genera dashboard royalties per maestro.

        Args:
            master_id: ID profilo maestro
            days: Giorni da includere

        Returns:
            RoyaltyDashboard con aggregazioni
        """
        profile = await self.get_master_profile(profile_id=master_id)
        if not profile:
            raise ValueError("Master profile not found")

        period_start = datetime.utcnow() - timedelta(days=days)
        period_end = datetime.utcnow()

        # Get royalties in period
        royalties_result = await self.db.execute(
            select(ViewRoyalty).where(
                ViewRoyalty.master_id == master_id,
                ViewRoyalty.created_at >= period_start
            )
        )
        royalties = list(royalties_result.scalars().all())

        # Milestone breakdown
        milestone_breakdown = {}
        for milestone in RoyaltyMilestone:
            count = sum(1 for r in royalties if r.milestone == str(milestone.value))
            milestone_breakdown[milestone.value] = count

        # Daily trend
        daily_views = []
        for i in range(days):
            day = period_start + timedelta(days=i)
            day_end = day + timedelta(days=1)
            day_royalties = [
                r for r in royalties
                if day <= r.created_at < day_end
            ]
            daily_views.append({
                'date': day.strftime('%Y-%m-%d'),
                'views': len(day_royalties),
                'amount': sum(r.master_amount_cents for r in day_royalties)
            })

        # Last payout
        last_payout = await self.db.execute(
            select(RoyaltyPayout)
            .where(
                RoyaltyPayout.master_id == master_id,
                RoyaltyPayout.status == str(PayoutStatus.COMPLETED.value)
            )
            .order_by(RoyaltyPayout.completed_at.desc())
            .limit(1)
        )
        last_payout_record = last_payout.scalar_one_or_none()

        # New subscribers in period
        new_subs_result = await self.db.execute(
            select(func.count(StudentSubscription.id)).where(
                StudentSubscription.master_id == master_id,
                StudentSubscription.started_at >= period_start
            )
        )
        new_subscribers = new_subs_result.scalar() or 0

        return RoyaltyDashboard(
            master_id=master_id,
            period_start=period_start,
            period_end=period_end,
            total_views=len(royalties),
            total_royalties_cents=sum(r.master_amount_cents for r in royalties),
            pending_payout_cents=profile.pending_payout_cents,
            last_payout_amount_cents=last_payout_record.net_amount_cents if last_payout_record else 0,
            last_payout_date=last_payout_record.completed_at if last_payout_record else None,
            milestone_breakdown=milestone_breakdown,
            daily_views=daily_views,
            top_videos=[],  # TODO: Aggregate by video
            total_subscribers=profile.total_subscribers,
            new_subscribers_period=new_subscribers,
            can_request_payout=profile.can_request_payout(self.config.min_payout_cents),
            min_payout_cents=profile.get_effective_min_payout(self.config.min_payout_cents),
            next_auto_payout_date=None  # TODO: Calculate based on frequency
        )

    # ======================== ADMIN STATS ========================

    async def get_global_stats(
        self,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche globali (admin).

        Args:
            days: Giorni da includere

        Returns:
            Dict con stats aggregate (conforme a RoyaltyStats schema)
        
        🎓 AI_TEACHING: Il return deve matchare ESATTAMENTE lo schema RoyaltyStats
        in schemas.py, altrimenti FastAPI ritorna 500 ResponseValidationError.
        """
        period_start = datetime.utcnow() - timedelta(days=days)
        period_end = datetime.utcnow()

        # Total views
        views_result = await self.db.execute(
            select(func.count(ViewRoyalty.id)).where(
                ViewRoyalty.created_at >= period_start
            )
        )
        total_views = views_result.scalar() or 0

        # Total royalties
        royalties_result = await self.db.execute(
            select(
                func.sum(ViewRoyalty.gross_amount_cents),
                func.sum(ViewRoyalty.platform_fee_cents),
                func.sum(ViewRoyalty.master_amount_cents)
            ).where(ViewRoyalty.created_at >= period_start)
        )
        totals = royalties_result.one()

        # Active masters
        masters_result = await self.db.execute(
            select(func.count(MasterProfile.id)).where(
                MasterProfile.is_active == True
            )
        )
        active_masters = masters_result.scalar() or 0

        # Masters with pending payouts
        masters_pending_result = await self.db.execute(
            select(func.count(MasterProfile.id)).where(
                MasterProfile.pending_payout_cents > 0
            )
        )
        masters_with_pending = masters_pending_result.scalar() or 0

        # Pending payouts total
        pending_result = await self.db.execute(
            select(func.sum(MasterProfile.pending_payout_cents)).where(
                MasterProfile.pending_payout_cents > 0
            )
        )
        total_pending = pending_result.scalar() or 0

        # Total paid out
        paid_out_result = await self.db.execute(
            select(func.sum(RoyaltyPayout.net_amount_cents)).where(
                RoyaltyPayout.status == str(PayoutStatus.COMPLETED.value)
            )
        )
        total_paid_out = paid_out_result.scalar() or 0

        # Average payout
        avg_payout_result = await self.db.execute(
            select(func.avg(RoyaltyPayout.net_amount_cents)).where(
                RoyaltyPayout.status == str(PayoutStatus.COMPLETED.value)
            )
        )
        avg_payout = avg_payout_result.scalar() or 0

        # Active subscriptions
        active_subs_result = await self.db.execute(
            select(func.count(StudentSubscription.id)).where(
                StudentSubscription.is_active == True
            )
        )
        total_active_subscriptions = active_subs_result.scalar() or 0

        # New subscriptions in period
        new_subs_result = await self.db.execute(
            select(func.count(StudentSubscription.id)).where(
                StudentSubscription.started_at >= period_start
            )
        )
        new_subscriptions_period = new_subs_result.scalar() or 0

        # Subscription revenue
        sub_revenue_result = await self.db.execute(
            select(func.sum(StudentSubscription.price_paid_cents)).where(
                StudentSubscription.started_at >= period_start
            )
        )
        subscription_revenue = sub_revenue_result.scalar() or 0

        # Blockchain stats
        blockchain_batches_result = await self.db.execute(
            select(func.count(RoyaltyBlockchainBatch.id))
        )
        blockchain_batches = blockchain_batches_result.scalar() or 0

        blockchain_verified_result = await self.db.execute(
            select(func.count(ViewRoyalty.id)).where(
                ViewRoyalty.blockchain_verified == True
            )
        )
        blockchain_verified_views = blockchain_verified_result.scalar() or 0

        # Return dict matching RoyaltyStats schema EXACTLY
        return {
            'period_start': period_start,
            'period_end': period_end,
            'total_views': total_views,
            'total_royalties_cents': totals[0] or 0,
            'total_platform_fees_cents': totals[1] or 0,
            'total_paid_out_cents': total_paid_out,
            'total_pending_cents': total_pending,
            'active_masters': active_masters,
            'masters_with_pending': masters_with_pending,
            'avg_payout_cents': int(avg_payout),
            'total_active_subscriptions': total_active_subscriptions,
            'new_subscriptions_period': new_subscriptions_period,
            'subscription_revenue_cents': subscription_revenue,
            'blockchain_batches': blockchain_batches,
            'blockchain_verified_views': blockchain_verified_views,
            'total_gas_cost_cents': 0  # TODO: Track actual gas costs
        }

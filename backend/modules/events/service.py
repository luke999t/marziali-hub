"""
AI_MODULE: Event Service Layer
AI_DESCRIPTION: Business logic per gestione eventi ASD, iscrizioni, waiting list, rimborsi
AI_BUSINESS: Orchestrazione completa flusso eventi dal checkout al rimborso (90% ricavi LIBRA)
AI_TEACHING: Service pattern, Stripe Connect split payment, async operations

ALTERNATIVE_VALUTATE:
- Fat controllers: Scartato, logica dispersa negli endpoint
- Direct Stripe calls in router: Scartato, non testabile
- Synchronous processing: Scartato, Stripe richiede async

PERCHE_QUESTA_SOLUZIONE:
- Service layer: Centralizza business logic, testabile
- Stripe Connect: Split payment automatico a checkout
- Waiting list: "Notify all, first to pay wins" strategy
- Transaction boundaries: Gestione esplicita commit/rollback

METRICHE_SUCCESSO:
- Transaction success rate: >99.9%
- Checkout completion: >85%
- Refund processing: <24h
"""

import uuid
import re
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from uuid import UUID
import logging

from sqlalchemy import select, func, and_, or_, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload

from modules.events.config import get_events_config, EventsConfig, ConfigResolver
from modules.events.models import (
    ASDPartner,
    Event,
    EventOption,
    EventSubscription,
    EventWaitingList,
    ASDRefundRequest,
    PlatformAlertConfig,
    EventNotification,
    EventStatus,
    SubscriptionStatus,
    RefundStatus,
    AlertType,
    NotificationChannel,
    PresaleCriteriaType,
    RefundApprovalMode
)
from modules.events.schemas import (
    ASDPartnerCreate,
    ASDPartnerUpdate,
    EventCreate,
    EventUpdate,
    EventOptionCreate,
    EventOptionUpdate,
    EventSubscriptionCreate,
    RefundRequestCreate,
    CheckoutResponse
)

logger = logging.getLogger(__name__)


class EventService:
    """
    Service layer per gestione eventi ASD.

    Gestisce:
    - CRUD ASD Partners (con Stripe Connect)
    - CRUD Eventi e Opzioni
    - Checkout iscrizioni con split payment
    - Waiting list management
    - Rimborsi con approvazione
    - Scheduling alert

    USAGE:
    ```python
    service = EventService(db)
    event = await service.create_event(asd_id, event_data)
    checkout = await service.create_checkout(user_id, subscription_data)
    ```
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[EventsConfig] = None
    ):
        """
        Inizializza service.

        Args:
            db: Sessione database async
            config: Configurazione eventi (default: from env)
        """
        self.db = db
        self.config = config or get_events_config()

    # ======================== ASD PARTNERS ========================

    async def create_asd_partner(
        self,
        data: ASDPartnerCreate,
        created_by: UUID
    ) -> ASDPartner:
        """
        Crea ASD partner.

        Args:
            data: Dati creazione
            created_by: ID utente admin che crea

        Returns:
            ASDPartner creato

        Raises:
            ValueError: Se ASD con stesso nome esiste
        """
        # Check nome univoco
        existing = await self.db.execute(
            select(ASDPartner).where(
                func.lower(ASDPartner.name) == data.name.lower()
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError(f"ASD with name '{data.name}' already exists")

        # Generate slug if not provided
        slug = data.slug or re.sub(r'[^a-z0-9]+', '-', data.name.lower()).strip('-')
        
        partner = ASDPartner(
            name=data.name,
            slug=slug,
            description=data.description,
            logo_url=data.logo_url,
            website=data.website,
            email=data.email,
            phone=data.phone,
            address=data.address,
            city=data.city,
            province=data.province,
            postal_code=data.postal_code,
            country=data.country or "Italia",
            fiscal_code=data.fiscal_code,
            vat_number=data.vat_number,
            default_split_percentage=data.default_split_percentage,
            refund_approval_mode=data.refund_approval_mode
        )

        self.db.add(partner)
        await self.db.flush()

        logger.info(f"Created ASD partner {partner.id}: {partner.name}")
        return partner

    async def get_asd_partner(
        self,
        partner_id: Optional[UUID] = None,
        admin_user_id: Optional[UUID] = None,
        stripe_account_id: Optional[str] = None
    ) -> Optional[ASDPartner]:
        """
        Ottiene ASD partner.

        Args:
            partner_id: ID partner
            admin_user_id: ID admin user
            stripe_account_id: Stripe Connect account ID

        Returns:
            ASDPartner o None
        """
        query = select(ASDPartner).options(
            selectinload(ASDPartner.events).options(
                selectinload(Event.options)
            )
        )

        if partner_id:
            query = query.where(ASDPartner.id == partner_id)
        elif admin_user_id:
            query = query.where(ASDPartner.admin_user_id == admin_user_id)
        elif stripe_account_id:
            query = query.where(ASDPartner.stripe_account_id == stripe_account_id)
        else:
            return None

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def update_asd_partner(
        self,
        partner_id: UUID,
        data: ASDPartnerUpdate
    ) -> Optional[ASDPartner]:
        """
        Aggiorna ASD partner.

        Args:
            partner_id: ID partner
            data: Dati update

        Returns:
            ASDPartner aggiornato o None
        """
        partner = await self.get_asd_partner(partner_id=partner_id)
        if not partner:
            return None

        update_data = data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if value is not None:
                setattr(partner, field, value)

        partner.updated_at = datetime.utcnow()
        await self.db.flush()

        logger.info(f"Updated ASD partner {partner_id}")
        return partner

    async def list_asd_partners(
        self,
        active_only: bool = True,
        verified_only: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[ASDPartner]:
        """
        Lista ASD partners.

        Args:
            active_only: Solo attivi
            verified_only: Solo Stripe verificati
            limit: Max risultati
            offset: Offset paginazione

        Returns:
            Lista ASDPartner
        """
        query = select(ASDPartner).options(
            selectinload(ASDPartner.events).options(
                selectinload(Event.options)
            )
        )

        if active_only:
            query = query.where(ASDPartner.is_active == True)
        if verified_only:
            query = query.where(ASDPartner.is_verified == True)

        query = query.order_by(ASDPartner.name).offset(offset).limit(limit)

        result = await self.db.execute(query)
        return list(result.unique().scalars().all())

    async def update_stripe_account(
        self,
        partner_id: UUID,
        stripe_account_id: str,
        verified: bool = False
    ) -> Optional[ASDPartner]:
        """
        Aggiorna Stripe Connect account per ASD.

        Args:
            partner_id: ID partner
            stripe_account_id: Stripe account ID
            verified: Se account verificato

        Returns:
            ASDPartner aggiornato
        """
        partner = await self.get_asd_partner(partner_id=partner_id)
        if not partner:
            return None

        partner.stripe_account_id = stripe_account_id
        partner.is_verified = verified
        partner.updated_at = datetime.utcnow()

        await self.db.flush()
        logger.info(f"Updated Stripe account for ASD {partner_id}: {stripe_account_id}")
        return partner

    # ======================== EVENTS ========================

    async def create_event(
        self,
        asd_id: UUID,
        data: EventCreate,
        created_by: UUID
    ) -> Event:
        """
        Crea evento per ASD.

        Args:
            asd_id: ID ASD partner
            data: Dati evento
            created_by: ID utente che crea

        Returns:
            Event creato

        Raises:
            ValueError: Se ASD non esiste o non attivo
        """
        # Verifica ASD
        asd = await self.get_asd_partner(partner_id=asd_id)
        if not asd:
            raise ValueError(f"ASD partner {asd_id} not found")
        if not asd.is_active:
            raise ValueError(f"ASD partner {asd_id} is not active")

        # Calcola status iniziale
        now = datetime.utcnow().date()
        if data.start_date <= now:
            raise ValueError("Event start date must be in the future")

        # Generate slug if not provided
        slug = data.slug or re.sub(r'[^a-z0-9]+', '-', data.title.lower()).strip('-')

        # Handle location
        location_name = None
        location_address = None
        location_city = None
        location_country = "Italia"
        location_coordinates = None
        if data.location:
            location_name = data.location.name
            location_address = data.location.address
            location_city = data.location.city
            location_country = data.location.country or "Italia"
            location_coordinates = data.location.coordinates

        # Handle presale criteria
        presale_criteria_dict = None
        if data.presale_criteria:
            presale_criteria_dict = data.presale_criteria.model_dump()

        # Handle alert config override
        alert_config_dict = None
        if data.alert_config_override:
            alert_config_dict = data.alert_config_override.model_dump()

        event = Event(
            asd_id=asd_id,
            title=data.title,
            slug=slug,
            description=data.description,
            short_description=data.short_description,
            start_date=data.start_date,
            end_date=data.end_date,
            presale_start=data.presale_start,
            presale_end=data.presale_end,
            sale_start=data.sale_start,
            presale_enabled=data.presale_enabled,
            presale_criteria=presale_criteria_dict,
            total_capacity=data.total_capacity,
            min_threshold=data.min_threshold,
            location_name=location_name,
            location_address=location_address,
            location_city=location_city,
            location_country=location_country,
            location_coordinates=location_coordinates,
            bundle_course_id=data.bundle_course_id,
            bundle_discount_percent=data.bundle_discount_percent,
            split_percentage=data.split_percentage,
            requires_refund_approval=data.requires_refund_approval,
            alert_config_override=alert_config_dict,
            discipline=data.discipline,
            instructor_name=data.instructor_name,
            instructor_bio=data.instructor_bio,
            status=EventStatus.DRAFT,
            created_by=created_by
        )

        self.db.add(event)
        await self.db.flush()

        logger.info(f"Created event {event.id}: {event.title}")
        return event

    async def get_event(
        self,
        event_id: UUID,
        include_options: bool = False
    ) -> Optional[Event]:
        """
        Ottiene evento.

        Args:
            event_id: ID evento
            include_options: Ignored (options accessed via dynamic relationship)

        Returns:
            Event o None
        """
        query = select(Event).options(
            selectinload(Event.options),
            selectinload(Event.subscriptions),
            joinedload(Event.asd_partner)
        ).where(Event.id == event_id)
        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def update_event(
        self,
        event_id: UUID,
        data: EventUpdate
    ) -> Optional[Event]:
        """
        Aggiorna evento.

        Args:
            event_id: ID evento
            data: Dati update

        Returns:
            Event aggiornato o None
        """
        event = await self.get_event(event_id)
        if not event:
            return None

        update_data = data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if value is not None:
                if field == 'refund_approval_mode':
                    value = RefundApprovalMode(value)
                elif field == 'status':
                    value = EventStatus(value)
                setattr(event, field, value)

        event.updated_at = datetime.utcnow()
        await self.db.flush()

        logger.info(f"Updated event {event_id}")
        return event

    async def list_events(
        self,
        asd_id: Optional[UUID] = None,
        status: Optional[EventStatus] = None,
        upcoming_only: bool = False,
        include_past: bool = False,
        limit: int = 50,
        offset: int = 0
    ) -> List[Event]:
        """
        Lista eventi.

        Args:
            asd_id: Filtra per ASD
            status: Filtra per status
            upcoming_only: Solo futuri
            include_past: Includi passati
            limit: Max risultati
            offset: Offset

        Returns:
            Lista Event
        """
        query = select(Event).options(
            selectinload(Event.options),
            selectinload(Event.subscriptions),
            joinedload(Event.asd_partner)
        )

        if asd_id:
            query = query.where(Event.asd_id == asd_id)
        if status:
            query = query.where(Event.status == status)
        if upcoming_only:
            query = query.where(Event.start_date > datetime.utcnow())
        if not include_past:
            query = query.where(
                or_(
                    Event.start_date >= datetime.utcnow(),
                    Event.status == EventStatus.OPEN
                )
            )

        query = query.order_by(Event.start_date).offset(offset).limit(limit)

        result = await self.db.execute(query)
        return list(result.unique().scalars().all())

    async def publish_event(self, event_id: UUID) -> Optional[Event]:
        """
        Pubblica evento.

        Args:
            event_id: ID evento

        Returns:
            Event pubblicato
        """
        event = await self.get_event(event_id)
        if not event:
            return None

        if event.status == EventStatus.CANCELLED:
            raise ValueError("Cannot publish cancelled event")

        event.status = EventStatus.OPEN
        event.published_at = datetime.utcnow()
        event.updated_at = datetime.utcnow()

        await self.db.flush()
        logger.info(f"Published event {event_id}")
        return event

    async def cancel_event(
        self,
        event_id: UUID,
        reason: Optional[str] = None
    ) -> Optional[Event]:
        """
        Cancella evento.

        Args:
            event_id: ID evento
            reason: Motivo cancellazione
            refund_all: Crea rimborsi automatici

        Returns:
            Tuple (Event, lista user_ids da notificare)
        """
        event = await self.get_event(event_id)
        if not event:
            return None

        event.status = EventStatus.CANCELLED
        event.cancellation_reason = reason
        event.cancelled_at = datetime.utcnow()
        event.updated_at = datetime.utcnow()

        await self.db.flush()
        logger.info(f"Cancelled event {event_id}")
        return event

    async def get_event_availability(
        self,
        event_id: UUID
    ) -> Dict[str, Any]:
        """
        Ottiene disponibilità evento.

        Args:
            event_id: ID evento

        Returns:
            Dict con info disponibilità
        """
        event = await self.get_event(event_id, include_options=True)
        if not event:
            return {"error": "Event not found"}

        # Count confirmed subscriptions
        confirmed_count = await self.db.execute(
            select(func.count(EventSubscription.id)).where(
                EventSubscription.event_id == event_id,
                EventSubscription.status == SubscriptionStatus.CONFIRMED
            )
        )
        sold = confirmed_count.scalar() or 0

        # Waiting list count
        waiting_count = await self.db.execute(
            select(func.count(EventWaitingList.id)).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            )
        )
        waiting = waiting_count.scalar() or 0

        # Calculate sale phase
        now = datetime.utcnow()
        sale_phase = "not_started"

        if event.presale_start and now >= event.presale_start:
            if event.presale_end and now <= event.presale_end:
                sale_phase = "presale"
            elif event.sale_start and now >= event.sale_start:
                sale_phase = "sale"
            else:
                sale_phase = "between_presale_sale"
        elif event.sale_start and now >= event.sale_start:
            sale_phase = "sale"

        available = max(0, (event.total_capacity or 0) - sold)
        is_sold_out = available == 0 and event.total_capacity is not None

        return {
            "event_id": event_id,
            "max_capacity": event.total_capacity,
            "sold": sold,
            "available": available,
            "is_sold_out": is_sold_out,
            "waiting_list_count": waiting,
            "sale_phase": sale_phase,
            "presale_start": event.presale_start,
            "presale_end": event.presale_end,
            "sale_start": event.sale_start,
            "min_capacity": event.min_threshold,
            "threshold_reached": sold >= (event.min_threshold or 0) if event.min_threshold else True
        }

    # ======================== EVENT OPTIONS ========================

    async def create_event_option(
        self,
        event_id: UUID,
        data: EventOptionCreate
    ) -> EventOption:
        """
        Crea opzione evento.

        Args:
            event_id: ID evento
            data: Dati opzione

        Returns:
            EventOption creato
        """
        event = await self.get_event(event_id)
        if not event:
            raise ValueError(f"Event {event_id} not found")

        option = EventOption(
            event_id=event_id,
            name=data.name,
            description=data.description,
            start_date=data.start_date,
            end_date=data.end_date,
            price_cents=data.price_cents,
            early_bird_price_cents=data.early_bird_price_cents,
            early_bird_deadline=data.early_bird_deadline,
            includes_bundle=data.includes_bundle,
            sort_order=data.sort_order or 0
        )

        self.db.add(option)
        await self.db.flush()

        logger.info(f"Created option {option.id} for event {event_id}")
        return option

    async def update_event_option(
        self,
        option_id: UUID,
        data: EventOptionUpdate
    ) -> Optional[EventOption]:
        """
        Aggiorna opzione evento.

        Args:
            option_id: ID opzione
            data: Dati update

        Returns:
            EventOption aggiornato o None
        """
        result = await self.db.execute(
            select(EventOption).where(EventOption.id == option_id)
        )
        option = result.scalar_one_or_none()
        if not option:
            return None

        update_data = data.model_dump(exclude_unset=True)

        for field, value in update_data.items():
            if value is not None:
                setattr(option, field, value)

        option.updated_at = datetime.utcnow()
        await self.db.flush()

        return option

    async def get_option_availability(
        self,
        option_id: UUID
    ) -> Dict[str, Any]:
        """
        Ottiene disponibilità opzione.

        Args:
            option_id: ID opzione

        Returns:
            Dict con disponibilità
        """
        result = await self.db.execute(
            select(EventOption).where(EventOption.id == option_id)
        )
        option = result.scalar_one_or_none()
        if not option:
            return {"error": "Option not found"}

        # Get parent event availability (capacity is shared)
        event_availability = await self.get_event_availability(option.event_id)

        return {
            "option_id": option_id,
            "event_id": option.event_id,
            "name": option.name,
            "price_cents": option.price_cents,
            "current_price_cents": option.current_price_cents,
            "is_active": option.is_active,
            "event_available": event_availability.get("available", 0),
            "event_sold_out": event_availability.get("is_sold_out", False)
        }

    # ======================== SUBSCRIPTIONS ========================

    async def create_subscription(
        self,
        user_id: UUID,
        data: EventSubscriptionCreate
    ) -> Tuple[EventSubscription, CheckoutResponse]:
        """
        Crea iscrizione evento (pre-checkout).

        Args:
            user_id: ID utente
            data: Dati iscrizione

        Returns:
            Tuple (EventSubscription, CheckoutResponse per Stripe)

        Raises:
            ValueError: Se evento non disponibile
        """
        event = await self.get_event(data.event_id, include_options=True)
        if not event:
            raise ValueError(f"Event {data.event_id} not found")

        # Check status
        if event.status not in [EventStatus.OPEN, EventStatus.SOLD_OUT]:
            raise ValueError(f"Event not available for registration")

        # Check availability
        availability = await self.get_event_availability(data.event_id)
        if availability.get("is_sold_out"):
            raise ValueError("Event is sold out")

        # Check presale criteria if in presale phase
        if availability.get("sale_phase") == "presale":
            eligible = await self._check_presale_eligibility(user_id, event)
            if not eligible:
                raise ValueError("Not eligible for presale")

        # Calculate price (use getattr for optional fields that may not exist on schema)
        selected_options = getattr(data, 'selected_options', None) or []
        quantity = getattr(data, 'quantity', 1) or 1
        notes = getattr(data, 'notes', None)
        participant_info = getattr(data, 'participant_info', None) or {}

        base_price = self._calculate_price(event, user_id, data)
        options_price = await self._calculate_options_price(event, selected_options)
        total_price = base_price + options_price

        # Calculate fees
        asd = await self.get_asd_partner(partner_id=event.asd_id)
        platform_fee_percent = getattr(asd, 'platform_fee_override', None) or self.config.stripe.platform_fee_percent
        platform_fee = int(total_price * platform_fee_percent / 100)
        asd_amount = total_price - platform_fee

        # Create subscription
        subscription = EventSubscription(
            event_id=data.event_id,
            user_id=user_id,
            option_id=data.option_id,
            amount_cents=total_price,
            platform_amount_cents=platform_fee,
            asd_amount_cents=asd_amount,
            status=SubscriptionStatus.PENDING,
            notes=notes
        )

        self.db.add(subscription)
        await self.db.flush()

        # Create checkout response for frontend
        checkout = CheckoutResponse(
            subscription_id=subscription.id,
            event_id=event.id,
            event_title=event.title,
            amount_cents=total_price,
            platform_amount_cents=platform_fee,
            asd_amount_cents=asd_amount,
            currency="eur",
            stripe_account_id=asd.stripe_account_id if asd else None,
            checkout_session_id=None,  # Will be set by StripeConnectService
            checkout_url=None,  # Will be set by StripeConnectService
            expires_at=datetime.utcnow() + timedelta(minutes=self.config.checkout_session_expiry_minutes)
        )

        logger.info(f"Created subscription {subscription.id} for user {user_id}, event {data.event_id}")
        return subscription, checkout

    async def _check_presale_eligibility(
        self,
        user_id: UUID,
        event: Event
    ) -> bool:
        """
        Verifica eligibilità presale.

        Args:
            user_id: ID utente
            event: Evento

        Returns:
            True se eligible
        """
        if not event.presale_criteria:
            return True

        criteria = event.presale_criteria
        criteria_type = criteria.get("type")

        if criteria_type == PresaleCriteriaType.EMAIL_LIST.value:
            emails = criteria.get("emails", [])
            # Check user email in list (would need user lookup)
            # Simplified: assume eligible if criteria exists
            return True

        elif criteria_type == PresaleCriteriaType.SUBSCRIPTION_ACTIVE.value:
            # Check active subscription
            # This would check modules.royalties
            return True

        elif criteria_type == PresaleCriteriaType.COURSE_PURCHASED.value:
            course_ids = criteria.get("course_ids", [])
            # Check user has purchased course
            return True

        elif criteria_type == PresaleCriteriaType.LEARNING_PATH.value:
            path_ids = criteria.get("learning_path_ids", [])
            # Check user learning paths
            return True

        elif criteria_type == PresaleCriteriaType.TIER_MINIMUM.value:
            tiers = criteria.get("tiers", [])
            # Check user tier
            return True

        return True

    def _calculate_price(
        self,
        event: Event,
        user_id: UUID,
        data: EventSubscriptionCreate
    ) -> int:
        """
        Calcola prezzo base.

        Args:
            event: Evento
            user_id: ID utente
            data: Dati subscription

        Returns:
            Prezzo in cents
        """
        now = datetime.utcnow()
        quantity = getattr(data, 'quantity', 1) or 1

        # Early bird pricing (use getattr for safety - these fields may not exist on Event)
        early_bird_price = getattr(event, 'early_bird_price_cents', None)
        early_bird_deadline = getattr(event, 'early_bird_deadline', None)
        if early_bird_price and early_bird_deadline:
            if now <= early_bird_deadline:
                return early_bird_price * quantity

        # Member price (would need membership check)
        # For now use base price
        member_price = getattr(event, 'member_price_cents', None)
        if member_price:
            # TODO: Check if user is ASD member
            pass

        return 0  # Price calculated from options

    async def _calculate_options_price(
        self,
        event: Event,
        selected_options: List[Dict[str, Any]]
    ) -> int:
        """
        Calcola prezzo opzioni.

        Args:
            event: Evento
            selected_options: Opzioni selezionate [{option_id, quantity}]

        Returns:
            Prezzo totale opzioni in cents
        """
        if not selected_options:
            return 0

        total = 0
        for sel in selected_options:
            option_id = sel.get("option_id")
            quantity = sel.get("quantity", 1)

            result = await self.db.execute(
                select(EventOption).where(
                    EventOption.id == option_id,
                    EventOption.event_id == event.id
                )
            )
            option = result.scalar_one_or_none()
            if option and option.is_active:
                total += (option.price_cents or 0) * quantity

        return total

    async def confirm_subscription(
        self,
        subscription_id: UUID,
        stripe_payment_intent_id: str,
        stripe_charge_id: Optional[str] = None
    ) -> Optional[EventSubscription]:
        """
        Conferma iscrizione dopo pagamento.

        Args:
            subscription_id: ID subscription
            stripe_payment_intent_id: Stripe payment intent ID
            stripe_charge_id: Stripe charge ID

        Returns:
            EventSubscription confermato
        """
        result = await self.db.execute(
            select(EventSubscription).where(EventSubscription.id == subscription_id)
        )
        subscription = result.scalar_one_or_none()
        if not subscription:
            return None

        subscription.status = SubscriptionStatus.CONFIRMED
        subscription.stripe_payment_intent_id = stripe_payment_intent_id
        subscription.stripe_charge_id = stripe_charge_id
        subscription.confirmed_at = datetime.utcnow()
        subscription.updated_at = datetime.utcnow()

        # Update event stats
        await self.db.execute(
            update(Event)
            .where(Event.id == subscription.event_id)
            .values(current_subscriptions=Event.current_subscriptions + 1)
        )

        # Check if event now sold out
        event = await self.get_event(subscription.event_id)
        if event and event.total_capacity:
            if event.current_subscriptions >= event.total_capacity:
                event.status = EventStatus.SOLD_OUT
                # Notify waiting list
                await self._notify_sold_out(event.id)

        # Handle bundle grant if configured
        if event and event.bundle_course_id and self.config.bundle_auto_grant:
            await self._grant_bundle_access(subscription.user_id, event)

        await self.db.flush()
        logger.info(f"Confirmed subscription {subscription_id}")
        return subscription

    async def _grant_bundle_access(
        self,
        user_id: UUID,
        event: Event
    ):
        """
        Grant bundle course/path access.

        Args:
            user_id: ID utente
            event: Evento con bundle
        """
        # This would integrate with courses module
        # Simplified: just log
        logger.info(f"Would grant bundle access: user={user_id}, course={event.bundle_course_id}")

    async def _notify_sold_out(self, event_id: UUID):
        """Notifica sold out a waiting list."""
        # Will be implemented in notifications.py
        pass

    async def get_user_subscriptions(
        self,
        user_id: UUID,
        event_id: Optional[UUID] = None,
        active_only: bool = True
    ) -> List[EventSubscription]:
        """
        Ottiene iscrizioni utente.

        Args:
            user_id: ID utente
            event_id: Filtra per evento
            active_only: Solo attive

        Returns:
            Lista subscriptions
        """
        query = select(EventSubscription).where(
            EventSubscription.user_id == user_id
        )

        if event_id:
            query = query.where(EventSubscription.event_id == event_id)
        if active_only:
            query = query.where(
                EventSubscription.status.in_([
                    SubscriptionStatus.CONFIRMED,
                    SubscriptionStatus.PENDING,
                    SubscriptionStatus.PENDING
                ])
            )

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # ======================== WAITING LIST ========================

    async def add_to_waiting_list(
        self,
        event_id: UUID,
        user_id: UUID,
        email: Optional[str] = None,
        preferred_option_id: Optional[UUID] = None
    ) -> EventWaitingList:
        """
        Aggiunge utente a waiting list.

        Args:
            event_id: ID evento
            user_id: ID utente
            email: Email (unused, kept for backward compatibility)
            preferred_option_id: ID opzione preferita

        Returns:
            EventWaitingList entry

        Raises:
            ValueError: Se gia in lista o iscritto
        """
        event = await self.get_event(event_id)
        if not event:
            raise ValueError(f"Event {event_id} not found")

        # Check if already in list
        existing = await self.db.execute(
            select(EventWaitingList).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.user_id == user_id,
                EventWaitingList.is_active == True
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("Already in waiting list")

        # Check if already subscribed
        subscribed = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.event_id == event_id,
                EventSubscription.user_id == user_id,
                EventSubscription.status.in_([
                    SubscriptionStatus.CONFIRMED,
                    SubscriptionStatus.PENDING
                ])
            )
        )
        if subscribed.scalar_one_or_none():
            raise ValueError("Already subscribed to event")

        # Check max waiting list
        count_result = await self.db.execute(
            select(func.count(EventWaitingList.id)).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            )
        )
        current_count = count_result.scalar() or 0

        if current_count >= self.config.max_waiting_list_per_event:
            raise ValueError("Waiting list is full")

        entry = EventWaitingList(
            event_id=event_id,
            user_id=user_id,
            preferred_option_id=preferred_option_id
        )

        self.db.add(entry)
        await self.db.flush()

        logger.info(f"Added user {user_id} to waiting list for event {event_id}")
        return entry

    async def process_waiting_list(
        self,
        event_id: UUID,
        spots_available: int = 1
    ) -> List[EventWaitingList]:
        """
        Processa waiting list quando posti si liberano.

        STRATEGY: "Notify all, first to pay wins"
        - Notifica tutti in lista
        - Chi paga prima ottiene il posto
        - Rimuove chi ha pagato dalla lista

        Args:
            event_id: ID evento
            spots_available: Posti disponibili

        Returns:
            Lista entries notificate
        """
        # Get active waiting list ordered by created_at
        result = await self.db.execute(
            select(EventWaitingList).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            ).order_by(EventWaitingList.created_at)
        )
        entries = list(result.scalars().all())

        if not entries:
            return []

        # Notify all (strategy: first to pay wins)
        for entry in entries:
            entry.notified_at = datetime.utcnow()
            entry.notification_count = (entry.notification_count or 0) + 1

        await self.db.flush()

        logger.info(f"Notified {len(entries)} waiting list entries for event {event_id}")
        return entries

    async def remove_from_waiting_list(
        self,
        event_id: UUID,
        user_id: UUID,
        reason: str = "user_cancelled"
    ) -> bool:
        """
        Rimuove da waiting list.

        Args:
            event_id: ID evento
            user_id: ID utente
            reason: Motivo rimozione

        Returns:
            True se rimosso
        """
        result = await self.db.execute(
            update(EventWaitingList)
            .where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.user_id == user_id,
                EventWaitingList.is_active == True
            )
            .values(is_active=False)
        )

        if result.rowcount > 0:
            # Reorder positions
            await self._reorder_waiting_list(event_id)
            logger.info(f"Removed user {user_id} from waiting list, reason: {reason}")
            return True
        return False

    async def _reorder_waiting_list(self, event_id: UUID):
        """Riordina posizioni waiting list."""
        result = await self.db.execute(
            select(EventWaitingList).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            ).order_by(EventWaitingList.created_at)
        )
        entries = list(result.scalars().all())

        for i, entry in enumerate(entries, start=1):
            entry.position = i

        await self.db.flush()

    async def get_user_waiting_list(
        self,
        user_id: UUID,
        include_event: bool = True
    ) -> List[EventWaitingList]:
        """
        Lista waiting list entries per utente.

        Args:
            user_id: ID utente
            include_event: Include relazione evento

        Returns:
            Lista EventWaitingList entries
        """
        query = select(EventWaitingList).where(
            EventWaitingList.user_id == user_id,
            EventWaitingList.is_active == True
        ).order_by(EventWaitingList.created_at.desc())

        if include_event:
            query = query.options(selectinload(EventWaitingList.event))

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # ======================== REFUNDS ========================

    async def request_refund(
        self,
        user_id: UUID,
        data: RefundRequestCreate
    ) -> ASDRefundRequest:
        """
        Richiede rimborso.

        Args:
            user_id: ID utente
            data: Dati richiesta

        Returns:
            ASDRefundRequest creata

        Raises:
            ValueError: Se subscription non valida
        """
        # Get subscription
        result = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.id == data.subscription_id,
                EventSubscription.user_id == user_id
            )
        )
        subscription = result.scalar_one_or_none()
        if not subscription:
            raise ValueError("Subscription not found")

        if subscription.status != SubscriptionStatus.CONFIRMED:
            raise ValueError("Can only refund confirmed subscriptions")

        # Check if already has pending refund
        existing = await self.db.execute(
            select(ASDRefundRequest).where(
                ASDRefundRequest.subscription_id == data.subscription_id,
                ASDRefundRequest.status.in_([
                    RefundStatus.PENDING,
                    RefundStatus.APPROVED
                ])
            )
        )
        if existing.scalar_one_or_none():
            raise ValueError("Refund already requested")

        # Get event and ASD for refund policy
        event = await self.get_event(subscription.event_id)
        if not event:
            raise ValueError("Event not found")

        asd = await self.get_asd_partner(partner_id=event.asd_id)

        # Calculate refund amount
        refund_amount = data.requested_amount_cents or subscription.amount_cents

        # Determine if approval is required based on event or ASD setting
        requires_approval = True
        if event.requires_refund_approval is False:
            requires_approval = False
        elif asd and asd.refund_approval_mode == RefundApprovalMode.NEVER_REQUIRED:
            requires_approval = False

        refund = ASDRefundRequest(
            subscription_id=data.subscription_id,
            asd_id=event.asd_id,
            requested_by=user_id,
            reason=data.reason,
            requested_amount_cents=refund_amount,
            status=RefundStatus.PENDING,
            requires_approval=requires_approval
        )

        self.db.add(refund)
        await self.db.flush()

        logger.info(f"Created refund request {refund.id} for subscription {data.subscription_id}")
        return refund

    async def process_refund(
        self,
        refund_id: UUID,
        approved: bool,
        processed_by: UUID,
        rejection_reason: Optional[str] = None
    ) -> Tuple[Optional[ASDRefundRequest], str]:
        """
        Processa richiesta rimborso.

        Args:
            refund_id: ID richiesta
            approved: Approvato o rifiutato
            processed_by: ID utente che processa
            rejection_reason: Motivo rifiuto

        Returns:
            Tuple (ASDRefundRequest, messaggio)
        """
        result = await self.db.execute(
            select(ASDRefundRequest).where(ASDRefundRequest.id == refund_id)
        )
        refund = result.scalar_one_or_none()
        if not refund:
            return None, "Refund request not found"

        if refund.status not in [RefundStatus.PENDING, RefundStatus.APPROVED]:
            return None, f"Cannot process refund in status {refund.status.value}"

        if approved:
            refund.status = RefundStatus.APPROVED
            refund.approved_at = datetime.utcnow()
            refund.approved_by = processed_by

            # Mark subscription as refund pending
            await self.db.execute(
                update(EventSubscription)
                .where(EventSubscription.id == refund.subscription_id)
                .values(status=SubscriptionStatus.CANCELLED)
            )

            message = "Refund approved"
        else:
            refund.status = RefundStatus.REJECTED
            refund.rejection_reason = rejection_reason
            refund.rejected_at = datetime.utcnow()
            refund.rejected_by = processed_by
            message = "Refund rejected"

        refund.updated_at = datetime.utcnow()
        await self.db.flush()

        logger.info(f"Processed refund {refund_id}: {message}")
        return refund, message

    async def complete_refund(
        self,
        refund_id: UUID,
        stripe_refund_id: str
    ) -> Optional[ASDRefundRequest]:
        """
        Completa rimborso dopo Stripe refund.

        Args:
            refund_id: ID richiesta
            stripe_refund_id: Stripe refund ID

        Returns:
            ASDRefundRequest completato
        """
        result = await self.db.execute(
            select(ASDRefundRequest).where(ASDRefundRequest.id == refund_id)
        )
        refund = result.scalar_one_or_none()
        if not refund:
            return None

        refund.status = RefundStatus.PROCESSED
        refund.processed_at = datetime.utcnow()
        refund.stripe_refund_id = stripe_refund_id

        # Update subscription
        await self.db.execute(
            update(EventSubscription)
            .where(EventSubscription.id == refund.subscription_id)
            .values(status=SubscriptionStatus.REFUNDED)
        )

        # Update event capacity
        sub_result = await self.db.execute(
            select(EventSubscription).where(EventSubscription.id == refund.subscription_id)
        )
        subscription = sub_result.scalar_one_or_none()
        if subscription:
            await self.db.execute(
                update(Event)
                .where(Event.id == subscription.event_id)
                .values(current_subscriptions=Event.current_subscriptions - 1)
            )

            # Check if should notify waiting list
            event = await self.get_event(subscription.event_id)
            if event and event.status == EventStatus.SOLD_OUT:
                event.status = EventStatus.OPEN
                await self.process_waiting_list(event.id, 1)

        await self.db.flush()
        logger.info(f"Completed refund {refund_id}")
        return refund

    async def get_refund_requests(
        self,
        event_id: Optional[UUID] = None,
        asd_id: Optional[UUID] = None,
        user_id: Optional[UUID] = None,
        status: Optional[RefundStatus] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[ASDRefundRequest]:
        """
        Lista richieste rimborso.

        Args:
            event_id: Filtra per evento
            asd_id: Filtra per ASD
            user_id: Filtra per utente
            status: Filtra per status
            limit: Max risultati
            offset: Offset

        Returns:
            Lista ASDRefundRequest
        """
        query = select(ASDRefundRequest)

        if user_id:
            query = query.where(ASDRefundRequest.requested_by == user_id)
        if status:
            query = query.where(ASDRefundRequest.status == status)
        if event_id:
            query = query.join(EventSubscription).where(
                EventSubscription.event_id == event_id
            )
        if asd_id:
            query = query.join(EventSubscription).join(Event).where(
                Event.asd_id == asd_id
            )

        query = query.order_by(ASDRefundRequest.created_at.desc()).offset(offset).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # ======================== STATS ========================

    async def get_event_stats(
        self,
        event_id: UUID
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche evento.

        Args:
            event_id: ID evento

        Returns:
            Dict con statistiche
        """
        event = await self.get_event(event_id)
        if not event:
            return {"error": "Event not found"}

        # Subscriptions by status
        status_counts = {}
        for status in SubscriptionStatus:
            count = await self.db.execute(
                select(func.count(EventSubscription.id)).where(
                    EventSubscription.event_id == event_id,
                    EventSubscription.status == status
                )
            )
            status_counts[status.value] = count.scalar() or 0

        # Revenue
        revenue_result = await self.db.execute(
            select(
                func.sum(EventSubscription.amount_cents),
                func.sum(EventSubscription.platform_amount_cents),
                func.sum(EventSubscription.asd_amount_cents)
            ).where(
                EventSubscription.event_id == event_id,
                EventSubscription.status == SubscriptionStatus.CONFIRMED
            )
        )
        revenue = revenue_result.one()

        # Refunds
        refund_result = await self.db.execute(
            select(func.sum(ASDRefundRequest.requested_amount_cents)).where(
                ASDRefundRequest.status == RefundStatus.PROCESSED
            ).join(EventSubscription).where(
                EventSubscription.event_id == event_id
            )
        )
        total_refunded = refund_result.scalar() or 0

        # Waiting list
        waiting_result = await self.db.execute(
            select(func.count(EventWaitingList.id)).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            )
        )
        waiting_count = waiting_result.scalar() or 0

        return {
            "event_id": event_id,
            "status": event.status.value,
            "subscriptions_by_status": status_counts,
            "total_confirmed": status_counts.get(SubscriptionStatus.CONFIRMED.value, 0),
            "total_revenue_cents": revenue[0] or 0,
            "platform_fees_cents": revenue[1] or 0,
            "asd_revenue_cents": revenue[2] or 0,
            "total_refunded_cents": total_refunded,
            "net_revenue_cents": (revenue[0] or 0) - total_refunded,
            "capacity_used": event.current_subscriptions,
            "capacity_max": event.total_capacity,
            "capacity_percent": (event.current_subscriptions / event.total_capacity * 100) if event.total_capacity else None,
            "waiting_list_count": waiting_count,
            "threshold_reached": event.current_subscriptions >= (event.min_threshold or 0) if event.min_threshold else True
        }

    async def get_asd_stats(
        self,
        asd_id: UUID,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche ASD.

        Args:
            asd_id: ID ASD
            days: Periodo in giorni

        Returns:
            Dict con statistiche
        """
        period_start = datetime.utcnow() - timedelta(days=days)

        # Events count
        events_result = await self.db.execute(
            select(func.count(Event.id)).where(Event.asd_id == asd_id)
        )
        total_events = events_result.scalar() or 0

        # Active events
        active_result = await self.db.execute(
            select(func.count(Event.id)).where(
                Event.asd_id == asd_id,
                Event.status == EventStatus.OPEN,
                Event.start_date >= datetime.utcnow()
            )
        )
        active_events = active_result.scalar() or 0

        # Total subscriptions in period
        subs_result = await self.db.execute(
            select(func.count(EventSubscription.id)).where(
                EventSubscription.status == SubscriptionStatus.CONFIRMED,
                EventSubscription.confirmed_at >= period_start
            ).join(Event).where(Event.asd_id == asd_id)
        )
        total_subscriptions = subs_result.scalar() or 0

        # Revenue in period
        revenue_result = await self.db.execute(
            select(
                func.sum(EventSubscription.amount_cents),
                func.sum(EventSubscription.platform_amount_cents),
                func.sum(EventSubscription.asd_amount_cents)
            ).where(
                EventSubscription.status == SubscriptionStatus.CONFIRMED,
                EventSubscription.confirmed_at >= period_start
            ).join(Event).where(Event.asd_id == asd_id)
        )
        revenue = revenue_result.one()

        return {
            "asd_id": asd_id,
            "period_days": days,
            "total_events": total_events,
            "active_events": active_events,
            "total_subscriptions_period": total_subscriptions,
            "total_revenue_cents": revenue[0] or 0,
            "platform_fees_cents": revenue[1] or 0,
            "asd_net_revenue_cents": revenue[2] or 0
        }

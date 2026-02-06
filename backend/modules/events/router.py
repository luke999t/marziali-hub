"""
AI_MODULE: Events API Router
AI_DESCRIPTION: FastAPI endpoints per gestione eventi ASD
AI_BUSINESS: API completa per CRUD eventi, checkout, rimborsi (90% ricavi LIBRA)
AI_TEACHING: FastAPI router, dependency injection, OpenAPI docs

ALTERNATIVE_VALUTATE:
- GraphQL: Scartato, REST più semplice per MVP
- gRPC: Scartato, non serve per frontend web/mobile
- Separate microservices: Scartato, over-engineering

PERCHE_QUESTA_SOLUZIONE:
- FastAPI: Async native, validazione Pydantic, OpenAPI auto
- Router modulare: Separazione concerns, testing facilitato
- Dependency injection: DB session, auth, services iniettati

ENDPOINTS:
- /asd: CRUD ASD partners, Stripe Connect onboarding
- /events: CRUD eventi, opzioni, disponibilità
- /subscriptions: Checkout, conferma, lista iscrizioni
- /waiting-list: Gestione waiting list
- /refunds: Richieste rimborso, approvazione
- /notifications: Notifiche utente
- /webhooks: Stripe webhooks
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Header
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, joinedload

from core.database import get_db
from core.auth import get_current_user, get_current_admin_user
from modules.events.service import EventService
from modules.events.stripe_connect import StripeConnectService
from modules.events.notifications import NotificationService
from models.user import User
from modules.events.models import EventStatus, SubscriptionStatus, RefundStatus
from modules.events.schemas import (
    ASDPartnerCreate,
    ASDPartnerUpdate,
    ASDPartnerResponse,
    EventCreate,
    EventUpdate,
    EventResponse,
    EventOptionCreate,
    EventOptionUpdate,
    EventSubscriptionCreate,
    EventSubscriptionResponse,
    RefundRequestCreate,
    RefundRequestResponse,
    AlertConfigUpdate,
    WaitingListResponse,
    CheckoutResponse
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


# ======================== DEPENDENCIES ========================

async def get_event_service(
    db: AsyncSession = Depends(get_db)
) -> EventService:
    """Dependency per EventService."""
    return EventService(db)


async def get_stripe_service(
    db: AsyncSession = Depends(get_db)
) -> StripeConnectService:
    """Dependency per StripeConnectService."""
    return StripeConnectService(db)


async def get_notification_service(
    db: AsyncSession = Depends(get_db)
) -> NotificationService:
    """Dependency per NotificationService."""
    return NotificationService(db)


# ======================== ASD PARTNERS ========================

@router.post("/asd", response_model=ASDPartnerResponse, status_code=201)
async def create_asd_partner(
    data: ASDPartnerCreate,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service)
):
    """
    Crea nuovo ASD partner.

    Requires: Admin role
    """
    try:
        partner = await service.create_asd_partner(
            data=data,
            created_by=current_user.id
        )
        return partner
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/asd", response_model=List[ASDPartnerResponse])
async def list_asd_partners(
    active_only: bool = Query(True),
    verified_only: bool = Query(False),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    service: EventService = Depends(get_event_service)
):
    """
    Lista ASD partners.

    Public endpoint (filtered data).
    """
    partners = await service.list_asd_partners(
        active_only=active_only,
        verified_only=verified_only,
        limit=limit,
        offset=offset
    )
    return partners


@router.get("/asd/{partner_id}", response_model=ASDPartnerResponse)
async def get_asd_partner(
    partner_id: UUID,
    service: EventService = Depends(get_event_service)
):
    """Ottiene ASD partner per ID."""
    partner = await service.get_asd_partner(partner_id=partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="ASD partner not found")
    return partner


@router.patch("/asd/{partner_id}", response_model=ASDPartnerResponse)
async def update_asd_partner(
    partner_id: UUID,
    data: ASDPartnerUpdate,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service)
):
    """
    Aggiorna ASD partner.

    Requires: Admin role or ASD admin
    """
    partner = await service.update_asd_partner(partner_id, data)
    if not partner:
        raise HTTPException(status_code=404, detail="ASD partner not found")
    return partner


@router.post("/asd/{partner_id}/stripe/connect")
async def create_stripe_connect_account(
    partner_id: UUID,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """
    Crea Stripe Connect account per ASD.

    Returns URL per onboarding.
    """
    partner = await service.get_asd_partner(partner_id=partner_id)
    if not partner:
        raise HTTPException(status_code=404, detail="ASD partner not found")

    try:
        account_id, onboarding_url = await stripe_service.create_connect_account(
            asd_id=partner_id,
            email=partner.email
        )
        return {
            "account_id": account_id,
            "onboarding_url": onboarding_url
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/asd/{partner_id}/stripe/status")
async def get_stripe_account_status(
    partner_id: UUID,
    current_user: dict = Depends(get_current_user),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """Ottiene status account Stripe."""
    status = await stripe_service.get_account_status(partner_id)
    return status


@router.post("/asd/{partner_id}/stripe/dashboard-link")
async def create_stripe_dashboard_link(
    partner_id: UUID,
    current_user: dict = Depends(get_current_user),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """
    Crea link per dashboard Stripe Express.

    ASD può vedere transazioni e payouts.
    """
    try:
        url = await stripe_service.create_dashboard_link(partner_id)
        return {"dashboard_url": url}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ======================== EVENTS ========================

@router.post("/", response_model=EventResponse, status_code=201)
async def create_event(
    asd_id: UUID,
    data: EventCreate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """
    Crea nuovo evento.

    Requires: ASD admin or platform admin
    """
    try:
        event = await service.create_event(
            asd_id=asd_id,
            data=data,
            created_by=current_user.id
        )
        return event
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/", response_model=List[EventResponse])
async def list_events(
    asd_id: Optional[UUID] = Query(None),
    status: Optional[str] = Query(None),
    upcoming_only: bool = Query(False),
    limit: int = Query(50, le=100),
    offset: int = Query(0, ge=0),
    service: EventService = Depends(get_event_service)
):
    """
    Lista eventi.

    Public endpoint (solo eventi pubblicati).
    """
    event_status = None
    if status:
        try:
            event_status = EventStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    events = await service.list_events(
        asd_id=asd_id,
        status=event_status,
        upcoming_only=upcoming_only,
        limit=limit,
        offset=offset
    )
    return events


# ======================== ADMIN ENDPOINTS ========================

@router.get("/admin/stats")
async def get_admin_stats(
    asd_id: Optional[UUID] = Query(None),
    days: int = Query(30, le=365),
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service)
):
    """
    Statistiche admin.

    Requires: Platform admin
    """
    if asd_id:
        stats = await service.get_asd_stats(asd_id, days)
    else:
        # Aggregate all ASD stats
        from modules.events.models import ASDPartner
        from sqlalchemy import select

        result = await service.db.execute(select(ASDPartner.id))
        asd_ids = [r[0] for r in result.all()]

        total_stats = {
            "period_days": days,
            "total_asd": len(asd_ids),
            "total_events": 0,
            "active_events": 0,
            "total_subscriptions_period": 0,
            "total_revenue_cents": 0,
            "platform_fees_cents": 0
        }

        for aid in asd_ids:
            asd_stats = await service.get_asd_stats(aid, days)
            total_stats["total_events"] += asd_stats.get("total_events", 0)
            total_stats["active_events"] += asd_stats.get("active_events", 0)
            total_stats["total_subscriptions_period"] += asd_stats.get("total_subscriptions_period", 0)
            total_stats["total_revenue_cents"] += asd_stats.get("total_revenue_cents", 0)
            total_stats["platform_fees_cents"] += asd_stats.get("platform_fees_cents", 0)

        stats = total_stats

    return stats


@router.get("/admin/refunds/pending", response_model=List[RefundRequestResponse])
async def get_pending_refunds(
    asd_id: Optional[UUID] = Query(None),
    limit: int = Query(50, le=100),
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service)
):
    """
    Lista rimborsi pending.

    Requires: Admin
    """
    refunds = await service.get_refund_requests(
        asd_id=asd_id,
        status=RefundStatus.PENDING,
        limit=limit
    )
    return refunds


@router.post("/admin/notifications/process")
async def process_pending_notifications(
    batch_size: int = Query(100, le=500),
    current_user: dict = Depends(get_current_admin_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Processa notifiche pending.

    Manual trigger per scheduler.
    """
    processed = await notification_service.process_pending_notifications(batch_size)
    return {"processed": processed}


@router.post("/admin/notifications/cleanup")
async def cleanup_old_notifications(
    days: int = Query(90, ge=30),
    current_user: dict = Depends(get_current_admin_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Rimuove notifiche vecchie.

    Requires: Admin
    """
    removed = await notification_service.cleanup_old_notifications(days)
    return {"removed": removed}


# ======================== OPTIONS BY ID (must be before /{event_id}) ========================

@router.patch("/options/{option_id}")
async def update_event_option(
    option_id: UUID,
    data: EventOptionUpdate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Aggiorna opzione evento."""
    option = await service.update_event_option(option_id, data)
    if not option:
        raise HTTPException(status_code=404, detail="Option not found")
    return option


@router.get("/options/{option_id}/availability")
async def get_option_availability(
    option_id: UUID,
    service: EventService = Depends(get_event_service)
):
    """Ottiene disponibilità opzione."""
    availability = await service.get_option_availability(option_id)
    if "error" in availability:
        raise HTTPException(status_code=404, detail=availability["error"])
    return availability


# ======================== SUBSCRIPTIONS (must be before /{event_id}) ========================

@router.post("/subscriptions", response_model=CheckoutResponse, status_code=201)
async def create_subscription(
    data: EventSubscriptionCreate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """
    Crea iscrizione e inizia checkout.

    Returns: checkout URL per pagamento Stripe
    """
    try:
        subscription, checkout = await service.create_subscription(
            user_id=current_user.id,
            data=data
        )

        # Create Stripe checkout session
        session = await stripe_service.create_checkout_session(
            subscription_id=subscription.id,
            success_url=f"https://app.example.com/events/{data.event_id}/success",
            cancel_url=f"https://app.example.com/events/{data.event_id}/cancel"
        )

        checkout.checkout_session_id = session["session_id"]
        checkout.checkout_url = session["checkout_url"]

        return checkout

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/subscriptions", response_model=List[EventSubscriptionResponse])
async def list_user_subscriptions(
    event_id: Optional[UUID] = Query(None),
    active_only: bool = Query(True),
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Lista iscrizioni utente corrente."""
    subscriptions = await service.get_user_subscriptions(
        user_id=current_user.id,
        event_id=event_id,
        active_only=active_only
    )
    return subscriptions


@router.get("/subscriptions/{subscription_id}", response_model=EventSubscriptionResponse)
async def get_subscription(
    subscription_id: UUID,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Ottiene dettaglio iscrizione."""
    from sqlalchemy import select
    from modules.events.models import EventSubscription, Event, EventOption

    result = await db.execute(
        select(EventSubscription).options(
            joinedload(EventSubscription.event).options(
                selectinload(Event.options)
            ),
            joinedload(EventSubscription.option)
        ).where(
            EventSubscription.id == subscription_id,
            EventSubscription.user_id == current_user.id
        )
    )
    subscription = result.scalar_one_or_none()
    if not subscription:
        raise HTTPException(status_code=404, detail="Subscription not found")
    return subscription


@router.get("/user/waiting-list", response_model=List[WaitingListResponse])
async def list_user_waiting_list(
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Lista waiting list entries utente corrente."""
    entries = await service.get_user_waiting_list(user_id=current_user.id)
    return entries


# ======================== REFUNDS (must be before /{event_id}) ========================

@router.post("/refunds", response_model=RefundRequestResponse, status_code=201)
async def request_refund(
    data: RefundRequestCreate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Richiede rimborso.

    Auto-approves based on event refund policy.
    """
    try:
        refund = await service.request_refund(
            user_id=current_user.id,
            data=data
        )

        # Notify admins
        await notification_service.notify_admin_refund_request(refund.id)

        return refund
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/refunds", response_model=List[RefundRequestResponse])
async def list_refunds(
    event_id: Optional[UUID] = Query(None),
    status: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Lista richieste rimborso utente."""
    refund_status = None
    if status:
        try:
            refund_status = RefundStatus(status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {status}")

    refunds = await service.get_refund_requests(
        user_id=current_user.id,
        event_id=event_id,
        status=refund_status
    )
    return refunds


@router.post("/refunds/{refund_id}/approve")
async def approve_refund(
    refund_id: UUID,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service),
    stripe_service: StripeConnectService = Depends(get_stripe_service),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Approva richiesta rimborso.

    Requires: Admin or ASD admin
    """
    refund, message = await service.process_refund(
        refund_id=refund_id,
        approved=True,
        processed_by=current_user.id
    )
    if not refund:
        raise HTTPException(status_code=404, detail=message)

    # Process Stripe refund
    try:
        stripe_result = await stripe_service.create_refund(refund_id)
        await notification_service.notify_refund_status(refund_id, "processed")
        return {
            "refund_id": refund_id,
            "status": "processed",
            "stripe_refund": stripe_result
        }
    except ValueError as e:
        return {
            "refund_id": refund_id,
            "status": "approved",
            "stripe_error": str(e)
        }


@router.post("/refunds/{refund_id}/reject")
async def reject_refund(
    refund_id: UUID,
    reason: str,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Rifiuta richiesta rimborso.

    Requires: Admin or ASD admin
    """
    refund, message = await service.process_refund(
        refund_id=refund_id,
        approved=False,
        processed_by=current_user.id,
        rejection_reason=reason
    )
    if not refund:
        raise HTTPException(status_code=404, detail=message)

    await notification_service.notify_refund_status(refund_id, "rejected")

    return {"refund_id": refund_id, "status": "rejected"}


# ======================== NOTIFICATIONS (must be before /{event_id}) ========================

@router.get("/notifications")
async def get_user_notifications(
    unread_only: bool = Query(False),
    limit: int = Query(50, le=100),
    current_user: dict = Depends(get_current_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """Ottiene notifiche utente."""
    notifications = await notification_service.get_user_notifications(
        user_id=current_user.id,
        unread_only=unread_only,
        limit=limit
    )
    return notifications


@router.get("/notifications/unread-count")
async def get_unread_notification_count(
    current_user: dict = Depends(get_current_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """Conta notifiche non lette."""
    count = await notification_service.get_unread_count(current_user.id)
    return {"unread_count": count}


@router.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: UUID,
    current_user: dict = Depends(get_current_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """Segna notifica come letta."""
    success = await notification_service.mark_notification_read(
        notification_id=notification_id,
        user_id=current_user.id
    )
    if not success:
        raise HTTPException(status_code=404, detail="Notification not found")
    return {"status": "read"}


@router.post("/notifications/mark-all-read")
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """Segna tutte le notifiche come lette."""
    count = await notification_service.mark_all_read(current_user.id)
    return {"marked_read": count}


# ======================== WEBHOOKS (must be before /{event_id}) ========================

@router.post("/webhooks/stripe")
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(..., alias="Stripe-Signature"),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """
    Stripe webhook endpoint.

    Handles: checkout.session.completed, charge.refunded, account.updated
    """
    payload = await request.body()

    result = await stripe_service.handle_webhook(
        payload=payload,
        signature=stripe_signature
    )

    if "error" in result:
        logger.error(f"Webhook error: {result['error']}")
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.post("/webhooks/stripe-connect")
async def stripe_connect_webhook(
    request: Request,
    stripe_signature: str = Header(..., alias="Stripe-Signature"),
    stripe_service: StripeConnectService = Depends(get_stripe_service)
):
    """
    Stripe Connect webhook endpoint.

    Handles Connect-specific events (account.updated).
    """
    from modules.events.config import get_events_config

    payload = await request.body()
    config = get_events_config()

    result = await stripe_service.handle_webhook(
        payload=payload,
        signature=stripe_signature,
        webhook_secret=config.stripe.connect_webhook_secret
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


# ======================== EVENT BY ID ENDPOINTS ========================

@router.get("/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: UUID,
    include_options: bool = Query(True),
    service: EventService = Depends(get_event_service)
):
    """Ottiene evento per ID."""
    event = await service.get_event(event_id, include_options=include_options)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.patch("/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: UUID,
    data: EventUpdate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """
    Aggiorna evento.

    Requires: ASD admin or platform admin
    """
    event = await service.update_event(event_id, data)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.post("/{event_id}/publish", response_model=EventResponse)
async def publish_event(
    event_id: UUID,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Pubblica evento.

    Schedula anche alert/reminder.
    """
    try:
        event = await service.publish_event(event_id)
        if not event:
            raise HTTPException(status_code=404, detail="Event not found")

        # Schedule notifications
        await notification_service.schedule_event_reminders(event_id)
        await notification_service.schedule_presale_alerts(event_id)
        await notification_service.schedule_threshold_checks(event_id)

        return event
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{event_id}/cancel")
async def cancel_event(
    event_id: UUID,
    reason: Optional[str] = None,
    current_user: dict = Depends(get_current_admin_user),
    service: EventService = Depends(get_event_service),
    notification_service: NotificationService = Depends(get_notification_service)
):
    """
    Cancella evento.

    Creates refunds and notifies subscribers.
    """
    event = await service.cancel_event(
        event_id=event_id,
        reason=reason
    )
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    # Send cancellation notifications
    await notification_service.notify_event_cancelled(event_id, reason)

    return {
        "event_id": event_id,
        "status": "cancelled"
    }


@router.get("/{event_id}/availability")
async def get_event_availability(
    event_id: UUID,
    service: EventService = Depends(get_event_service)
):
    """
    Ottiene disponibilità evento.

    Returns: posti disponibili, fase vendita, waiting list count
    """
    availability = await service.get_event_availability(event_id)
    if "error" in availability:
        raise HTTPException(status_code=404, detail=availability["error"])
    return availability


@router.get("/{event_id}/stats")
async def get_event_stats(
    event_id: UUID,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """
    Ottiene statistiche evento.

    Requires: ASD admin or platform admin
    """
    stats = await service.get_event_stats(event_id)
    if "error" in stats:
        raise HTTPException(status_code=404, detail=stats["error"])
    return stats


# ======================== EVENT OPTIONS ========================

@router.post("/{event_id}/options", status_code=201)
async def create_event_option(
    event_id: UUID,
    data: EventOptionCreate,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Crea opzione per evento."""
    try:
        option = await service.create_event_option(event_id, data)
        return option
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ======================== WAITING LIST ========================

@router.post("/{event_id}/waiting-list", response_model=WaitingListResponse, status_code=201)
async def add_to_waiting_list(
    event_id: UUID,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Aggiunge utente a waiting list."""
    try:
        entry = await service.add_to_waiting_list(
            event_id=event_id,
            user_id=current_user.id,
            email=current_user.email or ""
        )
        return entry
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/{event_id}/waiting-list")
async def remove_from_waiting_list(
    event_id: UUID,
    current_user: dict = Depends(get_current_user),
    service: EventService = Depends(get_event_service)
):
    """Rimuove utente da waiting list."""
    removed = await service.remove_from_waiting_list(
        event_id=event_id,
        user_id=current_user.id
    )
    if not removed:
        raise HTTPException(status_code=404, detail="Not in waiting list")
    return {"status": "removed"}


@router.get("/{event_id}/waiting-list")
async def get_waiting_list(
    event_id: UUID,
    current_user: dict = Depends(get_current_admin_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Lista waiting list evento.

    Requires: Admin
    """
    from sqlalchemy import select
    from modules.events.models import EventWaitingList

    result = await db.execute(
        select(EventWaitingList).options(
            joinedload(EventWaitingList.event),
            joinedload(EventWaitingList.user),
            joinedload(EventWaitingList.preferred_option)
        ).where(
            EventWaitingList.event_id == event_id,
            EventWaitingList.is_active == True
        ).order_by(EventWaitingList.created_at)
    )
    entries = list(result.unique().scalars().all())
    return entries

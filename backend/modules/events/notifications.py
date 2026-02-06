"""
AI_MODULE: Event Notifications Service
AI_DESCRIPTION: Sistema notifiche/alert configurabile per eventi ASD
AI_BUSINESS: Alert critici per engagement utenti e gestione eventi
AI_TEACHING: Multi-channel notifications, scheduling, templates

ALTERNATIVE_VALUTATE:
- Cron jobs esterni: Scartato, meno controllo, difficile debug
- Inline notifications: Scartato, blocca request, non scalabile
- Third-party service only: Scartato, vendor lock-in

PERCHE_QUESTA_SOLUZIONE:
- DB-backed scheduling: Tracciabilità, retry, audit
- Multi-channel: Email, push, dashboard, SMS (futuro)
- Configurabile: 2 livelli (piattaforma, evento override)
- Template-based: Consistenza, i18n ready

ALERT TYPES:
- EVENT_REMINDER: X giorni prima evento
- PRESALE_START: Inizio prevendita
- SALE_START: Inizio vendita
- LOW_CAPACITY: Pochi posti rimasti
- SOLD_OUT: Tutto esaurito
- THRESHOLD_WARNING: Soglia minima non raggiunta
- WAITLIST_SPOT: Posto disponibile in waiting list
- REFUND_REQUEST: Nuova richiesta rimborso
- EVENT_CANCELLED: Evento cancellato

CHANNELS:
- email: Via SendGrid/SES
- push: Via Firebase/OneSignal
- dashboard: In-app notifications
- sms: Via Twilio (future)
"""

from datetime import datetime, timedelta, date
from typing import Optional, List, Dict, Any, Callable
from uuid import UUID
import logging
import asyncio

from sqlalchemy import select, func, and_, or_, update, delete
from sqlalchemy.ext.asyncio import AsyncSession

from modules.events.config import (
    get_events_config,
    EventsConfig,
    ConfigResolver
)
from modules.events.models import (
    Event,
    EventSubscription,
    EventWaitingList,
    ASDRefundRequest,
    PlatformAlertConfig,
    EventNotification,
    EventStatus,
    SubscriptionStatus,
    AlertType,
    NotificationChannel
)
from modules.events.email_service import EmailService, EmailType, get_email_service
from models import User

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Service per gestione notifiche eventi.

    Gestisce:
    - Scheduling alert basato su config
    - Multi-channel delivery (email, push, dashboard)
    - Template rendering
    - Retry logic per failures

    USAGE:
    ```python
    service = NotificationService(db)

    # Schedule reminders for event
    await service.schedule_event_reminders(event_id)

    # Process pending notifications
    await service.process_pending_notifications()

    # Send immediate notification
    await service.send_notification(
        user_id, AlertType.EVENT_CANCELLED, context
    )
    ```
    """

    def __init__(
        self,
        db: AsyncSession,
        config: Optional[EventsConfig] = None,
        email_sender: Optional[Callable] = None,
        push_sender: Optional[Callable] = None,
        email_service: Optional[EmailService] = None
    ):
        """
        Inizializza notification service.

        Args:
            db: Database session
            config: Events config
            email_sender: Async callable per email (injected) - deprecated
            push_sender: Async callable per push (injected)
            email_service: EmailService instance (recommended)
        """
        self.db = db
        self.config = config or get_events_config()
        self._email_sender = email_sender
        self._push_sender = push_sender
        self._email_service = email_service or get_email_service()

    def _map_alert_to_email_type(self, alert_type: AlertType) -> Optional[EmailType]:
        """Map AlertType to EmailType for email service."""
        mapping = {
            AlertType.EVENT_REMINDER: EmailType.EVENT_REMINDER_7DAYS,
            AlertType.WAITLIST_SPOT: EmailType.WAITLIST_SPOT_AVAILABLE,
            AlertType.REFUND_REQUEST: EmailType.REFUND_APPROVED,
            AlertType.EVENT_CANCELLED: EmailType.EVENT_CANCELLED,
        }
        return mapping.get(alert_type)

    async def _get_user(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    # ======================== SCHEDULING ========================

    async def schedule_event_reminders(
        self,
        event_id: UUID
    ) -> List[EventNotification]:
        """
        Schedula reminder per evento.

        Args:
            event_id: ID evento

        Returns:
            Lista notifiche create

        LOGIC:
        1. Get event e config (con override)
        2. Per ogni giorno reminder, calcola scheduled_at
        3. Crea notification records per ogni subscriber
        """
        event = await self._get_event(event_id)
        if not event:
            return []

        resolver = ConfigResolver(self.config, event.alert_config_override)

        if not resolver.get_reminder_enabled():
            logger.info(f"Reminders disabled for event {event_id}")
            return []

        reminder_days = resolver.get_reminder_days()
        channels = resolver.get_channels(AlertType.EVENT_REMINDER)

        # Get confirmed subscribers
        subscribers = await self._get_event_subscribers(event_id)

        notifications = []
        for days in reminder_days:
            scheduled_at = event.start_date - timedelta(days=days)

            # Skip if already past
            if scheduled_at <= date.today():
                continue

            for user_id in subscribers:
                # Check if already scheduled
                existing = await self._notification_exists(
                    user_id, event_id, AlertType.EVENT_REMINDER, days
                )
                if existing:
                    continue

                notification = EventNotification(
                    recipient_user_id=user_id,
                    recipient_type="specific_user",
                    event_id=event_id,
                    alert_type=AlertType.EVENT_REMINDER,
                    channels=[ch for ch, enabled in channels.items() if enabled],
                    scheduled_for=datetime.combine(scheduled_at, datetime.min.time()),
                    data={
                        "days_before": days,
                        "event_title": event.title,
                        "event_date": event.start_date.isoformat(),
                        "location": event.location_name
                    }
                )
                self.db.add(notification)
                notifications.append(notification)

        await self.db.flush()
        logger.info(f"Scheduled {len(notifications)} reminders for event {event_id}")
        return notifications

    async def schedule_presale_alerts(
        self,
        event_id: UUID
    ) -> List[EventNotification]:
        """
        Schedula alert inizio prevendita.

        Args:
            event_id: ID evento

        Returns:
            Lista notifiche create

        TARGETS:
        - Users matching presale_criteria
        - Users in waiting list
        """
        event = await self._get_event(event_id)
        if not event or not event.presale_start:
            return []

        resolver = ConfigResolver(self.config, event.alert_config_override)
        channels = resolver.get_channels(AlertType.PRESALE_START)

        # Schedule for X hours before presale
        notify_before = self.config.presale.notify_before_hours
        scheduled_at = event.presale_start - timedelta(hours=notify_before)

        if scheduled_at <= datetime.utcnow():
            return []

        # Get eligible users (simplified - would check presale_criteria)
        # For now, get users from waiting list + past event attendees
        waiting_users = await self._get_waiting_list_users(event_id)

        notifications = []
        for user_id in waiting_users:
            notification = EventNotification(
                recipient_user_id=user_id,
                recipient_type="specific_user",
                event_id=event_id,
                alert_type=AlertType.PRESALE_START,
                channels=[ch for ch, enabled in channels.items() if enabled],
                scheduled_for=scheduled_at,
                data={
                    "event_title": event.title,
                    "presale_start": event.presale_start.isoformat(),
                    "presale_end": event.presale_end.isoformat() if event.presale_end else None
                }
            )
            self.db.add(notification)
            notifications.append(notification)

        await self.db.flush()
        logger.info(f"Scheduled {len(notifications)} presale alerts for event {event_id}")
        return notifications

    async def schedule_threshold_checks(
        self,
        event_id: UUID
    ) -> List[EventNotification]:
        """
        Schedula check soglia minima.

        Args:
            event_id: ID evento

        Returns:
            Lista notifiche create (per admin/ASD)

        LOGIC:
        - Check X giorni prima evento
        - Se sotto soglia, notifica admin + ASD
        """
        event = await self._get_event(event_id)
        if not event or not event.min_threshold:
            return []

        resolver = ConfigResolver(self.config, event.alert_config_override)

        if not resolver.get_threshold_enabled():
            return []

        check_days = resolver.get_threshold_days()
        channels = resolver.get_channels(AlertType.THRESHOLD_WARNING)

        # Get admin users to notify
        admin_users = await self._get_event_admins(event_id)

        notifications = []
        for days in check_days:
            scheduled_at = event.start_date - timedelta(days=days)

            if scheduled_at <= date.today():
                continue

            for user_id in admin_users:
                notification = EventNotification(
                    recipient_user_id=user_id,
                    recipient_type="specific_user",
                    event_id=event_id,
                    alert_type=AlertType.THRESHOLD_WARNING,
                    channels=[ch for ch, enabled in channels.items() if enabled],
                    scheduled_for=datetime.combine(scheduled_at, datetime.min.time()),
                    data={
                        "days_before": days,
                        "min_capacity": event.min_threshold,
                        "check_type": "scheduled"
                    }
                )
                self.db.add(notification)
                notifications.append(notification)

        await self.db.flush()
        return notifications

    # ======================== IMMEDIATE NOTIFICATIONS ========================

    async def notify_low_capacity(
        self,
        event_id: UUID,
        remaining_spots: int
    ) -> List[EventNotification]:
        """
        Notifica pochi posti rimasti.

        Args:
            event_id: ID evento
            remaining_spots: Posti rimanenti

        Returns:
            Lista notifiche create

        TARGETS:
        - Users in waiting list
        - Users who viewed but didn't purchase (future)
        """
        event = await self._get_event(event_id)
        if not event:
            return []

        resolver = ConfigResolver(self.config, event.alert_config_override)
        threshold = resolver.get_low_capacity_threshold()

        if remaining_spots > threshold:
            return []

        channels = resolver.get_channels(AlertType.LOW_CAPACITY)
        waiting_users = await self._get_waiting_list_users(event_id)

        notifications = []
        for user_id in waiting_users:
            notification = await self._create_and_send_notification(
                user_id=user_id,
                event_id=event_id,
                alert_type=AlertType.LOW_CAPACITY,
                channels=channels,
                context={
                    "event_title": event.title,
                    "remaining_spots": remaining_spots,
                    "event_date": event.start_date.isoformat()
                }
            )
            notifications.append(notification)

        return notifications

    async def notify_waitlist_spot_available(
        self,
        event_id: UUID,
        spots_available: int = 1
    ) -> List[EventNotification]:
        """
        Notifica posto disponibile a waiting list.

        STRATEGY: "Notify all, first to pay wins"

        Args:
            event_id: ID evento
            spots_available: Posti disponibili

        Returns:
            Lista notifiche create
        """
        event = await self._get_event(event_id)
        if not event:
            return []

        resolver = ConfigResolver(self.config, event.alert_config_override)
        channels = resolver.get_channels(AlertType.WAITLIST_SPOT)

        # Get all active waiting list entries
        result = await self.db.execute(
            select(EventWaitingList).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            ).order_by(EventWaitingList.position)
        )
        entries = list(result.scalars().all())

        notifications = []
        for entry in entries:
            notification = await self._create_and_send_notification(
                user_id=entry.user_id,
                event_id=event_id,
                alert_type=AlertType.WAITLIST_SPOT,
                channels=channels,
                context={
                    "event_title": event.title,
                    "spots_available": spots_available,
                    "position": entry.position,
                    "event_date": event.start_date.isoformat()
                }
            )
            notifications.append(notification)

            # Update waiting list entry
            entry.notified_at = datetime.utcnow()
            entry.notification_count += 1

        await self.db.flush()
        logger.info(f"Notified {len(notifications)} waiting list users for event {event_id}")
        return notifications

    async def notify_event_cancelled(
        self,
        event_id: UUID,
        reason: Optional[str] = None
    ) -> List[EventNotification]:
        """
        Notifica cancellazione evento.

        Args:
            event_id: ID evento
            reason: Motivo cancellazione

        Returns:
            Lista notifiche create

        TARGETS:
        - All confirmed subscribers
        - All waiting list users
        """
        event = await self._get_event(event_id)
        if not event:
            return []

        channels = {"email": True, "push": True, "dashboard": True}

        # Get all affected users
        subscribers = await self._get_event_subscribers(event_id)
        waiting_users = await self._get_waiting_list_users(event_id)

        all_users = set(subscribers) | set(waiting_users)

        notifications = []
        for user_id in all_users:
            notification = await self._create_and_send_notification(
                user_id=user_id,
                event_id=event_id,
                alert_type=AlertType.EVENT_CANCELLED,
                channels=channels,
                context={
                    "event_title": event.title,
                    "event_date": event.start_date.isoformat(),
                    "reason": reason,
                    "refund_info": "Automatic refund will be processed" if user_id in subscribers else None
                },
                priority="high"
            )
            notifications.append(notification)

        logger.info(f"Sent cancellation notices to {len(notifications)} users for event {event_id}")
        return notifications

    async def notify_refund_status(
        self,
        refund_id: UUID,
        status: str
    ) -> Optional[EventNotification]:
        """
        Notifica cambio stato rimborso.

        Args:
            refund_id: ID richiesta rimborso
            status: Nuovo status (approved, rejected, processed)

        Returns:
            Notifica creata
        """
        result = await self.db.execute(
            select(ASDRefundRequest).where(ASDRefundRequest.id == refund_id)
        )
        refund = result.scalar_one_or_none()
        if not refund:
            return None

        # Get subscription and event
        sub_result = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.id == refund.subscription_id
            )
        )
        subscription = sub_result.scalar_one_or_none()
        if not subscription:
            return None

        event = await self._get_event(subscription.event_id)

        alert_type = AlertType.REFUND_REQUEST  # Using same type, context differs

        notification = await self._create_and_send_notification(
            user_id=subscription.user_id,
            event_id=subscription.event_id,
            alert_type=alert_type,
            channels={"email": True, "push": True, "dashboard": True},
            context={
                "event_title": event.title if event else "Event",
                "refund_status": status,
                "amount_cents": refund.requested_amount_cents,
                "rejection_reason": refund.rejection_reason if status == "rejected" else None
            }
        )

        return notification

    async def notify_admin_refund_request(
        self,
        refund_id: UUID
    ) -> List[EventNotification]:
        """
        Notifica admin di nuova richiesta rimborso.

        Args:
            refund_id: ID richiesta rimborso

        Returns:
            Lista notifiche create
        """
        result = await self.db.execute(
            select(ASDRefundRequest).where(ASDRefundRequest.id == refund_id)
        )
        refund = result.scalar_one_or_none()
        if not refund:
            return []

        sub_result = await self.db.execute(
            select(EventSubscription).where(
                EventSubscription.id == refund.subscription_id
            )
        )
        subscription = sub_result.scalar_one_or_none()
        if not subscription:
            return []

        # Get admin users
        admin_users = await self._get_event_admins(subscription.event_id)

        notifications = []
        for admin_id in admin_users:
            notification = await self._create_and_send_notification(
                user_id=admin_id,
                event_id=subscription.event_id,
                alert_type=AlertType.REFUND_REQUEST,
                channels={"email": True, "dashboard": True},
                context={
                    "refund_id": str(refund_id),
                    "amount_cents": refund.requested_amount_cents,
                    "reason": refund.reason,
                    "user_id": str(refund.requested_by) if refund.requested_by else None
                }
            )
            notifications.append(notification)

        return notifications

    # ======================== PROCESSING ========================

    async def process_pending_notifications(
        self,
        batch_size: int = 100
    ) -> int:
        """
        Processa notifiche pending schedulate.

        Args:
            batch_size: Max notifiche per batch

        Returns:
            Numero notifiche processate

        USAGE:
        - Chiamato da scheduler/cron ogni X minuti
        - Processa notifiche con scheduled_at <= now
        """
        now = datetime.utcnow()

        result = await self.db.execute(
            select(EventNotification).where(
                EventNotification.scheduled_for <= now,
                EventNotification.sent == False,
                EventNotification.send_attempts < 3
            ).limit(batch_size)
        )
        notifications = list(result.scalars().all())

        processed = 0
        for notification in notifications:
            success = await self._send_notification(notification)
            if success:
                notification.sent = True
                notification.sent_at = datetime.utcnow()
                processed += 1
            else:
                notification.send_attempts += 1
                if notification.send_attempts >= 3:
                    notification.last_error = "Max retries exceeded"

        await self.db.flush()
        logger.info(f"Processed {processed}/{len(notifications)} pending notifications")
        return processed

    async def retry_failed_notifications(
        self,
        max_age_hours: int = 24
    ) -> int:
        """
        Retry notifiche fallite recenti.

        Args:
            max_age_hours: Max età per retry

        Returns:
            Numero retry
        """
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)

        result = await self.db.execute(
            select(EventNotification).where(
                EventNotification.created_at >= cutoff,
                EventNotification.sent == False,
                EventNotification.send_attempts >= 3,
                EventNotification.send_attempts < 5
            )
        )
        notifications = list(result.scalars().all())

        retried = 0
        for notification in notifications:
            notification.last_error = None
            notification.scheduled_for = datetime.utcnow()
            retried += 1

        await self.db.flush()
        logger.info(f"Queued {retried} notifications for retry")
        return retried

    # ======================== HELPERS ========================

    async def _get_event(self, event_id: UUID) -> Optional[Event]:
        """Get event by ID."""
        result = await self.db.execute(
            select(Event).where(Event.id == event_id)
        )
        return result.scalar_one_or_none()

    async def _get_event_subscribers(self, event_id: UUID) -> List[UUID]:
        """Get user IDs of confirmed subscribers."""
        result = await self.db.execute(
            select(EventSubscription.user_id).where(
                EventSubscription.event_id == event_id,
                EventSubscription.status == SubscriptionStatus.CONFIRMED
            )
        )
        return [r[0] for r in result.all()]

    async def _get_waiting_list_users(self, event_id: UUID) -> List[UUID]:
        """Get user IDs in waiting list."""
        result = await self.db.execute(
            select(EventWaitingList.user_id).where(
                EventWaitingList.event_id == event_id,
                EventWaitingList.is_active == True
            )
        )
        return [r[0] for r in result.all()]

    async def _get_event_admins(self, event_id: UUID) -> List[UUID]:
        """Get admin user IDs for event (ASD admin + platform admins)."""
        from modules.events.models import ASDPartner

        event = await self._get_event(event_id)
        if not event:
            return []

        # Get ASD admin
        result = await self.db.execute(
            select(ASDPartner.admin_user_id).where(
                ASDPartner.id == event.asd_id
            )
        )
        asd_admin = result.scalar_one_or_none()

        admins = []
        if asd_admin:
            admins.append(asd_admin)

        # TODO: Add platform admins from users table
        return admins

    async def _notification_exists(
        self,
        user_id: UUID,
        event_id: UUID,
        alert_type: AlertType,
        days_before: int
    ) -> bool:
        """Check if notification already exists."""
        result = await self.db.execute(
            select(EventNotification.id).where(
                EventNotification.recipient_user_id == user_id,
                EventNotification.event_id == event_id,
                EventNotification.alert_type == alert_type,
                EventNotification.data["days_before"].astext == str(days_before)
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None

    async def _create_and_send_notification(
        self,
        user_id: UUID,
        event_id: UUID,
        alert_type: AlertType,
        channels: Dict[str, bool],
        context: Dict[str, Any],
        priority: str = "normal"
    ) -> EventNotification:
        """Create notification and send immediately."""
        notification = EventNotification(
            recipient_user_id=user_id,
            recipient_type="specific_user",
            event_id=event_id,
            alert_type=alert_type,
            channels=[ch for ch, enabled in channels.items() if enabled],
            scheduled_for=datetime.utcnow(),
            data=context
        )
        self.db.add(notification)
        await self.db.flush()

        # Try to send immediately
        success = await self._send_notification(notification)
        if success:
            notification.sent_at = datetime.utcnow()
        else:
            notification.send_attempts = 1

        return notification

    async def _send_notification(
        self,
        notification: EventNotification
    ) -> bool:
        """
        Send notification through configured channels.

        Args:
            notification: Notification to send

        Returns:
            True if at least one channel succeeded
        """
        success = False

        for channel in notification.channels:
            try:
                if channel == NotificationChannel.EMAIL.value or channel == "email":
                    # Use EmailService for email sending
                    email_sent = await self._send_email_via_service(notification)
                    if email_sent:
                        success = True

                elif channel == NotificationChannel.PUSH.value or channel == "push":
                    if self._push_sender:
                        await self._send_push(notification)
                        success = True
                    else:
                        logger.debug("Push sender not configured")

                elif channel == NotificationChannel.DASHBOARD.value or channel == "dashboard":
                    # Dashboard notifications are just the DB record
                    success = True

                elif channel == NotificationChannel.SMS.value or channel == "sms":
                    # SMS not implemented
                    logger.debug("SMS not implemented")

            except Exception as e:
                logger.error(f"Error sending {channel} notification: {e}")
                notification.last_error = str(e)

        return success

    async def _send_email_via_service(
        self,
        notification: EventNotification
    ) -> bool:
        """
        Send email notification via EmailService.

        Args:
            notification: Notification to send

        Returns:
            True if email was sent successfully
        """
        if not notification.recipient_user_id:
            logger.warning("No recipient user ID for email notification")
            return False

        # Get user email
        user = await self._get_user(notification.recipient_user_id)
        if not user or not user.email:
            logger.warning(f"User {notification.recipient_user_id} not found or has no email")
            return False

        # Get event for context
        event = await self._get_event(notification.event_id) if notification.event_id else None
        context = notification.data or {}

        # Get user name
        user_name = getattr(user, 'first_name', '') or getattr(user, 'name', '') or user.email.split('@')[0]

        try:
            # Send based on alert type
            if notification.alert_type == AlertType.EVENT_REMINDER:
                days_until = context.get('days_before', 7)
                return await self._email_service.send_event_reminder(
                    to_email=user.email,
                    user_name=user_name,
                    event_title=context.get('event_title', event.title if event else 'Evento'),
                    event_date=context.get('event_date', event.start_date.isoformat() if event else ''),
                    event_location=context.get('location', event.location_name if event else ''),
                    event_address=event.location_address if event else None,
                    days_until=days_until
                )

            elif notification.alert_type == AlertType.WAITLIST_SPOT:
                checkout_url = context.get('checkout_url', f"https://events.libra.it/events/{notification.event_id}")
                return await self._email_service.send_waitlist_notification(
                    to_email=user.email,
                    user_name=user_name,
                    event_title=context.get('event_title', event.title if event else 'Evento'),
                    event_date=context.get('event_date', event.start_date.isoformat() if event else ''),
                    checkout_url=checkout_url,
                    expires_in_hours=24
                )

            elif notification.alert_type == AlertType.EVENT_CANCELLED:
                return await self._email_service.send_event_cancelled(
                    to_email=user.email,
                    user_name=user_name,
                    event_title=context.get('event_title', event.title if event else 'Evento'),
                    event_date=context.get('event_date', event.start_date.isoformat() if event else ''),
                    cancellation_reason=context.get('reason'),
                    refund_info=context.get('refund_info', 'Il rimborso verrà elaborato automaticamente.')
                )

            elif notification.alert_type == AlertType.REFUND_REQUEST:
                refund_status = context.get('refund_status', 'approved')
                approved = refund_status in ['approved', 'processed']
                amount_cents = context.get('amount_cents', 0)
                refund_amount = f"€{amount_cents / 100:.2f}" if amount_cents else "N/A"

                return await self._email_service.send_refund_notification(
                    to_email=user.email,
                    user_name=user_name,
                    event_title=context.get('event_title', event.title if event else 'Evento'),
                    refund_amount=refund_amount,
                    approved=approved,
                    reason=context.get('rejection_reason')
                )

            else:
                # Fallback: use generic email with send_email
                subject = self._get_email_subject(notification.alert_type, context)
                html_content = f"""
                <html>
                <body>
                    <h2>{subject}</h2>
                    <p>Ciao {user_name},</p>
                    <p>{context.get('message', 'Hai ricevuto una notifica.')}</p>
                </body>
                </html>
                """
                return await self._email_service.send_email(
                    to_email=user.email,
                    subject=subject,
                    html_content=html_content
                )

        except Exception as e:
            logger.error(f"Error sending email via EmailService: {e}")
            return False

    async def _send_email(self, notification: EventNotification):
        """Send email notification."""
        template = self._get_email_template(notification.alert_type)
        subject = self._get_email_subject(notification.alert_type, notification.data)

        if self._email_sender:
            await self._email_sender(
                to_user_id=notification.user_id,
                subject=subject,
                template=template,
                context=notification.data
            )

    async def _send_push(self, notification: EventNotification):
        """Send push notification."""
        title = self._get_push_title(notification.alert_type)
        body = self._get_push_body(notification.alert_type, notification.data)

        if self._push_sender:
            await self._push_sender(
                user_id=notification.user_id,
                title=title,
                body=body,
                data=notification.data
            )

    def _get_email_template(self, alert_type: AlertType) -> str:
        """Get email template name for alert type."""
        templates = {
            AlertType.EVENT_REMINDER: "event_reminder",
            AlertType.PRESALE_START: "presale_start",
            AlertType.SALE_START: "sale_start",
            AlertType.LOW_CAPACITY: "low_capacity",
            AlertType.THRESHOLD_WARNING: "threshold_warning",
            AlertType.WAITLIST_SPOT: "waitlist_spot",
            AlertType.REFUND_REQUEST: "refund_status",
            AlertType.EVENT_CANCELLED: "event_cancelled",
        }
        return templates.get(alert_type, "generic")

    def _get_email_subject(
        self,
        alert_type: AlertType,
        context: Dict[str, Any]
    ) -> str:
        """Get email subject for alert type."""
        event_title = context.get("event_title", "Evento")

        subjects = {
            AlertType.EVENT_REMINDER: f"Promemoria: {event_title} tra {context.get('days_before', '?')} giorni",
            AlertType.PRESALE_START: f"Prevendita in arrivo: {event_title}",
            AlertType.SALE_START: f"Vendita aperta: {event_title}",
            AlertType.LOW_CAPACITY: f"Ultimi posti disponibili: {event_title}",
            AlertType.THRESHOLD_WARNING: f"Attenzione: Soglia minima non raggiunta - {event_title}",
            AlertType.WAITLIST_SPOT: f"Posto disponibile! {event_title}",
            AlertType.REFUND_REQUEST: f"Aggiornamento rimborso: {event_title}",
            AlertType.EVENT_CANCELLED: f"Evento cancellato: {event_title}",
        }
        return subjects.get(alert_type, f"Notifica: {event_title}")

    def _get_push_title(self, alert_type: AlertType) -> str:
        """Get push notification title."""
        titles = {
            AlertType.EVENT_REMINDER: "Promemoria Evento",
            AlertType.PRESALE_START: "Prevendita In Arrivo",
            AlertType.SALE_START: "Vendita Aperta",
            AlertType.LOW_CAPACITY: "Ultimi Posti!",
            AlertType.THRESHOLD_WARNING: "Attenzione Evento",
            AlertType.WAITLIST_SPOT: "Posto Disponibile!",
            AlertType.REFUND_REQUEST: "Aggiornamento Rimborso",
            AlertType.EVENT_CANCELLED: "Evento Cancellato",
        }
        return titles.get(alert_type, "Notifica")

    def _get_push_body(
        self,
        alert_type: AlertType,
        context: Dict[str, Any]
    ) -> str:
        """Get push notification body."""
        event_title = context.get("event_title", "Evento")

        bodies = {
            AlertType.EVENT_REMINDER: f"{event_title} tra {context.get('days_before', '?')} giorni",
            AlertType.PRESALE_START: f"La prevendita per {event_title} sta per iniziare",
            AlertType.SALE_START: f"I biglietti per {event_title} sono disponibili",
            AlertType.LOW_CAPACITY: f"Solo {context.get('remaining_spots', '?')} posti per {event_title}",
            AlertType.THRESHOLD_WARNING: f"Soglia minima non raggiunta per {event_title}",
            AlertType.WAITLIST_SPOT: f"Un posto si è liberato per {event_title}!",
            AlertType.REFUND_REQUEST: f"Il tuo rimborso è stato {context.get('refund_status', 'aggiornato')}",
            AlertType.EVENT_CANCELLED: f"{event_title} è stato cancellato",
        }
        return bodies.get(alert_type, f"Aggiornamento per {event_title}")

    # ======================== USER PREFERENCES ========================

    async def get_user_notifications(
        self,
        user_id: UUID,
        unread_only: bool = False,
        limit: int = 50
    ) -> List[EventNotification]:
        """
        Ottiene notifiche utente (per dashboard).

        Args:
            user_id: ID utente
            unread_only: Solo non lette
            limit: Max risultati

        Returns:
            Lista notifiche
        """
        query = select(EventNotification).where(
            EventNotification.recipient_user_id == user_id,
            EventNotification.sent == True
        )

        # Note: read_at tracking not implemented in current schema
        # unread_only parameter is ignored

        query = query.order_by(EventNotification.sent_at.desc()).limit(limit)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def mark_notification_read(
        self,
        notification_id: UUID,
        user_id: UUID
    ) -> bool:
        """
        Segna notifica come letta.

        Note: read_at tracking not implemented in current schema.
        This function verifies ownership but doesn't update read status.

        Args:
            notification_id: ID notifica
            user_id: ID utente (per verifica ownership)

        Returns:
            True se notifica esiste ed appartiene all'utente
        """
        result = await self.db.execute(
            select(EventNotification.id).where(
                EventNotification.id == notification_id,
                EventNotification.recipient_user_id == user_id
            )
        )
        return result.scalar_one_or_none() is not None

    async def mark_all_read(self, user_id: UUID) -> int:
        """
        Segna tutte le notifiche come lette.

        Note: read_at tracking not implemented in current schema.
        Returns count of sent notifications for user.

        Args:
            user_id: ID utente

        Returns:
            Numero notifiche inviate per l'utente
        """
        result = await self.db.execute(
            select(func.count(EventNotification.id)).where(
                EventNotification.recipient_user_id == user_id,
                EventNotification.sent == True
            )
        )
        return result.scalar() or 0

    async def get_unread_count(self, user_id: UUID) -> int:
        """
        Conta notifiche non lette.

        Note: read_at tracking not implemented in current schema.
        Returns total count of sent notifications.

        Args:
            user_id: ID utente

        Returns:
            Conteggio notifiche inviate
        """
        result = await self.db.execute(
            select(func.count(EventNotification.id)).where(
                EventNotification.recipient_user_id == user_id,
                EventNotification.sent == True
            )
        )
        return result.scalar() or 0

    # ======================== CLEANUP ========================

    async def cleanup_old_notifications(
        self,
        days: int = 90
    ) -> int:
        """
        Rimuove notifiche vecchie.

        Args:
            days: Età massima

        Returns:
            Numero rimosse
        """
        cutoff = datetime.utcnow() - timedelta(days=days)

        result = await self.db.execute(
            delete(EventNotification).where(
                EventNotification.created_at < cutoff
            )
        )
        await self.db.flush()

        logger.info(f"Cleaned up {result.rowcount} old notifications")
        return result.rowcount

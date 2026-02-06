"""
================================================================================
AI_MODULE: NotificationService
AI_DESCRIPTION: Servizio per gestione notifiche e push notifications
AI_BUSINESS: User engagement, real-time notifications, FCM/APNS integration
AI_TEACHING: Async service pattern, push notification logic, batch operations

ALTERNATIVE_VALUTATE:
- Polling: Scartata per inefficienza e latenza
- WebSocket only: Scartata per complessita mobile
- Push + in-app combo: SCELTA per copertura completa

PERCHE_QUESTA_SOLUZIONE:
- Vantaggio tecnico: Push garantisce delivery anche con app in background
- Vantaggio business: Engagement rate +40% con push notifications
- Trade-off accettati: Dipendenza da FCM/APNS

METRICHE_SUCCESSO:
- Push delivery rate: >= 95%
- Notification open rate: >= 25%
- User opt-out rate: <= 10%

INTEGRATION_DEPENDENCIES:
- Upstream: models/notification.py, models/user.py
- Downstream: api/v1/notifications.py, Firebase/APNS services
================================================================================
"""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
import uuid
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, update, delete
from sqlalchemy.orm import selectinload

from models.notification import (
    Notification,
    NotificationType,
    NotificationPriority,
    DeviceToken,
    DeviceType,
    NotificationPreference
)
from models.user import User

logger = logging.getLogger(__name__)


# === CONSTANTS ===

DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
NOTIFICATION_RETENTION_DAYS = 90  # Keep notifications for 90 days


class NotificationService:
    """
    Servizio per gestione notifiche utente.

    BUSINESS_PURPOSE: Gestire notifiche in-app e push per user engagement.
    Supporta creazione, lettura, marking, e push notification delivery.

    TECHNICAL_EXPLANATION: Async service con dependency injection di db session.
    Usa SQLAlchemy async per operazioni DB e supporta batch operations.
    """

    def __init__(self, db: AsyncSession):
        """
        Inizializza il servizio con database session.

        Args:
            db: AsyncSession SQLAlchemy per operazioni DB
        """
        self.db = db

    # === NOTIFICATION CRUD ===

    async def create_notification(
        self,
        user_id: str,
        notification_type: NotificationType,
        title: str,
        body: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        image_url: Optional[str] = None,
        action_type: Optional[str] = None,
        action_payload: Optional[Dict[str, Any]] = None,
        expires_at: Optional[datetime] = None,
        send_push: bool = True
    ) -> Notification:
        """
        Crea una nuova notifica per un utente.

        BUSINESS_PURPOSE: Entry point per creare notifiche da qualsiasi modulo
        TECHNICAL_EXPLANATION: Crea record DB + optional push notification

        Args:
            user_id: UUID dell'utente
            notification_type: Tipo notifica (SYSTEM, VIDEO_NEW, etc.)
            title: Titolo notifica
            body: Corpo notifica
            priority: Priorita (LOW, NORMAL, HIGH, URGENT)
            image_url: URL immagine opzionale
            action_type: Tipo azione al click (open_video, open_profile, etc.)
            action_payload: Payload JSON per l'azione
            expires_at: Data scadenza opzionale
            send_push: Se inviare push notification

        Returns:
            Notification creata
        """
        user_uuid = uuid.UUID(user_id)

        # Check user preferences
        preferences = await self._get_user_preferences(user_uuid)
        if preferences and not preferences.is_notification_enabled(notification_type):
            logger.info(f"Notification {notification_type.value} disabled for user {user_id}")
            # Still create notification but don't send push
            send_push = False

        notification = Notification(
            id=uuid.uuid4(),
            user_id=user_uuid,
            type=notification_type,
            priority=priority,
            title=title,
            body=body,
            image_url=image_url,
            action_type=action_type,
            action_payload=action_payload,
            is_read=False,
            push_sent=False,
            created_at=datetime.utcnow(),
            expires_at=expires_at
        )

        self.db.add(notification)
        await self.db.commit()
        await self.db.refresh(notification)

        # Send push notification if enabled
        if send_push:
            await self._send_push_notification(notification, preferences)

        return notification

    async def create_bulk_notifications(
        self,
        user_ids: List[str],
        notification_type: NotificationType,
        title: str,
        body: str,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        image_url: Optional[str] = None,
        action_type: Optional[str] = None,
        action_payload: Optional[Dict[str, Any]] = None,
        expires_at: Optional[datetime] = None,
        send_push: bool = True
    ) -> int:
        """
        Crea notifiche per multipli utenti (broadcast).

        BUSINESS_PURPOSE: Notifiche di sistema, annunci, live events
        TECHNICAL_EXPLANATION: Batch insert per performance

        Args:
            user_ids: Lista UUID utenti
            notification_type: Tipo notifica
            title: Titolo notifica
            body: Corpo notifica
            priority: Priorita
            image_url: URL immagine opzionale
            action_type: Tipo azione al click
            action_payload: Payload JSON per l'azione
            expires_at: Data scadenza opzionale
            send_push: Se inviare push notifications

        Returns:
            Numero di notifiche create
        """
        notifications = []
        now = datetime.utcnow()

        for user_id in user_ids:
            try:
                user_uuid = uuid.UUID(user_id)
                notification = Notification(
                    id=uuid.uuid4(),
                    user_id=user_uuid,
                    type=notification_type,
                    priority=priority,
                    title=title,
                    body=body,
                    image_url=image_url,
                    action_type=action_type,
                    action_payload=action_payload,
                    is_read=False,
                    push_sent=False,
                    created_at=now,
                    expires_at=expires_at
                )
                notifications.append(notification)
            except ValueError:
                logger.warning(f"Invalid user_id: {user_id}")
                continue

        if notifications:
            self.db.add_all(notifications)
            await self.db.commit()

            if send_push:
                # Send push notifications in background
                for notification in notifications:
                    preferences = await self._get_user_preferences(notification.user_id)
                    await self._send_push_notification(notification, preferences)

        return len(notifications)

    async def get_notification(
        self,
        notification_id: str,
        user_id: str
    ) -> Optional[Notification]:
        """
        Ottiene una notifica specifica.

        Args:
            notification_id: UUID notifica
            user_id: UUID utente (per verifica ownership)

        Returns:
            Notification o None
        """
        result = await self.db.execute(
            select(Notification).where(
                and_(
                    Notification.id == uuid.UUID(notification_id),
                    Notification.user_id == uuid.UUID(user_id)
                )
            )
        )
        return result.scalar_one_or_none()

    async def get_user_notifications(
        self,
        user_id: str,
        page: int = 1,
        page_size: int = DEFAULT_PAGE_SIZE,
        unread_only: bool = False,
        notification_type: Optional[NotificationType] = None
    ) -> Tuple[List[Notification], int]:
        """
        Ottiene lista notifiche utente con paginazione.

        BUSINESS_PURPOSE: Feed notifiche in-app
        TECHNICAL_EXPLANATION: Query paginata con filtri opzionali

        Args:
            user_id: UUID dell'utente
            page: Numero pagina (1-indexed)
            page_size: Elementi per pagina
            unread_only: Solo non lette
            notification_type: Filtra per tipo

        Returns:
            Tuple (lista notifiche, totale)
        """
        user_uuid = uuid.UUID(user_id)
        page_size = min(page_size, MAX_PAGE_SIZE)
        offset = (page - 1) * page_size

        # Base query
        conditions = [
            Notification.user_id == user_uuid,
            or_(
                Notification.expires_at.is_(None),
                Notification.expires_at > datetime.utcnow()
            )
        ]

        if unread_only:
            conditions.append(Notification.is_read == False)

        if notification_type:
            conditions.append(Notification.type == notification_type)

        # Get total count
        count_result = await self.db.execute(
            select(func.count(Notification.id)).where(and_(*conditions))
        )
        total = count_result.scalar() or 0

        # Get paginated results
        result = await self.db.execute(
            select(Notification)
            .where(and_(*conditions))
            .order_by(desc(Notification.created_at))
            .offset(offset)
            .limit(page_size)
        )
        notifications = result.scalars().all()

        return list(notifications), total

    async def get_unread_count(self, user_id: str) -> int:
        """
        Ottiene conteggio notifiche non lette.

        Args:
            user_id: UUID dell'utente

        Returns:
            Numero notifiche non lette
        """
        result = await self.db.execute(
            select(func.count(Notification.id)).where(
                and_(
                    Notification.user_id == uuid.UUID(user_id),
                    Notification.is_read == False,
                    or_(
                        Notification.expires_at.is_(None),
                        Notification.expires_at > datetime.utcnow()
                    )
                )
            )
        )
        return result.scalar() or 0

    async def mark_as_read(
        self,
        notification_id: str,
        user_id: str
    ) -> bool:
        """
        Marca notifica come letta.

        Args:
            notification_id: UUID notifica
            user_id: UUID utente

        Returns:
            True se aggiornata con successo
        """
        notification = await self.get_notification(notification_id, user_id)
        if not notification:
            return False

        notification.mark_as_read()
        await self.db.commit()
        return True

    async def mark_all_as_read(self, user_id: str) -> int:
        """
        Marca tutte le notifiche utente come lette.

        Args:
            user_id: UUID dell'utente

        Returns:
            Numero di notifiche aggiornate
        """
        user_uuid = uuid.UUID(user_id)
        now = datetime.utcnow()

        result = await self.db.execute(
            update(Notification)
            .where(
                and_(
                    Notification.user_id == user_uuid,
                    Notification.is_read == False
                )
            )
            .values(is_read=True, read_at=now)
        )
        await self.db.commit()
        return result.rowcount

    async def delete_notification(
        self,
        notification_id: str,
        user_id: str
    ) -> bool:
        """
        Elimina una notifica.

        Args:
            notification_id: UUID notifica
            user_id: UUID utente

        Returns:
            True se eliminata con successo
        """
        notification = await self.get_notification(notification_id, user_id)
        if not notification:
            return False

        await self.db.delete(notification)
        await self.db.commit()
        return True

    async def delete_all_notifications(self, user_id: str) -> int:
        """
        Elimina tutte le notifiche di un utente.

        Args:
            user_id: UUID dell'utente

        Returns:
            Numero di notifiche eliminate
        """
        result = await self.db.execute(
            delete(Notification).where(
                Notification.user_id == uuid.UUID(user_id)
            )
        )
        await self.db.commit()
        return result.rowcount

    # === DEVICE TOKEN MANAGEMENT ===

    async def register_device_token(
        self,
        user_id: str,
        token: str,
        device_type: DeviceType,
        device_name: Optional[str] = None,
        device_model: Optional[str] = None,
        os_version: Optional[str] = None,
        app_version: Optional[str] = None
    ) -> DeviceToken:
        """
        Registra o aggiorna device token per push notifications.

        BUSINESS_PURPOSE: Abilitare push notifications
        TECHNICAL_EXPLANATION: Upsert token, deactivate duplicates

        Args:
            user_id: UUID dell'utente
            token: FCM/APNS token
            device_type: Tipo device (ios, android, web)
            device_name: Nome device opzionale
            device_model: Modello device opzionale
            os_version: Versione OS opzionale
            app_version: Versione app opzionale

        Returns:
            DeviceToken registrato
        """
        user_uuid = uuid.UUID(user_id)

        # Check if token already exists
        result = await self.db.execute(
            select(DeviceToken).where(DeviceToken.token == token)
        )
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing token
            existing.user_id = user_uuid
            existing.device_type = device_type
            existing.device_name = device_name
            existing.device_model = device_model
            existing.os_version = os_version
            existing.app_version = app_version
            existing.is_active = True
            existing.update_last_used()
            await self.db.commit()
            return existing

        # Create new token
        device_token = DeviceToken(
            id=uuid.uuid4(),
            user_id=user_uuid,
            token=token,
            device_type=device_type,
            device_name=device_name,
            device_model=device_model,
            os_version=os_version,
            app_version=app_version,
            is_active=True,
            last_used_at=datetime.utcnow(),
            created_at=datetime.utcnow()
        )

        self.db.add(device_token)
        await self.db.commit()
        await self.db.refresh(device_token)

        return device_token

    async def unregister_device_token(
        self,
        user_id: str,
        token: str
    ) -> bool:
        """
        Disattiva device token (logout o uninstall).

        Args:
            user_id: UUID dell'utente
            token: Token da disattivare

        Returns:
            True se disattivato con successo
        """
        result = await self.db.execute(
            select(DeviceToken).where(
                and_(
                    DeviceToken.user_id == uuid.UUID(user_id),
                    DeviceToken.token == token
                )
            )
        )
        device_token = result.scalar_one_or_none()

        if not device_token:
            return False

        device_token.deactivate()
        await self.db.commit()
        return True

    async def get_user_device_tokens(
        self,
        user_id: str,
        active_only: bool = True
    ) -> List[DeviceToken]:
        """
        Ottiene device tokens di un utente.

        Args:
            user_id: UUID dell'utente
            active_only: Solo token attivi

        Returns:
            Lista DeviceToken
        """
        conditions = [DeviceToken.user_id == uuid.UUID(user_id)]
        if active_only:
            conditions.append(DeviceToken.is_active == True)

        result = await self.db.execute(
            select(DeviceToken)
            .where(and_(*conditions))
            .order_by(desc(DeviceToken.last_used_at))
        )
        return list(result.scalars().all())

    # === NOTIFICATION PREFERENCES ===

    async def get_user_preferences(
        self,
        user_id: str
    ) -> Optional[NotificationPreference]:
        """
        Ottiene preferenze notifiche utente.

        Args:
            user_id: UUID dell'utente

        Returns:
            NotificationPreference o None
        """
        return await self._get_user_preferences(uuid.UUID(user_id))

    async def update_user_preferences(
        self,
        user_id: str,
        preferences: Dict[str, Any]
    ) -> NotificationPreference:
        """
        Aggiorna preferenze notifiche utente.

        Args:
            user_id: UUID dell'utente
            preferences: Dict con preferenze da aggiornare

        Returns:
            NotificationPreference aggiornato
        """
        user_uuid = uuid.UUID(user_id)
        existing = await self._get_user_preferences(user_uuid)

        if not existing:
            # Create new preferences
            existing = NotificationPreference(
                id=uuid.uuid4(),
                user_id=user_uuid,
                created_at=datetime.utcnow()
            )
            self.db.add(existing)

        # Update fields
        allowed_fields = {
            'system_enabled', 'video_new_enabled', 'live_start_enabled',
            'achievement_enabled', 'subscription_enabled', 'social_enabled',
            'promo_enabled', 'push_enabled', 'push_system', 'push_video_new',
            'push_live_start', 'push_achievement', 'push_subscription',
            'push_social', 'push_promo', 'quiet_hours_enabled',
            'quiet_hours_start', 'quiet_hours_end'
        }

        for key, value in preferences.items():
            if key in allowed_fields and hasattr(existing, key):
                setattr(existing, key, value)

        await self.db.commit()
        await self.db.refresh(existing)
        return existing

    # === BUSINESS NOTIFICATIONS ===

    async def notify_new_video(
        self,
        video_id: str,
        maestro_id: str,
        maestro_name: str,
        video_title: str,
        thumbnail_url: Optional[str] = None,
        follower_ids: Optional[List[str]] = None
    ) -> int:
        """
        Notifica followers di un maestro per nuovo video.

        Args:
            video_id: UUID del video
            maestro_id: UUID del maestro
            maestro_name: Nome del maestro
            video_title: Titolo del video
            thumbnail_url: URL thumbnail
            follower_ids: Lista follower IDs (se None, query tutti)

        Returns:
            Numero notifiche create
        """
        if follower_ids is None:
            # Query followers from database
            # This would need a followers table - for now use provided list
            return 0

        return await self.create_bulk_notifications(
            user_ids=follower_ids,
            notification_type=NotificationType.VIDEO_NEW,
            title=f"Nuovo video da {maestro_name}",
            body=video_title,
            image_url=thumbnail_url,
            action_type="open_video",
            action_payload={
                "video_id": video_id,
                "maestro_id": maestro_id
            }
        )

    async def notify_live_start(
        self,
        live_id: str,
        maestro_id: str,
        maestro_name: str,
        live_title: str,
        thumbnail_url: Optional[str] = None,
        follower_ids: Optional[List[str]] = None
    ) -> int:
        """
        Notifica followers che un live e iniziato.

        Args:
            live_id: UUID del live
            maestro_id: UUID del maestro
            maestro_name: Nome del maestro
            live_title: Titolo del live
            thumbnail_url: URL thumbnail
            follower_ids: Lista follower IDs

        Returns:
            Numero notifiche create
        """
        if follower_ids is None:
            return 0

        return await self.create_bulk_notifications(
            user_ids=follower_ids,
            notification_type=NotificationType.LIVE_START,
            priority=NotificationPriority.HIGH,
            title=f"{maestro_name} e in LIVE!",
            body=live_title,
            image_url=thumbnail_url,
            action_type="open_live",
            action_payload={
                "live_id": live_id,
                "maestro_id": maestro_id
            },
            expires_at=datetime.utcnow() + timedelta(hours=4)  # Live notification expires
        )

    async def notify_achievement(
        self,
        user_id: str,
        achievement_id: str,
        achievement_name: str,
        achievement_description: str,
        badge_url: Optional[str] = None
    ) -> Notification:
        """
        Notifica utente per achievement sbloccato.

        Args:
            user_id: UUID dell'utente
            achievement_id: ID achievement
            achievement_name: Nome achievement
            achievement_description: Descrizione
            badge_url: URL badge image

        Returns:
            Notification creata
        """
        return await self.create_notification(
            user_id=user_id,
            notification_type=NotificationType.ACHIEVEMENT,
            title=f"Achievement Sbloccato: {achievement_name}",
            body=achievement_description,
            image_url=badge_url,
            action_type="open_achievements",
            action_payload={"achievement_id": achievement_id}
        )

    async def notify_subscription_expiring(
        self,
        user_id: str,
        days_remaining: int,
        tier_name: str
    ) -> Notification:
        """
        Notifica utente che subscription sta per scadere.

        Args:
            user_id: UUID dell'utente
            days_remaining: Giorni rimanenti
            tier_name: Nome del tier

        Returns:
            Notification creata
        """
        if days_remaining <= 1:
            title = "Abbonamento in scadenza domani!"
            priority = NotificationPriority.URGENT
        elif days_remaining <= 3:
            title = f"Abbonamento in scadenza tra {days_remaining} giorni"
            priority = NotificationPriority.HIGH
        else:
            title = f"Abbonamento {tier_name} in scadenza"
            priority = NotificationPriority.NORMAL

        return await self.create_notification(
            user_id=user_id,
            notification_type=NotificationType.SUBSCRIPTION,
            priority=priority,
            title=title,
            body=f"Rinnova ora per continuare ad accedere a tutti i contenuti {tier_name}.",
            action_type="open_subscription",
            action_payload={"days_remaining": days_remaining}
        )

    async def send_system_notification(
        self,
        user_ids: List[str],
        title: str,
        body: str,
        action_url: Optional[str] = None
    ) -> int:
        """
        Invia notifica di sistema a lista utenti.

        Args:
            user_ids: Lista UUID utenti
            title: Titolo
            body: Corpo
            action_url: URL azione opzionale

        Returns:
            Numero notifiche create
        """
        action_payload = {"url": action_url} if action_url else None

        return await self.create_bulk_notifications(
            user_ids=user_ids,
            notification_type=NotificationType.SYSTEM,
            priority=NotificationPriority.HIGH,
            title=title,
            body=body,
            action_type="open_url" if action_url else None,
            action_payload=action_payload
        )

    # === MAINTENANCE ===

    async def cleanup_expired_notifications(self) -> int:
        """
        Elimina notifiche scadute (maintenance job).

        Returns:
            Numero notifiche eliminate
        """
        cutoff_date = datetime.utcnow() - timedelta(days=NOTIFICATION_RETENTION_DAYS)

        result = await self.db.execute(
            delete(Notification).where(
                or_(
                    and_(
                        Notification.expires_at.isnot(None),
                        Notification.expires_at < datetime.utcnow()
                    ),
                    Notification.created_at < cutoff_date
                )
            )
        )
        await self.db.commit()
        return result.rowcount

    async def cleanup_inactive_device_tokens(
        self,
        inactive_days: int = 90
    ) -> int:
        """
        Elimina device tokens inattivi.

        Args:
            inactive_days: Giorni di inattivita

        Returns:
            Numero token eliminati
        """
        cutoff_date = datetime.utcnow() - timedelta(days=inactive_days)

        result = await self.db.execute(
            delete(DeviceToken).where(
                and_(
                    DeviceToken.is_active == False,
                    DeviceToken.last_used_at < cutoff_date
                )
            )
        )
        await self.db.commit()
        return result.rowcount

    # === STATS ===

    async def get_notification_stats(
        self,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche notifiche utente.

        Args:
            user_id: UUID dell'utente

        Returns:
            Dict con statistiche
        """
        user_uuid = uuid.UUID(user_id)

        # Total notifications
        total_result = await self.db.execute(
            select(func.count(Notification.id)).where(
                Notification.user_id == user_uuid
            )
        )
        total = total_result.scalar() or 0

        # Unread count
        unread = await self.get_unread_count(user_id)

        # By type counts
        type_counts = {}
        for ntype in NotificationType:
            result = await self.db.execute(
                select(func.count(Notification.id)).where(
                    and_(
                        Notification.user_id == user_uuid,
                        Notification.type == ntype
                    )
                )
            )
            type_counts[ntype.value] = result.scalar() or 0

        # Device tokens
        tokens = await self.get_user_device_tokens(user_id)

        return {
            "total_notifications": total,
            "unread_count": unread,
            "by_type": type_counts,
            "active_devices": len(tokens),
            "device_types": [t.device_type.value for t in tokens]
        }

    # === PRIVATE HELPERS ===

    async def _get_user_preferences(
        self,
        user_uuid: uuid.UUID
    ) -> Optional[NotificationPreference]:
        """
        Helper per recuperare preferenze utente.

        Args:
            user_uuid: UUID dell'utente

        Returns:
            NotificationPreference o None
        """
        result = await self.db.execute(
            select(NotificationPreference).where(
                NotificationPreference.user_id == user_uuid
            )
        )
        return result.scalar_one_or_none()

    async def _send_push_notification(
        self,
        notification: Notification,
        preferences: Optional[NotificationPreference]
    ) -> bool:
        """
        Invia push notification.

        BUSINESS_PURPOSE: Delivery push notification a device
        TECHNICAL_EXPLANATION: Check preferences, quiet hours, then send via FCM/APNS

        Args:
            notification: Notification da inviare
            preferences: Preferenze utente

        Returns:
            True se inviata con successo
        """
        # Check if push enabled for this notification type
        if preferences:
            if not preferences.is_push_enabled_for_type(notification.type):
                logger.info(f"Push disabled for type {notification.type.value}")
                return False

            if preferences.is_in_quiet_hours():
                logger.info(f"User in quiet hours, skipping push")
                return False

        # Get active device tokens
        tokens = await self.get_user_device_tokens(str(notification.user_id))

        if not tokens:
            logger.info(f"No active device tokens for user {notification.user_id}")
            return False

        # Send to FCM/APNS (placeholder - would integrate with actual service)
        success = await self._send_to_push_service(notification, tokens)

        # Update notification status
        notification.push_sent = success
        notification.push_sent_at = datetime.utcnow() if success else None
        await self.db.commit()

        return success

    async def _send_to_push_service(
        self,
        notification: Notification,
        tokens: List[DeviceToken]
    ) -> bool:
        """
        Send notification to FCM/APNS.

        This is a placeholder - would integrate with actual push service.

        Args:
            notification: Notification to send
            tokens: List of device tokens

        Returns:
            True if sent successfully
        """
        # TODO: Integrate with Firebase Cloud Messaging / APNS
        # For now, log and return success
        logger.info(
            f"Would send push notification {notification.id} "
            f"to {len(tokens)} devices"
        )

        # Placeholder for actual FCM/APNS integration:
        # try:
        #     for token in tokens:
        #         if token.device_type == DeviceType.IOS:
        #             await self._send_apns(notification, token)
        #         else:
        #             await self._send_fcm(notification, token)
        #     return True
        # except Exception as e:
        #     logger.error(f"Push notification failed: {e}")
        #     notification.push_error = str(e)
        #     return False

        return True

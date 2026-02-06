"""
================================================================================
AI_MODULE: Notifications API Router
AI_DESCRIPTION: REST API endpoints per notifiche e push notifications
AI_BUSINESS: User engagement tramite notifiche in-app e push
AI_TEACHING: FastAPI routing, dependency injection, pagination

ALTERNATIVE_VALUTATE:
- WebSocket realtime: Scartata per complessita mobile
- Polling: Scartata per inefficienza
- REST + Push combo: SCELTA per copertura completa

PERCHE_QUESTA_SOLUZIONE:
- REST API standard per lista/read notifiche
- Push notifications per delivery real-time
- Pagination per performance con molte notifiche

METRICHE_SUCCESSO:
- Response time: < 100ms (p95)
- Error rate: < 0.1%

INTEGRATION_DEPENDENCIES:
- Upstream: modules/notifications/notification_service.py
- Downstream: flutter_app/features/notifications/

ENDPOINTS:
- GET /notifications - Lista notifiche utente (paginata)
- GET /notifications/unread-count - Conteggio non lette
- GET /notifications/{id} - Dettaglio notifica
- PATCH /notifications/{id}/read - Marca come letta
- POST /notifications/mark-all-read - Marca tutte come lette
- DELETE /notifications/{id} - Elimina notifica
- DELETE /notifications - Elimina tutte le notifiche
- POST /device-tokens - Registra device token
- DELETE /device-tokens/{token} - Rimuove device token
- GET /device-tokens - Lista device tokens utente
- GET /preferences - Ottieni preferenze notifiche
- PATCH /preferences - Aggiorna preferenze notifiche
- POST /admin/broadcast - Invia notifica broadcast (admin only)

FIX 2026-01-26: Route ordering fixed - specific paths must come BEFORE parametric paths
================================================================================
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, Body
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from datetime import datetime

# NOTE: get_db import removed - all endpoints now create their own sessions
# to avoid async generator conflicts with get_current_user
from core.security import get_current_user, get_current_admin_user
from models.user import User
from models.notification import NotificationType, NotificationPriority, DeviceType
from modules.notifications.notification_service import NotificationService
from api.v1.schemas import (
    NotificationResponse,
    NotificationListResponse,
    NotificationPreferencesResponse,
    NotificationPreferencesUpdate,
    DeviceTokenRequest,
    DeviceTokenResponse,
    DeviceTokenListResponse,
    UnreadCountResponse,
    BroadcastNotificationRequest,
    MessageResponse
)

router = APIRouter()


# ==============================================================================
# NOTIFICATION LIST (root path - must be first)
# ==============================================================================

@router.get(
    "",
    response_model=NotificationListResponse,
    summary="Get user notifications",
    description="Get paginated list of notifications for the current user"
)
async def get_notifications(
    page: int = Query(1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(20, ge=1, description="Items per page (max 100)"),
    unread_only: bool = Query(False, description="Filter to unread only"),
    notification_type: Optional[str] = Query(None, description="Filter by type"),
    current_user: User = Depends(get_current_user)
):
    """Get paginated list of user notifications."""
    from core.database import AsyncSessionLocal

    page_size = min(page_size, 100)

    ntype = None
    if notification_type:
        try:
            ntype = NotificationType(notification_type)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid notification type: {notification_type}"
            )

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        notifications, total = await service.get_user_notifications(
            user_id=str(current_user.id),
            page=page,
            page_size=page_size,
            unread_only=unread_only,
            notification_type=ntype
        )

        return NotificationListResponse(
            items=[n.to_dict() for n in notifications],
            total=total,
            page=page,
            page_size=page_size,
            has_more=total > page * page_size
        )


@router.delete(
    "",
    response_model=MessageResponse,
    summary="Delete all notifications",
    description="Delete all notifications for the current user"
)
async def delete_all_notifications(
    current_user: User = Depends(get_current_user)
):
    """Delete all user notifications."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        count = await service.delete_all_notifications(str(current_user.id))
        return MessageResponse(message=f"{count} notifications deleted")


# ==============================================================================
# SPECIFIC PATHS - MUST COME BEFORE /{notification_id}
# ==============================================================================

@router.get(
    "/unread-count",
    response_model=UnreadCountResponse,
    summary="Get unread notification count",
    description="Get the count of unread notifications for the current user"
)
async def get_unread_count(
    current_user: User = Depends(get_current_user)
):
    """Get unread notification count."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        count = await service.get_unread_count(str(current_user.id))
        return UnreadCountResponse(count=count)


@router.post(
    "/mark-all-read",
    response_model=MessageResponse,
    summary="Mark all notifications as read",
    description="Mark all notifications for the current user as read"
)
async def mark_all_as_read(
    current_user: User = Depends(get_current_user)
):
    """Mark all notifications as read."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        count = await service.mark_all_as_read(str(current_user.id))
        return MessageResponse(message=f"{count} notifications marked as read")


# ==============================================================================
# DEVICE TOKEN ENDPOINTS - MUST COME BEFORE /{notification_id}
# ==============================================================================

@router.get(
    "/device-tokens",
    response_model=DeviceTokenListResponse,
    summary="Get user device tokens",
    description="Get list of registered device tokens for the current user"
)
async def get_device_tokens(
    current_user: User = Depends(get_current_user)
):
    """Get user's registered device tokens."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        tokens = await service.get_user_device_tokens(str(current_user.id))
        return DeviceTokenListResponse(
            items=[t.to_dict() for t in tokens] if tokens else [],
            total=len(tokens) if tokens else 0
        )


@router.post(
    "/device-tokens",
    response_model=DeviceTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register device token",
    description="Register a device token for push notifications"
)
async def register_device_token(
    request: DeviceTokenRequest,
    current_user: User = Depends(get_current_user)
):
    """Register device token for push notifications."""
    from core.database import AsyncSessionLocal

    try:
        device_type = DeviceType(request.device_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid device type: {request.device_type}"
        )

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        token = await service.register_device_token(
            user_id=str(current_user.id),
            token=request.token,
            device_type=device_type,
            device_name=request.device_name,
            device_model=request.device_model,
            os_version=request.os_version,
            app_version=request.app_version
        )

        return DeviceTokenResponse(**token.to_dict())


@router.delete(
    "/device-tokens/{token}",
    response_model=MessageResponse,
    summary="Unregister device token",
    description="Unregister a device token (on logout or uninstall)"
)
async def unregister_device_token(
    token: str = Path(..., description="Device token to unregister"),
    current_user: User = Depends(get_current_user)
):
    """Unregister device token."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        success = await service.unregister_device_token(
            user_id=str(current_user.id),
            token=token
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device token not found"
            )

        return MessageResponse(message="Device token unregistered")


# ==============================================================================
# NOTIFICATION PREFERENCES - MUST COME BEFORE /{notification_id}
# ==============================================================================

@router.get(
    "/preferences",
    response_model=NotificationPreferencesResponse,
    summary="Get notification preferences",
    description="Get notification preferences for the current user"
)
async def get_preferences(
    current_user: User = Depends(get_current_user)
):
    """Get user notification preferences."""
    from core.database import AsyncSessionLocal

    default_prefs = {
        "system_enabled": True,
        "video_new_enabled": True,
        "live_start_enabled": True,
        "achievement_enabled": True,
        "subscription_enabled": True,
        "social_enabled": True,
        "promo_enabled": False,
        "push_enabled": True,
        "push_system": True,
        "push_video_new": True,
        "push_live_start": True,
        "push_achievement": True,
        "push_subscription": True,
        "push_social": False,
        "push_promo": False,
        "quiet_hours_enabled": False,
        "quiet_hours_start": "22:00",
        "quiet_hours_end": "08:00"
    }

    try:
        async with AsyncSessionLocal() as db:
            service = NotificationService(db)
            preferences = await service.get_user_preferences(str(current_user.id))

            if not preferences:
                return default_prefs

            return preferences.to_dict()
    except Exception:
        return default_prefs


@router.patch(
    "/preferences",
    response_model=NotificationPreferencesResponse,
    summary="Update notification preferences",
    description="Update notification preferences for the current user"
)
async def update_preferences(
    request: NotificationPreferencesUpdate,
    current_user: User = Depends(get_current_user)
):
    """Update user notification preferences."""
    import re
    from core.database import AsyncSessionLocal

    time_pattern = re.compile(r'^([01]?[0-9]|2[0-3]):[0-5][0-9]$')

    if request.quiet_hours_start is not None:
        if not time_pattern.match(request.quiet_hours_start):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="quiet_hours_start must be in HH:MM format (00:00-23:59)"
            )

    if request.quiet_hours_end is not None:
        if not time_pattern.match(request.quiet_hours_end):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="quiet_hours_end must be in HH:MM format (00:00-23:59)"
            )

    preferences_dict = {
        k: v for k, v in request.model_dump().items()
        if v is not None
    }

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        preferences = await service.update_user_preferences(
            user_id=str(current_user.id),
            preferences=preferences_dict
        )

        return NotificationPreferencesResponse(**preferences.to_dict())


# ==============================================================================
# ADMIN ENDPOINTS - MUST COME BEFORE /{notification_id}
# ==============================================================================

@router.post(
    "/admin/broadcast",
    response_model=MessageResponse,
    summary="Broadcast notification (Admin)",
    description="Send a notification to multiple users (admin only)"
)
async def broadcast_notification(
    request: BroadcastNotificationRequest,
    current_user: User = Depends(get_current_admin_user)
):
    """Broadcast notification to multiple users (admin only)."""
    from core.database import AsyncSessionLocal

    try:
        notification_type = NotificationType(request.notification_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid notification type: {request.notification_type}"
        )

    priority = NotificationPriority.NORMAL
    if request.priority:
        try:
            priority = NotificationPriority(request.priority)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid priority: {request.priority}"
            )

    try:
        async with AsyncSessionLocal() as db:
            service = NotificationService(db)
            count = await service.create_bulk_notifications(
                user_ids=request.user_ids,
                notification_type=notification_type,
                title=request.title,
                body=request.body,
                priority=priority,
                image_url=request.image_url,
                action_type=request.action_type,
                action_payload=request.action_payload,
                send_push=request.send_push
            )

            return MessageResponse(message=f"Notification sent to {count} users")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to broadcast notification: {str(e)}"
        )


@router.get(
    "/admin/stats/{user_id}",
    summary="Get user notification stats (Admin)",
    description="Get notification statistics for a specific user (admin only)"
)
async def get_user_stats(
    user_id: str = Path(..., description="User UUID"),
    current_user: User = Depends(get_current_admin_user)
):
    """Get notification statistics for a user (admin only)."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        stats = await service.get_notification_stats(user_id)
        return stats


@router.post(
    "/admin/cleanup",
    response_model=MessageResponse,
    summary="Cleanup expired notifications (Admin)",
    description="Delete expired notifications and inactive device tokens (admin only)"
)
async def cleanup_notifications(
    current_user: User = Depends(get_current_admin_user)
):
    """Cleanup expired notifications and inactive tokens (admin only)."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)

        expired_count = await service.cleanup_expired_notifications()
        tokens_count = await service.cleanup_inactive_device_tokens()

        return MessageResponse(
            message=f"Cleaned up {expired_count} expired notifications and {tokens_count} inactive device tokens"
        )


# ==============================================================================
# PARAMETRIC PATHS - MUST COME LAST (catches /{notification_id})
# ==============================================================================

@router.get(
    "/{notification_id}",
    response_model=NotificationResponse,
    summary="Get notification detail",
    description="Get a specific notification by ID"
)
async def get_notification(
    notification_id: str = Path(..., description="Notification UUID"),
    current_user: User = Depends(get_current_user)
):
    """Get specific notification detail."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        notification = await service.get_notification(
            notification_id=notification_id,
            user_id=str(current_user.id)
        )

        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )

        return NotificationResponse(**notification.to_dict())


@router.patch(
    "/{notification_id}/read",
    response_model=MessageResponse,
    summary="Mark notification as read",
    description="Mark a specific notification as read"
)
async def mark_as_read(
    notification_id: str = Path(..., description="Notification UUID"),
    current_user: User = Depends(get_current_user)
):
    """Mark notification as read."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        success = await service.mark_as_read(
            notification_id=notification_id,
            user_id=str(current_user.id)
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )

        return MessageResponse(message="Notification marked as read")


@router.delete(
    "/{notification_id}",
    response_model=MessageResponse,
    summary="Delete notification",
    description="Delete a specific notification"
)
async def delete_notification(
    notification_id: str = Path(..., description="Notification UUID"),
    current_user: User = Depends(get_current_user)
):
    """Delete a notification."""
    from core.database import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        service = NotificationService(db)
        success = await service.delete_notification(
            notification_id=notification_id,
            user_id=str(current_user.id)
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )

        return MessageResponse(message="Notification deleted")

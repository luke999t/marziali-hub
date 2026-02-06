"""LIVE STREAMING API ROUTER"""
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from datetime import datetime
from typing import List
import secrets

from core.database import get_db
from core.security import get_current_user, get_current_admin_user
from models.user import User
from models.video import LiveEvent
from api.v1.schemas import LiveEventCreateRequest, LiveEventResponse, MessageResponse

router = APIRouter()


@router.get("/sessions")
async def get_live_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    🎓 AI_MODULE: Live Sessions List
    🎓 AI_DESCRIPTION: Ritorna lista sessioni live attive e programmate
    🎓 AI_BUSINESS: Utenti vedono lezioni live disponibili
    🎓 AI_TEACHING: Query con filtro stato attivo + count aggregato
    """
    # Sessioni attualmente live
    active_result = await db.execute(
        select(func.count()).select_from(LiveEvent).where(LiveEvent.is_active == True)
    )
    active_now = active_result.scalar() or 0

    # Tutte le sessioni (attive + programmate future)
    sessions_result = await db.execute(
        select(LiveEvent)
        .where(
            and_(
                LiveEvent.is_active == True
            )
        )
        .order_by(LiveEvent.scheduled_start.desc())
        .limit(20)
    )
    sessions = sessions_result.scalars().all()

    # Conta totale eventi
    total_result = await db.execute(
        select(func.count()).select_from(LiveEvent)
    )
    total = total_result.scalar() or 0

    sessions_data = [
        {
            "id": str(s.id),
            "title": s.title,
            "is_active": s.is_active,
            "scheduled_start": s.scheduled_start.isoformat() if s.scheduled_start else None,
            "current_viewers": s.current_viewers,
        }
        for s in sessions
    ]

    return {
        "sessions": sessions_data,
        "total": total,
        "active_now": active_now,
        "active_sessions": active_now
    }


@router.post("/events", response_model=LiveEventResponse)
async def create_live_event(
    data: LiveEventCreateRequest,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Create a new live event.

    Admin only endpoint.
    """
    # Generate unique stream key
    stream_key = secrets.token_urlsafe(32)

    # RTMP URL (in production configurare con nginx-rtmp o MediaMTX)
    rtmp_url = f"rtmp://localhost:1935/live/{stream_key}"

    # Create event
    event = LiveEvent(
        title=data.title,
        description=data.description,
        stream_key=stream_key,
        rtmp_url=rtmp_url,
        scheduled_start=data.scheduled_start,
        scheduled_end=data.scheduled_end,
        tier_required=data.tier_required,
        max_viewers=data.max_viewers,
        recording_enabled=data.recording_enabled,
        instructor_id=admin.id
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)

    return LiveEventResponse.model_validate(event)


@router.get("/events", response_model=List[LiveEventResponse])
async def list_live_events(
    active_only: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    List live events.

    Filter by active if needed.
    """
    query = select(LiveEvent)

    if active_only:
        query = query.where(LiveEvent.is_active == True)

    query = query.order_by(LiveEvent.scheduled_start.desc())

    result = await db.execute(query)
    events = result.scalars().all()

    return [LiveEventResponse.model_validate(e) for e in events]


@router.get("/events/{event_id}", response_model=LiveEventResponse)
async def get_live_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get live event details."""
    result = await db.execute(
        select(LiveEvent).where(LiveEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Live event not found")

    # Check tier access
    from models.user import UserTier
    user_tier_order = ["free", "hybrid_light", "hybrid_standard", "premium", "business"]

    if user_tier_order.index(current_user.tier.value) < user_tier_order.index(event.tier_required):
        raise HTTPException(status_code=403, detail="Insufficient tier")

    return LiveEventResponse.model_validate(event)


@router.post("/events/{event_id}/start", response_model=MessageResponse)
async def start_live_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Start live event.

    Admin only.
    """
    result = await db.execute(
        select(LiveEvent).where(LiveEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Live event not found")

    if event.is_active:
        raise HTTPException(status_code=400, detail="Event already active")

    # Start event
    event.is_active = True
    event.started_at = datetime.utcnow()

    # Generate HLS URL (in production nginx-rtmp trasforma RTMP -> HLS)
    event.hls_url = f"https://cdn.example.com/live/{event.stream_key}/index.m3u8"

    await db.commit()

    return MessageResponse(message="Live event started!", success=True)


@router.post("/events/{event_id}/stop", response_model=MessageResponse)
async def stop_live_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """
    Stop live event.

    Admin only.
    """
    result = await db.execute(
        select(LiveEvent).where(LiveEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Live event not found")

    if not event.is_active:
        raise HTTPException(status_code=400, detail="Event not active")

    # Stop event
    event.is_active = False
    event.ended_at = datetime.utcnow()

    await db.commit()

    return MessageResponse(message="Live event stopped!", success=True)


@router.delete("/events/{event_id}", response_model=MessageResponse)
async def delete_live_event(
    event_id: str,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin_user)
):
    """Delete live event (admin only)."""
    result = await db.execute(
        select(LiveEvent).where(LiveEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if not event:
        raise HTTPException(status_code=404, detail="Live event not found")

    if event.is_active:
        raise HTTPException(status_code=400, detail="Cannot delete active event")

    await db.delete(event)
    await db.commit()

    return MessageResponse(message="Event deleted", success=True)


# === WEBSOCKET FOR LIVE VIEWERS COUNT ===

class LiveConnectionManager:
    """Manage WebSocket connections for live viewers."""

    def __init__(self):
        self.active_connections: dict[str, List[WebSocket]] = {}

    async def connect(self, event_id: str, websocket: WebSocket):
        await websocket.accept()
        if event_id not in self.active_connections:
            self.active_connections[event_id] = []
        self.active_connections[event_id].append(websocket)

    def disconnect(self, event_id: str, websocket: WebSocket):
        if event_id in self.active_connections:
            self.active_connections[event_id].remove(websocket)

    async def broadcast(self, event_id: str, message: dict):
        if event_id in self.active_connections:
            for connection in self.active_connections[event_id]:
                await connection.send_json(message)

    def get_viewer_count(self, event_id: str) -> int:
        return len(self.active_connections.get(event_id, []))


manager = LiveConnectionManager()


@router.websocket("/events/{event_id}/ws")
async def live_websocket(
    event_id: str,
    websocket: WebSocket,
    db: AsyncSession = Depends(get_db)
):
    """
    WebSocket endpoint for live event viewers.

    Updates viewer count in real-time.
    """
    await manager.connect(event_id, websocket)

    # Update viewer count in DB
    result = await db.execute(
        select(LiveEvent).where(LiveEvent.id == event_id)
    )
    event = result.scalar_one_or_none()

    if event:
        viewer_count = manager.get_viewer_count(event_id)
        event.current_viewers = viewer_count

        if viewer_count > event.peak_viewers:
            event.peak_viewers = viewer_count

        await db.commit()

        # Broadcast viewer count
        await manager.broadcast(event_id, {
            "type": "viewer_count",
            "count": viewer_count
        })

    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()

            # Echo back (can add chat functionality here)
            await websocket.send_json({
                "type": "ping",
                "message": "pong"
            })

    except WebSocketDisconnect:
        manager.disconnect(event_id, websocket)

        # Update viewer count
        if event:
            viewer_count = manager.get_viewer_count(event_id)
            event.current_viewers = viewer_count
            await db.commit()

            await manager.broadcast(event_id, {
                "type": "viewer_count",
                "count": viewer_count
            })

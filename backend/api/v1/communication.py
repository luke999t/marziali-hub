"""
🎓 AI_MODULE: Communication API
🎓 AI_DESCRIPTION: Messages, correction requests, real-time chat endpoints
🎓 AI_BUSINESS: Enable student-maestro communication + video correction workflow
🎓 AI_TEACHING: REST API + WebSocket for real-time + CRUD operations

📄 ALTERNATIVE_VALUTATE:
- GraphQL: Più complesso, overkill per questo use case
- gRPC: Migliore performance ma no browser support nativo
- REST + WebSocket: Best trade-off semplicità/performance

💡 PERCHÉ_QUESTA_SOLUZIONE:
- REST per CRUD: Standard, facile da usare
- WebSocket per real-time: Low latency per chat live
- Paginazione built-in: Scalabile per migliaia di messaggi
- Rate limiting: Previene spam

🔧 DEPENDENCIES:
- fastapi: Web framework
- sqlalchemy: ORM (2.x async)
- pydantic: Validation

⚠️ LIMITAZIONI_NOTE:
- WebSocket disconnection: Client deve reconnect
- Max message size: 10MB (file attachments)
- Rate limit: 100 msg/min per user

🎯 METRICHE_SUCCESSO:
- Message delivery: <100ms
- WebSocket latency: <50ms
- Uptime: >99.9%

🔄 FIX 2025-01-11:
- Convertito da SQLAlchemy 1.x sync (.query()) a SQLAlchemy 2.x async (select())
- Tutte le funzioni ora sono async con await db.execute()
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, or_, and_
from typing import List, Optional
from datetime import datetime
import uuid
import logging
import json

from core.database import get_db
from core.security import get_current_user
from models.user import User
from models.communication import (
    Message,
    MessageAttachmentType,
    CorrectionRequest,
    CorrectionRequestStatus
)
from pydantic import BaseModel, Field, validator

logger = logging.getLogger(__name__)

router = APIRouter(tags=["communication"])


# === SCHEMAS ===

class MessageCreate(BaseModel):
    """Schema for creating a message"""
    to_user_id: uuid.UUID
    content: str = Field(..., min_length=1, max_length=5000)
    attachment_type: Optional[MessageAttachmentType] = None
    attachment_url: Optional[str] = None
    attachment_metadata: Optional[dict] = None

    @validator('content')
    def content_not_empty(cls, v):
        if not v or not v.strip():
            raise ValueError('Content cannot be empty')
        return v.strip()


class MessageResponse(BaseModel):
    """Schema for message response"""
    id: uuid.UUID
    from_user_id: uuid.UUID
    to_user_id: uuid.UUID
    content: str
    attachment_type: Optional[MessageAttachmentType]
    attachment_url: Optional[str]
    is_read: bool
    read_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class MessageListResponse(BaseModel):
    """Paginated messages response"""
    messages: List[MessageResponse]
    total: int
    page: int
    page_size: int
    has_more: bool


class CorrectionRequestCreate(BaseModel):
    """Schema for creating correction request"""
    maestro_id: uuid.UUID
    video_url: str = Field(..., min_length=1)
    video_duration: Optional[float] = None
    notes: Optional[str] = Field(None, max_length=2000)

    @validator('video_duration')
    def duration_positive(cls, v):
        if v is not None and v <= 0:
            raise ValueError('Video duration must be positive')
        return v


class CorrectionRequestUpdate(BaseModel):
    """Schema for updating correction request (maestro response)"""
    status: CorrectionRequestStatus
    feedback_text: Optional[str] = Field(None, max_length=5000)
    feedback_video_url: Optional[str] = None
    feedback_audio_url: Optional[str] = None
    feedback_annotations: Optional[List[dict]] = None


class CorrectionRequestResponse(BaseModel):
    """Schema for correction request response"""
    id: uuid.UUID
    student_id: uuid.UUID
    maestro_id: uuid.UUID
    video_url: str
    video_duration_seconds: Optional[int] = None
    status: CorrectionRequestStatus
    feedback_text: Optional[str]
    feedback_video_url: Optional[str]
    feedback_audio_url: Optional[str]
    feedback_annotations: Optional[List[dict]]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# === ENDPOINTS - MESSAGES ===

@router.post("/messages", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    message_data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Send a message to another user

    **Rate Limit**: 100 messages/minute per user
    **Max size**: 10MB for attachments
    """
    # Verify recipient exists - SQLAlchemy 2.x async
    result = await db.execute(
        select(User).where(User.id == message_data.to_user_id)
    )
    recipient = result.scalar_one_or_none()
    
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient user not found")

    # Cannot message yourself
    if message_data.to_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot send message to yourself")

    # Create message
    message = Message(
        from_user_id=current_user.id,
        to_user_id=message_data.to_user_id,
        content=message_data.content,
        attachment_type=message_data.attachment_type,
        attachment_url=message_data.attachment_url,
        attachment_metadata=message_data.attachment_metadata
    )

    db.add(message)
    await db.commit()
    await db.refresh(message)

    logger.info(f"Message sent: {current_user.id} -> {message_data.to_user_id}")

    return message


@router.get("/messages", response_model=MessageListResponse)
async def list_messages(
    conversation_with: Optional[uuid.UUID] = Query(None, description="Filter by conversation partner"),
    unread_only: bool = Query(False, description="Show only unread messages"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List messages for current user

    **Filters**:
    - `conversation_with`: Show conversation with specific user
    - `unread_only`: Show only unread messages
    - Pagination: page, page_size
    """
    # Build base query conditions
    if conversation_with:
        base_condition = or_(
            and_(Message.from_user_id == current_user.id, Message.to_user_id == conversation_with),
            and_(Message.from_user_id == conversation_with, Message.to_user_id == current_user.id)
        )
    else:
        base_condition = or_(
            Message.from_user_id == current_user.id,
            Message.to_user_id == current_user.id
        )

    # Add unread filter if needed
    if unread_only:
        base_condition = and_(
            base_condition,
            Message.to_user_id == current_user.id,
            Message.is_read == False
        )

    # Count total - SQLAlchemy 2.x
    count_result = await db.execute(
        select(func.count()).select_from(Message).where(base_condition)
    )
    total = count_result.scalar() or 0

    # Get paginated messages
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Message)
        .where(base_condition)
        .order_by(Message.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    messages = result.scalars().all()

    has_more = (offset + len(messages)) < total

    return MessageListResponse(
        messages=messages,
        total=total,
        page=page,
        page_size=page_size,
        has_more=has_more
    )


@router.patch("/messages/{message_id}/read", response_model=MessageResponse)
async def mark_message_read(
    message_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Mark message as read

    **Authorization**: Only recipient can mark message as read
    """
    result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Only recipient can mark as read
    if message.to_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to mark this message as read")

    # Mark as read
    message.mark_as_read()
    await db.commit()
    await db.refresh(message)

    logger.info(f"Message {message_id} marked as read by {current_user.id}")

    return message


@router.get("/messages/unread/count")
async def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get count of unread messages"""
    result = await db.execute(
        select(func.count()).select_from(Message).where(
            and_(
                Message.to_user_id == current_user.id,
                Message.is_read == False
            )
        )
    )
    count = result.scalar() or 0

    return {"unread_count": count}


@router.delete("/messages/{message_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_message(
    message_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a message

    **Authorization**: Only sender can delete message
    """
    result = await db.execute(
        select(Message).where(Message.id == message_id)
    )
    message = result.scalar_one_or_none()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Only sender can delete
    if message.from_user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this message")

    await db.delete(message)
    await db.commit()

    logger.info(f"Message {message_id} deleted by {current_user.id}")

    return None


# === ENDPOINTS - CORRECTION REQUESTS ===

@router.post("/corrections", response_model=CorrectionRequestResponse, status_code=status.HTTP_201_CREATED)
async def create_correction_request(
    request_data: CorrectionRequestCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a correction request for a video

    **Workflow**:
    1. Student uploads video
    2. Student creates correction request → maestro
    3. Maestro reviews video
    4. Maestro provides feedback (text, video, audio, annotations)
    5. Student receives feedback
    """
    # Verify maestro exists and get Maestro record
    from models.maestro import Maestro
    
    result = await db.execute(
        select(Maestro).where(Maestro.id == request_data.maestro_id)
    )
    maestro = result.scalar_one_or_none()
    
    if not maestro:
        raise HTTPException(status_code=404, detail="Maestro not found")

    # Create request
    correction_request = CorrectionRequest(
        student_id=current_user.id,
        maestro_id=maestro.id,
        video_url=request_data.video_url,
        video_duration_seconds=int(request_data.video_duration) if request_data.video_duration else None,
        message=request_data.notes
    )

    db.add(correction_request)
    await db.commit()
    await db.refresh(correction_request)

    logger.info(f"Correction request created: student={current_user.id}, maestro={request_data.maestro_id}")

    return correction_request


@router.get("/corrections", response_model=List[CorrectionRequestResponse])
async def list_correction_requests(
    role: Optional[str] = Query(None, pattern="^(student|maestro)$", description="Filter by role (student or maestro)"),
    status_filter: Optional[CorrectionRequestStatus] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List correction requests

    **Filters**:
    - `role=student`: Show requests I created
    - `role=maestro`: Show requests assigned to me
    - `status`: Filter by status
    """
    from models.maestro import Maestro
    
    # Build query based on role
    if role == "student":
        base_condition = CorrectionRequest.student_id == current_user.id
    elif role == "maestro":
        # Get current user's maestro record
        maestro_result = await db.execute(
            select(Maestro).where(Maestro.user_id == current_user.id)
        )
        maestro = maestro_result.scalar_one_or_none()
        
        if not maestro:
            return []
        base_condition = CorrectionRequest.maestro_id == maestro.id
    else:
        # Show all requests involving user (as student or maestro)
        maestro_result = await db.execute(
            select(Maestro).where(Maestro.user_id == current_user.id)
        )
        maestro = maestro_result.scalar_one_or_none()
        
        if maestro:
            base_condition = or_(
                CorrectionRequest.student_id == current_user.id,
                CorrectionRequest.maestro_id == maestro.id
            )
        else:
            base_condition = CorrectionRequest.student_id == current_user.id

    # Add status filter if provided
    if status_filter:
        base_condition = and_(base_condition, CorrectionRequest.status == status_filter)

    result = await db.execute(
        select(CorrectionRequest)
        .where(base_condition)
        .order_by(CorrectionRequest.created_at.desc())
    )
    requests = result.scalars().all()

    return list(requests)


@router.get("/corrections/{request_id}", response_model=CorrectionRequestResponse)
async def get_correction_request(
    request_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get correction request by ID"""
    from models.maestro import Maestro
    
    result = await db.execute(
        select(CorrectionRequest).where(CorrectionRequest.id == request_id)
    )
    request = result.scalar_one_or_none()

    if not request:
        raise HTTPException(status_code=404, detail="Correction request not found")

    # Authorization: student or maestro involved
    is_student = request.student_id == current_user.id
    
    maestro_result = await db.execute(
        select(Maestro).where(Maestro.user_id == current_user.id)
    )
    maestro = maestro_result.scalar_one_or_none()
    is_maestro = maestro and request.maestro_id == maestro.id

    if not is_student and not is_maestro:
        raise HTTPException(status_code=403, detail="Not authorized to view this request")

    return request


@router.patch("/corrections/{request_id}", response_model=CorrectionRequestResponse)
async def update_correction_request(
    request_id: uuid.UUID,
    update_data: CorrectionRequestUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update correction request (maestro provides feedback)

    **Authorization**: Only assigned maestro can update
    """
    from models.maestro import Maestro
    
    result = await db.execute(
        select(CorrectionRequest).where(CorrectionRequest.id == request_id)
    )
    request = result.scalar_one_or_none()

    if not request:
        raise HTTPException(status_code=404, detail="Correction request not found")

    # Get current user's maestro record
    maestro_result = await db.execute(
        select(Maestro).where(Maestro.user_id == current_user.id)
    )
    maestro = maestro_result.scalar_one_or_none()
    
    if not maestro:
        raise HTTPException(status_code=403, detail="Only maestros can update correction requests")

    # Only assigned maestro can update
    if request.maestro_id != maestro.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this request")

    # Update fields
    request.status = update_data.status
    if update_data.feedback_text is not None:
        request.feedback_text = update_data.feedback_text
    if update_data.feedback_video_url is not None:
        request.feedback_video_url = update_data.feedback_video_url
    if update_data.feedback_audio_url is not None:
        request.feedback_audio_url = update_data.feedback_audio_url
    if update_data.feedback_annotations is not None:
        request.feedback_annotations = update_data.feedback_annotations

    # Update timestamps based on status
    if update_data.status == CorrectionRequestStatus.IN_PROGRESS and not request.started_at:
        request.started_at = datetime.utcnow()
    elif update_data.status == CorrectionRequestStatus.COMPLETED and not request.completed_at:
        request.completed_at = datetime.utcnow()

    await db.commit()
    await db.refresh(request)

    logger.info(f"Correction request {request_id} updated by maestro {current_user.id}")

    return request


# === WEBSOCKET - REAL-TIME CHAT ===

class ConnectionManager:
    """Manage WebSocket connections for real-time chat"""

    def __init__(self):
        self.active_connections: dict[uuid.UUID, WebSocket] = {}

    async def connect(self, user_id: uuid.UUID, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        logger.info(f"WebSocket connected: user={user_id}")

    def disconnect(self, user_id: uuid.UUID):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
            logger.info(f"WebSocket disconnected: user={user_id}")

    async def send_personal_message(self, message: dict, user_id: uuid.UUID):
        if user_id in self.active_connections:
            try:
                await self.active_connections[user_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send message to {user_id}: {e}")
                self.disconnect(user_id)


manager = ConnectionManager()


@router.websocket("/ws/chat/{user_id}")
async def websocket_chat_endpoint(
    websocket: WebSocket,
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db)
):
    """
    WebSocket endpoint for real-time chat

    **Protocol**:
    - Client sends: {"to_user_id": "...", "content": "..."}
    - Server sends: {"from_user_id": "...", "content": "...", "timestamp": "..."}
    """
    await manager.connect(user_id, websocket)

    try:
        while True:
            # Receive message
            data = await websocket.receive_json()

            to_user_id = uuid.UUID(data.get("to_user_id"))
            content = data.get("content", "").strip()

            if not content:
                continue

            # Save to database
            message = Message(
                from_user_id=user_id,
                to_user_id=to_user_id,
                content=content
            )
            db.add(message)
            await db.commit()

            # Send to recipient (if online)
            await manager.send_personal_message(
                {
                    "type": "new_message",
                    "from_user_id": str(user_id),
                    "content": content,
                    "timestamp": message.created_at.isoformat()
                },
                to_user_id
            )

            # Confirm to sender
            await websocket.send_json({
                "type": "message_sent",
                "message_id": str(message.id),
                "timestamp": message.created_at.isoformat()
            })

    except WebSocketDisconnect:
        manager.disconnect(user_id)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        manager.disconnect(user_id)

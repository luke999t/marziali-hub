"""
================================================================================
    GDPR Router - User Data Rights Management
================================================================================

AI_MODULE: GDPRRouter
AI_DESCRIPTION: Endpoints per gestione diritti GDPR utenti eventi
AI_BUSINESS: Compliance GDPR obbligatoria per dati partecipanti eventi
AI_TEACHING: FastAPI router per data export, consent management, data deletion

ENDPOINTS:
- GET /me/gdpr-data: Esporta tutti i dati personali utente (Art. 15 GDPR)
- POST /me/consent: Aggiorna preferenze consenso (Art. 7 GDPR)
- DELETE /me/gdpr-data: Richiesta cancellazione dati (Art. 17 GDPR)

================================================================================
"""

from datetime import datetime
from typing import Optional, List
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core.database import get_db
from core.auth import get_current_user
from models import User
from modules.events.models import (
    EventSubscription, EventWaitingList, SubscriptionStatus
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/me", tags=["GDPR"])


# ======================== SCHEMAS ========================

class ConsentUpdate(BaseModel):
    """Schema per aggiornamento consensi."""
    gdpr_consent: Optional[bool] = Field(None, description="Consenso trattamento dati")
    marketing_consent: Optional[bool] = Field(None, description="Consenso marketing")


class ConsentResponse(BaseModel):
    """Schema risposta consensi."""
    gdpr_consent: bool
    gdpr_consent_at: Optional[datetime]
    marketing_consent: bool
    marketing_consent_at: Optional[datetime]


class SubscriptionExport(BaseModel):
    """Schema export iscrizione."""
    id: str
    event_title: str
    option_name: str
    status: str
    amount_cents: int
    participant_name: Optional[str]
    participant_email: Optional[str]
    participant_phone: Optional[str]
    dietary_requirements: Optional[str]
    notes: Optional[str]
    gdpr_consent: bool
    gdpr_consent_at: Optional[datetime]
    marketing_consent: bool
    marketing_consent_at: Optional[datetime]
    created_at: datetime
    confirmed_at: Optional[datetime]

    class Config:
        from_attributes = True


class WaitingListExport(BaseModel):
    """Schema export waiting list."""
    id: str
    event_title: str
    is_active: bool
    notified_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class GDPRDataExport(BaseModel):
    """Schema export completo dati GDPR."""
    user: dict
    subscriptions: List[SubscriptionExport]
    waiting_list: List[WaitingListExport]
    exported_at: datetime


class DeletionRequest(BaseModel):
    """Schema richiesta cancellazione."""
    reason: Optional[str] = Field(None, description="Motivazione richiesta cancellazione")
    confirm: bool = Field(..., description="Conferma cancellazione")


class DeletionResponse(BaseModel):
    """Schema risposta cancellazione."""
    message: str
    anonymized_records: int
    deletion_scheduled: bool


# ======================== ENDPOINTS ========================

@router.get("/gdpr-data", response_model=GDPRDataExport)
async def export_gdpr_data(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Esporta tutti i dati personali dell'utente (Art. 15 GDPR).

    Restituisce:
    - Dati profilo utente
    - Tutte le iscrizioni eventi
    - Tutte le voci in waiting list
    """
    # Fetch subscriptions with event info
    subscriptions_query = (
        select(EventSubscription)
        .where(EventSubscription.user_id == current_user.id)
        .options(
            selectinload(EventSubscription.event),
            selectinload(EventSubscription.option)
        )
        .order_by(EventSubscription.created_at.desc())
    )
    result = await db.execute(subscriptions_query)
    subscriptions = result.scalars().all()

    # Fetch waiting list entries with event info
    waiting_query = (
        select(EventWaitingList)
        .where(EventWaitingList.user_id == current_user.id)
        .options(selectinload(EventWaitingList.event))
        .order_by(EventWaitingList.created_at.desc())
    )
    result = await db.execute(waiting_query)
    waiting_entries = result.scalars().all()

    # Build export
    subscriptions_export = [
        SubscriptionExport(
            id=str(sub.id),
            event_title=sub.event.title if sub.event else "N/A",
            option_name=sub.option.name if sub.option else "N/A",
            status=sub.status.value,
            amount_cents=sub.amount_cents,
            participant_name=sub.participant_name,
            participant_email=sub.participant_email,
            participant_phone=sub.participant_phone,
            dietary_requirements=sub.dietary_requirements,
            notes=sub.notes,
            gdpr_consent=sub.gdpr_consent,
            gdpr_consent_at=sub.gdpr_consent_at,
            marketing_consent=sub.marketing_consent,
            marketing_consent_at=sub.marketing_consent_at,
            created_at=sub.created_at,
            confirmed_at=sub.confirmed_at,
        )
        for sub in subscriptions
    ]

    waiting_export = [
        WaitingListExport(
            id=str(entry.id),
            event_title=entry.event.title if entry.event else "N/A",
            is_active=entry.is_active,
            notified_at=entry.notified_at,
            created_at=entry.created_at,
        )
        for entry in waiting_entries
    ]

    # User data export (safe fields only)
    user_data = {
        "id": str(current_user.id),
        "email": current_user.email,
        "first_name": getattr(current_user, 'first_name', None),
        "last_name": getattr(current_user, 'last_name', None),
        "created_at": str(current_user.created_at) if hasattr(current_user, 'created_at') else None,
    }

    logger.info(f"GDPR data export requested by user {current_user.id}")

    return GDPRDataExport(
        user=user_data,
        subscriptions=subscriptions_export,
        waiting_list=waiting_export,
        exported_at=datetime.utcnow()
    )


@router.post("/consent", response_model=ConsentResponse)
async def update_consent(
    consent: ConsentUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Aggiorna preferenze consenso utente (Art. 7 GDPR).

    Aggiorna il consenso su TUTTE le iscrizioni attive dell'utente.
    """
    now = datetime.utcnow()
    client_ip = request.client.host if request.client else None

    # Build update dict
    update_data = {}
    if consent.gdpr_consent is not None:
        update_data["gdpr_consent"] = consent.gdpr_consent
        update_data["gdpr_consent_at"] = now if consent.gdpr_consent else None
        update_data["gdpr_consent_ip"] = client_ip if consent.gdpr_consent else None

    if consent.marketing_consent is not None:
        update_data["marketing_consent"] = consent.marketing_consent
        update_data["marketing_consent_at"] = now if consent.marketing_consent else None

    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nessun consenso da aggiornare"
        )

    # Update all user subscriptions
    stmt = (
        update(EventSubscription)
        .where(EventSubscription.user_id == current_user.id)
        .where(EventSubscription.status.in_([
            SubscriptionStatus.PENDING,
            SubscriptionStatus.CONFIRMED
        ]))
        .values(**update_data)
    )
    await db.execute(stmt)
    await db.flush()

    # Get latest consent status from most recent subscription
    latest_query = (
        select(EventSubscription)
        .where(EventSubscription.user_id == current_user.id)
        .order_by(EventSubscription.created_at.desc())
        .limit(1)
    )
    result = await db.execute(latest_query)
    latest_sub = result.scalar_one_or_none()

    if latest_sub:
        response = ConsentResponse(
            gdpr_consent=latest_sub.gdpr_consent,
            gdpr_consent_at=latest_sub.gdpr_consent_at,
            marketing_consent=latest_sub.marketing_consent,
            marketing_consent_at=latest_sub.marketing_consent_at,
        )
    else:
        response = ConsentResponse(
            gdpr_consent=consent.gdpr_consent or False,
            gdpr_consent_at=now if consent.gdpr_consent else None,
            marketing_consent=consent.marketing_consent or False,
            marketing_consent_at=now if consent.marketing_consent else None,
        )

    logger.info(f"Consent updated for user {current_user.id}: gdpr={consent.gdpr_consent}, marketing={consent.marketing_consent}")

    return response


@router.delete("/gdpr-data", response_model=DeletionResponse)
async def request_data_deletion(
    deletion: DeletionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Richiesta cancellazione dati (Art. 17 GDPR - Diritto all'oblio).

    NOTA: Non cancella fisicamente i record per motivi fiscali/legali.
    Invece, anonimizza i dati personali:
    - participant_name → "GDPR_DELETED"
    - participant_email → null
    - participant_phone → null
    - dietary_requirements → null
    - notes → null
    - gdpr_consent → false
    - marketing_consent → false

    I record di pagamento sono mantenuti per obblighi fiscali (10 anni).
    """
    if not deletion.confirm:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Devi confermare la richiesta di cancellazione"
        )

    now = datetime.utcnow()

    # Anonymize subscriptions
    anonymize_data = {
        "participant_name": "GDPR_DELETED",
        "participant_email": None,
        "participant_phone": None,
        "dietary_requirements": None,
        "notes": None,
        "gdpr_consent": False,
        "gdpr_consent_at": None,
        "gdpr_consent_ip": None,
        "marketing_consent": False,
        "marketing_consent_at": None,
        "updated_at": now,
    }

    stmt = (
        update(EventSubscription)
        .where(EventSubscription.user_id == current_user.id)
        .values(**anonymize_data)
    )
    result = await db.execute(stmt)
    anonymized_count = result.rowcount

    # Deactivate waiting list entries
    stmt = (
        update(EventWaitingList)
        .where(EventWaitingList.user_id == current_user.id)
        .where(EventWaitingList.is_active == True)
        .values(is_active=False)
    )
    await db.execute(stmt)

    await db.commit()

    logger.warning(
        f"GDPR data deletion requested by user {current_user.id}. "
        f"Reason: {deletion.reason or 'Not specified'}. "
        f"Anonymized {anonymized_count} subscription records."
    )

    return DeletionResponse(
        message="I tuoi dati personali sono stati anonimizzati. "
                "I record di pagamento sono mantenuti per obblighi fiscali.",
        anonymized_records=anonymized_count,
        deletion_scheduled=False  # Immediate anonymization
    )


@router.get("/consent", response_model=ConsentResponse)
async def get_consent_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Ottiene lo stato attuale dei consensi utente.

    Restituisce i consensi dall'iscrizione più recente.
    """
    latest_query = (
        select(EventSubscription)
        .where(EventSubscription.user_id == current_user.id)
        .order_by(EventSubscription.created_at.desc())
        .limit(1)
    )
    result = await db.execute(latest_query)
    latest_sub = result.scalar_one_or_none()

    if latest_sub:
        return ConsentResponse(
            gdpr_consent=latest_sub.gdpr_consent,
            gdpr_consent_at=latest_sub.gdpr_consent_at,
            marketing_consent=latest_sub.marketing_consent,
            marketing_consent_at=latest_sub.marketing_consent_at,
        )

    # No subscriptions, return defaults
    return ConsentResponse(
        gdpr_consent=False,
        gdpr_consent_at=None,
        marketing_consent=False,
        marketing_consent_at=None,
    )

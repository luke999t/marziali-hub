"""
AI_MODULE: Royalty API Router
AI_DESCRIPTION: FastAPI endpoints per sistema royalties
AI_BUSINESS: API REST complete per gestione royalties, subscriptions, payouts
AI_TEACHING: FastAPI routing, dependency injection, OpenAPI docs, error handling

ALTERNATIVE_VALUTATE:
- GraphQL: Scartato, complessita non necessaria per questo caso
- gRPC: Scartato, non adatto per web frontend
- WebSocket: Scartato per CRUD ops, ok per real-time tracking

PERCHE_QUESTA_SOLUZIONE:
- REST: Standard, facile integrazione frontend
- FastAPI: Async native, OpenAPI auto-docs
- Dependency injection: Testabile, modulare
- Pydantic validation: Type-safe request/response

METRICHE_SUCCESSO:
- Response time p99: <200ms
- API coverage: 100% use cases
- Documentation: Auto-generated OpenAPI
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from uuid import UUID
import logging

from core.database import get_db
from core.security import get_current_user, get_current_admin_user, get_optional_user
from .config import get_royalty_config, RoyaltyConfig
from .service import RoyaltyService
from .schemas import (
    MasterProfileCreate,
    MasterProfileUpdate,
    MasterProfileResponse,
    StudentSubscriptionCreate,
    StudentSubscriptionResponse,
    TrackViewRequest,
    TrackViewResponse,
    RoyaltyPayoutResponse,
    RoyaltyDashboard,
    RoyaltyConfigResponse,
    RoyaltyConfigUpdate,
    PayoutRequestCreate,
    AvailableMasterResponse,
    BlockchainVerifyRequest,
    BlockchainVerifyResponse,
    RoyaltyStats
)

logger = logging.getLogger(__name__)

router = APIRouter()


# ======================== DEPENDENCIES ========================

def get_royalty_service(db: AsyncSession = Depends(get_db)) -> RoyaltyService:
    """Dependency injection per RoyaltyService."""
    return RoyaltyService(db)


def get_config() -> RoyaltyConfig:
    """Dependency injection per configurazione."""
    return get_royalty_config()


async def get_current_user_id(current_user = Depends(get_current_user)) -> UUID:
    """
    Estrae user ID dal token JWT usando sistema auth standard.
    
    🎓 AI_TEACHING: Usa get_current_user da core/security.py per consistenza
    con tutto il resto dell'applicazione.
    """
    return current_user.id


async def get_optional_user_id(current_user = Depends(get_optional_user)) -> Optional[UUID]:
    """
    Estrae user ID opzionale (per endpoint che funzionano anche senza auth).
    """
    if current_user:
        return current_user.id
    return None


async def require_user(current_user = Depends(get_current_user)) -> UUID:
    """
    Richiede utente autenticato.
    
    🎓 AI_TEACHING: Wrapper che restituisce solo l'ID invece dell'intero User object.
    """
    return current_user.id


async def require_admin(admin_user = Depends(get_current_admin_user)) -> UUID:
    """
    Richiede utente admin usando sistema JWT standard.
    
    🎓 AI_TEACHING: Usa get_current_admin_user da core/security.py
    che verifica is_admin nel database.
    """
    return admin_user.id


# ======================== ADMIN ENDPOINTS ========================

@router.get(
    "/admin/config",
    response_model=RoyaltyConfigResponse,
    tags=["admin"],
    summary="Get royalty configuration",
    description="Retrieve current royalty system configuration (admin only)"
)
async def get_royalty_configuration(
    admin_id: UUID = Depends(require_admin),
    config: RoyaltyConfig = Depends(get_config)
):
    """
    Ottiene configurazione royalties corrente.

    Accessibile solo agli admin.
    """
    return RoyaltyConfigResponse(
        student_master_mode=config.student_master_mode,
        max_masters_per_student=config.max_masters_per_student,
        master_switch_cooldown_days=config.master_switch_cooldown_days,
        subscription_types={
            k: v.model_dump() for k, v in config.subscription_types.items()
        },
        royalty_milestones=config.royalty_milestones.model_dump(),
        revenue_split=config.revenue_split.model_dump(),
        min_payout_cents=config.min_payout_cents,
        payout_frequency=config.payout_frequency,
        payout_processing_days=config.payout_processing_days,
        blockchain_enabled=config.blockchain.enabled,
        blockchain_network=config.blockchain.network,
        fraud_detection_enabled=config.fraud_detection_enabled,
        max_views_per_user_per_video_per_day=config.max_views_per_user_per_video_per_day
    )


@router.put(
    "/admin/config",
    response_model=RoyaltyConfigResponse,
    tags=["admin"],
    summary="Update royalty configuration",
    description="Update royalty system configuration (admin only)"
)
async def update_royalty_configuration(
    update_data: RoyaltyConfigUpdate,
    admin_id: UUID = Depends(require_admin)
):
    """
    Aggiorna configurazione royalties.

    TODO: Persist to database for hot reload.
    """
    # For now, just validate and return current config
    # In production, this would update database config
    logger.info(f"Config update requested by admin {admin_id}")
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Database config override not yet implemented"
    )


@router.get(
    "/admin/stats",
    response_model=RoyaltyStats,
    tags=["admin"],
    summary="Get global royalty statistics",
    description="Retrieve platform-wide royalty statistics (admin only)"
)
async def get_global_stats(
    days: int = Query(30, ge=1, le=365, description="Days to include"),
    admin_id: UUID = Depends(require_admin),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Ottiene statistiche globali royalties.

    Include:
    - Totale views e royalties
    - Fee piattaforma
    - Payout pendenti
    """
    stats = await service.get_global_stats(days=days)
    return stats


# ======================== MASTER ENDPOINTS ========================

@router.post(
    "/masters/profile",
    response_model=MasterProfileResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["masters"],
    summary="Create master royalty profile",
    description="Create a new master profile for royalty tracking"
)
async def create_master_profile(
    data: MasterProfileCreate,
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Crea profilo maestro per royalties.

    L'utente deve essere maestro verificato.
    """
    # Verify user is creating their own profile
    if data.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot create profile for another user"
        )

    try:
        profile = await service.create_master_profile(data)
        return MasterProfileResponse.model_validate(profile)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get(
    "/masters/{master_id}/dashboard",
    response_model=RoyaltyDashboard,
    tags=["masters"],
    summary="Get master royalty dashboard",
    description="Retrieve royalty dashboard for a master"
)
async def get_master_dashboard(
    master_id: UUID,
    days: int = Query(30, ge=1, le=365),
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Ottiene dashboard royalties per maestro.

    Include:
    - Statistiche periodo
    - Breakdown milestone
    - Trend giornaliero
    - Top video
    """
    # Verify ownership
    profile = await service.get_master_profile(profile_id=master_id)
    if not profile or profile.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    try:
        dashboard = await service.get_master_dashboard(master_id, days=days)
        return dashboard
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.get(
    "/masters/{master_id}/history",
    response_model=List[RoyaltyPayoutResponse],
    tags=["masters"],
    summary="Get master payout history",
    description="Retrieve payout history for a master"
)
async def get_master_payout_history(
    master_id: UUID,
    limit: int = Query(50, ge=1, le=200),
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """Ottiene storico payouts maestro."""
    # Verify ownership
    profile = await service.get_master_profile(profile_id=master_id)
    if not profile or profile.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    payouts = await service.get_master_payouts(master_id, limit=limit)
    return [RoyaltyPayoutResponse.model_validate(p) for p in payouts]


@router.put(
    "/masters/{master_id}/config",
    response_model=MasterProfileResponse,
    tags=["masters"],
    summary="Update master profile configuration",
    description="Update master's royalty configuration"
)
async def update_master_config(
    master_id: UUID,
    data: MasterProfileUpdate,
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Aggiorna configurazione profilo maestro.

    Permette override personalizzati per:
    - Pricing model
    - Royalty split
    - Milestone amounts
    - Payout settings
    """
    # Verify ownership
    profile = await service.get_master_profile(profile_id=master_id)
    if not profile or profile.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    updated = await service.update_master_profile(master_id, data)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found"
        )

    return MasterProfileResponse.model_validate(updated)


@router.post(
    "/masters/{master_id}/request-payout",
    response_model=RoyaltyPayoutResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["masters"],
    summary="Request royalty payout",
    description="Request a payout of accumulated royalties"
)
async def request_payout(
    master_id: UUID,
    request: Request,
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Richiede payout royalties accumulate.

    Requisiti:
    - Profilo verificato per payouts
    - Importo >= minimo configurato
    """
    # Verify ownership
    profile = await service.get_master_profile(profile_id=master_id)
    if not profile or profile.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    payout_request = PayoutRequestCreate(master_id=master_id)
    payout, message = await service.request_payout(payout_request)

    if not payout:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    return RoyaltyPayoutResponse.model_validate(payout)


# ======================== STUDENT ENDPOINTS ========================

@router.get(
    "/students/{student_id}/subscriptions",
    response_model=List[StudentSubscriptionResponse],
    tags=["students"],
    summary="Get student subscriptions",
    description="Retrieve all subscriptions for a student"
)
async def get_student_subscriptions(
    student_id: UUID,
    active_only: bool = Query(True),
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """Ottiene abbonamenti studente."""
    # Verify ownership
    if student_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    subscriptions = await service.get_student_subscriptions(
        student_id,
        active_only=active_only
    )
    return [StudentSubscriptionResponse.model_validate(s) for s in subscriptions]


@router.post(
    "/students/{student_id}/subscriptions",
    response_model=StudentSubscriptionResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["students"],
    summary="Create student subscription",
    description="Subscribe a student to a master or platform"
)
async def create_subscription(
    student_id: UUID,
    data: StudentSubscriptionCreate,
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service),
    config: RoyaltyConfig = Depends(get_config)
):
    """
    Crea abbonamento studente.

    Tipi:
    - PLATFORM: Abbonamento piattaforma
    - MASTER: Abbonamento maestro specifico
    - PER_VIDEO: Acquisto singolo video
    """
    # Verify ownership
    if student_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    # Override student_id from path
    data.student_id = student_id

    # Get price from config
    sub_config = config.subscription_types.get(data.subscription_tier)
    if not sub_config:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid subscription tier: {data.subscription_tier}"
        )

    price_cents = sub_config.price_cents

    try:
        subscription = await service.create_subscription(data, price_cents)
        return StudentSubscriptionResponse.model_validate(subscription)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.delete(
    "/students/{student_id}/subscriptions/{subscription_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["students"],
    summary="Cancel subscription",
    description="Cancel a student subscription"
)
async def cancel_subscription(
    student_id: UUID,
    subscription_id: UUID,
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """Cancella abbonamento."""
    # Verify ownership
    if student_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    success = await service.cancel_subscription(subscription_id, student_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Subscription not found or already cancelled"
        )


@router.get(
    "/students/{student_id}/available-masters",
    response_model=List[AvailableMasterResponse],
    tags=["students"],
    summary="Get available masters",
    description="Get list of masters available for subscription"
)
async def get_available_masters(
    student_id: UUID,
    discipline: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user_id: UUID = Depends(require_user),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """Ottiene maestri disponibili per subscription."""
    # Verify ownership
    if student_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    masters = await service.get_available_masters(
        student_id,
        discipline=discipline,
        limit=limit
    )
    return masters


# ======================== TRACKING ENDPOINTS ========================

@router.post(
    "/track-view",
    response_model=TrackViewResponse,
    tags=["tracking"],
    summary="Track video view milestone",
    description="Track a view milestone for royalty calculation"
)
async def track_view(
    data: TrackViewRequest,
    request: Request,
    user_id: Optional[UUID] = Depends(get_optional_user_id),
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Traccia milestone visualizzazione video.

    Chiamato dal video player quando utente raggiunge:
    - started: Video iniziato (>5s)
    - 25: Raggiunto 25%
    - 50: Raggiunto 50%
    - 75: Raggiunto 75%
    - completed: Video completato (>90%)
    """
    # Get master_id from video (TODO: lookup from videos table)
    # For now, expect it in header
    master_id_header = request.headers.get("X-Master-ID")
    if not master_id_header:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Master-ID header required"
        )

    try:
        master_id = UUID(master_id_header)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid X-Master-ID"
        )

    # Get client IP
    ip_address = request.client.host if request.client else None

    royalty, message = await service.track_view(
        request=data,
        student_id=user_id,
        master_id=master_id,
        ip_address=ip_address
    )

    return TrackViewResponse(
        success=royalty is not None,
        royalty_id=royalty.id if royalty else None,
        milestone=data.milestone,
        amount_cents=royalty.master_amount_cents if royalty else 0,
        message=message
    )


@router.get(
    "/verify/{view_id}",
    response_model=BlockchainVerifyResponse,
    tags=["tracking"],
    summary="Verify view on blockchain",
    description="Verify a tracked view exists on blockchain"
)
async def verify_view(
    view_id: UUID,
    service: RoyaltyService = Depends(get_royalty_service)
):
    """
    Verifica view su blockchain.

    Ritorna:
    - Proof Merkle
    - Transaction hash
    - IPFS hash metadata
    - Block number e conferme
    """
    # TODO: Implement verification logic
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Blockchain verification not yet implemented"
    )


# ======================== HEALTH ENDPOINT ========================

@router.get(
    "/health",
    tags=["system"],
    summary="Health check",
    description="Check royalty system health"
)
async def health_check(
    service: RoyaltyService = Depends(get_royalty_service)
):
    """Check salute sistema royalties."""
    blockchain_status = service.blockchain.get_status()

    return {
        "status": "healthy",
        "blockchain": blockchain_status,
        "config_loaded": True
    }

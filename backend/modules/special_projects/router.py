"""
AI_MODULE: Special Projects API Router
AI_DESCRIPTION: FastAPI endpoints per progetti speciali e votazioni
AI_BUSINESS: 15+ API endpoints, full CRUD + voting + analytics
AI_TEACHING: FastAPI router, dependency injection, permission decorators

ALTERNATIVE_VALUTATE:
- GraphQL: Scartato, overkill per use case semplice
- gRPC: Scartato, frontend web-based
- WebSocket voting: Scartato, HTTP sufficient for voting

PERCHE_QUESTA_SOLUZIONE:
- REST API: Standard, well-understood
- Dependency injection: Testable, clean
- Structured responses: Consistent error handling

METRICHE_SUCCESSO:
- Response time P99: <100ms
- API coverage: 100% use cases
- Error handling: Consistent format
"""

import logging
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from core.database import get_db
from core.security import get_current_user, get_current_admin_user as get_current_admin
from models import User

from .service import SpecialProjectsService
from .config import get_special_projects_config, clear_config_cache
from .schemas import (
    SpecialProjectCreate,
    SpecialProjectUpdate,
    SpecialProjectResponse,
    SpecialProjectListResponse,
    ProjectVoteCreate,
    ProjectVoteResponse,
    MyVoteResponse,
    EligibilityResponse,
    EligibilityCheckRequest,
    VotingStatsResponse,
    ConfigResponse,
    ConfigUpdateRequest,
    BulkConfigUpdateRequest,
    ProjectStatusEnum,
    EligibilityStatusEnum
)
from .models import ProjectStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/special-projects", tags=["Special Projects"])


# ======================== DEPENDENCIES ========================

async def get_service(db: AsyncSession = Depends(get_db)) -> SpecialProjectsService:
    """Dependency per ottenere service."""
    return SpecialProjectsService(db)


# ======================== PUBLIC ENDPOINTS ========================

@router.get(
    "",
    response_model=SpecialProjectListResponse,
    summary="Lista progetti speciali"
)
async def list_projects(
    status: Optional[ProjectStatusEnum] = Query(None, description="Filtra per status"),
    page: int = Query(1, ge=1, description="Pagina"),
    page_size: int = Query(20, ge=1, le=100, description="Elementi per pagina"),
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Lista progetti speciali pubblici.

    - Utenti vedono solo progetti attivi
    - Ordinati per weighted_votes decrescente
    - Paginazione standard
    """
    project_status = ProjectStatus(status.value) if status else None

    projects, total = await service.list_projects(
        status=project_status,
        include_drafts=False,
        page=page,
        page_size=page_size
    )

    total_pages = (total + page_size - 1) // page_size

    return SpecialProjectListResponse(
        projects=[SpecialProjectResponse.model_validate(p) for p in projects],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get(
    "/votable",
    response_model=list[SpecialProjectResponse],
    summary="Lista progetti votabili"
)
async def list_votable_projects(
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Lista progetti attualmente aperti al voto.

    Solo progetti ACTIVE con date votazione valide.
    """
    projects = await service.list_active_for_voting()
    return [SpecialProjectResponse.model_validate(p) for p in projects]


@router.get("/health", summary="Health check")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "module": "special_projects",
        "version": "1.0.0"
    }


# ======================== USER ENDPOINTS (authenticated) ========================
# NOTE: These specific routes MUST come BEFORE /{project_id} to avoid path matching issues

@router.get(
    "/my-eligibility",
    response_model=EligibilityResponse,
    summary="Verifica mia eligibilità voto"
)
async def check_my_eligibility(
    force_recalculate: bool = Query(False, description="Forza ricalcolo"),
    current_user: User = Depends(get_current_user),
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Verifica se utente corrente può votare.

    Ritorna:
    - Status eligibilità (eligible, not_eligible, pending)
    - Peso voto
    - Progress requisiti (per free users)
    """
    eligibility = await service.check_user_eligibility(
        current_user.id,
        force_recalculate=force_recalculate
    )

    return EligibilityResponse(
        user_id=eligibility.user_id,
        status=EligibilityStatusEnum(eligibility.status),
        vote_weight=eligibility.vote_weight,
        subscription_tier=eligibility.subscription_tier,
        can_vote=eligibility.is_eligible(),
        vote_cycle=eligibility.vote_cycle,
        watch_minutes_current=eligibility.watch_minutes_current or 0,
        watch_minutes_required=eligibility.watch_minutes_required,
        ads_watched_current=eligibility.ads_watched_current or 0,
        ads_watched_required=eligibility.ads_watched_required,
        videos_completed_current=eligibility.videos_completed_current or 0,
        videos_completed_required=eligibility.videos_completed_required,
        progress_percent=eligibility.progress_percent,
        ineligibility_reason=eligibility.ineligibility_reason
    )


@router.get(
    "/my-vote",
    response_model=MyVoteResponse,
    summary="Il mio voto corrente"
)
async def get_my_vote(
    current_user: User = Depends(get_current_user),
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Ottiene voto corrente dell'utente.

    Include:
    - Voto attuale (se esiste)
    - Possibilità di cambiare
    - Peso voto attuale
    """
    vote = await service.get_user_current_vote(current_user.id)
    eligibility = await service.check_user_eligibility(current_user.id)

    config = get_special_projects_config()

    vote_response = None
    if vote:
        project = await service.get_project(vote.project_id)
        vote_response = ProjectVoteResponse(
            id=vote.id,
            user_id=vote.user_id,
            project_id=vote.project_id,
            project_title=project.title if project else None,
            vote_weight=vote.vote_weight,
            subscription_tier_at_vote=vote.subscription_tier_at_vote,
            vote_cycle=vote.vote_cycle,
            is_active=vote.is_active,
            voted_at=vote.voted_at,
            changed_from_previous=vote.changed_from_previous,
            previous_project_id=vote.previous_project_id
        )

    return MyVoteResponse(
        has_voted=vote is not None,
        current_vote=vote_response,
        can_change=config.voting_rules.can_change_vote_same_cycle or (vote is None),
        vote_weight=eligibility.vote_weight,
        eligibility_status=EligibilityStatusEnum(eligibility.status)
    )


@router.get(
    "/my-history",
    response_model=list[ProjectVoteResponse],
    summary="Storico miei voti"
)
async def get_my_vote_history(
    limit: int = Query(12, ge=1, le=36, description="Numero cicli"),
    current_user: User = Depends(get_current_user),
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Storico voti utente negli ultimi N cicli.
    """
    votes = await service.get_user_vote_history(current_user.id, limit)

    results = []
    for vote in votes:
        project = await service.get_project(vote.project_id)
        results.append(ProjectVoteResponse(
            id=vote.id,
            user_id=vote.user_id,
            project_id=vote.project_id,
            project_title=project.title if project else None,
            vote_weight=vote.vote_weight,
            subscription_tier_at_vote=vote.subscription_tier_at_vote,
            vote_cycle=vote.vote_cycle,
            is_active=vote.is_active,
            voted_at=vote.voted_at,
            changed_from_previous=vote.changed_from_previous,
            previous_project_id=vote.previous_project_id
        ))

    return results


# ======================== PUBLIC ENDPOINTS (specific paths) ========================

@router.get(
    "/slug/{slug}",
    response_model=SpecialProjectResponse,
    summary="Dettaglio progetto per slug"
)
async def get_project_by_slug(
    slug: str,
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Ottiene progetto per URL slug.
    """
    project = await service.get_project_by_slug(slug)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return SpecialProjectResponse.model_validate(project)


# ======================== DYNAMIC PATH ENDPOINTS ========================
# NOTE: This generic route MUST come AFTER all specific routes to avoid conflicts

@router.get(
    "/{project_id}",
    response_model=SpecialProjectResponse,
    summary="Dettaglio progetto"
)
async def get_project(
    project_id: UUID,
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Ottiene dettaglio singolo progetto.
    """
    project = await service.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return SpecialProjectResponse.model_validate(project)


@router.post(
    "/{project_id}/vote",
    response_model=ProjectVoteResponse,
    summary="Vota per progetto"
)
async def vote_for_project(
    project_id: UUID,
    confirm_change: bool = Query(False, description="Conferma cambio voto"),
    current_user: User = Depends(get_current_user),
    service: SpecialProjectsService = Depends(get_service),
    db: AsyncSession = Depends(get_db)
):
    """
    Registra voto per progetto.

    Rules:
    - 1 voto per ciclo
    - Non può cambiare nello stesso mese (default)
    - Peso basato su subscription tier
    """
    vote_data = ProjectVoteCreate(
        project_id=project_id,
        confirm_change=confirm_change
    )

    vote, message = await service.vote(current_user.id, vote_data)

    if not vote:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

    await db.commit()

    project = await service.get_project(project_id)

    return ProjectVoteResponse(
        id=vote.id,
        user_id=vote.user_id,
        project_id=vote.project_id,
        project_title=project.title if project else None,
        vote_weight=vote.vote_weight,
        subscription_tier_at_vote=vote.subscription_tier_at_vote,
        vote_cycle=vote.vote_cycle,
        is_active=vote.is_active,
        voted_at=vote.voted_at,
        changed_from_previous=vote.changed_from_previous,
        previous_project_id=vote.previous_project_id
    )


# ======================== ADMIN ENDPOINTS ========================

@router.get("/admin/test-bypass")
async def test_bypass():
    """TEST: Endpoint senza auth per verificare routing"""
    return {"status": "ok", "message": "Routing funziona!"}


@router.post(
    "/admin/projects",
    response_model=SpecialProjectResponse,
    summary="Crea progetto (admin)",
    status_code=status.HTTP_201_CREATED
)
async def create_project(
    data: SpecialProjectCreate,
    current_admin: User = Depends(get_current_admin),
    service: SpecialProjectsService = Depends(get_service),
    db: AsyncSession = Depends(get_db)
):
    """
    Crea nuovo progetto speciale.

    Solo admin può creare progetti.
    """
    project = await service.create_project(data, current_admin.id)
    await db.commit()

    return SpecialProjectResponse.model_validate(project)


@router.put(
    "/admin/projects/{project_id}",
    response_model=SpecialProjectResponse,
    summary="Aggiorna progetto (admin)"
)
async def update_project(
    project_id: UUID,
    data: SpecialProjectUpdate,
    current_admin: User = Depends(get_current_admin),
    service: SpecialProjectsService = Depends(get_service),
    db: AsyncSession = Depends(get_db)
):
    """
    Aggiorna progetto esistente.

    Può cambiare status, contenuto, date votazione.
    """
    project = await service.update_project(project_id, data)

    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    await db.commit()

    return SpecialProjectResponse.model_validate(project)


@router.delete(
    "/admin/projects/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Elimina progetto (admin)"
)
async def delete_project(
    project_id: UUID,
    current_admin: User = Depends(get_current_admin),
    service: SpecialProjectsService = Depends(get_service),
    db: AsyncSession = Depends(get_db)
):
    """
    Soft delete progetto.
    """
    project = await service.get_project(project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )

    project.is_deleted = True
    from datetime import datetime
    project.deleted_at = datetime.utcnow()

    await db.commit()


@router.get(
    "/admin/config",
    response_model=ConfigResponse,
    summary="Ottieni configurazione (admin)"
)
async def get_config(
    current_admin: User = Depends(get_current_admin)
):
    """
    Ottiene configurazione corrente sistema votazione.
    """
    # DEBUG: Logging per diagnosticare 403
    print(f">>> DEBUG get_config chiamato!")
    print(f">>> current_admin = {current_admin}")
    print(f">>> type = {type(current_admin)}")
    print(f">>> is_admin = {getattr(current_admin, 'is_admin', 'NOT FOUND')}")

    config = get_special_projects_config()

    return ConfigResponse(
        vote_weights={
            "premium_full": config.vote_weights.premium_full,
            "premium_hybrid": config.vote_weights.premium_hybrid,
            "free_with_ads": config.vote_weights.free_with_ads,
            "free_no_ads": config.vote_weights.free_no_ads
        },
        free_user_requirements={
            "min_watch_minutes": config.free_user_requirements.min_watch_minutes,
            "min_ads_watched": config.free_user_requirements.min_ads_watched,
            "min_videos_completed": config.free_user_requirements.min_videos_completed,
            "lookback_days": config.free_user_requirements.lookback_days
        },
        voting_rules={
            "vote_cycle_type": config.voting_rules.vote_cycle_type,
            "votes_per_user_per_cycle": config.voting_rules.votes_per_user_per_cycle,
            "can_change_vote_same_cycle": config.voting_rules.can_change_vote_same_cycle,
            "vote_persists_next_cycle": config.voting_rules.vote_persists_next_cycle
        },
        project_settings={
            "min_description_length": config.project_min_description_length,
            "max_description_length": config.project_max_description_length,
            "require_image": config.require_project_image,
            "require_budget": config.require_project_budget
        }
    )


@router.put(
    "/admin/config",
    response_model=ConfigResponse,
    summary="Aggiorna configurazione (admin)"
)
async def update_config(
    data: ConfigUpdateRequest,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Aggiorna singola chiave configurazione.

    Salva in database per override runtime.
    """
    from .models import SpecialProjectsConfigDB
    from sqlalchemy import select
    from datetime import datetime

    # Get or create config entry
    result = await db.execute(
        select(SpecialProjectsConfigDB).where(
            SpecialProjectsConfigDB.config_key == data.config_key
        )
    )
    config_entry = result.scalar_one_or_none()

    if config_entry:
        config_entry.previous_value = config_entry.config_value
        config_entry.config_value = data.config_value
        config_entry.change_reason = data.change_reason
        config_entry.updated_by = current_admin.id
        config_entry.updated_at = datetime.utcnow()
    else:
        # Determine value type
        value_type = "string"
        if isinstance(data.config_value, bool):
            value_type = "bool"
        elif isinstance(data.config_value, int):
            value_type = "int"
        elif isinstance(data.config_value, float):
            value_type = "float"
        elif isinstance(data.config_value, (dict, list)):
            value_type = "json"

        config_entry = SpecialProjectsConfigDB(
            config_key=data.config_key,
            config_value=data.config_value,
            value_type=value_type,
            change_reason=data.change_reason,
            updated_by=current_admin.id
        )
        db.add(config_entry)

    await db.commit()

    # Clear cache to reload
    clear_config_cache()

    # Return updated config
    return await get_config(current_admin)


@router.get(
    "/admin/stats",
    response_model=VotingStatsResponse,
    summary="Statistiche votazione (admin)"
)
async def get_voting_stats(
    cycle: Optional[str] = Query(None, description="Ciclo (es: 2024-01)"),
    current_admin: User = Depends(get_current_admin),
    service: SpecialProjectsService = Depends(get_service)
):
    """
    Statistiche aggregate votazione.

    Include partecipazione, breakdown per tier, top projects.
    """
    stats = await service.get_voting_stats(cycle)

    return VotingStatsResponse(
        vote_cycle=stats["vote_cycle"],
        total_eligible_voters=stats["total_eligible_voters"],
        total_votes_cast=stats["total_votes_cast"],
        participation_rate=stats["participation_rate"],
        votes_by_tier=stats["votes_by_tier"],
        weighted_votes_by_tier=stats["weighted_votes_by_tier"],
        top_projects=stats["top_projects"],
        votes_per_day=[]  # TODO: implement time series
    )


@router.post(
    "/admin/close-cycle",
    summary="Chiudi ciclo votazione (admin)"
)
async def close_voting_cycle(
    cycle: Optional[str] = Query(None, description="Ciclo da chiudere"),
    current_admin: User = Depends(get_current_admin),
    service: SpecialProjectsService = Depends(get_service),
    db: AsyncSession = Depends(get_db)
):
    """
    Chiude ciclo votazione e determina vincitore.
    """
    results = await service.close_voting_cycle(cycle)
    await db.commit()

    return {
        "success": True,
        "cycle": results["vote_cycle"],
        "winner_project_id": results.get("winner_project_id"),
        "winner_title": results.get("winner_title"),
        "total_votes": results["total_votes_cast"],
        "total_weighted_votes": results.get("total_weighted_votes", 0)
    }

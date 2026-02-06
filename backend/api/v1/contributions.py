"""
# AI_MODULE: ContributionsAPI
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: API router per sistema gestione contributi staff con RBAC e workflow
# AI_BUSINESS: Espone via REST il sistema contributi staff con gestione membri,
#              contributi, workflow approvazione, audit log, e versioning.
# AI_TEACHING: Router FastAPI che usa ContributionManager come facade. Pattern RBAC
#              con permessi granulari. Audit log immutabile per compliance.
# AI_DEPENDENCIES: FastAPI, ContributionManager, pydantic
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

Contributions API Router
========================

Endpoints per sistema contributi staff:
- Gestione staff members con RBAC
- CRUD contributi con versioning automatico
- Workflow revisione (submit, approve, reject)
- Audit log per compliance
- Storico versioni con diff
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from enum import Enum
import logging

from core.security import get_current_user, get_current_admin_user
from models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()  # prefix gestito in main.py


# ==================== Pydantic Schemas ====================

class StaffRoleType(str, Enum):
    ADMIN = "admin"
    MODERATOR = "moderator"
    TRANSLATOR = "translator"
    REVIEWER = "reviewer"
    CONTRIBUTOR = "contributor"
    VIEWER = "viewer"


class ContributionTypeEnum(str, Enum):
    TRANSLATION = "translation"
    TRANSCRIPTION = "transcription"
    ANNOTATION = "annotation"
    CORRECTION = "correction"
    GLOSSARY = "glossary"
    SUBTITLE = "subtitle"
    VOICEOVER = "voiceover"
    KNOWLEDGE = "knowledge"
    TECHNIQUE = "technique"
    METADATA = "metadata"


class ContributionStatusType(str, Enum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    IN_REVIEW = "in_review"
    CHANGES_REQUESTED = "changes_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class ReviewDecisionType(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


# === Staff Member Schemas ===

class CreateStaffMemberRequest(BaseModel):
    """Request per creare membro staff."""
    user_id: str = Field(..., description="ID utente nel sistema principale")
    username: str = Field(..., min_length=2, max_length=50)
    email: EmailStr
    role: StaffRoleType = Field(default=StaffRoleType.CONTRIBUTOR)
    projects: Optional[List[str]] = Field(default=None, description="Progetti assegnati")


class UpdateStaffMemberRequest(BaseModel):
    """Request per aggiornare membro staff."""
    username: Optional[str] = Field(default=None, min_length=2, max_length=50)
    email: Optional[EmailStr] = None
    role: Optional[StaffRoleType] = None
    projects: Optional[List[str]] = None
    is_active: Optional[bool] = None


class StaffMemberResponse(BaseModel):
    """Response membro staff."""
    id: str
    user_id: str
    username: str
    email: str
    role: str
    permissions: List[str]
    projects: List[str]
    is_active: bool
    created_at: str
    updated_at: str
    created_by: Optional[str] = None


# === Contribution Schemas ===

class CreateContributionRequest(BaseModel):
    """Request per creare contributo."""
    title: str = Field(..., min_length=1, max_length=200)
    content_type: ContributionTypeEnum
    content: Dict[str, Any] = Field(..., description="Contenuto strutturato")
    project_id: Optional[str] = None
    tags: Optional[List[str]] = None


class UpdateContributionRequest(BaseModel):
    """Request per aggiornare contributo."""
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    content: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    change_summary: Optional[str] = Field(default=None, max_length=500)


class ContributionResponse(BaseModel):
    """Response contributo."""
    id: str
    contributor_id: str
    project_id: Optional[str] = None
    content_type: str
    status: str
    title: str
    content: Dict[str, Any]
    current_version: int
    created_at: str
    updated_at: str
    submitted_at: Optional[str] = None
    approved_at: Optional[str] = None
    published_at: Optional[str] = None
    reviewer_id: Optional[str] = None
    approver_id: Optional[str] = None
    tags: List[str]


# === Review Schemas ===

class SubmitForReviewRequest(BaseModel):
    """Request per sottomettere contributo per review."""
    priority: str = Field(default="normal", pattern="^(low|normal|high|urgent)$")
    notes: Optional[str] = Field(default=None, max_length=1000)


class ReviewDecisionRequest(BaseModel):
    """Request per decisione review."""
    decision: ReviewDecisionType
    notes: Optional[str] = Field(default=None, max_length=2000)
    requested_changes: Optional[List[str]] = None


class ReviewCommentRequest(BaseModel):
    """Request per aggiungere commento review."""
    content: str = Field(..., min_length=1, max_length=2000)
    line_number: Optional[int] = None
    field_path: Optional[str] = None


# === Audit & Version Schemas ===

class AuditEntryResponse(BaseModel):
    """Response entry audit."""
    id: str
    action: str
    actor_id: str
    target_type: str
    target_id: str
    project_id: Optional[str] = None
    timestamp: str
    details: Dict[str, Any]


class VersionDiffResponse(BaseModel):
    """Response diff tra versioni."""
    old_version: int
    new_version: int
    changes: List[Dict[str, Any]]
    added_fields: List[str]
    removed_fields: List[str]
    modified_fields: List[str]


class ContributionVersionResponse(BaseModel):
    """Response versione contributo."""
    version_number: int
    content: Dict[str, Any]
    created_by: str
    created_at: str
    change_summary: Optional[str] = None


# === Stats Schema ===

class ContributionStatsResponse(BaseModel):
    """Response statistiche sistema."""
    staff: Dict[str, Any]
    contributions: Dict[str, Any]
    versioning: Dict[str, Any]
    workflow: Dict[str, Any]


# ==================== Helper Functions ====================

async def get_contribution_manager():
    """Dependency per ottenere ContributionManager."""
    from services.staff_contribution import ContributionManager
    return await ContributionManager.get_instance()


async def get_staff_member_from_user(
    user: User,
    manager,
) -> Optional[Any]:
    """Ottiene StaffMember dal User corrente."""
    return await manager.get_staff_member_by_user_id(str(user.id))


# ==================== Staff Member Endpoints ====================

@router.post("/staff", response_model=StaffMemberResponse, summary="Crea membro staff")
async def create_staff_member(
    request: CreateStaffMemberRequest,
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_contribution_manager),
):
    """
    Crea un nuovo membro staff (solo admin).

    Ruoli disponibili:
    - **admin**: Accesso completo
    - **moderator**: Approva/rifiuta contributi
    - **translator**: Traduce contenuti
    - **reviewer**: Revisiona traduzioni
    - **contributor**: Contributi base
    - **viewer**: Solo lettura
    """
    try:
        from services.staff_contribution import StaffRole

        role_map = {
            StaffRoleType.ADMIN: StaffRole.ADMIN,
            StaffRoleType.MODERATOR: StaffRole.MODERATOR,
            StaffRoleType.TRANSLATOR: StaffRole.TRANSLATOR,
            StaffRoleType.REVIEWER: StaffRole.REVIEWER,
            StaffRoleType.CONTRIBUTOR: StaffRole.CONTRIBUTOR,
            StaffRoleType.VIEWER: StaffRole.VIEWER,
        }

        member = await manager.add_staff_member(
            user_id=request.user_id,
            username=request.username,
            email=request.email,
            role=role_map[request.role],
            created_by=str(current_user.id),
            projects=request.projects,
        )

        return StaffMemberResponse(
            id=member.id,
            user_id=member.user_id,
            username=member.username,
            email=member.email,
            role=member.role,
            permissions=member.permissions,
            projects=member.projects,
            is_active=member.is_active,
            created_at=member.created_at,
            updated_at=member.updated_at,
            created_by=member.created_by,
        )
    except Exception as e:
        logger.error(f"Create staff member error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/staff", summary="Lista membri staff")
async def list_staff_members(
    role: Optional[StaffRoleType] = None,
    is_active: bool = True,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Lista tutti i membri staff con filtri."""
    try:
        from services.staff_contribution import StaffRole

        role_param = None
        if role:
            role_map = {
                StaffRoleType.ADMIN: StaffRole.ADMIN,
                StaffRoleType.MODERATOR: StaffRole.MODERATOR,
                StaffRoleType.TRANSLATOR: StaffRole.TRANSLATOR,
                StaffRoleType.REVIEWER: StaffRole.REVIEWER,
                StaffRoleType.CONTRIBUTOR: StaffRole.CONTRIBUTOR,
                StaffRoleType.VIEWER: StaffRole.VIEWER,
            }
            role_param = role_map[role]

        members = await manager.list_staff(
            role=role_param,
            is_active=is_active,
            limit=limit,
            offset=offset,
        )

        return {
            "members": [
                {
                    "id": m.id,
                    "user_id": m.user_id,
                    "username": m.username,
                    "email": m.email,
                    "role": m.role,
                    "is_active": m.is_active,
                    "created_at": m.created_at,
                }
                for m in members
            ],
            "count": len(members),
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        logger.error(f"List staff error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/staff/{member_id}", response_model=StaffMemberResponse)
async def get_staff_member(
    member_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene dettagli membro staff."""
    member = await manager.get_staff_member(member_id)
    if not member:
        raise HTTPException(status_code=404, detail="Membro staff non trovato")

    return StaffMemberResponse(
        id=member.id,
        user_id=member.user_id,
        username=member.username,
        email=member.email,
        role=member.role,
        permissions=member.permissions,
        projects=member.projects,
        is_active=member.is_active,
        created_at=member.created_at,
        updated_at=member.updated_at,
        created_by=member.created_by,
    )


@router.put("/staff/{member_id}", response_model=StaffMemberResponse)
async def update_staff_member(
    member_id: str,
    request: UpdateStaffMemberRequest,
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_contribution_manager),
):
    """Aggiorna membro staff (solo admin)."""
    try:
        from services.staff_contribution import StaffRole

        updates = {}
        if request.username is not None:
            updates["username"] = request.username
        if request.email is not None:
            updates["email"] = request.email
        if request.role is not None:
            role_map = {
                StaffRoleType.ADMIN: StaffRole.ADMIN,
                StaffRoleType.MODERATOR: StaffRole.MODERATOR,
                StaffRoleType.TRANSLATOR: StaffRole.TRANSLATOR,
                StaffRoleType.REVIEWER: StaffRole.REVIEWER,
                StaffRoleType.CONTRIBUTOR: StaffRole.CONTRIBUTOR,
                StaffRoleType.VIEWER: StaffRole.VIEWER,
            }
            updates["role"] = role_map[request.role]
        if request.projects is not None:
            updates["projects"] = request.projects
        if request.is_active is not None:
            updates["is_active"] = request.is_active

        member = await manager.update_staff_member(
            member_id=member_id,
            actor_id=str(current_user.id),
            **updates,
        )

        if not member:
            raise HTTPException(status_code=404, detail="Membro staff non trovato")

        return StaffMemberResponse(
            id=member.id,
            user_id=member.user_id,
            username=member.username,
            email=member.email,
            role=member.role,
            permissions=member.permissions,
            projects=member.projects,
            is_active=member.is_active,
            created_at=member.created_at,
            updated_at=member.updated_at,
            created_by=member.created_by,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update staff error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/staff/me/profile", response_model=StaffMemberResponse)
async def get_my_staff_profile(
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene il proprio profilo staff."""
    member = await manager.get_staff_member_by_user_id(str(current_user.id))
    if not member:
        raise HTTPException(status_code=404, detail="Non sei un membro staff")

    return StaffMemberResponse(
        id=member.id,
        user_id=member.user_id,
        username=member.username,
        email=member.email,
        role=member.role,
        permissions=member.permissions,
        projects=member.projects,
        is_active=member.is_active,
        created_at=member.created_at,
        updated_at=member.updated_at,
        created_by=member.created_by,
    )


# ==================== Admin & My Contributions - MUST COME BEFORE /{contribution_id} ====================
# FIX 2025-01-27: Route ordering - path specifici PRIMA di path con parametri

@router.get("/admin/stats", response_model=ContributionStatsResponse, summary="Statistiche sistema")
async def get_system_stats(
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene statistiche complete del sistema (solo admin)."""
    try:
        stats = await manager.get_stats()
        return ContributionStatsResponse(
            staff=stats["staff"],
            contributions=stats["contributions"],
            versioning=stats["versioning"],
            workflow=stats["workflow"],
        )
    except Exception as e:
        logger.error(f"Get stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/admin/audit", summary="Audit log globale")
async def get_global_audit(
    actor_id: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    current_user: User = Depends(get_current_admin_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene l'audit log globale (solo admin)."""
    try:
        entries = await manager.get_audit_log(actor_id=actor_id, limit=limit)

        return {
            "entries": [
                {
                    "id": e.id,
                    "action": e.action,
                    "actor_id": e.actor_id,
                    "target_type": e.target_type,
                    "target_id": e.target_id,
                    "project_id": e.project_id,
                    "timestamp": e.timestamp,
                    "details": e.details,
                }
                for e in entries
            ],
            "count": len(entries),
        }
    except Exception as e:
        logger.error(f"Get global audit error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/my-contributions", summary="I miei contributi")
async def get_my_contributions(
    status: Optional[ContributionStatusType] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene i contributi dell'utente corrente."""
    try:
        from services.staff_contribution import ContributionStatus

        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        status_param = None
        if status:
            status_map = {
                ContributionStatusType.DRAFT: ContributionStatus.DRAFT,
                ContributionStatusType.PENDING_REVIEW: ContributionStatus.PENDING_REVIEW,
                ContributionStatusType.IN_REVIEW: ContributionStatus.IN_REVIEW,
                ContributionStatusType.CHANGES_REQUESTED: ContributionStatus.CHANGES_REQUESTED,
                ContributionStatusType.APPROVED: ContributionStatus.APPROVED,
                ContributionStatusType.REJECTED: ContributionStatus.REJECTED,
                ContributionStatusType.PUBLISHED: ContributionStatus.PUBLISHED,
                ContributionStatusType.ARCHIVED: ContributionStatus.ARCHIVED,
            }
            status_param = status_map[status]

        contributions = await manager.list_contributions(
            contributor_id=member.id,
            status=status_param,
            limit=limit,
            offset=offset,
        )

        return {
            "contributions": [
                {
                    "id": c.id,
                    "content_type": c.content_type,
                    "status": c.status,
                    "title": c.title,
                    "current_version": c.current_version,
                    "created_at": c.created_at,
                    "updated_at": c.updated_at,
                    "tags": c.tags,
                }
                for c in contributions
            ],
            "count": len(contributions),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get my contributions error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Contribution Endpoints ====================

@router.post("/", response_model=ContributionResponse, summary="Crea contributo")
async def create_contribution(
    request: CreateContributionRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """
    Crea un nuovo contributo.

    Tipi disponibili:
    - **translation**: Traduzione testo
    - **transcription**: Trascrizione audio/video
    - **annotation**: Annotazione video
    - **correction**: Correzione contenuto
    - **glossary**: Voce glossario
    - **subtitle**: Sottotitoli
    - **voiceover**: Voice over
    - **knowledge**: Knowledge base entry
    - **technique**: Descrizione tecnica
    - **metadata**: Metadata video
    """
    try:
        from services.staff_contribution import ContributionType

        type_map = {
            ContributionTypeEnum.TRANSLATION: ContributionType.TRANSLATION,
            ContributionTypeEnum.TRANSCRIPTION: ContributionType.TRANSCRIPTION,
            ContributionTypeEnum.ANNOTATION: ContributionType.ANNOTATION,
            ContributionTypeEnum.CORRECTION: ContributionType.CORRECTION,
            ContributionTypeEnum.GLOSSARY: ContributionType.GLOSSARY,
            ContributionTypeEnum.SUBTITLE: ContributionType.SUBTITLE,
            ContributionTypeEnum.VOICEOVER: ContributionType.VOICEOVER,
            ContributionTypeEnum.KNOWLEDGE: ContributionType.KNOWLEDGE,
            ContributionTypeEnum.TECHNIQUE: ContributionType.TECHNIQUE,
            ContributionTypeEnum.METADATA: ContributionType.METADATA,
        }

        # Ottieni staff member
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(
                status_code=403,
                detail="Devi essere un membro staff per creare contributi"
            )

        contribution = await manager.create_contribution(
            contributor_id=member.id,
            title=request.title,
            content_type=type_map[request.content_type],
            content=request.content,
            project_id=request.project_id,
            tags=request.tags,
        )

        return ContributionResponse(
            id=contribution.id,
            contributor_id=contribution.contributor_id,
            project_id=contribution.project_id,
            content_type=contribution.content_type,
            status=contribution.status,
            title=contribution.title,
            content=contribution.content,
            current_version=contribution.current_version,
            created_at=contribution.created_at,
            updated_at=contribution.updated_at,
            submitted_at=contribution.submitted_at,
            approved_at=contribution.approved_at,
            published_at=contribution.published_at,
            reviewer_id=contribution.reviewer_id,
            approver_id=contribution.approver_id,
            tags=contribution.tags,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create contribution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", summary="Lista contributi")
async def list_contributions(
    contributor_id: Optional[str] = None,
    project_id: Optional[str] = None,
    status: Optional[ContributionStatusType] = None,
    content_type: Optional[ContributionTypeEnum] = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Lista contributi con filtri."""
    try:
        from services.staff_contribution import ContributionStatus, ContributionType

        status_param = None
        if status:
            status_map = {
                ContributionStatusType.DRAFT: ContributionStatus.DRAFT,
                ContributionStatusType.PENDING_REVIEW: ContributionStatus.PENDING_REVIEW,
                ContributionStatusType.IN_REVIEW: ContributionStatus.IN_REVIEW,
                ContributionStatusType.CHANGES_REQUESTED: ContributionStatus.CHANGES_REQUESTED,
                ContributionStatusType.APPROVED: ContributionStatus.APPROVED,
                ContributionStatusType.REJECTED: ContributionStatus.REJECTED,
                ContributionStatusType.PUBLISHED: ContributionStatus.PUBLISHED,
                ContributionStatusType.ARCHIVED: ContributionStatus.ARCHIVED,
            }
            status_param = status_map[status]

        type_param = None
        if content_type:
            type_map = {
                ContributionTypeEnum.TRANSLATION: ContributionType.TRANSLATION,
                ContributionTypeEnum.TRANSCRIPTION: ContributionType.TRANSCRIPTION,
                ContributionTypeEnum.ANNOTATION: ContributionType.ANNOTATION,
                ContributionTypeEnum.CORRECTION: ContributionType.CORRECTION,
                ContributionTypeEnum.GLOSSARY: ContributionType.GLOSSARY,
                ContributionTypeEnum.SUBTITLE: ContributionType.SUBTITLE,
                ContributionTypeEnum.VOICEOVER: ContributionType.VOICEOVER,
                ContributionTypeEnum.KNOWLEDGE: ContributionType.KNOWLEDGE,
                ContributionTypeEnum.TECHNIQUE: ContributionType.TECHNIQUE,
                ContributionTypeEnum.METADATA: ContributionType.METADATA,
            }
            type_param = type_map[content_type]

        contributions = await manager.list_contributions(
            contributor_id=contributor_id,
            project_id=project_id,
            status=status_param,
            content_type=type_param,
            limit=limit,
            offset=offset,
        )

        return {
            "contributions": [
                {
                    "id": c.id,
                    "contributor_id": c.contributor_id,
                    "project_id": c.project_id,
                    "content_type": c.content_type,
                    "status": c.status,
                    "title": c.title,
                    "current_version": c.current_version,
                    "created_at": c.created_at,
                    "updated_at": c.updated_at,
                    "tags": c.tags,
                }
                for c in contributions
            ],
            "count": len(contributions),
            "limit": limit,
            "offset": offset,
        }
    except Exception as e:
        logger.error(f"List contributions error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{contribution_id}", response_model=ContributionResponse)
async def get_contribution(
    contribution_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene dettagli contributo."""
    contribution = await manager.get_contribution(contribution_id)
    if not contribution:
        raise HTTPException(status_code=404, detail="Contributo non trovato")

    return ContributionResponse(
        id=contribution.id,
        contributor_id=contribution.contributor_id,
        project_id=contribution.project_id,
        content_type=contribution.content_type,
        status=contribution.status,
        title=contribution.title,
        content=contribution.content,
        current_version=contribution.current_version,
        created_at=contribution.created_at,
        updated_at=contribution.updated_at,
        submitted_at=contribution.submitted_at,
        approved_at=contribution.approved_at,
        published_at=contribution.published_at,
        reviewer_id=contribution.reviewer_id,
        approver_id=contribution.approver_id,
        tags=contribution.tags,
    )


@router.put("/{contribution_id}", response_model=ContributionResponse)
async def update_contribution(
    contribution_id: str,
    request: UpdateContributionRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """
    Aggiorna contributo.

    Crea automaticamente una nuova versione se il contenuto cambia.
    """
    try:
        # Ottieni staff member
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        contribution = await manager.update_contribution(
            contribution_id=contribution_id,
            editor_id=member.id,
            content=request.content,
            title=request.title,
            tags=request.tags,
            change_summary=request.change_summary,
        )

        if not contribution:
            raise HTTPException(status_code=404, detail="Contributo non trovato")

        return ContributionResponse(
            id=contribution.id,
            contributor_id=contribution.contributor_id,
            project_id=contribution.project_id,
            content_type=contribution.content_type,
            status=contribution.status,
            title=contribution.title,
            content=contribution.content,
            current_version=contribution.current_version,
            created_at=contribution.created_at,
            updated_at=contribution.updated_at,
            submitted_at=contribution.submitted_at,
            approved_at=contribution.approved_at,
            published_at=contribution.published_at,
            reviewer_id=contribution.reviewer_id,
            approver_id=contribution.approver_id,
            tags=contribution.tags,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Update contribution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{contribution_id}", summary="Elimina contributo")
async def delete_contribution(
    contribution_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Elimina un contributo."""
    try:
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        deleted = await manager.delete_contribution(contribution_id, member.id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Contributo non trovato")

        return {"message": "Contributo eliminato", "contribution_id": contribution_id}
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete contribution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Workflow Endpoints ====================

@router.post("/{contribution_id}/submit", response_model=ContributionResponse)
async def submit_for_review(
    contribution_id: str,
    request: SubmitForReviewRequest,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Sottomette un contributo per revisione."""
    try:
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        contribution = await manager.submit_for_review(
            contribution_id=contribution_id,
            submitter_id=member.id,
            priority=request.priority,
            notes=request.notes,
        )

        return ContributionResponse(
            id=contribution.id,
            contributor_id=contribution.contributor_id,
            project_id=contribution.project_id,
            content_type=contribution.content_type,
            status=contribution.status,
            title=contribution.title,
            content=contribution.content,
            current_version=contribution.current_version,
            created_at=contribution.created_at,
            updated_at=contribution.updated_at,
            submitted_at=contribution.submitted_at,
            approved_at=contribution.approved_at,
            published_at=contribution.published_at,
            reviewer_id=contribution.reviewer_id,
            approver_id=contribution.approver_id,
            tags=contribution.tags,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Submit for review error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{contribution_id}/approve", response_model=ContributionResponse)
async def approve_contribution(
    contribution_id: str,
    notes: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Approva un contributo (richiede permesso APPROVE_CONTRIBUTION)."""
    try:
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        contribution = await manager.approve(
            contribution_id=contribution_id,
            approver_id=member.id,
            notes=notes,
        )

        return ContributionResponse(
            id=contribution.id,
            contributor_id=contribution.contributor_id,
            project_id=contribution.project_id,
            content_type=contribution.content_type,
            status=contribution.status,
            title=contribution.title,
            content=contribution.content,
            current_version=contribution.current_version,
            created_at=contribution.created_at,
            updated_at=contribution.updated_at,
            submitted_at=contribution.submitted_at,
            approved_at=contribution.approved_at,
            published_at=contribution.published_at,
            reviewer_id=contribution.reviewer_id,
            approver_id=contribution.approver_id,
            tags=contribution.tags,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Approve error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{contribution_id}/reject", response_model=ContributionResponse)
async def reject_contribution(
    contribution_id: str,
    reason: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Rifiuta un contributo (richiede permesso REJECT_CONTRIBUTION)."""
    try:
        member = await manager.get_staff_member_by_user_id(str(current_user.id))
        if not member:
            raise HTTPException(status_code=403, detail="Non sei un membro staff")

        contribution = await manager.reject(
            contribution_id=contribution_id,
            rejector_id=member.id,
            reason=reason,
        )

        return ContributionResponse(
            id=contribution.id,
            contributor_id=contribution.contributor_id,
            project_id=contribution.project_id,
            content_type=contribution.content_type,
            status=contribution.status,
            title=contribution.title,
            content=contribution.content,
            current_version=contribution.current_version,
            created_at=contribution.created_at,
            updated_at=contribution.updated_at,
            submitted_at=contribution.submitted_at,
            approved_at=contribution.approved_at,
            published_at=contribution.published_at,
            reviewer_id=contribution.reviewer_id,
            approver_id=contribution.approver_id,
            tags=contribution.tags,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Reject error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Version & Audit Endpoints ====================

@router.get("/{contribution_id}/history", summary="Storico versioni")
async def get_contribution_history(
    contribution_id: str,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene lo storico delle versioni di un contributo."""
    try:
        # Verifica contributo esiste
        contribution = await manager.get_contribution(contribution_id)
        if not contribution:
            raise HTTPException(status_code=404, detail="Contributo non trovato")

        versions = await manager.get_contribution_history(contribution_id)

        return {
            "contribution_id": contribution_id,
            "current_version": contribution.current_version,
            "versions": [
                {
                    "version_number": v.version_number,
                    "created_by": v.created_by,
                    "created_at": v.created_at,
                    "change_summary": v.change_summary,
                }
                for v in versions
            ],
            "count": len(versions),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get history error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{contribution_id}/history/{version_number}")
async def get_contribution_version(
    contribution_id: str,
    version_number: int,
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene una specifica versione di un contributo."""
    try:
        versions = await manager.get_contribution_history(contribution_id)
        version = next((v for v in versions if v.version_number == version_number), None)

        if not version:
            raise HTTPException(status_code=404, detail="Versione non trovata")

        return {
            "contribution_id": contribution_id,
            "version_number": version.version_number,
            "content": version.content,
            "created_by": version.created_by,
            "created_at": version.created_at,
            "change_summary": version.change_summary,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get version error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{contribution_id}/audit", summary="Audit log contributo")
async def get_contribution_audit(
    contribution_id: str,
    limit: int = Query(default=50, le=200),
    current_user: User = Depends(get_current_user),
    manager = Depends(get_contribution_manager),
):
    """Ottiene l'audit log di un contributo."""
    try:
        entries = await manager.get_audit_log(contribution_id=contribution_id, limit=limit)

        return {
            "contribution_id": contribution_id,
            "entries": [
                {
                    "id": e.id,
                    "action": e.action,
                    "actor_id": e.actor_id,
                    "timestamp": e.timestamp,
                    "details": e.details,
                }
                for e in entries
            ],
            "count": len(entries),
        }
    except Exception as e:
        logger.error(f"Get audit error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== OLD ENDPOINTS REMOVED - MOVED ABOVE /{contribution_id} ====================
# FIX 2025-01-27: Route ordering fix - vedi inizio file per /admin/stats, /admin/audit, /my-contributions

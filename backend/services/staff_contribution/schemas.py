"""
# AI_MODULE: StaffContributionSchemas
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Schema e tipi per sistema contributi staff
# AI_BUSINESS: Definisce ruoli, permessi, tipi contributo, stati workflow
# AI_TEACHING: Enum per type-safety, dataclass per dati strutturati,
#              serializzazione JSON per storage e API.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

Schemas Module
==============

Definisce tutti i tipi e schemi per StaffContribution:
- Enum per ruoli, permessi, stati
- Dataclass per entita principali
- Serializzazione JSON
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from typing import Optional, List, Dict, Any, Set


class StaffRole(Enum):
    """Ruoli staff con gerarchia."""
    ADMIN = "admin"  # Accesso completo
    MODERATOR = "moderator"  # Modera contenuti
    TRANSLATOR = "translator"  # Traduce
    REVIEWER = "reviewer"  # Revisiona
    CONTRIBUTOR = "contributor"  # Contribuisce
    VIEWER = "viewer"  # Solo lettura

    @property
    def level(self) -> int:
        """Livello gerarchico del ruolo (piu' alto = piu' permessi)."""
        levels = {
            StaffRole.VIEWER: 1,
            StaffRole.CONTRIBUTOR: 2,
            StaffRole.TRANSLATOR: 3,
            StaffRole.REVIEWER: 4,
            StaffRole.MODERATOR: 5,
            StaffRole.ADMIN: 6,
        }
        return levels[self]

    def __lt__(self, other: "StaffRole") -> bool:
        return self.level < other.level

    def __le__(self, other: "StaffRole") -> bool:
        return self.level <= other.level


class Permission(Enum):
    """Permessi granulari."""
    # Lettura
    VIEW_CONTENT = "view_content"
    VIEW_TRANSLATIONS = "view_translations"
    VIEW_AUDIT_LOG = "view_audit_log"
    VIEW_STAFF = "view_staff"

    # Creazione
    CREATE_CONTRIBUTION = "create_contribution"
    CREATE_TRANSLATION = "create_translation"
    CREATE_COMMENT = "create_comment"

    # Modifica
    EDIT_OWN_CONTRIBUTION = "edit_own_contribution"
    EDIT_ANY_CONTRIBUTION = "edit_any_contribution"
    EDIT_TRANSLATION = "edit_translation"

    # Eliminazione
    DELETE_OWN_CONTRIBUTION = "delete_own_contribution"
    DELETE_ANY_CONTRIBUTION = "delete_any_contribution"

    # Review
    SUBMIT_FOR_REVIEW = "submit_for_review"
    REVIEW_CONTRIBUTION = "review_contribution"
    APPROVE_CONTRIBUTION = "approve_contribution"
    REJECT_CONTRIBUTION = "reject_contribution"

    # Admin
    MANAGE_STAFF = "manage_staff"
    MANAGE_ROLES = "manage_roles"
    MANAGE_PERMISSIONS = "manage_permissions"
    VIEW_ALL_PROJECTS = "view_all_projects"
    MANAGE_PROJECTS = "manage_projects"

    # Speciali
    PUBLISH_CONTENT = "publish_content"
    UNPUBLISH_CONTENT = "unpublish_content"
    REVERT_VERSION = "revert_version"
    EXPORT_DATA = "export_data"


class ContributionType(Enum):
    """Tipi di contributo."""
    TRANSLATION = "translation"  # Traduzione testo
    SUBTITLE = "subtitle"  # Sottotitoli video
    TRANSCRIPTION = "transcription"  # Trascrizione audio
    ANNOTATION = "annotation"  # Annotazione video/immagine
    REVIEW = "review"  # Revisione contenuto
    CORRECTION = "correction"  # Correzione errore
    TERMINOLOGY = "terminology"  # Termine glossario
    DOCUMENTATION = "documentation"  # Documentazione
    METADATA = "metadata"  # Metadata contenuto
    OTHER = "other"


class ContributionStatus(Enum):
    """Stati di un contributo."""
    DRAFT = "draft"  # Bozza, non visibile
    PENDING_REVIEW = "pending_review"  # In attesa revisione
    IN_REVIEW = "in_review"  # Revisione in corso
    CHANGES_REQUESTED = "changes_requested"  # Richieste modifiche
    APPROVED = "approved"  # Approvato
    REJECTED = "rejected"  # Rifiutato
    PUBLISHED = "published"  # Pubblicato
    ARCHIVED = "archived"  # Archiviato


class ReviewStatus(Enum):
    """Stati revisione."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class AuditAction(Enum):
    """Azioni loggabili."""
    # Contributi
    CONTRIBUTION_CREATED = "contribution_created"
    CONTRIBUTION_UPDATED = "contribution_updated"
    CONTRIBUTION_DELETED = "contribution_deleted"
    CONTRIBUTION_SUBMITTED = "contribution_submitted"
    CONTRIBUTION_APPROVED = "contribution_approved"
    CONTRIBUTION_REJECTED = "contribution_rejected"
    CONTRIBUTION_PUBLISHED = "contribution_published"
    CONTRIBUTION_UNPUBLISHED = "contribution_unpublished"
    CONTRIBUTION_REVERTED = "contribution_reverted"

    # Versioni
    VERSION_CREATED = "version_created"
    VERSION_RESTORED = "version_restored"

    # Review
    REVIEW_STARTED = "review_started"
    REVIEW_COMPLETED = "review_completed"
    REVIEW_COMMENT_ADDED = "review_comment_added"
    CHANGES_REQUESTED = "changes_requested"

    # Staff
    STAFF_MEMBER_ADDED = "staff_member_added"
    STAFF_MEMBER_REMOVED = "staff_member_removed"
    STAFF_ROLE_CHANGED = "staff_role_changed"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"

    # Accesso
    LOGIN = "login"
    LOGOUT = "logout"
    ACCESS_DENIED = "access_denied"


@dataclass
class StaffMember:
    """Membro dello staff."""
    id: str
    user_id: str  # ID utente nel sistema principale
    username: str
    email: str
    role: str  # StaffRole.value
    permissions: List[str] = field(default_factory=list)  # Permission.value aggiuntivi
    projects: List[str] = field(default_factory=list)  # Project IDs assegnati
    is_active: bool = True
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    created_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StaffMember":
        """Crea da dizionario."""
        return cls(**data)

    def to_json(self) -> str:
        """Serializza in JSON."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "StaffMember":
        """Deserializza da JSON."""
        return cls.from_dict(json.loads(json_str))

    @property
    def staff_role(self) -> StaffRole:
        """Ottiene StaffRole enum."""
        return StaffRole(self.role)

    def has_permission(self, permission: Permission) -> bool:
        """Controlla se ha permesso specifico."""
        return permission.value in self.permissions


@dataclass
class Contribution:
    """Contributo staff."""
    id: str
    contributor_id: str  # StaffMember.id
    project_id: Optional[str]
    content_type: str  # ContributionType.value
    status: str  # ContributionStatus.value
    title: str
    content: Dict[str, Any]  # Contenuto strutturato
    current_version: int = 1
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    submitted_at: Optional[str] = None
    approved_at: Optional[str] = None
    published_at: Optional[str] = None
    reviewer_id: Optional[str] = None
    approver_id: Optional[str] = None
    parent_contribution_id: Optional[str] = None  # Per correzioni/revisioni
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        d = asdict(self)
        d['content'] = json.dumps(d['content']) if isinstance(d['content'], dict) else d['content']
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Contribution":
        """Crea da dizionario."""
        if isinstance(data.get('content'), str):
            data['content'] = json.loads(data['content'])
        return cls(**data)

    def to_json(self) -> str:
        """Serializza in JSON."""
        return json.dumps(asdict(self), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "Contribution":
        """Deserializza da JSON."""
        return cls.from_dict(json.loads(json_str))

    @property
    def contribution_status(self) -> ContributionStatus:
        """Ottiene ContributionStatus enum."""
        return ContributionStatus(self.status)

    @property
    def contribution_type(self) -> ContributionType:
        """Ottiene ContributionType enum."""
        return ContributionType(self.content_type)

    def can_be_edited(self) -> bool:
        """Controlla se puo' essere modificato."""
        editable_statuses = {
            ContributionStatus.DRAFT.value,
            ContributionStatus.CHANGES_REQUESTED.value,
        }
        return self.status in editable_statuses

    def can_be_submitted(self) -> bool:
        """Controlla se puo' essere sottomesso."""
        return self.status == ContributionStatus.DRAFT.value

    def can_be_approved(self) -> bool:
        """Controlla se puo' essere approvato."""
        return self.status in {
            ContributionStatus.PENDING_REVIEW.value,
            ContributionStatus.IN_REVIEW.value,
        }


@dataclass
class ContributionVersion:
    """Versione di un contributo."""
    id: str
    contribution_id: str
    version_number: int
    content: Dict[str, Any]
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    created_by: str = ""
    change_summary: Optional[str] = None
    diff_from_previous: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        d = asdict(self)
        d['content'] = json.dumps(d['content']) if isinstance(d['content'], dict) else d['content']
        if d['diff_from_previous']:
            d['diff_from_previous'] = json.dumps(d['diff_from_previous'])
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContributionVersion":
        """Crea da dizionario."""
        if isinstance(data.get('content'), str):
            data['content'] = json.loads(data['content'])
        if isinstance(data.get('diff_from_previous'), str):
            data['diff_from_previous'] = json.loads(data['diff_from_previous'])
        return cls(**data)


@dataclass
class ReviewComment:
    """Commento durante revisione."""
    id: str
    contribution_id: str
    reviewer_id: str
    version_number: int
    comment: str
    line_reference: Optional[str] = None  # Riferimento a riga/sezione
    status: str = "open"  # open, resolved, wontfix
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    resolved_at: Optional[str] = None
    resolved_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReviewComment":
        """Crea da dizionario."""
        return cls(**data)


@dataclass
class AuditEntry:
    """Entry nel log di audit."""
    id: str
    timestamp: str
    action: str  # AuditAction.value
    actor_id: str  # StaffMember.id
    target_type: str  # "contribution", "staff_member", "version", etc.
    target_id: str
    project_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    previous_state: Optional[Dict[str, Any]] = None
    new_state: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        d = asdict(self)
        d['details'] = json.dumps(d['details']) if isinstance(d['details'], dict) else d['details']
        if d['previous_state']:
            d['previous_state'] = json.dumps(d['previous_state'])
        if d['new_state']:
            d['new_state'] = json.dumps(d['new_state'])
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Crea da dizionario."""
        if isinstance(data.get('details'), str):
            data['details'] = json.loads(data['details'])
        if isinstance(data.get('previous_state'), str):
            data['previous_state'] = json.loads(data['previous_state'])
        if isinstance(data.get('new_state'), str):
            data['new_state'] = json.loads(data['new_state'])
        return cls(**data)

    @property
    def audit_action(self) -> AuditAction:
        """Ottiene AuditAction enum."""
        return AuditAction(self.action)


@dataclass
class ReviewRequest:
    """Richiesta di revisione."""
    id: str
    contribution_id: str
    requester_id: str
    assigned_reviewer_id: Optional[str] = None
    status: str = ReviewStatus.PENDING.value
    priority: str = "normal"  # low, normal, high, urgent
    due_date: Optional[str] = None
    notes: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    decision: Optional[str] = None  # approved, rejected, changes_requested

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReviewRequest":
        """Crea da dizionario."""
        return cls(**data)


# Costanti utili
ROLE_HIERARCHY = {
    StaffRole.VIEWER: 1,
    StaffRole.CONTRIBUTOR: 2,
    StaffRole.TRANSLATOR: 3,
    StaffRole.REVIEWER: 4,
    StaffRole.MODERATOR: 5,
    StaffRole.ADMIN: 6,
}

# Stati transizioni valide
VALID_STATUS_TRANSITIONS = {
    ContributionStatus.DRAFT: {
        ContributionStatus.PENDING_REVIEW,
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.PENDING_REVIEW: {
        ContributionStatus.IN_REVIEW,
        ContributionStatus.DRAFT,
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.IN_REVIEW: {
        ContributionStatus.APPROVED,
        ContributionStatus.REJECTED,
        ContributionStatus.CHANGES_REQUESTED,
    },
    ContributionStatus.CHANGES_REQUESTED: {
        ContributionStatus.PENDING_REVIEW,
        ContributionStatus.DRAFT,
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.APPROVED: {
        ContributionStatus.PUBLISHED,
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.REJECTED: {
        ContributionStatus.DRAFT,
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.PUBLISHED: {
        ContributionStatus.ARCHIVED,
    },
    ContributionStatus.ARCHIVED: set(),  # Stato finale
}


def can_transition(from_status: ContributionStatus, to_status: ContributionStatus) -> bool:
    """Verifica se transizione di stato e' valida."""
    allowed = VALID_STATUS_TRANSITIONS.get(from_status, set())
    return to_status in allowed

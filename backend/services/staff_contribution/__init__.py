"""
# AI_MODULE: StaffContribution
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Sistema gestione contributi staff con RBAC, audit log, versioning e review workflow
# AI_BUSINESS: Permette a traduttori, revisori, admin di contribuire contenuti con
#              tracciamento completo, controllo accessi granulare, e workflow approvazione.
# AI_TEACHING: Package che implementa RBAC (Role-Based Access Control), audit log immutabile,
#              versioning copy-on-write, e workflow di review. Pattern Singleton per manager.
# AI_DEPENDENCIES: SQLAlchemy async, Pydantic
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

StaffContribution Package
=========================

Sistema completo per gestione contributi dello staff.

Componenti:
-----------
- ContributionManager: Facade principale per tutte le operazioni
- RBAC: Role-Based Access Control con permessi granulari
- AuditLog: Log immutabile di tutte le azioni
- Versioning: Controllo versione con copy-on-write
- ReviewWorkflow: Workflow approvazione contributi

Ruoli:
------
- ADMIN: Accesso completo, gestione utenti e ruoli
- MODERATOR: Approva/rifiuta contributi, modera contenuti
- TRANSLATOR: Traduce contenuti, crea nuove versioni
- REVIEWER: Revisiona traduzioni, approva modifiche
- CONTRIBUTOR: Contribuisce contenuti base
- VIEWER: Solo lettura

Uso:
----
    from services.staff_contribution import ContributionManager

    # Singleton pattern
    manager = await ContributionManager.get_instance()

    # Crea contributo
    contribution = await manager.create_contribution(
        user_id="user123",
        content_type="translation",
        content={"text": "Traduzione", "source_lang": "ja", "target_lang": "it"},
        project_id="project456"
    )

    # Workflow approvazione
    await manager.submit_for_review(contribution.id)
    await manager.approve(contribution.id, reviewer_id="reviewer789")

Testing:
--------
    # Reset per test isolation
    ContributionManager._reset_for_testing()
"""

from .schemas import (
    StaffRole,
    Permission,
    ContributionType,
    ContributionStatus,
    ReviewStatus,
    StaffMember,
    Contribution,
    ContributionVersion,
    ReviewComment,
    AuditEntry,
)
from .rbac import RBAC, RolePermissions
from .audit_log import AuditLog, AuditAction
from .versioning import VersionControl, VersionDiff
from .review_workflow import ReviewWorkflow, ReviewDecision
from .contribution_manager import ContributionManager

__all__ = [
    # Main facade
    "ContributionManager",

    # RBAC
    "RBAC",
    "RolePermissions",
    "StaffRole",
    "Permission",

    # Audit
    "AuditLog",
    "AuditAction",
    "AuditEntry",

    # Versioning
    "VersionControl",
    "VersionDiff",

    # Review
    "ReviewWorkflow",
    "ReviewDecision",

    # Schemas
    "ContributionType",
    "ContributionStatus",
    "ReviewStatus",
    "StaffMember",
    "Contribution",
    "ContributionVersion",
    "ReviewComment",
]

__version__ = "1.0.0"
__author__ = "Media Center Arti Marziali"

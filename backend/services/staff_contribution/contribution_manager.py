"""
# AI_MODULE: ContributionManager
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Facade principale per sistema gestione contributi staff
# AI_BUSINESS: Punto di ingresso unico per CRUD contributi, workflow revisione,
#              gestione staff, audit log. Semplifica integrazione API.
# AI_TEACHING: Pattern Facade che espone API semplice. Coordina RBAC, AuditLog,
#              VersionControl, ReviewWorkflow. Singleton con _reset_for_testing.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

ContributionManager Module
==========================

Facade principale per sistema contributi staff.

Espone API semplificate per:
- Gestione staff (create, update, delete members)
- Contributi (CRUD con versioning automatico)
- Workflow revisione (submit, review, approve/reject)
- Audit (log automatico di ogni azione)
- Controllo accessi (check permessi RBAC)

Uso:
    manager = await ContributionManager.get_instance()

    # Crea staff member
    member = await manager.add_staff_member(
        user_id="user123",
        username="mario",
        email="mario@example.com",
        role=StaffRole.TRANSLATOR
    )

    # Crea contributo
    contribution = await manager.create_contribution(
        contributor_id=member.id,
        title="Traduzione tecniche karate",
        content_type=ContributionType.TRANSLATION,
        content={"source": "oi-zuki", "translation": "pugno avanzando"}
    )

    # Workflow
    await manager.submit_for_review(contribution.id, member.id)
    await manager.approve(contribution.id, reviewer_member.id)
"""

import asyncio
import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
import logging
import uuid

from .schemas import (
    StaffRole,
    Permission,
    ContributionType,
    ContributionStatus,
    StaffMember,
    Contribution,
    ContributionVersion,
    AuditEntry,
    ReviewComment,
    can_transition,
)
from .rbac import RBAC
from .audit_log import AuditLog, AuditAction
from .versioning import VersionControl
from .review_workflow import ReviewWorkflow, ReviewDecision

logger = logging.getLogger(__name__)


class ContributionManager:
    """
    Facade principale per sistema contributi.

    Singleton pattern con _reset_for_testing per test isolation.
    """

    _instance: Optional["ContributionManager"] = None
    _lock = asyncio.Lock()

    # Schema SQL per staff e contributi
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS staff_members (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL,
        permissions TEXT DEFAULT '[]',
        projects TEXT DEFAULT '[]',
        is_active INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        created_by TEXT,
        metadata TEXT DEFAULT '{}'
    );

    CREATE INDEX IF NOT EXISTS idx_staff_user ON staff_members(user_id);
    CREATE INDEX IF NOT EXISTS idx_staff_role ON staff_members(role);

    CREATE TABLE IF NOT EXISTS contributions (
        id TEXT PRIMARY KEY,
        contributor_id TEXT NOT NULL,
        project_id TEXT,
        content_type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'draft',
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        current_version INTEGER DEFAULT 1,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        submitted_at TEXT,
        approved_at TEXT,
        published_at TEXT,
        reviewer_id TEXT,
        approver_id TEXT,
        parent_contribution_id TEXT,
        tags TEXT DEFAULT '[]',
        metadata TEXT DEFAULT '{}',
        FOREIGN KEY (contributor_id) REFERENCES staff_members(id)
    );

    CREATE INDEX IF NOT EXISTS idx_contributions_contributor ON contributions(contributor_id);
    CREATE INDEX IF NOT EXISTS idx_contributions_status ON contributions(status);
    CREATE INDEX IF NOT EXISTS idx_contributions_project ON contributions(project_id);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inizializza ContributionManager.

        Args:
            db_path: Path database SQLite base. Se None, usa default.
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "storage", "staff")
        self._base_path = Path(db_path)
        self._db_path = self._base_path / "contributions.db"
        self._conn: Optional[sqlite3.Connection] = None

        # Sotto-moduli
        self._rbac: Optional[RBAC] = None
        self._audit: Optional[AuditLog] = None
        self._versions: Optional[VersionControl] = None
        self._reviews: Optional[ReviewWorkflow] = None

        self._initialized = False

    @classmethod
    async def get_instance(cls, db_path: Optional[str] = None) -> "ContributionManager":
        """
        Ottiene istanza singleton.

        Args:
            db_path: Path base (solo alla prima chiamata)

        Returns:
            Istanza ContributionManager
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
                await cls._instance._initialize()
            return cls._instance

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset singleton per test isolation."""
        if cls._instance is not None:
            if cls._instance._conn:
                cls._instance._conn.close()
            AuditLog._reset_for_testing()
            VersionControl._reset_for_testing()
            ReviewWorkflow._reset_for_testing()
        cls._instance = None

    async def _initialize(self) -> None:
        """Inizializza database e sotto-moduli."""
        if self._initialized:
            return

        # Crea directory
        self._base_path.mkdir(parents=True, exist_ok=True)

        # Database principale
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

        # Sotto-moduli
        self._rbac = RBAC()
        self._audit = await AuditLog.get_instance(str(self._base_path / "audit.db"))
        self._versions = await VersionControl.get_instance(str(self._base_path / "versions.db"))
        self._reviews = await ReviewWorkflow.get_instance(str(self._base_path / "reviews.db"))

        self._initialized = True
        logger.info(f"ContributionManager inizializzato: {self._base_path}")

    def _generate_id(self) -> str:
        """Genera ID univoco."""
        return str(uuid.uuid4())

    # ==================== Staff Management ====================

    async def add_staff_member(
        self,
        user_id: str,
        username: str,
        email: str,
        role: StaffRole,
        created_by: Optional[str] = None,
        projects: Optional[List[str]] = None,
        permissions: Optional[List[Permission]] = None,
    ) -> StaffMember:
        """
        Aggiunge nuovo membro staff.

        Args:
            user_id: ID utente nel sistema principale
            username: Username
            email: Email
            role: Ruolo
            created_by: ID chi crea
            projects: Progetti assegnati
            permissions: Permessi aggiuntivi

        Returns:
            StaffMember creato
        """
        member_id = self._generate_id()
        now = datetime.now().isoformat()

        member = StaffMember(
            id=member_id,
            user_id=user_id,
            username=username,
            email=email,
            role=role.value,
            permissions=[p.value for p in permissions] if permissions else [],
            projects=projects or [],
            created_at=now,
            updated_at=now,
            created_by=created_by,
        )

        self._conn.execute(
            """
            INSERT INTO staff_members
            (id, user_id, username, email, role, permissions, projects,
             is_active, created_at, updated_at, created_by, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                member.id, member.user_id, member.username, member.email,
                member.role, json.dumps(member.permissions),
                json.dumps(member.projects), 1, member.created_at,
                member.updated_at, member.created_by, json.dumps(member.metadata),
            )
        )
        self._conn.commit()

        # Audit
        await self._audit.log(
            action=AuditAction.STAFF_MEMBER_ADDED,
            actor_id=created_by or "system",
            target_type="staff_member",
            target_id=member_id,
            details={"username": username, "role": role.value},
            new_state=member.to_dict(),
        )

        logger.info(f"Staff member aggiunto: {username} ({role.value})")
        return member

    async def get_staff_member(self, member_id: str) -> Optional[StaffMember]:
        """Ottiene membro staff per ID."""
        cursor = self._conn.execute(
            "SELECT * FROM staff_members WHERE id = ?",
            (member_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_member(row)
        return None

    async def get_staff_member_by_user_id(self, user_id: str) -> Optional[StaffMember]:
        """Ottiene membro staff per user_id."""
        cursor = self._conn.execute(
            "SELECT * FROM staff_members WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_member(row)
        return None

    def _row_to_member(self, row: sqlite3.Row) -> StaffMember:
        """Converte row SQLite in StaffMember."""
        return StaffMember(
            id=row["id"],
            user_id=row["user_id"],
            username=row["username"],
            email=row["email"],
            role=row["role"],
            permissions=json.loads(row["permissions"]),
            projects=json.loads(row["projects"]),
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            created_by=row["created_by"],
            metadata=json.loads(row["metadata"]),
        )

    async def update_staff_member(
        self,
        member_id: str,
        actor_id: str,
        **updates
    ) -> Optional[StaffMember]:
        """
        Aggiorna membro staff.

        Args:
            member_id: ID membro
            actor_id: ID chi aggiorna
            **updates: Campi da aggiornare

        Returns:
            StaffMember aggiornato o None
        """
        member = await self.get_staff_member(member_id)
        if not member:
            return None

        previous_state = member.to_dict()

        allowed = {"username", "email", "role", "permissions", "projects", "is_active", "metadata"}
        for key, value in updates.items():
            if key in allowed:
                if key == "role" and isinstance(value, StaffRole):
                    value = value.value
                elif key == "permissions" and isinstance(value, list):
                    value = [p.value if isinstance(p, Permission) else p for p in value]
                setattr(member, key, value)

        member.updated_at = datetime.now().isoformat()

        # Serializza per DB
        self._conn.execute(
            """
            UPDATE staff_members SET
                username = ?, email = ?, role = ?, permissions = ?,
                projects = ?, is_active = ?, updated_at = ?, metadata = ?
            WHERE id = ?
            """,
            (
                member.username, member.email, member.role,
                json.dumps(member.permissions), json.dumps(member.projects),
                1 if member.is_active else 0, member.updated_at,
                json.dumps(member.metadata), member.id,
            )
        )
        self._conn.commit()

        # Audit
        await self._audit.log(
            action=AuditAction.STAFF_ROLE_CHANGED if "role" in updates else AuditAction.STAFF_MEMBER_ADDED,
            actor_id=actor_id,
            target_type="staff_member",
            target_id=member_id,
            details=updates,
            previous_state=previous_state,
            new_state=member.to_dict(),
        )

        return member

    async def list_staff(
        self,
        role: Optional[StaffRole] = None,
        is_active: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> List[StaffMember]:
        """Lista membri staff."""
        conditions = []
        params = []

        if role:
            conditions.append("role = ?")
            params.append(role.value)

        conditions.append("is_active = ?")
        params.append(1 if is_active else 0)

        where = " AND ".join(conditions)

        cursor = self._conn.execute(
            f"SELECT * FROM staff_members WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset]
        )

        return [self._row_to_member(row) for row in cursor.fetchall()]

    # ==================== Contributions ====================

    async def create_contribution(
        self,
        contributor_id: str,
        title: str,
        content_type: ContributionType,
        content: Dict[str, Any],
        project_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Contribution:
        """
        Crea nuovo contributo.

        Args:
            contributor_id: ID contributor
            title: Titolo
            content_type: Tipo contributo
            content: Contenuto strutturato
            project_id: ID progetto
            tags: Tags

        Returns:
            Contribution creato
        """
        # Verifica permesso
        member = await self.get_staff_member(contributor_id)
        if not member:
            raise ValueError(f"Contributor non trovato: {contributor_id}")

        if not self._rbac.has_permission(member, Permission.CREATE_CONTRIBUTION):
            raise PermissionError("Permesso CREATE_CONTRIBUTION richiesto")

        if project_id and not self._rbac.can_access_project(member, project_id):
            raise PermissionError(f"Accesso al progetto {project_id} negato")

        # Crea contributo
        contribution_id = self._generate_id()
        now = datetime.now().isoformat()

        contribution = Contribution(
            id=contribution_id,
            contributor_id=contributor_id,
            project_id=project_id,
            content_type=content_type.value,
            status=ContributionStatus.DRAFT.value,
            title=title,
            content=content,
            current_version=1,
            created_at=now,
            updated_at=now,
            tags=tags or [],
        )

        self._conn.execute(
            """
            INSERT INTO contributions
            (id, contributor_id, project_id, content_type, status, title, content,
             current_version, created_at, updated_at, tags, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                contribution.id, contribution.contributor_id, contribution.project_id,
                contribution.content_type, contribution.status, contribution.title,
                json.dumps(contribution.content), contribution.current_version,
                contribution.created_at, contribution.updated_at,
                json.dumps(contribution.tags), json.dumps(contribution.metadata),
            )
        )
        self._conn.commit()

        # Crea prima versione
        await self._versions.create_version(
            contribution_id=contribution_id,
            content=content,
            created_by=contributor_id,
            change_summary="Creazione iniziale",
        )

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_CREATED,
            actor_id=contributor_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=project_id,
            details={"title": title, "type": content_type.value},
            new_state=contribution.to_dict(),
        )

        logger.info(f"Contributo creato: {contribution_id} da {contributor_id}")
        return contribution

    async def get_contribution(self, contribution_id: str) -> Optional[Contribution]:
        """Ottiene contributo per ID."""
        cursor = self._conn.execute(
            "SELECT * FROM contributions WHERE id = ?",
            (contribution_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_contribution(row)
        return None

    def _row_to_contribution(self, row: sqlite3.Row) -> Contribution:
        """Converte row SQLite in Contribution."""
        return Contribution(
            id=row["id"],
            contributor_id=row["contributor_id"],
            project_id=row["project_id"],
            content_type=row["content_type"],
            status=row["status"],
            title=row["title"],
            content=json.loads(row["content"]),
            current_version=row["current_version"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            submitted_at=row["submitted_at"],
            approved_at=row["approved_at"],
            published_at=row["published_at"],
            reviewer_id=row["reviewer_id"],
            approver_id=row["approver_id"],
            parent_contribution_id=row["parent_contribution_id"],
            tags=json.loads(row["tags"]),
            metadata=json.loads(row["metadata"]),
        )

    async def update_contribution(
        self,
        contribution_id: str,
        editor_id: str,
        content: Optional[Dict[str, Any]] = None,
        title: Optional[str] = None,
        tags: Optional[List[str]] = None,
        change_summary: Optional[str] = None,
    ) -> Optional[Contribution]:
        """
        Aggiorna contributo (crea nuova versione).

        Args:
            contribution_id: ID contributo
            editor_id: ID chi modifica
            content: Nuovo contenuto
            title: Nuovo titolo
            tags: Nuovi tags
            change_summary: Riepilogo modifiche

        Returns:
            Contribution aggiornato o None
        """
        contribution = await self.get_contribution(contribution_id)
        if not contribution:
            return None

        # Verifica permesso
        member = await self.get_staff_member(editor_id)
        if not member:
            raise ValueError(f"Editor non trovato: {editor_id}")

        is_owner = contribution.contributor_id == editor_id
        if is_owner:
            if not self._rbac.has_permission(member, Permission.EDIT_OWN_CONTRIBUTION):
                raise PermissionError("Permesso EDIT_OWN_CONTRIBUTION richiesto")
        else:
            if not self._rbac.has_permission(member, Permission.EDIT_ANY_CONTRIBUTION):
                raise PermissionError("Permesso EDIT_ANY_CONTRIBUTION richiesto")

        if not contribution.can_be_edited():
            raise ValueError(f"Contributo in stato {contribution.status} non modificabile")

        previous_state = contribution.to_dict()

        # Aggiorna campi
        if content:
            contribution.content = content
            contribution.current_version += 1
            await self._versions.create_version(
                contribution_id=contribution_id,
                content=content,
                created_by=editor_id,
                change_summary=change_summary,
            )

        if title:
            contribution.title = title

        if tags is not None:
            contribution.tags = tags

        contribution.updated_at = datetime.now().isoformat()

        self._conn.execute(
            """
            UPDATE contributions SET
                title = ?, content = ?, current_version = ?,
                updated_at = ?, tags = ?
            WHERE id = ?
            """,
            (
                contribution.title, json.dumps(contribution.content),
                contribution.current_version, contribution.updated_at,
                json.dumps(contribution.tags), contribution.id,
            )
        )
        self._conn.commit()

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_UPDATED,
            actor_id=editor_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=contribution.project_id,
            details={"change_summary": change_summary},
            previous_state=previous_state,
            new_state=contribution.to_dict(),
        )

        return contribution

    async def delete_contribution(
        self,
        contribution_id: str,
        deleter_id: str,
    ) -> bool:
        """
        Elimina contributo.

        Args:
            contribution_id: ID contributo
            deleter_id: ID chi elimina

        Returns:
            True se eliminato
        """
        contribution = await self.get_contribution(contribution_id)
        if not contribution:
            return False

        # Verifica permesso
        member = await self.get_staff_member(deleter_id)
        if not member:
            return False

        is_owner = contribution.contributor_id == deleter_id
        if is_owner:
            if not self._rbac.has_permission(member, Permission.DELETE_OWN_CONTRIBUTION):
                raise PermissionError("Permesso DELETE_OWN_CONTRIBUTION richiesto")
        else:
            if not self._rbac.has_permission(member, Permission.DELETE_ANY_CONTRIBUTION):
                raise PermissionError("Permesso DELETE_ANY_CONTRIBUTION richiesto")

        previous_state = contribution.to_dict()

        # Elimina
        self._conn.execute("DELETE FROM contributions WHERE id = ?", (contribution_id,))
        self._conn.commit()

        # Elimina versioni
        await self._versions.delete_contribution_versions(contribution_id)

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_DELETED,
            actor_id=deleter_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=contribution.project_id,
            previous_state=previous_state,
        )

        return True

    # ==================== Workflow ====================

    async def submit_for_review(
        self,
        contribution_id: str,
        submitter_id: str,
        priority: str = "normal",
        notes: Optional[str] = None,
    ) -> Contribution:
        """Sottomette contributo per revisione."""
        contribution = await self.get_contribution(contribution_id)
        if not contribution:
            raise ValueError(f"Contributo non trovato: {contribution_id}")

        if not contribution.can_be_submitted():
            raise ValueError(f"Contributo in stato {contribution.status} non sottomettibile")

        member = await self.get_staff_member(submitter_id)
        if not member or not self._rbac.has_permission(member, Permission.SUBMIT_FOR_REVIEW):
            raise PermissionError("Permesso SUBMIT_FOR_REVIEW richiesto")

        # Aggiorna stato
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE contributions SET status = ?, submitted_at = ?, updated_at = ? WHERE id = ?",
            (ContributionStatus.PENDING_REVIEW.value, now, now, contribution_id)
        )
        self._conn.commit()

        # Crea review request
        await self._reviews.submit_for_review(
            contribution_id=contribution_id,
            requester_id=submitter_id,
            priority=priority,
            notes=notes,
        )

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_SUBMITTED,
            actor_id=submitter_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=contribution.project_id,
            details={"priority": priority},
        )

        return await self.get_contribution(contribution_id)

    async def approve(
        self,
        contribution_id: str,
        approver_id: str,
        notes: Optional[str] = None,
    ) -> Contribution:
        """Approva contributo."""
        contribution = await self.get_contribution(contribution_id)
        if not contribution:
            raise ValueError(f"Contributo non trovato: {contribution_id}")

        if not contribution.can_be_approved():
            raise ValueError(f"Contributo in stato {contribution.status} non approvabile")

        member = await self.get_staff_member(approver_id)
        if not member or not self._rbac.has_permission(member, Permission.APPROVE_CONTRIBUTION):
            raise PermissionError("Permesso APPROVE_CONTRIBUTION richiesto")

        # Aggiorna stato
        now = datetime.now().isoformat()
        self._conn.execute(
            """
            UPDATE contributions SET
                status = ?, approved_at = ?, approver_id = ?, updated_at = ?
            WHERE id = ?
            """,
            (ContributionStatus.APPROVED.value, now, approver_id, now, contribution_id)
        )
        self._conn.commit()

        # Completa review
        await self._reviews.complete_review(
            contribution_id=contribution_id,
            reviewer_id=approver_id,
            decision=ReviewDecision.APPROVED,
            notes=notes,
        )

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_APPROVED,
            actor_id=approver_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=contribution.project_id,
        )

        return await self.get_contribution(contribution_id)

    async def reject(
        self,
        contribution_id: str,
        rejector_id: str,
        reason: str,
    ) -> Contribution:
        """Rifiuta contributo."""
        contribution = await self.get_contribution(contribution_id)
        if not contribution:
            raise ValueError(f"Contributo non trovato: {contribution_id}")

        member = await self.get_staff_member(rejector_id)
        if not member or not self._rbac.has_permission(member, Permission.REJECT_CONTRIBUTION):
            raise PermissionError("Permesso REJECT_CONTRIBUTION richiesto")

        # Aggiorna stato
        now = datetime.now().isoformat()
        self._conn.execute(
            "UPDATE contributions SET status = ?, updated_at = ? WHERE id = ?",
            (ContributionStatus.REJECTED.value, now, contribution_id)
        )
        self._conn.commit()

        # Completa review
        await self._reviews.complete_review(
            contribution_id=contribution_id,
            reviewer_id=rejector_id,
            decision=ReviewDecision.REJECTED,
            notes=reason,
        )

        # Audit
        await self._audit.log(
            action=AuditAction.CONTRIBUTION_REJECTED,
            actor_id=rejector_id,
            target_type="contribution",
            target_id=contribution_id,
            project_id=contribution.project_id,
            details={"reason": reason},
        )

        return await self.get_contribution(contribution_id)

    # ==================== Access Control ====================

    def check_permission(
        self,
        member: StaffMember,
        permission: Permission,
        resource_owner_id: Optional[str] = None,
    ) -> bool:
        """Verifica permesso."""
        return self._rbac.has_permission(member, permission, resource_owner_id)

    def check_project_access(
        self,
        member: StaffMember,
        project_id: str,
    ) -> bool:
        """Verifica accesso progetto."""
        return self._rbac.can_access_project(member, project_id)

    # ==================== Queries ====================

    async def list_contributions(
        self,
        contributor_id: Optional[str] = None,
        project_id: Optional[str] = None,
        status: Optional[ContributionStatus] = None,
        content_type: Optional[ContributionType] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Contribution]:
        """Lista contributi con filtri."""
        conditions = []
        params = []

        if contributor_id:
            conditions.append("contributor_id = ?")
            params.append(contributor_id)

        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)

        if status:
            conditions.append("status = ?")
            params.append(status.value)

        if content_type:
            conditions.append("content_type = ?")
            params.append(content_type.value)

        where = " AND ".join(conditions) if conditions else "1=1"

        cursor = self._conn.execute(
            f"""
            SELECT * FROM contributions
            WHERE {where}
            ORDER BY updated_at DESC
            LIMIT ? OFFSET ?
            """,
            params + [limit, offset]
        )

        return [self._row_to_contribution(row) for row in cursor.fetchall()]

    async def get_contribution_history(
        self,
        contribution_id: str,
    ) -> List[ContributionVersion]:
        """Ottiene storico versioni contributo."""
        return await self._versions.get_history(contribution_id)

    async def get_audit_log(
        self,
        contribution_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Ottiene log audit."""
        if contribution_id:
            return await self._audit.get_by_target("contribution", contribution_id, limit)
        elif actor_id:
            return await self._audit.get_by_actor(actor_id, limit)
        else:
            return await self._audit.get_recent(24, limit)

    # ==================== Stats ====================

    async def get_stats(self) -> Dict[str, Any]:
        """Ottiene statistiche sistema."""
        # Staff
        staff_count = self._conn.execute(
            "SELECT COUNT(*) FROM staff_members WHERE is_active = 1"
        ).fetchone()[0]

        staff_by_role = {}
        for row in self._conn.execute(
            "SELECT role, COUNT(*) as cnt FROM staff_members WHERE is_active = 1 GROUP BY role"
        ):
            staff_by_role[row["role"]] = row["cnt"]

        # Contributi
        contrib_count = self._conn.execute("SELECT COUNT(*) FROM contributions").fetchone()[0]

        contrib_by_status = {}
        for row in self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM contributions GROUP BY status"
        ):
            contrib_by_status[row["status"]] = row["cnt"]

        # Versioning
        version_stats = await self._versions.get_stats()

        # Review workflow
        workflow_stats = await self._reviews.get_workflow_stats()

        return {
            "staff": {
                "total": staff_count,
                "by_role": staff_by_role,
            },
            "contributions": {
                "total": contrib_count,
                "by_status": contrib_by_status,
            },
            "versioning": version_stats,
            "workflow": workflow_stats,
        }

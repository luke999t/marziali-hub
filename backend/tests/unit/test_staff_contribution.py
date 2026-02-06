"""
# AI_MODULE: TestStaffContribution
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Test suite REALE per StaffContribution - ZERO MOCK
# AI_BUSINESS: Verifica funzionamento completo sistema contributi staff
# AI_TEACHING: Test REALI che usano SQLite locale, nessun mock.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

Test Suite StaffContribution
============================

Test REALI per tutti i componenti StaffContribution:
- RBAC
- AuditLog
- VersionControl
- ReviewWorkflow
- ContributionManager

POLICY: ZERO MOCK - tutti i test usano componenti reali.
"""

import asyncio
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

# Import moduli staff_contribution
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from services.staff_contribution.schemas import (
    StaffRole,
    Permission,
    ContributionType,
    ContributionStatus,
    ReviewStatus,
    StaffMember,
    Contribution,
    AuditAction,
    can_transition,
)
from services.staff_contribution.rbac import RBAC, RolePermissions
from services.staff_contribution.audit_log import AuditLog
from services.staff_contribution.versioning import VersionControl
from services.staff_contribution.review_workflow import ReviewWorkflow, ReviewDecision
from services.staff_contribution.contribution_manager import ContributionManager


# ==================== Fixtures ====================

@pytest.fixture
def temp_dir():
    """Directory temporanea per test."""
    temp = tempfile.mkdtemp(prefix="staff_test_")
    yield temp
    shutil.rmtree(temp, ignore_errors=True)


@pytest.fixture
def sample_member():
    """StaffMember di esempio."""
    return StaffMember(
        id="member-001",
        user_id="user-001",
        username="mario_rossi",
        email="mario@example.com",
        role=StaffRole.TRANSLATOR.value,
        permissions=[],
        projects=["project-1", "project-2"],
        is_active=True,
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
    )


@pytest.fixture
def admin_member():
    """Admin StaffMember."""
    return StaffMember(
        id="admin-001",
        user_id="admin-user-001",
        username="admin",
        email="admin@example.com",
        role=StaffRole.ADMIN.value,
        permissions=[],
        projects=[],
        is_active=True,
        created_at=datetime.now().isoformat(),
        updated_at=datetime.now().isoformat(),
    )


# ==================== Schemas Tests ====================

class TestSchemas:
    """Test per schemas."""

    def test_staff_role_hierarchy(self):
        """Test gerarchia ruoli."""
        assert StaffRole.VIEWER < StaffRole.CONTRIBUTOR
        assert StaffRole.CONTRIBUTOR < StaffRole.TRANSLATOR
        assert StaffRole.TRANSLATOR < StaffRole.REVIEWER
        assert StaffRole.REVIEWER < StaffRole.MODERATOR
        assert StaffRole.MODERATOR < StaffRole.ADMIN

    def test_staff_role_level(self):
        """Test livello ruoli."""
        assert StaffRole.VIEWER.level == 1
        assert StaffRole.ADMIN.level == 6

    def test_can_transition_valid(self):
        """Test transizioni stato valide."""
        assert can_transition(ContributionStatus.DRAFT, ContributionStatus.PENDING_REVIEW)
        assert can_transition(ContributionStatus.PENDING_REVIEW, ContributionStatus.IN_REVIEW)
        assert can_transition(ContributionStatus.IN_REVIEW, ContributionStatus.APPROVED)
        assert can_transition(ContributionStatus.APPROVED, ContributionStatus.PUBLISHED)

    def test_can_transition_invalid(self):
        """Test transizioni stato non valide."""
        assert not can_transition(ContributionStatus.DRAFT, ContributionStatus.PUBLISHED)
        assert not can_transition(ContributionStatus.ARCHIVED, ContributionStatus.DRAFT)
        assert not can_transition(ContributionStatus.REJECTED, ContributionStatus.PUBLISHED)

    def test_staff_member_serialization(self, sample_member):
        """Test serializzazione StaffMember."""
        json_str = sample_member.to_json()
        restored = StaffMember.from_json(json_str)

        assert restored.id == sample_member.id
        assert restored.username == sample_member.username
        assert restored.role == sample_member.role

    def test_contribution_can_be_edited(self):
        """Test contribution.can_be_edited()."""
        contrib_draft = Contribution(
            id="c1", contributor_id="m1", project_id=None,
            content_type="translation", status=ContributionStatus.DRAFT.value,
            title="Test", content={},
        )
        assert contrib_draft.can_be_edited() is True

        contrib_approved = Contribution(
            id="c2", contributor_id="m1", project_id=None,
            content_type="translation", status=ContributionStatus.APPROVED.value,
            title="Test", content={},
        )
        assert contrib_approved.can_be_edited() is False


# ==================== RBAC Tests ====================

class TestRBAC:
    """Test per RBAC."""

    @pytest.fixture
    def rbac(self):
        """RBAC instance."""
        return RBAC()

    def test_role_permissions_viewer(self, rbac):
        """Test permessi ruolo VIEWER."""
        perms = rbac.get_role_permissions(StaffRole.VIEWER)

        assert Permission.VIEW_CONTENT in perms
        assert Permission.CREATE_CONTRIBUTION not in perms
        assert Permission.MANAGE_STAFF not in perms

    def test_role_permissions_translator(self, rbac):
        """Test permessi ruolo TRANSLATOR."""
        perms = rbac.get_role_permissions(StaffRole.TRANSLATOR)

        assert Permission.VIEW_CONTENT in perms
        assert Permission.CREATE_TRANSLATION in perms
        assert Permission.EDIT_TRANSLATION in perms
        assert Permission.MANAGE_STAFF not in perms

    def test_role_permissions_admin(self, rbac):
        """Test permessi ruolo ADMIN (tutti)."""
        perms = rbac.get_role_permissions(StaffRole.ADMIN)

        # Admin ha tutti i permessi
        assert Permission.VIEW_CONTENT in perms
        assert Permission.MANAGE_STAFF in perms
        assert Permission.MANAGE_ROLES in perms

    def test_has_permission(self, rbac, sample_member):
        """Test has_permission."""
        # Translator ha permesso CREATE_TRANSLATION
        assert rbac.has_permission(sample_member, Permission.CREATE_TRANSLATION)

        # Translator non ha permesso MANAGE_STAFF
        assert not rbac.has_permission(sample_member, Permission.MANAGE_STAFF)

    def test_has_permission_inactive_member(self, rbac, sample_member):
        """Test permesso per membro inattivo."""
        sample_member.is_active = False
        assert not rbac.has_permission(sample_member, Permission.VIEW_CONTENT)

    def test_has_role_level(self, rbac, sample_member, admin_member):
        """Test has_role_level."""
        # Translator ha almeno livello CONTRIBUTOR
        assert rbac.has_role_level(sample_member, StaffRole.CONTRIBUTOR)

        # Translator non ha almeno livello MODERATOR
        assert not rbac.has_role_level(sample_member, StaffRole.MODERATOR)

        # Admin ha almeno livello ADMIN
        assert rbac.has_role_level(admin_member, StaffRole.ADMIN)

    def test_can_manage(self, rbac, admin_member, sample_member):
        """Test can_manage."""
        # Admin puo' gestire translator
        assert rbac.can_manage(admin_member, sample_member)

        # Translator non puo' gestire admin
        assert not rbac.can_manage(sample_member, admin_member)

    def test_can_access_project(self, rbac, sample_member, admin_member):
        """Test accesso progetto."""
        # Member ha accesso ai suoi progetti
        assert rbac.can_access_project(sample_member, "project-1")
        assert not rbac.can_access_project(sample_member, "project-999")

        # Admin ha accesso a tutti
        assert rbac.can_access_project(admin_member, "any-project")

    def test_grant_revoke_permission(self, rbac, sample_member):
        """Test grant/revoke permesso."""
        # Grant
        rbac.grant_permission(sample_member, Permission.EXPORT_DATA)
        assert Permission.EXPORT_DATA.value in sample_member.permissions

        # Revoke
        rbac.revoke_permission(sample_member, Permission.EXPORT_DATA)
        assert Permission.EXPORT_DATA.value not in sample_member.permissions

    def test_change_role(self, rbac, sample_member):
        """Test cambio ruolo."""
        rbac.change_role(sample_member, StaffRole.REVIEWER)
        assert sample_member.role == StaffRole.REVIEWER.value


# ==================== AuditLog Tests ====================

class TestAuditLog:
    """Test per AuditLog."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_dir):
        """Setup per ogni test."""
        AuditLog._reset_for_testing()
        self.temp_dir = temp_dir

    @pytest.mark.asyncio
    async def test_audit_log_init(self, temp_dir):
        """Test inizializzazione audit log."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        assert audit is not None
        assert os.path.exists(db_path)

    @pytest.mark.asyncio
    async def test_log_action(self, temp_dir):
        """Test logging azione."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        entry = await audit.log(
            action=AuditAction.CONTRIBUTION_CREATED,
            actor_id="user-001",
            target_type="contribution",
            target_id="contrib-001",
            details={"title": "Test"},
        )

        assert entry is not None
        assert entry.action == AuditAction.CONTRIBUTION_CREATED.value
        assert entry.actor_id == "user-001"

    @pytest.mark.asyncio
    async def test_get_entry(self, temp_dir):
        """Test recupero entry."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        created = await audit.log(
            action=AuditAction.STAFF_MEMBER_ADDED,
            actor_id="admin",
            target_type="staff_member",
            target_id="member-001",
        )

        retrieved = await audit.get(created.id)

        assert retrieved is not None
        assert retrieved.id == created.id

    @pytest.mark.asyncio
    async def test_query_by_actor(self, temp_dir):
        """Test query per attore."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        # Log multiple actions
        await audit.log(AuditAction.LOGIN, "user-001", "session", "s1")
        await audit.log(AuditAction.CONTRIBUTION_CREATED, "user-001", "contribution", "c1")
        await audit.log(AuditAction.LOGIN, "user-002", "session", "s2")

        results = await audit.query(actor_id="user-001")

        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_query_by_action(self, temp_dir):
        """Test query per azione."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        await audit.log(AuditAction.LOGIN, "user-001", "session", "s1")
        await audit.log(AuditAction.LOGOUT, "user-001", "session", "s1")

        results = await audit.query(action=AuditAction.LOGIN)

        assert len(results) == 1
        assert results[0].action == AuditAction.LOGIN.value

    @pytest.mark.asyncio
    async def test_verify_integrity(self, temp_dir):
        """Test verifica integrita hash chain."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        await audit.log(AuditAction.LOGIN, "user-001", "session", "s1")
        await audit.log(AuditAction.LOGIN, "user-002", "session", "s2")

        result = await audit.verify_integrity()

        assert result["valid"] is True
        assert result["total_entries"] == 2
        assert result["verified_entries"] == 2

    @pytest.mark.asyncio
    async def test_export_json(self, temp_dir):
        """Test export JSON."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        await audit.log(AuditAction.LOGIN, "user-001", "session", "s1")

        export_path = os.path.join(temp_dir, "export.json")
        count = await audit.export_json(export_path)

        assert count >= 1
        assert os.path.exists(export_path)

    @pytest.mark.asyncio
    async def test_stats(self, temp_dir):
        """Test statistiche."""
        db_path = os.path.join(temp_dir, "audit.db")
        audit = await AuditLog.get_instance(db_path)

        await audit.log(AuditAction.LOGIN, "user-001", "session", "s1")

        stats = await audit.get_stats()

        assert stats["total_entries"] >= 1


# ==================== VersionControl Tests ====================

class TestVersionControl:
    """Test per VersionControl."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_dir):
        """Setup per ogni test."""
        VersionControl._reset_for_testing()
        self.temp_dir = temp_dir

    @pytest.mark.asyncio
    async def test_version_control_init(self, temp_dir):
        """Test inizializzazione version control."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        assert vc is not None
        assert os.path.exists(db_path)

    @pytest.mark.asyncio
    async def test_create_first_version(self, temp_dir):
        """Test creazione prima versione."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        version = await vc.create_version(
            contribution_id="contrib-001",
            content={"text": "Hello"},
            created_by="user-001",
            change_summary="Initial version",
        )

        assert version is not None
        assert version.version_number == 1
        assert version.content == {"text": "Hello"}

    @pytest.mark.asyncio
    async def test_create_subsequent_versions(self, temp_dir):
        """Test versioni successive."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        contrib_id = "contrib-002"

        v1 = await vc.create_version(contrib_id, {"text": "V1"}, "user-001", "V1")
        v2 = await vc.create_version(contrib_id, {"text": "V2"}, "user-001", "V2")
        v3 = await vc.create_version(contrib_id, {"text": "V3"}, "user-001", "V3")

        assert v1.version_number == 1
        assert v2.version_number == 2
        assert v3.version_number == 3

    @pytest.mark.asyncio
    async def test_get_version(self, temp_dir):
        """Test recupero versione specifica."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        contrib_id = "contrib-003"
        await vc.create_version(contrib_id, {"text": "V1"}, "user-001", "V1")
        await vc.create_version(contrib_id, {"text": "V2"}, "user-001", "V2")

        v1 = await vc.get_version(contrib_id, 1)
        v2 = await vc.get_version(contrib_id, 2)

        assert v1.content == {"text": "V1"}
        assert v2.content == {"text": "V2"}

    @pytest.mark.asyncio
    async def test_get_latest_version(self, temp_dir):
        """Test recupero ultima versione."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        contrib_id = "contrib-004"
        await vc.create_version(contrib_id, {"text": "V1"}, "user-001", "V1")
        await vc.create_version(contrib_id, {"text": "V2"}, "user-001", "V2")

        latest = await vc.get_latest_version(contrib_id)

        assert latest.version_number == 2
        assert latest.content == {"text": "V2"}

    @pytest.mark.asyncio
    async def test_get_history(self, temp_dir):
        """Test storico versioni."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        contrib_id = "contrib-005"
        await vc.create_version(contrib_id, {"text": "V1"}, "user-001", "V1")
        await vc.create_version(contrib_id, {"text": "V2"}, "user-001", "V2")
        await vc.create_version(contrib_id, {"text": "V3"}, "user-001", "V3")

        history = await vc.get_history(contrib_id)

        assert len(history) == 3
        # Ordine decrescente (piu' recente prima)
        assert history[0].version_number == 3
        assert history[2].version_number == 1

    @pytest.mark.asyncio
    async def test_compute_diff(self, temp_dir):
        """Test calcolo diff."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        old = {"title": "Hello", "text": "World"}
        new = {"title": "Hello", "text": "Universe", "author": "John"}

        diff = vc.compute_diff(old, new)

        assert "author" in diff.added_fields
        assert "text" in diff.modified_fields
        assert diff.modified_fields["text"]["old"] == "World"
        assert diff.modified_fields["text"]["new"] == "Universe"

    @pytest.mark.asyncio
    async def test_restore_version(self, temp_dir):
        """Test ripristino versione."""
        db_path = os.path.join(temp_dir, "versions.db")
        vc = await VersionControl.get_instance(db_path)

        contrib_id = "contrib-006"
        await vc.create_version(contrib_id, {"text": "Original"}, "user-001", "V1")
        await vc.create_version(contrib_id, {"text": "Changed"}, "user-001", "V2")

        # Ripristina V1
        restored = await vc.restore_version(contrib_id, 1, "user-002")

        assert restored.version_number == 3  # Nuova versione
        assert restored.content == {"text": "Original"}
        assert "Ripristinato" in restored.change_summary


# ==================== ReviewWorkflow Tests ====================

class TestReviewWorkflow:
    """Test per ReviewWorkflow."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_dir):
        """Setup per ogni test."""
        ReviewWorkflow._reset_for_testing()
        self.temp_dir = temp_dir

    @pytest.mark.asyncio
    async def test_workflow_init(self, temp_dir):
        """Test inizializzazione workflow."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        assert workflow is not None
        assert os.path.exists(db_path)

    @pytest.mark.asyncio
    async def test_submit_for_review(self, temp_dir):
        """Test submit per review."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        request = await workflow.submit_for_review(
            contribution_id="contrib-001",
            requester_id="user-001",
            priority="normal",
        )

        assert request is not None
        assert request.status == ReviewStatus.PENDING.value

    @pytest.mark.asyncio
    async def test_assign_reviewer(self, temp_dir):
        """Test assegnazione reviewer."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        await workflow.submit_for_review("contrib-002", "user-001")
        request = await workflow.assign_reviewer("contrib-002", "reviewer-001")

        assert request is not None
        assert request.assigned_reviewer_id == "reviewer-001"

    @pytest.mark.asyncio
    async def test_start_review(self, temp_dir):
        """Test inizio revisione."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        await workflow.submit_for_review("contrib-003", "user-001")
        request = await workflow.start_review("contrib-003", "reviewer-001")

        assert request is not None
        assert request.status == ReviewStatus.IN_PROGRESS.value
        assert request.started_at is not None

    @pytest.mark.asyncio
    async def test_complete_review_approved(self, temp_dir):
        """Test completamento review con approvazione."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        await workflow.submit_for_review("contrib-004", "user-001")
        await workflow.start_review("contrib-004", "reviewer-001")
        request = await workflow.complete_review(
            "contrib-004",
            "reviewer-001",
            ReviewDecision.APPROVED,
            "Ottimo lavoro",
        )

        assert request is not None
        assert request.status == ReviewStatus.COMPLETED.value
        assert request.decision == ReviewDecision.APPROVED.value

    @pytest.mark.asyncio
    async def test_add_comment(self, temp_dir):
        """Test aggiunta commento."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        comment = await workflow.add_comment(
            contribution_id="contrib-005",
            reviewer_id="reviewer-001",
            version_number=1,
            comment="Controlla questa frase",
            line_reference="line:10",
        )

        assert comment is not None
        assert comment.status == "open"

    @pytest.mark.asyncio
    async def test_resolve_comment(self, temp_dir):
        """Test risoluzione commento."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        comment = await workflow.add_comment(
            contribution_id="contrib-006",
            reviewer_id="reviewer-001",
            version_number=1,
            comment="Da correggere",
        )

        resolved = await workflow.resolve_comment(
            comment.id,
            resolved_by="user-001",
            status="resolved",
        )

        assert resolved.status == "resolved"
        assert resolved.resolved_by == "user-001"

    @pytest.mark.asyncio
    async def test_get_pending_reviews(self, temp_dir):
        """Test lista review in attesa."""
        db_path = os.path.join(temp_dir, "reviews.db")
        workflow = await ReviewWorkflow.get_instance(db_path)

        await workflow.submit_for_review("contrib-007", "user-001", priority="high")
        await workflow.submit_for_review("contrib-008", "user-002", priority="normal")

        pending = await workflow.get_pending_reviews()

        assert len(pending) == 2
        # High priority prima
        assert pending[0].contribution_id == "contrib-007"


# ==================== ContributionManager Tests ====================

class TestContributionManager:
    """Test per ContributionManager (facade)."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_dir):
        """Setup per ogni test."""
        ContributionManager._reset_for_testing()
        self.temp_dir = temp_dir

    @pytest.mark.asyncio
    async def test_manager_init(self, temp_dir):
        """Test inizializzazione manager."""
        manager = await ContributionManager.get_instance(temp_dir)

        assert manager is not None

    @pytest.mark.asyncio
    async def test_add_staff_member(self, temp_dir):
        """Test aggiunta staff member."""
        manager = await ContributionManager.get_instance(temp_dir)

        member = await manager.add_staff_member(
            user_id="user-001",
            username="mario",
            email="mario@test.com",
            role=StaffRole.TRANSLATOR,
        )

        assert member is not None
        assert member.username == "mario"
        assert member.role == StaffRole.TRANSLATOR.value

    @pytest.mark.asyncio
    async def test_get_staff_member(self, temp_dir):
        """Test recupero staff member."""
        manager = await ContributionManager.get_instance(temp_dir)

        created = await manager.add_staff_member(
            user_id="user-002",
            username="luigi",
            email="luigi@test.com",
            role=StaffRole.REVIEWER,
        )

        retrieved = await manager.get_staff_member(created.id)

        assert retrieved is not None
        assert retrieved.username == "luigi"

    @pytest.mark.asyncio
    async def test_create_contribution(self, temp_dir):
        """Test creazione contributo."""
        manager = await ContributionManager.get_instance(temp_dir)

        member = await manager.add_staff_member(
            user_id="user-003",
            username="translator1",
            email="t1@test.com",
            role=StaffRole.TRANSLATOR,
        )

        contrib = await manager.create_contribution(
            contributor_id=member.id,
            title="Traduzione oi-zuki",
            content_type=ContributionType.TRANSLATION,
            content={"source": "oi-zuki", "translation": "pugno avanzando"},
        )

        assert contrib is not None
        assert contrib.title == "Traduzione oi-zuki"
        assert contrib.status == ContributionStatus.DRAFT.value

    @pytest.mark.asyncio
    async def test_update_contribution(self, temp_dir):
        """Test aggiornamento contributo."""
        manager = await ContributionManager.get_instance(temp_dir)

        member = await manager.add_staff_member(
            user_id="user-004",
            username="translator2",
            email="t2@test.com",
            role=StaffRole.TRANSLATOR,
        )

        contrib = await manager.create_contribution(
            contributor_id=member.id,
            title="Test",
            content_type=ContributionType.TRANSLATION,
            content={"v": 1},
        )

        updated = await manager.update_contribution(
            contribution_id=contrib.id,
            editor_id=member.id,
            content={"v": 2},
            change_summary="Aggiornato",
        )

        assert updated is not None
        assert updated.content == {"v": 2}
        assert updated.current_version == 2

    @pytest.mark.asyncio
    async def test_workflow_submit_approve(self, temp_dir):
        """Test workflow completo submit -> approve."""
        manager = await ContributionManager.get_instance(temp_dir)

        # Crea translator
        translator = await manager.add_staff_member(
            user_id="user-005",
            username="translator3",
            email="t3@test.com",
            role=StaffRole.TRANSLATOR,
        )

        # Crea reviewer
        reviewer = await manager.add_staff_member(
            user_id="user-006",
            username="reviewer1",
            email="r1@test.com",
            role=StaffRole.REVIEWER,
        )

        # Crea contributo
        contrib = await manager.create_contribution(
            contributor_id=translator.id,
            title="Traduzione",
            content_type=ContributionType.TRANSLATION,
            content={"text": "traduzione"},
        )

        # Submit
        submitted = await manager.submit_for_review(contrib.id, translator.id)
        assert submitted.status == ContributionStatus.PENDING_REVIEW.value

        # Approve
        approved = await manager.approve(contrib.id, reviewer.id)
        assert approved.status == ContributionStatus.APPROVED.value
        assert approved.approver_id == reviewer.id

    @pytest.mark.asyncio
    async def test_workflow_reject(self, temp_dir):
        """Test workflow reject."""
        manager = await ContributionManager.get_instance(temp_dir)

        translator = await manager.add_staff_member(
            user_id="user-007", username="t4", email="t4@test.com",
            role=StaffRole.TRANSLATOR,
        )

        reviewer = await manager.add_staff_member(
            user_id="user-008", username="r2", email="r2@test.com",
            role=StaffRole.REVIEWER,
        )

        contrib = await manager.create_contribution(
            contributor_id=translator.id,
            title="Test",
            content_type=ContributionType.TRANSLATION,
            content={},
        )

        await manager.submit_for_review(contrib.id, translator.id)
        rejected = await manager.reject(contrib.id, reviewer.id, "Non conforme")

        assert rejected.status == ContributionStatus.REJECTED.value

    @pytest.mark.asyncio
    async def test_permission_denied(self, temp_dir):
        """Test permesso negato."""
        manager = await ContributionManager.get_instance(temp_dir)

        viewer = await manager.add_staff_member(
            user_id="user-009", username="viewer1", email="v1@test.com",
            role=StaffRole.VIEWER,  # Solo lettura
        )

        with pytest.raises(PermissionError):
            await manager.create_contribution(
                contributor_id=viewer.id,
                title="Test",
                content_type=ContributionType.TRANSLATION,
                content={},
            )

    @pytest.mark.asyncio
    async def test_get_contribution_history(self, temp_dir):
        """Test storico versioni contributo."""
        manager = await ContributionManager.get_instance(temp_dir)

        member = await manager.add_staff_member(
            user_id="user-010", username="t5", email="t5@test.com",
            role=StaffRole.TRANSLATOR,
        )

        contrib = await manager.create_contribution(
            contributor_id=member.id,
            title="Test",
            content_type=ContributionType.TRANSLATION,
            content={"v": 1},
        )

        await manager.update_contribution(
            contrib.id, member.id, content={"v": 2}, change_summary="V2"
        )

        history = await manager.get_contribution_history(contrib.id)

        assert len(history) == 2

    @pytest.mark.asyncio
    async def test_get_stats(self, temp_dir):
        """Test statistiche sistema."""
        manager = await ContributionManager.get_instance(temp_dir)

        await manager.add_staff_member(
            user_id="user-011", username="t6", email="t6@test.com",
            role=StaffRole.TRANSLATOR,
        )

        stats = await manager.get_stats()

        assert "staff" in stats
        assert "contributions" in stats
        assert stats["staff"]["total"] >= 1


# ==================== Integration Tests ====================

class TestIntegration:
    """Test di integrazione tra componenti."""

    @pytest.fixture(autouse=True)
    def setup(self, temp_dir):
        """Setup per ogni test."""
        ContributionManager._reset_for_testing()
        self.temp_dir = temp_dir

    @pytest.mark.asyncio
    async def test_full_workflow_with_audit(self, temp_dir):
        """Test workflow completo con audit log."""
        manager = await ContributionManager.get_instance(temp_dir)

        # Setup
        translator = await manager.add_staff_member(
            user_id="user-int-001", username="translator", email="t@test.com",
            role=StaffRole.TRANSLATOR,
        )

        reviewer = await manager.add_staff_member(
            user_id="user-int-002", username="reviewer", email="r@test.com",
            role=StaffRole.REVIEWER,
        )

        # Create
        contrib = await manager.create_contribution(
            contributor_id=translator.id,
            title="Integration Test",
            content_type=ContributionType.TRANSLATION,
            content={"original": "テスト", "translation": "test"},
        )

        # Submit & Approve
        await manager.submit_for_review(contrib.id, translator.id)
        await manager.approve(contrib.id, reviewer.id)

        # Check audit log
        audit_entries = await manager.get_audit_log(contribution_id=contrib.id)

        actions = [e.action for e in audit_entries]
        assert AuditAction.CONTRIBUTION_CREATED.value in actions
        assert AuditAction.CONTRIBUTION_SUBMITTED.value in actions
        assert AuditAction.CONTRIBUTION_APPROVED.value in actions


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

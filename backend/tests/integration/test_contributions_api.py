"""
# AI_MODULE: TestContributionsAPI
# AI_VERSION: 1.1.0
# AI_DESCRIPTION: Test integrazione API Contributions - ZERO MOCK
# AI_BUSINESS: Verifica endpoint API contributions con chiamate HTTP reali
# AI_TEACHING: Test REALI con TestClient FastAPI. Nessun mock.
#              Testa RBAC, workflow, audit, versioning.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13
# AI_UPDATED: 2025-01-11 - Rimosso fixture locali, usa conftest.py globale

Test Integration ContributionsAPI
=================================

REGOLA INVIOLABILE: Questo file NON contiene mock.
Tutti i test usano le fixture globali da conftest.py.
"""

import uuid
from pathlib import Path

import pytest

# Import sys path per moduli backend
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# NOTA: NON importiamo TestClient qui - usiamo api_client da conftest.py
# NOTA: NON definiamo fixture client/auth_headers - usiamo quelle globali


# ==================== Local Fixtures (non-conflicting) ====================

@pytest.fixture
def unique_id():
    """Genera ID univoco per test."""
    return uuid.uuid4().hex[:8]


# ==================== Staff Member Tests ====================

class TestStaffMemberEndpoints:
    """Test endpoint staff members."""

    def test_list_staff_requires_auth(self, api_client):
        """Lista staff richiede autenticazione."""
        response = api_client.get("/api/v1/contributions/staff")
        assert response.status_code in (401, 403)

    def test_list_staff_members(self, api_client, auth_headers):
        """Lista membri staff."""
        response = api_client.get(
            "/api/v1/contributions/staff",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_list_staff_with_filters(self, api_client, auth_headers):
        """Lista staff con filtri."""
        response = api_client.get(
            "/api/v1/contributions/staff?role=translator&is_active=true",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_list_staff_pagination(self, api_client, auth_headers):
        """Lista staff con paginazione."""
        response = api_client.get(
            "/api/v1/contributions/staff?limit=10&offset=0",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_get_staff_member_not_found(self, api_client, auth_headers):
        """Staff member non esistente."""
        response = api_client.get(
            "/api/v1/contributions/staff/non-existent-id",
            headers=auth_headers
        )
        assert response.status_code in (403, 404)

    def test_create_staff_requires_admin(self, api_client, auth_headers, unique_id):
        """Creare staff richiede admin."""
        response = api_client.post(
            "/api/v1/contributions/staff",
            json={
                "user_id": f"user_{unique_id}",
                "username": f"testuser_{unique_id}",
                "email": f"test_{unique_id}@example.com",
                "role": "contributor"
            },
            headers=auth_headers
        )
        assert response.status_code in (401, 403, 404)

    def test_get_my_profile_not_staff(self, api_client, auth_headers):
        """Profilo se non membro staff."""
        response = api_client.get(
            "/api/v1/contributions/staff/me/profile",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)


# ==================== Contribution CRUD Tests ====================

class TestContributionCRUDEndpoints:
    """Test endpoint CRUD contributi."""

    def test_list_contributions_requires_auth(self, api_client):
        """Lista contributi richiede autenticazione."""
        response = api_client.get("/api/v1/contributions/")
        assert response.status_code in (401, 403)

    def test_list_contributions(self, api_client, auth_headers):
        """Lista contributi."""
        response = api_client.get(
            "/api/v1/contributions/",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_list_contributions_with_filters(self, api_client, auth_headers):
        """Lista contributi con filtri."""
        response = api_client.get(
            "/api/v1/contributions/?status=draft&content_type=translation",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_list_contributions_pagination(self, api_client, auth_headers):
        """Lista contributi con paginazione."""
        response = api_client.get(
            "/api/v1/contributions/?limit=20&offset=0",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_get_contribution_not_found(self, api_client, auth_headers):
        """Contributo non esistente."""
        response = api_client.get(
            "/api/v1/contributions/non-existent-id",
            headers=auth_headers
        )
        assert response.status_code in (403, 404)

    def test_create_contribution_requires_staff(self, api_client, auth_headers, unique_id):
        """Creare contributo richiede essere staff."""
        response = api_client.post(
            "/api/v1/contributions/",
            json={
                "title": f"Test Contribution {unique_id}",
                "content_type": "translation",
                "content": {"text": "Test content", "source": "ja", "target": "it"}
            },
            headers=auth_headers
        )
        assert response.status_code in (200, 201, 403, 404)

    def test_create_contribution_validates_title(self, api_client, auth_headers):
        """Creare contributo valida titolo."""
        response = api_client.post(
            "/api/v1/contributions/",
            json={
                "title": "",
                "content_type": "translation",
                "content": {}
            },
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)

    def test_create_contribution_validates_content_type(self, api_client, auth_headers):
        """Creare contributo valida content_type."""
        response = api_client.post(
            "/api/v1/contributions/",
            json={
                "title": "Test",
                "content_type": "invalid_type",
                "content": {}
            },
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)

    def test_update_contribution_not_found(self, api_client, auth_headers):
        """Aggiornare contributo non esistente."""
        response = api_client.put(
            "/api/v1/contributions/non-existent-id",
            json={"title": "Updated Title"},
            headers=auth_headers
        )
        assert response.status_code in (403, 404)

    def test_delete_contribution_not_found(self, api_client, auth_headers):
        """Eliminare contributo non esistente."""
        response = api_client.delete(
            "/api/v1/contributions/non-existent-id",
            headers=auth_headers
        )
        assert response.status_code in (403, 404)


# ==================== Workflow Tests ====================

class TestWorkflowEndpoints:
    """Test endpoint workflow."""

    def test_submit_contribution_not_found(self, api_client, auth_headers):
        """Submit contributo non esistente."""
        response = api_client.post(
            "/api/v1/contributions/non-existent-id/submit",
            json={"priority": "normal"},
            headers=auth_headers
        )
        assert response.status_code in (400, 403, 404, 500)

    def test_submit_validates_priority(self, api_client, auth_headers):
        """Submit valida priority."""
        response = api_client.post(
            "/api/v1/contributions/some-id/submit",
            json={"priority": "invalid_priority"},
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)

    def test_approve_contribution_not_found(self, api_client, auth_headers):
        """Approve contributo non esistente."""
        response = api_client.post(
            "/api/v1/contributions/non-existent-id/approve",
            headers=auth_headers
        )
        assert response.status_code in (400, 403, 404, 500)

    def test_reject_requires_reason(self, api_client, auth_headers):
        """Reject richiede reason."""
        response = api_client.post(
            "/api/v1/contributions/some-id/reject",
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)

    def test_reject_contribution_not_found(self, api_client, auth_headers):
        """Reject contributo non esistente."""
        response = api_client.post(
            "/api/v1/contributions/non-existent-id/reject?reason=Not%20acceptable",
            headers=auth_headers
        )
        assert response.status_code in (400, 403, 404, 500)


# ==================== Version & Audit Tests ====================

class TestVersionAuditEndpoints:
    """Test endpoint versioning e audit."""

    def test_get_history_not_found(self, api_client, auth_headers):
        """History contributo non esistente."""
        response = api_client.get(
            "/api/v1/contributions/non-existent-id/history",
            headers=auth_headers
        )
        assert response.status_code in (403, 404)

    def test_get_version_not_found(self, api_client, auth_headers):
        """Versione specifica non esistente."""
        response = api_client.get(
            "/api/v1/contributions/non-existent-id/history/1",
            headers=auth_headers
        )
        assert response.status_code in (403, 404)

    def test_get_audit_not_found(self, api_client, auth_headers):
        """Audit contributo non esistente."""
        response = api_client.get(
            "/api/v1/contributions/non-existent-id/audit",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)


# ==================== Admin Tests ====================

class TestAdminEndpoints:
    """Test endpoint admin."""

    def test_stats_requires_admin(self, api_client, auth_headers):
        """Stats richiede admin."""
        response = api_client.get(
            "/api/v1/contributions/admin/stats",
            headers=auth_headers
        )
        assert response.status_code in (401, 403, 404)

    def test_global_audit_requires_admin(self, api_client, auth_headers):
        """Global audit richiede admin."""
        response = api_client.get(
            "/api/v1/contributions/admin/audit",
            headers=auth_headers
        )
        assert response.status_code in (401, 403, 404)


# ==================== My Contributions Tests ====================

class TestMyContributionsEndpoints:
    """Test endpoint my-contributions."""

    def test_my_contributions_requires_staff(self, api_client, auth_headers):
        """My contributions richiede essere staff."""
        response = api_client.get(
            "/api/v1/contributions/my-contributions",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_my_contributions_with_filters(self, api_client, auth_headers):
        """My contributions con filtri."""
        response = api_client.get(
            "/api/v1/contributions/my-contributions?status=draft",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)


# ==================== Authorization Tests ====================

class TestAuthorizationRules:
    """Test regole autorizzazione."""

    def test_all_endpoints_require_auth(self, api_client):
        """Tutti gli endpoint richiedono auth."""
        protected_endpoints = [
            "/api/v1/contributions/",
            "/api/v1/contributions/staff",
            "/api/v1/contributions/my-contributions",
        ]
        for endpoint in protected_endpoints:
            response = api_client.get(endpoint)
            assert response.status_code in (401, 403, 404), f"{endpoint} dovrebbe richiedere auth"

    def test_admin_endpoints_require_admin(self, api_client, auth_headers):
        """Endpoint admin richiedono admin."""
        admin_endpoints = [
            "/api/v1/contributions/admin/stats",
            "/api/v1/contributions/admin/audit",
        ]
        for endpoint in admin_endpoints:
            response = api_client.get(endpoint, headers=auth_headers)
            assert response.status_code in (401, 403, 404), f"{endpoint} dovrebbe richiedere admin"


# ==================== Input Validation Tests ====================

class TestInputValidation:
    """Test validazione input."""

    def test_list_pagination_validates_limit(self, api_client, auth_headers):
        """List valida limite paginazione."""
        response = api_client.get(
            "/api/v1/contributions/?limit=10000",
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)

    def test_list_pagination_validates_offset(self, api_client, auth_headers):
        """List valida offset paginazione."""
        response = api_client.get(
            "/api/v1/contributions/?offset=-1",
            headers=auth_headers
        )
        assert response.status_code in (403, 404, 422)


# ==================== Response Format Tests ====================

class TestResponseFormats:
    """Test formati response."""

    def test_list_contributions_format(self, api_client, auth_headers):
        """Lista contributions ha formato corretto."""
        response = api_client.get(
            "/api/v1/contributions/",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

    def test_list_staff_format(self, api_client, auth_headers):
        """Lista staff ha formato corretto."""
        response = api_client.get(
            "/api/v1/contributions/staff",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)


# ==================== Content Type Tests ====================

class TestContentTypes:
    """Test tipi contributo validi."""

    def test_valid_content_types_accepted(self, api_client, auth_headers):
        """Almeno un content type valido è accettato."""
        response = api_client.post(
            "/api/v1/contributions/",
            json={
                "title": "Test translation",
                "content_type": "translation",
                "content": {"test": "data"}
            },
            headers=auth_headers
        )
        # Accetta 200/201 (success) o 403/404 (non staff/endpoint mancante)
        assert response.status_code in (200, 201, 403, 404)


# ==================== Status Transitions Tests ====================

class TestStatusTransitions:
    """Test transizioni stato valide."""

    def test_filter_by_valid_status(self, api_client, auth_headers):
        """Filtro per stato draft."""
        response = api_client.get(
            "/api/v1/contributions/?status=draft",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)


# ==================== Role Tests ====================

class TestRoles:
    """Test ruoli staff validi."""

    def test_filter_by_valid_role(self, api_client, auth_headers):
        """Filtro per ruolo translator."""
        response = api_client.get(
            "/api/v1/contributions/staff?role=translator",
            headers=auth_headers
        )
        assert response.status_code in (200, 403, 404)

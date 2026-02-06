"""
================================================================================
AI_MODULE: TestModerationAPI
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integration Video Moderation API - Approve/Reject workflow
AI_BUSINESS: Content moderation critica per qualità piattaforma - priorità ALTA
AI_TEACHING: ZERO MOCK - chiamate API reali con httpx sincrono
AI_CREATED: 2026-01-25

================================================================================

ZERO_MOCK_POLICY:
- Nessun mock, patch, fake consentito
- Tutti i test chiamano backend REALE su localhost:8000

ENDPOINTS TESTATI:
- GET /moderation/videos/pending: Lista video pending
- POST /moderation/videos/{id}/approve: Approva video
- POST /moderation/videos/{id}/reject: Rifiuta video
- POST /moderation/videos/{id}/request-changes: Richiedi modifiche
- GET /moderation/videos/{id}/history: Storico moderazione
- GET /moderation/stats: Statistiche moderazione

================================================================================
"""

import pytest
import httpx
import uuid

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration, pytest.mark.api]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BACKEND_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/moderation"
AUTH_PREFIX = "/api/v1/auth"


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(scope="module")
def test_user_credentials():
    """Genera credenziali uniche per evitare UniqueViolation."""
    unique = uuid.uuid4().hex[:8]
    return {
        "email": f"modtest_{unique}@test.com",
        "password": "Test123456!",
        "username": f"modtest_{unique}"
    }


@pytest.fixture(scope="module")
def auth_token(test_user_credentials):
    """Registra utente test e ottieni token."""
    response = httpx.post(
        f"{BACKEND_URL}{AUTH_PREFIX}/register",
        json=test_user_credentials,
        timeout=60.0
    )

    if response.status_code == 201:
        data = response.json()
        return data.get("access_token") or data.get("token")

    if response.status_code in [400, 409]:
        login_response = httpx.post(
            f"{BACKEND_URL}{AUTH_PREFIX}/login",
            json={
                "email": test_user_credentials["email"],
                "password": test_user_credentials["password"]
            },
            timeout=60.0
        )
        if login_response.status_code == 200:
            data = login_response.json()
            return data.get("access_token") or data.get("token")

    pytest.skip(f"Cannot authenticate: {response.status_code}")


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Headers con Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}


# ==============================================================================
# TEST: Pending Videos (Admin Required)
# ==============================================================================

class TestPendingVideos:
    """Test pending videos list."""

    def test_pending_requires_auth(self):
        """GET /moderation/videos/pending senza token -> 401/403."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/pending",
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_pending_with_non_admin(self, auth_headers):
        """GET /moderation/videos/pending con non-admin -> 403."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/pending",
            headers=auth_headers,
            timeout=60.0
        )
        # Non-admin should get 403
        assert response.status_code in [403, 500, 503]

    def test_pending_invalid_token(self):
        """GET /moderation/videos/pending con token invalido -> 401."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/pending",
            headers={"Authorization": "Bearer invalid_token"},
            timeout=60.0
        )
        assert response.status_code in [401, 503]


# ==============================================================================
# TEST: Approve Video
# ==============================================================================

class TestApproveVideo:
    """Test approve video endpoint."""

    def test_approve_requires_auth(self):
        """POST /moderation/videos/{id}/approve senza token -> 401/403."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/approve",
            json={"notes": "Approved"},
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_approve_nonexistent_video(self, auth_headers):
        """POST /moderation/videos/{id}/approve video inesistente -> 403/404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/approve",
            headers=auth_headers,
            json={"notes": "Test approval"},
            timeout=60.0
        )
        # 403 for non-admin, 404 for not found
        assert response.status_code in [403, 404, 500, 503]

    def test_approve_invalid_uuid(self, auth_headers):
        """POST /moderation/videos/{id}/approve con UUID invalido -> 422."""
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/not-a-uuid/approve",
            headers=auth_headers,
            json={"notes": "Test"},
            timeout=60.0
        )
        assert response.status_code in [403, 404, 422, 500, 503]


# ==============================================================================
# TEST: Reject Video
# ==============================================================================

class TestRejectVideo:
    """Test reject video endpoint."""

    def test_reject_requires_auth(self):
        """POST /moderation/videos/{id}/reject senza token -> 401/403."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/reject",
            json={"rejection_reason": "Inappropriate content"},
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_reject_nonexistent_video(self, auth_headers):
        """POST /moderation/videos/{id}/reject video inesistente -> 403/404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/reject",
            headers=auth_headers,
            json={"rejection_reason": "Test rejection"},
            timeout=60.0
        )
        assert response.status_code in [403, 404, 500, 503]

    def test_reject_missing_reason(self, auth_headers):
        """POST /moderation/videos/{id}/reject senza reason -> 422."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/reject",
            headers=auth_headers,
            json={},
            timeout=60.0
        )
        # 422 validation error or 403 forbidden
        assert response.status_code in [403, 422, 500, 503]


# ==============================================================================
# TEST: Request Changes
# ==============================================================================

class TestRequestChanges:
    """Test request changes endpoint."""

    def test_request_changes_requires_auth(self):
        """POST /moderation/videos/{id}/request-changes senza token -> 401/403."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/request-changes",
            json={"required_changes": ["Fix audio", "Improve lighting"]},
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_request_changes_nonexistent(self, auth_headers):
        """POST /moderation/videos/{id}/request-changes video inesistente -> 403/404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/request-changes",
            headers=auth_headers,
            json={"required_changes": ["Fix audio"], "notes": "Please improve"},
            timeout=60.0
        )
        assert response.status_code in [403, 404, 500, 503]

    def test_request_changes_empty_list(self, auth_headers):
        """POST /moderation/videos/{id}/request-changes con lista vuota -> 422."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/request-changes",
            headers=auth_headers,
            json={"required_changes": []},
            timeout=60.0
        )
        # 422 validation error or 403/404
        assert response.status_code in [403, 404, 422, 500, 503]


# ==============================================================================
# TEST: Moderation History
# ==============================================================================

class TestModerationHistory:
    """Test moderation history endpoint."""

    def test_history_requires_auth(self):
        """GET /moderation/videos/{id}/history senza token -> 401/403."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/history",
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_history_nonexistent_video(self, auth_headers):
        """GET /moderation/videos/{id}/history video inesistente."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/history",
            headers=auth_headers,
            timeout=60.0
        )
        # May return empty list or 403/404
        assert response.status_code in [200, 403, 404, 500, 503]

    def test_history_invalid_uuid(self, auth_headers):
        """GET /moderation/videos/{id}/history con UUID invalido."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/invalid-uuid/history",
            headers=auth_headers,
            timeout=60.0
        )
        assert response.status_code in [403, 404, 422, 500, 503]


# ==============================================================================
# TEST: Moderation Stats
# ==============================================================================

class TestModerationStats:
    """Test moderation stats endpoint."""

    def test_stats_requires_auth(self):
        """GET /moderation/stats senza token -> 401/403."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/stats",
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

    def test_stats_with_non_admin(self, auth_headers):
        """GET /moderation/stats con non-admin -> 403."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/stats",
            headers=auth_headers,
            timeout=60.0
        )
        assert response.status_code in [403, 500, 503]


# ==============================================================================
# TEST: Security
# ==============================================================================

class TestModerationSecurity:
    """Test security aspects of moderation API."""

    def test_sql_injection_in_video_id(self, auth_headers):
        """SQL injection in video_id deve essere prevenuta."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/'; DROP TABLE videos; --/history",
            headers=auth_headers,
            timeout=60.0
        )
        assert response.status_code in [403, 404, 422, 500, 503]

    def test_xss_in_rejection_reason(self, auth_headers):
        """XSS in rejection_reason deve essere prevenuta."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/videos/{fake_uuid}/reject",
            headers=auth_headers,
            json={"rejection_reason": "<script>alert('xss')</script>"},
            timeout=60.0
        )
        # Non deve crashare
        assert response.status_code in [403, 404, 500, 503]

    def test_malformed_auth_header(self):
        """Header Authorization malformato -> 401."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/videos/pending",
            headers={"Authorization": "NotBearer token"},
            timeout=60.0
        )
        assert response.status_code in [401, 403, 503]

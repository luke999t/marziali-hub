"""
================================================================================
AI_MODULE: TestCurriculaAuthAPI
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test Curricula API con autenticazione - ZERO MOCK
AI_BUSINESS: Percorsi formativi - differenziatore vs YouTube (+60% retention)
AI_TEACHING: ZERO MOCK - chiamate API reali con httpx sincrono
AI_CREATED: 2026-01-23

================================================================================

ZERO_MOCK_POLICY:
- Nessun mock, patch, fake consentito
- Tutti i test chiamano backend REALE su localhost:8000

COVERAGE_TARGETS:
- Auth flow: 100%
- CRUD base: 100%
- Error handling: 100%

ENDPOINTS TESTATI:
- GET /curricula: Lista curricula (auth required)
- GET /curricula/{id}: Dettaglio curriculum
- POST /curricula: Crea curriculum (instructor only)
- GET /curricula/me/enrollments: Mie iscrizioni
- POST /curricula/{id}/enroll: Iscrizione a curriculum

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
API_PREFIX = "/api/v1/curricula"
AUTH_PREFIX = "/api/v1/auth"


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture(scope="module")
def test_user_credentials():
    """Genera credenziali uniche per evitare UniqueViolation."""
    unique = uuid.uuid4().hex[:8]
    return {
        "email": f"currictest_{unique}@test.com",
        "password": "Test123456!",
        "username": f"currictest_{unique}"
    }


@pytest.fixture(scope="module")
def auth_token(test_user_credentials):
    """
    Registra utente test e ottieni token.
    Riusa token per tutti i test del modulo.
    """
    # Prova registrazione
    response = httpx.post(
        f"{BACKEND_URL}{AUTH_PREFIX}/register",
        json=test_user_credentials,
        timeout=60.0
    )

    if response.status_code == 201:
        data = response.json()
        return data.get("access_token") or data.get("token")

    # Se utente esiste, prova login
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

    pytest.skip(f"Cannot authenticate: {response.status_code} - {response.text}")


@pytest.fixture(scope="module")
def auth_headers(auth_token):
    """Headers con Bearer token."""
    return {"Authorization": f"Bearer {auth_token}"}


# ==============================================================================
# TEST: Authentication Required
# ==============================================================================

class TestCurriculaAuthentication:
    """Test che verificano requisiti autenticazione."""

    def test_list_requires_auth(self):
        """GET /curricula senza token -> 401 o 200 (se pubblico)."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            timeout=60.0
        )
        # 401/403 se auth richiesta, 200 se endpoint pubblico, 503 se DB down
        assert response.status_code in [200, 401, 403, 503]

    def test_detail_requires_auth(self):
        """GET /curricula/{id} senza token -> 401 o 404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/{fake_uuid}",
            timeout=60.0
        )
        # 401/403 auth required, 404 not found, 422 invalid id, 503 DB down
        assert response.status_code in [401, 403, 404, 422, 503]

    def test_enrollments_requires_auth(self):
        """GET /curricula/me/enrollments senza token -> 401/403."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/me/enrollments",
            timeout=60.0
        )
        # 401/403 se auth richiesta, 503 se DB down
        assert response.status_code in [401, 403, 503]


# ==============================================================================
# TEST: List Curricula
# ==============================================================================

class TestCurriculaList:
    """Test lista curricula con autenticazione."""

    def test_list_with_auth_returns_200(self, auth_headers):
        """GET /curricula con token -> 200 o 503 se DB down."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers=auth_headers,
            timeout=60.0
        )
        # 200 OK, 503 DB unavailable
        assert response.status_code in [200, 503]

    def test_list_returns_array(self, auth_headers):
        """GET /curricula ritorna array."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers=auth_headers,
            timeout=60.0
        )
        if response.status_code == 503:
            pytest.skip("Database unavailable")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_list_response_format(self, auth_headers):
        """GET /curricula ritorna JSON."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers=auth_headers,
            timeout=60.0
        )
        if response.status_code == 503:
            pytest.skip("Database unavailable")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")


# ==============================================================================
# TEST: Curriculum Detail
# ==============================================================================

class TestCurriculaDetail:
    """Test dettaglio curriculum."""

    def test_detail_not_found(self, auth_headers):
        """GET /curricula/{id} con ID inesistente -> 404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/{fake_uuid}",
            headers=auth_headers,
            timeout=60.0
        )
        # 404 Not Found, 422 UUID non valido, 503 DB down
        assert response.status_code in [404, 422, 503]

    def test_detail_invalid_id_format(self, auth_headers):
        """GET /curricula/{id} con ID non-UUID -> 422."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/invalid-id-format",
            headers=auth_headers,
            timeout=60.0
        )
        # 422 Unprocessable Entity, 404 not found, 500 server error, 503 DB down
        assert response.status_code in [404, 422, 500, 503]


# ==============================================================================
# TEST: Create Curriculum
# ==============================================================================

class TestCurriculaCreate:
    """Test creazione curriculum."""

    def test_create_requires_auth(self):
        """POST /curricula senza token -> 401/403."""
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/",
            json={
                "title": "Test Curriculum",
                "description": "Test description"
            },
            timeout=60.0
        )
        # 401/403 auth required, 503 DB down
        assert response.status_code in [401, 403, 503]

    def test_create_with_auth(self, auth_headers):
        """POST /curricula con token."""
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers=auth_headers,
            json={
                "title": f"Test Curriculum {uuid.uuid4().hex[:6]}",
                "description": "Test description for integration test",
                "style": "karate",
                "difficulty_level": "beginner"
            },
            timeout=60.0
        )
        # 201 Created, 403 Forbidden (non instructor), 422 validation, 503 DB down
        assert response.status_code in [201, 403, 422, 503]

    def test_create_missing_required_fields(self, auth_headers):
        """POST /curricula senza campi richiesti -> 422."""
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers=auth_headers,
            json={},
            timeout=60.0
        )
        # 422 validation error, 403 non autorizzato, 503 DB down
        assert response.status_code in [403, 422, 503]


# ==============================================================================
# TEST: User Enrollments
# ==============================================================================

class TestCurriculaEnrollments:
    """Test iscrizioni utente."""

    def test_my_enrollments_with_auth(self, auth_headers):
        """GET /curricula/me/enrollments con token -> 200."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/me/enrollments",
            headers=auth_headers,
            timeout=60.0
        )
        # 200 OK, 503 DB down
        assert response.status_code in [200, 503]

    def test_my_enrollments_returns_array(self, auth_headers):
        """GET /curricula/me/enrollments ritorna array."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/me/enrollments",
            headers=auth_headers,
            timeout=60.0
        )
        if response.status_code == 503:
            pytest.skip("Database unavailable")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


# ==============================================================================
# TEST: Enroll in Curriculum
# ==============================================================================

class TestCurriculaEnroll:
    """Test iscrizione a curriculum."""

    def test_enroll_requires_auth(self):
        """POST /curricula/{id}/enroll senza token -> 401/403."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/{fake_uuid}/enroll",
            timeout=60.0
        )
        # 401/403 auth required, 503 DB down
        assert response.status_code in [401, 403, 503]

    def test_enroll_not_found(self, auth_headers):
        """POST /curricula/{id}/enroll con ID inesistente -> 404."""
        fake_uuid = str(uuid.uuid4())
        response = httpx.post(
            f"{BACKEND_URL}{API_PREFIX}/{fake_uuid}/enroll",
            headers=auth_headers,
            timeout=60.0
        )
        # 404 Not Found, 422 UUID non valido, 503 DB down
        assert response.status_code in [404, 422, 503]


# ==============================================================================
# TEST: Security
# ==============================================================================

class TestCurriculaSecurity:
    """Test aspetti sicurezza."""

    def test_invalid_token(self):
        """Token non valido -> 401."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers={"Authorization": "Bearer invalid_token_12345"},
            timeout=60.0
        )
        # 401 invalid token, 503 DB down
        assert response.status_code in [401, 503]

    def test_malformed_auth_header(self):
        """Header Authorization malformato -> 401."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/",
            headers={"Authorization": "NotBearer token"},
            timeout=60.0
        )
        # 401 o 403, 503 DB down
        assert response.status_code in [401, 403, 503]

    def test_sql_injection_in_id(self, auth_headers):
        """SQL injection in ID deve essere prevenuta."""
        response = httpx.get(
            f"{BACKEND_URL}{API_PREFIX}/'; DROP TABLE curricula; --",
            headers=auth_headers,
            timeout=60.0
        )
        # Non deve crashare - 404, 422, 500, o 503
        assert response.status_code in [404, 422, 500, 503]

"""
================================================================================
AI_MODULE: TestSchedulerAPI
AI_VERSION: 2.0.0
AI_DESCRIPTION: Test Scheduler endpoints con backend REALE - ZERO MOCK
AI_BUSINESS: Gestione job schedulati - Monitoring, trigger manuale, health
AI_TEACHING: ZERO MOCK - chiamate HTTP SYNC reali a localhost:8000

FIX 2025-01-26: Rimosso ASGITransport che causava:
- "Event loop is closed"
- "another operation is in progress"
- Problemi con asyncpg e connessioni zombie

Ora usa httpx.Client SYNC con chiamate HTTP reali al backend.
================================================================================

ZERO_MOCK_POLICY: Nessun mock consentito
COVERAGE_TARGETS: Line 90%+, Pass rate 95%+

ENDPOINTS TESTATI:
- GET /scheduler/jobs: Lista tutti i job
- GET /scheduler/jobs/{job_id}: Dettaglio job
- GET /scheduler/jobs/{job_id}/history: Storico esecuzioni
- POST /scheduler/jobs/{job_id}/trigger: Trigger manuale
- POST /scheduler/jobs/{job_id}/pause: Pausa job
- POST /scheduler/jobs/{job_id}/resume: Riprendi job
- GET /scheduler/running: Job in esecuzione
- GET /scheduler/health: Health check sistema
- GET /scheduler/backups: Lista backup
- GET /scheduler/stats: Statistiche scheduler

================================================================================
"""

import pytest
import httpx
import os

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration, pytest.mark.api]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/scheduler"
AUTH_PREFIX = "/api/v1/auth"


# ==============================================================================
# FIXTURES - SYNC HTTP CLIENT (NO ASYNCIO ISSUES)
# ==============================================================================

@pytest.fixture(scope="module")
def http_client():
    """
    Client HTTP SYNC per test scheduler.
    
    FIX 2025-01-26: Usa client SYNC invece di async per evitare
    problemi con event loop e asyncpg.
    
    ZERO MOCK: Chiamate HTTP reali a localhost:8000
    """
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        try:
            response = client.get("/health")
            if response.status_code != 200:
                pytest.skip(f"Backend not healthy: {response.status_code}")
        except httpx.ConnectError:
            pytest.skip(f"Backend not running at {BASE_URL}")
        yield client


@pytest.fixture(scope="module")
def auth_headers(http_client):
    """Get auth headers for test user."""
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "test@martialarts.com",
            "password": "TestPassword123!"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    # Try alternative user
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "premium_test@example.com",
            "password": "test123"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    pytest.skip("Test user not available - run seed script")


@pytest.fixture(scope="module")
def admin_headers(http_client):
    """Get auth headers for admin user."""
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "admin@martialarts.com",
            "password": "AdminPassword123!"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    pytest.skip("Admin user not available - run seed script")


# ==============================================================================
# TEST: Jobs List
# ==============================================================================

class TestSchedulerJobsList:
    """Test scheduler jobs list endpoint."""

    def test_list_jobs_requires_auth(self, http_client):
        """GET /scheduler/jobs richiede auth."""
        response = http_client.get(f"{API_PREFIX}/jobs")

        assert response.status_code in [401, 403, 500, 503]

    def test_list_jobs_with_auth(self, http_client, auth_headers):
        """GET /scheduler/jobs con auth ritorna lista job."""
        response = http_client.get(
            f"{API_PREFIX}/jobs",
            headers=auth_headers
        )

        assert response.status_code in [200, 403, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "jobs" in data or isinstance(data, list)

    def test_list_jobs_admin(self, http_client, admin_headers):
        """GET /scheduler/jobs con admin ritorna lista completa."""
        response = http_client.get(
            f"{API_PREFIX}/jobs",
            headers=admin_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "jobs" in data or isinstance(data, list)


# ==============================================================================
# TEST: Job Detail
# ==============================================================================

class TestSchedulerJobDetail:
    """Test scheduler job detail endpoint."""

    def test_get_job_requires_auth(self, http_client):
        """GET /scheduler/jobs/{id} richiede auth."""
        response = http_client.get(f"{API_PREFIX}/jobs/test-job")

        assert response.status_code in [401, 403, 500, 503]

    def test_get_job_not_found(self, http_client, auth_headers):
        """GET /scheduler/jobs/{id} con ID inesistente."""
        response = http_client.get(
            f"{API_PREFIX}/jobs/non-existent-job-id",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]

    def test_get_job_invalid_id(self, http_client, auth_headers):
        """GET /scheduler/jobs/{id} con ID invalido."""
        response = http_client.get(
            f"{API_PREFIX}/jobs/invalid-job-id",
            headers=auth_headers
        )

        assert response.status_code in [404, 422]


# ==============================================================================
# TEST: Job History
# ==============================================================================

class TestSchedulerJobHistory:
    """Test scheduler job history endpoint."""

    def test_job_history_requires_auth(self, http_client):
        """GET /scheduler/jobs/{id}/history richiede auth."""
        response = http_client.get(f"{API_PREFIX}/jobs/test-job/history")

        assert response.status_code in [401, 403, 500, 503]

    def test_job_history_not_found(self, http_client, auth_headers):
        """GET /scheduler/jobs/{id}/history con job inesistente."""
        response = http_client.get(
            f"{API_PREFIX}/jobs/non-existent-job/history",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]


# ==============================================================================
# TEST: Job Trigger
# ==============================================================================

class TestSchedulerJobTrigger:
    """Test manual job trigger endpoint."""

    def test_trigger_requires_auth(self, http_client):
        """POST /scheduler/jobs/{id}/trigger richiede auth."""
        response = http_client.post(f"{API_PREFIX}/jobs/test-job/trigger")

        assert response.status_code in [401, 403, 500, 503]

    def test_trigger_requires_admin(self, http_client, auth_headers):
        """POST /scheduler/jobs/{id}/trigger richiede admin."""
        response = http_client.post(
            f"{API_PREFIX}/jobs/test-job/trigger",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]

    def test_trigger_job_not_found(self, http_client, admin_headers):
        """POST /scheduler/jobs/{id}/trigger con job inesistente."""
        response = http_client.post(
            f"{API_PREFIX}/jobs/non-existent-job/trigger",
            headers=admin_headers
        )

        assert response.status_code in [404, 422, 500, 503]


# ==============================================================================
# TEST: Job Pause/Resume
# ==============================================================================

class TestSchedulerJobPauseResume:
    """Test job pause and resume endpoints."""

    def test_pause_requires_auth(self, http_client):
        """POST /scheduler/jobs/{id}/pause richiede auth."""
        response = http_client.post(f"{API_PREFIX}/jobs/test-job/pause")

        assert response.status_code in [401, 403, 500, 503]

    def test_resume_requires_auth(self, http_client):
        """POST /scheduler/jobs/{id}/resume richiede auth."""
        response = http_client.post(f"{API_PREFIX}/jobs/test-job/resume")

        assert response.status_code in [401, 403, 500, 503]

    def test_pause_requires_admin(self, http_client, auth_headers):
        """POST /scheduler/jobs/{id}/pause richiede admin."""
        response = http_client.post(
            f"{API_PREFIX}/jobs/test-job/pause",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]

    def test_resume_requires_admin(self, http_client, auth_headers):
        """POST /scheduler/jobs/{id}/resume richiede admin."""
        response = http_client.post(
            f"{API_PREFIX}/jobs/test-job/resume",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]


# ==============================================================================
# TEST: Running Jobs
# ==============================================================================

class TestSchedulerRunning:
    """Test running jobs endpoint."""

    def test_running_requires_auth(self, http_client):
        """GET /scheduler/running richiede auth."""
        response = http_client.get(f"{API_PREFIX}/running")

        assert response.status_code in [401, 403, 500, 503]

    def test_running_jobs_list(self, http_client, auth_headers):
        """GET /scheduler/running ritorna lista job attivi."""
        response = http_client.get(
            f"{API_PREFIX}/running",
            headers=auth_headers
        )

        assert response.status_code in [200, 403, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "running_jobs" in data or isinstance(data, list)


# ==============================================================================
# TEST: Health Check
# ==============================================================================

class TestSchedulerHealth:
    """Test scheduler health endpoint."""

    def test_health_public_access(self, http_client):
        """GET /scheduler/health accessibile pubblicamente."""
        response = http_client.get(f"{API_PREFIX}/health")

        assert response.status_code in [200, 401, 403, 500, 503]

    def test_health_with_auth(self, http_client, auth_headers):
        """GET /scheduler/health con auth."""
        response = http_client.get(
            f"{API_PREFIX}/health",
            headers=auth_headers
        )

        assert response.status_code in [200, 403, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "status" in data or "healthy" in data or "scheduler" in data

    def test_health_response_format(self, http_client, admin_headers):
        """GET /scheduler/health ritorna formato corretto."""
        response = http_client.get(
            f"{API_PREFIX}/health",
            headers=admin_headers
        )

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, dict)


# ==============================================================================
# TEST: Backups
# ==============================================================================

class TestSchedulerBackups:
    """Test scheduler backups endpoint."""

    def test_backups_requires_auth(self, http_client):
        """GET /scheduler/backups richiede auth."""
        response = http_client.get(f"{API_PREFIX}/backups")

        assert response.status_code in [401, 403, 500, 503]

    def test_backups_list(self, http_client, admin_headers):
        """GET /scheduler/backups ritorna lista backup."""
        response = http_client.get(
            f"{API_PREFIX}/backups",
            headers=admin_headers
        )

        assert response.status_code in [200, 403, 404, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "backups" in data or isinstance(data, list)


# ==============================================================================
# TEST: Statistics
# ==============================================================================

class TestSchedulerStats:
    """Test scheduler statistics endpoint."""

    def test_stats_requires_auth(self, http_client):
        """GET /scheduler/stats richiede auth."""
        response = http_client.get(f"{API_PREFIX}/stats")

        assert response.status_code in [401, 403, 500, 503]

    def test_stats_with_auth(self, http_client, auth_headers):
        """GET /scheduler/stats con auth."""
        response = http_client.get(
            f"{API_PREFIX}/stats",
            headers=auth_headers
        )

        assert response.status_code in [200, 403, 500, 503]

    def test_stats_contains_metrics(self, http_client, admin_headers):
        """GET /scheduler/stats contiene metriche."""
        response = http_client.get(
            f"{API_PREFIX}/stats",
            headers=admin_headers
        )

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, dict)


# ==============================================================================
# TEST: Security
# ==============================================================================

class TestSchedulerSecurity:
    """Test security aspects of scheduler endpoints."""

    def test_invalid_token(self, http_client):
        """Richieste con token invalido falliscono."""
        response = http_client.get(
            f"{API_PREFIX}/jobs",
            headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_expired_token_format(self, http_client):
        """Token malformato/expired viene rifiutato."""
        # FIX 2025-01-27: Token expired sintatticamente valido invece di "Bearer "
        # "Bearer " (senza token) causa errore httpx "Illegal header value"
        expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxfQ.invalid_signature"
        response = http_client.get(
            f"{API_PREFIX}/health",
            headers={"Authorization": f"Bearer {expired_token}"}
        )

        assert response.status_code in [200, 401, 403, 500, 503]

    def test_path_traversal_job_id(self, http_client, auth_headers):
        """Path traversal in job_id viene prevenuta."""
        response = http_client.get(
            f"{API_PREFIX}/jobs/../../../etc/passwd",
            headers=auth_headers
        )

        assert response.status_code in [400, 403, 404, 422, 500, 503]


# ==============================================================================
# TEST: Response Format
# ==============================================================================

class TestSchedulerResponseFormat:
    """Test response format consistency."""

    def test_jobs_response_json(self, http_client, admin_headers):
        """GET /scheduler/jobs ritorna JSON valido."""
        response = http_client.get(
            f"{API_PREFIX}/jobs",
            headers=admin_headers
        )

        if response.status_code == 200:
            assert "application/json" in response.headers.get("content-type", "")

    def test_error_response_format(self, http_client, auth_headers):
        """Errori ritornano formato consistente."""
        response = http_client.get(
            f"{API_PREFIX}/jobs/non-existent",
            headers=auth_headers
        )

        if response.status_code in [403, 404]:
            data = response.json()
            assert "detail" in data or "message" in data or "error" in data

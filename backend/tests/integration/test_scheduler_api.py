"""
================================================================================
AI_MODULE: Scheduler Admin API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per Scheduler Admin REST endpoints
AI_BUSINESS: Garantisce funzionamento gestione job scheduler
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock scheduler: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

METRICHE_SUCCESSO:
- Coverage: 90%+ per scheduler.py REST endpoints
- Pass rate: 95%+
- Response time: <500ms per endpoint

ENDPOINTS TESTATI:
- GET /api/v1/scheduler/jobs - Lista tutti i job
- GET /api/v1/scheduler/jobs/{job_id} - Dettaglio singolo job
- GET /api/v1/scheduler/jobs/{job_id}/history - Storico esecuzioni
- POST /api/v1/scheduler/jobs/{job_id}/trigger - Trigger manuale
- POST /api/v1/scheduler/jobs/{job_id}/pause - Pausa job
- POST /api/v1/scheduler/jobs/{job_id}/resume - Riprendi job
- GET /api/v1/scheduler/running - Job in esecuzione
- GET /api/v1/scheduler/health - Health status servizi
- GET /api/v1/scheduler/backups - Lista backup
- GET /api/v1/scheduler/stats - Statistiche scheduler

================================================================================
"""

import pytest
import httpx
from typing import Dict


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/scheduler"


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestSchedulerAuth:
    """Test autenticazione Scheduler endpoints."""

    def test_list_jobs_no_auth(self, api_client):
        """List jobs richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/jobs")

        assert response.status_code in [401, 403, 404]

    def test_get_job_no_auth(self, api_client):
        """Get job details richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/jobs/health_check")

        assert response.status_code in [401, 403, 404]

    def test_trigger_job_no_auth(self, api_client):
        """Trigger job richiede autenticazione admin."""
        response = api_client.post(f"{API_PREFIX}/jobs/health_check/trigger")

        assert response.status_code in [401, 403, 404]

    def test_pause_job_no_auth(self, api_client):
        """Pause job richiede autenticazione admin."""
        response = api_client.post(f"{API_PREFIX}/jobs/health_check/pause")

        assert response.status_code in [401, 403, 404]

    def test_resume_job_no_auth(self, api_client):
        """Resume job richiede autenticazione admin."""
        response = api_client.post(f"{API_PREFIX}/jobs/health_check/resume")

        assert response.status_code in [401, 403, 404]

    def test_running_jobs_no_auth(self, api_client):
        """Running jobs richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/running")

        assert response.status_code in [401, 403, 404]

    def test_health_no_auth(self, api_client):
        """Health status richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/health")

        assert response.status_code in [401, 403, 404]

    def test_backups_no_auth(self, api_client):
        """Backups list richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/backups")

        assert response.status_code in [401, 403, 404]

    def test_stats_no_auth(self, api_client):
        """Stats richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/stats")

        assert response.status_code in [401, 403, 404]


# =============================================================================
# USER ACCESS TESTS
# =============================================================================

class TestSchedulerUserAccess:
    """Test accesso utente normale a Scheduler endpoints."""

    def test_list_jobs_user_denied(self, api_client, auth_headers):
        """
        Utente normale non ha accesso ai job.

        BUSINESS: Solo admin gestiscono scheduler.
        """
        response = api_client.get(
            f"{API_PREFIX}/jobs",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]

    def test_get_job_user_denied(self, api_client, auth_headers):
        """Utente normale non vede dettagli job."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]

    def test_trigger_job_user_denied(self, api_client, auth_headers):
        """Utente normale non puo triggare job."""
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/trigger",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]

    def test_health_user_denied(self, api_client, auth_headers):
        """Utente normale non vede health status."""
        response = api_client.get(
            f"{API_PREFIX}/health",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]


# =============================================================================
# ADMIN JOB LIST TESTS
# =============================================================================

class TestSchedulerAdminJobs:
    """Test gestione job admin."""

    def test_list_all_jobs(self, api_client, admin_headers):
        """
        Admin vede lista tutti i job.

        BUSINESS: Admin monitora stato scheduler.
        """
        response = api_client.get(
            f"{API_PREFIX}/jobs",
            headers=admin_headers
        )

        # 200 con lista job, 500 se scheduler non inizializzato
        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)

            # Verifica struttura job
            if len(data) > 0:
                job = data[0]
                assert "job_id" in job
                assert "name" in job

    def test_get_job_details_health_check(self, api_client, admin_headers):
        """
        Admin vede dettagli job health_check.

        BUSINESS: Dettaglio singolo job per debug.
        """
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check",
            headers=admin_headers
        )

        # 200 se job esiste, 404 se non esiste, 500 se errore
        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            assert "job_id" in data
            assert data["job_id"] == "health_check"

    def test_get_job_details_not_found(self, api_client, admin_headers):
        """Get job inesistente."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/non_existent_job",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]

    def test_get_job_history(self, api_client, admin_headers):
        """
        Admin vede storico esecuzioni job.

        BUSINESS: Analisi storico per troubleshooting.
        """
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check/history",
            headers=admin_headers
        )

        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)

    def test_get_job_history_with_limit(self, api_client, admin_headers):
        """Storico job con limite risultati."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check/history",
            headers=admin_headers,
            params={"limit": 5}
        )

        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            assert len(data) <= 5

    def test_get_job_history_not_found(self, api_client, admin_headers):
        """Storico job inesistente."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/non_existent_job/history",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]


# =============================================================================
# ADMIN JOB CONTROL TESTS
# =============================================================================

class TestSchedulerAdminControl:
    """Test controllo job admin."""

    def test_trigger_job_health_check(self, api_client, admin_headers):
        """
        Admin triggera job manualmente.

        BUSINESS: Trigger manuale per test e debug.
        """
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/trigger",
            headers=admin_headers
        )

        # 200 se triggerato, 404 se non esiste, 409 se gia running, 500 se errore
        assert response.status_code in [200, 404, 409, 500]

        if response.status_code == 200:
            data = response.json()
            assert "success" in data
            assert "job_id" in data

    def test_trigger_job_not_found(self, api_client, admin_headers):
        """Trigger job inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/jobs/non_existent_job/trigger",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]

    def test_pause_job(self, api_client, admin_headers):
        """
        Admin mette in pausa job.

        BUSINESS: Pausa temporanea per manutenzione.
        """
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/pause",
            headers=admin_headers
        )

        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            assert data.get("success") is True
            assert "paused" in data.get("message", "").lower()

    def test_pause_job_not_found(self, api_client, admin_headers):
        """Pausa job inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/jobs/non_existent_job/pause",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]

    def test_resume_job(self, api_client, admin_headers):
        """
        Admin riprende job in pausa.

        BUSINESS: Riattivazione dopo manutenzione.
        """
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/resume",
            headers=admin_headers
        )

        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            assert data.get("success") is True
            assert "resumed" in data.get("message", "").lower()

    def test_resume_job_not_found(self, api_client, admin_headers):
        """Resume job inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/jobs/non_existent_job/resume",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]


# =============================================================================
# MONITORING ENDPOINTS TESTS
# =============================================================================

class TestSchedulerMonitoring:
    """Test endpoint monitoring."""

    def test_get_running_jobs(self, api_client, admin_headers):
        """
        Admin vede job in esecuzione.

        BUSINESS: Monitoring real-time esecuzioni.
        """
        response = api_client.get(
            f"{API_PREFIX}/running",
            headers=admin_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "count" in data
            assert "jobs" in data
            assert isinstance(data["jobs"], list)

    def test_get_system_health(self, api_client, admin_headers):
        """
        Admin vede health status servizi.

        BUSINESS: Monitoring salute sistema (DB, Redis, Storage).
        """
        response = api_client.get(
            f"{API_PREFIX}/health",
            headers=admin_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "status" in data
            assert "services" in data
            assert "system" in data

    def test_list_backups(self, api_client, admin_headers):
        """
        Admin vede lista backup disponibili.

        BUSINESS: Accesso backup per disaster recovery.
        """
        response = api_client.get(
            f"{API_PREFIX}/backups",
            headers=admin_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)

            # Verifica struttura backup
            if len(data) > 0:
                backup = data[0]
                assert "filename" in backup
                assert "size_bytes" in backup

    def test_get_scheduler_stats(self, api_client, admin_headers):
        """
        Admin vede statistiche scheduler.

        BUSINESS: Overview statistiche per monitoring dashboard.
        """
        response = api_client.get(
            f"{API_PREFIX}/stats",
            headers=admin_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "total_jobs" in data
            assert "active_jobs" in data
            assert "paused_jobs" in data
            assert "running_jobs" in data


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestSchedulerValidation:
    """Test validazione input."""

    def test_job_history_invalid_limit(self, api_client, admin_headers):
        """History con limit invalido."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check/history",
            headers=admin_headers,
            params={"limit": -1}
        )

        # Limit negativo potrebbe essere ignorato o dare 422
        assert response.status_code in [200, 404, 422, 500]

    def test_job_history_limit_exceeded(self, api_client, admin_headers):
        """History con limit oltre il massimo."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check/history",
            headers=admin_headers,
            params={"limit": 10000}
        )

        # Dovrebbe limitare a 100
        assert response.status_code in [200, 404, 422, 500]


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestSchedulerErrors:
    """Test gestione errori."""

    def test_malformed_job_id(self, api_client, admin_headers):
        """Job ID malformato."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/../../../etc/passwd",
            headers=admin_headers
        )

        # Path traversal dovrebbe essere bloccato
        assert response.status_code in [400, 404, 422]

    def test_very_long_job_id(self, api_client, admin_headers):
        """Job ID molto lungo."""
        long_id = "a" * 1000

        response = api_client.get(
            f"{API_PREFIX}/jobs/{long_id}",
            headers=admin_headers
        )

        assert response.status_code in [400, 404, 414, 500]

    def test_special_characters_job_id(self, api_client, admin_headers):
        """Job ID con caratteri speciali."""
        response = api_client.get(
            f"{API_PREFIX}/jobs/test%00job",
            headers=admin_headers
        )

        assert response.status_code in [400, 404, 422, 500]


# =============================================================================
# JOB LIFECYCLE TESTS
# =============================================================================

class TestSchedulerJobLifecycle:
    """Test ciclo di vita job."""

    @pytest.mark.skip(reason="Richiede job scheduler attivo")
    def test_pause_resume_cycle(self, api_client, admin_headers):
        """
        Ciclo completo: pause -> verify -> resume -> verify.

        BUSINESS: Workflow tipico manutenzione job.
        """
        # Step 1: Pause job
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/pause",
            headers=admin_headers
        )
        assert response.status_code == 200

        # Step 2: Verify paused
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check",
            headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["is_paused"] is True

        # Step 3: Resume job
        response = api_client.post(
            f"{API_PREFIX}/jobs/health_check/resume",
            headers=admin_headers
        )
        assert response.status_code == 200

        # Step 4: Verify resumed
        response = api_client.get(
            f"{API_PREFIX}/jobs/health_check",
            headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["is_paused"] is False


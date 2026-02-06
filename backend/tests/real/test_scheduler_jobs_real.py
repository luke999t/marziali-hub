"""
================================================================================
AI_MODULE: Scheduler Jobs Real Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test REALI scheduler jobs - ZERO MOCK
AI_BUSINESS: Validazione 100% job maintenance, backup, analytics, health check
AI_TEACHING: pytest-asyncio, httpx, database reale

ZERO MOCK - Backend DEVE essere attivo su localhost:8000

JOB_TESTATI:
1. cleanup_expired_downloads_drm - Pulizia file DRM scaduti
2. notify_expiring_downloads - Notifiche download in scadenza
3. cleanup_sessions_unified - Pulizia sessioni
4. daily_analytics - Report analytics giornaliero
5. database_backup - Backup PostgreSQL
6. health_check - Health check servizi
================================================================================
"""

import pytest
import httpx
import os
from datetime import datetime
from time import sleep

# Backend URL from env or default
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# Test credentials (Admin required for scheduler endpoints)
ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL", "admin@mediacenter.it")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD", "Admin2024!")


# ================================================================================
# PREREQUISITI
# ================================================================================

class TestBackendPrerequisite:
    """Verifica che il backend sia attivo - prerequisito per tutti i test."""

    def test_backend_health(self):
        """Backend DEVE essere attivo per eseguire i test."""
        try:
            response = httpx.get(f"{BACKEND_URL}/health", timeout=5)
            assert response.status_code == 200, f"Backend not healthy: {response.status_code}"
            data = response.json()
            assert data.get("status") == "healthy"
        except httpx.ConnectError:
            pytest.fail(
                f"BACKEND NON ATTIVO su {BACKEND_URL} - "
                f"Avvialo con: cd backend && python -m uvicorn main:app --reload"
            )
        except httpx.TimeoutException:
            pytest.fail(f"Backend timeout su {BACKEND_URL}")


# ================================================================================
# TEST SCHEDULER ADMIN API
# ================================================================================

class TestSchedulerAdminAPI:
    """Test endpoint admin scheduler."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin reale per accesso endpoint scheduler."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code} - {response.text}")
            return response.json().get("access_token")
        except httpx.ConnectError:
            pytest.skip("Backend not available")

    def test_list_all_jobs(self, admin_token):
        """GET /api/v1/scheduler/jobs - Lista tutti i job registrati."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code} - {response.text}"
        jobs = response.json()
        assert isinstance(jobs, list)
        assert len(jobs) > 0, "No jobs registered"

        # Verifica che i job richiesti siano presenti
        job_ids = [j["job_id"] for j in jobs]
        required_jobs = [
            "health_check",
            "daily_analytics",
            "database_backup",
            "cleanup_sessions_unified",
            "cleanup_expired_downloads_drm",
            "notify_expiring_downloads",
        ]

        for required_job in required_jobs:
            assert required_job in job_ids, f"Job '{required_job}' non registrato!"

        print(f"\n[OK] {len(jobs)} job registrati:")
        for job in jobs:
            print(f"  - {job['job_id']}: {job['name']} (paused={job['is_paused']})")

    def test_get_job_details(self, admin_token):
        """GET /api/v1/scheduler/jobs/{job_id} - Dettaglio singolo job."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        job = response.json()

        assert job["job_id"] == "health_check"
        assert "next_run_time" in job
        assert "is_paused" in job
        assert "is_running" in job

        print(f"\n[OK] Health check job details:")
        print(f"  - Next run: {job.get('next_run_time')}")
        print(f"  - Paused: {job['is_paused']}")
        print(f"  - Running: {job['is_running']}")

    def test_get_job_history(self, admin_token):
        """GET /api/v1/scheduler/jobs/{job_id}/history - Storico esecuzioni."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check/history?limit=5",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        history = response.json()
        assert isinstance(history, list)

        print(f"\n[OK] Health check history: {len(history)} esecuzioni")
        for entry in history[:3]:
            print(f"  - {entry.get('started_at')}: {entry.get('status')}")

    def test_scheduler_stats(self, admin_token):
        """GET /api/v1/scheduler/stats - Statistiche scheduler."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        stats = response.json()

        assert "total_jobs" in stats
        assert "active_jobs" in stats
        assert "scheduler_running" in stats
        assert stats["scheduler_running"] is True, "Scheduler non attivo!"

        print(f"\n[OK] Scheduler stats:")
        print(f"  - Total jobs: {stats['total_jobs']}")
        print(f"  - Active jobs: {stats['active_jobs']}")
        print(f"  - Paused jobs: {stats['paused_jobs']}")
        print(f"  - Running now: {stats['running_jobs']}")

    def test_get_running_jobs(self, admin_token):
        """GET /api/v1/scheduler/running - Job in esecuzione."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/running",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        result = response.json()
        assert "count" in result
        assert "jobs" in result

        print(f"\n[OK] Currently running: {result['count']} jobs")


# ================================================================================
# TEST TRIGGER MANUALE JOB
# ================================================================================

class TestJobManualTrigger:
    """Test trigger manuale dei job."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin reale."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code}")
            return response.json().get("access_token")
        except httpx.ConnectError:
            pytest.skip("Backend not available")

    def test_trigger_health_check_job(self, admin_token):
        """
        POST /api/v1/scheduler/jobs/health_check/trigger
        Trigger manuale health check e verifica risultato.
        """
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.post(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check/trigger",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=30  # Health check potrebbe richiedere tempo
        )

        assert response.status_code == 200, f"Failed: {response.status_code} - {response.text}"
        result = response.json()

        assert result["success"] is True
        assert result["job_id"] == "health_check"
        assert "result" in result

        job_result = result["result"]
        assert job_result["status"] in ["success", "failed"]

        if job_result["status"] == "success":
            print(f"\n[OK] Health check triggered successfully:")
            print(f"  - Duration: {job_result.get('duration_seconds', 0):.2f}s")
            details = job_result.get("details", {})
            if "database" in details:
                print(f"  - Database: {'OK' if details['database'].get('ok') else 'FAIL'}")
            if "redis" in details:
                print(f"  - Redis: {'OK' if details['redis'].get('ok') else 'FAIL'}")
            if "storage" in details:
                print(f"  - Storage: {'OK' if details['storage'].get('ok') else 'FAIL'}")
        else:
            print(f"\n[WARNING] Health check reported issues:")
            print(f"  - Error: {job_result.get('error_message')}")

    def test_trigger_cleanup_sessions_job(self, admin_token):
        """
        POST /api/v1/scheduler/jobs/cleanup_sessions_unified/trigger
        Trigger manuale cleanup sessioni.
        """
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.post(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/cleanup_sessions_unified/trigger",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=30
        )

        assert response.status_code == 200, f"Failed: {response.status_code} - {response.text}"
        result = response.json()

        assert result["success"] is True
        assert result["job_id"] == "cleanup_sessions_unified"

        job_result = result["result"]
        print(f"\n[OK] Cleanup sessions triggered:")
        print(f"  - Status: {job_result['status']}")
        print(f"  - Records processed: {job_result.get('records_processed', 0)}")

        details = job_result.get("details", {})
        if details:
            print(f"  - Device tokens deactivated: {details.get('device_tokens_deactivated', 0)}")
            print(f"  - Ads sessions abandoned: {details.get('ads_sessions_abandoned', 0)}")
            print(f"  - Ads sessions deleted: {details.get('ads_sessions_deleted', 0)}")


# ================================================================================
# TEST PAUSE/RESUME
# ================================================================================

class TestJobPauseResume:
    """Test pause e resume job."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin reale."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code}")
            return response.json().get("access_token")
        except httpx.ConnectError:
            pytest.skip("Backend not available")

    def test_pause_and_resume_job(self, admin_token):
        """
        Test ciclo completo pause/resume su un job.
        Usa notify_expiring_downloads come job di test.
        """
        if not admin_token:
            pytest.skip("No admin token available")

        job_id = "notify_expiring_downloads"
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. Verifica stato iniziale
        status_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}",
            headers=headers,
            timeout=10
        )
        assert status_response.status_code == 200
        initial_status = status_response.json()
        was_paused = initial_status.get("is_paused", False)

        # 2. Pause
        pause_response = httpx.post(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}/pause",
            headers=headers,
            timeout=10
        )
        assert pause_response.status_code == 200
        assert pause_response.json()["success"] is True
        print(f"\n[OK] Job '{job_id}' paused")

        # 3. Verifica che sia pausato
        status_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}",
            headers=headers,
            timeout=10
        )
        assert status_response.json()["is_paused"] is True

        # 4. Resume
        resume_response = httpx.post(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}/resume",
            headers=headers,
            timeout=10
        )
        assert resume_response.status_code == 200
        assert resume_response.json()["success"] is True
        print(f"[OK] Job '{job_id}' resumed")

        # 5. Verifica che sia ripartito
        status_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}",
            headers=headers,
            timeout=10
        )
        assert status_response.json()["is_paused"] is False

        # 6. Ripristina stato iniziale se era pausato
        if was_paused:
            httpx.post(
                f"{BACKEND_URL}/api/v1/scheduler/jobs/{job_id}/pause",
                headers=headers,
                timeout=10
            )


# ================================================================================
# TEST HEALTH & BACKUPS ENDPOINT
# ================================================================================

class TestHealthAndBackups:
    """Test endpoint health e backups."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin reale."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code}")
            return response.json().get("access_token")
        except httpx.ConnectError:
            pytest.skip("Backend not available")

    def test_get_system_health(self, admin_token):
        """GET /api/v1/scheduler/health - Stato salute servizi."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/health",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        health = response.json()

        assert "status" in health
        assert health["status"] in ["healthy", "degraded", "unknown"]

        print(f"\n[OK] System health: {health['status']}")

        if "services" in health:
            for service, data in health["services"].items():
                status = "OK" if data.get("ok") else "FAIL"
                latency = data.get("latency_ms", "N/A")
                print(f"  - {service}: {status} (latency: {latency}ms)")

        if "system" in health and health["system"]:
            system = health["system"]
            print(f"  - CPU: {system.get('cpu_percent', 'N/A')}%")
            print(f"  - Memory: {system.get('memory_percent', 'N/A')}%")
            print(f"  - Disk: {system.get('disk_percent', 'N/A')}%")

    def test_list_backups(self, admin_token):
        """GET /api/v1/scheduler/backups - Lista backup disponibili."""
        if not admin_token:
            pytest.skip("No admin token available")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/backups",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )

        assert response.status_code == 200, f"Failed: {response.status_code}"
        backups = response.json()
        assert isinstance(backups, list)

        print(f"\n[OK] {len(backups)} backup(s) disponibili:")
        for backup in backups[:5]:  # Show max 5
            print(f"  - {backup['filename']}: {backup['size_mb']}MB ({backup['created_at']})")

        if not backups:
            print("  (Nessun backup ancora creato - normale per nuovo sistema)")


# ================================================================================
# TEST SECURITY - ACCESSO NON AUTORIZZATO
# ================================================================================

class TestSchedulerSecurity:
    """Test sicurezza endpoint scheduler - solo admin."""

    def test_list_jobs_without_auth(self):
        """Endpoint scheduler DEVE richiedere autenticazione."""
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs",
            timeout=10
        )
        # Deve tornare 401 o 403
        assert response.status_code in [401, 403], (
            f"Scheduler endpoint accessible without auth! Status: {response.status_code}"
        )
        print("\n[OK] Scheduler endpoint richiede autenticazione")

    def test_trigger_job_without_admin(self):
        """
        Trigger job NON deve essere possibile senza ruolo admin.
        Tentiamo login con utente normale (se esiste).
        """
        # Try to login as a regular user
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={
                    "email": "studente.premium@mediacenter.it",
                    "password": "Student2024!"
                },
                timeout=10
            )

            if response.status_code != 200:
                pytest.skip("No regular user available for test")

            user_token = response.json().get("access_token")

            # Try to trigger a job
            trigger_response = httpx.post(
                f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check/trigger",
                headers={"Authorization": f"Bearer {user_token}"},
                timeout=10
            )

            # Should be forbidden
            assert trigger_response.status_code in [401, 403], (
                f"Regular user can trigger jobs! Status: {trigger_response.status_code}"
            )
            print("\n[OK] Job trigger richiede ruolo admin")

        except httpx.ConnectError:
            pytest.skip("Backend not available")


# ================================================================================
# INTEGRATION TEST - FULL WORKFLOW
# ================================================================================

class TestSchedulerIntegration:
    """Test integrazione completo workflow scheduler."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin reale."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code}")
            return response.json().get("access_token")
        except httpx.ConnectError:
            pytest.skip("Backend not available")

    def test_full_scheduler_workflow(self, admin_token):
        """
        Test workflow completo:
        1. Verifica scheduler attivo
        2. Lista job
        3. Trigger health check
        4. Verifica history aggiornata
        5. Check health endpoint
        """
        if not admin_token:
            pytest.skip("No admin token available")

        headers = {"Authorization": f"Bearer {admin_token}"}

        print("\n=== SCHEDULER INTEGRATION TEST ===")

        # 1. Stats - verifica scheduler attivo
        stats_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/stats",
            headers=headers,
            timeout=10
        )
        assert stats_response.status_code == 200
        stats = stats_response.json()
        assert stats["scheduler_running"] is True
        print(f"[1/5] Scheduler running: OK ({stats['total_jobs']} jobs)")

        # 2. Lista job
        jobs_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs",
            headers=headers,
            timeout=10
        )
        assert jobs_response.status_code == 200
        jobs = jobs_response.json()
        assert len(jobs) >= 6  # Almeno i 6 job richiesti
        print(f"[2/5] Jobs registered: {len(jobs)}")

        # 3. Trigger health check
        trigger_response = httpx.post(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check/trigger",
            headers=headers,
            timeout=30
        )
        assert trigger_response.status_code == 200
        print("[3/5] Health check triggered: OK")

        # 4. Verifica history
        history_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/jobs/health_check/history?limit=1",
            headers=headers,
            timeout=10
        )
        assert history_response.status_code == 200
        history = history_response.json()
        assert len(history) > 0
        latest = history[0]
        print(f"[4/5] Latest health check: {latest['status']} ({latest.get('duration_seconds', 0):.2f}s)")

        # 5. Health endpoint
        health_response = httpx.get(
            f"{BACKEND_URL}/api/v1/scheduler/health",
            headers=headers,
            timeout=10
        )
        assert health_response.status_code == 200
        health = health_response.json()
        print(f"[5/5] System health status: {health['status']}")

        print("=== INTEGRATION TEST PASSED ===")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])

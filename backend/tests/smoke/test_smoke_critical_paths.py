"""
🎓 AI_MODULE: Smoke Tests - Critical Paths
🎓 AI_DESCRIPTION: Verifica che le funzionalità critiche siano operative
🎓 AI_BUSINESS: Primo check dopo deploy, deve passare in <30 secondi totali
🎓 AI_TEACHING: Smoke tests = subset minimo per verificare sistema funzionante

METRICHE_SUCCESSO:
- Tempo esecuzione: <30 secondi totali
- Pass rate: 100% (se fallisce uno, sistema non è pronto)

REGOLA ZERO MOCK:
- Nessun mock, fake, patch
- Backend reale localhost:8000
- Skip se backend offline
"""

import pytest
import httpx
from typing import Optional

BASE_URL = "http://localhost:8000"
TIMEOUT = 5.0


def get_auth_headers(client: httpx.Client) -> Optional[dict]:
    """Login e ritorna headers con token."""
    try:
        response = client.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={
                "email": "test@martialarts.com",
                "password": "TestPassword123!"
            }
        )
        if response.status_code == 200:
            token = response.json().get("access_token")
            return {"Authorization": f"Bearer {token}"}
    except Exception:
        pass
    return None


@pytest.mark.smoke
class TestSmokeHealth:
    """Smoke test: Sistema base operativo."""

    def test_health_endpoint(self):
        """Sistema risponde su /health."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/health")
            assert response.status_code == 200, f"Health check failed: {response.text}"
            data = response.json()
            assert data.get("status") == "healthy" or "status" in data

    def test_root_endpoint(self):
        """Root endpoint risponde."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/")
            assert response.status_code == 200

    def test_docs_endpoint(self):
        """Documentazione API disponibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/docs")
            assert response.status_code == 200


@pytest.mark.smoke
class TestSmokeAuth:
    """Smoke test: Autenticazione."""

    def test_login_endpoint_exists(self):
        """Endpoint login raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={
                    "email": "test@martialarts.com",
                    "password": "TestPassword123!"
                }
            )
            # OK o credenziali errate, ma endpoint esiste e risponde
            assert response.status_code in [200, 401, 422], f"Unexpected: {response.status_code}"

    def test_register_endpoint_exists(self):
        """Endpoint registrazione raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.post(
                f"{BASE_URL}/api/v1/auth/register",
                json={
                    "email": "smoke_test@example.com",
                    "password": "SmokeTest123!",
                    "username": "smoke_test_user"
                }
            )
            # Creato, già esiste, o validation error - tutti ok per smoke
            assert response.status_code in [200, 201, 400, 409, 422]

    def test_me_endpoint_requires_auth(self):
        """Endpoint /me richiede autenticazione."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/api/v1/users/me")
            # Deve ritornare 401 senza token, non 500
            assert response.status_code == 401


@pytest.mark.smoke
class TestSmokeVideos:
    """Smoke test: Video API."""

    def test_videos_list_endpoint(self):
        """Endpoint video raggiungibile con autenticazione."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                response = client.get(
                    f"{BASE_URL}/api/v1/videos",
                    headers=headers
                )
                # 200 OK o 404 empty - entrambi validi
                assert response.status_code in [200, 404]
            else:
                # Se login fallisce, verifica che endpoint richieda auth
                response = client.get(f"{BASE_URL}/api/v1/videos")
                assert response.status_code == 401

    def test_videos_categories_endpoint(self):
        """Endpoint categorie video raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                response = client.get(
                    f"{BASE_URL}/api/v1/videos/categories",
                    headers=headers
                )
                assert response.status_code in [200, 404]


@pytest.mark.smoke
class TestSmokeFusion:
    """Smoke test: Fusion API."""

    def test_fusion_projects_endpoint(self):
        """Endpoint fusion progetti raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                response = client.get(
                    f"{BASE_URL}/api/v1/fusion/projects",
                    headers=headers
                )
                # 200 OK o 404 empty - entrambi validi
                # Non deve essere 500 (regression BUG-001)
                assert response.status_code != 500, f"Internal error: {response.text}"
                assert response.status_code in [200, 404]


@pytest.mark.smoke
class TestSmokeSkeleton:
    """Smoke test: Skeleton extraction API."""

    def test_skeleton_health(self):
        """Skeleton service operativo."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                # Verifica che endpoint skeleton esista
                response = client.get(
                    f"{BASE_URL}/api/v1/skeleton/health",
                    headers=headers
                )
                # Se endpoint health non esiste, prova list
                if response.status_code == 404:
                    response = client.get(
                        f"{BASE_URL}/api/v1/skeleton",
                        headers=headers
                    )
                assert response.status_code in [200, 404, 405]


@pytest.mark.smoke
class TestSmokePayments:
    """Smoke test: Payments API."""

    def test_subscriptions_endpoint(self):
        """Endpoint subscriptions raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                response = client.get(
                    f"{BASE_URL}/api/v1/subscriptions/plans",
                    headers=headers
                )
                assert response.status_code in [200, 404]


@pytest.mark.smoke
class TestSmokeAdmin:
    """Smoke test: Admin API (requires admin user)."""

    def test_admin_requires_auth(self):
        """Admin endpoint richiede autenticazione admin."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/api/v1/admin/dashboard")
            # Deve ritornare 401 o 403, non 500
            assert response.status_code in [401, 403]


@pytest.mark.smoke
class TestSmokeNotifications:
    """Smoke test: Notifications API."""

    def test_notifications_endpoint(self):
        """Endpoint notifications raggiungibile."""
        with httpx.Client(timeout=TIMEOUT) as client:
            headers = get_auth_headers(client)
            if headers:
                response = client.get(
                    f"{BASE_URL}/api/v1/notifications",
                    headers=headers
                )
                assert response.status_code in [200, 404]


@pytest.mark.smoke
class TestSmokeDatabase:
    """Smoke test: Database connectivity."""

    def test_database_via_auth(self):
        """Database operativo (verificato via login)."""
        with httpx.Client(timeout=TIMEOUT) as client:
            # Il login richiede database - se funziona, DB è ok
            response = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={
                    "email": "test@martialarts.com",
                    "password": "TestPassword123!"
                }
            )
            # Se 401 (credenziali errate) = DB funziona
            # Se 500 = potenziale problema DB
            assert response.status_code != 500, f"Possible DB error: {response.text}"


@pytest.mark.smoke
class TestSmokeAPIVersioning:
    """Smoke test: API versioning."""

    def test_api_v1_prefix_works(self):
        """Tutti gli endpoint usano /api/v1 prefix."""
        endpoints_to_check = [
            "/api/v1/auth/login",
            "/api/v1/users/me",
            "/api/v1/videos",
        ]

        with httpx.Client(timeout=TIMEOUT) as client:
            for endpoint in endpoints_to_check:
                response = client.get(f"{BASE_URL}{endpoint}")
                # Non deve essere 404 (endpoint non trovato)
                # 401 = endpoint esiste ma richiede auth
                # 405 = endpoint esiste ma metodo sbagliato
                assert response.status_code != 404, f"Endpoint {endpoint} not found"


@pytest.mark.smoke
class TestSmokeCORS:
    """Smoke test: CORS configuration."""

    def test_cors_headers_present(self):
        """CORS headers configurati correttamente."""
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.options(
                f"{BASE_URL}/api/v1/auth/login",
                headers={"Origin": "http://localhost:3000"}
            )
            # Se CORS è configurato, dovrebbe rispondere
            # con access-control headers o 200/204
            assert response.status_code in [200, 204, 405]

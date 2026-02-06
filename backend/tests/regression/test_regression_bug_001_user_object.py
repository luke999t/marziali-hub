"""
🎓 AI_MODULE: Regression Test - BUG-001 User Object Attribute Error
🎓 AI_DESCRIPTION: Verifica che bug 'User' object has no attribute 'get' non si ripresenti
🎓 AI_BUSINESS: Previene regressioni su endpoint fusione

BUG-001 DETAILS:
- CAUSA: current_user.get("id") chiamato su oggetto SQLAlchemy invece di dict
- FIX: Helper get_user_id() che gestisce entrambi i casi
- FILE INTERESSATI: api/v1/fusion.py, api/v1/export.py
- DATA FIX: 2026-01-19

REGOLA ZERO MOCK:
- Nessun mock, fake, patch
- Backend reale localhost:8000
- Skip se backend offline
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000"
TIMEOUT = 10.0

# Test credentials
TEST_USER_EMAIL = "test@martialarts.com"
TEST_USER_PASSWORD = "TestPassword123!"


def authenticate(client: httpx.Client) -> str:
    """Login e ritorna token."""
    response = client.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={
            "email": TEST_USER_EMAIL,
            "password": TEST_USER_PASSWORD
        }
    )
    if response.status_code == 200:
        return response.json().get("access_token")
    return None


@pytest.mark.regression
class TestRegressionBug001:
    """
    BUG-001: 'User' object has no attribute 'get'

    Questo bug si verificava quando:
    1. Utente autenticato chiama endpoint fusion
    2. current_user è un oggetto SQLAlchemy User
    3. Il codice faceva current_user.get("id") invece di current_user.id

    Il fix ha introdotto un helper get_user_id() che gestisce entrambi i casi.
    """

    def test_fusion_list_projects_no_attribute_error(self):
        """
        GET /fusion/projects NON deve dare 500 per 'User' has no attribute 'get'.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}
            response = client.get(
                f"{BASE_URL}/api/v1/fusion/projects",
                headers=headers
            )

            # REGRESSION CHECK: Non deve essere 500
            assert response.status_code != 500, \
                f"REGRESSION BUG-001: Internal Server Error - {response.text}"

            # Deve essere 200 (lista progetti) o 404 (nessun progetto)
            assert response.status_code in [200, 404], \
                f"Unexpected status: {response.status_code} - {response.text}"

    def test_fusion_create_project_no_attribute_error(self):
        """
        POST /fusion/projects NON deve dare 500 per 'User' has no attribute 'get'.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}
            response = client.post(
                f"{BASE_URL}/api/v1/fusion/projects",
                headers=headers,
                json={
                    "name": "Regression Test BUG-001",
                    "description": "Test to prevent regression",
                    "style": "karate",
                    "technique_name": "Mae-geri"
                }
            )

            # REGRESSION CHECK: Non deve essere 500
            assert response.status_code != 500, \
                f"REGRESSION BUG-001: Internal Server Error - {response.text}"

            # 201 (creato), 200, o 403 (non autorizzato) sono tutti ok
            assert response.status_code in [200, 201, 403, 422], \
                f"Unexpected status: {response.status_code} - {response.text}"

            # Cleanup se creato
            if response.status_code in [200, 201]:
                project_id = response.json().get("id")
                if project_id:
                    client.delete(
                        f"{BASE_URL}/api/v1/fusion/projects/{project_id}",
                        headers=headers
                    )

    def test_fusion_get_project_no_attribute_error(self):
        """
        GET /fusion/projects/{id} NON deve dare 500 per 'User' has no attribute 'get'.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Prima crea un progetto
            create_response = client.post(
                f"{BASE_URL}/api/v1/fusion/projects",
                headers=headers,
                json={
                    "name": "Regression Test Detail",
                    "style": "karate"
                }
            )

            if create_response.status_code not in [200, 201]:
                pytest.skip("Cannot create test project")

            project_id = create_response.json().get("id")

            try:
                # Test get detail
                get_response = client.get(
                    f"{BASE_URL}/api/v1/fusion/projects/{project_id}",
                    headers=headers
                )

                # REGRESSION CHECK: Non deve essere 500
                assert get_response.status_code != 500, \
                    f"REGRESSION BUG-001: Internal Server Error - {get_response.text}"

                assert get_response.status_code == 200

            finally:
                # Cleanup
                client.delete(
                    f"{BASE_URL}/api/v1/fusion/projects/{project_id}",
                    headers=headers
                )

    def test_export_endpoints_no_attribute_error(self):
        """
        Export endpoints NON devono dare 500 per 'User' has no attribute 'get'.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Test list exports
            list_response = client.get(
                f"{BASE_URL}/api/v1/export/blender",
                headers=headers
            )

            # REGRESSION CHECK: Non deve essere 500
            assert list_response.status_code != 500, \
                f"REGRESSION BUG-001 (export): Internal Server Error - {list_response.text}"

            # 200, 404, o endpoint diverso
            assert list_response.status_code in [200, 404, 405]


@pytest.mark.regression
class TestRegressionBug001EdgeCases:
    """
    Edge cases per BUG-001 - verifica in scenari limite.
    """

    def test_multiple_rapid_requests_no_500(self):
        """
        Richieste rapide consecutive non devono causare 500.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # 5 richieste rapide
            for i in range(5):
                response = client.get(
                    f"{BASE_URL}/api/v1/fusion/projects",
                    headers=headers
                )
                assert response.status_code != 500, \
                    f"REGRESSION BUG-001: 500 on request {i+1}"

    def test_concurrent_user_endpoints_no_500(self):
        """
        Diversi endpoint user-authenticated non devono dare 500.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            endpoints = [
                "/api/v1/fusion/projects",
                "/api/v1/users/me",
                "/api/v1/videos",
                "/api/v1/notifications",
            ]

            for endpoint in endpoints:
                response = client.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers
                )
                # Nessun endpoint deve dare 500
                assert response.status_code != 500, \
                    f"REGRESSION: 500 on {endpoint} - {response.text}"

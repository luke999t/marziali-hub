"""
🎓 AI_MODULE: Regression Test - BUG-002 Database Session Empty Error
🎓 AI_DESCRIPTION: Verifica che errori database vuoti non si ripresentino
🎓 AI_BUSINESS: Previene errori silenziosi del database

BUG-002 DETAILS:
- CAUSA: get_db_optional falliva silenziosamente senza logging
- FIX: Logging migliorato + gestione errore esplicita
- SINTOMO: Response 500 con body vuoto o errore generico
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


@pytest.mark.regression
class TestRegressionBug002:
    """
    BUG-002: Database session error vuoto

    Questo bug si verificava quando:
    1. Database connection falliva
    2. get_db_optional non loggava l'errore
    3. Response era 500 con body vuoto o messaggio generico

    Il fix ha introdotto logging dettagliato e messaggi di errore espliciti.
    """

    def test_authenticated_endpoints_return_meaningful_errors(self):
        """
        Endpoint autenticati NON devono dare errori vuoti.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            # Token invalido
            headers = {"Authorization": "Bearer invalid_token_12345"}

            endpoints_to_test = [
                "/api/v1/fusion/projects",
                "/api/v1/users/me",
                "/api/v1/videos",
            ]

            for endpoint in endpoints_to_test:
                response = client.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers
                )

                # REGRESSION CHECK: Deve dare 401, non 500 con errore vuoto
                assert response.status_code == 401, \
                    f"Expected 401 for {endpoint}, got {response.status_code}"

                # Deve avere un messaggio di errore
                try:
                    error_data = response.json()
                    assert "detail" in error_data or "message" in error_data, \
                        f"No error message in response for {endpoint}"
                except Exception:
                    # Se non è JSON, deve comunque avere un body
                    assert response.text, \
                        f"REGRESSION BUG-002: Empty error response for {endpoint}"

    def test_malformed_token_returns_clear_error(self):
        """
        Token malformato deve ritornare errore chiaro.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            # Token completamente malformato
            headers = {"Authorization": "NotBearer just_garbage"}

            response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )

            # Deve essere 401, non 500
            assert response.status_code in [401, 403], \
                f"Expected 401/403 for malformed token, got {response.status_code}"

    def test_expired_token_returns_clear_error(self):
        """
        Token scaduto deve ritornare errore chiaro (non 500 vuoto).
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            # Token che sembra valido ma è scaduto
            expired_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxfQ.invalid"
            headers = {"Authorization": f"Bearer {expired_token}"}

            response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )

            # Deve essere 401, non 500
            assert response.status_code == 401, \
                f"Expected 401 for expired token, got {response.status_code}"

            # Deve avere messaggio
            assert response.text, "REGRESSION BUG-002: Empty response for expired token"

    def test_no_auth_header_returns_401_not_500(self):
        """
        Richiesta senza header Authorization deve dare 401, non 500.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            protected_endpoints = [
                "/api/v1/users/me",
                "/api/v1/fusion/projects",
                "/api/v1/videos",
                "/api/v1/notifications",
            ]

            for endpoint in protected_endpoints:
                response = client.get(f"{BASE_URL}{endpoint}")

                # REGRESSION CHECK: Mai 500
                assert response.status_code != 500, \
                    f"REGRESSION BUG-002: 500 without auth on {endpoint}"

                # Deve essere 401
                assert response.status_code == 401, \
                    f"Expected 401 for {endpoint} without auth, got {response.status_code}"


@pytest.mark.regression
class TestRegressionBug002DatabaseErrors:
    """
    Test specifici per gestione errori database.
    """

    def test_health_check_verifies_db_connection(self):
        """
        Health check deve verificare connessione database.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.get(f"{BASE_URL}/health")

            assert response.status_code == 200, \
                f"Health check failed: {response.text}"

            health_data = response.json()

            # Se c'è un campo database, deve essere healthy
            if "database" in health_data:
                assert health_data["database"] in ["healthy", "ok", True], \
                    "Database not healthy"

    def test_login_validates_db_access(self):
        """
        Login richiede accesso DB - se fallisce, errore deve essere chiaro.
        """
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={
                    "email": "test@martialarts.com",
                    "password": "TestPassword123!"
                }
            )

            # 200 (login ok) o 401 (credenziali errate) = DB funziona
            # 500 = possibile problema DB
            if response.status_code == 500:
                # Se 500, verifica che ci sia un messaggio
                assert response.text, \
                    "REGRESSION BUG-002: Empty 500 response on login"

                # Il messaggio non deve essere generico
                error_text = response.text.lower()
                assert "internal server error" not in error_text or \
                       len(response.text) > 30, \
                    "REGRESSION BUG-002: Generic 500 message without details"

            # In condizioni normali, deve essere 200 o 401
            assert response.status_code in [200, 401, 422], \
                f"Unexpected status on login: {response.status_code}"

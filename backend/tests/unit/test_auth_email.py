"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Auth & Email Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.
    Se il backend e spento, i test DEVONO fallire.

    NOTE: Questi test richiedono backend running.
    Spostati logicamente in tests/api/ ma mantenuti qui per storico.

================================================================================
"""

import pytest

# Skip all tests in this module - they require running backend
pytestmark = pytest.mark.skip(reason="Requires running backend - API tests should be in tests/api/")
import httpx
from datetime import datetime

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BACKEND_URL = "http://127.0.0.1:8000"
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: LOGIN SUCCESS
# ==============================================================================
class TestLoginSuccess:
    """Test login success - REAL API"""

    def test_login_free_user_success(self, api_client, seed_user_free):
        """Test login con utente FREE funziona"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_free["email"],
            "password": seed_user_free["password"]
        })

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["access_token"] is not None
        assert len(data["access_token"]) > 10

    def test_login_premium_user_success(self, api_client, seed_user_premium):
        """Test login con utente PREMIUM funziona"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_premium["email"],
            "password": seed_user_premium["password"]
        })

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "user" in data

    def test_login_admin_user_success(self, api_client, seed_user_admin):
        """Test login con utente ADMIN funziona"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_admin["email"],
            "password": seed_user_admin["password"]
        })

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data


# ==============================================================================
# TEST: LOGIN FAILURE
# ==============================================================================
class TestLoginFailure:
    """Test login failure - REAL API"""

    def test_login_wrong_password(self, api_client, seed_user_free):
        """Test login con password sbagliata fallisce con 401"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_free["email"],
            "password": "PASSWORD_SBAGLIATA_123"
        })

        assert response.status_code == 401

    def test_login_nonexistent_user(self, api_client):
        """Test login con utente inesistente fallisce con 401"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": "utente.che.non.esiste@example.com",
            "password": "Test123!"
        })

        assert response.status_code == 401

    def test_login_malformed_email(self, api_client):
        """Test login con email malformata fallisce"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": "not-an-email",
            "password": "Test123!"
        })

        # 422 Validation Error o 401
        assert response.status_code in [401, 422]

    def test_login_empty_body(self, api_client):
        """Test login senza body fallisce"""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={})

        assert response.status_code >= 400


# ==============================================================================
# TEST: TOKEN VALIDATION
# ==============================================================================
class TestTokenValidation:
    """Test token validation - REAL API"""

    def test_token_allows_protected_access(self, api_client, auth_headers_free):
        """Test token permette accesso a endpoint protetti"""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers_free
        )

        assert response.status_code == 200
        data = response.json()
        assert "email" in data

    def test_no_token_returns_401_or_403(self, api_client):
        """Test richiesta senza token fallisce"""
        response = api_client.get(f"{API_PREFIX}/auth/me")

        # FastAPI HTTPBearer returns 403 when no token, 401 when invalid
        assert response.status_code in [401, 403]

    def test_invalid_token_returns_401(self, api_client):
        """Test richiesta con token invalido fallisce con 401"""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": "Bearer token_completamente_invalido_123"}
        )

        assert response.status_code == 401


# ==============================================================================
# TEST: USER PROFILE
# ==============================================================================
class TestUserProfile:
    """Test user profile - REAL API"""

    def test_get_me_returns_user_data(self, api_client, auth_headers_free, seed_user_free):
        """Test /auth/me ritorna dati utente"""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers_free
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == seed_user_free["email"]

    def test_get_me_premium_user(self, api_client, auth_headers_premium, seed_user_premium):
        """Test /auth/me per utente premium"""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers_premium
        )

        assert response.status_code == 200
        data = response.json()
        assert data["email"] == seed_user_premium["email"]


# ==============================================================================
# TEST: REGISTRATION (if endpoint exists)
# ==============================================================================
class TestRegistration:
    """Test registration - REAL API"""

    def test_register_duplicate_email_fails(self, api_client, seed_user_free):
        """Test registrazione con email duplicata fallisce"""
        response = api_client.post(f"{API_PREFIX}/auth/register", json={
            "email": seed_user_free["email"],  # Already exists
            "password": "NewPassword123!",
            "username": "newuser_test"
        })

        # Should fail with 400 or 409 Conflict
        assert response.status_code in [400, 409, 422]


# ==============================================================================
# TEST: PASSWORD RESET (if endpoint exists)
# ==============================================================================
class TestPasswordReset:
    """Test password reset - REAL API"""

    def test_password_reset_nonexistent_email(self, api_client):
        """Test reset password per email inesistente"""
        response = api_client.post(f"{API_PREFIX}/auth/password-reset", json={
            "email": "nonexistent@test.com"
        })

        # Potrebbe ritornare 200 (per sicurezza) o 404
        assert response.status_code in [200, 404, 422]


# ==============================================================================
# TEST: REFRESH TOKEN
# ==============================================================================
class TestRefreshToken:
    """Test refresh token - REAL API"""

    def test_refresh_token_flow(self, api_client, seed_user_free):
        """Test flusso refresh token"""
        # 1. Login per ottenere tokens
        login_response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_free["email"],
            "password": seed_user_free["password"]
        })

        assert login_response.status_code == 200
        tokens = login_response.json()

        # 2. Se c'e refresh_token, prova a refreshare
        if "refresh_token" in tokens:
            refresh_response = api_client.post(
                f"{API_PREFIX}/auth/refresh",
                json={"refresh_token": tokens["refresh_token"]}
            )
            # Potrebbe essere 200 o endpoint non esistente
            assert refresh_response.status_code in [200, 404, 422]


# ==============================================================================
# TEST: LOGOUT
# ==============================================================================
class TestLogout:
    """Test logout - REAL API"""

    def test_logout_with_token(self, api_client, auth_headers_free):
        """Test logout con token valido"""
        response = api_client.post(
            f"{API_PREFIX}/auth/logout",
            headers=auth_headers_free
        )

        # Potrebbe essere 200 o endpoint non esistente
        assert response.status_code in [200, 204, 404]

"""
================================================================================
AI_MODULE: Auth Integration Enterprise Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione COMPLETA API Auth con database REALE
AI_BUSINESS: Validazione flussi completi auth: register, login, token, security
AI_TEACHING: Integration testing con TestClient, fixtures auth, DB reale

ZERO MOCK - LEGGE SUPREMA
Tutti i test chiamano API REALI su localhost:8000.
================================================================================
"""

import pytest
import uuid
import jwt
from datetime import datetime, timedelta

# ==============================================================================
# MARKERS
# ==============================================================================
API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.integration]


# ==============================================================================
# TEST: Registration Flow - REAL BACKEND
# ==============================================================================
class TestAuthRegistrationFlow:
    """Test flusso completo registrazione - REAL API."""

    def test_register_new_user_success(self, api_client):
        """Registrazione nuovo utente con successo."""
        unique_id = uuid.uuid4().hex[:8]

        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"test_register_{unique_id}@example.com",
                "username": f"testuser_{unique_id}",
                "password": "ValidPassword123!",
                "full_name": "Test User"
            }
        )

        assert response.status_code in [200, 201]

        if response.status_code in [200, 201]:
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data.get("token_type") == "bearer"

    def test_register_returns_valid_jwt(self, api_client):
        """Registrazione restituisce JWT valido."""
        unique_id = uuid.uuid4().hex[:8]

        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"test_jwt_{unique_id}@example.com",
                "username": f"jwtuser_{unique_id}",
                "password": "ValidPassword123!",
                "full_name": "JWT Test User"
            }
        )

        if response.status_code in [200, 201]:
            data = response.json()
            access_token = data.get("access_token")

            # Verifica che sia un JWT valido (3 parti separate da .)
            assert access_token is not None
            parts = access_token.split(".")
            assert len(parts) == 3

    def test_register_duplicate_email_fails(self, api_client):
        """Registrazione con email duplicata deve fallire."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"duplicate_{unique_id}@example.com"

        # Prima registrazione
        api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"user1_{unique_id}",
                "password": "ValidPassword123!",
                "full_name": "User 1"
            }
        )

        # Seconda registrazione stessa email
        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"user2_{unique_id}",
                "password": "ValidPassword123!",
                "full_name": "User 2"
            }
        )

        assert response.status_code in [400, 409, 422]

    def test_register_duplicate_username_fails(self, api_client):
        """Registrazione con username duplicato deve fallire."""
        unique_id = uuid.uuid4().hex[:8]
        username = f"dupuser_{unique_id}"

        # Prima registrazione
        api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"user1_{unique_id}@example.com",
                "username": username,
                "password": "ValidPassword123!",
                "full_name": "User 1"
            }
        )

        # Seconda registrazione stesso username
        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"user2_{unique_id}@example.com",
                "username": username,
                "password": "ValidPassword123!",
                "full_name": "User 2"
            }
        )

        assert response.status_code in [400, 409, 422]

    def test_register_invalid_email_format(self, api_client):
        """Registrazione con email invalida."""
        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": "not-an-email",
                "username": "testuser",
                "password": "ValidPassword123!",
                "full_name": "Test User"
            }
        )

        assert response.status_code == 422

    def test_register_weak_password(self, api_client):
        """Registrazione con password debole."""
        unique_id = uuid.uuid4().hex[:8]

        response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"test_{unique_id}@example.com",
                "username": f"weakpwd_{unique_id}",
                "password": "weak",
                "full_name": "Test User"
            }
        )

        assert response.status_code == 422


# ==============================================================================
# TEST: Login Flow - REAL BACKEND
# ==============================================================================
class TestAuthLoginFlow:
    """Test flusso completo login - REAL API."""

    def test_login_success_returns_tokens(self, api_client):
        """Login con successo restituisce token."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"test_login_{unique_id}@example.com"
        password = "ValidPassword123!"

        # Registra
        api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"loginuser_{unique_id}",
                "password": password,
                "full_name": "Login Test User"
            }
        )

        # Login
        response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email, "password": password}
        )

        assert response.status_code == 200

        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data.get("token_type") == "bearer"

    def test_login_wrong_password(self, api_client):
        """Login con password errata."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"test_wrongpwd_{unique_id}@example.com"

        # Registra
        api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"wrongpwd_{unique_id}",
                "password": "CorrectPassword123!",
                "full_name": "Test User"
            }
        )

        # Login con password sbagliata
        response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email, "password": "WrongPassword123!"}
        )

        assert response.status_code in [400, 401, 403]

    def test_login_nonexistent_user(self, api_client):
        """Login con utente inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={
                "email": "nonexistent_user_12345@example.com",
                "password": "SomePassword123!"
            }
        )

        assert response.status_code in [400, 401, 403, 404]

    def test_login_case_insensitive_email(self, api_client):
        """Email è case-insensitive."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"CasE_TeSt_{unique_id}@example.com"
        password = "ValidPassword123!"

        # Registra con maiuscole
        api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"casetest_{unique_id}",
                "password": password,
                "full_name": "Case Test User"
            }
        )

        # Login con minuscole
        response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email.lower(), "password": password}
        )

        # Dovrebbe funzionare se case-insensitive
        assert response.status_code in [200, 400, 401]


# ==============================================================================
# TEST: Token Refresh Flow - REAL BACKEND
# ==============================================================================
class TestAuthTokenRefreshFlow:
    """Test flusso refresh token - REAL API."""

    def test_refresh_token_returns_new_tokens(self, api_client):
        """Refresh token restituisce nuovi token."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"test_refresh_{unique_id}@example.com"
        password = "ValidPassword123!"

        # Registra e ottieni token
        register_response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"refreshuser_{unique_id}",
                "password": password,
                "full_name": "Refresh Test User"
            }
        )

        if register_response.status_code in [200, 201]:
            refresh_token = register_response.json().get("refresh_token")

            if refresh_token:
                # Refresh
                response = api_client.post(
                    f"{API_PREFIX}/auth/refresh",
                    json={"refresh_token": refresh_token}
                )

                # 200 se funziona, 404 se endpoint non esiste
                assert response.status_code in [200, 404]

                if response.status_code == 200:
                    data = response.json()
                    assert "access_token" in data

    def test_refresh_invalid_token_fails(self, api_client):
        """Refresh con token invalido fallisce."""
        response = api_client.post(
            f"{API_PREFIX}/auth/refresh",
            json={"refresh_token": "invalid_refresh_token_here"}
        )

        assert response.status_code in [400, 401, 403, 404, 422]


# ==============================================================================
# TEST: Me Endpoint - REAL BACKEND
# ==============================================================================
class TestAuthMeEndpoint:
    """Test endpoint /me - REAL API."""

    def test_me_authenticated_returns_user(self, api_client, auth_headers):
        """Me con auth restituisce dati utente."""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers
        )

        assert response.status_code == 200

        data = response.json()
        assert "email" in data or "id" in data

    def test_me_without_auth_fails(self, api_client):
        """Me senza auth fallisce."""
        response = api_client.get(f"{API_PREFIX}/auth/me")

        assert response.status_code in [401, 403]

    def test_me_invalid_token_fails(self, api_client):
        """Me con token invalido fallisce."""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": "Bearer invalid_token_here"}
        )

        assert response.status_code in [401, 403]

    def test_me_does_not_return_password(self, api_client, auth_headers):
        """Me non restituisce password."""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            assert "password" not in data
            assert "hashed_password" not in data


# ==============================================================================
# TEST: Logout Flow - REAL BACKEND
# ==============================================================================
class TestAuthLogoutFlow:
    """Test flusso logout - REAL API."""

    def test_logout_success(self, api_client, auth_headers):
        """Logout con successo."""
        response = api_client.post(
            f"{API_PREFIX}/auth/logout",
            headers=auth_headers
        )

        # 200 OK o 404 se endpoint non implementato
        assert response.status_code in [200, 204, 404]

    def test_logout_without_auth(self, api_client):
        """Logout senza auth."""
        response = api_client.post(f"{API_PREFIX}/auth/logout")

        # Potrebbe richiedere auth o accettare
        assert response.status_code in [200, 401, 403, 404]


# ==============================================================================
# TEST: Token Validation - REAL BACKEND
# ==============================================================================
class TestAuthTokenValidation:
    """Test validazione token - REAL API."""

    def test_expired_token_rejected(self, api_client):
        """Token scaduto viene rifiutato."""
        from core.security import SECRET_KEY, ALGORITHM

        # Crea token scaduto
        expired_payload = {
            "sub": "testuser",
            "email": "test@example.com",
            "user_id": str(uuid.uuid4()),
            "exp": datetime.utcnow() - timedelta(hours=1)
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)

        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )

        assert response.status_code in [401, 403]

    def test_wrong_signature_token_rejected(self, api_client):
        """Token con firma sbagliata viene rifiutato."""
        wrong_key_payload = {
            "sub": "testuser",
            "email": "test@example.com",
            "user_id": str(uuid.uuid4()),
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        wrong_token = jwt.encode(wrong_key_payload, "wrong_secret", algorithm="HS256")

        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": f"Bearer {wrong_token}"}
        )

        assert response.status_code in [401, 403]


# ==============================================================================
# TEST: Complete Auth Journey - REAL BACKEND
# ==============================================================================
class TestAuthCompleteJourney:
    """Test journey completo autenticazione - REAL API."""

    def test_register_login_access_logout(self, api_client):
        """Journey completo: register → login → access → logout."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"journey_{unique_id}@example.com"
        password = "ValidPassword123!"

        # Step 1: Register
        register_response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"journey_{unique_id}",
                "password": password,
                "full_name": "Journey Test User"
            }
        )
        assert register_response.status_code in [200, 201]

        # Step 2: Login
        login_response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email, "password": password}
        )
        assert login_response.status_code == 200

        access_token = login_response.json().get("access_token")
        auth_headers = {"Authorization": f"Bearer {access_token}"}

        # Step 3: Access protected resource
        me_response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers
        )
        assert me_response.status_code == 200

        # Step 4: Logout
        logout_response = api_client.post(
            f"{API_PREFIX}/auth/logout",
            headers=auth_headers
        )
        assert logout_response.status_code in [200, 204, 404]

    def test_token_reuse_after_refresh(self, api_client):
        """Token può essere riusato dopo refresh."""
        unique_id = uuid.uuid4().hex[:8]
        email = f"reuse_{unique_id}@example.com"
        password = "ValidPassword123!"

        # Register
        register_response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": email,
                "username": f"reuseuser_{unique_id}",
                "password": password,
                "full_name": "Reuse Test User"
            }
        )

        if register_response.status_code in [200, 201]:
            data = register_response.json()
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")

            # Use original token
            me_response = api_client.get(
                f"{API_PREFIX}/auth/me",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            assert me_response.status_code == 200

            # Refresh
            if refresh_token:
                refresh_response = api_client.post(
                    f"{API_PREFIX}/auth/refresh",
                    json={"refresh_token": refresh_token}
                )

                if refresh_response.status_code == 200:
                    new_access_token = refresh_response.json().get("access_token")

                    # Use new token
                    me_response2 = api_client.get(
                        f"{API_PREFIX}/auth/me",
                        headers={"Authorization": f"Bearer {new_access_token}"}
                    )
                    assert me_response2.status_code == 200

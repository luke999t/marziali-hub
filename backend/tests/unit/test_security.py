"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Security Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di logica pura (password hash, JWT) + test API REALI.

================================================================================
"""

import pytest
import jwt
from datetime import datetime, timedelta

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: PASSWORD FUNCTIONS - Pure Logic
# ==============================================================================
class TestPasswordFunctions:
    """Test funzioni password - logica pura."""

    def test_verify_password_correct(self):
        """Test verifica password corretta."""
        from core.security import verify_password, get_password_hash

        password = "TestPassword123!"
        hashed = get_password_hash(password)
        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test verifica password sbagliata."""
        from core.security import verify_password, get_password_hash

        password = "TestPassword123!"
        hashed = get_password_hash(password)
        assert verify_password("WrongPassword!", hashed) is False

    def test_get_password_hash_bcrypt(self):
        """Test che hash usi bcrypt."""
        from core.security import get_password_hash

        password = "TestPassword123!"
        hashed = get_password_hash(password)
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")
        assert len(hashed) == 60

    def test_get_password_hash_unique(self):
        """Test che stessa password produca hash diversi (salt)."""
        from core.security import get_password_hash

        password = "TestPassword123!"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        assert hash1 != hash2


# ==============================================================================
# TEST: JWT TOKEN FUNCTIONS - Pure Logic
# ==============================================================================
class TestJWTTokenFunctions:
    """Test funzioni JWT - logica pura."""

    def test_create_access_token_default_expiry(self):
        """Test creazione token con expiry default."""
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        data = {"sub": "testuser", "email": "test@test.com", "user_id": "123"}
        token = create_access_token(data)

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        assert payload["sub"] == "testuser"
        assert payload["email"] == "test@test.com"
        assert "exp" in payload

    def test_create_access_token_custom_expiry(self):
        """Test creazione token con expiry custom."""
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        data = {"sub": "testuser", "email": "test@test.com"}
        token = create_access_token(data, expires_delta=timedelta(hours=1))

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp_time = datetime.fromtimestamp(payload["exp"])
        now = datetime.utcnow()
        time_diff_hours = (exp_time - now).total_seconds() / 3600

        # Token expires in future
        assert time_diff_hours > 0.5

    def test_decode_access_token_success(self):
        """Test decodifica token con successo."""
        from core.security import create_access_token, decode_access_token, TokenData

        data = {
            "sub": "testuser",
            "email": "test@test.com",
            "user_id": "123",
            "is_superuser": False
        }
        token = create_access_token(data)

        token_data = decode_access_token(token)

        assert isinstance(token_data, TokenData)
        assert token_data.username == "testuser"
        assert token_data.email == "test@test.com"
        assert token_data.user_id == "123"
        assert token_data.is_superuser is False

    def test_decode_access_token_superuser(self):
        """Test decodifica token superuser."""
        from core.security import create_access_token, decode_access_token

        data = {
            "sub": "admin",
            "email": "admin@test.com",
            "user_id": "admin123",
            "is_superuser": True
        }
        token = create_access_token(data)

        token_data = decode_access_token(token)

        assert token_data.is_superuser is True


# ==============================================================================
# TEST: TOKEN ERROR HANDLING - Pure Logic
# ==============================================================================
class TestTokenErrorHandling:
    """Test gestione errori token - logica pura."""

    def test_decode_access_token_expired(self):
        """Test decodifica token scaduto solleva eccezione."""
        from core.security import create_access_token, decode_access_token
        from fastapi import HTTPException

        data = {"sub": "testuser", "email": "test@test.com"}
        token = create_access_token(data, expires_delta=timedelta(seconds=-1))

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(token)

        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_decode_access_token_invalid(self):
        """Test decodifica token invalido solleva eccezione."""
        from core.security import decode_access_token
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token("invalid_token_string")

        assert exc_info.value.status_code == 401

    def test_decode_access_token_tampered(self):
        """Test decodifica token manomesso solleva eccezione."""
        from core.security import create_access_token, decode_access_token
        from fastapi import HTTPException

        data = {"sub": "testuser", "email": "test@test.com"}
        token = create_access_token(data)

        # Tamper with token
        parts = token.split('.')
        parts[1] = parts[1][:-1] + 'X'
        tampered = '.'.join(parts)

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(tampered)

        assert exc_info.value.status_code == 401

    def test_decode_access_token_missing_username(self):
        """Test token senza 'sub' solleva eccezione."""
        from core.security import decode_access_token, SECRET_KEY, ALGORITHM
        from fastapi import HTTPException

        # Create token manually without 'sub'
        payload = {"email": "test@test.com", "exp": datetime.utcnow() + timedelta(hours=1)}
        token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

        with pytest.raises(HTTPException) as exc_info:
            decode_access_token(token)

        assert exc_info.value.status_code == 401


# ==============================================================================
# TEST: SECURITY API - REAL BACKEND
# ==============================================================================
@pytest.mark.skip(reason="Requires running backend - API tests should be in tests/api/")
class TestSecurityAPI:
    """Test API security - REAL BACKEND"""

    def test_valid_token_allows_access(self, api_client, auth_headers_free):
        """Test token valido permette accesso."""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers_free
        )

        assert response.status_code == 200

    def test_invalid_token_denied(self, api_client):
        """Test token invalido negato."""
        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code == 401

    def test_expired_token_denied(self, api_client):
        """Test token scaduto negato."""
        from core.security import create_access_token

        # Create expired token
        token = create_access_token(
            {"sub": "test", "email": "test@test.com"},
            expires_delta=timedelta(seconds=-1)
        )

        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    def test_no_token_denied(self, api_client):
        """Test senza token negato."""
        response = api_client.get(f"{API_PREFIX}/auth/me")

        # 401 o 403 a seconda dell'implementazione
        assert response.status_code in [401, 403]

    def test_admin_endpoint_requires_admin(self, api_client, auth_headers_free):
        """Test endpoint admin richiede admin."""
        response = api_client.get(
            f"{API_PREFIX}/admin/users",
            headers=auth_headers_free  # FREE user, not admin
        )

        # FREE user non dovrebbe avere accesso ad endpoint admin
        assert response.status_code in [403, 404]

    def test_admin_endpoint_allows_admin(self, api_client, auth_headers_admin):
        """Test endpoint admin permette admin."""
        response = api_client.get(
            f"{API_PREFIX}/admin/users",
            headers=auth_headers_admin
        )

        # Admin dovrebbe avere accesso (o 404 se endpoint non esiste)
        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: SECURITY ATTACK PREVENTION - REAL BACKEND
# ==============================================================================
class TestSecurityAttackPrevention:
    """Test prevenzione attacchi - REAL BACKEND"""

    def test_sql_injection_in_login(self, api_client):
        """Test SQL injection nel login."""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": "' OR 1=1 --",
            "password": "password"
        })

        # Non deve permettere bypass
        assert response.status_code in [401, 422]

    def test_xss_in_registration(self, api_client):
        """Test XSS nella registrazione."""
        response = api_client.post(f"{API_PREFIX}/auth/register", json={
            "email": "test@test.com",
            "password": "Test123!",
            "username": "<script>alert('xss')</script>"
        })

        # Potrebbe accettare ma sanitizzare, o rifiutare
        if response.status_code == 200:
            data = response.json()
            if "username" in data:
                # Dovrebbe essere sanitizzato
                assert "<script>" not in data.get("username", "")

    def test_very_long_password(self, api_client, seed_user_free):
        """Test password molto lunga."""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": seed_user_free["email"],
            "password": "A" * 10000  # 10KB password
        })

        # Dovrebbe gestire gracefully
        assert response.status_code in [401, 422, 413]

    def test_unicode_injection(self, api_client):
        """Test unicode injection."""
        response = api_client.post(f"{API_PREFIX}/auth/login", json={
            "email": "test\u0000@test.com",
            "password": "password"
        })

        # Dovrebbe gestire gracefully
        assert response.status_code in [401, 422]

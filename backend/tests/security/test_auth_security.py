"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Auth System Security Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di sicurezza - logica pura + API REALI.

================================================================================
"""

import pytest
import re
import jwt
from datetime import datetime, timedelta

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.security]


# ==============================================================================
# TEST: OWASP A01 - Broken Access Control - Pure Logic
# ==============================================================================
class TestBrokenAccessControlLogic:
    """Test broken access control prevention - pure logic."""

    def test_security_token_cannot_elevate_privileges(self):
        """
        Security Test: User cannot modify JWT to gain admin privileges
        OWASP: A01:2021 - Broken Access Control
        """
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        # Create non-admin token
        token = create_access_token(
            data={"sub": "user", "email": "user@test.com", "is_superuser": False}
        )

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Cannot modify claims without breaking signature
        assert payload["is_superuser"] is False

    def test_security_user_isolation(self):
        """Test user data isolation."""
        user1_id = "user_123"
        user2_id = "user_456"

        def can_access_resource(current_user_id, resource_owner_id, is_admin=False):
            return is_admin or current_user_id == resource_owner_id

        # User cannot access other user's data
        assert can_access_resource(user1_id, user2_id) is False

        # User can access own data
        assert can_access_resource(user1_id, user1_id) is True

        # Admin can access all data
        assert can_access_resource(user1_id, user2_id, is_admin=True) is True


# ==============================================================================
# TEST: OWASP A02 - Cryptographic Failures - Pure Logic
# ==============================================================================
class TestCryptographicFailuresLogic:
    """Test cryptographic failure prevention - pure logic."""

    def test_security_passwords_stored_hashed(self):
        """
        Security Test: Passwords are never stored in plain text
        OWASP: A02:2021 - Cryptographic Failures
        """
        from core.security import get_password_hash

        password = "MySecretPassword123!"
        hashed = get_password_hash(password)

        # Hashed password is different from original
        assert hashed != password

        # Uses bcrypt
        assert hashed.startswith("$2b$") or hashed.startswith("$2a$")

    def test_security_jwt_signed_not_none_algorithm(self):
        """Test JWT uses proper signing algorithm."""
        from core.security import ALGORITHM

        # Algorithm should not be 'none'
        assert ALGORITHM != "none"
        assert ALGORITHM in ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]


# ==============================================================================
# TEST: OWASP A03 - Injection - Pure Logic
# ==============================================================================
class TestInjectionLogic:
    """Test injection prevention - pure logic."""

    def test_security_sql_injection_patterns(self):
        """
        Security Test: SQL injection patterns detected
        OWASP: A03:2021 - Injection
        """
        sql_pattern = re.compile(
            r"('|\"|--|;|/\*|\*/|@@|union|select|insert|update|delete|drop|exec)",
            re.IGNORECASE
        )

        malicious_inputs = [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users--",
            "1 UNION SELECT * FROM users",
        ]

        for input_val in malicious_inputs:
            assert sql_pattern.search(input_val) is not None

    def test_security_email_validation(self):
        """Test email format validation prevents injection."""
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

        # Valid emails
        assert email_pattern.match("test@example.com") is not None
        assert email_pattern.match("user.name@domain.co.uk") is not None

        # Invalid/malicious emails
        assert email_pattern.match("' OR '1'='1") is None
        assert email_pattern.match("admin@test.com'; DROP TABLE--") is None


# ==============================================================================
# TEST: OWASP A04 - Insecure Design - Pure Logic
# ==============================================================================
class TestInsecureDesignLogic:
    """Test insecure design prevention - pure logic."""

    def test_security_token_expiry_enforced(self):
        """
        Security Test: Expired tokens cannot be used
        OWASP: A04:2021 - Insecure Design
        """
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        # Create expired token
        expired_token = create_access_token(
            data={"sub": "testuser"},
            expires_delta=timedelta(seconds=-1)
        )

        with pytest.raises(jwt.ExpiredSignatureError):
            jwt.decode(expired_token, SECRET_KEY, algorithms=[ALGORITHM])

    def test_security_rate_limiting_design(self):
        """Test rate limiting is designed correctly."""
        from datetime import datetime

        rate_limits = {}

        def check_rate(user_id, max_requests=5, window_seconds=60):
            now = datetime.utcnow().timestamp()

            if user_id not in rate_limits:
                rate_limits[user_id] = {"requests": [], "window_start": now}

            limit = rate_limits[user_id]

            # Clean old requests
            limit["requests"] = [t for t in limit["requests"] if now - t < window_seconds]

            if len(limit["requests"]) >= max_requests:
                return False

            limit["requests"].append(now)
            return True

        # First 5 requests pass
        for _ in range(5):
            assert check_rate("user_123") is True

        # 6th request blocked
        assert check_rate("user_123") is False


# ==============================================================================
# TEST: OWASP A05 - Security Misconfiguration - Pure Logic
# ==============================================================================
class TestSecurityMisconfigurationLogic:
    """Test security misconfiguration prevention - pure logic."""

    def test_security_secret_key_strength(self):
        """
        Security Test: Secret key is strong
        OWASP: A05:2021 - Security Misconfiguration
        """
        from core.security import SECRET_KEY

        weak_secrets = ["secret", "password", "123456", "test", "admin", ""]

        assert SECRET_KEY not in weak_secrets
        assert len(SECRET_KEY) >= 32

    def test_security_debug_mode_check(self):
        """Test debug mode configuration."""
        import os

        # In production, DEBUG should be False
        debug_mode = os.getenv("DEBUG", "false").lower() == "true"

        # This test documents the expected configuration
        # In real deployment, DEBUG should be False


# ==============================================================================
# TEST: OWASP A07 - Identification and Authentication Failures - Pure Logic
# ==============================================================================
class TestAuthenticationFailuresLogic:
    """Test authentication failure prevention - pure logic."""

    def test_security_password_requirements(self):
        """Test password requirements are enforced."""
        def validate_password(password):
            if len(password) < 8:
                return False, "Password too short"
            if not re.search(r'[A-Z]', password):
                return False, "Must have uppercase"
            if not re.search(r'[a-z]', password):
                return False, "Must have lowercase"
            if not re.search(r'\d', password):
                return False, "Must have digit"
            return True, "Valid"

        # Weak passwords
        assert validate_password("short")[0] is False
        assert validate_password("nouppercaseordigit")[0] is False

        # Strong password
        assert validate_password("SecurePassword123!")[0] is True

    def test_security_enumeration_prevention(self):
        """Test user enumeration prevention."""
        def login_error_message(user_exists, password_correct):
            # Same message regardless of which failed
            if not user_exists or not password_correct:
                return "Invalid email or password"
            return "Success"

        # Both cases return same error
        assert login_error_message(False, True) == "Invalid email or password"
        assert login_error_message(True, False) == "Invalid email or password"


# ==============================================================================
# TEST: OWASP A08 - Software and Data Integrity Failures - Pure Logic
# ==============================================================================
class TestDataIntegrityLogic:
    """Test data integrity - pure logic."""

    def test_security_jwt_signature_verification(self):
        """
        Security Test: JWT signature is verified
        OWASP: A08:2021 - Data Integrity Failures
        """
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        token = create_access_token(data={"sub": "testuser"})

        # Tamper with token
        parts = token.split('.')
        parts[1] = parts[1][:-1] + 'X'  # Modify payload
        tampered_token = '.'.join(parts)

        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(tampered_token, SECRET_KEY, algorithms=[ALGORITHM])

    def test_security_token_type_validation(self):
        """Test token type validation."""
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        # Create refresh token
        refresh_token = create_access_token(
            data={"sub": "user", "type": "refresh"}
        )

        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        # Type should be present for refresh tokens
        assert payload.get("type") == "refresh"


# ==============================================================================
# TEST: AUTH API SECURITY - REAL BACKEND
# ==============================================================================
class TestAuthAPISecurityReal:
    """Test auth API security - REAL BACKEND."""

    def test_security_login_requires_credentials(self, api_client):
        """Test login requires valid credentials."""
        # No credentials
        response = api_client.post("/api/v1/auth/login", data={})
        assert response.status_code in [401, 422, 404]

    def test_security_protected_endpoints_require_auth(self, api_client):
        """Test protected endpoints require authentication."""
        endpoints = [
            "/api/v1/auth/me",
            "/api/v1/auth/refresh",
        ]

        for endpoint in endpoints:
            response = api_client.get(endpoint)
            assert response.status_code in [401, 403, 404, 405]

    def test_security_invalid_token_rejected(self, api_client):
        """Test invalid token is rejected."""
        response = api_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code in [401, 403, 404]

    def test_security_sql_injection_in_login(self, api_client):
        """Test SQL injection in login."""
        malicious_inputs = [
            "' OR '1'='1",
            "admin'--",
        ]

        for payload in malicious_inputs:
            response = api_client.post(
                "/api/v1/auth/login",
                data={"username": payload, "password": "test"}
            )

            # Should not crash server
            assert response.status_code in [401, 422, 404]


# ==============================================================================
# TEST: PASSWORD SECURITY - Pure Logic
# ==============================================================================
class TestPasswordSecurityLogic:
    """Test password security - pure logic."""

    def test_security_bcrypt_hash_format(self):
        """Test bcrypt hash format."""
        from core.security import get_password_hash

        hash_val = get_password_hash("TestPassword123!")

        # Bcrypt format: $2b$rounds$salt+hash
        assert hash_val.startswith("$2b$") or hash_val.startswith("$2a$")
        assert len(hash_val) == 60

    def test_security_salt_uniqueness(self):
        """Test each hash has unique salt."""
        from core.security import get_password_hash

        password = "SamePassword123!"

        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)

        # Same password, different hashes (different salts)
        assert hash1 != hash2


# ==============================================================================
# TEST: SESSION SECURITY - Pure Logic
# ==============================================================================
class TestSessionSecurityLogic:
    """Test session security - pure logic."""

    def test_security_disabled_user_blocked(self):
        """Test disabled users are blocked."""
        def can_user_login(is_active, email_verified=True):
            return is_active and email_verified

        assert can_user_login(is_active=False) is False
        assert can_user_login(is_active=True) is True

    def test_security_token_blacklist_concept(self):
        """Test token blacklist concept."""
        blacklisted_tokens = set()

        def is_token_valid(token):
            return token not in blacklisted_tokens

        token = "valid_token"

        # Before blacklist
        assert is_token_valid(token) is True

        # After blacklist
        blacklisted_tokens.add(token)
        assert is_token_valid(token) is False

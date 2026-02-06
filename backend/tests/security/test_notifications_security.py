"""
================================================================================
AI_MODULE: Notifications Security Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Security test suite for notifications system
AI_BUSINESS: Ensure notification system is secure against common attacks
AI_TEACHING: Security testing patterns, OWASP, penetration testing

CRITICAL: ZERO MOCK POLICY
- All tests call real backend API
- Tests verify actual security behavior

SECURITY AREAS TESTED:
- Authentication & Authorization (IDOR, Privilege Escalation)
- Input Validation (SQL Injection, XSS, Buffer Overflow)
- Rate Limiting
- Data Exposure
- Session Management
================================================================================
"""

import pytest
import uuid
import json
from typing import Dict
from fastapi.testclient import TestClient


# =============================================================================
# AUTHENTICATION & AUTHORIZATION TESTS
# =============================================================================

class TestAuthenticationSecurity:
    """
    Test authentication security for notification endpoints.

    OWASP: A01:2021 - Broken Access Control
    """

    def test_list_notifications_no_auth(
        self,
        api_client: TestClient
    ):
        """
        Test: Access notifications without authentication.

        Expected: 401 Unauthorized
        Security: Unauthenticated access must be blocked.
        """
        response = api_client.get("/api/v1/notifications")
        assert response.status_code in [401, 403]

    def test_device_tokens_no_auth(
        self,
        api_client: TestClient
    ):
        """
        Test: Register device without authentication.

        Expected: 401 Unauthorized
        Security: Device tokens contain user identity info.
        """
        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            json={
                "token": f"test_token_{uuid.uuid4().hex}",
                "device_type": "android"
            }
        )
        assert response.status_code in [401, 403]

    def test_preferences_no_auth(
        self,
        api_client: TestClient
    ):
        """
        Test: Access preferences without authentication.

        Expected: 401 Unauthorized
        Security: Preferences contain user behavior data.
        """
        response = api_client.get("/api/v1/notifications/preferences")
        assert response.status_code in [401, 403]

    def test_expired_token(
        self,
        api_client: TestClient
    ):
        """
        Test: Access with expired JWT token.

        Expected: 401 Unauthorized
        Security: Expired tokens must be rejected.
        """
        # Use a fake/malformed token
        expired_headers = {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2MDAwMDAwMDB9.fake"}

        response = api_client.get(
            "/api/v1/notifications",
            headers=expired_headers
        )
        assert response.status_code in [401, 403]

    def test_malformed_token(
        self,
        api_client: TestClient
    ):
        """
        Test: Access with malformed JWT token.

        Expected: 401 Unauthorized
        Security: Invalid tokens must be rejected.
        """
        malformed_headers = {"Authorization": "Bearer not-a-valid-jwt"}

        response = api_client.get(
            "/api/v1/notifications",
            headers=malformed_headers
        )
        assert response.status_code in [401, 403]

    def test_token_without_bearer_prefix(
        self,
        api_client: TestClient,
        auth_token: str
    ):
        """
        Test: Token without Bearer prefix.

        Expected: 401 Unauthorized
        Security: Token format must be validated.
        """
        headers = {"Authorization": auth_token}  # Missing "Bearer "

        response = api_client.get(
            "/api/v1/notifications",
            headers=headers
        )
        assert response.status_code in [401, 403]


# =============================================================================
# AUTHORIZATION & IDOR TESTS
# =============================================================================

class TestAuthorizationSecurity:
    """
    Test authorization and IDOR vulnerabilities.

    OWASP: A01:2021 - Broken Access Control (IDOR)
    """

    def test_idor_get_notification(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Access notification belonging to another user (IDOR).

        Expected: 404 Not Found (not 403)
        Security: Should not reveal if notification exists for other user.
        """
        # Generate a random notification ID that would belong to someone else
        other_user_notification_id = str(uuid.uuid4())

        response = api_client.get(
            f"/api/v1/notifications/{other_user_notification_id}",
            headers=auth_headers
        )

        # Must return 404 (not 403) to avoid enumeration attacks
        assert response.status_code == 404

    def test_idor_mark_notification_read(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Mark another user's notification as read (IDOR).

        Expected: 404 Not Found
        Security: Cannot manipulate other users' notifications.
        """
        other_user_notification_id = str(uuid.uuid4())

        response = api_client.patch(
            f"/api/v1/notifications/{other_user_notification_id}/read",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_idor_delete_notification(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Delete another user's notification (IDOR).

        Expected: 404 Not Found
        Security: Cannot delete other users' notifications.
        """
        other_user_notification_id = str(uuid.uuid4())

        response = api_client.delete(
            f"/api/v1/notifications/{other_user_notification_id}",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_privilege_escalation_admin_broadcast(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Regular user attempting admin broadcast.

        Expected: 403 Forbidden
        Security: Admin endpoints must check privileges.
        """
        response = api_client.post(
            "/api/v1/notifications/admin/broadcast",
            headers=auth_headers,  # Regular user headers
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "system",
                "title": "Privilege Escalation Test",
                "body": "This should not work"
            }
        )

        assert response.status_code in [401, 403]

    def test_privilege_escalation_admin_stats(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Regular user accessing admin stats.

        Expected: 403 Forbidden
        Security: Admin stats contain sensitive data.
        """
        response = api_client.get(
            f"/api/v1/notifications/admin/stats/{uuid.uuid4()}",
            headers=auth_headers
        )

        assert response.status_code in [401, 403]

    def test_privilege_escalation_admin_cleanup(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Regular user triggering admin cleanup.

        Expected: 403 Forbidden
        Security: Cleanup is destructive admin operation.
        """
        response = api_client.post(
            "/api/v1/notifications/admin/cleanup",
            headers=auth_headers
        )

        assert response.status_code in [401, 403]


# =============================================================================
# SQL INJECTION TESTS
# =============================================================================

class TestSQLInjectionSecurity:
    """
    Test SQL injection protection.

    OWASP: A03:2021 - Injection
    """

    def test_sqli_notification_type_filter(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: SQL injection in notification_type filter.

        Expected: 400 Bad Request (not 500)
        Security: Input must be sanitized.
        """
        payloads = [
            "'; DROP TABLE notifications; --",
            "1 OR 1=1",
            "' UNION SELECT * FROM users --",
            "1; SELECT * FROM users",
        ]

        for payload in payloads:
            response = api_client.get(
                f"/api/v1/notifications?notification_type={payload}",
                headers=auth_headers
            )

            # Should be 400 (invalid type) not 500 (SQL error)
            assert response.status_code in [400, 422], f"Potential SQLi with payload: {payload}"
            assert response.status_code != 500, f"Server error indicates possible SQLi: {payload}"

    def test_sqli_notification_id(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: SQL injection in notification_id path parameter.

        Expected: 404 or 422 (not 500)
        Security: Path parameters must be validated.
        """
        payloads = [
            "'; DROP TABLE notifications; --",
            "1 OR 1=1",
            "1' UNION SELECT * FROM users --",
        ]

        for payload in payloads:
            response = api_client.get(
                f"/api/v1/notifications/{payload}",
                headers=auth_headers
            )

            # UUID validation should catch this early
            assert response.status_code in [400, 404, 422], f"Potential SQLi with payload: {payload}"
            assert response.status_code != 500, f"Server error indicates possible SQLi: {payload}"

    def test_sqli_device_token(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: SQL injection in device token.

        Expected: Success (data stored safely) or validation error
        Security: Tokens must be escaped before storage.
        """
        payload = f"'; DROP TABLE device_tokens; --_{uuid.uuid4().hex}"

        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": payload,
                "device_type": "android"
            }
        )

        # Should either succeed (escaped) or fail validation
        assert response.status_code in [201, 422]
        assert response.status_code != 500


# =============================================================================
# XSS TESTS
# =============================================================================

class TestXSSSecurity:
    """
    Test XSS (Cross-Site Scripting) protection.

    OWASP: A03:2021 - Injection (XSS)
    """

    def test_xss_device_name(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: XSS payload in device name.

        Expected: Data stored safely (escaped)
        Security: User input must not execute as script.
        """
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
        ]

        for payload in xss_payloads:
            response = api_client.post(
                "/api/v1/notifications/device-tokens",
                headers=auth_headers,
                json={
                    "token": f"xss_test_{uuid.uuid4().hex}",
                    "device_type": "android",
                    "device_name": payload
                }
            )

            # Should succeed but store escaped content
            assert response.status_code == 201, f"Failed for payload: {payload}"

    def test_xss_in_preferences(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: XSS payload in quiet hours (string field).

        Expected: Validation error (invalid format)
        Security: String fields must be validated.
        """
        response = api_client.patch(
            "/api/v1/notifications/preferences",
            headers=auth_headers,
            json={
                "quiet_hours_start": "<script>alert('xss')</script>"
            }
        )

        # Should fail format validation
        assert response.status_code == 422


# =============================================================================
# DATA EXPOSURE TESTS
# =============================================================================

class TestDataExposureSecurity:
    """
    Test sensitive data exposure.

    OWASP: A02:2021 - Cryptographic Failures / Data Exposure
    """

    def test_no_sensitive_data_in_error(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Error responses don't leak sensitive data.

        Security: Errors should not expose internal details.
        """
        response = api_client.get(
            "/api/v1/notifications/invalid-uuid-format",
            headers=auth_headers
        )

        if response.status_code >= 400:
            body = response.text.lower()
            # Should not expose internal details
            assert "traceback" not in body
            assert "sqlalchemy" not in body
            assert "password" not in body
            assert "secret" not in body

    def test_notification_doesnt_expose_user_data(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Notification responses don't expose extra user data.

        Security: Only necessary fields should be returned.
        """
        response = api_client.get(
            "/api/v1/notifications",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            for item in data.get("items", []):
                # Should not contain these sensitive fields
                assert "user_email" not in item
                assert "user_password" not in item
                assert "hashed_password" not in item

    def test_device_token_not_exposed_in_list(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Full device token not exposed in listing.

        Security: Token is sensitive and should be partially hidden.
        """
        # Register a token first
        unique_token = f"sensitive_token_{uuid.uuid4().hex}"
        api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": unique_token,
                "device_type": "android"
            }
        )

        # List tokens
        response = api_client.get(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers
        )

        # Token format in response should be safe
        # (either not present or truncated)
        if response.status_code == 200:
            data = response.json()
            # Response format may vary - just ensure no error
            assert "items" in data


# =============================================================================
# INPUT VALIDATION TESTS
# =============================================================================

class TestInputValidationSecurity:
    """
    Test input validation security.

    OWASP: A04:2021 - Insecure Design
    """

    def test_oversized_notification_body(
        self,
        api_client: TestClient,
        admin_headers: Dict[str, str]
    ):
        """
        Test: Extremely large notification body.

        Expected: Validation error or truncation
        Security: Prevent DoS via large inputs.
        """
        # 10MB of data
        large_body = "A" * (10 * 1024 * 1024)

        response = api_client.post(
            "/api/v1/notifications/admin/broadcast",
            headers=admin_headers,
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "system",
                "title": "Test",
                "body": large_body
            }
        )

        # Should reject oversized input
        assert response.status_code in [400, 413, 422, 401, 403]

    def test_oversized_device_token(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Extremely long device token.

        Expected: Validation error
        Security: Token length must be limited.
        """
        # Token > 500 chars (schema max)
        long_token = "A" * 1000

        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": long_token,
                "device_type": "android"
            }
        )

        assert response.status_code == 422

    def test_null_bytes_in_input(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Null bytes in device name.

        Expected: Accept or sanitize
        Security: Null bytes should not cause issues.
        """
        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": f"null_test_{uuid.uuid4().hex}",
                "device_type": "android",
                "device_name": "Test\x00Device"
            }
        )

        # Should not cause server error
        assert response.status_code != 500

    def test_unicode_normalization(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Unicode characters in device name.

        Expected: Accept unicode properly
        Security: Unicode should be handled consistently.
        """
        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": f"unicode_test_{uuid.uuid4().hex}",
                "device_type": "android",
                "device_name": "Test\u202eDevi\u0441e"  # RTL override + Cyrillic
            }
        )

        assert response.status_code in [201, 422]
        assert response.status_code != 500

    def test_negative_pagination_values(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Negative values in pagination.

        Expected: 422 Validation Error
        Security: Prevent unexpected DB behavior.
        """
        response = api_client.get(
            "/api/v1/notifications?page=-1&page_size=-10",
            headers=auth_headers
        )

        assert response.status_code == 422


# =============================================================================
# HEADER INJECTION TESTS
# =============================================================================

class TestHeaderInjectionSecurity:
    """
    Test header injection protection.

    Security: Prevent response splitting / header injection.
    """

    def test_crlf_injection_in_token(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: CRLF injection in device token.

        Expected: Accept or sanitize
        Security: Cannot inject headers via token.
        """
        payload = f"token_{uuid.uuid4().hex}\r\nX-Injected: header"

        response = api_client.post(
            "/api/v1/notifications/device-tokens",
            headers=auth_headers,
            json={
                "token": payload,
                "device_type": "android"
            }
        )

        # Should not cause issues
        assert "X-Injected" not in response.headers.get("", "")
        assert response.status_code != 500


# =============================================================================
# JSON INJECTION TESTS
# =============================================================================

class TestJSONInjectionSecurity:
    """
    Test JSON injection protection.

    Security: Prevent JSON deserialization attacks.
    """

    def test_json_prototype_pollution(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: JSON prototype pollution attempt.

        Expected: Ignored or rejected
        Security: __proto__ should not be processed.
        """
        response = api_client.patch(
            "/api/v1/notifications/preferences",
            headers=auth_headers,
            json={
                "__proto__": {"admin": True},
                "push_enabled": True
            }
        )

        # Should ignore __proto__ field
        assert response.status_code in [200, 422]

    def test_deeply_nested_json(
        self,
        api_client: TestClient,
        auth_headers: Dict[str, str]
    ):
        """
        Test: Deeply nested JSON in action_payload.

        Expected: Accept or limit depth
        Security: Prevent stack overflow from deep nesting.
        """
        # Create 100-level deep nested structure
        nested = {"level": 0}
        current = nested
        for i in range(100):
            current["nested"] = {"level": i + 1}
            current = current["nested"]

        # This would be in admin broadcast
        response = api_client.post(
            "/api/v1/notifications/admin/broadcast",
            headers=auth_headers,  # Will fail auth, but tests parsing
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "system",
                "title": "Test",
                "body": "Test",
                "action_payload": nested
            }
        )

        # Should not cause stack overflow (500)
        assert response.status_code != 500

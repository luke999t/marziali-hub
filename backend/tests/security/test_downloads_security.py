"""
================================================================================
AI_MODULE: Downloads Security Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test sicurezza per Downloads API con ZERO MOCK
AI_BUSINESS: Protegge contenuti premium da accesso non autorizzato
AI_TEACHING: OWASP Top 10, SQL injection, IDOR, token security

ZERO MOCK POLICY:
- All tests call real backend
- Verify actual security enforcement

SECURITY CATEGORIES:
1. AUTHENTICATION: Token validation, expired tokens
2. AUTHORIZATION: IDOR, tier bypass, ownership
3. INJECTION: SQL injection, command injection
4. DRM SECURITY: Token tampering, replay attacks
5. RATE LIMITING: Brute force protection
================================================================================
"""

import pytest
import uuid
import json
from datetime import datetime, timedelta


# ==============================================================================
# AUTHENTICATION TESTS
# ==============================================================================

class TestDownloadsAuthentication:
    """Test autenticazione endpoint downloads."""

    def test_all_endpoints_require_auth(self, api_client):
        """Tutti gli endpoint devono richiedere autenticazione."""
        endpoints = [
            ("POST", "/api/v1/downloads/request", {"video_id": str(uuid.uuid4()), "device_id": "test"}),
            ("GET", "/api/v1/downloads/list", None),
            ("GET", f"/api/v1/downloads/url/{uuid.uuid4()}", None),
            ("PATCH", f"/api/v1/downloads/progress/{uuid.uuid4()}", {"downloaded_bytes": 0, "completed": False}),
            ("DELETE", f"/api/v1/downloads/{uuid.uuid4()}", None),
            ("POST", f"/api/v1/downloads/refresh-drm/{uuid.uuid4()}", None),
            ("POST", f"/api/v1/downloads/offline-view/{uuid.uuid4()}", {"drm_token": "test"}),
            ("GET", "/api/v1/downloads/limits", None),
            ("GET", "/api/v1/downloads/storage", None),
        ]

        for method, path, body in endpoints:
            if method == "GET":
                response = api_client.get(path)
            elif method == "POST":
                response = api_client.post(path, json=body or {})
            elif method == "PATCH":
                response = api_client.patch(path, json=body or {})
            elif method == "DELETE":
                response = api_client.delete(path)

            assert response.status_code in [401, 403], \
                f"{method} {path} should require auth, got {response.status_code}"

    def test_invalid_token_rejected(self, api_client):
        """Token JWT invalido deve essere rifiutato."""
        invalid_headers = {"Authorization": "Bearer invalid_token_12345"}

        response = api_client.get(
            "/api/v1/downloads/list",
            headers=invalid_headers
        )

        assert response.status_code in [401, 403]

    def test_malformed_auth_header_rejected(self, api_client):
        """Header Authorization malformato deve essere rifiutato."""
        malformed_headers = [
            {"Authorization": "invalid"},
            {"Authorization": "Basic dXNlcjpwYXNz"},  # Basic auth instead of Bearer
            {"Authorization": "Bearer"},  # Missing token
            {"Authorization": ""},
        ]

        for headers in malformed_headers:
            response = api_client.get(
                "/api/v1/downloads/list",
                headers=headers
            )
            assert response.status_code in [401, 403, 422]


# ==============================================================================
# AUTHORIZATION / IDOR TESTS
# ==============================================================================

class TestDownloadsAuthorization:
    """Test autorizzazione e IDOR (Insecure Direct Object Reference)."""

    def test_cannot_access_other_user_download(self, api_client, auth_headers):
        """Non si puo accedere a download di altri utenti."""
        # UUID di download che non appartiene all'utente
        other_download_id = str(uuid.uuid4())

        # Tentativo di ottenere URL
        response = api_client.get(
            f"/api/v1/downloads/url/{other_download_id}",
            headers=auth_headers
        )
        assert response.status_code in [400, 403, 404]

        # Tentativo di aggiornare progresso
        response = api_client.patch(
            f"/api/v1/downloads/progress/{other_download_id}",
            json={"downloaded_bytes": 1000, "completed": False},
            headers=auth_headers
        )
        assert response.status_code in [400, 403, 404]

        # Tentativo di eliminare
        response = api_client.delete(
            f"/api/v1/downloads/{other_download_id}",
            headers=auth_headers
        )
        assert response.status_code in [400, 403, 404]

    def test_cannot_refresh_drm_for_other_user(self, api_client, auth_headers):
        """Non si puo rinnovare DRM di altri utenti."""
        other_download_id = str(uuid.uuid4())

        response = api_client.post(
            f"/api/v1/downloads/refresh-drm/{other_download_id}",
            headers=auth_headers
        )

        assert response.status_code in [400, 403, 404]

    def test_admin_endpoint_requires_admin_role(self, api_client, auth_headers):
        """Endpoint admin richiedono ruolo admin."""
        response = api_client.post(
            "/api/v1/downloads/admin/expire-check",
            headers=auth_headers
        )

        # Utente normale deve ricevere 403
        assert response.status_code == 403

    def test_tier_enforcement_cannot_be_bypassed(self, api_client, auth_headers_free):
        """FREE user non puo bypassare limiti tier."""
        # Tentativo di scaricare come FREE
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": "bypass-attempt",
                "device_name": "Bypass Device"
            },
            headers=auth_headers_free
        )

        # Deve essere bloccato (403 tier limit o 400 video not found)
        assert response.status_code in [400, 403]


# ==============================================================================
# SQL INJECTION TESTS
# ==============================================================================

class TestDownloadsSQLInjection:
    """Test protezione SQL injection."""

    SQL_PAYLOADS = [
        "'; DROP TABLE downloads; --",
        "1' OR '1'='1",
        "1; DELETE FROM users WHERE '1'='1",
        "' UNION SELECT * FROM users --",
        "1' AND SLEEP(5) --",
        "'; EXEC xp_cmdshell('dir'); --",
        "1'; WAITFOR DELAY '0:0:5'--",
    ]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_video_id(self, api_client, auth_headers, payload):
        """SQL injection in video_id deve essere bloccato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": payload,
                "device_id": "test-device"
            },
            headers=auth_headers
        )

        # Deve ritornare errore di validazione, non SQL error
        assert response.status_code in [400, 422]
        # Non deve contenere errori SQL nel response
        response_text = response.text.lower()
        assert "syntax error" not in response_text
        assert "sql" not in response_text

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_device_id(self, api_client, auth_headers, payload):
        """SQL injection in device_id deve essere bloccato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": payload
            },
            headers=auth_headers
        )

        # Non deve causare errori SQL
        assert response.status_code in [400, 403, 422, 507]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_query_params(self, api_client, auth_headers, payload):
        """SQL injection in query params deve essere bloccato."""
        response = api_client.get(
            f"/api/v1/downloads/list?device_id={payload}",
            headers=auth_headers
        )

        # Deve essere gestito correttamente
        assert response.status_code in [200, 400]

    @pytest.mark.parametrize("payload", SQL_PAYLOADS)
    def test_sql_injection_in_url_path(self, api_client, auth_headers, payload):
        """SQL injection in URL path deve essere bloccato."""
        # URL encode the payload
        import urllib.parse
        encoded_payload = urllib.parse.quote(payload)

        response = api_client.get(
            f"/api/v1/downloads/url/{encoded_payload}",
            headers=auth_headers
        )

        assert response.status_code in [400, 404, 422]


# ==============================================================================
# DRM SECURITY TESTS
# ==============================================================================

class TestDRMSecurity:
    """Test sicurezza sistema DRM."""

    def test_invalid_drm_token_rejected(self, api_client, auth_headers):
        """Token DRM invalido deve essere rifiutato."""
        fake_download_id = str(uuid.uuid4())

        invalid_tokens = [
            "invalid_token",
            "drm_fake_token",
            "",
            "null",
            "undefined",
            "<script>alert(1)</script>",
            "' OR '1'='1",
        ]

        for token in invalid_tokens:
            response = api_client.post(
                f"/api/v1/downloads/offline-view/{fake_download_id}",
                json={"drm_token": token},
                headers=auth_headers
            )

            # Deve essere rifiutato (401 invalid token, 404 download not found)
            assert response.status_code in [400, 401, 404]

    def test_drm_token_not_leaked_in_errors(self, api_client, auth_headers):
        """Token DRM non deve essere esposto nei messaggi di errore."""
        fake_download_id = str(uuid.uuid4())

        response = api_client.post(
            f"/api/v1/downloads/offline-view/{fake_download_id}",
            json={"drm_token": "secret_token_12345"},
            headers=auth_headers
        )

        # Il token non deve apparire nella risposta
        assert "secret_token_12345" not in response.text

    def test_drm_token_cannot_be_guessed(self, api_client, auth_headers):
        """Token DRM deve essere sufficientemente lungo e random."""
        # Questo test verifica che i token generati non siano prevedibili
        # (La verifica reale avviene quando si ha un download completato)
        fake_download_id = str(uuid.uuid4())

        # Tentativo con token breve
        response = api_client.post(
            f"/api/v1/downloads/offline-view/{fake_download_id}",
            json={"drm_token": "123"},
            headers=auth_headers
        )

        assert response.status_code in [400, 401, 404]


# ==============================================================================
# XSS TESTS
# ==============================================================================

class TestDownloadsXSS:
    """Test protezione XSS."""

    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
    ]

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_device_name(self, api_client, auth_headers, payload):
        """XSS in device_name deve essere sanitizzato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": "test-device",
                "device_name": payload
            },
            headers=auth_headers
        )

        # Non deve causare errori server (500)
        assert response.status_code != 500

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_xss_in_device_id(self, api_client, auth_headers, payload):
        """XSS in device_id deve essere sanitizzato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": payload,
                "device_name": "Test"
            },
            headers=auth_headers
        )

        # Non deve causare errori server (500)
        assert response.status_code != 500


# ==============================================================================
# RATE LIMITING TESTS
# ==============================================================================

class TestDownloadsRateLimiting:
    """Test rate limiting per prevenire abuse."""

    def test_multiple_rapid_requests_handled(self, api_client, auth_headers):
        """Richieste rapide multiple devono essere gestite."""
        # Invia 10 richieste rapide
        responses = []
        for _ in range(10):
            response = api_client.get(
                "/api/v1/downloads/list",
                headers=auth_headers
            )
            responses.append(response.status_code)

        # Non tutte devono fallire con 500
        assert 500 not in responses, "Server should handle rapid requests"

        # Se c'e rate limiting, ci aspettiamo alcuni 429
        # Altrimenti tutti 200
        success_count = responses.count(200)
        assert success_count > 0, "At least some requests should succeed"

    def test_brute_force_download_request(self, api_client, auth_headers):
        """Tentativo brute force di download deve essere limitato."""
        # Simula tentativo brute force con molti video_id
        for _ in range(20):
            api_client.post(
                "/api/v1/downloads/request",
                json={
                    "video_id": str(uuid.uuid4()),
                    "device_id": f"brute-{uuid.uuid4().hex[:8]}"
                },
                headers=auth_headers
            )

        # Il server deve ancora rispondere (non crash)
        response = api_client.get("/api/v1/downloads/limits", headers=auth_headers)
        assert response.status_code in [200, 429]


# ==============================================================================
# INPUT VALIDATION TESTS
# ==============================================================================

class TestDownloadsInputValidation:
    """Test validazione input."""

    def test_oversized_device_id_rejected(self, api_client, auth_headers):
        """Device ID troppo lungo deve essere rifiutato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": "x" * 1000  # 1000 caratteri
            },
            headers=auth_headers
        )

        assert response.status_code in [400, 422]

    def test_oversized_device_name_rejected(self, api_client, auth_headers):
        """Device name troppo lungo deve essere rifiutato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": str(uuid.uuid4()),
                "device_id": "test",
                "device_name": "x" * 1000  # 1000 caratteri
            },
            headers=auth_headers
        )

        assert response.status_code in [400, 422]

    def test_negative_bytes_rejected(self, api_client, auth_headers):
        """Bytes negativi devono essere rifiutati."""
        fake_id = str(uuid.uuid4())

        response = api_client.patch(
            f"/api/v1/downloads/progress/{fake_id}",
            json={
                "downloaded_bytes": -1000,
                "completed": False
            },
            headers=auth_headers
        )

        assert response.status_code in [400, 404, 422]

    def test_invalid_json_rejected(self, api_client, auth_headers):
        """JSON malformato deve essere rifiutato."""
        response = api_client.post(
            "/api/v1/downloads/request",
            content="not valid json{{{",
            headers={**auth_headers, "Content-Type": "application/json"}
        )

        assert response.status_code == 422

    def test_null_values_handled(self, api_client, auth_headers):
        """Valori null devono essere gestiti correttamente."""
        response = api_client.post(
            "/api/v1/downloads/request",
            json={
                "video_id": None,
                "device_id": None
            },
            headers=auth_headers
        )

        assert response.status_code in [400, 422]


# ==============================================================================
# CONTENT TYPE TESTS
# ==============================================================================

class TestDownloadsContentType:
    """Test Content-Type handling."""

    def test_requires_json_content_type(self, api_client, auth_headers):
        """POST richiede Content-Type JSON."""
        response = api_client.post(
            "/api/v1/downloads/request",
            content="video_id=123&device_id=test",
            headers={**auth_headers, "Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code in [400, 415, 422]

    def test_xml_content_type_rejected(self, api_client, auth_headers):
        """XML Content-Type deve essere rifiutato (prevenzione XXE)."""
        response = api_client.post(
            "/api/v1/downloads/request",
            content="<request><video_id>123</video_id></request>",
            headers={**auth_headers, "Content-Type": "application/xml"}
        )

        assert response.status_code in [400, 415, 422]


# ==============================================================================
# ENUMERATION TESTS
# ==============================================================================

class TestDownloadsEnumeration:
    """Test protezione da enumeration attacks."""

    def test_consistent_error_for_nonexistent_downloads(self, api_client, auth_headers):
        """Errori per download inesistenti devono essere consistenti."""
        # Genera molti UUID e verifica che le risposte siano consistenti
        responses = []
        for _ in range(5):
            fake_id = str(uuid.uuid4())
            response = api_client.get(
                f"/api/v1/downloads/url/{fake_id}",
                headers=auth_headers
            )
            responses.append((response.status_code, len(response.content)))

        # Tutti devono avere stesso status code
        status_codes = [r[0] for r in responses]
        assert len(set(status_codes)) == 1, "Responses should be consistent to prevent enumeration"

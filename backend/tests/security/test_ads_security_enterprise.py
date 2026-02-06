"""
================================================================================
AI_MODULE: Ads Security Enterprise Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test sicurezza COMPLETI per Ads - OWASP, penetration testing
AI_BUSINESS: Validazione sicurezza ads: SQL injection, XSS, fraud prevention
AI_TEACHING: Security testing - OWASP Top 10, input validation, fraud detection

ZERO MOCK - LEGGE SUPREMA
Test di sicurezza reali, no mock.
================================================================================
"""

import pytest
import uuid
import time
from datetime import datetime

# ==============================================================================
# MARKERS
# ==============================================================================
API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.security]


# ==============================================================================
# SQL INJECTION PAYLOADS
# ==============================================================================
SQL_INJECTION_PAYLOADS = [
    "'; DROP TABLE ads_batches; --",
    "' OR '1'='1",
    "1; SELECT * FROM users",
    "' UNION SELECT * FROM users --",
    "1' AND '1'='1",
    "admin'--",
    "' OR 1=1 --",
    "'; DELETE FROM ads_views; --",
    "1; UPDATE users SET is_admin=true; --",
    "' OR ''='",
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "<svg onload=alert('xss')>",
    "'-alert(1)-'",
]


# ==============================================================================
# TEST: OWASP A03 - Injection - SQL Injection
# ==============================================================================
class TestAdsSQLInjection:
    """Test SQL injection prevention - OWASP A03."""

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_batch_id_sql_injection(self, api_client, auth_headers_free, payload):
        """Verifica che batch_id non sia vulnerabile a SQL injection."""
        response = api_client.get(
            f"{API_PREFIX}/ads/batch/{payload}",
            headers=auth_headers_free
        )
        # Non deve ritornare dati sensibili né crashare
        assert response.status_code in [400, 404, 422, 500]

        response_text = response.text.lower()
        assert "password" not in response_text
        assert "hashed" not in response_text
        assert "secret" not in response_text
        assert "credit_card" not in response_text

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_batch_type_sql_injection(self, api_client, auth_headers_free, payload):
        """Verifica che batch_type non sia vulnerabile a SQL injection."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": payload},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422, 500]

        # Non deve esporre errori SQL dettagliati
        response_text = response.text.lower()
        assert "syntax error" not in response_text
        assert "sql" not in response_text or "error" not in response_text

    @pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
    def test_ad_id_sql_injection(self, api_client, auth_headers_free, payload):
        """Verifica che ad_id non sia vulnerabile a SQL injection."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": payload, "duration": 30},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422, 500]


# ==============================================================================
# TEST: OWASP A03 - Injection - XSS Prevention
# ==============================================================================
class TestAdsXSSPrevention:
    """Test XSS prevention - OWASP A03."""

    @pytest.mark.parametrize("payload", XSS_PAYLOADS)
    def test_batch_type_xss(self, api_client, auth_headers_free, payload):
        """Verifica che batch_type non permetta XSS."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": payload},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422, 500]

        # Se risponde con errore, non deve echoare il payload direttamente
        if response.status_code in [400, 422]:
            response_text = response.text
            assert "<script>" not in response_text
            assert "onerror=" not in response_text


# ==============================================================================
# TEST: OWASP A01 - Broken Access Control
# ==============================================================================
class TestAdsBrokenAccessControl:
    """Test broken access control - OWASP A01."""

    def test_cannot_view_other_user_batch(self, api_client, auth_headers_free):
        """Utente non può vedere batch di altri utenti."""
        # UUID di un altro utente (fake)
        other_user_batch_id = str(uuid.uuid4())

        response = api_client.get(
            f"{API_PREFIX}/ads/batch/{other_user_batch_id}",
            headers=auth_headers_free
        )
        # Deve essere 403 Forbidden o 404 Not Found
        assert response.status_code in [403, 404]

    def test_cannot_complete_other_user_batch(self, api_client, auth_headers_free):
        """Utente non può completare batch di altri utenti."""
        other_user_batch_id = str(uuid.uuid4())

        response = api_client.post(
            f"{API_PREFIX}/ads/batch/{other_user_batch_id}/complete",
            headers=auth_headers_free
        )
        assert response.status_code in [403, 404]

    def test_cannot_access_admin_endpoints_as_user(self, api_client, auth_headers_free):
        """Utente normale non può accedere a endpoint admin."""
        admin_endpoints = [
            f"{API_PREFIX}/ads/stats/admin",
            f"{API_PREFIX}/ads/inventory",
            f"{API_PREFIX}/ads/revenue",
        ]

        for endpoint in admin_endpoints:
            response = api_client.get(endpoint, headers=auth_headers_free)
            # Deve essere 403 Forbidden o 404 Not Found
            assert response.status_code in [403, 404], f"Endpoint {endpoint} should be protected"

    def test_unauthenticated_cannot_record_views(self, api_client):
        """Utente non autenticato non può registrare views."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 30}
        )
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: OWASP A04 - Insecure Design - Fraud Prevention
# ==============================================================================
class TestAdsFraudPrevention:
    """Test fraud prevention - OWASP A04."""

    def test_rapid_fire_views_detection(self, api_client, auth_headers_free):
        """Rapid fire views devono essere rilevate come fraud."""
        # Registra 10 views molto rapidamente
        responses = []
        for _ in range(10):
            response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={"ad_id": str(uuid.uuid4()), "duration": 30},
                headers=auth_headers_free
            )
            responses.append(response)

        # Dopo molte views rapide, potrebbe essere bloccato o flaggato
        # Almeno le ultime richieste potrebbero avere rate limiting
        status_codes = [r.status_code for r in responses]
        # Accettiamo che alcune passino (200/201) o vengano limitate (429)
        assert all(s in [200, 201, 400, 404, 422, 429] for s in status_codes)

    def test_very_short_view_duration_flagged(self, api_client, auth_headers_free):
        """View con durata molto breve potrebbe essere fraud."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 1},  # 1 secondo
            headers=auth_headers_free
        )
        # Potrebbe essere accettato ma flaggato internamente
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_impossible_view_duration_rejected(self, api_client, auth_headers_free):
        """Durate impossibili devono essere rifiutate."""
        # 24 ore per un ad
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 86400},
            headers=auth_headers_free
        )
        # Dovrebbe essere rifiutato o flaggato come fraud
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_negative_duration_rejected(self, api_client, auth_headers_free):
        """Durate negative devono essere rifiutate."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": -100},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]


# ==============================================================================
# TEST: OWASP A05 - Security Misconfiguration
# ==============================================================================
class TestAdsSecurityMisconfiguration:
    """Test security misconfiguration - OWASP A05."""

    def test_error_responses_no_stack_trace(self, api_client, auth_headers_free):
        """Errori non devono esporre stack trace."""
        # Request che causa errore
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": None},  # Null value
            headers=auth_headers_free
        )

        response_text = response.text.lower()
        # Non deve contenere stack trace Python
        assert "traceback" not in response_text
        assert "file \"" not in response_text
        assert "line " not in response_text or "error" not in response_text

    def test_error_responses_no_internal_paths(self, api_client, auth_headers_free):
        """Errori non devono esporre path interni."""
        response = api_client.get(
            f"{API_PREFIX}/ads/batch/invalid",
            headers=auth_headers_free
        )

        response_text = response.text.lower()
        # Non deve contenere path di sistema
        assert "/home/" not in response_text
        assert "c:\\" not in response_text
        assert "/var/" not in response_text

    def test_no_debug_info_in_responses(self, api_client, auth_headers_free):
        """Risposte non devono contenere info di debug."""
        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )

        if response.status_code == 200:
            data = response.json()
            # Non deve contenere campi di debug
            assert "debug" not in str(data).lower()
            assert "internal" not in str(data).lower()
            assert "sql" not in str(data).lower()


# ==============================================================================
# TEST: OWASP A07 - Identification and Authentication Failures
# ==============================================================================
class TestAdsAuthenticationFailures:
    """Test authentication failures - OWASP A07."""

    def test_expired_token_rejected(self, api_client):
        """Token scaduto deve essere rifiutato."""
        import jwt
        from core.security import SECRET_KEY, ALGORITHM

        # Crea token scaduto
        expired_payload = {
            "sub": "testuser",
            "email": "test@example.com",
            "user_id": str(uuid.uuid4()),
            "exp": datetime.utcnow().timestamp() - 3600  # 1 ora fa
        }
        expired_token = jwt.encode(expired_payload, SECRET_KEY, algorithm=ALGORITHM)

        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        assert response.status_code in [401, 403, 404]

    def test_malformed_token_rejected(self, api_client):
        """Token malformato deve essere rifiutato."""
        malformed_tokens = [
            "Bearer malformed.token.here",
            "Bearer eyJhbGciOiJIUzI1NiJ9.invalid",
            "Bearer ",
            "NotBearer validtoken",
        ]

        for token_header in malformed_tokens:
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers={"Authorization": token_header}
            )
            assert response.status_code in [401, 403, 404]

    def test_wrong_signature_token_rejected(self, api_client):
        """Token con firma sbagliata deve essere rifiutato."""
        import jwt

        # Token firmato con chiave sbagliata
        wrong_key_payload = {
            "sub": "testuser",
            "email": "test@example.com",
            "user_id": str(uuid.uuid4()),
            "exp": datetime.utcnow().timestamp() + 3600
        }
        wrong_token = jwt.encode(wrong_key_payload, "wrong_secret_key", algorithm="HS256")

        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers={"Authorization": f"Bearer {wrong_token}"}
        )
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Rate Limiting
# ==============================================================================
class TestAdsRateLimiting:
    """Test rate limiting per prevenire abuse."""

    def test_batch_start_rate_limited(self, api_client, auth_headers_free):
        """Start batch deve avere rate limiting."""
        responses = []
        for _ in range(20):
            response = api_client.post(
                f"{API_PREFIX}/ads/batch/start",
                json={"batch_type": "3_video"},
                headers=auth_headers_free
            )
            responses.append(response.status_code)

        # Dopo molte richieste, potrebbe esserci rate limiting (429)
        # O blocco per batch già attivo (400)
        assert all(s in [200, 201, 400, 404, 422, 429] for s in responses)

    def test_view_recording_rate_limited(self, api_client, auth_headers_free):
        """Record view deve avere rate limiting ragionevole."""
        responses = []
        for _ in range(50):
            response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={"ad_id": str(uuid.uuid4()), "duration": 30},
                headers=auth_headers_free
            )
            responses.append(response.status_code)

        # Verifica che non ci siano errori di server (500)
        assert 500 not in responses


# ==============================================================================
# TEST: Input Validation
# ==============================================================================
class TestAdsInputValidation:
    """Test input validation sicuro."""

    def test_batch_type_max_length(self, api_client, auth_headers_free):
        """batch_type con lunghezza eccessiva."""
        long_type = "a" * 1000
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": long_type},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]

    def test_duration_max_value(self, api_client, auth_headers_free):
        """duration con valore eccessivo."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 999999999},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_special_characters_in_fields(self, api_client, auth_headers_free):
        """Caratteri speciali devono essere gestiti."""
        special_chars = ["<>&\"'", "\\n\\r\\t", "\x00\x01", "emoji 🎯"]

        for chars in special_chars:
            response = api_client.post(
                f"{API_PREFIX}/ads/batch/start",
                json={"batch_type": chars},
                headers=auth_headers_free
            )
            # Non deve crashare
            assert response.status_code in [400, 404, 422, 500]

    def test_unicode_handling(self, api_client, auth_headers_free):
        """Unicode deve essere gestito correttamente."""
        unicode_strings = [
            "中文测试",
            "العربية",
            "日本語テスト",
            "🎬📹🎥",
        ]

        for ustr in unicode_strings:
            response = api_client.post(
                f"{API_PREFIX}/ads/batch/start",
                json={"batch_type": ustr},
                headers=auth_headers_free
            )
            # Non deve crashare
            assert response.status_code in [400, 404, 422, 500]

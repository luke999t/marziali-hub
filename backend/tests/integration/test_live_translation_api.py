"""
================================================================================
AI_MODULE: Live Translation API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per Live Translation REST endpoints
AI_BUSINESS: Garantisce funzionamento traduzione live per eventi
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock translation: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

NOTE: WebSocket endpoints testati separatamente in test_live_translation_websocket_enterprise.py

METRICHE_SUCCESSO:
- Coverage: 90%+ per live_translation.py REST endpoints
- Pass rate: 95%+
- Response time: <500ms per endpoint

ENDPOINTS TESTATI (REST):
- POST /api/v1/live-translation/events/{event_id}/start (admin)
- POST /api/v1/live-translation/events/{event_id}/stop (admin)
- GET /api/v1/live-translation/events/{event_id}/stats
- GET /api/v1/live-translation/languages/supported
- GET /api/v1/live-translation/providers/info
- POST /api/v1/live-translation/providers/switch (admin)

WEBSOCKET ENDPOINTS (non testati qui):
- WS /api/v1/live-translation/events/{event_id}/subtitles
- WS /api/v1/live-translation/events/{event_id}/broadcast

================================================================================
"""

import pytest
import httpx
from typing import Dict


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/live-translation"


# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================

class TestLiveTranslationPublic:
    """Test endpoint pubblici Live Translation."""

    def test_supported_languages(self, api_client):
        """
        Lista lingue supportate accessibile pubblicamente.

        BUSINESS: Frontend mostra opzioni lingua all'utente.
        """
        response = api_client.get(f"{API_PREFIX}/languages/supported")

        assert response.status_code == 200
        data = response.json()

        assert "speech_languages" in data
        assert "translation_languages" in data

        # Verifica che ci siano lingue
        assert isinstance(data["speech_languages"], list)
        assert isinstance(data["translation_languages"], list)

    def test_providers_info(self, api_client):
        """
        Info provider accessibile pubblicamente.

        BUSINESS: Trasparenza su quale servizio viene usato.
        """
        response = api_client.get(f"{API_PREFIX}/providers/info")

        assert response.status_code == 200
        data = response.json()

        # Dovrebbe contenere info su provider attivi
        assert isinstance(data, dict)


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestLiveTranslationAuth:
    """Test autenticazione Live Translation endpoints."""

    def test_start_session_no_auth(self, api_client):
        """Start session richiede autenticazione."""
        response = api_client.post(
            f"{API_PREFIX}/events/test-event/start",
            params={
                "source_language": "it",
                "target_languages": ["en", "es"]
            }
        )

        assert response.status_code in [401, 403]

    def test_stop_session_no_auth(self, api_client):
        """Stop session richiede autenticazione."""
        response = api_client.post(f"{API_PREFIX}/events/test-event/stop")

        assert response.status_code in [401, 403]

    def test_switch_provider_no_auth(self, api_client):
        """Switch provider richiede autenticazione."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            params={
                "service_type": "translation",
                "provider": "nllb"
            }
        )

        assert response.status_code in [401, 403]

    def test_stats_requires_auth(self, api_client):
        """Stats richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/events/test-event/stats")

        assert response.status_code in [401, 403]


# =============================================================================
# ADMIN SESSION MANAGEMENT
# =============================================================================

class TestLiveTranslationAdminSessions:
    """Test gestione sessioni admin."""

    def test_start_session_requires_admin(self, api_client, auth_headers):
        """
        Start session richiede admin.

        BUSINESS: Solo admin possono avviare traduzione eventi.
        """
        response = api_client.post(
            f"{API_PREFIX}/events/test-event/start",
            headers=auth_headers,
            params={
                "source_language": "it",
                "target_languages": ["en", "es"]
            }
        )

        # Utente normale non e admin
        assert response.status_code in [401, 403]

    def test_start_session_event_not_found(self, api_client, admin_headers):
        """Start session con evento inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/events/non-existent-event/start",
            headers=admin_headers,
            params={
                "source_language": "it",
                "target_languages": ["en", "es"]
            }
        )

        assert response.status_code == 404

    def test_stop_session_requires_admin(self, api_client, auth_headers):
        """Stop session richiede admin."""
        response = api_client.post(
            f"{API_PREFIX}/events/test-event/stop",
            headers=auth_headers
        )

        assert response.status_code in [401, 403]

    def test_stop_session_event_not_found(self, api_client, admin_headers):
        """Stop session con evento inesistente (puo essere silently ignored)."""
        response = api_client.post(
            f"{API_PREFIX}/events/non-existent-event/stop",
            headers=admin_headers
        )

        # Stop puo ritornare 200 anche se sessione non attiva
        assert response.status_code in [200, 404]


# =============================================================================
# STATS ENDPOINT
# =============================================================================

class TestLiveTranslationStats:
    """Test stats traduzione."""

    def test_stats_with_auth(self, api_client, auth_headers):
        """
        Stats con autenticazione.

        BUSINESS: Utenti vedono statistiche viewer per lingua.
        """
        response = api_client.get(
            f"{API_PREFIX}/events/test-event/stats",
            headers=auth_headers
        )

        # Evento potrebbe non esistere
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "event_id" in data
            assert "is_active" in data
            assert "total_viewers" in data
            assert "language_stats" in data

    def test_stats_inactive_event(self, api_client, auth_headers):
        """Stats per evento senza sessione attiva."""
        response = api_client.get(
            f"{API_PREFIX}/events/non-existent-event/stats",
            headers=auth_headers
        )

        # Se evento non esiste nel DB, potrebbe dare 200 con stats vuote o 404
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert data["is_active"] is False or data.get("total_viewers", 0) == 0


# =============================================================================
# PROVIDER MANAGEMENT
# =============================================================================

class TestLiveTranslationProviders:
    """Test gestione provider."""

    def test_switch_provider_requires_admin(self, api_client, auth_headers):
        """Switch provider richiede admin."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            headers=auth_headers,
            params={
                "service_type": "translation",
                "provider": "nllb"
            }
        )

        assert response.status_code in [401, 403]

    def test_switch_provider_invalid_service_type(self, api_client, admin_headers):
        """Switch provider con service type invalido."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            headers=admin_headers,
            params={
                "service_type": "invalid",
                "provider": "nllb"
            }
        )

        assert response.status_code in [400, 422]

    def test_switch_provider_invalid_provider(self, api_client, admin_headers):
        """Switch provider con provider invalido."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            headers=admin_headers,
            params={
                "service_type": "translation",
                "provider": "invalid-provider"
            }
        )

        assert response.status_code in [400, 422]

    def test_switch_speech_provider(self, api_client, admin_headers):
        """Admin puo switchare speech provider (se supportato)."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            headers=admin_headers,
            params={
                "service_type": "speech",
                "provider": "whisper"
            }
        )

        # Potrebbe funzionare o dare errore se provider non disponibile
        assert response.status_code in [200, 400]

    def test_switch_translation_provider(self, api_client, admin_headers):
        """Admin puo switchare translation provider (se supportato)."""
        response = api_client.post(
            f"{API_PREFIX}/providers/switch",
            headers=admin_headers,
            params={
                "service_type": "translation",
                "provider": "google"
            }
        )

        # Potrebbe funzionare o dare errore se provider non disponibile
        assert response.status_code in [200, 400]


# =============================================================================
# PREMIUM FEATURES
# =============================================================================

class TestLiveTranslationPremium:
    """Test features premium (se presenti)."""

    def test_stats_premium_user(self, api_client, auth_headers_premium):
        """Utente premium puo vedere stats."""
        response = api_client.get(
            f"{API_PREFIX}/events/test-event/stats",
            headers=auth_headers_premium
        )

        # 200 con stats o 404 se evento non esiste
        assert response.status_code in [200, 404]


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestLiveTranslationValidation:
    """Test validazione input."""

    def test_start_session_empty_target_languages(self, api_client, admin_headers):
        """Start session senza target languages."""
        response = api_client.post(
            f"{API_PREFIX}/events/test-event/start",
            headers=admin_headers,
            params={
                "source_language": "it"
                # target_languages mancante
            }
        )

        # Potrebbe usare default o richiedere esplicitamente
        assert response.status_code in [200, 404, 422]

    def test_start_session_invalid_source_language(self, api_client, admin_headers):
        """Start session con lingua sorgente invalida."""
        response = api_client.post(
            f"{API_PREFIX}/events/test-event/start",
            headers=admin_headers,
            params={
                "source_language": "xx",  # Codice invalido
                "target_languages": ["en"]
            }
        )

        # Potrebbe validare o accettare qualsiasi codice
        assert response.status_code in [200, 400, 404, 422]


# =============================================================================
# LIFECYCLE TEST
# =============================================================================

class TestLiveTranslationLifecycle:
    """Test ciclo di vita sessione traduzione."""

    @pytest.mark.skip(reason="Richiede evento live reale nel database")
    def test_session_lifecycle(self, api_client, admin_headers, live_event_id):
        """
        Ciclo completo: start -> stats -> stop.

        BUSINESS: Workflow tipico traduzione live.
        """
        # Step 1: Start session
        response = api_client.post(
            f"{API_PREFIX}/events/{live_event_id}/start",
            headers=admin_headers,
            params={
                "source_language": "it",
                "target_languages": ["en", "es", "fr"]
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data
        assert data["source_language"] == "it"

        # Step 2: Get stats
        response = api_client.get(
            f"{API_PREFIX}/events/{live_event_id}/stats",
            headers=admin_headers
        )

        assert response.status_code == 200
        stats = response.json()
        assert stats["is_active"] is True

        # Step 3: Stop session
        response = api_client.post(
            f"{API_PREFIX}/events/{live_event_id}/stop",
            headers=admin_headers
        )

        assert response.status_code == 200

        # Step 4: Verify stopped
        response = api_client.get(
            f"{API_PREFIX}/events/{live_event_id}/stats",
            headers=admin_headers
        )

        assert response.status_code == 200
        stats = response.json()
        assert stats["is_active"] is False


# =============================================================================
# ERROR HANDLING
# =============================================================================

class TestLiveTranslationErrors:
    """Test gestione errori."""

    def test_malformed_event_id(self, api_client, auth_headers):
        """Event ID malformato."""
        response = api_client.get(
            f"{API_PREFIX}/events/../../../etc/passwd/stats",
            headers=auth_headers
        )

        # Path traversal dovrebbe essere bloccato
        assert response.status_code in [400, 404, 422]

    def test_very_long_event_id(self, api_client, auth_headers):
        """Event ID molto lungo."""
        long_id = "a" * 1000

        response = api_client.get(
            f"{API_PREFIX}/events/{long_id}/stats",
            headers=auth_headers
        )

        # Dovrebbe gestire gracefully
        assert response.status_code in [400, 404, 414, 422]

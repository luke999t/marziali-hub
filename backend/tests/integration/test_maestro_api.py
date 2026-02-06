"""
================================================================================
AI_MODULE: Maestro API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per Maestro panel endpoints
AI_BUSINESS: Garantisce funzionamento gestionale per insegnanti
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock maestro data: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

METRICHE_SUCCESSO:
- Coverage: 90%+ per maestro.py
- Pass rate: 95%+
- Response time: <500ms per endpoint

ENDPOINTS TESTATI:
- GET /api/v1/maestro/dashboard
- GET /api/v1/maestro/videos
- DELETE /api/v1/maestro/videos/{video_id}
- POST /api/v1/maestro/live-events
- GET /api/v1/maestro/live-events
- DELETE /api/v1/maestro/live-events/{event_id}
- GET /api/v1/maestro/earnings
- POST /api/v1/maestro/withdrawals
- GET /api/v1/maestro/withdrawals
- GET /api/v1/maestro/corrections
- POST /api/v1/maestro/corrections/{id}/feedback
- GET /api/v1/maestro/translations
- GET /api/v1/maestro/glossary

================================================================================
"""

import pytest
import httpx
from typing import Dict
from datetime import datetime, timedelta


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/maestro"


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestMaestroAuth:
    """Test autenticazione per Maestro endpoints."""

    def test_dashboard_requires_auth(self, api_client):
        """Dashboard richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/dashboard")

        assert response.status_code in [401, 403]

    def test_videos_list_requires_auth(self, api_client):
        """Lista video richiede auth."""
        response = api_client.get(f"{API_PREFIX}/videos")

        assert response.status_code in [401, 403]

    def test_earnings_requires_auth(self, api_client):
        """Earnings richiede auth."""
        response = api_client.get(f"{API_PREFIX}/earnings")

        assert response.status_code in [401, 403]

    def test_corrections_requires_auth(self, api_client):
        """Lista correzioni richiede auth."""
        response = api_client.get(f"{API_PREFIX}/corrections")

        assert response.status_code in [401, 403]


# =============================================================================
# MAESTRO ROLE REQUIREMENT
# =============================================================================

class TestMaestroRoleAccess:
    """Test accesso richiede ruolo maestro."""

    def test_dashboard_requires_maestro_role(self, api_client, auth_headers):
        """
        Dashboard accessibile solo a utenti con ruolo maestro.

        BUSINESS: Utenti normali non devono vedere dashboard maestro.
        """
        response = api_client.get(
            f"{API_PREFIX}/dashboard",
            headers=auth_headers
        )

        # Utente normale non e maestro - deve ricevere 403
        assert response.status_code in [403, 404]

    def test_videos_requires_maestro_role(self, api_client, auth_headers):
        """Lista video accessibile solo a maestri."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers
        )

        assert response.status_code in [403, 404]

    def test_live_events_requires_maestro_role(self, api_client, auth_headers):
        """Live events accessibile solo a maestri."""
        response = api_client.get(
            f"{API_PREFIX}/live-events",
            headers=auth_headers
        )

        assert response.status_code in [403, 404]

    def test_earnings_requires_maestro_role(self, api_client, auth_headers):
        """Earnings accessibile solo a maestri."""
        response = api_client.get(
            f"{API_PREFIX}/earnings",
            headers=auth_headers
        )

        assert response.status_code in [403, 404]

    def test_withdrawals_requires_maestro_role(self, api_client, auth_headers):
        """Withdrawals accessibile solo a maestri."""
        response = api_client.get(
            f"{API_PREFIX}/withdrawals",
            headers=auth_headers
        )

        assert response.status_code in [403, 404]


# =============================================================================
# DASHBOARD (with maestro user)
# =============================================================================

class TestMaestroDashboard:
    """Test dashboard maestro (richiede utente maestro nel DB)."""

    def test_dashboard_returns_metrics(self, api_client, maestro_auth_headers):
        """
        Dashboard ritorna metriche chiave.

        BUSINESS: Maestro vede stats a colpo d'occhio.
        """
        response = api_client.get(
            f"{API_PREFIX}/dashboard",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()

        # Verifica campi metriche
        assert "total_videos" in data
        assert "total_followers" in data
        assert "earnings_last_30_days" in data
        assert "pending_corrections" in data
        assert "upcoming_live_events" in data


# =============================================================================
# VIDEO MANAGEMENT
# =============================================================================

class TestMaestroVideos:
    """Test gestione video maestro."""

    def test_list_videos_empty(self, api_client, maestro_auth_headers):
        """Lista video per nuovo maestro e vuota."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "videos" in data

    def test_list_videos_pagination(self, api_client, maestro_auth_headers):
        """Test pagination video."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=maestro_auth_headers,
            params={"skip": 0, "limit": 10}
        )

        assert response.status_code == 200
        data = response.json()
        assert "videos" in data
        assert "skip" in data
        assert "limit" in data

    def test_list_videos_filter_by_status(self, api_client, maestro_auth_headers):
        """Test filtro per status video."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=maestro_auth_headers,
            params={"status": "ready"}
        )

        assert response.status_code == 200

    def test_delete_video_not_found(self, api_client, auth_headers):
        """Delete video inesistente."""
        response = api_client.delete(
            f"{API_PREFIX}/videos/non-existent-video",
            headers=auth_headers
        )

        # 403 (non maestro) o 404 (video non trovato)
        assert response.status_code in [403, 404]


# =============================================================================
# LIVE EVENTS
# =============================================================================

class TestMaestroLiveEvents:
    """Test live events maestro."""

    def test_create_live_event_not_maestro(self, api_client, auth_headers):
        """
        Creazione live event fallisce per non-maestri.

        BUSINESS: Solo maestri possono creare eventi.
        """
        future_date = (datetime.utcnow() + timedelta(days=7)).isoformat()

        response = api_client.post(
            f"{API_PREFIX}/live-events",
            headers=auth_headers,
            json={
                "title": "Test Live Event",
                "description": "Test description",
                "event_type": "seminar",
                "scheduled_start": future_date,
                "donations_enabled": True,
                "chat_enabled": True
            }
        )

        assert response.status_code in [403, 404]

    def test_create_live_event_success(self, api_client, maestro_auth_headers):
        """Maestro puo creare live event."""
        future_date = (datetime.utcnow() + timedelta(days=7)).isoformat()

        response = api_client.post(
            f"{API_PREFIX}/live-events",
            headers=maestro_auth_headers,
            json={
                "title": "Seminario Karate Avanzato",
                "description": "Kata e Kumite",
                "event_type": "seminar",
                "scheduled_start": future_date,
                "donations_enabled": True,
                "chat_enabled": True
            }
        )

        assert response.status_code in [200, 201]
        data = response.json()
        assert "event" in data

    def test_delete_live_event_not_found(self, api_client, auth_headers):
        """Cancellazione evento inesistente."""
        response = api_client.delete(
            f"{API_PREFIX}/live-events/non-existent-event",
            headers=auth_headers
        )

        assert response.status_code in [403, 404]


# =============================================================================
# EARNINGS & WITHDRAWALS
# =============================================================================

class TestMaestroEarnings:
    """Test earnings maestro."""

    def test_earnings_default_period(self, api_client, maestro_auth_headers):
        """
        Earnings con periodo default (30 giorni).

        BUSINESS: Maestro vede guadagni recenti.
        """
        response = api_client.get(
            f"{API_PREFIX}/earnings",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()

        assert "period" in data
        assert "donations_count" in data
        assert "total_stelline" in data
        assert "total_eur" in data

    def test_earnings_different_periods(self, api_client, maestro_auth_headers):
        """Test earnings con diversi periodi."""
        periods = ["7d", "30d", "90d", "365d", "all"]

        for period in periods:
            response = api_client.get(
                f"{API_PREFIX}/earnings",
                headers=maestro_auth_headers,
                params={"period": period}
            )

            assert response.status_code == 200, f"Failed for period: {period}"


class TestMaestroWithdrawals:
    """Test withdrawals maestro."""

    def test_withdrawal_request_not_maestro(self, api_client, auth_headers):
        """Richiesta withdrawal fallisce per non-maestri."""
        response = api_client.post(
            f"{API_PREFIX}/withdrawals",
            headers=auth_headers,
            json={
                "stelline_amount": 1000000,  # 10000 stelline
                "payout_method": "bank_transfer",
                "iban": "IT60X0542811101000000123456"
            }
        )

        assert response.status_code in [403, 404]

    def test_withdrawal_minimum_amount(self, api_client, maestro_auth_headers):
        """Test importo minimo withdrawal."""
        # Importo sotto il minimo
        response = api_client.post(
            f"{API_PREFIX}/withdrawals",
            headers=maestro_auth_headers,
            json={
                "stelline_amount": 1000,  # Sotto minimo
                "payout_method": "bank_transfer",
                "iban": "IT60X0542811101000000123456"
            }
        )

        assert response.status_code == 400

    def test_list_withdrawals_empty(self, api_client, maestro_auth_headers):
        """Lista withdrawals per nuovo maestro."""
        response = api_client.get(
            f"{API_PREFIX}/withdrawals",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "withdrawals" in data


# =============================================================================
# CORRECTIONS
# =============================================================================

class TestMaestroCorrections:
    """Test richieste correzione."""

    def test_list_corrections(self, api_client, maestro_auth_headers):
        """
        Lista richieste correzione.

        BUSINESS: Maestro vede richieste feedback da studenti.
        """
        response = api_client.get(
            f"{API_PREFIX}/corrections",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "correction_requests" in data

    def test_list_corrections_filter_status(self, api_client, maestro_auth_headers):
        """Test filtro correzioni per status."""
        response = api_client.get(
            f"{API_PREFIX}/corrections",
            headers=maestro_auth_headers,
            params={"status": "pending"}
        )

        assert response.status_code == 200

    def test_submit_feedback_not_maestro(self, api_client, auth_headers):
        """Submit feedback fallisce per non-maestri."""
        response = api_client.post(
            f"{API_PREFIX}/corrections/test-request-id/feedback",
            headers=auth_headers,
            json={
                "feedback_text": "Ottimo lavoro!"
            }
        )

        assert response.status_code in [403, 404]

    @pytest.mark.skip(reason="Richiede utente maestro e richiesta correzione esistente")
    def test_submit_feedback_success(self, api_client, maestro_auth_headers, correction_request_id):
        """Maestro puo inviare feedback."""
        response = api_client.post(
            f"{API_PREFIX}/corrections/{correction_request_id}/feedback",
            headers=maestro_auth_headers,
            json={
                "feedback_text": "Ottimo lavoro sulla postura! Migliora il timing del colpo.",
                "feedback_annotations": {"frame_10": "postura corretta", "frame_25": "anticipa"}
            }
        )

        assert response.status_code == 200


# =============================================================================
# TRANSLATIONS
# =============================================================================

class TestMaestroTranslations:
    """Test translation datasets maestro."""

    def test_list_translation_datasets(self, api_client, maestro_auth_headers):
        """
        Lista translation datasets.

        BUSINESS: Maestro gestisce dataset per traduzione automatica.
        """
        response = api_client.get(
            f"{API_PREFIX}/translations",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "datasets" in data


class TestMaestroGlossary:
    """Test glossario maestro."""

    def test_list_glossary_terms(self, api_client, maestro_auth_headers):
        """
        Lista termini glossario.

        BUSINESS: Glossario personalizzato per traduzioni accurate.
        """
        response = api_client.get(
            f"{API_PREFIX}/glossary",
            headers=maestro_auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "terms" in data

    def test_glossary_search(self, api_client, maestro_auth_headers):
        """Test ricerca nel glossario."""
        response = api_client.get(
            f"{API_PREFIX}/glossary",
            headers=maestro_auth_headers,
            params={"search": "kata"}
        )

        assert response.status_code == 200

    def test_glossary_pagination(self, api_client, maestro_auth_headers):
        """Test pagination glossario."""
        response = api_client.get(
            f"{API_PREFIX}/glossary",
            headers=maestro_auth_headers,
            params={"skip": 0, "limit": 50}
        )

        assert response.status_code == 200
        data = response.json()
        assert "skip" in data
        assert "limit" in data


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestMaestroValidation:
    """Test validazione input."""

    def test_invalid_earnings_period(self, api_client, auth_headers):
        """Periodo earnings invalido."""
        response = api_client.get(
            f"{API_PREFIX}/earnings",
            headers=auth_headers,
            params={"period": "invalid"}
        )

        # 403 (non maestro) o 422 (validation error)
        assert response.status_code in [403, 404, 422]

    def test_invalid_pagination_params(self, api_client, auth_headers):
        """Parametri pagination invalidi."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers,
            params={"skip": -1, "limit": 1000}
        )

        # 403 (non maestro) o 422 (validation error)
        assert response.status_code in [403, 404, 422]

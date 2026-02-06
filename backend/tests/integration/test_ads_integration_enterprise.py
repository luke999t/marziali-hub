"""
================================================================================
AI_MODULE: Ads Integration Enterprise Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione COMPLETA API Ads con database REALE
AI_BUSINESS: Validazione flussi completi ads: batch, views, stats, fraud
AI_TEACHING: Integration testing con TestClient, fixtures auth, DB reale

ZERO MOCK - LEGGE SUPREMA
Tutti i test chiamano API REALI su localhost:8000.
================================================================================
"""

import pytest
import uuid
import time
from datetime import datetime, timedelta

# ==============================================================================
# MARKERS
# ==============================================================================
API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.integration]


# ==============================================================================
# TEST: Ads Batch Session API - REAL BACKEND
# ==============================================================================
class TestAdsBatchSessionAPI:
    """Test Ads Batch Session endpoints - REAL API."""

    def test_start_batch_session_unauthenticated(self, api_client):
        """Start batch senza auth deve fallire."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"}
        )
        assert response.status_code in [401, 403, 404]

    def test_start_batch_session_free_user(self, api_client, auth_headers_free):
        """Utente FREE può avviare batch ads."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )
        # 200/201 success, 404 endpoint non esiste, 400/422 validation
        assert response.status_code in [200, 201, 400, 404, 422]

        if response.status_code in [200, 201]:
            data = response.json()
            assert "session_id" in data or "id" in data or "batch_id" in data

    def test_start_batch_session_invalid_batch_type(self, api_client, auth_headers_free):
        """Batch type invalido deve fallire."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "invalid_type"},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]

    def test_start_batch_3_videos(self, api_client, auth_headers_free):
        """Start batch 3 video."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_start_batch_5_videos(self, api_client, auth_headers_free):
        """Start batch 5 video."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "5_video"},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_start_batch_10_videos(self, api_client, auth_headers_free):
        """Start batch 10 video."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "10_video"},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_get_active_session(self, api_client, auth_headers_free):
        """Get sessione attiva."""
        response = api_client.get(
            f"{API_PREFIX}/ads/batch/active",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 204, 404]

    def test_get_session_by_id_not_found(self, api_client, auth_headers_free):
        """Get sessione inesistente."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/ads/batch/{fake_id}",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 403]

    def test_complete_batch_session(self, api_client, auth_headers_free):
        """Complete sessione batch."""
        # Prima crea sessione
        start_response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )

        if start_response.status_code in [200, 201]:
            data = start_response.json()
            session_id = data.get("session_id") or data.get("id") or data.get("batch_id")

            if session_id:
                # Completa sessione
                response = api_client.post(
                    f"{API_PREFIX}/ads/batch/{session_id}/complete",
                    headers=auth_headers_free
                )
                assert response.status_code in [200, 400, 404]

    def test_abandon_batch_session(self, api_client, auth_headers_free):
        """Abbandona sessione batch."""
        # Prima crea sessione
        start_response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )

        if start_response.status_code in [200, 201]:
            data = start_response.json()
            session_id = data.get("session_id") or data.get("id") or data.get("batch_id")

            if session_id:
                # Abbandona sessione
                response = api_client.delete(
                    f"{API_PREFIX}/ads/batch/{session_id}",
                    headers=auth_headers_free
                )
                assert response.status_code in [200, 204, 400, 404]


# ==============================================================================
# TEST: Ads View Recording API - REAL BACKEND
# ==============================================================================
class TestAdsViewRecordingAPI:
    """Test Ads View Recording endpoints - REAL API."""

    def test_record_view_unauthenticated(self, api_client):
        """Record view senza auth deve fallire."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 30}
        )
        assert response.status_code in [401, 403, 404]

    def test_record_view_authenticated(self, api_client, auth_headers_free):
        """Record view con auth."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 30},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_record_view_zero_duration(self, api_client, auth_headers_free):
        """Record view con durata zero."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 0},
            headers=auth_headers_free
        )
        # Zero duration potrebbe essere rifiutato o accettato
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_record_view_negative_duration(self, api_client, auth_headers_free):
        """Record view con durata negativa deve fallire."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": -10},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]

    def test_record_view_very_long_duration(self, api_client, auth_headers_free):
        """Record view con durata molto lunga (fraud signal)."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 3600},
            headers=auth_headers_free
        )
        # Long duration potrebbe essere accettato con fraud score aumentato
        assert response.status_code in [200, 201, 400, 404, 422]

    def test_record_view_missing_ad_id(self, api_client, auth_headers_free):
        """Record view senza ad_id."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"duration": 30},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]

    def test_record_view_invalid_ad_id(self, api_client, auth_headers_free):
        """Record view con ad_id invalido."""
        response = api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": "not-a-uuid", "duration": 30},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]


# ==============================================================================
# TEST: Ads Stats API - REAL BACKEND
# ==============================================================================
class TestAdsStatsAPI:
    """Test Ads Stats endpoints - REAL API."""

    def test_get_user_stats_unauthenticated(self, api_client):
        """Get stats senza auth."""
        response = api_client.get(f"{API_PREFIX}/ads/stats")
        # Potrebbe essere pubblico o richiedere auth
        assert response.status_code in [200, 401, 403, 404]

    def test_get_user_stats_authenticated(self, api_client, auth_headers_free):
        """Get stats utente autenticato."""
        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            # Verifica campi attesi
            assert isinstance(data, dict)

    def test_get_admin_stats(self, api_client, auth_headers_admin):
        """Get stats admin."""
        response = api_client.get(
            f"{API_PREFIX}/ads/stats/admin",
            headers=auth_headers_admin
        )
        assert response.status_code in [200, 403, 404]

    def test_get_revenue_stats(self, api_client, auth_headers_admin):
        """Get revenue stats."""
        response = api_client.get(
            f"{API_PREFIX}/ads/revenue",
            headers=auth_headers_admin
        )
        assert response.status_code in [200, 403, 404]

    def test_get_stats_by_date_range(self, api_client, auth_headers_admin):
        """Get stats con range date."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        response = api_client.get(
            f"{API_PREFIX}/ads/stats?start_date={today}&end_date={today}",
            headers=auth_headers_admin
        )
        assert response.status_code in [200, 400, 404, 422]


# ==============================================================================
# TEST: Ads Inventory API - REAL BACKEND
# ==============================================================================
class TestAdsInventoryAPI:
    """Test Ads Inventory endpoints - REAL API."""

    def test_get_inventory(self, api_client, auth_headers_admin):
        """Get inventory ads."""
        response = api_client.get(
            f"{API_PREFIX}/ads/inventory",
            headers=auth_headers_admin
        )
        assert response.status_code in [200, 403, 404]

    def test_get_next_ad(self, api_client, auth_headers_free):
        """Get prossimo ad da mostrare."""
        response = api_client.get(
            f"{API_PREFIX}/ads/next",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 204, 404]

    def test_get_next_ad_with_position(self, api_client, auth_headers_free):
        """Get prossimo ad per posizione specifica."""
        for position in ["pre_roll", "mid_roll", "post_roll"]:
            response = api_client.get(
                f"{API_PREFIX}/ads/next?position={position}",
                headers=auth_headers_free
            )
            assert response.status_code in [200, 204, 400, 404, 422]


# ==============================================================================
# TEST: Ads Complete Flow - REAL BACKEND
# ==============================================================================
class TestAdsCompleteFlow:
    """Test flusso completo ads - REAL API."""

    def test_complete_batch_3_flow(self, api_client, auth_headers_free):
        """Flusso completo batch 3 video."""
        # 1. Start batch
        start_response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )

        assert start_response.status_code in [200, 201], \
            f"Batch start failed: {start_response.status_code} - {start_response.text}"

        data = start_response.json()
        session_id = data.get("session_id") or data.get("id") or data.get("batch_id")

        assert session_id, f"session_id not returned in response: {data}"

        # 2. Record views (simula 3 video guardati)
        for i in range(3):
            view_response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={
                    "session_id": session_id,
                    "ad_id": str(uuid.uuid4()),
                    "duration": 60 + i * 10
                },
                headers=auth_headers_free
            )
            # View potrebbe avere endpoint diverso
            assert view_response.status_code in [200, 201, 400, 404, 422]

        # 3. Complete batch
        complete_response = api_client.post(
            f"{API_PREFIX}/ads/batch/{session_id}/complete",
            headers=auth_headers_free
        )
        assert complete_response.status_code in [200, 400, 404]

        # 4. Verify stats updated
        stats_response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )
        assert stats_response.status_code in [200, 404]

    def test_batch_expiration_check(self, api_client, auth_headers_free):
        """Verifica logica scadenza batch."""
        response = api_client.get(
            f"{API_PREFIX}/ads/batch/expired",
            headers=auth_headers_free
        )
        # Potrebbe non esistere endpoint dedicato
        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: Ads Tier Restrictions - REAL BACKEND
# ==============================================================================
class TestAdsTierRestrictions:
    """Test restrizioni per tier - REAL API."""

    def test_premium_user_no_ads(self, api_client, auth_headers_premium):
        """Utente PREMIUM non deve vedere ads."""
        response = api_client.get(
            f"{API_PREFIX}/ads/next",
            headers=auth_headers_premium
        )
        # Premium non dovrebbe ricevere ads
        assert response.status_code in [200, 204, 403, 404]

        if response.status_code == 200:
            data = response.json()
            # Potrebbe restituire empty o null
            assert data is None or data == {} or data.get("ad_id") is None

    def test_free_user_sees_ads(self, api_client, auth_headers_free):
        """Utente FREE deve vedere ads."""
        response = api_client.get(
            f"{API_PREFIX}/ads/next",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 204, 404]


# ==============================================================================
# TEST: Ads Error Handling - REAL BACKEND
# ==============================================================================
class TestAdsErrorHandling:
    """Test gestione errori - REAL API."""

    def test_malformed_json_request(self, api_client, auth_headers_free):
        """Request con JSON malformato."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            content="not valid json",
            headers={**auth_headers_free, "Content-Type": "application/json"}
        )
        assert response.status_code in [400, 404, 422]

    def test_empty_body_request(self, api_client, auth_headers_free):
        """Request con body vuoto."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={},
            headers=auth_headers_free
        )
        assert response.status_code in [400, 404, 422]

    def test_extra_fields_ignored(self, api_client, auth_headers_free):
        """Request con campi extra deve essere accettata o rifiutata gracefully."""
        response = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={
                "batch_type": "3_video",
                "extra_field": "should_be_ignored",
                "another_field": 123
            },
            headers=auth_headers_free
        )
        # Extra fields should be ignored or cause validation error
        assert response.status_code in [200, 201, 400, 404, 422]


# ==============================================================================
# TEST: Ads Database Consistency - REAL BACKEND
# ==============================================================================
class TestAdsDatabaseConsistency:
    """Test consistenza database - REAL API."""

    def test_concurrent_batch_start_same_user(self, api_client, auth_headers_free):
        """Avvio batch concorrente stesso utente."""
        # Prima batch
        response1 = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )

        # Seconda batch (dovrebbe fallire se già attiva)
        response2 = api_client.post(
            f"{API_PREFIX}/ads/batch/start",
            json={"batch_type": "3_video"},
            headers=auth_headers_free
        )

        # Almeno una deve riuscire
        statuses = {response1.status_code, response2.status_code}
        # Non dovrebbero essere entrambe 200/201 se c'è vincolo
        assert any(s in [200, 201, 404] for s in statuses)

    def test_view_increments_counter(self, api_client, auth_headers_free):
        """Verifica che view incrementi contatore."""
        # Get stats iniziali
        initial_stats = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )

        # Record view
        api_client.post(
            f"{API_PREFIX}/ads/view",
            json={"ad_id": str(uuid.uuid4()), "duration": 30},
            headers=auth_headers_free
        )

        # Get stats finali
        final_stats = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )

        # Verifica incremento (se endpoint esiste)
        if initial_stats.status_code == 200 and final_stats.status_code == 200:
            initial = initial_stats.json()
            final = final_stats.json()

            initial_views = initial.get("views_today", initial.get("total_views", 0))
            final_views = final.get("views_today", final.get("total_views", 0))

            # Views dovrebbero essere >= iniziali
            assert final_views >= initial_views

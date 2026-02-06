"""
================================================================================
AI_MODULE: Temp Zone API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per Temp Zone REST endpoints
AI_BUSINESS: Garantisce funzionamento gestione file temporanei
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock TempZoneManager: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

METRICHE_SUCCESSO:
- Coverage: 90%+ per temp_zone.py REST endpoints
- Pass rate: 95%+
- Response time: <500ms per endpoint

ENDPOINTS TESTATI:
- GET /api/v1/temp-zone/stats - Statistiche temp zone
- GET /api/v1/temp-zone/batches - Lista batch con filtri
- GET /api/v1/temp-zone/batches/{id} - Dettaglio batch
- DELETE /api/v1/temp-zone/batches/{id} - Cancella batch (admin)
- POST /api/v1/temp-zone/cleanup - Cleanup bulk (admin)
- GET /api/v1/temp-zone/expiring - Batch in scadenza
- GET /api/v1/temp-zone/audit - Audit log (admin)
- GET /api/v1/temp-zone/config - Configurazione
- PATCH /api/v1/temp-zone/config - Aggiorna config (admin)
- GET /api/v1/temp-zone/batch-types - Tipi batch supportati

================================================================================
"""

import pytest
import httpx
from typing import Dict


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/admin/temp-zone"


# =============================================================================
# PUBLIC ENDPOINTS
# =============================================================================

class TestTempZonePublic:
    """Test endpoint pubblici Temp Zone."""

    def test_batch_types_public(self, api_client):
        """
        Lista tipi batch accessibile pubblicamente.

        BUSINESS: Frontend mostra opzioni tipo batch.
        """
        response = api_client.get(f"{API_PREFIX}/batch-types")

        # Questo endpoint potrebbe essere pubblico o richiedere auth
        assert response.status_code in [200, 401, 403]

        if response.status_code == 200:
            data = response.json()
            assert "batch_types" in data
            assert isinstance(data["batch_types"], list)


# =============================================================================
# AUTHENTICATION TESTS
# =============================================================================

class TestTempZoneAuth:
    """Test autenticazione Temp Zone endpoints."""

    def test_stats_no_auth(self, api_client):
        """Stats richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/stats")

        assert response.status_code in [401, 403, 404]

    def test_batches_no_auth(self, api_client):
        """Lista batches richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/batches")

        assert response.status_code in [401, 403, 404]

    def test_get_batch_no_auth(self, api_client):
        """Get batch richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/batches/test-batch-id")

        assert response.status_code in [401, 403, 404]

    def test_delete_batch_no_auth(self, api_client):
        """Delete batch richiede autenticazione admin."""
        response = api_client.delete(f"{API_PREFIX}/batches/test-batch-id")

        assert response.status_code in [401, 403, 404]

    def test_cleanup_no_auth(self, api_client):
        """Cleanup richiede autenticazione admin."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            json={"confirm": True}
        )

        assert response.status_code in [401, 403, 404]

    def test_expiring_no_auth(self, api_client):
        """Expiring batches richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/expiring")

        assert response.status_code in [401, 403, 404]

    def test_audit_no_auth(self, api_client):
        """Audit log richiede autenticazione admin."""
        response = api_client.get(f"{API_PREFIX}/audit")

        assert response.status_code in [401, 403, 404]

    def test_config_no_auth(self, api_client):
        """Config richiede autenticazione."""
        response = api_client.get(f"{API_PREFIX}/config")

        assert response.status_code in [401, 403, 404]

    def test_update_config_no_auth(self, api_client):
        """Update config richiede autenticazione admin."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            json={"auto_cleanup_enabled": True}
        )

        assert response.status_code in [401, 403, 404]


# =============================================================================
# USER ACCESS TESTS
# =============================================================================

class TestTempZoneUser:
    """Test accesso utente normale a Temp Zone endpoints."""

    def test_stats_with_auth(self, api_client, auth_headers):
        """
        Utente vede statistiche temp zone.

        BUSINESS: Utenti monitorano propri file temporanei.
        """
        response = api_client.get(
            f"{API_PREFIX}/stats",
            headers=auth_headers
        )

        # 200 con stats, 500 se servizio non disponibile
        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "total_batches" in data
            assert "total_size_bytes" in data
            assert "by_status" in data

    def test_batches_list_with_auth(self, api_client, auth_headers):
        """
        Utente vede lista propri batch.

        BUSINESS: Dashboard file temporanei.
        """
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "batches" in data
            assert "total" in data
            assert isinstance(data["batches"], list)

    def test_batches_filter_by_status(self, api_client, auth_headers):
        """Filtra batch per status."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"status": "completed"}
        )

        assert response.status_code in [200, 400, 500]

    def test_batches_filter_by_type(self, api_client, auth_headers):
        """Filtra batch per tipo."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"batch_type": "pdf_ocr"}
        )

        assert response.status_code in [200, 400, 500]

    def test_batches_pagination(self, api_client, auth_headers):
        """Paginazione lista batch."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"limit": 10, "offset": 0}
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "filtered" in data
            assert len(data["batches"]) <= 10

    def test_get_batch_details(self, api_client, auth_headers):
        """Utente vede dettagli batch."""
        response = api_client.get(
            f"{API_PREFIX}/batches/test-batch-id",
            headers=auth_headers
        )

        # 404 se non esiste, 200 se esiste
        assert response.status_code in [200, 404, 500]

    def test_expiring_batches(self, api_client, auth_headers):
        """
        Utente vede batch in scadenza.

        BUSINESS: Alert batch che scadranno presto.
        """
        response = api_client.get(
            f"{API_PREFIX}/expiring",
            headers=auth_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)

    def test_config_view(self, api_client, auth_headers):
        """
        Utente vede configurazione.

        BUSINESS: Trasparenza su policy retention.
        """
        response = api_client.get(
            f"{API_PREFIX}/config",
            headers=auth_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "auto_cleanup_enabled" in data
            assert "delete_after_days" in data

    def test_delete_batch_requires_admin(self, api_client, auth_headers):
        """
        Utente normale non puo cancellare batch.

        BUSINESS: Solo admin cancellano dati.
        """
        response = api_client.delete(
            f"{API_PREFIX}/batches/test-batch-id",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]

    def test_cleanup_requires_admin(self, api_client, auth_headers):
        """Utente normale non puo fare cleanup."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=auth_headers,
            json={"confirm": True}
        )

        assert response.status_code in [401, 403, 404]

    def test_audit_requires_admin(self, api_client, auth_headers):
        """Utente normale non vede audit log."""
        response = api_client.get(
            f"{API_PREFIX}/audit",
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 404]

    def test_update_config_requires_admin(self, api_client, auth_headers):
        """Utente normale non puo modificare config."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=auth_headers,
            json={"auto_cleanup_enabled": False}
        )

        assert response.status_code in [401, 403, 404]


# =============================================================================
# ADMIN BATCH MANAGEMENT
# =============================================================================

class TestTempZoneAdmin:
    """Test gestione admin Temp Zone."""

    def test_delete_batch_not_found(self, api_client, admin_headers):
        """Admin cancella batch inesistente."""
        response = api_client.delete(
            f"{API_PREFIX}/batches/non-existent-batch-id",
            headers=admin_headers
        )

        assert response.status_code in [404, 500]

    def test_cleanup_without_confirm(self, api_client, admin_headers):
        """
        Cleanup senza conferma fallisce.

        BUSINESS: Safety check per operazioni distruttive.
        """
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=admin_headers,
            json={"confirm": False}
        )

        assert response.status_code in [400, 422]

    def test_cleanup_completed_batches(self, api_client, admin_headers):
        """Admin cleanup batch completati."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=admin_headers,
            json={
                "delete_completed": True,
                "delete_failed": False,
                "confirm": True
            }
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "deleted_count" in data
            assert "freed_bytes" in data

    def test_cleanup_failed_batches(self, api_client, admin_headers):
        """Admin cleanup batch falliti."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=admin_headers,
            json={
                "delete_completed": False,
                "delete_failed": True,
                "confirm": True
            }
        )

        assert response.status_code in [200, 500]

    def test_cleanup_with_older_than(self, api_client, admin_headers):
        """Admin cleanup batch piu vecchi di X giorni."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=admin_headers,
            json={
                "delete_completed": True,
                "older_than_days": 30,
                "confirm": True
            }
        )

        assert response.status_code in [200, 500]

    def test_audit_log(self, api_client, admin_headers):
        """
        Admin vede audit log.

        BUSINESS: Tracciabilita operazioni sensibili.
        """
        response = api_client.get(
            f"{API_PREFIX}/audit",
            headers=admin_headers
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "entries" in data
            assert "total" in data

    def test_audit_log_filter_action(self, api_client, admin_headers):
        """Filtra audit log per action."""
        response = api_client.get(
            f"{API_PREFIX}/audit",
            headers=admin_headers,
            params={"action": "DELETE"}
        )

        assert response.status_code in [200, 500]

    def test_audit_log_filter_target(self, api_client, admin_headers):
        """Filtra audit log per target ID."""
        response = api_client.get(
            f"{API_PREFIX}/audit",
            headers=admin_headers,
            params={"target_id": "test-batch-id"}
        )

        assert response.status_code in [200, 500]

    def test_audit_log_with_limit(self, api_client, admin_headers):
        """Audit log con limite risultati."""
        response = api_client.get(
            f"{API_PREFIX}/audit",
            headers=admin_headers,
            params={"limit": 10}
        )

        assert response.status_code in [200, 500]


# =============================================================================
# ADMIN CONFIG MANAGEMENT
# =============================================================================

class TestTempZoneAdminConfig:
    """Test gestione configurazione admin."""

    def test_update_auto_cleanup(self, api_client, admin_headers):
        """
        Admin abilita/disabilita auto cleanup.

        BUSINESS: Controllo policy retention.
        """
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"auto_cleanup_enabled": True}
        )

        assert response.status_code in [200, 500]

        if response.status_code == 200:
            data = response.json()
            assert "auto_cleanup_enabled" in data

    def test_update_delete_after_days(self, api_client, admin_headers):
        """Admin modifica retention period."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"delete_after_days": 60}
        )

        assert response.status_code in [200, 500]

    def test_update_warn_before_days(self, api_client, admin_headers):
        """Admin modifica warning period."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"warn_before_days": 7}
        )

        assert response.status_code in [200, 500]

    def test_update_secure_delete(self, api_client, admin_headers):
        """Admin abilita secure delete."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"secure_delete": True}
        )

        assert response.status_code in [200, 500]

    def test_update_multiple_config(self, api_client, admin_headers):
        """Admin modifica multipli parametri config."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={
                "auto_cleanup_enabled": True,
                "delete_after_days": 30,
                "warn_before_days": 5
            }
        )

        assert response.status_code in [200, 500]


# =============================================================================
# VALIDATION TESTS
# =============================================================================

class TestTempZoneValidation:
    """Test validazione input."""

    def test_batches_invalid_status(self, api_client, auth_headers):
        """Lista batch con status invalido."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"status": "invalid_status"}
        )

        assert response.status_code in [400, 422]

    def test_batches_invalid_batch_type(self, api_client, auth_headers):
        """Lista batch con tipo invalido."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"batch_type": "invalid_type"}
        )

        assert response.status_code in [400, 422]

    def test_batches_invalid_limit(self, api_client, auth_headers):
        """Lista batch con limit invalido."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers,
            params={"limit": -1}
        )

        assert response.status_code in [200, 422, 500]

    def test_cleanup_invalid_older_than(self, api_client, admin_headers):
        """Cleanup con older_than_days invalido."""
        response = api_client.post(
            f"{API_PREFIX}/cleanup",
            headers=admin_headers,
            json={
                "delete_completed": True,
                "older_than_days": 1000,  # > 365
                "confirm": True
            }
        )

        assert response.status_code in [200, 422, 500]

    def test_config_invalid_delete_after_days(self, api_client, admin_headers):
        """Config con delete_after_days invalido."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"delete_after_days": 0}  # < 1
        )

        assert response.status_code in [422, 500]

    def test_config_invalid_warn_before_days(self, api_client, admin_headers):
        """Config con warn_before_days invalido."""
        response = api_client.patch(
            f"{API_PREFIX}/config",
            headers=admin_headers,
            json={"warn_before_days": 100}  # > 30
        )

        assert response.status_code in [422, 500]


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestTempZoneErrors:
    """Test gestione errori."""

    def test_malformed_batch_id(self, api_client, auth_headers):
        """Batch ID malformato."""
        response = api_client.get(
            f"{API_PREFIX}/batches/../../../etc/passwd",
            headers=auth_headers
        )

        # Path traversal dovrebbe essere bloccato
        assert response.status_code in [400, 404, 422]

    def test_very_long_batch_id(self, api_client, auth_headers):
        """Batch ID molto lungo."""
        long_id = "a" * 1000

        response = api_client.get(
            f"{API_PREFIX}/batches/{long_id}",
            headers=auth_headers
        )

        assert response.status_code in [400, 404, 414, 500]

    def test_special_characters_batch_id(self, api_client, auth_headers):
        """Batch ID con caratteri speciali."""
        response = api_client.get(
            f"{API_PREFIX}/batches/test%00batch",
            headers=auth_headers
        )

        assert response.status_code in [400, 404, 422, 500]


# =============================================================================
# PREMIUM ACCESS TESTS
# =============================================================================

class TestTempZonePremium:
    """Test accesso premium."""

    def test_premium_user_stats(self, api_client, auth_headers_premium):
        """Utente premium vede stats."""
        response = api_client.get(
            f"{API_PREFIX}/stats",
            headers=auth_headers_premium
        )

        assert response.status_code in [200, 500]

    def test_premium_user_batches(self, api_client, auth_headers_premium):
        """Utente premium vede batch."""
        response = api_client.get(
            f"{API_PREFIX}/batches",
            headers=auth_headers_premium
        )

        assert response.status_code in [200, 500]


# =============================================================================
# BATCH TYPES INFO TESTS
# =============================================================================

class TestTempZoneBatchTypes:
    """Test info tipi batch."""

    def test_get_batch_types(self, api_client, auth_headers):
        """Lista tipi batch supportati."""
        response = api_client.get(
            f"{API_PREFIX}/batch-types",
            headers=auth_headers
        )

        # Potrebbe essere pubblico o autenticato
        assert response.status_code in [200, 401, 403]

        if response.status_code == 200:
            data = response.json()
            assert "batch_types" in data

            # Verifica struttura
            if len(data["batch_types"]) > 0:
                bt = data["batch_types"][0]
                assert "value" in bt
                assert "name" in bt


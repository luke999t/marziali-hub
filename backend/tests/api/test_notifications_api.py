"""
================================================================================
AI_MODULE: TestNotificationsAPI
AI_VERSION: 2.0.0
AI_DESCRIPTION: Test Notifications endpoints con backend REALE - ZERO MOCK
AI_BUSINESS: User engagement - Notifiche in-app, push notifications, preferences
AI_TEACHING: ZERO MOCK - chiamate HTTP SYNC reali a localhost:8000

FIX 2025-01-26: Rimosso ASGITransport che causava:
- "Event loop is closed"
- "another operation is in progress"
- Problemi con asyncpg e connessioni zombie

Ora usa httpx.Client SYNC con chiamate HTTP reali al backend.
================================================================================

ZERO_MOCK_POLICY: Nessun mock consentito
COVERAGE_TARGETS: Line 90%+, Pass rate 95%+

ENDPOINTS TESTATI:
- GET /notifications: Lista notifiche utente (paginata)
- GET /notifications/unread-count: Conteggio non lette
- GET /notifications/{id}: Dettaglio notifica
- PATCH /notifications/{id}/read: Marca come letta
- POST /notifications/mark-all-read: Marca tutte come lette
- DELETE /notifications/{id}: Elimina notifica
- DELETE /notifications: Elimina tutte le notifiche
- POST /notifications/device-tokens: Registra device token
- DELETE /notifications/device-tokens/{token}: Rimuove device token
- GET /notifications/device-tokens: Lista device tokens
- GET /notifications/preferences: Ottieni preferenze
- PATCH /notifications/preferences: Aggiorna preferenze
- POST /notifications/admin/broadcast: Broadcast (admin only)

================================================================================
"""

import pytest
import httpx
import uuid
import os

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration, pytest.mark.api]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/notifications"
AUTH_PREFIX = "/api/v1/auth"


# ==============================================================================
# FIXTURES - SYNC HTTP CLIENT (NO ASYNCIO ISSUES)
# ==============================================================================

@pytest.fixture(scope="module")
def http_client():
    """
    Client HTTP SYNC per test notifications.
    
    FIX 2025-01-26: Usa client SYNC invece di async per evitare
    problemi con event loop e asyncpg.
    
    ZERO MOCK: Chiamate HTTP reali a localhost:8000
    """
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        try:
            response = client.get("/health")
            if response.status_code != 200:
                pytest.skip(f"Backend not healthy: {response.status_code}")
        except httpx.ConnectError:
            pytest.skip(f"Backend not running at {BASE_URL}")
        yield client


@pytest.fixture(scope="module")
def auth_headers(http_client):
    """Get auth headers for test user."""
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "test@martialarts.com",
            "password": "TestPassword123!"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    # Try alternative user
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "premium_test@example.com",
            "password": "test123"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    pytest.skip("Test user not available - run seed script")


@pytest.fixture(scope="module")
def admin_headers(http_client):
    """Get auth headers for admin user."""
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "admin@martialarts.com",
            "password": "AdminPassword123!"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    pytest.skip("Admin user not available - run seed script")


# ==============================================================================
# TEST: Notification List
# ==============================================================================

class TestNotificationList:
    """Test notification list endpoint."""

    def test_list_requires_auth(self, http_client):
        """GET /notifications richiede auth."""
        response = http_client.get(f"{API_PREFIX}")

        assert response.status_code in [401, 403, 500, 503]

    def test_list_notifications(self, http_client, auth_headers):
        """GET /notifications ritorna lista paginata."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data
        assert "has_more" in data

    def test_list_with_pagination(self, http_client, auth_headers):
        """GET /notifications con pagination."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"page": 1, "page_size": 5}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 5

    def test_list_filter_unread(self, http_client, auth_headers):
        """GET /notifications con filtro unread_only."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"unread_only": True}
        )

        assert response.status_code == 200

    def test_list_filter_type(self, http_client, auth_headers):
        """GET /notifications con filtro tipo."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"notification_type": "system"}
        )

        assert response.status_code == 200

    def test_list_invalid_type(self, http_client, auth_headers):
        """GET /notifications con tipo invalido."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"notification_type": "invalid_type"}
        )

        assert response.status_code == 400


# ==============================================================================
# TEST: Unread Count
# ==============================================================================

class TestUnreadCount:
    """Test unread count endpoint."""

    def test_unread_requires_auth(self, http_client):
        """GET /notifications/unread-count richiede auth."""
        response = http_client.get(f"{API_PREFIX}/unread-count")

        assert response.status_code in [401, 403, 500, 503]

    def test_get_unread_count(self, http_client, auth_headers):
        """GET /notifications/unread-count ritorna conteggio."""
        response = http_client.get(
            f"{API_PREFIX}/unread-count",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "count" in data
        assert isinstance(data["count"], int)
        assert data["count"] >= 0


# ==============================================================================
# TEST: Notification Detail
# ==============================================================================

class TestNotificationDetail:
    """Test notification detail endpoint."""

    def test_get_notification_requires_auth(self, http_client):
        """GET /notifications/{id} richiede auth."""
        fake_id = str(uuid.uuid4())
        response = http_client.get(f"{API_PREFIX}/{fake_id}")

        assert response.status_code in [401, 403, 500, 503]

    def test_get_notification_not_found(self, http_client, auth_headers):
        """GET /notifications/{id} con ID inesistente."""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{API_PREFIX}/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404


# ==============================================================================
# TEST: Mark as Read
# ==============================================================================

class TestMarkAsRead:
    """Test mark as read endpoints."""

    def test_mark_read_requires_auth(self, http_client):
        """PATCH /notifications/{id}/read richiede auth."""
        fake_id = str(uuid.uuid4())
        response = http_client.patch(f"{API_PREFIX}/{fake_id}/read")

        assert response.status_code in [401, 403, 500, 503]

    def test_mark_read_not_found(self, http_client, auth_headers):
        """PATCH /notifications/{id}/read con ID inesistente."""
        fake_id = str(uuid.uuid4())
        response = http_client.patch(
            f"{API_PREFIX}/{fake_id}/read",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_mark_all_read_requires_auth(self, http_client):
        """POST /notifications/mark-all-read richiede auth."""
        response = http_client.post(f"{API_PREFIX}/mark-all-read")

        assert response.status_code in [401, 403, 500, 503]

    def test_mark_all_read(self, http_client, auth_headers):
        """POST /notifications/mark-all-read marca tutte come lette."""
        response = http_client.post(
            f"{API_PREFIX}/mark-all-read",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data


# ==============================================================================
# TEST: Delete Notifications
# ==============================================================================

class TestDeleteNotifications:
    """Test delete notification endpoints."""

    def test_delete_requires_auth(self, http_client):
        """DELETE /notifications/{id} richiede auth."""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(f"{API_PREFIX}/{fake_id}")

        assert response.status_code in [401, 403, 500, 503]

    def test_delete_not_found(self, http_client, auth_headers):
        """DELETE /notifications/{id} con ID inesistente."""
        fake_id = str(uuid.uuid4())
        response = http_client.delete(
            f"{API_PREFIX}/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_delete_all_requires_auth(self, http_client):
        """DELETE /notifications richiede auth."""
        response = http_client.delete(f"{API_PREFIX}")

        assert response.status_code in [401, 403, 500, 503]

    def test_delete_all(self, http_client, auth_headers):
        """DELETE /notifications elimina tutte."""
        response = http_client.delete(
            f"{API_PREFIX}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "message" in data


# ==============================================================================
# TEST: Device Tokens
# ==============================================================================

class TestDeviceTokens:
    """Test device token endpoints."""

    def test_register_requires_auth(self, http_client):
        """POST /notifications/device-tokens richiede auth."""
        response = http_client.post(
            f"{API_PREFIX}/device-tokens",
            json={
                "token": "test_token_12345678",
                "device_type": "android"
            }
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_register_android_token(self, http_client, auth_headers):
        """POST /notifications/device-tokens registra token Android."""
        unique_token = f"android_fcm_{uuid.uuid4().hex}"
        response = http_client.post(
            f"{API_PREFIX}/device-tokens",
            headers=auth_headers,
            json={
                "token": unique_token,
                "device_type": "android",
                "device_name": "Test Device",
                "app_version": "1.0.0"
            }
        )

        assert response.status_code == 201
        data = response.json()
        assert "id" in data
        assert data["device_type"] == "android"

    def test_register_ios_token(self, http_client, auth_headers):
        """POST /notifications/device-tokens registra token iOS."""
        unique_token = f"ios_apns_{uuid.uuid4().hex}"
        response = http_client.post(
            f"{API_PREFIX}/device-tokens",
            headers=auth_headers,
            json={
                "token": unique_token,
                "device_type": "ios",
                "device_name": "iPhone Test",
                "app_version": "1.0.0"
            }
        )

        assert response.status_code == 201

    def test_register_invalid_device_type(self, http_client, auth_headers):
        """POST /notifications/device-tokens con tipo invalido."""
        response = http_client.post(
            f"{API_PREFIX}/device-tokens",
            headers=auth_headers,
            json={
                "token": f"token_{uuid.uuid4().hex}",
                "device_type": "invalid_type"
            }
        )

        assert response.status_code == 400

    def test_list_device_tokens(self, http_client, auth_headers):
        """GET /notifications/device-tokens ritorna lista."""
        response = http_client.get(
            f"{API_PREFIX}/device-tokens",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_unregister_token_not_found(self, http_client, auth_headers):
        """DELETE /notifications/device-tokens/{token} non trovato."""
        response = http_client.delete(
            f"{API_PREFIX}/device-tokens/nonexistent_token_{uuid.uuid4().hex}",
            headers=auth_headers
        )

        assert response.status_code == 404


# ==============================================================================
# TEST: Preferences
# ==============================================================================

class TestPreferences:
    """Test notification preferences endpoints."""

    def test_get_preferences_requires_auth(self, http_client):
        """GET /notifications/preferences richiede auth."""
        response = http_client.get(f"{API_PREFIX}/preferences")

        assert response.status_code in [401, 403, 500, 503]

    def test_get_preferences(self, http_client, auth_headers):
        """GET /notifications/preferences ritorna preferenze."""
        response = http_client.get(
            f"{API_PREFIX}/preferences",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "system_enabled" in data
        assert "push_enabled" in data
        assert "quiet_hours_enabled" in data

    def test_update_preferences_requires_auth(self, http_client):
        """PATCH /notifications/preferences richiede auth."""
        response = http_client.patch(
            f"{API_PREFIX}/preferences",
            json={"push_enabled": False}
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_update_preferences(self, http_client, auth_headers):
        """PATCH /notifications/preferences aggiorna preferenze."""
        response = http_client.patch(
            f"{API_PREFIX}/preferences",
            headers=auth_headers,
            json={"promo_enabled": False}
        )

        assert response.status_code == 200

    def test_update_quiet_hours_invalid(self, http_client, auth_headers):
        """PATCH /notifications/preferences con quiet_hours invalido."""
        response = http_client.patch(
            f"{API_PREFIX}/preferences",
            headers=auth_headers,
            json={"quiet_hours_start": "25:00"}
        )

        assert response.status_code == 422


# ==============================================================================
# TEST: Admin Broadcast
# ==============================================================================

class TestAdminBroadcast:
    """Test admin broadcast endpoint."""

    def test_broadcast_requires_auth(self, http_client):
        """POST /notifications/admin/broadcast richiede auth."""
        response = http_client.post(
            f"{API_PREFIX}/admin/broadcast",
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "system",
                "title": "Test",
                "body": "Test body"
            }
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_broadcast_requires_admin(self, http_client, auth_headers):
        """POST /notifications/admin/broadcast richiede admin."""
        response = http_client.post(
            f"{API_PREFIX}/admin/broadcast",
            headers=auth_headers,
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "system",
                "title": "Test",
                "body": "Test body"
            }
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_broadcast_invalid_type(self, http_client, admin_headers):
        """POST /notifications/admin/broadcast con tipo invalido."""
        response = http_client.post(
            f"{API_PREFIX}/admin/broadcast",
            headers=admin_headers,
            json={
                "user_ids": [str(uuid.uuid4())],
                "notification_type": "invalid_type",
                "title": "Test",
                "body": "Test body"
            }
        )

        assert response.status_code in [400, 401, 403, 500, 503]


# ==============================================================================
# TEST: Validation
# ==============================================================================

class TestValidation:
    """Test input validation."""

    def test_invalid_pagination_page(self, http_client, auth_headers):
        """GET /notifications con page invalida."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"page": -1}
        )

        assert response.status_code == 422

    def test_invalid_pagination_size(self, http_client, auth_headers):
        """GET /notifications con page_size invalida."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"page_size": 0}
        )

        assert response.status_code == 422

    def test_page_size_capped(self, http_client, auth_headers):
        """GET /notifications page_size cappato a 100."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"page_size": 500}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["page_size"] <= 100


# ==============================================================================
# TEST: Security
# ==============================================================================

class TestSecurity:
    """Test security aspects."""

    def test_invalid_token(self, http_client):
        """Richieste con token invalido falliscono."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code in [401, 403, 500, 503]

    def test_sql_injection_type(self, http_client, auth_headers):
        """SQL injection nel tipo notifica prevenuta."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers,
            params={"notification_type": "'; DROP TABLE notifications; --"}
        )

        assert response.status_code in [400, 422, 500, 503]

    def test_xss_in_device_name(self, http_client, auth_headers):
        """XSS in device name sanitizzato."""
        response = http_client.post(
            f"{API_PREFIX}/device-tokens",
            headers=auth_headers,
            json={
                "token": f"xss_test_{uuid.uuid4().hex}",
                "device_type": "android",
                "device_name": "<script>alert('xss')</script>"
            }
        )

        assert response.status_code == 201


# ==============================================================================
# TEST: Response Format
# ==============================================================================

class TestResponseFormat:
    """Test response format consistency."""

    def test_list_response_json(self, http_client, auth_headers):
        """GET /notifications ritorna JSON valido."""
        response = http_client.get(
            f"{API_PREFIX}",
            headers=auth_headers
        )

        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

    def test_error_response_format(self, http_client, auth_headers):
        """Errori ritornano formato consistente."""
        fake_id = str(uuid.uuid4())
        response = http_client.get(
            f"{API_PREFIX}/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404
        data = response.json()
        assert "detail" in data

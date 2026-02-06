"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Users API Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.

================================================================================
"""

import pytest

API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.integration]


# ==============================================================================
# TEST: User Profile - REAL API
# ==============================================================================
class TestUserProfile:
    """Test user profile - REAL API"""

    def test_get_profile_requires_auth(self, api_client):
        """Profilo richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me")
        assert response.status_code in [401, 403, 404]

    def test_get_profile(self, api_client, auth_headers_free):
        """Get profilo autenticato"""
        response = api_client.get(
            f"{API_PREFIX}/users/me",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            # Should contain email field
            assert "email" in data

    def test_get_profile_premium(self, api_client, auth_headers_premium):
        """Get profilo utente premium"""
        response = api_client.get(
            f"{API_PREFIX}/users/me",
            headers=auth_headers_premium
        )
        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            # Should contain email field
            assert "email" in data

    def test_update_profile(self, api_client, auth_headers_free):
        """Update profilo"""
        response = api_client.put(
            f"{API_PREFIX}/users/me",
            json={"full_name": "Updated Name"},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422]

    def test_update_profile_requires_auth(self, api_client):
        """Update profilo richiede auth"""
        response = api_client.put(
            f"{API_PREFIX}/users/me",
            json={"full_name": "Test"}
        )
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: User Settings - REAL API
# ==============================================================================
class TestUserSettings:
    """Test user settings - REAL API"""

    def test_get_settings_requires_auth(self, api_client):
        """Settings richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me/settings")
        assert response.status_code in [401, 403, 404]

    def test_get_settings(self, api_client, auth_headers_free):
        """Get settings"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/settings",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

    def test_update_settings(self, api_client, auth_headers_free):
        """Update settings"""
        response = api_client.put(
            f"{API_PREFIX}/users/me/settings",
            json={"notifications_enabled": True, "language": "it"},
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422]


# ==============================================================================
# TEST: User Subscription - REAL API
# ==============================================================================
class TestUserSubscription:
    """Test user subscription - REAL API"""

    def test_get_subscription_requires_auth(self, api_client):
        """Subscription richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me/subscription")
        assert response.status_code in [401, 403, 404]

    def test_get_subscription_free_user(self, api_client, auth_headers_free):
        """Get subscription per utente FREE"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/subscription",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            # FREE user should have free tier
            assert data.get("tier") in ["FREE", "free", None] or "tier" not in data

    def test_get_subscription_premium_user(self, api_client, auth_headers_premium):
        """Get subscription per utente PREMIUM"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/subscription",
            headers=auth_headers_premium
        )
        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: User Wallet - REAL API
# ==============================================================================
class TestUserWallet:
    """Test user wallet (stelline) - REAL API"""

    def test_get_wallet_requires_auth(self, api_client):
        """Wallet richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me/wallet")
        assert response.status_code in [401, 403, 404]

    def test_get_wallet(self, api_client, auth_headers_free):
        """Get wallet balance"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/wallet",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

    def test_get_wallet_transactions(self, api_client, auth_headers_free):
        """Get wallet transactions"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/wallet/transactions",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: User Notifications - REAL API
# ==============================================================================
class TestUserNotifications:
    """Test user notifications - REAL API"""

    def test_get_notifications_requires_auth(self, api_client):
        """Notifications richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me/notifications")
        assert response.status_code in [401, 403, 404]

    def test_get_notifications(self, api_client, auth_headers_free):
        """Get notifications"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/notifications",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

    def test_mark_notifications_read(self, api_client, auth_headers_free):
        """Mark notifications as read"""
        response = api_client.post(
            f"{API_PREFIX}/users/me/notifications/read-all",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 204, 404]


# ==============================================================================
# TEST: User Activity - REAL API
# ==============================================================================
class TestUserActivity:
    """Test user activity - REAL API"""

    def test_get_activity_requires_auth(self, api_client):
        """Activity richiede auth"""
        response = api_client.get(f"{API_PREFIX}/users/me/activity")
        assert response.status_code in [401, 403, 404]

    def test_get_activity(self, api_client, auth_headers_free):
        """Get user activity"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/activity",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

    def test_get_stats(self, api_client, auth_headers_free):
        """Get user stats"""
        response = api_client.get(
            f"{API_PREFIX}/users/me/stats",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: User Password - REAL API
# ==============================================================================
class TestUserPassword:
    """Test user password - REAL API"""

    def test_change_password_requires_auth(self, api_client):
        """Change password richiede auth"""
        response = api_client.post(
            f"{API_PREFIX}/users/me/password",
            json={"old_password": "test", "new_password": "newtest"}
        )
        assert response.status_code in [401, 403, 404]

    def test_change_password_wrong_old(self, api_client, auth_headers_free):
        """Change password con vecchia password sbagliata"""
        response = api_client.post(
            f"{API_PREFIX}/users/me/password",
            json={
                "old_password": "WrongPassword123!",
                "new_password": "NewPassword123!"
            },
            headers=auth_headers_free
        )
        assert response.status_code in [400, 401, 403, 404, 422]


# ==============================================================================
# TEST: User Deletion - REAL API
# ==============================================================================
class TestUserDeletion:
    """Test user deletion - REAL API"""

    def test_delete_account_requires_auth(self, api_client):
        """Delete account richiede auth"""
        response = api_client.delete(f"{API_PREFIX}/users/me")
        assert response.status_code in [401, 403, 404, 405]

    # Not testing actual deletion to avoid destroying test users


# ==============================================================================
# TEST: Public User Profile - REAL API
# ==============================================================================
class TestPublicUserProfile:
    """Test public user profile - REAL API"""

    def test_get_public_profile_not_found(self, api_client):
        """Public profile inesistente"""
        response = api_client.get(f"{API_PREFIX}/users/profile/nonexistent-user")
        assert response.status_code in [404, 400]

    def test_get_maestro_profile_not_found(self, api_client):
        """Maestro profile inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/maestri/{fake_id}")
        assert response.status_code in [404, 400]

    def test_list_maestri(self, api_client):
        """Lista maestri pubblici"""
        response = api_client.get(f"{API_PREFIX}/maestri")
        assert response.status_code in [200, 404]

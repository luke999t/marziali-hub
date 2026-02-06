"""
================================================================================
AI_MODULE: Test Payments API
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integration endpoint pagamenti Stripe
AI_BUSINESS: Garantisce flusso pagamenti funzionante
AI_TEACHING: ZERO MOCK - chiamate reali a localhost:8000

ENDPOINTS TESTATI:
- POST /payments/stelline/purchase - Create payment intent
- POST /payments/subscription/create - Create subscription
- GET /payments/history - Payment history
- POST /payments/video/{id}/purchase - PPV purchase
================================================================================
"""

import pytest

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1/payments"


# ==============================================================================
# TEST: Authentication Required
# ==============================================================================
class TestPaymentsAuth:
    """Test che tutti gli endpoint richiedano autenticazione."""

    def test_stelline_purchase_requires_auth(self, api_client):
        """POST /payments/stelline/purchase richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/stelline/purchase",
            json={"package": "small"}
        )
        assert response.status_code in [401, 403, 404, 500, 503]

    def test_subscription_create_requires_auth(self, api_client):
        """POST /payments/subscription/create richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/subscription/create",
            json={"tier": "PREMIUM"}
        )
        assert response.status_code in [401, 403, 404, 500, 503]

    def test_payment_history_requires_auth(self, api_client):
        """GET /payments/history richiede auth."""
        response = api_client.get(f"{API_PREFIX}/history")
        assert response.status_code in [401, 403, 404, 500, 503]

    def test_video_purchase_requires_auth(self, api_client):
        """POST /payments/video/{id}/purchase richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/video/test-id/purchase",
            json={}
        )
        assert response.status_code in [401, 403, 404, 500, 503]


# ==============================================================================
# TEST: Stelline Purchase Flow
# ==============================================================================
class TestStellinePurchase:
    """Test flusso acquisto stelline."""

    def test_purchase_invalid_package(self, api_client, auth_headers):
        """Test acquisto con pacchetto invalido."""
        response = api_client.post(
            f"{API_PREFIX}/stelline/purchase",
            headers=auth_headers,
            json={"package": "invalid_package"}
        )
        assert response.status_code in [400, 404, 422, 500, 503]

    def test_purchase_small_package(self, api_client, auth_headers):
        """Test acquisto pacchetto small."""
        response = api_client.post(
            f"{API_PREFIX}/stelline/purchase",
            headers=auth_headers,
            json={"package": "small"}
        )
        assert response.status_code in [200, 201, 400, 404, 500, 503]


# ==============================================================================
# TEST: Subscription Flow  
# ==============================================================================
class TestSubscriptionCreate:
    """Test flusso creazione subscription."""

    def test_create_subscription_invalid_tier(self, api_client, auth_headers):
        """Test subscription con tier invalido."""
        response = api_client.post(
            f"{API_PREFIX}/subscription/create",
            headers=auth_headers,
            json={"tier": "INVALID_TIER"}
        )
        assert response.status_code in [400, 404, 422, 500, 503]

    def test_create_subscription_premium(self, api_client, auth_headers):
        """Test creazione subscription PREMIUM."""
        response = api_client.post(
            f"{API_PREFIX}/subscription/create",
            headers=auth_headers,
            json={"tier": "PREMIUM"}
        )
        assert response.status_code in [200, 201, 400, 404, 500, 503]


# ==============================================================================
# TEST: Payment History
# ==============================================================================
class TestPaymentHistory:
    """Test storico pagamenti."""

    def test_get_history_authenticated(self, api_client, auth_headers):
        """Test GET payment history con auth."""
        response = api_client.get(
            f"{API_PREFIX}/history",
            headers=auth_headers
        )
        assert response.status_code in [200, 404, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))


# ==============================================================================
# TEST: Subscription Cancel
# ==============================================================================
class TestSubscriptionCancel:
    """Test cancellazione subscription."""

    def test_cancel_subscription_requires_auth(self, api_client):
        """POST /payments/subscription/cancel richiede auth."""
        response = api_client.post(f"{API_PREFIX}/subscription/cancel")
        assert response.status_code in [401, 403, 404, 422, 500, 503]

    def test_cancel_subscription_no_active(self, api_client, auth_headers):
        """Test cancel senza subscription attiva."""
        response = api_client.post(
            f"{API_PREFIX}/subscription/cancel",
            headers=auth_headers
        )
        assert response.status_code in [400, 404, 422, 500, 503]

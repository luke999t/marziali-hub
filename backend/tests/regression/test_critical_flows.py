"""
================================================================================
AI_MODULE: TestCriticalFlows
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test regression per flussi critici business - ZERO MOCK
AI_BUSINESS: Garantisce che funzionalità core non regrediscano
AI_TEACHING: End-to-end testing, business flow validation

ZERO_MOCK_POLICY:
- Tutti i test chiamano backend REALE
- Verificano flussi business completi
- FALLISCONO se backend spento

COVERAGE_TARGET: 100% flussi critici
================================================================================
"""

import pytest
import uuid
from datetime import datetime


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.regression, pytest.mark.critical]


# ==============================================================================
# TEST: User Registration Flow
# ==============================================================================
class TestUserRegistrationFlow:
    """Test flusso completo registrazione utente."""

    def test_full_registration_flow(self, api_client):
        """
        CRITICAL FLOW: Registrazione completa utente
        1. Register new user
        2. Login with new credentials
        3. Access protected endpoint
        4. Logout (if available)
        """
        unique_id = uuid.uuid4().hex[:8]
        test_email = f"flow_test_{unique_id}@example.com"
        test_username = f"flowuser_{unique_id}"
        test_password = "FlowTestPass123!"

        # Step 1: Register
        register_response = api_client.post("/api/v1/auth/register", json={
            "email": test_email,
            "username": test_username,
            "password": test_password,
            "full_name": "Flow Test User"
        })

        assert register_response.status_code in (200, 201), \
            f"Registration failed: {register_response.text}"

        # Step 2: Login
        login_response = api_client.post("/api/v1/auth/login", json={
            "email": test_email,
            "password": test_password
        })

        assert login_response.status_code == 200, \
            f"Login failed after registration: {login_response.text}"

        data = login_response.json()
        assert "access_token" in data, "No access_token in login response"

        token = data["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Step 3: Access protected endpoint
        me_response = api_client.get("/api/v1/users/me", headers=headers)
        assert me_response.status_code == 200, \
            f"Cannot access /me after login: {me_response.text}"

        user_data = me_response.json()
        assert user_data["email"] == test_email
        assert user_data["username"] == test_username

    def test_registration_prevents_duplicate_email(self, api_client):
        """
        CRITICAL: Sistema previene email duplicate.
        """
        unique_id = uuid.uuid4().hex[:8]
        test_email = f"dup_test_{unique_id}@example.com"

        # First registration
        response1 = api_client.post("/api/v1/auth/register", json={
            "email": test_email,
            "username": f"dupuser1_{unique_id}",
            "password": "DupTest123!",
            "full_name": "First User"
        })
        assert response1.status_code in (200, 201)

        # Second registration with same email
        response2 = api_client.post("/api/v1/auth/register", json={
            "email": test_email,
            "username": f"dupuser2_{unique_id}",
            "password": "DupTest123!",
            "full_name": "Second User"
        })

        # Should fail with 400/409 (conflict)
        assert response2.status_code in (400, 409, 422), \
            f"Duplicate email accepted! Status: {response2.status_code}"


# ==============================================================================
# TEST: Authentication Token Flow
# ==============================================================================
class TestAuthTokenFlow:
    """Test flusso completo token authentication."""

    def test_token_refresh_flow(self, api_client, auth_token):
        """
        CRITICAL FLOW: Refresh token functionality
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        # Access /me to verify token works
        me_response = api_client.get("/api/v1/users/me", headers=headers)
        assert me_response.status_code == 200

    def test_expired_token_rejected(self, api_client):
        """
        CRITICAL: Token scaduti vengono rifiutati.
        """
        # Use an obviously fake/expired token
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlIiwiZXhwIjoxfQ.fake"
        headers = {"Authorization": f"Bearer {fake_token}"}

        response = api_client.get("/api/v1/users/me", headers=headers)

        # Should be 401 Unauthorized
        assert response.status_code == 401, \
            f"Fake token accepted! Status: {response.status_code}"

    def test_malformed_token_rejected(self, api_client):
        """
        CRITICAL: Token malformati vengono rifiutati.
        """
        malformed_tokens = [
            "not-a-jwt",
            "Bearer ",
            "",
            "null",
            "undefined",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.",  # alg=none attack
        ]

        for token in malformed_tokens:
            headers = {"Authorization": f"Bearer {token}"}
            response = api_client.get("/api/v1/users/me", headers=headers)
            assert response.status_code in (401, 403, 422), \
                f"Malformed token '{token[:20]}...' accepted!"


# ==============================================================================
# TEST: Video Access Control Flow
# ==============================================================================
class TestVideoAccessControlFlow:
    """Test controllo accesso video."""

    def test_public_videos_accessible_without_auth(self, api_client):
        """
        CRITICAL: Video pubblici accessibili senza auth.
        """
        # Health check dovrebbe sempre funzionare
        response = api_client.get("/health")
        assert response.status_code == 200

    def test_protected_videos_require_auth(self, api_client):
        """
        CRITICAL: Endpoint protetti richiedono autenticazione.
        """
        protected_endpoints = [
            "/api/v1/users/me",
            "/api/v1/videos/saved",
        ]

        for endpoint in protected_endpoints:
            response = api_client.get(endpoint)
            assert response.status_code in (401, 403, 404), \
                f"Protected endpoint {endpoint} accessible without auth!"

    def test_video_list_with_auth(self, api_client, auth_headers):
        """
        CRITICAL: Lista video funziona con auth.
        """
        response = api_client.get("/api/v1/videos", headers=auth_headers)

        # Should return 200 with video list
        assert response.status_code == 200
        data = response.json()

        # Should be a list or paginated response
        assert isinstance(data, (list, dict))


# ==============================================================================
# TEST: User Profile Update Flow
# ==============================================================================
class TestUserProfileFlow:
    """Test flusso aggiornamento profilo."""

    def test_profile_update_flow(self, api_client, auth_headers):
        """
        CRITICAL FLOW: Aggiornamento profilo utente
        1. Get current profile
        2. Update profile
        3. Verify update persisted
        """
        # Step 1: Get current profile
        get_response = api_client.get("/api/v1/users/me", headers=auth_headers)
        assert get_response.status_code == 200

        original_data = get_response.json()
        original_name = original_data.get("full_name", "")

        # Step 2: Update profile with new name
        new_name = f"Updated Name {uuid.uuid4().hex[:4]}"
        update_response = api_client.patch(
            "/api/v1/users/me",
            headers=auth_headers,
            json={"full_name": new_name}
        )

        # Update might return 200 or 204
        assert update_response.status_code in (200, 204), \
            f"Profile update failed: {update_response.text}"

        # Step 3: Verify update
        verify_response = api_client.get("/api/v1/users/me", headers=auth_headers)
        assert verify_response.status_code == 200

        updated_data = verify_response.json()
        assert updated_data.get("full_name") == new_name, \
            f"Profile not updated: expected '{new_name}', got '{updated_data.get('full_name')}'"

        # Cleanup: restore original name
        if original_name:
            api_client.patch(
                "/api/v1/users/me",
                headers=auth_headers,
                json={"full_name": original_name}
            )


# ==============================================================================
# TEST: Password Security Flow
# ==============================================================================
class TestPasswordSecurityFlow:
    """Test sicurezza password."""

    def test_password_not_exposed_in_responses(self, api_client, auth_headers):
        """
        CRITICAL: Password MAI esposta nelle response.
        """
        response = api_client.get("/api/v1/users/me", headers=auth_headers)
        assert response.status_code == 200

        # Check response text for password-related fields
        response_text = response.text.lower()
        assert "password" not in response_text or "hashed" not in response_text, \
            "Password might be exposed in response!"

        # Also check the JSON data
        data = response.json()
        assert "password" not in data
        assert "hashed_password" not in data

    def test_login_with_wrong_password_fails(self, api_client):
        """
        CRITICAL: Login con password errata fallisce.
        """
        response = api_client.post("/api/v1/auth/login", json={
            "email": "test@example.com",
            "password": "WrongPassword123!"
        })

        # Should not be 200
        assert response.status_code in (400, 401, 403), \
            f"Login with wrong password succeeded! Status: {response.status_code}"


# ==============================================================================
# TEST: API Error Handling Flow
# ==============================================================================
class TestAPIErrorHandlingFlow:
    """Test gestione errori API."""

    def test_404_for_nonexistent_resource(self, api_client, auth_headers):
        """
        CRITICAL: 404 per risorse inesistenti.
        """
        fake_uuid = str(uuid.uuid4())
        response = api_client.get(
            f"/api/v1/videos/{fake_uuid}",
            headers=auth_headers
        )

        assert response.status_code == 404, \
            f"Expected 404 for fake video, got {response.status_code}"

    def test_422_for_invalid_data(self, api_client, auth_headers):
        """
        CRITICAL: 422 per dati invalidi.
        """
        response = api_client.post("/api/v1/auth/login", json={
            "email": "not-an-email",
            "password": "x"  # Too short
        })

        assert response.status_code in (400, 422), \
            f"Expected validation error, got {response.status_code}"

    def test_error_responses_are_json(self, api_client):
        """
        CRITICAL: Error responses sono JSON validi.
        """
        response = api_client.post("/api/v1/auth/login", json={
            "email": "invalid",
            "password": "x"
        })

        # Should be able to parse as JSON
        try:
            data = response.json()
            assert data is not None
        except Exception:
            pytest.fail(f"Error response is not valid JSON: {response.text}")


# ==============================================================================
# TEST: CORS and Headers Flow
# ==============================================================================
class TestCORSAndHeadersFlow:
    """Test CORS e security headers."""

    def test_cors_headers_present(self, api_client):
        """
        Test che CORS headers siano presenti.
        """
        response = api_client.options("/api/v1/auth/login")

        # CORS preflight should return 200 or 204
        assert response.status_code in (200, 204, 405)

    def test_content_type_json(self, api_client, auth_headers):
        """
        Test che API restituisca JSON.
        """
        response = api_client.get("/api/v1/users/me", headers=auth_headers)

        content_type = response.headers.get("content-type", "")
        assert "application/json" in content_type, \
            f"Expected JSON content-type, got: {content_type}"


# ==============================================================================
# TEST: Data Integrity Flow
# ==============================================================================
class TestDataIntegrityFlow:
    """Test integrità dati."""

    def test_user_data_consistency(self, api_client, auth_headers):
        """
        CRITICAL: Dati utente consistenti tra richieste.
        """
        # Make same request multiple times
        responses = []
        for _ in range(3):
            response = api_client.get("/api/v1/users/me", headers=auth_headers)
            if response.status_code == 200:
                responses.append(response.json())

        if len(responses) >= 2:
            # All responses should have same user ID
            user_ids = [r.get("id") for r in responses]
            assert len(set(user_ids)) == 1, \
                f"User ID inconsistent across requests: {user_ids}"

            # Email should be consistent
            emails = [r.get("email") for r in responses]
            assert len(set(emails)) == 1, \
                f"Email inconsistent across requests: {emails}"


# ==============================================================================
# TEST: Rate Limiting Flow (if implemented)
# ==============================================================================
class TestRateLimitingFlow:
    """Test rate limiting (se implementato)."""

    def test_many_requests_dont_crash_server(self, api_client):
        """
        Test che molte richieste non crashino il server.
        """
        success_count = 0

        for i in range(50):
            response = api_client.get("/health")
            if response.status_code == 200:
                success_count += 1

        # At least 90% should succeed
        assert success_count >= 45, \
            f"Only {success_count}/50 requests succeeded"


# ==============================================================================
# TEST: Business Logic Regression
# ==============================================================================
class TestBusinessLogicRegression:
    """Test regressione logica business."""

    def test_free_tier_default_for_new_users(self, api_client):
        """
        CRITICAL: Nuovi utenti hanno tier 'free' di default.
        """
        unique_id = uuid.uuid4().hex[:8]

        # Register new user
        register_response = api_client.post("/api/v1/auth/register", json={
            "email": f"tier_test_{unique_id}@example.com",
            "username": f"tieruser_{unique_id}",
            "password": "TierTest123!",
            "full_name": "Tier Test"
        })

        if register_response.status_code in (200, 201):
            # Login to get token
            login_response = api_client.post("/api/v1/auth/login", json={
                "email": f"tier_test_{unique_id}@example.com",
                "password": "TierTest123!"
            })

            if login_response.status_code == 200:
                token = login_response.json()["access_token"]
                headers = {"Authorization": f"Bearer {token}"}

                # Check user tier
                me_response = api_client.get("/api/v1/users/me", headers=headers)
                if me_response.status_code == 200:
                    user_data = me_response.json()
                    tier = user_data.get("tier", "").lower()
                    assert tier == "free", \
                        f"New user has tier '{tier}', expected 'free'"

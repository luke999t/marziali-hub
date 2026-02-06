"""
================================================================================
    Test Suite: Avatar API Endpoints
================================================================================

AI_MODULE: test_avatars
AI_DESCRIPTION: Test completi per API Avatar con ZERO MOCK policy
AI_BUSINESS: Verifica funzionalita avatar 3D system
AI_TESTING: ZERO MOCK - Tutti i test chiamano backend reale su localhost:8000

ENDPOINTS TESTATI:
  1. GET /api/v1/avatars/ - Lista avatar
  2. GET /api/v1/avatars/{id} - Dettaglio avatar
  3. GET /api/v1/avatars/{id}/file - Download GLB file
  4. GET /api/v1/avatars/bone-mapping - Get MediaPipe bone mapping
  5. GET /api/v1/avatars/styles - Get available styles
  6. POST /api/v1/avatars/{id}/apply-skeleton - Apply skeleton (auth)
  7. POST /api/v1/avatars/ - Create avatar (admin only)
  8. PUT /api/v1/avatars/{id} - Update avatar (admin only)
  9. DELETE /api/v1/avatars/{id} - Soft delete (admin only)

TARGET: 15+ test, 95% pass rate

================================================================================
"""

import pytest


# ============================================================================
# Constants
# ============================================================================

API_PREFIX = "/api/v1/avatars"


# ============================================================================
# Test: GET /api/v1/avatars/ - List Avatars
# ============================================================================

class TestListAvatars:
    """Test suite for GET /api/v1/avatars/ endpoint."""

    def test_list_avatars_public_access(self, api_client):
        """Test that avatar list is publicly accessible without auth."""
        response = api_client.get(f"{API_PREFIX}/")

        assert response.status_code == 200
        data = response.json()
        assert "avatars" in data
        assert "total" in data
        assert isinstance(data["avatars"], list)

    def test_list_avatars_returns_seeded_avatars(self, api_client):
        """Test that seed avatars are present in list."""
        response = api_client.get(f"{API_PREFIX}/")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 2  # At least the 2 seeded avatars

        # Check for expected avatar names
        names = [a["name"] for a in data["avatars"]]
        assert "Male Martial Artist" in names or "Female Martial Artist" in names

    def test_list_avatars_returns_expected_fields(self, api_client):
        """Test that each avatar in list has expected fields."""
        response = api_client.get(f"{API_PREFIX}/")

        assert response.status_code == 200
        data = response.json()

        if len(data["avatars"]) > 0:
            avatar = data["avatars"][0]
            # Check required fields
            assert "id" in avatar
            assert "name" in avatar
            assert "style" in avatar
            assert "model_url" in avatar
            assert "is_public" in avatar

    def test_list_avatars_filter_by_style(self, api_client):
        """Test filtering avatars by style."""
        response = api_client.get(f"{API_PREFIX}/?style=generic")

        assert response.status_code == 200
        data = response.json()

        # All returned avatars should have the filtered style
        for avatar in data["avatars"]:
            assert avatar["style"] == "generic"

    def test_list_avatars_pagination(self, api_client):
        """Test pagination with page and page_size parameters."""
        response = api_client.get(f"{API_PREFIX}/?page=1&page_size=1")

        assert response.status_code == 200
        data = response.json()
        assert len(data["avatars"]) <= 1
        assert data["page"] == 1
        assert data["page_size"] == 1


# ============================================================================
# Test: GET /api/v1/avatars/{id} - Get Avatar Detail
# ============================================================================

class TestGetAvatarDetail:
    """Test suite for GET /api/v1/avatars/{id} endpoint."""

    def test_get_avatar_detail_success(self, api_client):
        """Test getting avatar detail by ID."""
        # First get an avatar from list
        list_response = api_client.get(f"{API_PREFIX}/")
        assert list_response.status_code == 200
        avatars = list_response.json()["avatars"]
        assert len(avatars) > 0

        avatar_id = avatars[0]["id"]

        # Get detail
        response = api_client.get(f"{API_PREFIX}/{avatar_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == avatar_id
        assert "name" in data
        assert "description" in data
        assert "model_url" in data

    def test_get_avatar_detail_not_found(self, api_client):
        """Test getting non-existent avatar returns 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/{fake_uuid}")

        assert response.status_code == 404

    def test_get_avatar_detail_invalid_uuid(self, api_client):
        """Test getting avatar with invalid UUID format."""
        response = api_client.get(f"{API_PREFIX}/invalid-uuid")

        assert response.status_code == 400  # Bad request for invalid UUID

    def test_get_avatar_detail_public_access(self, api_client):
        """Test that avatar detail is publicly accessible without auth."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        # No auth headers - should still work
        response = api_client.get(f"{API_PREFIX}/{avatar_id}")
        assert response.status_code == 200


# ============================================================================
# Test: GET /api/v1/avatars/{id}/file - Download GLB File
# ============================================================================

class TestDownloadAvatarFile:
    """Test suite for GET /api/v1/avatars/{id}/file endpoint."""

    def test_download_avatar_file_success(self, api_client):
        """Test downloading avatar GLB file."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        response = api_client.get(f"{API_PREFIX}/{avatar_id}/file")

        assert response.status_code == 200
        # Check content type is GLB or octet-stream
        content_type = response.headers.get("content-type", "")
        assert "gltf-binary" in content_type or "octet-stream" in content_type

    def test_download_avatar_file_not_found(self, api_client):
        """Test downloading non-existent avatar file returns 404."""
        fake_uuid = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/{fake_uuid}/file")

        assert response.status_code == 404

    def test_download_avatar_file_has_content(self, api_client):
        """Test that downloaded file has content."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        response = api_client.get(f"{API_PREFIX}/{avatar_id}/file")

        assert response.status_code == 200
        # GLB files should have significant content
        assert len(response.content) > 1000  # At least 1KB


# ============================================================================
# Test: GET /api/v1/avatars/bone-mapping - Get Bone Mapping
# ============================================================================

class TestGetBoneMapping:
    """Test suite for GET /api/v1/avatars/bone-mapping endpoint."""

    def test_get_bone_mapping_success(self, api_client):
        """Test getting MediaPipe bone mapping."""
        response = api_client.get(f"{API_PREFIX}/bone-mapping")

        assert response.status_code == 200
        data = response.json()

        # Should return mapping structure
        assert isinstance(data, dict)

    def test_get_bone_mapping_public_access(self, api_client):
        """Test that bone mapping is publicly accessible."""
        # No auth headers
        response = api_client.get(f"{API_PREFIX}/bone-mapping")

        assert response.status_code == 200

    def test_get_bone_mapping_has_landmarks(self, api_client):
        """Test that bone mapping contains landmark information."""
        response = api_client.get(f"{API_PREFIX}/bone-mapping")

        assert response.status_code == 200
        data = response.json()

        # Verify it has some content (landmarks mapping)
        assert "landmark_to_bone" in data or "bones" in data or len(data) > 0


# ============================================================================
# Test: GET /api/v1/avatars/styles - Get Available Styles
# ============================================================================

class TestGetAvatarStyles:
    """Test suite for GET /api/v1/avatars/styles endpoint."""

    def test_get_avatar_styles_success(self, api_client):
        """Test getting available avatar styles."""
        response = api_client.get(f"{API_PREFIX}/styles")

        assert response.status_code == 200
        data = response.json()

        # Should return styles list
        assert "styles" in data
        assert isinstance(data["styles"], list)

    def test_get_avatar_styles_public_access(self, api_client):
        """Test that styles endpoint is publicly accessible."""
        # No auth headers
        response = api_client.get(f"{API_PREFIX}/styles")

        assert response.status_code == 200

    def test_get_avatar_styles_has_expected_fields(self, api_client):
        """Test that styles have expected structure."""
        response = api_client.get(f"{API_PREFIX}/styles")

        assert response.status_code == 200
        data = response.json()

        if len(data["styles"]) > 0:
            style = data["styles"][0]
            # Each style should have value and label
            assert "value" in style or "name" in style


# ============================================================================
# Test: POST /api/v1/avatars/{id}/apply-skeleton - Apply Skeleton
# ============================================================================

class TestApplySkeleton:
    """Test suite for POST /api/v1/avatars/{id}/apply-skeleton endpoint."""

    def test_apply_skeleton_requires_auth(self, api_client):
        """Test that apply skeleton requires authentication."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        # Request without auth
        skeleton_data = {"skeleton_id": "test-skeleton-id"}
        response = api_client.post(
            f"{API_PREFIX}/{avatar_id}/apply-skeleton",
            json=skeleton_data
        )

        assert response.status_code in [401, 403]

    def test_apply_skeleton_with_auth(self, api_client, auth_headers):
        """Test apply skeleton with valid auth."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        skeleton_data = {
            "skeleton_id": "00000000-0000-0000-0000-000000000001",
            "frame_number": 0
        }
        response = api_client.post(
            f"{API_PREFIX}/{avatar_id}/apply-skeleton",
            json=skeleton_data,
            headers=auth_headers
        )

        # Could succeed or return 404 if skeleton doesn't exist
        assert response.status_code in [200, 404, 422]


# ============================================================================
# Test: Admin Only Endpoints - Auth Requirements
# ============================================================================

class TestAdminOnlyEndpoints:
    """Test suite for admin-only endpoints auth requirements."""

    def test_create_avatar_requires_admin(self, api_client, auth_headers):
        """Test that non-admin user cannot create avatar."""
        data = {"name": "Test Avatar", "style": "generic"}

        # Using regular user auth - should be forbidden
        response = api_client.post(
            f"{API_PREFIX}/",
            data=data,
            headers=auth_headers
        )

        assert response.status_code in [401, 403, 422]

    def test_update_avatar_requires_admin(self, api_client, auth_headers):
        """Test that non-admin user cannot update avatar."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        update_data = {"name": "Updated Name"}
        response = api_client.put(
            f"{API_PREFIX}/{avatar_id}",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code in [401, 403]

    def test_delete_avatar_requires_admin(self, api_client, auth_headers):
        """Test that non-admin user cannot delete avatar."""
        # Get first avatar
        list_response = api_client.get(f"{API_PREFIX}/")
        avatars = list_response.json()["avatars"]
        if len(avatars) == 0:
            pytest.skip("No avatars in database")

        avatar_id = avatars[0]["id"]

        response = api_client.delete(
            f"{API_PREFIX}/{avatar_id}",
            headers=auth_headers
        )

        assert response.status_code in [401, 403]

    def test_create_avatar_no_auth_forbidden(self, api_client):
        """Test that unauthenticated request cannot create avatar."""
        data = {"name": "No Auth Avatar"}
        response = api_client.post(
            f"{API_PREFIX}/",
            data=data
        )

        assert response.status_code in [401, 403, 422]


# ============================================================================
# Test: Validation and Edge Cases
# ============================================================================

class TestValidationAndEdgeCases:
    """Test validation and edge cases."""

    def test_invalid_style_filter(self, api_client):
        """Test filtering with non-existent style."""
        response = api_client.get(f"{API_PREFIX}/?style=nonexistent_style")

        assert response.status_code == 200
        data = response.json()
        # Should return empty list
        assert data["total"] == 0 or len(data["avatars"]) == 0

    def test_pagination_beyond_results(self, api_client):
        """Test pagination with page beyond available results."""
        response = api_client.get(f"{API_PREFIX}/?page=999&page_size=10")

        assert response.status_code == 200
        data = response.json()
        # Should return empty avatars list
        assert len(data["avatars"]) == 0

    def test_invalid_page_size(self, api_client):
        """Test pagination with invalid page_size."""
        # page_size > 100 should be rejected or capped
        response = api_client.get(f"{API_PREFIX}/?page_size=200")

        # Either 422 validation error or capped to max
        assert response.status_code in [200, 422]

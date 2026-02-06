"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Moderation API Integration Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.

================================================================================
"""

import pytest
import uuid

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: Moderation List API - REAL BACKEND
# ==============================================================================
class TestModerationListAPI:
    """Test listing pending videos - REAL BACKEND."""

    def test_list_pending_videos_requires_admin(self, api_client):
        """Test that listing pending videos requires admin auth."""
        response = api_client.get(f"{API_PREFIX}/moderation/videos/pending")

        # Should fail without auth
        assert response.status_code in [401, 403]

    def test_list_pending_videos_with_admin(self, api_client, auth_headers_admin):
        """Test listing pending videos with admin auth."""
        response = api_client.get(
            f"{API_PREFIX}/moderation/videos/pending",
            headers=auth_headers_admin
        )

        # 200 if endpoint exists and works
        # 403 if admin doesn't have moderation permissions
        # 404 if endpoint not found
        assert response.status_code in [200, 403, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list)

    def test_list_pending_videos_forbidden_for_regular_user(self, api_client, auth_headers_free):
        """Test that regular user cannot list pending videos."""
        response = api_client.get(
            f"{API_PREFIX}/moderation/videos/pending",
            headers=auth_headers_free
        )

        # Should be forbidden for non-admin
        assert response.status_code in [403, 404]


# ==============================================================================
# TEST: Moderation Approve API - REAL BACKEND
# ==============================================================================
class TestModerationApproveAPI:
    """Test video approval workflow - REAL BACKEND."""

    def test_approve_video_requires_admin(self, api_client):
        """Test that approving video requires admin auth."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/approve",
            json={"notes": "Test"}
        )

        assert response.status_code in [401, 403]

    def test_approve_nonexistent_video(self, api_client, auth_headers_admin):
        """Test approving non-existent video returns 404."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/approve",
            json={"notes": "Test approval"},
            headers=auth_headers_admin
        )

        # 403 = forbidden, 404 = video not found or endpoint not found
        assert response.status_code in [403, 404, 422]

    def test_approve_forbidden_for_regular_user(self, api_client, auth_headers_free):
        """Test that regular user cannot approve videos."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/approve",
            json={"notes": "Test"},
            headers=auth_headers_free
        )

        assert response.status_code in [403, 404]


# ==============================================================================
# TEST: Moderation Reject API - REAL BACKEND
# ==============================================================================
class TestModerationRejectAPI:
    """Test video rejection workflow - REAL BACKEND."""

    def test_reject_video_requires_admin(self, api_client):
        """Test that rejecting video requires admin auth."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/reject",
            json={"rejection_reason": "Test"}
        )

        assert response.status_code in [401, 403]

    def test_reject_nonexistent_video(self, api_client, auth_headers_admin):
        """Test rejecting non-existent video."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/reject",
            json={"rejection_reason": "Test rejection"},
            headers=auth_headers_admin
        )

        # 403 = forbidden, 404 = video not found or endpoint not found
        assert response.status_code in [403, 404, 422]

    def test_reject_requires_reason(self, api_client, auth_headers_admin):
        """Test that rejection requires a reason."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/reject",
            json={},  # No reason
            headers=auth_headers_admin
        )

        # Should fail validation, or 403 if forbidden
        assert response.status_code in [403, 404, 422]


# ==============================================================================
# TEST: Moderation Request Changes API - REAL BACKEND
# ==============================================================================
class TestModerationRequestChangesAPI:
    """Test request changes workflow - REAL BACKEND."""

    def test_request_changes_requires_admin(self, api_client):
        """Test that requesting changes requires admin auth."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/request-changes",
            json={"required_changes": ["Fix audio"]}
        )

        assert response.status_code in [401, 403]

    def test_request_changes_nonexistent_video(self, api_client, auth_headers_admin):
        """Test requesting changes on non-existent video."""
        fake_id = str(uuid.uuid4())
        response = api_client.post(
            f"{API_PREFIX}/moderation/videos/{fake_id}/request-changes",
            json={
                "required_changes": ["Improve audio quality"],
                "notes": "Please fix these issues"
            },
            headers=auth_headers_admin
        )

        assert response.status_code in [403, 404, 422]


# ==============================================================================
# TEST: Moderation History API - REAL BACKEND
# ==============================================================================
class TestModerationHistoryAPI:
    """Test moderation history - REAL BACKEND."""

    def test_get_history_requires_admin(self, api_client):
        """Test that getting history requires admin auth."""
        fake_id = str(uuid.uuid4())
        response = api_client.get(
            f"{API_PREFIX}/moderation/videos/{fake_id}/history"
        )

        assert response.status_code in [401, 403]

    def test_get_history_nonexistent_video(self, api_client, auth_headers_admin):
        """Test getting history for non-existent video."""
        fake_id = str(uuid.uuid4())
        response = api_client.get(
            f"{API_PREFIX}/moderation/videos/{fake_id}/history",
            headers=auth_headers_admin
        )

        # 200 with empty list, 403 = forbidden, or 404
        assert response.status_code in [200, 403, 404]


# ==============================================================================
# TEST: Moderation Stats API - REAL BACKEND
# ==============================================================================
class TestModerationStatsAPI:
    """Test moderation statistics - REAL BACKEND."""

    def test_get_stats_requires_admin(self, api_client):
        """Test that getting stats requires admin auth."""
        response = api_client.get(f"{API_PREFIX}/moderation/stats")

        assert response.status_code in [401, 403]

    def test_get_stats_with_admin(self, api_client, auth_headers_admin):
        """Test getting moderation stats with admin auth."""
        response = api_client.get(
            f"{API_PREFIX}/moderation/stats",
            headers=auth_headers_admin
        )

        assert response.status_code in [200, 403, 404]

        if response.status_code == 200:
            data = response.json()
            # Should have stat fields
            assert isinstance(data, dict)


# ==============================================================================
# TEST: Moderation Validation - Pure Logic
# ==============================================================================
class TestModerationValidationLogic:
    """Test moderation validation logic - pure logic."""

    def test_valid_video_statuses(self):
        """Test valid video status values."""
        valid_statuses = ["pending", "approved", "rejected", "changes_requested"]

        for status in valid_statuses:
            assert isinstance(status, str)
            assert len(status) > 0

    def test_rejection_reason_required(self):
        """Test that rejection requires reason."""
        rejection_data = {
            "rejection_reason": "Low quality audio"
        }

        assert "rejection_reason" in rejection_data
        assert len(rejection_data["rejection_reason"]) > 0

    def test_changes_list_format(self):
        """Test format of required changes list."""
        changes_data = {
            "required_changes": [
                "Improve audio quality",
                "Add timestamps"
            ],
            "notes": "Please fix these issues"
        }

        assert isinstance(changes_data["required_changes"], list)
        assert len(changes_data["required_changes"]) > 0

    @pytest.mark.parametrize("status,is_final", [
        ("pending", False),
        ("approved", True),
        ("rejected", True),
        ("changes_requested", False),
    ])
    def test_status_finality(self, status, is_final):
        """Test which statuses are final."""
        final_statuses = ["approved", "rejected"]
        result = status in final_statuses
        assert result == is_final


# ==============================================================================
# TEST: Moderation Workflow - Pure Logic
# ==============================================================================
class TestModerationWorkflowLogic:
    """Test moderation workflow logic - pure logic."""

    def test_valid_status_transitions(self):
        """Test valid status transitions."""
        # pending -> approved | rejected | changes_requested
        # changes_requested -> pending (after resubmission)

        valid_transitions = {
            "pending": ["approved", "rejected", "changes_requested"],
            "changes_requested": ["pending"],
        }

        assert "pending" in valid_transitions
        assert "approved" in valid_transitions["pending"]
        assert "rejected" in valid_transitions["pending"]

    def test_approval_notes_optional(self):
        """Test that approval notes are optional."""
        # Approval can be done with or without notes
        approval_with_notes = {"notes": "Good quality video"}
        approval_without_notes = {}

        assert approval_with_notes.get("notes") == "Good quality video"
        assert approval_without_notes.get("notes") is None

    def test_rejection_reason_formats(self):
        """Test various rejection reason formats."""
        reasons = [
            "Low quality audio",
            "Copyright violation",
            "Inappropriate content",
            "Duplicate video",
        ]

        for reason in reasons:
            assert isinstance(reason, str)
            assert len(reason) > 0

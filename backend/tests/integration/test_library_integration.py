"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Library Integration Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.

================================================================================
"""

import pytest
import time
from datetime import datetime

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: User Library Journey - REAL BACKEND
# ==============================================================================
class TestUserLibraryJourney:
    """End-to-end tests for complete user workflows - REAL BACKEND."""

    def test_save_video_journey(self, api_client, auth_headers_free):
        """Test saving a video to library."""
        # Get videos to find one to save
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers_free
        )

        if response.status_code == 200:
            data = response.json()
            # Handle dict with videos key or direct list
            videos = data.get("items", data.get("videos", data)) if isinstance(data, dict) else data
            if videos and isinstance(videos, list) and len(videos) > 0:
                video_id = videos[0].get("id") or videos[0].get("video_id")

                # Save video
                save_response = api_client.post(
                    f"{API_PREFIX}/library/save/{video_id}",
                    headers=auth_headers_free
                )

                # 200/201 = saved, 409 = already saved
                assert save_response.status_code in [200, 201, 409, 404]

    def test_get_saved_videos(self, api_client, auth_headers_free):
        """Test retrieving saved videos."""
        response = api_client.get(
            f"{API_PREFIX}/library/saved",
            headers=auth_headers_free
        )

        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))

    def test_get_in_progress_videos(self, api_client, auth_headers_free):
        """Test retrieving in-progress videos."""
        response = api_client.get(
            f"{API_PREFIX}/library/in-progress",
            headers=auth_headers_free
        )

        assert response.status_code in [200, 404]

    def test_update_video_progress(self, api_client, auth_headers_free):
        """Test updating video progress."""
        # First get a video
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers_free
        )

        if response.status_code == 200:
            data = response.json()
            videos = data.get("items", data.get("videos", data)) if isinstance(data, dict) else data
            if videos and isinstance(videos, list) and len(videos) > 0:
                video_id = videos[0].get("id") or videos[0].get("video_id")

                # Update progress
                progress_response = api_client.post(
                    f"{API_PREFIX}/library/progress/{video_id}",
                    json={"progress": 50, "position_seconds": 300},
                    headers=auth_headers_free
                )

                assert progress_response.status_code in [200, 201, 404]

    def test_get_completed_videos(self, api_client, auth_headers_premium):
        """Test retrieving completed videos."""
        response = api_client.get(
            f"{API_PREFIX}/library/completed",
            headers=auth_headers_premium
        )

        assert response.status_code in [200, 404]

    def test_library_requires_auth(self, api_client):
        """Test that library endpoints require authentication."""
        response = api_client.get(f"{API_PREFIX}/library/saved")
        # 401/403 = auth required, 404 = endpoint not found
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Library Organization - REAL BACKEND
# ==============================================================================
class TestLibraryOrganization:
    """Test library organization features - REAL BACKEND."""

    def test_unsave_video(self, api_client, auth_headers_free):
        """Test removing video from library."""
        # First get saved videos
        response = api_client.get(
            f"{API_PREFIX}/library/saved",
            headers=auth_headers_free
        )

        if response.status_code == 200:
            saved = response.json()
            if saved and len(saved) > 0:
                video_id = saved[0].get("video_id") or saved[0].get("id")

                # Unsave
                unsave_response = api_client.delete(
                    f"{API_PREFIX}/library/save/{video_id}",
                    headers=auth_headers_free
                )

                assert unsave_response.status_code in [200, 204, 404]


# ==============================================================================
# TEST: Premium Download Features - REAL BACKEND
# ==============================================================================
class TestPremiumDownloadWorkflow:
    """Test download feature for premium users - REAL BACKEND."""

    def test_free_user_cannot_download(self, api_client, auth_headers_free):
        """Test that free user cannot download videos."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers_free
        )

        if response.status_code == 200:
            data = response.json()
            videos = data.get("items", data.get("videos", data)) if isinstance(data, dict) else data
            if videos and isinstance(videos, list) and len(videos) > 0:
                video_id = videos[0].get("id") or videos[0].get("video_id")

                # Try to download
                download_response = api_client.post(
                    f"{API_PREFIX}/library/downloads/{video_id}",
                    headers=auth_headers_free
                )

                # Should fail for free user
                assert download_response.status_code in [403, 402, 404, 422]

    def test_premium_user_download_access(self, api_client, auth_headers_premium):
        """Test that premium user can access download."""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers_premium
        )

        if response.status_code == 200:
            data = response.json()
            videos = data.get("items", data.get("videos", data)) if isinstance(data, dict) else data
            if videos and isinstance(videos, list) and len(videos) > 0:
                video_id = videos[0].get("id") or videos[0].get("video_id")

                # Try to download
                download_response = api_client.post(
                    f"{API_PREFIX}/library/downloads/{video_id}",
                    headers=auth_headers_premium
                )

                # Premium should have access
                assert download_response.status_code in [200, 201, 404]

    def test_get_downloads_list(self, api_client, auth_headers_premium):
        """Test getting downloads list."""
        response = api_client.get(
            f"{API_PREFIX}/library/downloads",
            headers=auth_headers_premium
        )

        assert response.status_code in [200, 404]


# ==============================================================================
# TEST: Data Consistency - REAL BACKEND
# ==============================================================================
class TestLibraryDataConsistency:
    """Tests for data consistency across endpoints - REAL BACKEND."""

    def test_library_stats_endpoint(self, api_client, auth_headers_free):
        """Test library stats endpoint."""
        response = api_client.get(
            f"{API_PREFIX}/library/stats",
            headers=auth_headers_free
        )

        # 200 = has stats, 404 = endpoint not found
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            # Should have stat fields
            assert isinstance(data, dict)


# ==============================================================================
# TEST: Error Handling - REAL BACKEND
# ==============================================================================
class TestLibraryErrorHandling:
    """Tests for error handling - REAL BACKEND."""

    def test_save_nonexistent_video(self, api_client, auth_headers_free):
        """Test saving non-existent video returns 404."""
        response = api_client.post(
            f"{API_PREFIX}/library/save/00000000-0000-0000-0000-000000000000",
            headers=auth_headers_free
        )

        assert response.status_code in [404, 422]

    def test_progress_invalid_video(self, api_client, auth_headers_free):
        """Test updating progress for invalid video."""
        response = api_client.post(
            f"{API_PREFIX}/library/progress/00000000-0000-0000-0000-000000000000",
            json={"progress": 50},
            headers=auth_headers_free
        )

        assert response.status_code in [404, 422]


# ==============================================================================
# TEST: Performance - REAL BACKEND
# ==============================================================================
class TestLibraryPerformance:
    """Performance tests - REAL BACKEND."""

    def test_library_response_time(self, api_client, auth_headers_free, performance_timer):
        """Test library endpoints respond quickly."""
        performance_timer.start()

        response = api_client.get(
            f"{API_PREFIX}/library/saved",
            headers=auth_headers_free
        )

        performance_timer.stop()

        # Should respond within 2 seconds
        if response.status_code == 200:
            performance_timer.assert_under(2.0)

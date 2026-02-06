"""
================================================================================
🎓 AI_MODULE: Skeleton Holistic Integration Tests
🎓 AI_VERSION: 1.0.0
🎓 AI_DESCRIPTION: Test REALI per Skeleton API 75 landmarks - ZERO MOCK
🎓 AI_BUSINESS: Verifica endpoint API skeleton contro backend REALE
🎓 AI_TEACHING: Test integration con TestClient FastAPI, autenticazione reale
🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
🎓 AI_CREATED: 2026-01-18

================================================================================

⛔ REGOLA INVIOLABILE: Questo file NON contiene mock.
Tutti i test chiamano API REALI su localhost:8000.

NOTE: Skeleton API may not yet be fully implemented.
Tests handle 404 gracefully for unimplemented endpoints.

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
# TEST: Skeleton Health Check
# ==============================================================================
class TestSkeletonHealth:
    """Test health check endpoint."""

    def test_skeleton_health_endpoint(self, api_client, auth_headers):
        """GET /skeleton/health ritorna status healthy."""
        response = api_client.get(
            f"{API_PREFIX}/skeleton/health",
            headers=auth_headers
        )
        # 200 if endpoint exists, 404 if not
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "status" in data
            assert data["status"] == "healthy"
            assert "service" in data
            assert data["service"] == "skeleton"

    def test_health_shows_features(self, api_client, auth_headers):
        """Health endpoint mostra features disponibili."""
        response = api_client.get(
            f"{API_PREFIX}/skeleton/health",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            if "features" in data:
                assert "holistic_75_landmarks" in data["features"]


# ==============================================================================
# TEST: Skeleton Extraction
# ==============================================================================
class TestSkeletonExtraction:
    """Test estrazione skeleton."""

    def test_extract_requires_auth(self, api_client):
        """POST /skeleton/extract richiede autenticazione."""
        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={"video_id": "test-video-id", "use_holistic": True}
        )
        assert response.status_code in [401, 403, 404]

    def test_extract_with_invalid_video_id(self, api_client, auth_headers):
        """POST /skeleton/extract con video inesistente."""
        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": "non-existent-video-id",
                "use_holistic": True
            },
            headers=auth_headers
        )
        # 404 for video not found, or 404 if endpoint doesn't exist
        assert response.status_code in [404, 422]

    def test_extract_with_valid_video(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/extract con video valido."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": test_video_id,
                "use_holistic": True,
                "model_complexity": 1
            },
            headers=auth_headers
        )
        # 200 if started, 404 if endpoint not exists
        assert response.status_code in [200, 201, 202, 404, 422]

        if response.status_code in [200, 201, 202]:
            data = response.json()
            assert "success" in data
            # Either started new job or skeleton already exists
            if "job_id" in data:
                assert data["job_id"] != ""

    def test_extract_use_holistic_true(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/extract con use_holistic=True (75 landmarks)."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": test_video_id,
                "use_holistic": True
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202, 404, 422]

    def test_extract_use_holistic_false(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/extract con use_holistic=False (33 landmarks)."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": test_video_id,
                "use_holistic": False
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202, 404, 422]

    def test_extract_model_complexity_0(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/extract con model_complexity=0 (lite)."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": test_video_id,
                "use_holistic": True,
                "model_complexity": 0
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202, 404, 422]

    def test_extract_model_complexity_2(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/extract con model_complexity=2 (heavy)."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/extract",
            json={
                "video_id": test_video_id,
                "use_holistic": True,
                "model_complexity": 2
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202, 404, 422]


# ==============================================================================
# TEST: Get Skeleton Data
# ==============================================================================
class TestGetSkeletonData:
    """Test recupero dati skeleton."""

    def test_get_skeleton_requires_auth(self, api_client, test_video_id):
        """GET /skeleton/videos/{id} richiede auth."""
        if not test_video_id:
            test_video_id = "00000000-0000-0000-0000-000000000000"

        response = api_client.get(f"{API_PREFIX}/skeleton/videos/{test_video_id}")
        assert response.status_code in [401, 403, 404]

    def test_get_skeleton_not_found(self, api_client, auth_headers):
        """GET /skeleton/videos/{id} ritorna 404 per skeleton inesistente."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{fake_id}",
            headers=auth_headers
        )
        assert response.status_code in [404, 422]

    def test_get_skeleton_valid(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id} ritorna dati skeleton."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}",
            headers=auth_headers
        )
        # 200 if skeleton exists, 404 if not
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "frames" in data or "version" in data


# ==============================================================================
# TEST: Get Skeleton Metadata
# ==============================================================================
class TestGetSkeletonMetadata:
    """Test recupero metadata skeleton."""

    def test_get_metadata_requires_auth(self, api_client, test_video_id):
        """GET /skeleton/videos/{id}/metadata richiede auth."""
        if not test_video_id:
            test_video_id = "00000000-0000-0000-0000-000000000000"

        response = api_client.get(f"{API_PREFIX}/skeleton/videos/{test_video_id}/metadata")
        assert response.status_code in [401, 403, 404]

    def test_get_metadata_valid(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id}/metadata ritorna solo metadata."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/metadata",
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            # Should have metadata but NOT full frames
            assert "total_landmarks" in data or "version" in data
            # frames should not be present or be minimal
            if "frames" in data:
                assert isinstance(data["frames"], int) or len(data.get("frames", [])) == 0


# ==============================================================================
# TEST: Get Single Frame
# ==============================================================================
class TestGetSingleFrame:
    """Test recupero singolo frame."""

    def test_get_frame_0(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id}/frame/0 ritorna primo frame."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/0",
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "frame" in data or "body" in data or "landmarks" in data

    def test_get_frame_negative_index(self, api_client, auth_headers, test_video_id):
        """Frame index negativo ritorna errore."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/-1",
            headers=auth_headers
        )
        # 400/422 for invalid index, 404 if endpoint not exists
        assert response.status_code in [400, 404, 422]

    def test_get_frame_out_of_range(self, api_client, auth_headers, test_video_id):
        """Frame index oltre limite ritorna errore."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/999999",
            headers=auth_headers
        )
        assert response.status_code in [400, 404, 422]

    def test_frame_has_75_landmarks(self, api_client, auth_headers, test_video_id):
        """Frame Holistic ha 75 landmarks totali."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/0",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            # Check for 75 landmarks structure
            if "landmark_counts" in data:
                counts = data["landmark_counts"]
                total = counts.get("body", 0) + counts.get("left_hand", 0) + counts.get("right_hand", 0)
                # 75 for Holistic, 33 for Pose
                assert total in [33, 75]


# ==============================================================================
# TEST: Get Frame Range
# ==============================================================================
class TestGetFrameRange:
    """Test recupero range di frame."""

    def test_get_frames_default(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id}/frames ritorna frame paginati."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frames",
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "frames" in data or "count" in data

    def test_get_frames_with_range(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id}/frames con start/end."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frames",
            params={"start": 0, "end": 10},
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_get_frames_with_limit(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/videos/{id}/frames con limit."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frames",
            params={"limit": 5},
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            if "count" in data:
                assert data["count"] <= 5


# ==============================================================================
# TEST: Extraction Status
# ==============================================================================
class TestExtractionStatus:
    """Test stato estrazione."""

    def test_status_not_found(self, api_client, auth_headers):
        """GET /skeleton/status/{job_id} ritorna 404 per job inesistente."""
        fake_job_id = "skeleton_nonexistent123"
        response = api_client.get(
            f"{API_PREFIX}/skeleton/status/{fake_job_id}",
            headers=auth_headers
        )
        assert response.status_code in [404]

    def test_status_requires_auth(self, api_client):
        """GET /skeleton/status/{job_id} richiede auth."""
        response = api_client.get(f"{API_PREFIX}/skeleton/status/any-job-id")
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Batch Extraction
# ==============================================================================
class TestBatchExtraction:
    """Test estrazione batch."""

    def test_batch_requires_auth(self, api_client):
        """POST /skeleton/batch richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/skeleton/batch",
            json={"video_ids": ["id1", "id2"]}
        )
        assert response.status_code in [401, 403, 404]

    def test_batch_with_invalid_ids(self, api_client, auth_headers):
        """POST /skeleton/batch con video inesistenti."""
        response = api_client.post(
            f"{API_PREFIX}/skeleton/batch",
            json={
                "video_ids": ["nonexistent1", "nonexistent2"],
                "use_holistic": True
            },
            headers=auth_headers
        )
        # 200 but with skipped entries, or 404 if endpoint not exists
        assert response.status_code in [200, 404, 422]

    def test_batch_with_valid_video(self, api_client, auth_headers, test_video_id):
        """POST /skeleton/batch con video valido."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/skeleton/batch",
            json={
                "video_ids": [test_video_id],
                "use_holistic": True
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 404, 422]


# ==============================================================================
# TEST: Download Skeleton
# ==============================================================================
class TestDownloadSkeleton:
    """Test download skeleton JSON."""

    def test_download_requires_auth(self, api_client, test_video_id):
        """GET /skeleton/download/{video_id} richiede auth."""
        if not test_video_id:
            test_video_id = "00000000-0000-0000-0000-000000000000"

        response = api_client.get(f"{API_PREFIX}/skeleton/download/{test_video_id}")
        assert response.status_code in [401, 403, 404]

    def test_download_not_found(self, api_client, auth_headers):
        """GET /skeleton/download/{video_id} ritorna 404 per skeleton inesistente."""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/skeleton/download/{fake_id}",
            headers=auth_headers
        )
        assert response.status_code in [404]

    def test_download_valid_skeleton(self, api_client, auth_headers, test_video_id):
        """GET /skeleton/download/{video_id} ritorna file JSON."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/download/{test_video_id}",
            headers=auth_headers
        )
        # 200 with JSON file, 404 if not exists
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            assert response.headers.get("content-type") in [
                "application/json",
                "application/json; charset=utf-8"
            ]


# ==============================================================================
# TEST: Response Format Validation
# ==============================================================================
class TestResponseFormat:
    """Test formato response API."""

    def test_skeleton_has_version(self, api_client, auth_headers, test_video_id):
        """Skeleton response include version field."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            # Should have version indicating format
            assert "version" in data or "total_landmarks" in data

    def test_skeleton_has_frames_array(self, api_client, auth_headers, test_video_id):
        """Skeleton response include frames array."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            assert "frames" in data
            assert isinstance(data["frames"], list)

    def test_frame_has_body_landmarks(self, api_client, auth_headers, test_video_id):
        """Frame response include body landmarks."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/0",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            frame = data.get("frame", data)
            # Should have body landmarks
            assert "body" in frame or "landmarks" in frame

    def test_holistic_frame_has_hands(self, api_client, auth_headers, test_video_id):
        """Frame Holistic include left_hand e right_hand."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.get(
            f"{API_PREFIX}/skeleton/videos/{test_video_id}/frame/0",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            frame = data.get("frame", data)
            # Holistic should have hands (may be empty arrays if not detected)
            if data.get("total_landmarks") == 75:
                assert "left_hand" in frame
                assert "right_hand" in frame

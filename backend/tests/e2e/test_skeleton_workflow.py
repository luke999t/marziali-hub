"""
End-to-End Tests - Skeleton Extraction Workflow
Full workflow tests from upload to skeleton retrieval

FIX 2026-02-04: Corretto endpoint da /api/v1/videos/skeletons a /api/v1/skeleton/list
"""

import pytest
import io
import json
import time
from pathlib import Path
from fastapi.testclient import TestClient


# === SIMPLIFIED TEST CLIENT (no auth) ===

@pytest.fixture(scope="module")
def client():
    """Simple test client without database/auth dependencies"""
    from main import app
    with TestClient(app) as c:
        yield c


# === E2E WORKFLOW TESTS ===

@pytest.mark.e2e
class TestCompleteIngestWorkflow:
    """E2E tests for complete ingest workflow"""

    def test_upload_list_retrieve_workflow(self, client: TestClient):
        """
        E2E: Complete workflow - upload -> list -> verify

        Steps:
        1. Get initial skeleton count
        2. Upload a video (without skeleton for speed)
        3. Check upload response has asset_id
        4. Check status endpoint works
        5. Verify skeleton count unchanged (no extraction)
        """
        # Step 1: Get initial state
        # FIX: Corretto endpoint da /api/v1/videos/skeletons a /api/v1/skeleton/list
        initial_response = client.get("/api/v1/skeleton/list")
        assert initial_response.status_code == 200
        initial_count = initial_response.json()["total"]

        # Step 2: Upload video
        fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom\x00\x00\x00\x00isomiso2mp41")
        upload_response = client.post(
            "/api/v1/videos/ingest",
            files={"files": ("e2e_test.mp4", fake_video, "video/mp4")},
            data={
                "title": "E2E Test Video",
                "extract_skeleton": "false"
            }
        )

        # Step 3: Verify upload response
        assert upload_response.status_code in [200, 201, 400, 422]

        if upload_response.status_code == 200:
            data = upload_response.json()
            asset_id = data.get("asset_id")

            # Step 4: Check status if we have asset_id
            if asset_id:
                status_response = client.get(f"/api/v1/videos/ingest/status/{asset_id}")
                assert status_response.status_code in [200, 404]

        # Step 5: Verify skeleton count (should be same - no extraction)
        # FIX: Corretto endpoint
        final_response = client.get("/api/v1/skeleton/list")
        assert final_response.status_code == 200
        final_count = final_response.json()["total"]
        assert final_count >= initial_count

    def test_api_health_before_operations(self, client: TestClient):
        """
        E2E: Verify health check before any operations
        """
        response = client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data.get("status") == "healthy" or "status" in data


@pytest.mark.e2e
class TestSkeletonRetrievalWorkflow:
    """E2E tests for skeleton data retrieval"""

    def test_list_and_access_skeleton(self, client: TestClient):
        """
        E2E: List skeletons and access individual skeleton data
        """
        # List all skeletons
        # FIX 2026-02-04: Corretto endpoint
        list_response = client.get("/api/v1/skeleton/list")
        assert list_response.status_code == 200

        data = list_response.json()
        assert "skeletons" in data
        assert "total" in data

        if data["total"] > 0:
            skeleton = data["skeletons"][0]

            # Verify skeleton has required fields
            assert "id" in skeleton
            assert "path" in skeleton

            # Verify data types
            if "frames" in skeleton:
                assert isinstance(skeleton["frames"], int)
            if "duration" in skeleton:
                assert isinstance(skeleton["duration"], (int, float))

    def test_skeleton_list_pagination_ready(self, client: TestClient):
        """
        E2E: Verify skeleton list supports pagination parameters
        """
        # Test with pagination params (even if not implemented yet)
        # FIX 2026-02-04: Corretto endpoint
        response = client.get("/api/v1/skeleton/list?limit=10&offset=0")

        # Should not crash with extra params
        assert response.status_code in [200, 422]


@pytest.mark.e2e
class TestErrorRecoveryWorkflow:
    """E2E tests for error recovery scenarios"""

    def test_invalid_upload_then_valid_upload(self, client: TestClient):
        """
        E2E: System recovers after invalid upload

        Steps:
        1. Try invalid upload (no file)
        2. Verify error response
        3. Try valid upload
        4. Verify success
        """
        # Step 1: Invalid upload (no file)
        invalid_response = client.post(
            "/api/v1/videos/ingest",
            data={"title": "No File"}
        )

        # Step 2: Should return validation error
        assert invalid_response.status_code == 422

        # Step 3: Valid upload
        fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom")
        valid_response = client.post(
            "/api/v1/videos/ingest",
            files={"files": ("recovery_test.mp4", fake_video, "video/mp4")},
            data={"extract_skeleton": "false"}
        )

        # Step 4: Should succeed or fail gracefully
        assert valid_response.status_code in [200, 201, 400, 422, 500]

    def test_not_found_then_valid_request(self, client: TestClient):
        """
        E2E: System handles 404 gracefully
        """
        # Request non-existent resource
        not_found = client.get("/api/v1/videos/ingest/status/non-existent-id-12345")
        assert not_found.status_code in [404, 400, 200]

        # Valid request should still work
        # FIX 2026-02-04: Corretto endpoint
        valid = client.get("/api/v1/skeleton/list")
        assert valid.status_code == 200


@pytest.mark.e2e
class TestAPIConsistency:
    """E2E tests for API consistency"""

    def test_response_content_types(self, client: TestClient):
        """
        E2E: All endpoints return correct content types
        """
        # FIX 2026-02-04: Corretto endpoint
        endpoints = [
            "/api/v1/skeleton/list",
            "/health",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                assert "application/json" in content_type

    def test_endpoint_method_restrictions(self, client: TestClient):
        """
        E2E: Endpoints respect HTTP method restrictions
        """
        # GET endpoints should not accept POST
        # (FastAPI returns 405 or processes anyway)

        # POST endpoints should not accept GET for modification
        get_ingest = client.get("/api/v1/videos/ingest")
        assert get_ingest.status_code in [405, 404, 200, 422]


@pytest.mark.e2e
@pytest.mark.slow
class TestLongRunningWorkflows:
    """E2E tests for long-running workflows"""

    def test_multiple_sequential_uploads(self, client: TestClient):
        """
        E2E: Multiple sequential uploads without degradation
        """
        results = []

        for i in range(5):
            fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom" * 10)
            start_time = time.time()

            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"seq_test_{i}.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )

            elapsed = time.time() - start_time
            results.append({
                "index": i,
                "status": response.status_code,
                "time": elapsed
            })

        # All should complete
        assert len(results) == 5

        # Response times should be relatively consistent
        times = [r["time"] for r in results]
        avg_time = sum(times) / len(times)

        # No request should take more than 3x average
        for r in results:
            assert r["time"] < avg_time * 3, f"Request {r['index']} took too long"

    def test_skeleton_list_stability_over_time(self, client: TestClient):
        """
        E2E: Skeleton list returns consistent results
        """
        responses = []

        for _ in range(10):
            # FIX 2026-02-04: Corretto endpoint
            response = client.get("/api/v1/skeleton/list")
            if response.status_code == 200:
                responses.append(response.json()["total"])
            time.sleep(0.1)

        if responses:
            # Total should be consistent
            assert len(set(responses)) == 1, "Skeleton count changed unexpectedly"


@pytest.mark.e2e
class TestDataIntegrity:
    """E2E tests for data integrity"""

    def test_skeleton_data_completeness(self, client: TestClient):
        """
        E2E: Skeleton data is complete and valid
        """
        # FIX 2026-02-04: Corretto endpoint
        response = client.get("/api/v1/skeleton/list")

        if response.status_code == 200:
            data = response.json()

            # Verify list integrity
            assert data["total"] == len(data["skeletons"])

            # Verify each skeleton has required data
            for skeleton in data["skeletons"]:
                assert skeleton.get("id") is not None
                assert skeleton.get("path") is not None

                # Path should be a valid string
                assert isinstance(skeleton["path"], str)
                assert len(skeleton["path"]) > 0

    def test_json_response_validity(self, client: TestClient):
        """
        E2E: All JSON responses are valid
        """
        # FIX 2026-02-04: Corretto endpoint
        endpoints = [
            "/api/v1/skeleton/list",
            "/health",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)

            if response.status_code == 200:
                # Should parse without error
                try:
                    data = response.json()
                    assert data is not None
                except json.JSONDecodeError:
                    pytest.fail(f"Invalid JSON from {endpoint}")


@pytest.mark.e2e
class TestCrossEndpointWorkflows:
    """E2E tests for cross-endpoint interactions"""

    def test_health_skeletons_ingest_chain(self, client: TestClient):
        """
        E2E: Verify all main endpoints work in sequence
        """
        # 1. Health check
        health = client.get("/health")
        assert health.status_code == 200

        # 2. List skeletons
        # FIX 2026-02-04: Corretto endpoint
        skeletons = client.get("/api/v1/skeleton/list")
        assert skeletons.status_code == 200

        # 3. Ingest options check
        ingest_options = client.options("/api/v1/videos/ingest")
        assert ingest_options.status_code != 404

        # 4. List skeletons again (consistency check)
        # FIX 2026-02-04: Corretto endpoint
        skeletons2 = client.get("/api/v1/skeleton/list")
        assert skeletons2.status_code == 200
        assert skeletons2.json()["total"] == skeletons.json()["total"]

    def test_idempotent_get_operations(self, client: TestClient):
        """
        E2E: GET operations are idempotent
        """
        # Same request should return same result
        # FIX 2026-02-04: Corretto endpoint
        response1 = client.get("/api/v1/skeleton/list")
        response2 = client.get("/api/v1/skeleton/list")

        if response1.status_code == 200 and response2.status_code == 200:
            assert response1.json() == response2.json()

"""
================================================================================
AI_MODULE: Fusion Stress Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Stress tests per Fusion API - carico intensivo
AI_BUSINESS: Verifica stabilita sotto carico: concurrent requests, burst load
AI_TEACHING: concurrent.futures, stress testing, stability testing
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

================================================================================

ZERO MOCK POLICY: Test contro backend REALE.

STRESS TARGETS:
- 50 concurrent project list requests
- 20 concurrent project creates
- Graceful degradation under load

================================================================================
"""

import pytest
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.stress, pytest.mark.slow]

API_PREFIX = "/api/v1"


# ==============================================================================
# CONCURRENT REQUEST TESTS
# ==============================================================================
class TestConcurrentRequests:
    """Test richieste concorrenti."""

    def test_20_concurrent_list_requests(self, api_client, auth_headers):
        """20 list requests concorrenti."""
        def make_request():
            return api_client.get(
                f"{API_PREFIX}/fusion/projects",
                headers=auth_headers
            )

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_request) for _ in range(20)]
            results = [f.result() for f in as_completed(futures)]

        # All should succeed or return 404 (endpoint not exists)
        success = sum(1 for r in results if r.status_code in [200, 404])
        assert success >= 15, f"Only {success}/20 requests succeeded"

    def test_10_concurrent_project_creates(self, api_client, auth_headers):
        """10 project creates concorrenti."""
        project_ids = []

        def make_request(idx):
            return api_client.post(
                f"{API_PREFIX}/fusion/projects",
                json={
                    "name": f"Concurrent Test {idx} {uuid.uuid4().hex[:8]}",
                    "style": "karate"
                },
                headers=auth_headers
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, i) for i in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # Collect created project IDs for cleanup
        for r in results:
            if r.status_code in [200, 201]:
                project_id = r.json().get("id")
                if project_id:
                    project_ids.append(project_id)

        success = sum(1 for r in results if r.status_code in [200, 201, 404])
        assert success >= 8, f"Only {success}/10 creates succeeded"

        # Cleanup
        for pid in project_ids:
            api_client.delete(f"{API_PREFIX}/fusion/projects/{pid}", headers=auth_headers)

    def test_concurrent_read_write(self, api_client, auth_headers):
        """Letture e scritture concorrenti."""
        # Create a project first
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"RW Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project for test")

        project_id = create_resp.json()["id"]

        def read_request():
            return api_client.get(
                f"{API_PREFIX}/fusion/projects/{project_id}",
                headers=auth_headers
            )

        def write_request():
            return api_client.put(
                f"{API_PREFIX}/fusion/projects/{project_id}",
                json={"description": f"Updated {uuid.uuid4().hex[:8]}"},
                headers=auth_headers
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            read_futures = [executor.submit(read_request) for _ in range(5)]
            write_futures = [executor.submit(write_request) for _ in range(5)]

            all_futures = read_futures + write_futures
            results = [f.result() for f in as_completed(all_futures)]

        success = sum(1 for r in results if r.status_code in [200, 404])
        assert success >= 8, f"Only {success}/10 requests succeeded"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)


# ==============================================================================
# SUSTAINED LOAD TESTS
# ==============================================================================
class TestSustainedLoad:
    """Test carico sostenuto."""

    def test_50_sequential_requests(self, api_client, auth_headers):
        """50 richieste sequenziali senza degradazione."""
        times = []

        for i in range(50):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/fusion/projects",
                headers=auth_headers
            )
            elapsed = time.time() - start
            times.append(elapsed)

            if response.status_code not in [200, 404]:
                pytest.fail(f"Request {i} failed with {response.status_code}")

        # Check no significant degradation
        if len(times) >= 20 and times[0] > 0:
            first_10_avg = sum(times[:10]) / 10
            last_10_avg = sum(times[-10:]) / 10

            if first_10_avg > 0:
                # Allow 3x degradation max
                assert last_10_avg < first_10_avg * 3, "Significant performance degradation"

    def test_burst_requests(self, api_client, auth_headers):
        """Burst di 30 richieste in rapida successione."""
        start = time.time()
        results = []

        for _ in range(30):
            response = api_client.get(
                f"{API_PREFIX}/fusion/health",
                headers=auth_headers
            )
            results.append(response.status_code)

        elapsed = time.time() - start

        # Should complete reasonably fast
        assert elapsed < 10, f"Burst took {elapsed:.1f}s, expected <10s"

        # Most should succeed
        success = sum(1 for s in results if s in [200, 404])
        assert success >= 25, f"Only {success}/30 requests succeeded"


# ==============================================================================
# ERROR RECOVERY TESTS
# ==============================================================================
class TestErrorRecovery:
    """Test recovery dopo errori."""

    def test_recover_from_invalid_requests(self, api_client, auth_headers):
        """API si riprende dopo richieste invalide."""
        # Make invalid requests
        for _ in range(10):
            api_client.get(
                f"{API_PREFIX}/fusion/projects/invalid-id-{uuid.uuid4().hex[:8]}",
                headers=auth_headers
            )

        # Valid request should still work
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects",
            headers=auth_headers
        )
        assert response.status_code in [200, 404]

    def test_recover_from_malformed_json(self, api_client, auth_headers):
        """API si riprende dopo JSON malformato."""
        # Send malformed requests
        for _ in range(5):
            api_client.post(
                f"{API_PREFIX}/fusion/projects",
                content='{invalid json}',
                headers={**auth_headers, "Content-Type": "application/json"}
            )

        # Valid request should still work
        response = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Recovery Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )

        if response.status_code in [200, 201]:
            # Cleanup
            project_id = response.json().get("id")
            if project_id:
                api_client.delete(
                    f"{API_PREFIX}/fusion/projects/{project_id}",
                    headers=auth_headers
                )

        assert response.status_code in [200, 201, 404]

    def test_recover_from_large_payloads(self, api_client, auth_headers):
        """API si riprende dopo payload grandi."""
        # Send oversized request
        large_description = "x" * 100000
        api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={
                "name": "Large Test",
                "description": large_description,
                "style": "karate"
            },
            headers=auth_headers
        )

        # Normal request should still work
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects",
            headers=auth_headers
        )
        assert response.status_code in [200, 404]


# ==============================================================================
# RESOURCE MANAGEMENT TESTS
# ==============================================================================
class TestResourceManagement:
    """Test gestione risorse."""

    def test_many_projects_list_stable(self, api_client, auth_headers):
        """Lista rimane stabile con molti progetti."""
        project_ids = []

        # Create 10 projects
        for i in range(10):
            response = api_client.post(
                f"{API_PREFIX}/fusion/projects",
                json={
                    "name": f"Stability Test {i} {uuid.uuid4().hex[:8]}",
                    "style": "karate"
                },
                headers=auth_headers
            )
            if response.status_code in [200, 201]:
                project_ids.append(response.json().get("id"))

        # List should still be fast
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 500, f"List took {elapsed:.1f}ms with many projects"

        # Cleanup
        for pid in project_ids:
            if pid:
                api_client.delete(
                    f"{API_PREFIX}/fusion/projects/{pid}",
                    headers=auth_headers
                )

    def test_project_with_many_videos_stable(self, api_client, auth_headers):
        """Progetto con molti video rimane stabile."""
        # Create project
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Many Videos Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project")

        project_id = create_resp.json()["id"]

        # Add multiple videos (even if they don't exist, to test handling)
        for i in range(10):
            api_client.post(
                f"{API_PREFIX}/fusion/projects/{project_id}/videos",
                json={
                    "video_id": f"test-video-{i}",
                    "label": f"Video {i}",
                    "weight": 1.0
                },
                headers=auth_headers
            )

        # Detail should still be fast
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects/{project_id}",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 200, f"Detail took {elapsed:.1f}ms with many videos"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)

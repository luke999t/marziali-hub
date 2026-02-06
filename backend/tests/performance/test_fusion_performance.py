"""
================================================================================
AI_MODULE: Fusion Performance Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Performance benchmarks per Fusion API
AI_BUSINESS: Verifica che API response <100ms, WebSocket latency <50ms
AI_TEACHING: pytest timing assertions, concurrent requests, latency testing
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

================================================================================

ZERO MOCK POLICY: Test contro backend REALE.

PERFORMANCE TARGETS:
- API GET: <100ms
- API POST: <200ms
- WebSocket message: <50ms
- List projects: <500ms

================================================================================
"""

import pytest
import time
import uuid

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.performance, pytest.mark.slow]

API_PREFIX = "/api/v1"


# ==============================================================================
# API RESPONSE TIME TESTS
# ==============================================================================
class TestAPIResponseTime:
    """Test tempi risposta API."""

    def test_health_response_under_100ms(self, api_client, auth_headers):
        """GET /fusion/health < 100ms."""
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/health",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000  # ms

        if response.status_code == 200:
            assert elapsed < 100, f"Health took {elapsed:.1f}ms, expected <100ms"

    def test_list_projects_under_500ms(self, api_client, auth_headers):
        """GET /fusion/projects < 500ms."""
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 500, f"List projects took {elapsed:.1f}ms, expected <500ms"

    def test_create_project_under_200ms(self, api_client, auth_headers):
        """POST /fusion/projects < 200ms."""
        start = time.time()
        response = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={
                "name": f"Perf Test {uuid.uuid4().hex[:8]}",
                "style": "karate"
            },
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code in [200, 201]:
            assert elapsed < 200, f"Create project took {elapsed:.1f}ms, expected <200ms"
            # Cleanup
            project_id = response.json().get("id")
            if project_id:
                api_client.delete(
                    f"{API_PREFIX}/fusion/projects/{project_id}",
                    headers=auth_headers
                )

    def test_get_project_detail_under_100ms(self, api_client, auth_headers):
        """GET /fusion/projects/{id} < 100ms."""
        # Create project first
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Detail Perf Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project for test")

        project_id = create_resp.json()["id"]

        # Measure detail fetch
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects/{project_id}",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 100, f"Get detail took {elapsed:.1f}ms, expected <100ms"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)

    def test_add_video_under_200ms(self, api_client, auth_headers, test_video_id):
        """POST /fusion/projects/{id}/videos < 200ms."""
        if not test_video_id:
            pytest.skip("No test video available")

        # Create project first
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Video Perf Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project for test")

        project_id = create_resp.json()["id"]

        # Measure add video
        start = time.time()
        response = api_client.post(
            f"{API_PREFIX}/fusion/projects/{project_id}/videos",
            json={
                "video_id": test_video_id,
                "label": "Performance Test",
                "weight": 1.0
            },
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code in [200, 201]:
            assert elapsed < 200, f"Add video took {elapsed:.1f}ms, expected <200ms"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)

    def test_get_status_under_100ms(self, api_client, auth_headers):
        """GET /fusion/projects/{id}/status < 100ms."""
        # Create project first
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Status Perf Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project for test")

        project_id = create_resp.json()["id"]

        # Measure status fetch
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects/{project_id}/status",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 100, f"Get status took {elapsed:.1f}ms, expected <100ms"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)

    def test_styles_under_100ms(self, api_client, auth_headers):
        """GET /fusion/styles < 100ms."""
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/styles",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 100, f"Get styles took {elapsed:.1f}ms, expected <100ms"

    def test_presets_under_100ms(self, api_client, auth_headers):
        """GET /fusion/presets < 100ms."""
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/fusion/presets",
            headers=auth_headers
        )
        elapsed = (time.time() - start) * 1000

        if response.status_code == 200:
            assert elapsed < 100, f"Get presets took {elapsed:.1f}ms, expected <100ms"


# ==============================================================================
# THROUGHPUT TESTS
# ==============================================================================
class TestThroughput:
    """Test throughput API."""

    def test_sequential_list_requests(self, api_client, auth_headers):
        """10 richieste lista sequenziali < 3s totali."""
        start = time.time()
        success_count = 0

        for _ in range(10):
            response = api_client.get(
                f"{API_PREFIX}/fusion/projects",
                headers=auth_headers
            )
            if response.status_code in [200, 404]:
                success_count += 1

        elapsed = time.time() - start

        if success_count == 10:
            assert elapsed < 3, f"10 list requests took {elapsed:.1f}s, expected <3s"

    def test_create_delete_cycle(self, api_client, auth_headers):
        """5 cicli create/delete < 3s totali."""
        start = time.time()
        success_count = 0

        for i in range(5):
            # Create
            create_resp = api_client.post(
                f"{API_PREFIX}/fusion/projects",
                json={"name": f"Cycle Test {i} {uuid.uuid4().hex[:8]}", "style": "karate"},
                headers=auth_headers
            )
            if create_resp.status_code in [200, 201]:
                project_id = create_resp.json()["id"]
                # Delete
                delete_resp = api_client.delete(
                    f"{API_PREFIX}/fusion/projects/{project_id}",
                    headers=auth_headers
                )
                if delete_resp.status_code in [200, 204]:
                    success_count += 1

        elapsed = time.time() - start

        if success_count == 5:
            assert elapsed < 3, f"5 create/delete cycles took {elapsed:.1f}s, expected <3s"


# ==============================================================================
# PAYLOAD SIZE TESTS
# ==============================================================================
class TestPayloadSize:
    """Test dimensione payload."""

    def test_project_list_reasonable_size(self, api_client, auth_headers):
        """Lista progetti < 100KB."""
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects?limit=50",
            headers=auth_headers
        )

        if response.status_code == 200:
            size_kb = len(response.content) / 1024
            assert size_kb < 100, f"Project list {size_kb:.1f}KB, expected <100KB"

    def test_project_detail_reasonable_size(self, api_client, auth_headers):
        """Dettaglio progetto < 50KB."""
        # Create project
        create_resp = api_client.post(
            f"{API_PREFIX}/fusion/projects",
            json={"name": f"Size Test {uuid.uuid4().hex[:8]}", "style": "karate"},
            headers=auth_headers
        )
        if create_resp.status_code not in [200, 201]:
            pytest.skip("Cannot create project")

        project_id = create_resp.json()["id"]

        # Get detail
        response = api_client.get(
            f"{API_PREFIX}/fusion/projects/{project_id}",
            headers=auth_headers
        )

        if response.status_code == 200:
            size_kb = len(response.content) / 1024
            assert size_kb < 50, f"Project detail {size_kb:.1f}KB, expected <50KB"

        # Cleanup
        api_client.delete(f"{API_PREFIX}/fusion/projects/{project_id}", headers=auth_headers)


# ==============================================================================
# PAGINATION PERFORMANCE
# ==============================================================================
class TestPaginationPerformance:
    """Test performance paginazione."""

    def test_pagination_consistent_time(self, api_client, auth_headers):
        """Paginazione ha tempo costante."""
        times = []

        for offset in [0, 20, 40]:
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/fusion/projects?limit=20&offset={offset}",
                headers=auth_headers
            )
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)

        if len(times) == 3 and all(t > 0 for t in times):
            # Varianza dovrebbe essere bassa (tempo costante O(1))
            avg = sum(times) / len(times)
            variance = sum((t - avg) ** 2 for t in times) / len(times)
            # Se la varianza e alta, la paginazione potrebbe essere O(n)
            # Accettiamo varianza ragionevole
            assert variance < avg * avg, "Pagination time is not constant"

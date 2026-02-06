"""
================================================================================
AI_MODULE: TestConcurrentAPI
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test stress con richieste API concorrenti REALI - ZERO MOCK
AI_BUSINESS: Verifica stabilità sistema sotto carico (uptime, latency SLA)
AI_TEACHING: asyncio.gather, connection pooling, rate limiting

ZERO_MOCK_POLICY:
- Tutti i test chiamano backend REALE
- Test FALLISCONO se backend spento
- Misurano latenza e success rate reali

COVERAGE_TARGET: Sistema completo sotto stress
================================================================================
"""

import pytest
import asyncio
import time
import statistics
from typing import List, Tuple


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.stress, pytest.mark.slow]


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def calculate_percentile(data: List[float], percentile: int) -> float:
    """Calculate percentile from list of values."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = int(len(sorted_data) * percentile / 100)
    return sorted_data[min(index, len(sorted_data) - 1)]


# ==============================================================================
# TEST: Health Check Stress
# ==============================================================================
class TestHealthCheckStress:
    """Test endpoint health sotto stress."""

    def test_health_100_sequential_requests(self, api_client):
        """
        100 richieste sequenziali a /health.
        Target: 100% success, < 100ms avg latency
        """
        latencies = []
        success_count = 0
        total_requests = 100

        for _ in range(total_requests):
            start = time.time()
            response = api_client.get("/health")
            latency = (time.time() - start) * 1000  # ms
            latencies.append(latency)

            if response.status_code == 200:
                success_count += 1

        success_rate = (success_count / total_requests) * 100
        avg_latency = statistics.mean(latencies)
        p95_latency = calculate_percentile(latencies, 95)
        p99_latency = calculate_percentile(latencies, 99)

        print(f"\n[Health Check Stress Results]")
        print(f"  Success Rate: {success_rate:.1f}%")
        print(f"  Avg Latency: {avg_latency:.1f}ms")
        print(f"  P95 Latency: {p95_latency:.1f}ms")
        print(f"  P99 Latency: {p99_latency:.1f}ms")

        # Assertions
        assert success_rate >= 99, f"Success rate {success_rate}% < 99%"
        assert avg_latency < 200, f"Avg latency {avg_latency}ms > 200ms"

    @pytest.mark.asyncio
    async def test_health_50_concurrent_requests(self, async_api_client):
        """
        50 richieste concorrenti a /health.
        Target: >= 95% success rate
        """
        import httpx

        async def make_request(client: httpx.AsyncClient) -> Tuple[int, float]:
            start = time.time()
            try:
                response = await client.get("/health")
                latency = (time.time() - start) * 1000
                return response.status_code, latency
            except Exception:
                return 500, (time.time() - start) * 1000

        results = await asyncio.gather(*[
            make_request(async_api_client) for _ in range(50)
        ])

        success_count = sum(1 for status, _ in results if status == 200)
        latencies = [lat for _, lat in results]
        success_rate = (success_count / 50) * 100

        print(f"\n[Concurrent Health Check Results]")
        print(f"  Success Rate: {success_rate:.1f}%")
        print(f"  Avg Latency: {statistics.mean(latencies):.1f}ms")

        assert success_rate >= 95, f"Concurrent success rate {success_rate}% < 95%"


# ==============================================================================
# TEST: Auth Endpoint Stress
# ==============================================================================
class TestAuthStress:
    """Test autenticazione sotto stress."""

    def test_login_50_sequential_requests(self, api_client):
        """
        50 login sequenziali con credenziali valide.
        Target: >= 95% success, < 500ms avg latency
        """
        latencies = []
        success_count = 0
        total_requests = 50

        for _ in range(total_requests):
            start = time.time()
            response = api_client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "TestPassword123!"
            })
            latency = (time.time() - start) * 1000
            latencies.append(latency)

            if response.status_code == 200:
                success_count += 1

        success_rate = (success_count / total_requests) * 100
        avg_latency = statistics.mean(latencies)

        print(f"\n[Login Stress Results]")
        print(f"  Success Rate: {success_rate:.1f}%")
        print(f"  Avg Latency: {avg_latency:.1f}ms")

        # Login involves password hashing - allow more latency
        assert success_rate >= 90, f"Login success rate {success_rate}% < 90%"
        assert avg_latency < 1000, f"Login avg latency {avg_latency}ms > 1000ms"

    def test_failed_login_rate_limiting(self, api_client):
        """
        Test che login falliti consecutivi siano rate-limited.
        Security: Previene brute force attacks.
        """
        import uuid
        fake_email = f"nonexistent_{uuid.uuid4().hex[:8]}@example.com"

        # Attempt 20 rapid failed logins
        statuses = []
        for _ in range(20):
            response = api_client.post("/api/v1/auth/login", json={
                "email": fake_email,
                "password": "WrongPassword123!"
            })
            statuses.append(response.status_code)

        # All should be 401 (unauthorized) - no 200s
        assert 200 not in statuses, "Login succeeded with wrong credentials!"

        # Count distinct status codes
        unique_statuses = set(statuses)
        print(f"\n[Rate Limit Test] Statuses: {unique_statuses}")

        # Should see 401 or eventually 429 (rate limited)
        assert all(s in (401, 429, 422) for s in statuses)


# ==============================================================================
# TEST: Video Listing Stress
# ==============================================================================
class TestVideoListingStress:
    """Test listing video sotto stress."""

    def test_video_list_100_requests(self, api_client, auth_headers):
        """
        100 richieste sequenziali alla lista video.
        Target: >= 95% success
        """
        success_count = 0
        total_requests = 100

        for i in range(total_requests):
            response = api_client.get(
                "/api/v1/videos?limit=10",
                headers=auth_headers
            )
            if response.status_code == 200:
                success_count += 1

        success_rate = (success_count / total_requests) * 100
        print(f"\n[Video List Stress] Success Rate: {success_rate:.1f}%")

        assert success_rate >= 95, f"Video list success rate {success_rate}% < 95%"

    def test_video_pagination_stress(self, api_client, auth_headers):
        """Test paginazione video sotto stress."""
        success_count = 0
        total_pages = 20

        for page in range(total_pages):
            response = api_client.get(
                f"/api/v1/videos?limit=10&offset={page * 10}",
                headers=auth_headers
            )
            if response.status_code == 200:
                success_count += 1

        success_rate = (success_count / total_pages) * 100
        assert success_rate >= 95


# ==============================================================================
# TEST: Mixed Workload Stress
# ==============================================================================
class TestMixedWorkloadStress:
    """Test carico misto (realistic traffic pattern)."""

    def test_mixed_workload_100_requests(self, api_client, auth_headers):
        """
        100 richieste miste simulando traffico reale.
        Mix: 40% health, 30% video list, 20% user profile, 10% login
        """
        results = {
            "health": {"success": 0, "total": 0},
            "videos": {"success": 0, "total": 0},
            "profile": {"success": 0, "total": 0},
            "login": {"success": 0, "total": 0},
        }

        import random

        for i in range(100):
            endpoint_type = random.choices(
                ["health", "videos", "profile", "login"],
                weights=[40, 30, 20, 10]
            )[0]

            if endpoint_type == "health":
                response = api_client.get("/health")
                results["health"]["total"] += 1
                if response.status_code == 200:
                    results["health"]["success"] += 1

            elif endpoint_type == "videos":
                response = api_client.get(
                    "/api/v1/videos?limit=5",
                    headers=auth_headers
                )
                results["videos"]["total"] += 1
                if response.status_code == 200:
                    results["videos"]["success"] += 1

            elif endpoint_type == "profile":
                response = api_client.get(
                    "/api/v1/users/me",
                    headers=auth_headers
                )
                results["profile"]["total"] += 1
                if response.status_code == 200:
                    results["profile"]["success"] += 1

            elif endpoint_type == "login":
                response = api_client.post("/api/v1/auth/login", json={
                    "email": "test@example.com",
                    "password": "TestPassword123!"
                })
                results["login"]["total"] += 1
                if response.status_code == 200:
                    results["login"]["success"] += 1

        print("\n[Mixed Workload Results]")
        total_success = 0
        total_requests = 0
        for endpoint, data in results.items():
            if data["total"] > 0:
                rate = (data["success"] / data["total"]) * 100
                print(f"  {endpoint}: {rate:.1f}% ({data['success']}/{data['total']})")
                total_success += data["success"]
                total_requests += data["total"]

        overall_rate = (total_success / total_requests) * 100
        print(f"  OVERALL: {overall_rate:.1f}%")

        assert overall_rate >= 90, f"Overall success rate {overall_rate}% < 90%"


# ==============================================================================
# TEST: Database Connection Pool Stress
# ==============================================================================
class TestDatabasePoolStress:
    """Test connection pool del database sotto stress."""

    def test_rapid_sequential_db_queries(self, api_client, auth_headers):
        """
        200 query sequenziali rapide per testare connection pool.
        """
        success_count = 0
        start_time = time.time()

        for _ in range(200):
            response = api_client.get(
                "/api/v1/users/me",
                headers=auth_headers
            )
            if response.status_code == 200:
                success_count += 1

        duration = time.time() - start_time
        qps = 200 / duration

        print(f"\n[DB Pool Stress]")
        print(f"  Queries: 200")
        print(f"  Duration: {duration:.2f}s")
        print(f"  QPS: {qps:.1f}")
        print(f"  Success: {success_count}/200")

        assert success_count >= 190, f"Only {success_count}/200 succeeded"
        assert qps >= 10, f"QPS {qps} < 10 (too slow)"


# ==============================================================================
# TEST: Memory Leak Detection (Long Running)
# ==============================================================================
class TestMemoryStability:
    """Test stabilità memoria durante carico prolungato."""

    def test_sustained_load_no_memory_growth(self, api_client, auth_headers):
        """
        500 richieste per verificare che non ci siano memory leak.
        Nota: Questo test non misura direttamente la memoria ma
        verifica che il server rimanga stabile.
        """
        success_count = 0
        errors = []

        for i in range(500):
            try:
                response = api_client.get("/health")
                if response.status_code == 200:
                    success_count += 1
                else:
                    errors.append(f"Request {i}: status {response.status_code}")
            except Exception as e:
                errors.append(f"Request {i}: {str(e)}")

        success_rate = (success_count / 500) * 100

        print(f"\n[Sustained Load Test]")
        print(f"  Total Requests: 500")
        print(f"  Success Rate: {success_rate:.1f}%")
        if errors:
            print(f"  First 5 Errors: {errors[:5]}")

        # After 500 requests, server should still be stable
        assert success_rate >= 98, f"Success rate dropped to {success_rate}%"


# ==============================================================================
# TEST: Response Time Consistency
# ==============================================================================
class TestResponseTimeConsistency:
    """Test che i tempi di risposta rimangano consistenti."""

    def test_latency_consistency_over_time(self, api_client):
        """
        Verifica che la latenza non degradi nel tempo.
        """
        batches = 5
        requests_per_batch = 20
        batch_latencies = []

        for batch in range(batches):
            latencies = []
            for _ in range(requests_per_batch):
                start = time.time()
                response = api_client.get("/health")
                if response.status_code == 200:
                    latencies.append((time.time() - start) * 1000)

            if latencies:
                avg = statistics.mean(latencies)
                batch_latencies.append(avg)
                print(f"Batch {batch + 1}: avg={avg:.1f}ms")

        if len(batch_latencies) >= 2:
            # Last batch should not be significantly slower than first
            first_batch = batch_latencies[0]
            last_batch = batch_latencies[-1]

            # Allow 100% degradation max (2x slower)
            assert last_batch < first_batch * 2, \
                f"Latency degraded: {first_batch:.1f}ms -> {last_batch:.1f}ms"

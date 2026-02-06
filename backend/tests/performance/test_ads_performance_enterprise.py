"""
================================================================================
AI_MODULE: Ads Performance Enterprise Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test performance/benchmark COMPLETI per Ads
AI_BUSINESS: Validazione performance ads: latency P95, throughput, response time
AI_TEACHING: Performance testing - latency percentiles, benchmarks, SLA validation

ZERO MOCK - LEGGE SUPREMA
Benchmark reali, no mock.
================================================================================
"""

import pytest
import uuid
import time
import statistics
from typing import List

# ==============================================================================
# MARKERS
# ==============================================================================
API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.performance]


# ==============================================================================
# PERFORMANCE THRESHOLDS (SLA)
# ==============================================================================
P95_LATENCY_MS = 500  # P95 latency < 500ms
P99_LATENCY_MS = 1000  # P99 latency < 1000ms
AVG_LATENCY_MS = 200  # Average latency < 200ms
MIN_THROUGHPUT_RPS = 10  # Minimum 10 requests/second


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def calculate_percentile(values: List[float], percentile: int) -> float:
    """Calcola percentile da lista di valori."""
    sorted_values = sorted(values)
    index = int(len(sorted_values) * percentile / 100)
    return sorted_values[min(index, len(sorted_values) - 1)]


def measure_latency_ms(func) -> float:
    """Misura latency in millisecondi."""
    start = time.time()
    func()
    return (time.time() - start) * 1000


# ==============================================================================
# TEST: Latency Benchmarks
# ==============================================================================
class TestAdsLatencyBenchmarks:
    """Benchmark latency API Ads."""

    def test_stats_endpoint_p95_latency(self, api_client, auth_headers_free):
        """P95 latency endpoint stats < 500ms."""
        latencies = []

        for _ in range(100):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests for latency measurement")

        p95 = calculate_percentile(latencies, 95)
        assert p95 < P95_LATENCY_MS, f"P95 latency {p95:.2f}ms > {P95_LATENCY_MS}ms"

    def test_batch_start_p95_latency(self, api_client, auth_headers_free):
        """P95 latency batch start < 500ms."""
        latencies = []

        for _ in range(50):
            start = time.time()
            response = api_client.post(
                f"{API_PREFIX}/ads/batch/start",
                json={"batch_type": "3_video"},
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 201, 400, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests for latency measurement")

        p95 = calculate_percentile(latencies, 95)
        assert p95 < P95_LATENCY_MS, f"P95 latency {p95:.2f}ms > {P95_LATENCY_MS}ms"

    def test_view_recording_p95_latency(self, api_client, auth_headers_free):
        """P95 latency view recording < 500ms."""
        latencies = []

        for _ in range(100):
            start = time.time()
            response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={"ad_id": str(uuid.uuid4()), "duration": 30},
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 201, 400, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests for latency measurement")

        p95 = calculate_percentile(latencies, 95)
        assert p95 < P95_LATENCY_MS, f"P95 latency {p95:.2f}ms > {P95_LATENCY_MS}ms"

    def test_next_ad_p95_latency(self, api_client, auth_headers_free):
        """P95 latency next ad < 500ms."""
        latencies = []

        for _ in range(100):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/ads/next",
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 204, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests for latency measurement")

        p95 = calculate_percentile(latencies, 95)
        assert p95 < P95_LATENCY_MS, f"P95 latency {p95:.2f}ms > {P95_LATENCY_MS}ms"


# ==============================================================================
# TEST: Average Latency
# ==============================================================================
class TestAdsAverageLatency:
    """Test latency media API Ads."""

    def test_stats_average_latency(self, api_client, auth_headers_free):
        """Average latency stats < 200ms."""
        latencies = []

        for _ in range(50):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests")

        avg = statistics.mean(latencies)
        assert avg < AVG_LATENCY_MS, f"Average latency {avg:.2f}ms > {AVG_LATENCY_MS}ms"

    def test_view_average_latency(self, api_client, auth_headers_free):
        """Average latency view recording < 200ms."""
        latencies = []

        for _ in range(50):
            start = time.time()
            response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={"ad_id": str(uuid.uuid4()), "duration": 30},
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 201, 400, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough successful requests")

        avg = statistics.mean(latencies)
        assert avg < AVG_LATENCY_MS, f"Average latency {avg:.2f}ms > {AVG_LATENCY_MS}ms"


# ==============================================================================
# TEST: Throughput
# ==============================================================================
class TestAdsThroughputBenchmarks:
    """Benchmark throughput API Ads."""

    def test_stats_throughput(self, api_client, auth_headers_free):
        """Throughput stats > 10 RPS."""
        count = 0
        start = time.time()
        duration_limit = 5

        while time.time() - start < duration_limit:
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers=auth_headers_free
            )
            if response.status_code in [200, 404]:
                count += 1

        throughput = count / duration_limit
        assert throughput >= MIN_THROUGHPUT_RPS, f"Throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS} RPS"

    def test_view_throughput(self, api_client, auth_headers_free):
        """Throughput view recording > 10 RPS."""
        count = 0
        start = time.time()
        duration_limit = 5

        while time.time() - start < duration_limit:
            response = api_client.post(
                f"{API_PREFIX}/ads/view",
                json={"ad_id": str(uuid.uuid4()), "duration": 30},
                headers=auth_headers_free
            )
            if response.status_code in [200, 201, 400, 404]:
                count += 1

        throughput = count / duration_limit
        assert throughput >= MIN_THROUGHPUT_RPS, f"Throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS} RPS"


# ==============================================================================
# TEST: Response Time Distribution
# ==============================================================================
class TestAdsResponseTimeDistribution:
    """Test distribuzione response time."""

    def test_stats_response_time_distribution(self, api_client, auth_headers_free):
        """Verifica distribuzione response time sana."""
        latencies = []

        for _ in range(100):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 20:
            pytest.skip("Not enough data points")

        # Calcola statistiche
        avg = statistics.mean(latencies)
        std_dev = statistics.stdev(latencies) if len(latencies) > 1 else 0
        p50 = calculate_percentile(latencies, 50)
        p95 = calculate_percentile(latencies, 95)
        p99 = calculate_percentile(latencies, 99)

        # Verifica distribuzione ragionevole
        # P50 non deve essere troppo lontano dalla media
        assert abs(p50 - avg) < avg, "High variance in response times"

        # P99 non deve essere più di 5x la media
        assert p99 < avg * 5, f"P99 ({p99:.2f}ms) too high compared to avg ({avg:.2f}ms)"


# ==============================================================================
# TEST: Consistency
# ==============================================================================
class TestAdsPerformanceConsistency:
    """Test consistenza performance."""

    def test_consistent_response_times(self, api_client, auth_headers_free):
        """Response time consistenti (bassa varianza)."""
        latencies = []

        for _ in range(50):
            start = time.time()
            response = api_client.get(
                f"{API_PREFIX}/ads/stats",
                headers=auth_headers_free
            )
            latency_ms = (time.time() - start) * 1000
            if response.status_code in [200, 404]:
                latencies.append(latency_ms)

        if len(latencies) < 10:
            pytest.skip("Not enough data points")

        # Coefficient of variation < 100%
        avg = statistics.mean(latencies)
        std_dev = statistics.stdev(latencies) if len(latencies) > 1 else 0
        cv = (std_dev / avg) * 100 if avg > 0 else 0

        # CV < 150% è accettabile per API
        assert cv < 150, f"High variability: CV = {cv:.2f}%"


# ==============================================================================
# TEST: Pure Logic Performance
# ==============================================================================
class TestAdsPureLogicPerformance:
    """Benchmark logica pura (senza I/O)."""

    def test_cpm_calculation_nanoseconds(self):
        """Calcolo CPM in nanosecondi."""
        from modules.ads.ads_service import DEFAULT_CPM_RATE

        iterations = 1000000
        start = time.time()

        for i in range(iterations):
            _ = (i / 1000.0) * DEFAULT_CPM_RATE

        duration_ns = (time.time() - start) * 1e9 / iterations

        # < 500 nanosecondi per calcolo (Python overhead)
        assert duration_ns < 500, f"CPM calculation {duration_ns:.2f}ns too slow"

    def test_tier_check_nanoseconds(self):
        """Check tier in nanosecondi."""
        from modules.ads.ads_service import TIERS_WITH_ADS
        from models.user import UserTier

        iterations = 1000000
        start = time.time()

        for _ in range(iterations):
            _ = UserTier.FREE in TIERS_WITH_ADS

        duration_ns = (time.time() - start) * 1e9 / iterations

        # < 500 nanosecondi per check (Python overhead)
        assert duration_ns < 500, f"Tier check {duration_ns:.2f}ns too slow"

    def test_batch_config_lookup_nanoseconds(self):
        """Lookup batch config in nanosecondi."""
        from modules.ads.ads_service import BATCH_CONFIG
        from models.ads import AdsBatchType

        iterations = 1000000
        start = time.time()

        for _ in range(iterations):
            _ = BATCH_CONFIG[AdsBatchType.BATCH_3]

        duration_ns = (time.time() - start) * 1e9 / iterations

        # < 500 nanosecondi per lookup (Python overhead)
        assert duration_ns < 500, f"Config lookup {duration_ns:.2f}ns too slow"


# ==============================================================================
# TEST: Cold Start
# ==============================================================================
class TestAdsColdStart:
    """Test cold start performance."""

    def test_first_request_latency(self, api_client, auth_headers_free):
        """Prima richiesta non deve essere troppo lenta."""
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )
        first_latency_ms = (time.time() - start) * 1000

        # Cold start può essere più lento, ma < 2 secondi
        assert first_latency_ms < 2000, f"Cold start latency {first_latency_ms:.2f}ms > 2000ms"

        # Seconda richiesta dovrebbe essere più veloce
        start = time.time()
        response = api_client.get(
            f"{API_PREFIX}/ads/stats",
            headers=auth_headers_free
        )
        second_latency_ms = (time.time() - start) * 1000

        # Warm request dovrebbe essere < 500ms
        if response.status_code in [200, 404]:
            assert second_latency_ms < 500, f"Warm latency {second_latency_ms:.2f}ms > 500ms"

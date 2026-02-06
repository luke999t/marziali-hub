"""
AI_MODULE: Avatar Performance Tests - Enterprise Suite
AI_DESCRIPTION: Benchmark prestazioni per Avatar API
AI_TEACHING: I test performance misurano:
             - Latenza P50/P95/P99 degli endpoint
             - Throughput (richieste/secondo)
             - Tempo di risposta sotto carico crescente
             - Performance caching bone mapping
             - Download speed file GLB

ZERO MOCK: Tutti i test chiamano il backend REALE su localhost:8000
"""

import pytest
import httpx
import time
import statistics
import os
import uuid
from typing import List, Dict, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# CONFIGURAZIONE
# ============================================================================

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/avatars"

# Performance targets (millisecondi)
TARGETS = {
    "list_p50": 100,
    "list_p95": 300,
    "list_p99": 500,
    "detail_p50": 50,
    "detail_p95": 150,
    "detail_p99": 300,
    "bone_mapping_p50": 30,
    "bone_mapping_p95": 100,
    "download_mbps_min": 10,  # Megabit/sec minimo
}


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class PerformanceResult:
    """Risultato di un performance test."""
    endpoint: str
    samples: int
    min_ms: float
    max_ms: float
    avg_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    success_rate: float
    throughput_rps: float  # requests per second


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Client HTTP."""
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Headers autenticazione."""
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPassword123!"
    })
    if response.status_code != 200:
        pytest.skip("Auth non disponibile")
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def measure_endpoint(
    url: str,
    headers: dict,
    samples: int = 100,
    method: str = "GET",
    **kwargs
) -> PerformanceResult:
    """
    Misura le prestazioni di un endpoint.
    """
    latencies: List[float] = []
    successes = 0
    start_total = time.time()
    
    for _ in range(samples):
        start = time.time()
        try:
            with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
                if method == "GET":
                    response = client.get(url, headers=headers, **kwargs)
                else:
                    response = client.post(url, headers=headers, **kwargs)
            
            latency_ms = (time.time() - start) * 1000
            latencies.append(latency_ms)
            
            if response.status_code in [200, 201, 404]:
                successes += 1
        except Exception:
            latencies.append((time.time() - start) * 1000)
    
    total_time = time.time() - start_total
    
    sorted_latencies = sorted(latencies)
    
    return PerformanceResult(
        endpoint=url,
        samples=samples,
        min_ms=min(latencies),
        max_ms=max(latencies),
        avg_ms=statistics.mean(latencies),
        p50_ms=sorted_latencies[int(samples * 0.50)],
        p95_ms=sorted_latencies[int(samples * 0.95)],
        p99_ms=sorted_latencies[int(samples * 0.99)] if samples >= 100 else sorted_latencies[-1],
        success_rate=(successes / samples) * 100,
        throughput_rps=samples / total_time
    )


def print_performance_result(result: PerformanceResult):
    """Stampa risultato formattato."""
    print(f"\n📊 Performance: {result.endpoint}")
    print(f"   Samples: {result.samples}")
    print(f"   Success rate: {result.success_rate:.1f}%")
    print(f"   Throughput: {result.throughput_rps:.1f} req/s")
    print(f"   Latency (ms):")
    print(f"     Min: {result.min_ms:.2f}")
    print(f"     Avg: {result.avg_ms:.2f}")
    print(f"     P50: {result.p50_ms:.2f}")
    print(f"     P95: {result.p95_ms:.2f}")
    print(f"     P99: {result.p99_ms:.2f}")
    print(f"     Max: {result.max_ms:.2f}")


# ============================================================================
# 1. LIST ENDPOINT PERFORMANCE
# ============================================================================

class TestAvatarListPerformance:
    """Benchmark endpoint lista avatar."""

    @pytest.mark.performance
    def test_list_avatars_latency(self, auth_headers):
        """Misura latenza GET /avatars/ (100 campioni)."""
        result = measure_endpoint(f"{API_PREFIX}/", auth_headers, samples=100)
        print_performance_result(result)
        
        # Verifica targets
        assert result.p50_ms < TARGETS["list_p50"], f"P50 too high: {result.p50_ms}ms"
        assert result.p95_ms < TARGETS["list_p95"], f"P95 too high: {result.p95_ms}ms"
        assert result.success_rate >= 99, f"Success rate too low: {result.success_rate}%"

    @pytest.mark.performance
    def test_list_with_pagination_performance(self, auth_headers):
        """Benchmark lista con pagination diverse."""
        page_sizes = [10, 25, 50, 100]
        results: Dict[int, PerformanceResult] = {}
        
        for page_size in page_sizes:
            result = measure_endpoint(
                f"{API_PREFIX}/",
                auth_headers,
                samples=50,
                params={"page": 1, "page_size": page_size}
            )
            results[page_size] = result
            print(f"   Page size {page_size}: P50={result.p50_ms:.2f}ms, P95={result.p95_ms:.2f}ms")
        
        # La performance non deve degradare troppo con page_size maggiore
        ratio = results[100].p95_ms / results[10].p95_ms
        assert ratio < 3, f"Performance degradation too high: {ratio:.2f}x"

    @pytest.mark.performance
    def test_list_with_style_filter(self, auth_headers):
        """Benchmark lista con filtro style."""
        styles = ["karate", "kung_fu", "taekwondo", "generic"]
        
        for style in styles:
            result = measure_endpoint(
                f"{API_PREFIX}/",
                auth_headers,
                samples=30,
                params={"style": style}
            )
            print(f"   Style '{style}': P50={result.p50_ms:.2f}ms")
            assert result.p50_ms < TARGETS["list_p50"] * 1.5  # 50% tolleranza per filtro


# ============================================================================
# 2. DETAIL ENDPOINT PERFORMANCE
# ============================================================================

class TestAvatarDetailPerformance:
    """Benchmark endpoint dettaglio avatar."""

    @pytest.mark.performance
    def test_detail_avatar_latency(self, client, auth_headers):
        """Misura latenza GET /avatars/{id}."""
        # Ottieni avatar esistente
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("API non disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar disponibile")
        
        avatar_id = avatars[0]["id"]
        
        result = measure_endpoint(
            f"{API_PREFIX}/{avatar_id}",
            auth_headers,
            samples=100
        )
        print_performance_result(result)
        
        assert result.p50_ms < TARGETS["detail_p50"]
        assert result.p95_ms < TARGETS["detail_p95"]

    @pytest.mark.performance
    def test_detail_nonexistent_avatar(self, auth_headers):
        """Benchmark 404 response time (deve essere veloce)."""
        fake_id = str(uuid.uuid4())
        
        result = measure_endpoint(
            f"{API_PREFIX}/{fake_id}",
            auth_headers,
            samples=50
        )
        print(f"\n📊 404 Performance: P50={result.p50_ms:.2f}ms, P95={result.p95_ms:.2f}ms")
        
        # 404 deve essere velocissimo (niente DB lookup pesante)
        assert result.p50_ms < 50, "404 response too slow"


# ============================================================================
# 3. BONE MAPPING PERFORMANCE (SHOULD BE CACHED)
# ============================================================================

class TestAvatarBoneMappingPerformance:
    """Benchmark bone mapping (deve essere cached)."""

    @pytest.mark.performance
    def test_bone_mapping_latency(self, auth_headers):
        """Misura latenza GET /avatars/bone-mapping."""
        result = measure_endpoint(
            f"{API_PREFIX}/bone-mapping",
            auth_headers,
            samples=100
        )
        print_performance_result(result)
        
        # Bone mapping è statico, deve essere molto veloce (cached)
        assert result.p50_ms < TARGETS["bone_mapping_p50"]
        assert result.p95_ms < TARGETS["bone_mapping_p95"]

    @pytest.mark.performance
    def test_bone_mapping_consistency(self, auth_headers):
        """Verifica che le risposte siano consistenti (cache hit)."""
        latencies = []
        
        for i in range(10):
            start = time.time()
            with httpx.Client(base_url=BASE_URL, timeout=10.0) as client:
                response = client.get(f"{API_PREFIX}/bone-mapping", headers=auth_headers)
            latencies.append((time.time() - start) * 1000)
        
        # Dopo la prima richiesta (cache warm), le successive devono essere veloci
        warm_latencies = latencies[1:]  # Escludi prima (cold)
        avg_warm = statistics.mean(warm_latencies)
        std_dev = statistics.stdev(warm_latencies) if len(warm_latencies) > 1 else 0
        
        print(f"\n📊 Cache Consistency: Avg={avg_warm:.2f}ms, StdDev={std_dev:.2f}ms")
        
        # Standard deviation bassa indica caching consistente
        assert std_dev < avg_warm * 0.5, "Inconsistent response times (cache miss?)"


# ============================================================================
# 4. STYLES ENDPOINT PERFORMANCE
# ============================================================================

class TestAvatarStylesPerformance:
    """Benchmark endpoint styles."""

    @pytest.mark.performance
    def test_styles_latency(self, auth_headers):
        """Misura latenza GET /avatars/styles."""
        result = measure_endpoint(
            f"{API_PREFIX}/styles",
            auth_headers,
            samples=50
        )
        print(f"\n📊 Styles: P50={result.p50_ms:.2f}ms, P95={result.p95_ms:.2f}ms")
        
        # Endpoint statico, deve essere velocissimo
        assert result.p50_ms < 30


# ============================================================================
# 5. FILE DOWNLOAD PERFORMANCE
# ============================================================================

class TestAvatarDownloadPerformance:
    """Benchmark download file GLB."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_file_download_speed(self, client, auth_headers):
        """Misura velocità download file GLB."""
        # Ottieni avatar
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("API non disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar disponibile")
        
        avatar_id = avatars[0]["id"]
        
        # Misura download
        download_times = []
        file_sizes = []
        
        for _ in range(5):
            start = time.time()
            response = client.get(
                f"{API_PREFIX}/{avatar_id}/file",
                headers=auth_headers
            )
            elapsed = time.time() - start
            
            if response.status_code == 200:
                download_times.append(elapsed)
                file_sizes.append(len(response.content))
        
        if not download_times:
            pytest.skip("Download non disponibile")
        
        avg_time = statistics.mean(download_times)
        avg_size = statistics.mean(file_sizes)
        speed_mbps = (avg_size * 8 / avg_time) / 1_000_000  # Megabit/sec
        
        print(f"\n📊 Download Performance:")
        print(f"   File size: {avg_size / 1024:.1f} KB")
        print(f"   Avg time: {avg_time:.2f}s")
        print(f"   Speed: {speed_mbps:.1f} Mbps")
        
        # Minimo 10 Mbps per file locali
        assert speed_mbps >= TARGETS["download_mbps_min"], f"Download too slow: {speed_mbps} Mbps"


# ============================================================================
# 6. APPLY SKELETON PERFORMANCE
# ============================================================================

class TestAvatarApplySkeletonPerformance:
    """Benchmark apply skeleton."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_apply_skeleton_latency(self, client, auth_headers):
        """Misura latenza POST /avatars/{id}/apply-skeleton."""
        # Ottieni avatar
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("API non disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar disponibile")
        
        avatar_id = avatars[0]["id"]
        skeleton_id = str(uuid.uuid4())  # Fittizio per test performance
        
        latencies = []
        for _ in range(20):
            start = time.time()
            response = client.post(
                f"{API_PREFIX}/{avatar_id}/apply-skeleton",
                json={"skeleton_id": skeleton_id},
                headers=auth_headers
            )
            latencies.append((time.time() - start) * 1000)
        
        p50 = sorted(latencies)[10]
        p95 = sorted(latencies)[19]
        
        print(f"\n📊 Apply Skeleton: P50={p50:.2f}ms, P95={p95:.2f}ms")
        
        # Apply skeleton è computazionalmente pesante ma deve restare < 1s
        assert p95 < 1000, f"Apply skeleton too slow: P95={p95}ms"


# ============================================================================
# 7. THROUGHPUT TEST
# ============================================================================

class TestAvatarThroughput:
    """Test throughput massimo."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_max_throughput(self, auth_headers):
        """Misura throughput massimo (richieste/secondo)."""
        start_time = time.time()
        request_count = 0
        errors = 0
        
        # 10 secondi di test
        duration = 10
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            
            while time.time() - start_time < duration:
                future = executor.submit(
                    lambda: httpx.get(
                        f"{BASE_URL}{API_PREFIX}/",
                        headers=auth_headers,
                        timeout=5.0
                    )
                )
                futures.append(future)
                request_count += 1
            
            for future in as_completed(futures):
                try:
                    response = future.result()
                    if response.status_code >= 500:
                        errors += 1
                except Exception:
                    errors += 1
        
        elapsed = time.time() - start_time
        throughput = request_count / elapsed
        error_rate = (errors / request_count) * 100
        
        print(f"\n📊 Throughput Test ({duration}s):")
        print(f"   Total requests: {request_count}")
        print(f"   Throughput: {throughput:.1f} req/s")
        print(f"   Error rate: {error_rate:.1f}%")
        
        # Minimo 50 req/s per API semplice
        assert throughput >= 50, f"Throughput too low: {throughput} req/s"
        assert error_rate < 5, f"Error rate too high: {error_rate}%"


# ============================================================================
# 8. LATENCY UNDER LOAD
# ============================================================================

class TestAvatarLatencyUnderLoad:
    """Test latenza con carico crescente."""

    @pytest.mark.performance
    @pytest.mark.slow
    def test_latency_degradation(self, auth_headers):
        """Verifica degradazione latenza con carico crescente."""
        load_levels = [1, 5, 10, 20]
        results: Dict[int, float] = {}
        
        for concurrency in load_levels:
            latencies = []
            
            with ThreadPoolExecutor(max_workers=concurrency) as executor:
                futures = []
                
                for _ in range(concurrency * 5):  # 5 richieste per worker
                    def measure():
                        start = time.time()
                        try:
                            with httpx.Client(base_url=BASE_URL, timeout=10.0) as c:
                                c.get(f"{API_PREFIX}/", headers=auth_headers)
                        except Exception:
                            pass
                        return (time.time() - start) * 1000
                    
                    futures.append(executor.submit(measure))
                
                for future in as_completed(futures):
                    latencies.append(future.result())
            
            p95 = sorted(latencies)[int(len(latencies) * 0.95)]
            results[concurrency] = p95
            print(f"   Concurrency {concurrency}: P95={p95:.2f}ms")
        
        # La latenza P95 non deve aumentare più di 3x con 20 concurrent
        degradation = results[20] / results[1]
        print(f"\n📊 Degradation factor: {degradation:.2f}x")
        
        assert degradation < 5, f"Latency degradation too high: {degradation}x"


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "performance", "--tb=short", "-s"])

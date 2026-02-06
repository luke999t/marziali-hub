"""
AI_MODULE: Avatar Stress Tests - Enterprise Suite
AI_DESCRIPTION: Test carico e concorrenza per Avatar API
AI_TEACHING: I test stress verificano che l'API gestisca:
             - Richieste concorrenti multiple (100+ simultanee)
             - Upload paralleli di file grandi
             - Picchi di traffico sulla lista avatar
             - Download simultanei di file GLB
             - Apply skeleton sotto carico

ZERO MOCK: Tutti i test chiamano il backend REALE su localhost:8000
"""

import pytest
import httpx
import asyncio
import uuid
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

# ============================================================================
# CONFIGURAZIONE
# ============================================================================

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/avatars"

# Parametri stress test
CONCURRENT_REQUESTS = 50
HEAVY_LOAD_REQUESTS = 100
MAX_RESPONSE_TIME_MS = 500
STRESS_TIMEOUT_SECONDS = 60


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Client HTTP sincrono."""
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

def make_request(url: str, headers: dict, method: str = "GET", **kwargs) -> Tuple[int, float]:
    """
    Esegue una richiesta e ritorna (status_code, response_time_ms).
    """
    start = time.time()
    try:
        with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
            if method == "GET":
                response = client.get(url, headers=headers, **kwargs)
            elif method == "POST":
                response = client.post(url, headers=headers, **kwargs)
            else:
                response = client.request(method, url, headers=headers, **kwargs)
        elapsed_ms = (time.time() - start) * 1000
        return response.status_code, elapsed_ms
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        return 500, elapsed_ms


# ============================================================================
# 1. CONCURRENT LIST REQUESTS
# ============================================================================

class TestAvatarConcurrentList:
    """Test richieste lista avatar concorrenti."""

    @pytest.mark.stress
    @pytest.mark.timeout(STRESS_TIMEOUT_SECONDS)
    def test_concurrent_list_requests(self, auth_headers):
        """50 richieste GET /avatars/ simultanee."""
        results: List[Tuple[int, float]] = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(make_request, f"{API_PREFIX}/", auth_headers)
                for _ in range(CONCURRENT_REQUESTS)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Analisi risultati
        success_count = sum(1 for status, _ in results if status == 200)
        avg_time = sum(t for _, t in results) / len(results)
        max_time = max(t for _, t in results)
        
        print(f"\n📊 Concurrent List Results:")
        print(f"   Total requests: {len(results)}")
        print(f"   Successful: {success_count}")
        print(f"   Avg response time: {avg_time:.2f}ms")
        print(f"   Max response time: {max_time:.2f}ms")
        
        # Assertions
        assert success_count >= CONCURRENT_REQUESTS * 0.95, f"Too many failures: {CONCURRENT_REQUESTS - success_count}"
        assert avg_time < MAX_RESPONSE_TIME_MS, f"Avg response time too high: {avg_time}ms"

    @pytest.mark.stress
    @pytest.mark.timeout(STRESS_TIMEOUT_SECONDS * 2)
    def test_heavy_load_list_requests(self, auth_headers):
        """100 richieste GET /avatars/ sotto carico pesante."""
        results: List[Tuple[int, float]] = []
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = [
                executor.submit(make_request, f"{API_PREFIX}/", auth_headers)
                for _ in range(HEAVY_LOAD_REQUESTS)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        success_count = sum(1 for status, _ in results if status == 200)
        error_count = sum(1 for status, _ in results if status >= 500)
        
        print(f"\n📊 Heavy Load Results:")
        print(f"   Total: {len(results)}, Success: {success_count}, Errors: {error_count}")
        
        # Sotto carico pesante accettiamo 90% success rate
        assert success_count >= HEAVY_LOAD_REQUESTS * 0.90
        # Mai più del 5% errori server
        assert error_count <= HEAVY_LOAD_REQUESTS * 0.05

    @pytest.mark.stress
    def test_concurrent_list_with_filters(self, auth_headers):
        """Richieste concorrenti con filtri diversi."""
        styles = ["karate", "kung_fu", "taekwondo", "judo", "generic"]
        results: List[Tuple[int, float]] = []
        
        def request_with_style(style: str):
            return make_request(
                f"{API_PREFIX}/",
                auth_headers,
                params={"style": style, "page": 1, "page_size": 10}
            )
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _ in range(10):  # 10 round
                for style in styles:
                    futures.append(executor.submit(request_with_style, style))
            
            for future in as_completed(futures):
                results.append(future.result())
        
        success_count = sum(1 for status, _ in results if status == 200)
        assert success_count >= len(results) * 0.95


# ============================================================================
# 2. CONCURRENT DETAIL REQUESTS
# ============================================================================

class TestAvatarConcurrentDetail:
    """Test richieste dettaglio avatar concorrenti."""

    @pytest.mark.stress
    def test_concurrent_detail_same_avatar(self, client, auth_headers):
        """50 richieste GET /avatars/{id} stesso avatar."""
        # Prima ottieni un avatar esistente
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("Nessun avatar disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar nel database")
        
        avatar_id = avatars[0]["id"]
        results: List[Tuple[int, float]] = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(make_request, f"{API_PREFIX}/{avatar_id}", auth_headers)
                for _ in range(CONCURRENT_REQUESTS)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        success_count = sum(1 for status, _ in results if status == 200)
        assert success_count >= CONCURRENT_REQUESTS * 0.95

    @pytest.mark.stress
    def test_concurrent_detail_nonexistent_avatars(self, auth_headers):
        """50 richieste a UUID inesistenti (test 404 handling)."""
        results: List[Tuple[int, float]] = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(
                    make_request,
                    f"{API_PREFIX}/{uuid.uuid4()}",
                    auth_headers
                )
                for _ in range(CONCURRENT_REQUESTS)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Tutti devono essere 404, nessun crash
        not_found_count = sum(1 for status, _ in results if status == 404)
        error_count = sum(1 for status, _ in results if status >= 500)
        
        assert not_found_count >= CONCURRENT_REQUESTS * 0.95
        assert error_count == 0, "Server errors su UUID inesistenti"


# ============================================================================
# 3. FILE DOWNLOAD STRESS
# ============================================================================

class TestAvatarDownloadStress:
    """Test download file GLB sotto carico."""

    @pytest.mark.stress
    @pytest.mark.timeout(STRESS_TIMEOUT_SECONDS)
    def test_concurrent_file_downloads(self, client, auth_headers):
        """20 download simultanei dello stesso file GLB."""
        # Ottieni avatar con file
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("API non disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar disponibile")
        
        avatar_id = avatars[0]["id"]
        results: List[Tuple[int, float]] = []
        
        def download_file():
            start = time.time()
            try:
                with httpx.Client(base_url=BASE_URL, timeout=60.0) as c:
                    response = c.get(
                        f"{API_PREFIX}/{avatar_id}/file",
                        headers=auth_headers
                    )
                elapsed = (time.time() - start) * 1000
                return response.status_code, elapsed, len(response.content)
            except Exception:
                return 500, (time.time() - start) * 1000, 0
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(download_file) for _ in range(20)]
            
            for future in as_completed(futures):
                status, elapsed, size = future.result()
                results.append((status, elapsed))
        
        success_count = sum(1 for status, _ in results if status in [200, 404])
        print(f"\n📊 Download Stress: {success_count}/20 successful")
        
        assert success_count >= 18  # Almeno 90%


# ============================================================================
# 4. BONE MAPPING STRESS
# ============================================================================

class TestAvatarBoneMappingStress:
    """Test bone mapping endpoint sotto carico."""

    @pytest.mark.stress
    def test_concurrent_bone_mapping_requests(self, auth_headers):
        """50 richieste GET /avatars/bone-mapping simultanee."""
        results: List[Tuple[int, float]] = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [
                executor.submit(make_request, f"{API_PREFIX}/bone-mapping", auth_headers)
                for _ in range(CONCURRENT_REQUESTS)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        success_count = sum(1 for status, _ in results if status == 200)
        avg_time = sum(t for _, t in results) / len(results)
        
        print(f"\n📊 Bone Mapping Stress: {success_count}/{CONCURRENT_REQUESTS}")
        print(f"   Avg time: {avg_time:.2f}ms")
        
        assert success_count >= CONCURRENT_REQUESTS * 0.95
        # Bone mapping deve essere veloce (cache)
        assert avg_time < 100, "Bone mapping troppo lento"


# ============================================================================
# 5. APPLY SKELETON STRESS
# ============================================================================

class TestAvatarApplySkeletonStress:
    """Test apply-skeleton sotto carico."""

    @pytest.mark.stress
    @pytest.mark.slow
    def test_concurrent_apply_skeleton(self, client, auth_headers):
        """20 richieste POST /avatars/{id}/apply-skeleton simultanee."""
        # Ottieni avatar
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        if list_response.status_code != 200:
            pytest.skip("API non disponibile")
        
        avatars = list_response.json().get("items", [])
        if not avatars:
            pytest.skip("Nessun avatar disponibile")
        
        avatar_id = avatars[0]["id"]
        
        # Skeleton ID fittizio (il test verifica la gestione del carico)
        skeleton_id = str(uuid.uuid4())
        results: List[Tuple[int, float]] = []
        
        def apply_skeleton():
            return make_request(
                f"{API_PREFIX}/{avatar_id}/apply-skeleton",
                auth_headers,
                method="POST",
                json={"skeleton_id": skeleton_id}
            )
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(apply_skeleton) for _ in range(20)]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Può essere 200 (success) o 404 (skeleton not found) - mai 500
        valid_count = sum(1 for status, _ in results if status in [200, 404, 422])
        error_count = sum(1 for status, _ in results if status >= 500)
        
        assert error_count == 0, "Server errors durante apply-skeleton"
        assert valid_count >= 18


# ============================================================================
# 6. MIXED WORKLOAD STRESS
# ============================================================================

class TestAvatarMixedWorkload:
    """Test carico misto (list + detail + download)."""

    @pytest.mark.stress
    @pytest.mark.timeout(STRESS_TIMEOUT_SECONDS * 2)
    def test_mixed_concurrent_operations(self, client, auth_headers):
        """Simulazione traffico reale con operazioni miste."""
        # Ottieni dati iniziali
        list_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
        avatar_id = None
        if list_response.status_code == 200:
            avatars = list_response.json().get("items", [])
            if avatars:
                avatar_id = avatars[0]["id"]
        
        results = {"list": [], "detail": [], "mapping": [], "styles": []}
        
        def mixed_request(op_type: str):
            if op_type == "list":
                return make_request(f"{API_PREFIX}/", auth_headers)
            elif op_type == "detail" and avatar_id:
                return make_request(f"{API_PREFIX}/{avatar_id}", auth_headers)
            elif op_type == "mapping":
                return make_request(f"{API_PREFIX}/bone-mapping", auth_headers)
            elif op_type == "styles":
                return make_request(f"{API_PREFIX}/styles", auth_headers)
            else:
                return make_request(f"{API_PREFIX}/", auth_headers)
        
        # Distribuzione realistica: 50% list, 30% detail, 10% mapping, 10% styles
        operations = (
            ["list"] * 25 +
            ["detail"] * 15 +
            ["mapping"] * 5 +
            ["styles"] * 5
        )
        
        with ThreadPoolExecutor(max_workers=15) as executor:
            futures = {
                executor.submit(mixed_request, op): op
                for op in operations
            }
            
            for future in as_completed(futures):
                op_type = futures[future]
                results[op_type].append(future.result())
        
        # Analisi per tipo
        total_success = 0
        total_requests = 0
        for op_type, op_results in results.items():
            if op_results:
                success = sum(1 for s, _ in op_results if s in [200, 404])
                total_success += success
                total_requests += len(op_results)
                print(f"   {op_type}: {success}/{len(op_results)} OK")
        
        print(f"\n📊 Mixed Workload: {total_success}/{total_requests} total")
        
        # Almeno 90% success rate complessivo
        assert total_success >= total_requests * 0.90


# ============================================================================
# 7. RATE LIMITING BEHAVIOR
# ============================================================================

class TestAvatarRateLimiting:
    """Test comportamento sotto rate limiting."""

    @pytest.mark.stress
    def test_rapid_fire_requests(self, auth_headers):
        """200 richieste rapidissime per testare rate limiting."""
        results: List[Tuple[int, float]] = []
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [
                executor.submit(make_request, f"{API_PREFIX}/", auth_headers)
                for _ in range(200)
            ]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        elapsed = time.time() - start_time
        
        success_count = sum(1 for status, _ in results if status == 200)
        rate_limited = sum(1 for status, _ in results if status == 429)
        errors = sum(1 for status, _ in results if status >= 500)
        
        print(f"\n📊 Rapid Fire Results ({elapsed:.2f}s):")
        print(f"   Success: {success_count}")
        print(f"   Rate limited (429): {rate_limited}")
        print(f"   Server errors: {errors}")
        
        # Se c'è rate limiting, deve usare 429, non 500
        assert errors <= 5, "Troppi server errors - sistema instabile"


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "stress", "--tb=short", "-s"])

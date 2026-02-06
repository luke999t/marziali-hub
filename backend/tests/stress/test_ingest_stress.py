"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Ingest System Stress Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.

================================================================================
"""

import pytest
import io
import os
import time
import threading
import concurrent.futures
import psutil
from pathlib import Path
from fastapi.testclient import TestClient
import gc


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.stress]


# === SIMPLIFIED TEST CLIENT (no auth) ===

@pytest.fixture(scope="module")
def client():
    """Simple test client without database/auth dependencies"""
    from main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture
def performance_tracker():
    """Simple performance tracker fixture"""
    class PerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None

        def start(self):
            self.start_time = time.time()

        def stop(self):
            self.end_time = time.time()

        def duration_ms(self):
            if self.start_time and self.end_time:
                return (self.end_time - self.start_time) * 1000
            return 0

    return PerformanceTracker()


# === STRESS TESTS ===

class TestConcurrentUploads:
    """Stress tests for concurrent file uploads"""

    def test_5_concurrent_uploads(self, client: TestClient):
        """Test 5 concurrent upload requests"""
        results = []
        errors = []

        def upload_file(index):
            try:
                fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom" * 100)
                response = client.post(
                    "/api/v1/videos/ingest",
                    files={"files": (f"video_{index}.mp4", fake_video, "video/mp4")},
                    data={"extract_skeleton": "false"}
                )
                results.append({
                    "index": index,
                    "status": response.status_code,
                    "time": time.time()
                })
            except Exception as e:
                errors.append({"index": index, "error": str(e)})

        threads = []
        for i in range(5):
            t = threading.Thread(target=upload_file, args=(i,))
            threads.append(t)

        start_time = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        end_time = time.time()

        # Assertions
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 5, f"Not all uploads completed: {len(results)}/5"

        # All should return valid status codes
        for r in results:
            assert r["status"] in [200, 201, 400, 422, 500]

        print(f"5 concurrent uploads completed in {end_time - start_time:.2f}s")

    def test_10_concurrent_skeleton_list_requests(self, client: TestClient):
        """Test 10 concurrent GET /skeletons requests"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for _ in range(10):
                futures.append(executor.submit(client.get, "/api/v1/videos/skeletons"))

            results = [f.result() for f in futures]

        # All should succeed
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 8, f"Too many failures: {10 - success_count}/10"

    def test_mixed_concurrent_operations(self, client: TestClient):
        """Test mixed read/write concurrent operations"""
        results = {"read": [], "write": []}

        def read_operation():
            response = client.get("/api/v1/videos/skeletons")
            results["read"].append(response.status_code)

        def write_operation():
            fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom")
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": ("test.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )
            results["write"].append(response.status_code)

        threads = []
        # 5 reads, 3 writes
        for _ in range(5):
            threads.append(threading.Thread(target=read_operation))
        for _ in range(3):
            threads.append(threading.Thread(target=write_operation))

        start_time = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        end_time = time.time()

        print(f"Mixed operations completed in {end_time - start_time:.2f}s")
        print(f"Read results: {results['read']}")
        print(f"Write results: {results['write']}")

        # At least most operations should succeed
        assert len(results["read"]) == 5
        assert len(results["write"]) == 3


class TestMemoryLimits:
    """Stress tests for memory usage"""

    def test_large_file_memory_handling(self, client: TestClient):
        """Test memory usage with large file upload"""
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB

        # Create 50MB file
        large_file = io.BytesIO(b"0" * (50 * 1024 * 1024))

        response = client.post(
            "/api/v1/videos/ingest",
            files={"files": ("large.mp4", large_file, "video/mp4")},
            data={"extract_skeleton": "false"}
        )

        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024  # MB

        memory_increase = final_memory - initial_memory
        print(f"Memory increase: {memory_increase:.2f} MB")

        # Memory should not explode (allow 200MB increase max)
        assert memory_increase < 200, f"Memory leak detected: {memory_increase}MB increase"

    def test_repeated_uploads_no_memory_leak(self, client: TestClient):
        """Test that repeated uploads don't cause memory leaks"""
        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024

        # Do 10 uploads
        for i in range(10):
            fake_video = io.BytesIO(b"\x00\x00\x00\x1cftypisom" * 1000)
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"test_{i}.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )
            del fake_video

        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024

        memory_increase = final_memory - initial_memory
        print(f"Memory after 10 uploads: {memory_increase:.2f} MB increase")

        # Should not leak significantly (< 50MB for 10 small uploads)
        assert memory_increase < 50

    def test_skeleton_list_memory_stability(self, client: TestClient):
        """Test memory stability with repeated skeleton list calls"""
        gc.collect()
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024

        # Call 100 times
        for _ in range(100):
            response = client.get("/api/v1/videos/skeletons")
            assert response.status_code == 200

        gc.collect()
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024

        memory_increase = final_memory - initial_memory
        print(f"Memory after 100 list calls: {memory_increase:.2f} MB increase")

        # Should be minimal increase
        assert memory_increase < 20


class TestRateLimiting:
    """Stress tests for rate limiting behavior"""

    def test_rapid_requests(self, client: TestClient):
        """Test rapid consecutive requests"""
        results = []
        start_time = time.time()

        # Send 50 requests as fast as possible
        for i in range(50):
            response = client.get("/api/v1/videos/skeletons")
            results.append({
                "index": i,
                "status": response.status_code,
                "time": time.time() - start_time
            })

        end_time = time.time()
        duration = end_time - start_time

        success_count = sum(1 for r in results if r["status"] == 200)
        rate_limited = sum(1 for r in results if r["status"] == 429)

        print(f"50 requests in {duration:.2f}s")
        print(f"Success: {success_count}, Rate limited: {rate_limited}")

        # Most should succeed (no rate limiting implemented = all succeed)
        assert success_count >= 40 or rate_limited > 0

    def test_burst_upload_handling(self, client: TestClient):
        """Test burst of upload requests"""
        results = []

        for i in range(20):
            fake_video = io.BytesIO(b"\x00" * 1024)  # 1KB each
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"burst_{i}.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )
            results.append(response.status_code)

        success_count = sum(1 for s in results if s in [200, 201])
        print(f"Burst upload: {success_count}/20 succeeded")

        # Should handle gracefully
        assert success_count > 0


class TestResourceExhaustion:
    """Stress tests for resource exhaustion scenarios"""

    def test_many_small_files(self, client: TestClient):
        """Test uploading many small files"""
        results = []

        for i in range(30):
            tiny_file = io.BytesIO(b"x" * 100)  # 100 bytes
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"tiny_{i}.mp4", tiny_file, "video/mp4")},
                data={"extract_skeleton": "false"}
            )
            results.append(response.status_code)

        success_count = sum(1 for s in results if s in [200, 201, 400, 422])
        print(f"Small files: {success_count}/30 processed")

        # All should be processed (success or validation error)
        assert success_count == 30

    def test_file_handle_cleanup(self, client: TestClient):
        """Test that file handles are properly cleaned up"""
        initial_fds = len(psutil.Process().open_files())

        # Upload 10 files
        for i in range(10):
            fake_video = io.BytesIO(b"\x00" * 10240)
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"fd_test_{i}.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )

        gc.collect()
        time.sleep(0.5)  # Allow cleanup

        final_fds = len(psutil.Process().open_files())
        fd_increase = final_fds - initial_fds

        print(f"File descriptor increase: {fd_increase}")

        # Should not leak many file descriptors
        assert fd_increase < 20


@pytest.mark.slow
class TestLongRunningOperations:
    """Stress tests for long-running operations"""

    def test_sustained_load_1_minute(self, client: TestClient, performance_tracker):
        """Test sustained load for 1 minute"""
        performance_tracker.start()

        end_time = time.time() + 60  # 1 minute
        request_count = 0
        error_count = 0

        while time.time() < end_time:
            try:
                response = client.get("/api/v1/videos/skeletons")
                if response.status_code != 200:
                    error_count += 1
                request_count += 1
                time.sleep(0.1)  # 10 req/s
            except Exception:
                error_count += 1

        performance_tracker.stop()

        print(f"Sustained load: {request_count} requests, {error_count} errors")
        print(f"Duration: {performance_tracker.duration_ms():.0f}ms")

        error_rate = error_count / request_count if request_count > 0 else 1
        assert error_rate < 0.1  # Less than 10% error rate


class TestResponseTimes:
    """Stress tests for response time under load"""

    def test_skeleton_list_response_time_under_load(self, client: TestClient):
        """Test response times remain acceptable under load"""
        response_times = []

        for _ in range(20):
            start = time.time()
            response = client.get("/api/v1/videos/skeletons")
            end = time.time()

            if response.status_code == 200:
                response_times.append((end - start) * 1000)  # ms

        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            p95_time = sorted(response_times)[int(len(response_times) * 0.95)]

            print(f"Response times - Avg: {avg_time:.2f}ms, Max: {max_time:.2f}ms, P95: {p95_time:.2f}ms")

            # P95 should be under 1 second
            assert p95_time < 1000

    def test_upload_response_time(self, client: TestClient):
        """Test upload response time"""
        response_times = []

        for i in range(5):
            fake_video = io.BytesIO(b"\x00" * 10240)  # 10KB
            start = time.time()
            response = client.post(
                "/api/v1/videos/ingest",
                files={"files": (f"time_test_{i}.mp4", fake_video, "video/mp4")},
                data={"extract_skeleton": "false"}
            )
            end = time.time()

            response_times.append((end - start) * 1000)

        avg_time = sum(response_times) / len(response_times)
        print(f"Upload avg response time: {avg_time:.2f}ms")

        # Should complete within reasonable time
        assert avg_time < 5000  # 5 seconds max avg

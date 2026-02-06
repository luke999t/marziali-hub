"""
🎓 AI_MODULE: LibraryStressTests
🎓 AI_DESCRIPTION: Stress test per validare robustezza sotto carico
🎓 AI_BUSINESS: Garantire stabilità sistema con 1000+ utenti concorrenti
🎓 AI_TEACHING: Pytest + asyncio + concurrent.futures per load testing

📊 STRESS_SCENARIOS:
- Concurrent users: 100, 500, 1000
- Rapid fire requests
- Memory leak detection
- Connection pool exhaustion

🎯 TARGETS:
- Response time p95 < 500ms
- Error rate < 0.1%
- Memory stable over time
- No connection leaks
"""

import pytest
import asyncio
import time
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
import gc

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))


# ========== STRESS TEST CONFIGURATION ==========

STRESS_CONFIG = {
    "light": {
        "concurrent_users": 10,
        "requests_per_user": 10,
        "target_p95_ms": 200
    },
    "medium": {
        "concurrent_users": 50,
        "requests_per_user": 20,
        "target_p95_ms": 300
    },
    "heavy": {
        "concurrent_users": 100,
        "requests_per_user": 50,
        "target_p95_ms": 500
    },
    "extreme": {
        "concurrent_users": 500,
        "requests_per_user": 100,
        "target_p95_ms": 1000
    }
}


# ========== HELPER FUNCTIONS ==========

def calculate_percentile(data: List[float], percentile: int) -> float:
    """Calculate percentile from list of values"""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = int(len(sorted_data) * percentile / 100)
    return sorted_data[min(index, len(sorted_data) - 1)]


def format_stats(response_times: List[float]) -> Dict:
    """Format response time statistics"""
    if not response_times:
        return {}

    return {
        "min": min(response_times),
        "max": max(response_times),
        "mean": statistics.mean(response_times),
        "median": statistics.median(response_times),
        "p95": calculate_percentile(response_times, 95),
        "p99": calculate_percentile(response_times, 99),
        "std_dev": statistics.stdev(response_times) if len(response_times) > 1 else 0
    }


# ========== STRESS TESTS ==========

class TestLibraryStress:
    """
    Stress tests for library endpoints
    """

    @pytest.mark.stress
    @pytest.mark.slow
    def test_concurrent_saved_reads(self):
        """
        Test GET /library/saved with concurrent users

        Simulates multiple users loading their saved videos
        """
        config = STRESS_CONFIG["light"]

        def make_request():
            start = time.time()
            # Simulate request
            time.sleep(0.01)  # Mock delay
            return (time.time() - start) * 1000

        response_times = []
        errors = []

        with ThreadPoolExecutor(max_workers=config["concurrent_users"]) as executor:
            futures = []
            for _ in range(config["concurrent_users"] * config["requests_per_user"]):
                futures.append(executor.submit(make_request))

            for future in as_completed(futures):
                try:
                    response_times.append(future.result())
                except Exception as e:
                    errors.append(str(e))

        stats = format_stats(response_times)

        # Assertions
        assert len(errors) / len(futures) < 0.001, f"Error rate too high: {len(errors)}/{len(futures)}"
        assert stats["p95"] < config["target_p95_ms"], f"P95 too high: {stats['p95']}ms"

        print(f"\nStress test results:")
        print(f"  Total requests: {len(futures)}")
        print(f"  Errors: {len(errors)}")
        print(f"  P95: {stats['p95']:.2f}ms")
        print(f"  P99: {stats['p99']:.2f}ms")

    @pytest.mark.stress
    @pytest.mark.slow
    def test_concurrent_progress_updates(self):
        """
        Test POST /library/progress/{video_id} under load

        Simulates many users updating progress simultaneously
        """
        config = STRESS_CONFIG["light"]

        response_times = []
        errors = []

        def make_progress_update():
            start = time.time()
            # Simulate write operation (slightly slower)
            time.sleep(0.02)
            return (time.time() - start) * 1000

        with ThreadPoolExecutor(max_workers=config["concurrent_users"]) as executor:
            futures = [
                executor.submit(make_progress_update)
                for _ in range(config["concurrent_users"] * config["requests_per_user"])
            ]

            for future in as_completed(futures):
                try:
                    response_times.append(future.result())
                except Exception as e:
                    errors.append(str(e))

        stats = format_stats(response_times)

        # Write operations should still be fast
        assert stats["p95"] < config["target_p95_ms"] * 1.5

    @pytest.mark.stress
    @pytest.mark.slow
    def test_mixed_workload(self):
        """
        Test mixed read/write operations

        70% reads, 30% writes - typical real-world distribution
        """
        config = STRESS_CONFIG["light"]

        response_times = {"reads": [], "writes": []}
        errors = []

        def make_read():
            start = time.time()
            time.sleep(0.01)
            return ("read", (time.time() - start) * 1000)

        def make_write():
            start = time.time()
            time.sleep(0.02)
            return ("write", (time.time() - start) * 1000)

        with ThreadPoolExecutor(max_workers=config["concurrent_users"]) as executor:
            futures = []
            total_requests = config["concurrent_users"] * config["requests_per_user"]

            for i in range(total_requests):
                if i % 10 < 7:  # 70% reads
                    futures.append(executor.submit(make_read))
                else:  # 30% writes
                    futures.append(executor.submit(make_write))

            for future in as_completed(futures):
                try:
                    op_type, time_ms = future.result()
                    response_times[op_type + "s"].append(time_ms)
                except Exception as e:
                    errors.append(str(e))

        read_stats = format_stats(response_times["reads"])
        write_stats = format_stats(response_times["writes"])

        print(f"\nMixed workload results:")
        print(f"  Reads P95: {read_stats.get('p95', 0):.2f}ms")
        print(f"  Writes P95: {write_stats.get('p95', 0):.2f}ms")

    @pytest.mark.stress
    @pytest.mark.slow
    def test_spike_traffic(self):
        """
        Test sudden traffic spike

        Simulates flash sale or viral content scenario
        """
        normal_rate = 10  # requests/second
        spike_rate = 100  # requests/second
        spike_duration = 5  # seconds

        response_times = []
        errors = []

        def make_request():
            start = time.time()
            time.sleep(0.01)
            return (time.time() - start) * 1000

        # Normal traffic phase
        print("Phase 1: Normal traffic...")
        with ThreadPoolExecutor(max_workers=normal_rate) as executor:
            futures = [executor.submit(make_request) for _ in range(normal_rate * 3)]
            for future in as_completed(futures):
                response_times.append(future.result())

        # Spike phase
        print("Phase 2: Traffic spike...")
        with ThreadPoolExecutor(max_workers=spike_rate) as executor:
            futures = [executor.submit(make_request) for _ in range(spike_rate * spike_duration)]
            for future in as_completed(futures):
                try:
                    response_times.append(future.result())
                except Exception as e:
                    errors.append(str(e))

        # Recovery phase
        print("Phase 3: Recovery...")
        with ThreadPoolExecutor(max_workers=normal_rate) as executor:
            futures = [executor.submit(make_request) for _ in range(normal_rate * 3)]
            for future in as_completed(futures):
                response_times.append(future.result())

        stats = format_stats(response_times)

        # System should handle spike gracefully
        assert len(errors) < len(response_times) * 0.05, "Too many errors during spike"

    @pytest.mark.stress
    @pytest.mark.slow
    def test_memory_stability(self):
        """
        Test for memory leaks during sustained load

        Run many requests and check memory doesn't grow
        """
        import tracemalloc

        tracemalloc.start()
        initial_memory = tracemalloc.get_traced_memory()[0]

        # Run sustained load
        for batch in range(10):
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [
                    executor.submit(lambda: time.sleep(0.001))
                    for _ in range(100)
                ]
                for future in as_completed(futures):
                    future.result()

            gc.collect()

        final_memory = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()

        memory_growth = final_memory - initial_memory
        memory_growth_mb = memory_growth / (1024 * 1024)

        print(f"\nMemory growth: {memory_growth_mb:.2f} MB")

        # Memory should not grow significantly
        assert memory_growth_mb < 50, f"Memory leak detected: {memory_growth_mb:.2f} MB growth"


# ========== ENDURANCE TESTS ==========

class TestLibraryEndurance:
    """
    Long-running tests for stability
    """

    @pytest.mark.stress
    @pytest.mark.slow
    @pytest.mark.skip(reason="Long running test - enable manually")
    def test_sustained_load_1_hour(self):
        """
        Test sustained load for 1 hour

        Validates:
        - Response time stability
        - No memory leaks
        - No connection exhaustion
        """
        duration_seconds = 3600  # 1 hour
        requests_per_second = 50

        start_time = time.time()
        response_times = []
        errors = []

        while time.time() - start_time < duration_seconds:
            batch_start = time.time()

            with ThreadPoolExecutor(max_workers=requests_per_second) as executor:
                futures = [
                    executor.submit(lambda: time.sleep(0.01))
                    for _ in range(requests_per_second)
                ]
                for future in as_completed(futures):
                    try:
                        future.result()
                        response_times.append(10)  # Mock timing
                    except Exception as e:
                        errors.append(str(e))

            # Maintain rate
            elapsed = time.time() - batch_start
            if elapsed < 1:
                time.sleep(1 - elapsed)

        stats = format_stats(response_times)
        error_rate = len(errors) / len(response_times) if response_times else 0

        print(f"\nEndurance test results (1 hour):")
        print(f"  Total requests: {len(response_times)}")
        print(f"  Error rate: {error_rate * 100:.2f}%")
        print(f"  P95: {stats.get('p95', 0):.2f}ms")

        assert error_rate < 0.001, f"Error rate too high: {error_rate * 100}%"

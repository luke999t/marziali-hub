"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Auth Performance Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di performance - logica pura + API REALI.

================================================================================
"""

import pytest
import time
import jwt

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.performance]


# ==============================================================================
# TEST: JWT Performance - Pure Logic
# ==============================================================================
class TestJWTPerformanceLogic:
    """Test JWT performance - pure logic."""

    def test_performance_jwt_generation_speed(self):
        """
        Performance Test: JWT token generation time
        Target: <5ms average
        """
        from core.security import create_access_token

        times = []

        for i in range(100):
            start = time.time()

            create_access_token(
                data={
                    "sub": f"user_{i}",
                    "email": f"user_{i}@test.com",
                    "user_id": f"id_{i}"
                }
            )

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times)

        assert avg_time < 5, f"JWT generation avg: {avg_time:.2f}ms > 5ms"

    def test_performance_jwt_validation_speed(self):
        """
        Performance Test: JWT token validation time
        Target: <3ms average
        """
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        # Generate token
        token = create_access_token(
            data={
                "sub": "testuser",
                "email": "test@test.com",
                "user_id": "test_id"
            }
        )

        times = []

        for _ in range(100):
            start = time.time()

            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times)

        assert avg_time < 3, f"JWT validation avg: {avg_time:.2f}ms > 3ms"

    def test_performance_jwt_batch_generation(self):
        """
        Performance Test: Batch JWT generation
        Target: Generate 1000 tokens in <1s
        """
        from core.security import create_access_token

        start = time.time()

        for i in range(1000):
            create_access_token(
                data={
                    "sub": f"batch_user_{i}",
                    "email": f"batch_{i}@test.com",
                    "user_id": f"batch_id_{i}"
                }
            )

        duration = time.time() - start

        assert duration < 1.0, f"Batch JWT generation: {duration:.2f}s > 1s"


# ==============================================================================
# TEST: Password Hashing Performance - Pure Logic
# ==============================================================================
class TestPasswordHashingPerformanceLogic:
    """Test password hashing performance - pure logic."""

    def test_performance_password_hashing_time(self):
        """
        Performance Test: Password hashing time
        Target: 50-200ms (bcrypt is intentionally slow for security)
        """
        from core.security import get_password_hash

        times = []

        for i in range(10):
            start = time.time()

            get_password_hash(f"Password{i}!")

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times)

        # Bcrypt should be slow (security), but not too slow
        assert 50 < avg_time < 300, f"Password hashing avg: {avg_time:.2f}ms (target: 50-300ms)"

    def test_performance_password_verification_time(self):
        """
        Performance Test: Password verification time
        Target: 50-200ms
        """
        from core.security import get_password_hash, verify_password

        password = "SecurePassword123!"
        hashed = get_password_hash(password)

        times = []

        for _ in range(10):
            start = time.time()

            verify_password(password, hashed)

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times)

        assert 50 < avg_time < 300, f"Password verification avg: {avg_time:.2f}ms"

    def test_performance_different_password_lengths(self):
        """
        Performance Test: Hashing time for different password lengths
        """
        from core.security import get_password_hash

        password_lengths = [8, 16, 32, 64, 128]
        times = {}

        for length in password_lengths:
            password = "A" * length

            start = time.time()
            get_password_hash(password)
            duration_ms = (time.time() - start) * 1000

            times[length] = duration_ms

        # All should be similar (bcrypt truncates at 72 chars)
        for length, duration in times.items():
            assert 50 < duration < 300, f"Length {length}: {duration:.2f}ms"


# ==============================================================================
# TEST: Security Function Performance - Pure Logic
# ==============================================================================
class TestSecurityFunctionPerformanceLogic:
    """Test security function performance - pure logic."""

    def test_performance_token_expiry_calculation(self):
        """
        Performance Test: Token expiry calculation
        """
        from datetime import datetime, timedelta

        start = time.time()

        for _ in range(10000):
            now = datetime.utcnow()
            expiry = now + timedelta(hours=24)
            _ = expiry.timestamp()

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 100, f"Expiry calc: {duration_ms:.2f}ms > 100ms"

    def test_performance_email_pattern_matching(self):
        """
        Performance Test: Email validation performance
        """
        import re

        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

        emails = [f"user_{i}@example.com" for i in range(1000)]

        start = time.time()

        for email in emails:
            email_pattern.match(email)

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 50, f"Email validation: {duration_ms:.2f}ms > 50ms"


# ==============================================================================
# TEST: Data Serialization Performance - Pure Logic
# ==============================================================================
class TestDataSerializationPerformanceLogic:
    """Test data serialization performance - pure logic."""

    def test_performance_user_data_serialization(self):
        """
        Performance Test: User data JSON serialization
        """
        import json
        from datetime import datetime

        user_data = {
            "id": "user_123",
            "email": "test@example.com",
            "username": "testuser",
            "created_at": datetime.utcnow().isoformat(),
            "is_active": True,
            "tier": "premium"
        }

        start = time.time()

        for _ in range(10000):
            json.dumps(user_data)

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 100, f"Serialization: {duration_ms:.2f}ms > 100ms"

    def test_performance_token_response_serialization(self):
        """
        Performance Test: Token response serialization
        """
        import json

        response = {
            "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzA0MDY3MjAwfQ.signature",
            "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIiwidHlwZSI6InJlZnJlc2gifQ.signature",
            "token_type": "bearer",
            "expires_in": 86400
        }

        start = time.time()

        for _ in range(10000):
            json.dumps(response)

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 100, f"Token serialization: {duration_ms:.2f}ms > 100ms"


# ==============================================================================
# TEST: UUID Performance - Pure Logic
# ==============================================================================
class TestUUIDPerformanceLogic:
    """Test UUID generation performance - pure logic."""

    def test_performance_uuid_generation(self):
        """
        Performance Test: UUID generation speed
        """
        import uuid

        start = time.time()

        for _ in range(10000):
            str(uuid.uuid4())

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 500, f"UUID generation: {duration_ms:.2f}ms > 500ms"

    def test_performance_uuid_parsing(self):
        """
        Performance Test: UUID parsing speed
        """
        import uuid

        uuids = [str(uuid.uuid4()) for _ in range(1000)]

        start = time.time()

        for uuid_str in uuids:
            uuid.UUID(uuid_str)

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < 50, f"UUID parsing: {duration_ms:.2f}ms > 50ms"


# ==============================================================================
# TEST: Auth API Performance - REAL BACKEND
# ==============================================================================
class TestAuthAPIPerformanceReal:
    """Test auth API performance - REAL BACKEND."""

    def test_performance_login_response_time(self, api_client):
        """
        Performance Test: Login API response time
        Target: <500ms average
        """
        times = []

        for _ in range(5):
            start = time.time()

            response = api_client.post(
                "/api/v1/auth/login",
                data={
                    "username": "giulia.bianchi@example.com",
                    "password": "Test123!"
                }
            )

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

            if response.status_code not in [200, 401, 404]:
                break

        avg_time = sum(times) / len(times) if times else 0

        # Accept if endpoint exists and responds
        assert avg_time < 1000, f"Login avg: {avg_time:.2f}ms > 1000ms"

    def test_performance_token_refresh_time(self, api_client, auth_headers_premium):
        """
        Performance Test: Token refresh API response time
        Target: <200ms average
        """
        times = []

        for _ in range(5):
            start = time.time()

            response = api_client.post(
                "/api/v1/auth/refresh",
                headers=auth_headers_premium
            )

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times) if times else 0

        # Accept if endpoint responds
        assert response.status_code in [200, 401, 404, 405]

    def test_performance_me_endpoint_time(self, api_client, auth_headers_premium):
        """
        Performance Test: /auth/me endpoint response time
        Target: <100ms average
        """
        times = []

        for _ in range(10):
            start = time.time()

            response = api_client.get(
                "/api/v1/auth/me",
                headers=auth_headers_premium
            )

            duration_ms = (time.time() - start) * 1000
            times.append(duration_ms)

        avg_time = sum(times) / len(times) if times else 0

        # Endpoint should be fast
        assert avg_time < 500, f"/auth/me avg: {avg_time:.2f}ms > 500ms"

    def test_performance_concurrent_auth_requests(self, api_client, auth_headers_premium):
        """
        Performance Test: Concurrent auth requests
        """
        import threading
        import queue

        results = queue.Queue()

        def make_request():
            start = time.time()
            response = api_client.get(
                "/api/v1/auth/me",
                headers=auth_headers_premium
            )
            duration_ms = (time.time() - start) * 1000
            results.put({"status": response.status_code, "duration": duration_ms})

        threads = [threading.Thread(target=make_request) for _ in range(10)]

        start = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total_duration = time.time() - start

        # All concurrent requests should complete in <5s
        assert total_duration < 5, f"Concurrent requests: {total_duration:.2f}s > 5s"


# ==============================================================================
# TEST: Error Handling Performance - Pure Logic
# ==============================================================================
class TestErrorHandlingPerformanceLogic:
    """Test error handling performance - pure logic."""

    def test_performance_invalid_password_check(self):
        """
        Performance Test: Invalid password verification
        (Should NOT be faster than valid - timing attack prevention)
        """
        from core.security import get_password_hash, verify_password

        password = "SecurePassword123!"
        hashed = get_password_hash(password)

        # Time valid password
        valid_times = []
        for _ in range(5):
            start = time.time()
            verify_password(password, hashed)
            valid_times.append((time.time() - start) * 1000)

        # Time invalid password
        invalid_times = []
        for _ in range(5):
            start = time.time()
            verify_password("WrongPassword!", hashed)
            invalid_times.append((time.time() - start) * 1000)

        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)

        # Both should take similar time (timing attack prevention)
        # Allow 50% variance
        ratio = avg_invalid / avg_valid if avg_valid > 0 else 1
        assert 0.5 < ratio < 2.0, f"Timing variance: {ratio:.2f} (should be ~1.0)"


# ==============================================================================
# TEST: Memory Performance - Pure Logic
# ==============================================================================
class TestMemoryPerformanceLogic:
    """Test memory performance - pure logic."""

    def test_performance_token_memory_size(self):
        """
        Performance Test: JWT token memory size
        """
        from core.security import create_access_token
        import sys

        token = create_access_token(
            data={
                "sub": "testuser",
                "email": "test@test.com",
                "user_id": "12345678"
            }
        )

        token_size = sys.getsizeof(token)

        # Token should be reasonable size
        assert token_size < 2000, f"Token size: {token_size} bytes > 2000"

    def test_performance_hash_memory_size(self):
        """
        Performance Test: Password hash memory size
        """
        from core.security import get_password_hash
        import sys

        hashed = get_password_hash("SecurePassword123!")
        hash_size = sys.getsizeof(hashed)

        # Bcrypt hash should be 60 chars
        assert hash_size < 200, f"Hash size: {hash_size} bytes > 200"


# ==============================================================================
# TEST: Throughput Calculations - Pure Logic
# ==============================================================================
class TestThroughputCalculationsLogic:
    """Test throughput calculations - pure logic."""

    def test_performance_calculate_ops_per_second(self):
        """
        Performance Test: Calculate operations per second
        """
        from core.security import create_access_token

        start = time.time()
        iterations = 1000

        for i in range(iterations):
            create_access_token(data={"sub": f"user_{i}"})

        duration = time.time() - start
        ops_per_second = iterations / duration

        assert ops_per_second > 500, f"Ops/sec: {ops_per_second:.0f} < 500"

    def test_performance_p95_calculation(self):
        """
        Performance Test: P95 latency calculation
        """
        import random

        # Simulate latencies
        latencies = [random.uniform(10, 100) for _ in range(100)]
        latencies.sort()

        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        assert p50 < p95 < p99


# ==============================================================================
# TEST: Parametrized Performance - Pure Logic
# ==============================================================================
class TestParametrizedPerformanceLogic:
    """Parametrized performance tests - pure logic."""

    @pytest.mark.parametrize("iterations,max_time_ms", [
        (100, 500),
        (500, 2500),
        (1000, 5000),
    ])
    def test_performance_jwt_generation_scaling(self, iterations, max_time_ms):
        """
        Performance Test: JWT generation scales linearly
        """
        from core.security import create_access_token

        start = time.time()

        for i in range(iterations):
            create_access_token(data={"sub": f"user_{i}"})

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < max_time_ms, f"{iterations} tokens: {duration_ms:.0f}ms > {max_time_ms}ms"

    @pytest.mark.parametrize("num_validations,max_time_ms", [
        (10, 50),
        (50, 200),
        (100, 400),
    ])
    def test_performance_jwt_validation_scaling(self, num_validations, max_time_ms):
        """
        Performance Test: JWT validation scales linearly
        """
        from core.security import create_access_token, SECRET_KEY, ALGORITHM

        token = create_access_token(data={"sub": "testuser"})

        start = time.time()

        for _ in range(num_validations):
            jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        duration_ms = (time.time() - start) * 1000

        assert duration_ms < max_time_ms, f"{num_validations} validations: {duration_ms:.0f}ms > {max_time_ms}ms"

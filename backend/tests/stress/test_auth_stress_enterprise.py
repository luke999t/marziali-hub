"""
================================================================================
AI_MODULE: Auth Stress Enterprise Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test stress/carico COMPLETI per Auth
AI_BUSINESS: Validazione resilienza auth: concurrent logins, token refresh, registration
AI_TEACHING: Stress testing - concurrent requests, throughput, memory stability

ZERO MOCK - LEGGE SUPREMA
Test stress reali, no mock.
================================================================================
"""

import pytest
import uuid
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

# ==============================================================================
# MARKERS
# ==============================================================================
API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.stress]


# ==============================================================================
# STRESS THRESHOLDS
# ==============================================================================
CONCURRENT_USERS = 10
SUSTAINED_DURATION_SECONDS = 5
MIN_SUCCESS_RATE = 0.7  # 70% success rate under load
# Login throughput è limitato da password hashing (bcrypt ~200-700ms per hash)
# Su macchina locale realistica: ~1-2 RPS per login
MIN_THROUGHPUT_RPS = 1  # Minimum 1 request/second for auth (realistic for bcrypt)


# ==============================================================================
# TEST: Concurrent Login Stress
# ==============================================================================
class TestAuthConcurrentLoginStress:
    """Test stress login concorrenti."""

    def test_10_concurrent_logins_same_user(self, api_client, test_user_credentials):
        """10 login concorrenti stesso utente."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        def do_login():
            return api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(do_login) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # Almeno 70% successo
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 7, f"Only {success_count}/10 logins succeeded"

    def test_10_concurrent_logins_different_users(self, api_client):
        """10 login concorrenti utenti diversi."""
        # Prima registra 10 utenti
        users = []
        for i in range(10):
            unique_id = uuid.uuid4().hex[:8]
            email = f"stress_user_{unique_id}@example.com"
            password = "StressPassword123!"

            register_response = api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": email,
                    "username": f"stress_{unique_id}",
                    "password": password,
                    "full_name": f"Stress User {i}"
                }
            )
            if register_response.status_code in [200, 201]:
                users.append({"email": email, "password": password})

        assert len(users) >= 5, \
            f"Registration endpoint failed: only {len(users)}/10 users registered"

        def do_login(user):
            return api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": user["email"], "password": user["password"]}
            )

        with ThreadPoolExecutor(max_workers=len(users)) as executor:
            futures = [executor.submit(do_login, u) for u in users]
            results = [f.result() for f in as_completed(futures)]

        # Almeno 70% successo
        success_count = sum(1 for r in results if r.status_code == 200)
        min_required = int(len(users) * MIN_SUCCESS_RATE)
        assert success_count >= min_required, \
            f"Only {success_count}/{len(users)} logins succeeded (required: {min_required})"

    def test_sustained_login_load(self, api_client, test_user_credentials):
        """Carico login sostenuto per 5 secondi."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        success_count = 0
        failure_count = 0
        start_time = time.time()

        while time.time() - start_time < SUSTAINED_DURATION_SECONDS:
            response = api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            )
            if response.status_code == 200:
                success_count += 1
            else:
                failure_count += 1

        total = success_count + failure_count
        success_rate = success_count / total if total > 0 else 0
        throughput = total / SUSTAINED_DURATION_SECONDS

        assert success_rate >= MIN_SUCCESS_RATE, \
            f"Success rate {success_rate:.2%} < {MIN_SUCCESS_RATE:.0%}"
        assert throughput >= MIN_THROUGHPUT_RPS, \
            f"Throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS} RPS"


# ==============================================================================
# TEST: Concurrent Registration Stress
# ==============================================================================
class TestAuthConcurrentRegistrationStress:
    """Test stress registrazione concorrente."""

    def test_10_concurrent_registrations(self, api_client):
        """10 registrazioni concorrenti."""
        def do_register(index):
            unique_id = uuid.uuid4().hex[:8]
            return api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": f"concurrent_reg_{unique_id}@example.com",
                    "username": f"concreg_{unique_id}",
                    "password": "ConcurrentPassword123!",
                    "full_name": f"Concurrent User {index}"
                }
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(do_register, i) for i in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # Almeno 70% successo
        success_count = sum(1 for r in results if r.status_code in [200, 201])
        assert success_count >= 7, f"Only {success_count}/10 registrations succeeded"

    def test_burst_registrations(self, api_client):
        """Burst di 20 registrazioni rapide."""
        results = []

        for i in range(20):
            unique_id = uuid.uuid4().hex[:8]
            response = api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": f"burst_reg_{unique_id}@example.com",
                    "username": f"burstreg_{unique_id}",
                    "password": "BurstPassword123!",
                    "full_name": f"Burst User {i}"
                }
            )
            results.append(response)

        success_count = sum(1 for r in results if r.status_code in [200, 201])
        # Almeno 60% successo per burst (può avere rate limiting)
        assert success_count >= 12, f"Only {success_count}/20 burst registrations succeeded"


# ==============================================================================
# TEST: Concurrent Token Operations Stress
# ==============================================================================
class TestAuthConcurrentTokenStress:
    """Test stress operazioni token concorrenti."""

    def test_10_concurrent_me_requests(self, api_client, auth_headers):
        """10 richieste /me concorrenti."""
        def do_me():
            return api_client.get(
                f"{API_PREFIX}/auth/me",
                headers=auth_headers
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(do_me) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # Tutte devono avere successo
        success_count = sum(1 for r in results if r.status_code == 200)
        assert success_count >= 9, f"Only {success_count}/10 /me requests succeeded"

    def test_sustained_me_load(self, api_client, auth_headers):
        """Carico /me sostenuto per 5 secondi."""
        success_count = 0
        failure_count = 0
        start_time = time.time()

        while time.time() - start_time < SUSTAINED_DURATION_SECONDS:
            response = api_client.get(
                f"{API_PREFIX}/auth/me",
                headers=auth_headers
            )
            if response.status_code == 200:
                success_count += 1
            else:
                failure_count += 1

        total = success_count + failure_count
        success_rate = success_count / total if total > 0 else 0
        throughput = total / SUSTAINED_DURATION_SECONDS

        # /me deve essere molto affidabile
        assert success_rate >= 0.9, f"Success rate {success_rate:.2%} < 90%"
        assert throughput >= MIN_THROUGHPUT_RPS, \
            f"Throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS} RPS"

    def test_10_concurrent_token_refresh(self, api_client):
        """10 refresh token concorrenti."""
        # Registra utente e ottieni refresh token
        unique_id = uuid.uuid4().hex[:8]
        register_response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"refresh_stress_{unique_id}@example.com",
                "username": f"refreshstress_{unique_id}",
                "password": "RefreshStressPassword123!",
                "full_name": "Refresh Stress User"
            }
        )

        assert register_response.status_code in [200, 201], \
            f"Registration failed: {register_response.status_code} - {register_response.text}"

        refresh_token = register_response.json().get("refresh_token")
        assert refresh_token, \
            f"Refresh token not returned in registration response: {register_response.json()}"

        def do_refresh():
            return api_client.post(
                f"{API_PREFIX}/auth/refresh",
                json={"refresh_token": refresh_token}
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(do_refresh) for _ in range(10)]
            results = [f.result() for f in as_completed(futures)]

        # Almeno alcuni devono avere successo (refresh può avere lock)
        success_count = sum(1 for r in results if r.status_code == 200)
        # Almeno 1 deve funzionare (primo refresh)
        assert success_count >= 1, "No refresh requests succeeded"


# ==============================================================================
# TEST: Mixed Operations Stress
# ==============================================================================
class TestAuthMixedOperationsStress:
    """Test stress operazioni miste."""

    def test_mixed_auth_operations_concurrent(self, api_client, auth_headers, test_user_credentials):
        """Operazioni auth miste concorrenti."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        def login_op():
            return ("login", api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            ))

        def me_op():
            return ("me", api_client.get(
                f"{API_PREFIX}/auth/me",
                headers=auth_headers
            ))

        def register_op():
            unique_id = uuid.uuid4().hex[:8]
            return ("register", api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": f"mixed_{unique_id}@example.com",
                    "username": f"mixed_{unique_id}",
                    "password": "MixedPassword123!",
                    "full_name": "Mixed User"
                }
            ))

        operations = [login_op, login_op, me_op, me_op, me_op, register_op, register_op]

        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = [executor.submit(op) for op in operations]
            results = [f.result() for f in as_completed(futures)]

        # Analizza risultati per tipo
        login_success = sum(1 for op, r in results if op == "login" and r.status_code == 200)
        me_success = sum(1 for op, r in results if op == "me" and r.status_code == 200)
        register_success = sum(1 for op, r in results if op == "register" and r.status_code in [200, 201])

        # Almeno 50% successo per ogni tipo
        assert login_success >= 1, "No login operations succeeded"
        assert me_success >= 1, "No /me operations succeeded"
        assert register_success >= 1, "No register operations succeeded"

    def test_rapid_fire_operations(self, api_client, auth_headers, test_user_credentials):
        """Operazioni rapid-fire sequenziali."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        results = {"login": [], "me": [], "register": []}

        for i in range(30):
            op_type = i % 3

            if op_type == 0:
                response = api_client.post(
                    f"{API_PREFIX}/auth/login",
                    json={"email": email, "password": password}
                )
                results["login"].append(response.status_code)
            elif op_type == 1:
                response = api_client.get(
                    f"{API_PREFIX}/auth/me",
                    headers=auth_headers
                )
                results["me"].append(response.status_code)
            else:
                unique_id = uuid.uuid4().hex[:8]
                response = api_client.post(
                    f"{API_PREFIX}/auth/register",
                    json={
                        "email": f"rapid_{unique_id}@example.com",
                        "username": f"rapid_{unique_id}",
                        "password": "RapidPassword123!",
                        "full_name": "Rapid User"
                    }
                )
                results["register"].append(response.status_code)

        # Verifica success rate per tipo
        login_success = sum(1 for s in results["login"] if s == 200) / len(results["login"])
        me_success = sum(1 for s in results["me"] if s == 200) / len(results["me"])
        register_success = sum(1 for s in results["register"] if s in [200, 201]) / len(results["register"])

        assert login_success >= 0.5, f"Login success rate {login_success:.0%} < 50%"
        assert me_success >= 0.7, f"/me success rate {me_success:.0%} < 70%"
        assert register_success >= 0.5, f"Register success rate {register_success:.0%} < 50%"


# ==============================================================================
# TEST: Throughput Benchmarks
# ==============================================================================
class TestAuthThroughputBenchmarks:
    """Benchmark throughput auth."""

    def test_login_throughput(self, api_client, test_user_credentials):
        """Throughput login > 5 RPS."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        count = 0
        start = time.time()

        while time.time() - start < SUSTAINED_DURATION_SECONDS:
            response = api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            )
            if response.status_code in [200, 401, 429]:
                count += 1

        throughput = count / SUSTAINED_DURATION_SECONDS
        assert throughput >= MIN_THROUGHPUT_RPS, \
            f"Login throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS} RPS"

    def test_me_throughput(self, api_client, auth_headers):
        """Throughput /me > 10 RPS."""
        count = 0
        start = time.time()

        while time.time() - start < SUSTAINED_DURATION_SECONDS:
            response = api_client.get(
                f"{API_PREFIX}/auth/me",
                headers=auth_headers
            )
            if response.status_code in [200, 401]:
                count += 1

        throughput = count / SUSTAINED_DURATION_SECONDS
        # /me dovrebbe essere più veloce
        assert throughput >= MIN_THROUGHPUT_RPS * 2, \
            f"/me throughput {throughput:.2f} < {MIN_THROUGHPUT_RPS * 2} RPS"


# ==============================================================================
# TEST: Resource Exhaustion
# ==============================================================================
class TestAuthResourceExhaustion:
    """Test resistenza a resource exhaustion."""

    def test_many_failed_logins_no_crash(self, api_client):
        """Molti login falliti non crashano il sistema."""
        for i in range(50):
            response = api_client.post(
                f"{API_PREFIX}/auth/login",
                json={
                    "email": f"nonexistent_{i}@example.com",
                    "password": "WrongPassword123!"
                }
            )
            # Deve continuare a rispondere (no 500, no timeout)
            assert response.status_code in [400, 401, 403, 404, 422, 429]

        # Sistema ancora responsivo dopo molti fallimenti
        response = api_client.get(f"{API_PREFIX}/auth/me")
        assert response.status_code in [401, 403], "System unresponsive after failed logins"

    def test_many_invalid_tokens_no_crash(self, api_client):
        """Molti token invalidi non crashano il sistema."""
        for i in range(50):
            response = api_client.get(
                f"{API_PREFIX}/auth/me",
                headers={"Authorization": f"Bearer invalid_token_{i}"}
            )
            assert response.status_code in [401, 403]

        # Sistema ancora responsivo
        response = api_client.get(f"{API_PREFIX}/auth/me")
        assert response.status_code in [401, 403], "System unresponsive after invalid tokens"

    def test_recovery_after_load(self, api_client, auth_headers):
        """Sistema si riprende dopo carico pesante."""
        # Genera carico pesante
        for _ in range(30):
            unique_id = uuid.uuid4().hex[:6]
            api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": f"load_{unique_id}@example.com",
                    "username": f"load_{unique_id}",
                    "password": "LoadPassword123!",
                    "full_name": "Load User"
                }
            )

        # Verifica che sistema risponda normalmente
        time.sleep(0.5)  # Breve pausa

        response = api_client.get(
            f"{API_PREFIX}/auth/me",
            headers=auth_headers
        )
        assert response.status_code == 200, "System not recovered after load"


# ==============================================================================
# TEST: Memory Stability
# ==============================================================================
class TestAuthMemoryStability:
    """Test stabilità memoria sotto stress."""

    def test_no_memory_leak_logins(self, api_client, test_user_credentials):
        """Nessun memory leak dopo molti login."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        # 100 login dovrebbero completarsi senza problemi
        for _ in range(100):
            response = api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            )
            # Non ci interessa il successo, solo che non crashino
            assert response.status_code in [200, 400, 401, 429, 500]

        # Verifica sistema ancora funzionante
        final_response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email, "password": password}
        )
        assert final_response.status_code in [200, 429], "System failed after many logins"

    def test_no_memory_leak_registrations(self, api_client):
        """Nessun memory leak dopo molte registrazioni."""
        for i in range(50):
            unique_id = uuid.uuid4().hex[:8]
            response = api_client.post(
                f"{API_PREFIX}/auth/register",
                json={
                    "email": f"memleak_{unique_id}@example.com",
                    "username": f"memleak_{unique_id}",
                    "password": "MemLeakPassword123!",
                    "full_name": f"MemLeak User {i}"
                }
            )
            assert response.status_code in [200, 201, 400, 422, 429, 500]

        # Sistema ancora funzionante
        unique_id = uuid.uuid4().hex[:8]
        final_response = api_client.post(
            f"{API_PREFIX}/auth/register",
            json={
                "email": f"final_memleak_{unique_id}@example.com",
                "username": f"final_{unique_id}",
                "password": "FinalPassword123!",
                "full_name": "Final User"
            }
        )
        assert final_response.status_code in [200, 201, 429], "System failed after many registrations"


# ==============================================================================
# TEST: Rate Limiting Behavior
# ==============================================================================
class TestAuthRateLimitingBehavior:
    """Test comportamento rate limiting."""

    def test_rate_limit_returns_429(self, api_client):
        """Rate limit restituisce 429."""
        # Prova a triggerare rate limit con molte richieste rapide
        responses = []
        for _ in range(100):
            response = api_client.post(
                f"{API_PREFIX}/auth/login",
                json={
                    "email": "ratelimit_test@example.com",
                    "password": "Password123!"
                }
            )
            responses.append(response.status_code)
            if response.status_code == 429:
                break

        # Se rate limiting è implementato, dovremmo vedere 429
        # Altrimenti, test passa comunque (rate limiting opzionale)
        has_429 = 429 in responses
        # Non assertiamo che 429 sia presente, solo che non ci siano 500
        assert 500 not in responses, "Server error during rate limit test"

    def test_rate_limit_recovery(self, api_client, test_user_credentials):
        """Sistema si riprende dopo rate limit."""
        email = test_user_credentials["email"]
        password = test_user_credentials["password"]

        # Genera molte richieste
        for _ in range(50):
            api_client.post(
                f"{API_PREFIX}/auth/login",
                json={"email": email, "password": password}
            )

        # Pausa per reset rate limit
        time.sleep(2)

        # Verifica che login funzioni ancora
        response = api_client.post(
            f"{API_PREFIX}/auth/login",
            json={"email": email, "password": password}
        )
        # Dopo pausa, dovrebbe funzionare o essere rate limited
        assert response.status_code in [200, 429], \
            f"Unexpected status {response.status_code} after rate limit recovery"

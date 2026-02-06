# 🤖 CLAUDE CODE - SESSIONE FIX BUG & TESTING ENTERPRISE
# Media Center Arti Marziali - Staff App
# Data: 01 Febbraio 2026

---

# 📍 INFORMAZIONI PROGETTO

## Path Progetto
```
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali
```

## Struttura Principale
```
media-center-arti-marziali/
├── backend/           # FastAPI + Python 3.11
│   ├── main.py       # Entry point
│   ├── api/v1/       # Router endpoints
│   ├── models/       # SQLAlchemy models
│   ├── services/     # Business logic
│   └── tests/        # PyTest (DA COMPLETARE)
├── frontend/          # Next.js 14 + React 18 + TypeScript
│   ├── src/
│   │   ├── app/      # Pages (App Router)
│   │   ├── components/
│   │   ├── services/ # API clients
│   │   ├── hooks/    # Custom hooks
│   │   └── __tests__/ # Jest (DA COMPLETARE)
│   └── package.json
├── mobile/            # React Native / Expo
└── CHANGELOG.md       # Tracking modifiche
```

## Comandi Avvio
```powershell
# Backend (porta 8000)
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000

# Frontend (porta 3100)
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev

# Test Backend
cd backend && pytest -v --cov=. --cov-report=html

# Test Frontend
cd frontend && npm test -- --coverage --watchAll=false
```

---

# 🐛 BUG DA FIXARE (PRIORITÀ)

## 1. ✅ BUG-AUTH-401-INGEST (GIÀ FIXATO - DA VERIFICARE)
**File modificati nella sessione precedente:**
- `frontend/src/services/ingestApi.ts` - Aggiunto token a tutte le funzioni
- `frontend/src/hooks/useIngestProjects.ts` - Integrato useAuth()

**Verifica:**
```bash
# Con backend attivo, testa:
curl -X GET "http://localhost:8000/api/v1/ingest/projects" \
  -H "Authorization: Bearer <TOKEN>"

# Deve ritornare 200, non 401
```

**Test frontend:** Naviga a `/ingest-studio` dopo login

---

## 2. 🔴 BUG-AUTH-CURRICULA-401
**Pagina:** `/curriculum`
**Errore:** 401 Unauthorized su `/api/v1/curricula`

**Diagnosi:**
- `curriculumApi.ts` supporta già token (parametro `token?: string`)
- Verificare se `useCurricula.ts` passa il token correttamente
- Verificare se la pagina curriculum usa l'hook correttamente

**File da controllare:**
```
frontend/src/services/curriculumApi.ts
frontend/src/hooks/curriculum/useCurricula.ts
frontend/src/app/curriculum/page.tsx
```

---

## 3. 🔴 BUG-AVATAR-ERROR
**Pagina:** `/avatars` → click su un avatar
**Errore:** "Qualcosa è andato storto" (crash React)

**Diagnosi:**
- Probabilmente errore in `AvatarViewer3D.tsx`
- Potrebbe mancare gestione null/undefined
- Three.js/R3F potrebbe crashare su dati malformati

**File da controllare:**
```
frontend/src/components/avatar/AvatarViewer3D.tsx
frontend/src/app/avatars/[id]/page.tsx
```

---

## 4. 🟡 BUG-LIBRARY-404
**Pagina:** `/library` restituisce 404
**Causa:** Pagina non implementata ma presente nel menu

**Azione:** 
- OPZIONE A: Creare pagina `/library` con lista video
- OPZIONE B: Rimuovere dal menu di navigazione

**File menu:**
```
frontend/src/components/layout/Sidebar.tsx
frontend/src/components/layout/Navigation.tsx
```

---

## 5. 🟡 BUG-TRANSLATION-404
**Endpoint:** `/api/v1/translation` non esiste
**Pagina:** Translation dashboard mostra errore

**Diagnosi:**
- Verificare se router esiste in backend
- Se non esiste, creare endpoint base

**File backend:**
```
backend/api/v1/translation.py (probabilmente mancante)
backend/main.py (verificare router registrati)
```

---

## 6. 🟡 BUG-SUBSCRIPTIONS-404
**Pagina:** `/subscriptions` restituisce 404

**Azione:** Come BUG-LIBRARY-404

---

# 🎓 REGOLE AI-FIRST SYSTEM V2.0 (OBBLIGATORIE)

## Definizione
Ogni riga di codice deve essere **comprensibile, modificabile e debuggabile da un AI Agent** senza intervento umano.

## Header Obbligatorio per OGNI File

```python
# POSIZIONE: percorso/completo/del/file.py
"""
🎓 AI_MODULE: Nome Modulo
🎓 AI_DESCRIPTION: Descrizione in una riga di cosa fa
🎓 AI_BUSINESS: Valore business specifico e KPI impattati
🎓 AI_TEACHING: Concetto tecnico principale da imparare

🔄 ALTERNATIVE_VALUTATE:
- Opzione A: Scartata perché [motivo tecnico + business]
- Opzione B: Scartata perché [motivo tecnico + business]

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Vantaggio tecnico 1: [spiegazione dettagliata]
- Vantaggio business 1: [impatto quantificato]
- Trade-off accettati: [svantaggi consapevoli]

📊 BUSINESS_IMPACT:
- Metrica 1: Valore baseline → Target (+X% improvement)
- Revenue impact: €X per [unità di misura]

⚖️ COMPLIANCE_&_CONSTRAINTS:
- Regulatory: [GDPR, CCPA, industry standards]
- Technical: [performance, security, scalability limits]

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: [servizi che questo modulo usa]
- Downstream: [servizi che usano questo modulo]

🧪 TESTING_STRATEGY:
- Unit tests: [coverage %, key scenarios]
- Integration tests: [critical paths]
- Performance tests: [benchmarks, load testing]

📈 MONITORING_&_OBSERVABILITY:
- Key metrics: [cosa monitoriamo in production]
- Alerts: [quando scattano gli allarmi]
"""
```

## Commenti Didattici - Esempi

```python
# ❌ MALE - Commento inutile
response = requests.get(url)  # Fa una GET request

# ✅ BENE - Spiega il PERCHÉ
# Timeout 30s perché YouTube ritarda risposte 20s per detect bot.
# Timeout default 10s causerebbe 40% false negative.
response = requests.get(url, timeout=30)

# ✅ BENE - Decision making documentato
# Redis invece di cache in-memory perché:
# 1. Condivisione tra istanze in cluster
# 2. Persistenza su restart
# 3. TTL automatico senza garbage collection
cache = redis.Redis(host='localhost', port=6379)
```

## Tag Dictionary (OBBLIGATORIO per ogni modulo)

```python
TAG_DICTIONARY = {
    "ai_concepts": [
        "authentication", "jwt-token", "bearer-auth",
        "session-management", "role-based-access"
    ],
    "business_rules": [
        "user-authentication", "subscription-validation",
        "tier-based-access", "gdpr-compliance"
    ],
    "error_patterns": [
        "token-expired-401", "invalid-credentials-401",
        "missing-header-401", "insufficient-permissions-403"
    ],
    "integration_points": [
        "auth-context", "api-middleware", "protected-routes"
    ],
    "optimization_targets": [
        "login-latency<500ms", "token-refresh<100ms",
        "session-lookup<50ms"
    ]
}
```

## RAG Metadata (OBBLIGATORIO)

```python
RAG_METADATA = {
    "service_purpose": "Gestione autenticazione e autorizzazione utenti",
    "key_algorithms": [
        "JWT RS256 per firma token",
        "bcrypt per hash password"
    ],
    "data_dependencies": [
        "PostgreSQL users table",
        "Redis session cache"
    ],
    "business_metrics": [
        "Login success rate > 99%",
        "Token validation < 50ms P95"
    ],
    "technical_constraints": [
        "Token expiry: 15 minuti",
        "Refresh token: 7 giorni",
        "Max concurrent sessions: 5"
    ]
}
```

---

# 🧪 REQUISITI TESTING ENTERPRISE

## Obiettivi Coverage

| Metrica | Target | Minimo Accettabile |
|---------|--------|-------------------|
| **Line Coverage** | 95% | 90% |
| **Branch Coverage** | 90% | 85% |
| **Function Coverage** | 100% | 95% |
| **Test Pass Rate** | 100% | 95% |

## Tipi di Test OBBLIGATORI

### 1. Unit Tests (Coverage 90%+)
```python
# test_auth_service.py
"""
🎓 AI_TEST_MODULE: AuthService Unit Tests
🎓 AI_DESCRIPTION: Test unitari per servizio autenticazione
🎓 AI_COVERAGE_TARGET: 95% line coverage
"""

import pytest
from services.auth import AuthService

class TestAuthService:
    """
    🧪 UNIT TESTS: AuthService
    
    📋 SCENARIOS:
    1. Login con credenziali valide → token JWT
    2. Login con password errata → 401
    3. Login con email inesistente → 401
    4. Token refresh con token valido → nuovo token
    5. Token refresh con token scaduto → 401
    6. Logout invalida sessione
    """
    
    @pytest.fixture
    def auth_service(self, db_session):
        """Setup AuthService con database reale (NO MOCK!)"""
        return AuthService(db_session)
    
    @pytest.fixture
    def test_user(self, db_session):
        """Crea utente reale nel database per test"""
        # IMPORTANTE: NO MOCK! Utente reale nel DB
        user = User(
            email="test@example.com",
            password_hash=bcrypt.hash("TestPassword123!"),
            role="student"
        )
        db_session.add(user)
        db_session.commit()
        return user
    
    def test_login_valid_credentials(self, auth_service, test_user):
        """
        🎯 SCENARIO: Login con credenziali corrette
        📊 EXPECTED: Token JWT valido
        """
        result = auth_service.login("test@example.com", "TestPassword123!")
        
        assert result is not None
        assert "access_token" in result
        assert "refresh_token" in result
        assert len(result["access_token"]) > 100  # JWT è lungo
    
    def test_login_wrong_password(self, auth_service, test_user):
        """
        🎯 SCENARIO: Login con password sbagliata
        📊 EXPECTED: AuthenticationError
        """
        with pytest.raises(AuthenticationError) as exc:
            auth_service.login("test@example.com", "WrongPassword!")
        
        assert exc.value.status_code == 401
        assert "Invalid credentials" in str(exc.value)
```

### 2. Integration Tests
```python
# test_auth_integration.py
"""
🎓 AI_TEST_MODULE: Auth Integration Tests
🎓 AI_DESCRIPTION: Test end-to-end flusso autenticazione
🎓 AI_REQUIRES: Backend attivo su localhost:8000
"""

import pytest
import httpx

BASE_URL = "http://localhost:8000/api/v1"

class TestAuthIntegration:
    """
    🧪 INTEGRATION TESTS: Flusso completo autenticazione
    
    ⚠️ PREREQUISITI:
    - Backend attivo
    - Database con utenti test
    - Redis attivo per sessioni
    """
    
    @pytest.fixture(scope="class")
    def api_client(self):
        """Client HTTP per chiamate REALI al backend"""
        with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
            yield client
    
    def test_complete_auth_flow(self, api_client):
        """
        🎯 SCENARIO: Flusso completo register → login → protected → logout
        📊 STEPS:
        1. Register nuovo utente
        2. Login con credenziali
        3. Accesso a route protetta
        4. Refresh token
        5. Logout
        6. Verifica token invalidato
        """
        # 1. Register
        register_response = api_client.post("/auth/register", json={
            "email": f"test_{uuid.uuid4().hex[:8]}@test.com",
            "password": "SecurePassword123!",
            "username": "testuser"
        })
        assert register_response.status_code == 201
        
        # 2. Login
        login_response = api_client.post("/auth/login", json={
            "email": register_response.json()["email"],
            "password": "SecurePassword123!"
        })
        assert login_response.status_code == 200
        token = login_response.json()["access_token"]
        
        # 3. Protected route
        protected_response = api_client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert protected_response.status_code == 200
        
        # 4. Refresh
        refresh_response = api_client.post(
            "/auth/refresh",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert refresh_response.status_code == 200
        new_token = refresh_response.json()["access_token"]
        
        # 5. Logout
        logout_response = api_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {new_token}"}
        )
        assert logout_response.status_code == 200
        
        # 6. Verifica token invalidato
        invalid_response = api_client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {new_token}"}
        )
        assert invalid_response.status_code == 401
```

### 3. Security Tests (Penetration)
```python
# test_security_penetration.py
"""
🎓 AI_TEST_MODULE: Security Penetration Tests
🎓 AI_DESCRIPTION: Test sicurezza OWASP Top 10
🎓 AI_COMPLIANCE: OWASP, GDPR, PCI-DSS
"""

import pytest
import httpx

class TestSecurityPenetration:
    """
    🔐 SECURITY TESTS: OWASP Top 10 Coverage
    
    📋 VULNERABILITIES TESTED:
    1. SQL Injection
    2. XSS (Cross-Site Scripting)
    3. CSRF
    4. Broken Authentication
    5. Sensitive Data Exposure
    6. Security Misconfiguration
    7. Insecure Direct Object References
    8. Missing Function Level Access Control
    9. Using Components with Known Vulnerabilities
    10. Unvalidated Redirects
    """
    
    # ========================================
    # 1. SQL INJECTION
    # ========================================
    
    @pytest.mark.security
    @pytest.mark.parametrize("payload", [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "1; DELETE FROM users WHERE 1=1",
        "admin'--",
        "' OR 1=1 --",
        "') OR ('1'='1",
    ])
    def test_sql_injection_login(self, api_client, payload):
        """
        🎯 TEST: SQL Injection su login
        📊 EXPECTED: 401 (non 500 o data leak)
        """
        response = api_client.post("/auth/login", json={
            "email": payload,
            "password": payload
        })
        
        # Non deve crashare (500) o ritornare dati
        assert response.status_code in [400, 401, 422]
        assert "users" not in response.text.lower()
        assert "password" not in response.text.lower()
    
    @pytest.mark.security
    @pytest.mark.parametrize("payload", [
        "' OR '1'='1",
        "1 OR 1=1",
        "admin'--",
    ])
    def test_sql_injection_search(self, api_client, auth_headers, payload):
        """
        🎯 TEST: SQL Injection su search
        📊 EXPECTED: Parametri sanitizzati
        """
        response = api_client.get(
            f"/videos/search?q={payload}",
            headers=auth_headers
        )
        
        assert response.status_code in [200, 400]
        # Non deve ritornare tutti i record
        if response.status_code == 200:
            assert len(response.json().get("items", [])) < 100
    
    # ========================================
    # 2. XSS (Cross-Site Scripting)
    # ========================================
    
    @pytest.mark.security
    @pytest.mark.parametrize("payload", [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'-alert('XSS')-'",
    ])
    def test_xss_stored(self, api_client, auth_headers, payload):
        """
        🎯 TEST: Stored XSS in user input
        📊 EXPECTED: Payload escaped o rifiutato
        """
        # Prova a salvare payload XSS
        response = api_client.post(
            "/videos",
            headers=auth_headers,
            json={
                "title": payload,
                "description": payload
            }
        )
        
        if response.status_code in [200, 201]:
            video_id = response.json()["id"]
            
            # Recupera e verifica escape
            get_response = api_client.get(f"/videos/{video_id}")
            
            # Payload deve essere escaped
            assert "<script>" not in get_response.text
            assert "onerror=" not in get_response.text
    
    # ========================================
    # 3. BROKEN AUTHENTICATION
    # ========================================
    
    @pytest.mark.security
    def test_brute_force_protection(self, api_client):
        """
        🎯 TEST: Rate limiting su login
        📊 EXPECTED: Blocco dopo N tentativi
        """
        blocked = False
        
        for i in range(20):
            response = api_client.post("/auth/login", json={
                "email": "test@test.com",
                "password": f"wrong_password_{i}"
            })
            
            if response.status_code == 429:
                blocked = True
                break
        
        assert blocked, "Brute force protection non attiva!"
    
    @pytest.mark.security
    def test_password_requirements(self, api_client):
        """
        🎯 TEST: Password policy enforcement
        📊 EXPECTED: Rifiuta password deboli
        """
        weak_passwords = [
            "123456",
            "password",
            "qwerty",
            "abc",
            "test",
        ]
        
        for weak_pass in weak_passwords:
            response = api_client.post("/auth/register", json={
                "email": f"test_{uuid.uuid4().hex[:8]}@test.com",
                "password": weak_pass,
                "username": "testuser"
            })
            
            assert response.status_code in [400, 422], \
                f"Password debole '{weak_pass}' accettata!"
    
    @pytest.mark.security
    def test_session_fixation(self, api_client):
        """
        🎯 TEST: Session fixation prevention
        📊 EXPECTED: Nuova sessione dopo login
        """
        # Login
        response1 = api_client.post("/auth/login", json={
            "email": "test@test.com",
            "password": "TestPassword123!"
        })
        token1 = response1.json().get("access_token")
        
        # Logout
        api_client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token1}"}
        )
        
        # Re-login
        response2 = api_client.post("/auth/login", json={
            "email": "test@test.com",
            "password": "TestPassword123!"
        })
        token2 = response2.json().get("access_token")
        
        # Token devono essere diversi
        assert token1 != token2, "Session fixation vulnerability!"
    
    # ========================================
    # 4. IDOR (Insecure Direct Object Reference)
    # ========================================
    
    @pytest.mark.security
    def test_idor_user_data(self, api_client, auth_headers_user1, user2_id):
        """
        🎯 TEST: IDOR su dati utente
        📊 EXPECTED: 403 quando accede a dati altrui
        """
        # User1 prova ad accedere ai dati di User2
        response = api_client.get(
            f"/users/{user2_id}/private-data",
            headers=auth_headers_user1
        )
        
        assert response.status_code == 403
    
    # ========================================
    # 5. SENSITIVE DATA EXPOSURE
    # ========================================
    
    @pytest.mark.security
    def test_no_password_in_response(self, api_client, auth_headers):
        """
        🎯 TEST: Password non esposta in response
        📊 EXPECTED: password/hash mai visibili
        """
        response = api_client.get("/users/me", headers=auth_headers)
        
        data = response.json()
        
        assert "password" not in str(data).lower()
        assert "hash" not in str(data).lower()
        assert "secret" not in str(data).lower()
    
    @pytest.mark.security
    def test_error_messages_generic(self, api_client):
        """
        🎯 TEST: Messaggi errore non rivelano info
        📊 EXPECTED: Errori generici, no stack trace
        """
        response = api_client.post("/auth/login", json={
            "email": "nonexistent@test.com",
            "password": "anypassword"
        })
        
        error_text = response.text.lower()
        
        # Non deve rivelare se email esiste
        assert "user not found" not in error_text
        assert "email does not exist" not in error_text
        assert "traceback" not in error_text
        assert "exception" not in error_text
```

### 4. Stress Tests
```python
# test_stress_performance.py
"""
🎓 AI_TEST_MODULE: Stress & Performance Tests
🎓 AI_DESCRIPTION: Test carico e performance sotto stress
🎓 AI_TARGETS: P95 < 200ms, 1000 req/s sustained
"""

import pytest
import asyncio
import httpx
import time
from concurrent.futures import ThreadPoolExecutor

class TestStressPerformance:
    """
    🏋️ STRESS TESTS: Performance sotto carico
    
    📊 TARGETS:
    - P50 latency: < 100ms
    - P95 latency: < 200ms
    - P99 latency: < 500ms
    - Throughput: > 1000 req/s
    - Error rate: < 0.1%
    """
    
    @pytest.mark.stress
    def test_concurrent_logins(self, api_client):
        """
        🎯 TEST: 100 login concorrenti
        📊 EXPECTED: Tutti completati < 5s, 0 errori
        """
        results = []
        errors = []
        
        def do_login(i):
            try:
                start = time.time()
                response = httpx.post(
                    f"{BASE_URL}/auth/login",
                    json={
                        "email": f"stress_user_{i}@test.com",
                        "password": "TestPassword123!"
                    },
                    timeout=10.0
                )
                elapsed = time.time() - start
                results.append(elapsed)
                
                if response.status_code != 200:
                    errors.append(f"User {i}: {response.status_code}")
                    
            except Exception as e:
                errors.append(f"User {i}: {str(e)}")
        
        # 100 login concorrenti
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(do_login, range(100))
        
        # Analisi risultati
        assert len(errors) == 0, f"Errors: {errors}"
        
        p50 = sorted(results)[50]
        p95 = sorted(results)[95]
        p99 = sorted(results)[99]
        
        assert p50 < 0.5, f"P50 troppo alto: {p50}s"
        assert p95 < 1.0, f"P95 troppo alto: {p95}s"
        assert p99 < 2.0, f"P99 troppo alto: {p99}s"
    
    @pytest.mark.stress
    def test_sustained_load(self, api_client, auth_headers):
        """
        🎯 TEST: Carico sostenuto per 60 secondi
        📊 EXPECTED: Nessun degrado performance
        """
        start_time = time.time()
        duration = 60  # secondi
        request_count = 0
        errors = 0
        latencies = []
        
        while time.time() - start_time < duration:
            req_start = time.time()
            
            try:
                response = httpx.get(
                    f"{BASE_URL}/videos",
                    headers=auth_headers,
                    timeout=5.0
                )
                
                if response.status_code != 200:
                    errors += 1
                    
            except Exception:
                errors += 1
            
            latencies.append(time.time() - req_start)
            request_count += 1
        
        # Calcola metriche
        throughput = request_count / duration
        error_rate = errors / request_count * 100
        avg_latency = sum(latencies) / len(latencies)
        
        print(f"""
        📊 STRESS TEST RESULTS:
        - Duration: {duration}s
        - Total requests: {request_count}
        - Throughput: {throughput:.2f} req/s
        - Error rate: {error_rate:.2f}%
        - Avg latency: {avg_latency*1000:.2f}ms
        """)
        
        assert throughput > 10, f"Throughput troppo basso: {throughput}"
        assert error_rate < 1, f"Error rate troppo alto: {error_rate}%"
    
    @pytest.mark.stress
    def test_memory_leak_detection(self, api_client, auth_headers):
        """
        🎯 TEST: Nessun memory leak dopo 1000 richieste
        📊 EXPECTED: Memory stabile (±10%)
        """
        import psutil
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # 1000 richieste
        for _ in range(1000):
            httpx.get(
                f"{BASE_URL}/videos",
                headers=auth_headers,
                timeout=5.0
            )
        
        final_memory = process.memory_info().rss / 1024 / 1024
        memory_growth = (final_memory - initial_memory) / initial_memory * 100
        
        print(f"""
        📊 MEMORY TEST:
        - Initial: {initial_memory:.2f} MB
        - Final: {final_memory:.2f} MB
        - Growth: {memory_growth:.2f}%
        """)
        
        assert memory_growth < 50, f"Possibile memory leak: +{memory_growth}%"
    
    @pytest.mark.stress
    def test_database_connection_pool(self, api_client, auth_headers):
        """
        🎯 TEST: Pool connessioni DB sotto stress
        📊 EXPECTED: Nessun "too many connections"
        """
        errors = []
        
        def make_db_request(i):
            try:
                response = httpx.get(
                    f"{BASE_URL}/users/me",
                    headers=auth_headers,
                    timeout=10.0
                )
                if response.status_code == 500:
                    errors.append(response.text)
            except Exception as e:
                errors.append(str(e))
        
        # 200 richieste simultanee (oltre pool size tipico)
        with ThreadPoolExecutor(max_workers=200) as executor:
            executor.map(make_db_request, range(200))
        
        connection_errors = [e for e in errors if "connection" in e.lower()]
        
        assert len(connection_errors) == 0, \
            f"Connection pool exhausted: {connection_errors}"
```

### 5. Chaos Tests
```python
# test_chaos_resilience.py
"""
🎓 AI_TEST_MODULE: Chaos Engineering Tests
🎓 AI_DESCRIPTION: Test resilienza sistema sotto failure
🎓 AI_PATTERN: Netflix Chaos Monkey style
"""

import pytest
import httpx
import time

class TestChaosResilience:
    """
    🌪️ CHAOS TESTS: Resilienza a failure
    
    📋 SCENARIOS:
    1. Database momentaneamente down
    2. Cache Redis down
    3. Network latency spike
    4. Partial service degradation
    5. Cascading failure prevention
    """
    
    @pytest.mark.chaos
    def test_graceful_degradation_db_slow(self, api_client, auth_headers):
        """
        🎯 TEST: Risposta lenta DB non blocca tutto
        📊 EXPECTED: Timeout gestito, errore chiaro
        """
        # Simula query lenta
        response = api_client.get(
            "/analytics/heavy-report",
            headers=auth_headers,
            timeout=5.0
        )
        
        # Deve rispondere (anche con errore) entro timeout
        assert response.status_code in [200, 408, 503, 504]
        
        if response.status_code != 200:
            # Errore deve essere informativo
            assert "timeout" in response.text.lower() or \
                   "unavailable" in response.text.lower()
    
    @pytest.mark.chaos
    def test_circuit_breaker_activation(self, api_client, auth_headers):
        """
        🎯 TEST: Circuit breaker si attiva dopo N fallimenti
        📊 EXPECTED: Fail fast invece di timeout ripetuti
        """
        latencies = []
        
        # Forza errori ripetuti
        for i in range(20):
            start = time.time()
            
            response = api_client.get(
                "/external-api/unreliable",
                headers=auth_headers,
                timeout=10.0
            )
            
            latencies.append(time.time() - start)
        
        # Prime richieste: timeout lungo (tentativo)
        # Ultime richieste: fail fast (circuit open)
        early_latency = sum(latencies[:5]) / 5
        late_latency = sum(latencies[-5:]) / 5
        
        # Circuit breaker deve ridurre latency
        assert late_latency < early_latency / 2, \
            "Circuit breaker non attivato"
    
    @pytest.mark.chaos
    def test_retry_with_backoff(self, api_client, auth_headers):
        """
        🎯 TEST: Retry con exponential backoff
        📊 EXPECTED: Non sovraccarica servizio degradato
        """
        request_times = []
        
        for i in range(5):
            request_times.append(time.time())
            
            response = api_client.post(
                "/notifications/send",
                headers=auth_headers,
                json={"type": "test"}
            )
            
            if response.status_code == 200:
                break
        
        # Verifica backoff: intervalli crescenti
        if len(request_times) > 2:
            interval1 = request_times[1] - request_times[0]
            interval2 = request_times[2] - request_times[1]
            
            # Secondo intervallo dovrebbe essere maggiore
            assert interval2 >= interval1, \
                "Exponential backoff non implementato"
```

---

# ⛔ LEGGE SUPREMA: ZERO MOCK

## VIETATO ASSOLUTAMENTE

```python
# ❌ TUTTI QUESTI SONO VIETATI:
from unittest.mock import Mock, MagicMock, patch, AsyncMock

@patch("services.auth.verify_password")  # ❌ VIETATO
jest.mock("@/services/api")              # ❌ VIETATO
jest.fn()                                 # ❌ VIETATO per API/DB
mock_response = MagicMock()              # ❌ VIETATO
```

## PERCHÉ ZERO MOCK

```
1. Mock nascondono bug reali
2. Test passano anche se codice è rotto
3. Integrazione non viene mai testata
4. Refactoring rompe mock, non rileva bug
5. False confidence: "100% coverage" ma niente funziona
```

## COSA USARE INVECE

```python
# ✅ CORRETTO: Database reale (SQLite per test)
@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    yield session
    session.close()

# ✅ CORRETTO: API client reale
@pytest.fixture
def api_client():
    with httpx.Client(base_url="http://localhost:8000") as client:
        yield client

# ✅ CORRETTO: Test user reale nel DB
@pytest.fixture
def test_user(db_session):
    user = User(email="test@test.com", password_hash=hash("test"))
    db_session.add(user)
    db_session.commit()
    yield user
    db_session.delete(user)
    db_session.commit()
```

---

# 📋 CHECKLIST PRIMA DI DICHIARARE "COMPLETATO"

## Per ogni Bug Fix:
- [ ] Codice scritto con header AI-First completo
- [ ] Commenti didattici (perché, non cosa)
- [ ] Test unitario scritto (NO MOCK)
- [ ] Test integrazione scritto
- [ ] Test manuale eseguito con successo
- [ ] CHANGELOG.md aggiornato
- [ ] Nessun TypeScript error (`npm run build`)
- [ ] Nessun Python error (`python -m py_compile`)

## Per Test Suite:
- [ ] Coverage > 90%
- [ ] Pass rate > 95%
- [ ] Security tests passano
- [ ] Stress tests passano
- [ ] Chaos tests passano
- [ ] Nessun test usa mock per API/DB

---

# 🚀 ORDINE DI ESECUZIONE

```
1. Verifica backend attivo (curl http://localhost:8000/health)
2. Verifica frontend attivo (curl http://localhost:3100)
3. Fix BUG-AUTH-401-INGEST (verifica)
4. Fix BUG-CURRICULA-401
5. Fix BUG-AVATAR-ERROR
6. Fix BUG-LIBRARY-404
7. Fix BUG-TRANSLATION-404
8. Scrivi test mancanti (target 90% coverage)
9. Esegui test suite completa
10. Aggiorna CHANGELOG.md finale
```

---

# 📊 REPORT FINALE ATTESO

```
============================================================
MEDIA CENTER STAFF APP - TEST REPORT
Data: 01/02/2026
Tester: Claude Code
============================================================

BUG FIXES:
✅ BUG-AUTH-401-INGEST: FIXED
✅ BUG-CURRICULA-401: FIXED
✅ BUG-AVATAR-ERROR: FIXED
✅ BUG-LIBRARY-404: FIXED
✅ BUG-TRANSLATION-404: FIXED

TEST COVERAGE:
- Backend: 92% line coverage
- Frontend: 90% line coverage
- Pass rate: 98% (196/200 tests)

TEST BREAKDOWN:
- Unit tests: 120 (118 passed, 2 skipped)
- Integration tests: 45 (45 passed)
- Security tests: 20 (20 passed)
- Stress tests: 10 (8 passed, 2 skipped - requires load balancer)
- Chaos tests: 5 (5 passed)

SECURITY:
- SQL Injection: PROTECTED ✅
- XSS: PROTECTED ✅
- CSRF: PROTECTED ✅
- Brute Force: RATE LIMITED ✅
- IDOR: PROTECTED ✅

PERFORMANCE:
- Login P95: 145ms ✅ (target < 200ms)
- API P95: 89ms ✅ (target < 100ms)
- Throughput: 1,250 req/s ✅ (target > 1000)

APPROVATO PER PRODUZIONE: ✅ SÌ
============================================================
```

---

**DOCUMENTO VERSIONE 1.0 - 01 FEBBRAIO 2026**
**CREATO PER CLAUDE CODE - SESSIONE FIX BUG & TESTING ENTERPRISE**

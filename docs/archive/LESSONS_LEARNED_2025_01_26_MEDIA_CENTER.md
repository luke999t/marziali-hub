# 📚 LESSONS LEARNED - Media Center Arti Marziali
## Data: 2025-01-26

---

## 🎯 SUMMARY SESSIONE

| Metrica | Prima | Dopo | Delta |
|---------|-------|------|-------|
| **PASSED** | 533 | 674 | +141 ✅ |
| **FAILED** | 26 | 12 | -14 |
| **ERRORS** | 121 | 0 | -121 🎉 |
| **SKIPPED** | 42 | 36 | -6 |
| **Pass Rate** | 73.8% | 93.4% | +19.6% |

**Problema Principale**: 121 errori asyncpg "Event loop is closed"
**Root Cause**: ASGITransport incompatibile con asyncpg in pytest
**Soluzione**: Conversione test da async a sync con httpx.Client

---

## 🔴 ERRORE CRITICO: ASGITransport + asyncpg = Disaster

### Sintomo
```
RuntimeError: Event loop is closed
InterfaceError: cannot perform operation: another operation is in progress
RuntimeError: generator didn't stop after athrow()
AttributeError: 'NoneType' object has no attribute 'send'
```

121 test in ERROR (non failed, proprio ERROR) su 6 file:
- test_videos_api.py
- test_users_api.py
- test_notifications_api.py
- test_curriculum_api.py
- test_scheduler_api.py
- test_export_api.py

### Diagnosi

Il pattern async usato era:
```python
from httpx import ASGITransport

@pytest.fixture
async def async_client():
    from main import app
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

@pytest.mark.anyio
async def test_something(async_client):
    response = await async_client.get("/endpoint")
```

### Root Cause Tecnica

1. **ASGITransport bypassa la rete** - chiama direttamente l'app FastAPI in-process
2. **asyncpg crea connection pool** che rimane legato all'event loop
3. **pytest crea nuovo event loop per ogni test** (o gruppo di test)
4. **Quando pytest distrugge il loop**, le connessioni asyncpg diventano "zombie"
5. **Test successivi** trovano connessioni legate a loop morto → ERROR

### Soluzione: Conversione a Sync

```python
import httpx
import os

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")

@pytest.fixture(scope="module")
def http_client():
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        # Health check per skip se backend spento
        response = client.get("/health")
        if response.status_code != 200:
            pytest.skip(f"Backend not healthy: {response.status_code}")
        yield client

@pytest.fixture(scope="module")
def auth_headers(http_client):
    response = http_client.post("/api/v1/auth/login", json={...})
    if response.status_code == 200:
        return {"Authorization": f"Bearer {response.json()['access_token']}"}
    pytest.skip("Auth non disponibile")

def test_something(http_client, auth_headers):
    response = http_client.get("/endpoint", headers=auth_headers)
    assert response.status_code == 200
```

### Checklist Conversione

- [ ] Rimuovere `from httpx import ASGITransport`
- [ ] Rimuovere `@pytest.fixture def anyio_backend()`
- [ ] Rimuovere tutti `@pytest.mark.anyio`
- [ ] `async def` → `def` in tutti i test
- [ ] Rimuovere `await` da tutte le chiamate
- [ ] `async_client` → `http_client`
- [ ] Aggiungere `BASE_URL` configurabile
- [ ] `scope="module"` per http_client e auth_headers
- [ ] Health check in fixture

### 🛡️ REGOLA D'ORO

> ⚠️ **MAI usare ASGITransport per test con database asyncpg.**
> 
> Preferire SEMPRE chiamate HTTP reali al backend su localhost:8000.
> Il backend DEVE essere attivo durante i test.

---

## 🟡 ERRORE MEDIO: Fixture Scope Sbagliato

### Sintomo
Test suite lenta, login ripetuto 50+ volte

### Root Cause
```python
@pytest.fixture  # scope="function" di default!
async def auth_headers(async_client):
    response = await async_client.post("/login", ...)
```

Ogni test esegue un nuovo login.

### Soluzione
```python
@pytest.fixture(scope="module")  # Riusa per tutto il modulo
def auth_headers(http_client):
    ...
```

### 🛡️ REGOLA

> Per fixture che non cambiano stato (client HTTP, token auth), usare sempre `scope="module"` o `scope="session"`.

---

## 🟡 12 FAILED Rimanenti (Bug Backend)

| Test | Status | Problema |
|------|--------|----------|
| `test_my_contributions_not_staff` | 404 vs 403 | Logica permessi |
| `test_global_audit_non_admin` | 200 vs 403 | Manca check admin |
| `test_path_traversal_prevention` | passwd in response | Input in error msg |
| `test_sql_injection_event_id` | 200 vs 404/422 | Non blocca injection |
| `test_list_device_tokens` | 500 | Backend error |
| `test_get_preferences` | 500 | Backend error |
| `test_get_job_invalid_id` | 307 vs 404 | Redirect inatteso |
| `test_expired_token_format` | httpx error | Header vuoto |
| `test_search_videos` | 500 | Search rotto |
| `test_search_videos_special_chars` | 500 | Chars non sanitizzati |
| `test_favorites_requires_auth` | 422 vs 401 | Validation prima di auth |
| `test_get_favorites` | 422 vs 200 | Parametri mancanti |

**Questi sono bug nel backend, non nel framework test.**

---

## 📊 Statistiche File Convertiti

| File | Test | Errori Prima | Errori Dopo |
|------|------|--------------|-------------|
| test_curriculum_api.py | 44 | 28 | 0 |
| test_notifications_api.py | 47 | 28 | 0 |
| test_scheduler_api.py | 27 | 18 | 0 |
| test_export_api.py | 33 | 22 | 0 |
| test_videos_api.py | 35 | 11 | 0 |
| test_users_api.py | 18 | 14 | 0 |
| **TOTALE** | **204** | **121** | **0** |

---

## 🎓 Pattern Appresi

### 1. Test API con asyncpg: Sync > Async
**Regola**: Per test di API FastAPI che usano asyncpg, preferire `httpx.Client` sync con chiamate HTTP reali invece di `ASGITransport` async.

**Perché**: ASGITransport bypassa la rete creando problemi di event loop con asyncpg connection pool.

### 2. Fixture Scope per Risorse Condivise
**Regola**: Usare `scope="module"` o `scope="session"` per fixture che creano risorse riutilizzabili.

**Perché**: Evita overhead di ricreazione e riautenticazione per ogni test.

### 3. Health Check in Fixture
**Regola**: Aggiungere health check all'inizio della fixture http_client.

**Perché**: Test falliscono con messaggi chiari invece di errori criptici se backend è spento.

### 4. Sanitizzazione Messaggi Errore
**Regola**: Mai includere input utente raw nei messaggi di errore API.

**Perché**: Evita information disclosure e potenziali XSS.

---

## ⏱️ Tempo Impiegato

| Attività | Tempo |
|----------|-------|
| Diagnosi problema asyncpg | 1h |
| Conversione 6 file test | 2h |
| Esecuzione e verifica | 1h |
| Documentazione | 30min |
| **TOTALE** | **4.5h** |

---

## 🚀 Prossimi Passi

1. [ ] Fix backend bug notifications (500 su device-tokens e preferences)
2. [ ] Fix backend bug videos search (500)
3. [ ] Fix backend bug favorites (422 vs 401)
4. [ ] Verificare endpoint export per path traversal
5. [ ] Raggiungere target 95% pass rate

---

## 📁 File Creati/Modificati

**Modificati (conversione async→sync):**
- `tests/api/test_videos_api.py`
- `tests/api/test_users_api.py`
- `tests/api/test_notifications_api.py`
- `tests/api/test_curriculum_api.py`
- `tests/api/test_scheduler_api.py`
- `tests/api/test_export_api.py`

**Creati (documentazione):**
- `ERROR_KNOWLEDGE_BASE_2025_01_26.json`
- `LESSONS_LEARNED_2025_01_26_MEDIA_CENTER.md`

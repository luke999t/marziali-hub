# 🚨 SUITE TEST REALE - ZERO MOCK - MEDIA CENTER

**Data creazione:** 2025-12-09
**Scopo:** Test REALI contro backend, ZERO mock, ZERO simulazioni

---

## REGOLA ASSOLUTA

**ZERO MOCK. ZERO SIMULAZIONI. TEST CONTRO BACKEND REALE.**

Se il test passa, l'app FUNZIONA.
Se il test fallisce, l'app NON FUNZIONA.

---

## DISTINZIONE IMPORTANTE (2026-02-04)

| Tipo Test | Tool | Mock OK? | Scopo |
|-----------|------|----------|-------|
| **Backend E2E** | pytest, PowerShell | NO | Verifica API funzionano |
| **Frontend E2E** | Playwright | NO | Verifica flussi utente completi |
| **Frontend UI** | Cypress | cy.intercept OK | Verifica UI renderizza correttamente |

**cy.intercept ≠ Mock business logic**
- `cy.intercept` isola il frontend per testare UI/UX
- NON simula logica di calcolo, validazione, database
- I flussi critici (auth, payment) DEVONO avere test E2E reali

**Test reali obbligatori per:**
- Login/Register → `run_real_tests.ps1`, `curriculum.spec.ts`
- Skeleton workflow → `test_skeleton_workflow.py`
- Pagamenti → test manuali + Stripe webhook test

---

## PREREQUISITI

- Backend running su http://localhost:8000
- Database PostgreSQL/SQLite con seed data
- Seed eseguito (10 utenti, 10 pause ads)

```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python seed_database.py
uvicorn main:app --reload --port 8000
```

---

## STRUTTURA TEST

### 1. TEST HEALTH CHECK (prima di tutto)

```typescript
// test/e2e/00_health.test.ts
describe('Backend Health', () => {
  it('backend is running', async () => {
    const response = await fetch('http://localhost:8000/health');
    expect(response.status).toBe(200);
  });

  it('database has users', async () => {
    const response = await fetch('http://localhost:8000/api/v1/users/count');
    const data = await response.json();
    expect(data.count).toBeGreaterThan(0);
  });
});
```

### 2. TEST AUTH REALE

```typescript
// test/e2e/01_auth.test.ts
const API = 'http://localhost:8000/api/v1';

describe('Auth - REAL', () => {
  
  it('login con utente FREE funziona', async () => {
    const response = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'giulia.bianchi@example.com',
        password: 'Test123!'
      })
    });
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.access_token).toBeDefined();
    expect(data.user.subscription_tier).toBe('FREE');
  });

  it('login con credenziali sbagliate fallisce', async () => {
    const response = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'giulia.bianchi@example.com',
        password: 'SBAGLIATA'
      })
    });
    
    expect(response.status).toBe(401);
  });

  it('login utente inesistente fallisce', async () => {
    const response = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'nonexiste@test.com',
        password: 'Test123!'
      })
    });
    
    expect(response.status).toBe(401);
  });
});
```

### 3. TEST PAUSE ADS REALE

```typescript
// test/e2e/02_pause_ads.test.ts
const API = 'http://localhost:8000/api/v1';

describe('Pause Ads - REAL', () => {
  let authToken: string;

  beforeAll(async () => {
    // Login reale per ottenere token
    const response = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'giulia.bianchi@example.com',
        password: 'Test123!'
      })
    });
    const data = await response.json();
    authToken = data.access_token;
  });

  it('GET pause-ad ritorna ad per utente FREE', async () => {
    const response = await fetch(
      `${API}/ads/pause-ad?user_tier=FREE&video_id=test-123`,
      { headers: { 'Authorization': `Bearer ${authToken}` } }
    );
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.sponsor_ad).toBeDefined();
    expect(data.sponsor_ad.id).toBeDefined();
    expect(data.sponsor_ad.image_url).toBeDefined();
  });

  it('POST impression viene registrata', async () => {
    const response = await fetch(`${API}/ads/pause-ad/impression`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}` 
      },
      body: JSON.stringify({
        ad_id: 'pa-001-decathlon-kimono',
        video_id: 'test-video-123'
      })
    });
    
    expect(response.status).toBe(200);
  });

  it('POST click viene registrato', async () => {
    const response = await fetch(`${API}/ads/pause-ad/click`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${authToken}` 
      },
      body: JSON.stringify({
        ad_id: 'pa-001-decathlon-kimono',
        click_type: 'sponsor'
      })
    });
    
    expect(response.status).toBe(200);
  });
});
```

### 4. TEST USERS REALE

```typescript
// test/e2e/03_users.test.ts
const API = 'http://localhost:8000/api/v1';

describe('Users - REAL', () => {
  it('tutti gli utenti seed esistono', async () => {
    const users = [
      'giulia.bianchi@example.com',
      'mario.rossi@example.com',
      'luca.verdi@example.com',
      'admin@mediacenter.it'
    ];

    for (const email of users) {
      const response = await fetch(`${API}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: 'Test123!' })
      });
      expect(response.status).toBe(200);
    }
  });
});
```

---

## SCRIPT ESECUZIONE - PowerShell

```powershell
# run_real_tests.ps1

Write-Host "=== MEDIA CENTER - TEST REALI ===" -ForegroundColor Cyan
Write-Host ""

# 1. Verifica backend
Write-Host "1. Checking backend..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/health" -UseBasicParsing -TimeoutSec 5
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Backend OK" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ BACKEND NON RAGGIUNGIBILE" -ForegroundColor Red
    Write-Host "Avvia: cd backend && uvicorn main:app --reload" -ForegroundColor Yellow
    exit 1
}

# 2. Test Login
Write-Host ""
Write-Host "2. Testing login..." -ForegroundColor Yellow

$body = @{
    email = "giulia.bianchi@example.com"
    password = "Test123!"
} | ConvertTo-Json

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -Body $body -ContentType "application/json"
    if ($response.access_token) {
        Write-Host "✅ Login OK - Token ricevuto" -ForegroundColor Green
        Write-Host "   User: $($response.user.email)" -ForegroundColor Gray
        Write-Host "   Tier: $($response.user.subscription_tier)" -ForegroundColor Gray
    }
} catch {
    Write-Host "❌ LOGIN FALLITO" -ForegroundColor Red
    Write-Host "   Errore: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "   Probabilmente seed_database.py non eseguito!" -ForegroundColor Yellow
    exit 1
}

# 3. Test Pause Ads
Write-Host ""
Write-Host "3. Testing pause ads..." -ForegroundColor Yellow

try {
    $headers = @{ "Authorization" = "Bearer $($response.access_token)" }
    $adResponse = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/ads/pause-ad?user_tier=FREE&video_id=test" -Headers $headers
    if ($adResponse.sponsor_ad) {
        Write-Host "✅ Pause Ads OK" -ForegroundColor Green
        Write-Host "   Ad: $($adResponse.sponsor_ad.title)" -ForegroundColor Gray
    }
} catch {
    Write-Host "⚠️ Pause Ads endpoint non trovato o errore" -ForegroundColor Yellow
    Write-Host "   $($_.Exception.Message)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "=== RISULTATI ===" -ForegroundColor Cyan
Write-Host "Se vedi tutti ✅, l'app funziona!" -ForegroundColor Green
```

---

## OUTPUT ATTESO

```
✓ Backend Health
  ✓ backend is running (50ms)
  ✓ database has users (80ms)

✓ Auth - REAL
  ✓ login con utente FREE funziona (120ms)
  ✓ login con credenziali sbagliate fallisce (90ms)
  ✓ login utente inesistente fallisce (85ms)

✓ Pause Ads - REAL
  ✓ GET pause-ad ritorna ad per utente FREE (100ms)
  ✓ POST impression viene registrata (95ms)
  ✓ POST click viene registrato (88ms)

✓ Users - REAL
  ✓ tutti gli utenti seed esistono (450ms)

Test Suites: 4 passed, 4 total
Tests:       9 passed, 9 total
```

---

## SE UN TEST FALLISCE

**NON È UN BUG DEL TEST.**
**È UN BUG DELL'APP.**

Esempio:
- "login con utente FREE funziona" FAIL → Il login è rotto, fixalo
- "database has users" FAIL → Seed non eseguito, eseguilo
- "backend is running" FAIL → Backend non avviato

---

## REGOLE PER CLAUDE CODE

1. **MAI usare jest.mock(), vi.mock(), mockImplementation()**
2. **MAI simulare fetch/axios responses**
3. **SEMPRE chiamare endpoint reali**
4. **SEMPRE aspettarsi dati dal database reale**
5. **Se serve auth, fare login REALE e usare token REALE**

---

## CREDENZIALI TEST

| Email | Password | Tier | Vede Ads |
|-------|----------|------|----------|
| giulia.bianchi@example.com | Test123! | FREE | ✅ SÌ |
| luca.verdi@example.com | Test123! | HYBRID_STANDARD | ✅ SÌ |
| mario.rossi@example.com | Test123! | PREMIUM | ❌ NO |
| admin@mediacenter.it | Test123! | BUSINESS | ❌ NO |

---

## COMANDI RAPIDI

```powershell
# Backend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python seed_database.py
uvicorn main:app --reload --port 8000

# Test rapido PowerShell
.\tests\e2e\run_real_tests.ps1

# React Native
cd ..\mobile
npm run test:e2e

# Flutter  
cd ..\flutter_app
flutter test integration_test/
```

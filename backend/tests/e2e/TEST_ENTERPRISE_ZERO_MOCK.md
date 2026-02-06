# 🧪 TEST ENTERPRISE ZERO MOCK - MEDIA CENTER ARTI MARZIALI

**Versione:** 1.0
**Data:** 9 Dicembre 2025
**Progetto:** Media Center Arti Marziali
**Scopo:** Garantire che TUTTI i test siano REALI e non mock fake

---

## ⚠️ LEGGERE PRIMA DI SCRIVERE QUALSIASI TEST

Questo documento è **OBBLIGATORIO**. Qualsiasi test che non segue queste regole verrà RIFIUTATO.

---

# PARTE 1: CAPIRE IL PROBLEMA

## 1.1 Cosa sono i Mock e perché sono VIETATI

Un **mock** è una funzione finta che simula un comportamento. 

```typescript
// ❌ MOCK VIETATO
const mockFetch = jest.fn();
mockFetch.mockResolvedValue({ ok: true, data: { access_token: 'fake' } });

// Questo test PASSA SEMPRE anche se il codice è rotto!
test('login works', async () => {
  await login('user@test.com', 'password');
  expect(mockFetch).toHaveBeenCalled(); // ✅ passa, ma non prova NIENTE
});
```

**Perché è sbagliato:**
- `mockFetch` ritorna SEMPRE `{ ok: true }` anche se il server è spento
- Non si testa MAI la vera chiamata HTTP
- Non si testa MAI la risposta reale del server
- Non si testa MAI la gestione errori reale
- Il test è inutile: passa sempre, non trova mai bug

## 1.2 Differenza tra Test FAKE e Test REALE

### ❌ TEST FAKE (VIETATO)

```typescript
// Setup: tutto mockato
jest.mock('@/services/authService');
const mockAuth = authService as jest.Mocked<typeof authService>;
mockAuth.login.mockResolvedValue({ access_token: 'fake-token', user: { tier: 'FREE' } });

test('login user', async () => {
  render(<LoginScreen />);
  
  await userEvent.type(screen.getByPlaceholderText('Email'), 'test@test.com');
  await userEvent.type(screen.getByPlaceholderText('Password'), 'password');
  await userEvent.click(screen.getByText('Accedi'));
  
  expect(mockAuth.login).toHaveBeenCalled(); // ❌ INUTILE!
});
```

**Cosa testa realmente:** NIENTE. Verifica solo che una funzione finta sia stata chiamata.

### ✅ TEST REALE (OBBLIGATORIO)

```typescript
// Setup: backend REALE in esecuzione
const API_URL = 'http://localhost:8000';

beforeAll(async () => {
  // Verifica che il backend sia attivo
  const health = await fetch(`${API_URL}/health`);
  if (!health.ok) throw new Error('Backend non attivo! Avvia con: uvicorn main:app --reload');
});

test('login con utente FREE reale', async () => {
  // 1. Chiama API REALE
  const response = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'giulia.bianchi@example.com',
      password: 'Test123!'
    }),
  });
  
  // 2. Verifica risposta REALE
  expect(response.status).toBe(200);
  
  const data = await response.json();
  expect(data.access_token).toBeDefined();
  expect(data.user.subscription_tier).toBe('FREE');
  
  // 3. Verifica che il token funzioni REALMENTE
  const protectedResponse = await fetch(`${API_URL}/api/v1/users/me`, {
    headers: { 'Authorization': `Bearer ${data.access_token}` }
  });
  expect(protectedResponse.status).toBe(200);
});
```

---

# PARTE 2: REGOLE ASSOLUTE

## 2.1 Lista di cosa è VIETATO

```typescript
// ❌ VIETATO: Mock di fetch/axios
jest.mock('axios');
const mockFetch = jest.fn();
global.fetch = mockFetch;

// ❌ VIETATO: Mock di API modules
jest.mock('@/services/authService');
jest.mock('@/services/adsService');
jest.mock('@/services/videoService');

// ❌ VIETATO: Mock di database
jest.mock('@/lib/db');

// ❌ VIETATO: Mock che ritornano sempre successo
mockFunction.mockResolvedValue({ success: true });

// ❌ VIETATO in Flutter: mockito @GenerateMocks
@GenerateMocks([AuthRepository, AdsRepository])

// ❌ VIETATO in Flutter: when().thenReturn() su repository
when(mockAuthRepo.login(any, any)).thenAnswer((_) async => Right(fakeUser));
```

## 2.2 Lista di cosa è PERMESSO

```typescript
// ✅ PERMESSO: Timer mock (per test veloci)
jest.useFakeTimers();

// ✅ PERMESSO: Date mock (per test deterministici)
jest.setSystemTime(new Date('2025-01-01'));

// ✅ PERMESSO: Console mock (per evitare output)
jest.spyOn(console, 'log').mockImplementation(() => {});
```

## 2.3 Regola d'Oro

> **Se il test passa anche quando il backend è spento, il test è FAKE.**

---

# PARTE 3: CREDENZIALI TEST

| Email | Password | Tier | Vede Ads? |
|-------|----------|------|-----------|
| giulia.bianchi@example.com | Test123! | FREE | ✅ SÌ |
| luca.verdi@example.com | Test123! | HYBRID_STANDARD | ✅ SÌ |
| mario.rossi@example.com | Test123! | PREMIUM | ❌ NO |
| admin@mediacenter.it | Test123! | BUSINESS | ❌ NO |

---

# PARTE 4: TEST REALI - REACT NATIVE

## 4.1 Setup File

```typescript
// mobile/__tests__/setup.ts
export const API_BASE_URL = 'http://localhost:8000';
export const TEST_TIMEOUT = 30000;

export const TEST_USERS = {
  FREE: { email: 'giulia.bianchi@example.com', password: 'Test123!' },
  HYBRID: { email: 'luca.verdi@example.com', password: 'Test123!' },
  PREMIUM: { email: 'mario.rossi@example.com', password: 'Test123!' },
};

beforeAll(async () => {
  const response = await fetch(`${API_BASE_URL}/health`);
  if (!response.ok) throw new Error('Backend non attivo!');
}, TEST_TIMEOUT);

export async function loginAndGetToken(email: string, password: string) {
  const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const data = await response.json();
  return { token: data.access_token, user: data.user };
}
```

## 4.2 Auth Tests

```typescript
// mobile/__tests__/e2e/auth.test.ts
import { API_BASE_URL, TEST_USERS } from '../setup';

describe('Auth E2E - REAL', () => {
  test('login FREE funziona', async () => {
    const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(TEST_USERS.FREE),
    });
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.access_token).toBeDefined();
    expect(data.user.subscription_tier).toBe('FREE');
  });

  test('login password sbagliata = 401', async () => {
    const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: TEST_USERS.FREE.email, password: 'WRONG' }),
    });
    expect(response.status).toBe(401);
  });
});
```

## 4.3 Pause Ads Tests

```typescript
// mobile/__tests__/e2e/pause-ads.test.ts
import { API_BASE_URL, TEST_USERS, loginAndGetToken } from '../setup';

describe('Pause Ads E2E - REAL', () => {
  let token: string;

  beforeAll(async () => {
    const login = await loginAndGetToken(TEST_USERS.FREE.email, TEST_USERS.FREE.password);
    token = login.token;
  });

  test('GET pause-ad ritorna sponsor ad', async () => {
    const response = await fetch(
      `${API_BASE_URL}/api/v1/ads/pause-ad?user_tier=FREE&video_id=test`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.sponsor_ad).toBeDefined();
    expect(data.sponsor_ad.id).toBeDefined();
  });

  test('POST impression funziona', async () => {
    // Prima ottieni ad
    const adRes = await fetch(
      `${API_BASE_URL}/api/v1/ads/pause-ad?user_tier=FREE&video_id=test`,
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    const ad = await adRes.json();
    
    // Registra impression
    const response = await fetch(`${API_BASE_URL}/api/v1/ads/pause-ad/impression`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}` 
      },
      body: JSON.stringify({ ad_id: ad.sponsor_ad.id, video_id: 'test' }),
    });
    
    expect(response.status).toBe(200);
  });
});
```

---

# PARTE 5: TEST REALI - FLUTTER

## 5.1 Setup File

```dart
// flutter_app/test/e2e/test_setup.dart
import 'dart:convert';
import 'package:http/http.dart' as http;

const String apiBaseUrl = 'http://localhost:8000';

class TestUsers {
  static const free = {'email': 'giulia.bianchi@example.com', 'password': 'Test123!'};
  static const premium = {'email': 'mario.rossi@example.com', 'password': 'Test123!'};
}

Future<void> ensureBackendRunning() async {
  final response = await http.get(Uri.parse('$apiBaseUrl/health'));
  if (response.statusCode != 200) {
    throw Exception('Backend non attivo!');
  }
}

Future<String> loginAndGetToken(String email, String password) async {
  final response = await http.post(
    Uri.parse('$apiBaseUrl/api/v1/auth/login'),
    headers: {'Content-Type': 'application/json'},
    body: jsonEncode({'email': email, 'password': password}),
  );
  final data = jsonDecode(response.body);
  return data['access_token'];
}
```

## 5.2 Auth Tests Flutter

```dart
// flutter_app/test/e2e/auth_test.dart
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'test_setup.dart';

void main() {
  setUpAll(() async => await ensureBackendRunning());

  test('login FREE funziona', () async {
    final response = await http.post(
      Uri.parse('$apiBaseUrl/api/v1/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(TestUsers.free),
    );
    
    expect(response.statusCode, 200);
    final data = jsonDecode(response.body);
    expect(data['access_token'], isNotNull);
    expect(data['user']['subscription_tier'], 'FREE');
  });

  test('login password sbagliata = 401', () async {
    final response = await http.post(
      Uri.parse('$apiBaseUrl/api/v1/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': TestUsers.free['email'], 'password': 'WRONG'}),
    );
    expect(response.statusCode, 401);
  });
}
```

---

# PARTE 6: COMANDI

```powershell
# === BACKEND (OBBLIGATORIO PRIMA DEI TEST) ===
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python seed_database.py
uvicorn main:app --reload --port 8000

# === TEST POWERSHELL ===
cd backend\tests\e2e
.\run_real_tests.ps1

# === REACT NATIVE ===
cd mobile
npm run test:e2e

# === FLUTTER ===
cd flutter_app
flutter test test/e2e/
```

---

# PARTE 7: CHECKLIST

## Prima di Ogni Test
- [ ] Backend attivo su localhost:8000?
- [ ] Seed eseguito?
- [ ] ZERO mock/jest.mock/mockito?

## Per Ogni Test Scritto
- [ ] Fallisce se spengo backend?
- [ ] Usa fetch/http REALE?
- [ ] Timeout >= 10s?

---

**QUESTO DOCUMENTO È LEGGE. TEST CON MOCK SARANNO RIFIUTATI.**

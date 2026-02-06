# 📋 DOCUMENTO MIGRAZIONE SESSIONE - 13 Gennaio 2026

## 🎯 CONTESTO PROGETTO

**Progetto:** Media Center Arti Marziali - Modulo Eventi/ASD
**Path:** `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali`

---

## 📊 STATO ATTUALE

### Test e Coverage

| Metrica | Valore |
|---------|--------|
| **Test totali** | 679 ✅ |
| **Coverage attuale** | 74.75% |
| **Coverage target** | 90% (minimo) / 95% (ideale) |
| **Gap** | -15.25% |

### Coverage per File

| File | Coverage | Target | Gap |
|------|----------|--------|-----|
| models.py | 100% ✅ | 95% | OK |
| __init__.py | 100% ✅ | 95% | OK |
| schemas.py | 90% ✅ | 95% | -5% |
| config.py | 90% ✅ | 95% | -5% |
| email_service.py | 73% | 90% | -17% |
| service.py | 71% | 90% | -19% |
| stripe_connect.py | 68% | 90% | -22% |
| gdpr_router.py | 72% | 90% | -18% |
| notifications.py | 62% | 90% | -28% |
| router.py | 58% | 90% | -32% |

---

## ✅ COMPLETATO OGGI (13 Gennaio 2026)

### 1. Integration Tests Frontend
- File: `frontend/src/__tests__/integration/events-user-pages.test.tsx`
- 33 test ZERO MOCK
- Tutti passano

### 2. Seed Data Script
- File: `backend/scripts/seed_events.py`
- 3 ASD Partners, 8 Eventi, Options, Subscriptions
- Idempotente

### 3. Email Service + Templates
- File: `backend/modules/events/email_service.py` (17KB)
- 7 template HTML in `backend/modules/events/templates/`
- SendGrid + SMTP fallback

### 4. GDPR System
- File: `backend/modules/events/gdpr_router.py` (13KB)
- Campi GDPR in EventSubscription model
- Checkbox frontend in checkout
- Migration SQL applicata

### 5. Sentry Frontend
- Abilitato in `sentry.client.config.ts`, `sentry.server.config.ts`, `sentry.edge.config.ts`

### 6. Email + Notifications Integration
- Integrato `EmailService` in `notifications.py`
- Metodo `_send_email_via_service()` per tutti i tipi alert

### 7. Bug Fix Stripe
- `stripe_verified` → `stripe_onboarding_complete`
- `current_capacity` → `current_subscriptions`
- `PENDING_PAYMENT` → `PENDING`
- `EXPIRED` → `CANCELLED`

---

## ❌ DA COMPLETARE

### Coverage 90%+ (Priorità ALTA)

I file sotto target hanno linee non coperte che richiedono:

1. **stripe_connect.py (68% → 90%)**
   - Chiavi Stripe TEST già in `.env` ✅
   - Testare `create_checkout_session` con API reale
   - Testare webhook handlers con payload reali
   - Usare `stripe-cli` per webhook testing

2. **router.py (58% → 90%)**
   - Testare TUTTI gli endpoint
   - Testare error paths (401, 403, 404, 422)
   - Testare con ruoli diversi

3. **notifications.py (62% → 90%)**
   - Testare `_send_email_via_service` per ogni AlertType
   - Testare scheduling methods
   - Testare `process_pending_notifications`

4. **email_service.py (73% → 90%)**
   - Usare MailHog su localhost:1025
   - Testare ogni metodo send_*
   - Testare template rendering

5. **service.py (71% → 90%)**
   - Testare edge cases CRUD
   - Testare tutti i filtri
   - Testare paginazione

---

## 🔧 CONFIGURAZIONE AMBIENTE

### Chiavi Stripe (già configurate in .env)
```
STRIPE_SECRET_KEY=sk_test_51Soj8m...
STRIPE_PUBLISHABLE_KEY=pk_test_51Soj8m...
STRIPE_WEBHOOK_SECRET=whsec_... (da aggiungere se mancante)
```

### Email Testing (MailHog)
```bash
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
```
- SMTP: localhost:1025
- Web UI: http://localhost:8025

### Database
```
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db
```

---

## 📝 PROMPT PER CONTINUARE COVERAGE

```
# TASK: Push Coverage to 90%+

## CONTEXT
- Current: 74.75% (679 tests)
- Target: 90% minimum
- Stripe TEST keys already in .env ✅
- Email testing via MailHog localhost:1025

## PRIORITY FILES

1. stripe_connect.py (68% → 90%)
2. router.py (58% → 90%)  
3. notifications.py (62% → 90%)
4. email_service.py (73% → 90%)
5. service.py (71% → 90%)

## METHOD

For each file:
1. Run: python -m pytest tests/ --cov=modules/events/[filename] --cov-report=term-missing -q
2. See uncovered lines
3. Write tests targeting those lines
4. Repeat until 85%+

## RULES
- ZERO MOCK
- Use real Stripe test API (keys in .env)
- Use MailHog for email testing
- Tests must FAIL if backend offline

START with stripe_connect.py. Show uncovered lines first.
```

---

## 📁 FILE CRITICI

### Backend
- `backend/modules/events/service.py` - Business logic
- `backend/modules/events/router.py` - API endpoints
- `backend/modules/events/stripe_connect.py` - Pagamenti
- `backend/modules/events/notifications.py` - Alert system
- `backend/modules/events/email_service.py` - Email transazionali
- `backend/modules/events/gdpr_router.py` - GDPR endpoints

### Frontend
- `frontend/src/app/events/page.tsx` - Lista eventi
- `frontend/src/app/events/[id]/page.tsx` - Dettaglio + checkout
- `frontend/src/app/me/subscriptions/page.tsx` - Le mie iscrizioni
- `frontend/src/app/me/waiting-list/page.tsx` - Lista attesa

### Test
- `backend/tests/test_events_service.py` - 359 test
- `backend/tests/test_events_router.py` - 219 test
- `backend/tests/modules/events/test_email_service.py` - 16 test
- `backend/tests/modules/events/test_gdpr_router.py` - 19 test
- `frontend/src/__tests__/integration/events-user-pages.test.tsx` - 33 test

---

## 🚀 PROSSIMI STEP

1. **Coverage 90%** - 2-3 ore
   - Usare prompt sopra con Code
   - Focus su file con gap maggiore

2. **Test E2E** - 4 ore
   - Flusso completo utente
   - Stripe checkout reale

3. **Deploy** - 4 ore
   - Docker compose
   - Railway/Fly.io

4. **Produzione** - 2-3 giorni totali

---

## 📞 COMANDI UTILI

```bash
# Backend
cd backend
python -m uvicorn main:app --reload --port 8000

# Frontend
cd frontend
npm run dev

# Test con coverage
python -m pytest tests/test_events_service.py tests/test_events_router.py tests/modules/events/ --cov=modules/events --cov-report=term-missing -q

# Seed data
python scripts/seed_events.py --verbose

# MailHog
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

---

**Data creazione:** 13 Gennaio 2026, 18:30
**Ultima sessione:** Coverage 74.75%, 679 test
**Prossimo obiettivo:** Coverage 90%+

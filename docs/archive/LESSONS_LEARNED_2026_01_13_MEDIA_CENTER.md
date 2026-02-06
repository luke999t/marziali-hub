# 📚 LESSONS LEARNED - Media Center Arti Marziali
## Data: 2026-01-13

---

## 🎯 SUMMARY SESSIONE

| Metrica | Valore |
|---------|--------|
| **Test totali** | 679 |
| **Coverage attuale** | 74.75% |
| **Coverage target** | 90% |
| **Gap** | -15.25% |
| **Nuovi test creati** | 33 (frontend integration) |

---

## ✅ COMPLETAMENTI

### 1. Integration Tests Frontend
- **File:** `frontend/src/__tests__/integration/events-user-pages.test.tsx`
- **Test:** 33 test ZERO MOCK
- **Stato:** Tutti passano ✅

### 2. Seed Data Script
- **File:** `backend/scripts/seed_events.py`
- **Contenuto:** 3 ASD Partners, 8 Eventi, Options, Subscriptions
- **Caratteristica:** Idempotente (può essere rieseguito)

### 3. Email Service + Templates
- **File:** `backend/modules/events/email_service.py` (17KB)
- **Templates:** 7 template HTML in `backend/modules/events/templates/`
- **Stack:** SendGrid + SMTP fallback

### 4. GDPR System
- **File:** `backend/modules/events/gdpr_router.py` (13KB)
- **Features:** 
  - Campi GDPR in EventSubscription model
  - Checkbox frontend in checkout
  - Migration SQL applicata

### 5. Sentry Frontend
- **Files:** sentry.client.config.ts, sentry.server.config.ts, sentry.edge.config.ts
- **Stato:** Abilitato ✅

### 6. Bug Fix Stripe
| Prima | Dopo |
|-------|------|
| stripe_verified | stripe_onboarding_complete |
| current_capacity | current_subscriptions |
| PENDING_PAYMENT | PENDING |
| EXPIRED | CANCELLED |

---

## 🔴 PROBLEMA PRINCIPALE: Coverage Gap

### File Sotto Target

| File | Coverage | Target | Gap |
|------|----------|--------|-----|
| router.py | 58% | 90% | -32% |
| notifications.py | 62% | 90% | -28% |
| stripe_connect.py | 68% | 90% | -22% |
| email_service.py | 73% | 90% | -17% |
| service.py | 71% | 90% | -19% |

### Approccio per Chiudere Gap

```bash
# Per ogni file sotto target:
python -m pytest tests/ --cov=modules/events/[filename] --cov-report=term-missing -q

# Output mostra linee non coperte, es:
# Name                    Stmts   Miss  Cover   Missing
# modules/events/router.py  450    189    58%   45-67, 120-145, 200-230
```

Poi scrivere test che esercitano quelle linee specifiche.

---

## 🛠️ CONFIGURAZIONE AMBIENTE

### Stripe TEST Keys (già in .env)
```
STRIPE_SECRET_KEY=sk_test_51Soj8m...
STRIPE_PUBLISHABLE_KEY=pk_test_51Soj8m...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### Email Testing con MailHog
```bash
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
```
- **SMTP:** localhost:1025
- **Web UI:** http://localhost:8025

MailHog cattura tutte le email inviate senza consegnarle realmente - perfetto per ZERO MOCK testing.

### Database
```
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db
```

---

## 🎓 PATTERN APPRESI

### 1. Coverage Incrementale
**Regola:** Usare `--cov-report=term-missing` per vedere esattamente quali linee mancano.

```bash
python -m pytest tests/test_X.py --cov=modules/X --cov-report=term-missing -q
```

### 2. Stripe Testing con TEST Keys
**Regola:** Chiavi `sk_test_*` permettono test reali senza processare pagamenti veri.

I test possono:
- Creare checkout sessions
- Simulare webhook
- Verificare onboarding flow

### 3. MailHog per Email Testing ZERO MOCK
**Regola:** MailHog cattura email SMTP senza inviarle.

```python
# In test
EMAIL_HOST = "localhost"
EMAIL_PORT = 1025

# Poi verifica in http://localhost:8025
```

### 4. Script Seed Idempotenti
**Regola:** Script di seed devono essere rieseguibili senza creare duplicati.

```python
# Pattern
existing = db.query(Model).filter(Model.unique_field == value).first()
if not existing:
    db.add(Model(...))
```

---

## 📋 PROSSIMI STEP

1. **Coverage 90%** - Priorità ALTA
   - Focus su file con gap maggiore (router.py, notifications.py)
   - Usare MailHog per email testing
   - Usare Stripe test keys per payment testing

2. **Test E2E** 
   - Flusso completo utente: browse → checkout → pagamento → conferma
   - Stripe checkout reale (test mode)

3. **Deploy**
   - Docker compose production
   - Railway/Fly.io

---

## 📞 COMANDI UTILI

```bash
# Backend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m uvicorn main:app --reload --port 8000

# Frontend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev

# Test con coverage dettagliato
python -m pytest tests/test_events_service.py tests/test_events_router.py tests/modules/events/ --cov=modules/events --cov-report=term-missing -q

# Seed data
python scripts/seed_events.py --verbose

# MailHog
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
```

---

*Documento generato: 13 Gennaio 2026*
*Coverage: 74.75% → Target 90%*

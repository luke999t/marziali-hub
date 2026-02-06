# 📅 MODULO EVENTI/ASD - STATO IMPLEMENTAZIONE

**Data:** 11 Gennaio 2026  
**Versione:** 1.1  
**Stato:** IMPLEMENTATO - Test in corso (51% coverage)

---

## 📊 RIEPILOGO

| Aspetto | Stato | Note |
|---------|-------|------|
| **Models** | ✅ Completo | 8 tabelle, 772 righe |
| **Schemas** | ✅ Completo | Pydantic v2, ~350 righe |
| **Config** | ✅ Completo | 2 livelli, ~375 righe |
| **Service** | ✅ Completo | Business logic, ~1200 righe, 10+ bug fixati |
| **Router** | ✅ Completo | ~50 endpoints, import error fixato |
| **Stripe Connect** | ✅ Completo | Split payment, ~450 righe |
| **Notifications** | ✅ Completo | Multi-channel, ~550 righe |
| **Migration** | ✅ Eseguita | PostgreSQL DDL, 8 tabelle create |
| **Test** | 🔄 In corso | 94 test passano, 51% coverage |
| **Frontend** | ✅ Completo | Lista + Dettaglio + API service |

**Totale codice backend:** ~225KB  
**Totale codice frontend:** ~35KB

---

## 🔧 BUG FIXATI (Sessione 11 Gennaio 2026)

### service.py - 10+ correzioni

| Bug | Prima | Dopo |
|-----|-------|------|
| Campo data evento | `Event.event_date` | `Event.start_date` |
| Campo fine vendita | `Event.sale_end` | Rimosso (non esiste) |
| Importo iscrizione | `amount_paid_cents` | `amount_cents` |
| Fee piattaforma | `platform_fee_cents` | `platform_amount_cents` |
| Quantità iscrizione | `subscription.quantity` | `1` (fisso) |
| Email waiting list | `EventWaitingList.email` | Rimosso (non esiste) |
| Posizione waiting list | `EventWaitingList.position` | `created_at` per ordinamento |
| Posti offerti WL | `spots_offered` | `notification_count` |
| Importo rimborso | `ASDRefundRequest.amount_cents` | `requested_amount_cents` |
| Approvazione rimborso | `Event.refund_approval_mode` | `ASDPartner.refund_approval_mode` |
| Capacità evento | `current_capacity` | `current_subscriptions` |

### router.py - 1 correzione

| Bug | Prima | Dopo |
|-----|-------|------|
| Import database | `get_async_session` | `get_db` |

---

## 📁 STRUTTURA FILE

```
backend/modules/events/
├── __init__.py           # Export modulo
├── models.py             # 8 tabelle SQLAlchemy (99% coverage)
├── schemas.py            # Pydantic v2 schemas (89% coverage)
├── config.py             # Configurazione 2 livelli (94% coverage)
├── service.py            # Business logic (64% coverage)
├── router.py             # FastAPI endpoints (0% → test in corso)
├── stripe_connect.py     # Integrazione Stripe (10% coverage)
└── notifications.py      # Sistema alert (11% coverage)

backend/tests/
├── test_events.py        # 36 test (models, config, schemas)
└── test_events_service.py # 58 test (service layer)

frontend/src/
├── app/events/
│   ├── page.tsx          # Lista eventi con filtri
│   └── [id]/page.tsx     # Dettaglio evento + checkout
├── components/events/
│   ├── EventCard.tsx     # Card preview evento
│   └── index.ts          # Export componenti
├── hooks/
│   └── useEvents.ts      # React hooks per API
└── services/
    └── eventsApi.ts      # API client completo
```

---

## 🧪 STATO TEST

### Risultati Attuali
| Metrica | Valore | Target |
|---------|--------|--------|
| **Test totali** | 94 | - |
| **Pass rate** | 100% | ✅ 100% |
| **Coverage totale** | 51% | 70%+ |
| **ZERO MOCK** | ✅ Confermato | ✅ |

### Coverage per File
| File | Coverage | Target | Status |
|------|----------|--------|--------|
| models.py | 99% | 90% | ✅ |
| config.py | 94% | 90% | ✅ |
| schemas.py | 89% | 85% | ✅ |
| service.py | 64% | 80% | 🔄 In corso |
| router.py | 0% | 60% | 🔄 In corso |
| stripe_connect.py | 10% | 50% | ⏳ |
| notifications.py | 11% | 50% | ⏳ |

### Test Suite
```
test_events.py (36 test)
├── TestEventModels - 12 test
├── TestEventConfigLayers - 8 test
├── TestEventSchemas - 10 test
└── TestComputedFields - 6 test

test_events_service.py (58 test)
├── TestEventServiceASD - 10 test
├── TestEventServiceEvents - 15 test
├── TestEventServiceOptions - 7 test
├── TestEventServiceWaitingList - 4 test
├── TestEventServiceStats - 4 test
├── TestEventServiceRefunds - 2 test
├── TestEventServiceSubscriptions - 2 test
├── TestNotificationServiceTests - 2 test
├── TestStripeConnectServiceTests - 2 test
├── TestComputedFieldsService - 6 test
└── TestEventServiceEdgeCases - 6 test
```

---

## 🖥️ FRONTEND IMPLEMENTATO

### Pagine
| Pagina | Path | Stato |
|--------|------|-------|
| Lista Eventi | `/events` | ✅ Con filtri, search, skeleton |
| Dettaglio Evento | `/events/[id]` | ✅ Con checkout, waiting list |

### Componenti
| Componente | File | Features |
|------------|------|----------|
| EventCard | `EventCard.tsx` | Badge stato, urgenza posti, prezzo |
| EventCardSkeleton | `EventCard.tsx` | Loading state |

### API Service
| Funzione | Endpoint | Descrizione |
|----------|----------|-------------|
| `getEvents()` | GET /events | Lista con filtri |
| `getEvent()` | GET /events/{id} | Dettaglio |
| `getEventOptions()` | GET /events/{id}/options | Opzioni evento |
| `createCheckout()` | POST /events/{id}/checkout | Crea sessione Stripe |
| `joinWaitingList()` | POST /events/{id}/waiting-list | Iscriviti WL |
| `leaveWaitingList()` | DELETE /events/{id}/waiting-list | Esci WL |
| `getMySubscriptions()` | GET /me/event-subscriptions | Mie iscrizioni |

### React Hooks
| Hook | Uso |
|------|-----|
| `useEvents(params)` | Lista eventi con loading/error |
| `useEvent(id)` | Singolo evento + opzioni |
| `useCheckout()` | Gestione checkout |
| `useWaitingList()` | Gestione waiting list |
| `useMySubscriptions()` | Iscrizioni utente |

---

## 🗄️ TABELLE DATABASE

### Schema Completo (8 tabelle)

```sql
-- 1. asd_partners: Partner ASD con Stripe Connect
-- 2. events: Eventi/stage con capacità
-- 3. event_options: Opzioni evento (full, weekend, etc.)
-- 4. event_subscriptions: Iscrizioni con split payment
-- 5. event_waiting_list: Lista attesa
-- 6. asd_refund_requests: Richieste rimborso
-- 7. platform_alert_config: Config alert piattaforma
-- 8. event_notifications: Notifiche schedulate
```

### Enum Types Creati
- `event_status`: draft, presale, open, sold_out, cancelled, completed
- `event_subscription_status`: pending, confirmed, cancelled, refunded
- `event_refund_status`: pending, approved, rejected, processed
- `refund_approval_mode`: always_required, never_required, per_event
- `event_alert_type`: 9 tipi (reminder, presale, sale, etc.)
- `notification_channel`: email, push, sms, dashboard

---

## 🔌 API ENDPOINTS (50+)

### ASD Partners (6)
```
POST   /events/asd                     # Crea ASD partner
GET    /events/asd                     # Lista ASD
GET    /events/asd/{id}                # Dettaglio ASD
PUT    /events/asd/{id}                # Modifica ASD
DELETE /events/asd/{id}                # Disattiva ASD
POST   /events/asd/{id}/stripe-connect # Onboarding Stripe
```

### Eventi (8)
```
POST   /events                         # Crea evento
GET    /events                         # Lista eventi
GET    /events/{id}                    # Dettaglio evento
PUT    /events/{id}                    # Modifica evento
GET    /events/{id}/availability       # Disponibilità
POST   /events/{id}/publish            # Pubblica evento
POST   /events/{id}/cancel             # Annulla evento
GET    /events/{id}/stats              # Statistiche
```

### Opzioni (4)
```
POST   /events/{id}/options            # Aggiungi opzione
GET    /events/{id}/options            # Lista opzioni
PUT    /events/{id}/options/{oid}      # Modifica opzione
DELETE /events/{id}/options/{oid}      # Rimuovi opzione
```

### Checkout & Iscrizioni (5)
```
POST   /events/{id}/checkout           # Crea Stripe session
GET    /events/{id}/subscriptions      # Lista iscritti (admin)
GET    /subscriptions/{id}             # Dettaglio iscrizione
POST   /subscriptions/{id}/confirm     # Conferma iscrizione
GET    /me/event-subscriptions         # Mie iscrizioni
```

### Waiting List (4)
```
POST   /events/{id}/waiting-list       # Iscriviti
DELETE /events/{id}/waiting-list       # Esci
GET    /events/{id}/waiting-list       # Lista (admin)
GET    /events/{id}/waiting-list/me    # Mia posizione
```

### Rimborsi (5)
```
POST   /refunds                        # Richiedi rimborso
GET    /refunds                        # Lista (admin)
GET    /refunds/{id}                   # Dettaglio
POST   /refunds/{id}/approve           # Approva
POST   /refunds/{id}/reject            # Rifiuta
```

### Dashboard & Config (4)
```
GET    /asd/dashboard                  # Dashboard ASD
GET    /asd/earnings                   # Incassi
GET    /admin/alert-config             # Config alert
PUT    /admin/alert-config/{type}      # Modifica config
```

---

## 💳 STRIPE CONNECT

### Split Payment
```
Utente paga €150
├── Stripe fee: ~€3.35 (2.9% + €0.25)
├── Netto: €146.65
│   ├── Platform 15%: €22.00 → Conto LIBRA
│   └── ASD 85%: €124.65 → Conto ASD (transfer)
```

### Flusso
1. ASD completa onboarding Stripe Express
2. Utente fa checkout → Stripe Checkout Session
3. Pagamento confermato → webhook `payment_intent.succeeded`
4. Transfer automatico ad ASD
5. Iscrizione confermata

---

## 📋 DECISIONI CONFERMATE

| Decisione | Scelta | Motivazione |
|-----------|--------|-------------|
| Self-cancel utente | ❌ NO | Deve contattare ASD |
| Fee Stripe | Ognuno le sue | ASD paga su sua quota |
| Notifiche | Email + Push | Entrambe configurabili |
| Soglia minima | Alert manuale | Admin decide |
| Waiting list | Notify all | Primo che paga vince |
| Approvazione rimborsi | Configurabile per ASD | Default: sempre richiesta |
| Split default | 85% ASD, 15% platform | Configurabile per evento |

---

## 🚀 PROSSIMI STEP

### Immediati
1. ✅ ~~Completare fix service.py~~ (fatto)
2. ✅ ~~Fix import router.py~~ (fatto)
3. 🔄 Completare test (target 70%+ coverage)
4. ⏳ Integrare router in main.py

### Breve termine
5. Dashboard ASD (frontend admin)
6. Pagina "Le mie iscrizioni" utente
7. Test end-to-end con Stripe test mode

### Medio termine
8. Notifiche push (Firebase/OneSignal)
9. Export CSV iscritti
10. Reportistica incassi

---

## 📎 FILE CORRELATI

- **Design originale:** `docs/DESIGN_MODULO_EVENTI_ASD.md`
- **Migration:** `migrations/create_events_tables.py`
- **Test models:** `tests/test_events.py`
- **Test service:** `tests/test_events_service.py`
- **Frontend API:** `frontend/src/services/eventsApi.ts`

---

## 📝 CHANGELOG

### v1.1 (11 Gennaio 2026 - sera)
- ✅ Fixati 10+ bug in service.py
- ✅ Fix import error router.py (get_async_session → get_db)
- ✅ 94 test passano (100% pass rate)
- ✅ Coverage da 36% a 51%
- ✅ Frontend completo (lista, dettaglio, API service, hooks)

### v1.0 (11 Gennaio 2026 - pomeriggio)
- ✅ Implementazione completa modulo
- ✅ Migration eseguita (8 tabelle)
- ✅ 36 test iniziali

---

**Ultimo aggiornamento:** 11 Gennaio 2026, 22:15

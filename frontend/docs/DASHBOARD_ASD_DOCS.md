# 📊 DASHBOARD ASD - DOCUMENTAZIONE TECNICA

**Data:** 11 Gennaio 2026  
**Versione:** 1.0  
**Stato:** IMPLEMENTATO  
**Path:** `frontend/src/app/asd-dashboard/`

---

## 📋 INDICE

1. [Overview](#1-overview)
2. [Struttura File](#2-struttura-file)
3. [API Service](#3-api-service)
4. [Pagine](#4-pagine)
5. [Componenti](#5-componenti)
6. [Flussi Utente](#6-flussi-utente)
7. [Integrazione Backend](#7-integrazione-backend)
8. [Testing](#8-testing)

---

## 1. OVERVIEW

### 1.1 Scopo

La Dashboard ASD è il centro di controllo per gli organizzatori di eventi (ASD - Associazioni Sportive Dilettantistiche). Permette di:

- Creare e gestire eventi
- Monitorare iscrizioni in tempo reale
- Analizzare incassi e payout
- Gestire account Stripe Connect
- Processare rimborsi

### 1.2 Utenti Target

| Ruolo | Accesso | Funzionalità |
|-------|---------|--------------|
| Admin ASD | Completo | Tutte le funzionalità |
| Staff ASD | Limitato | Solo visualizzazione (futuro) |
| Super Admin | Completo + Admin | Gestione multi-ASD (futuro) |

### 1.3 Requisiti Accesso

- Utente autenticato
- Ruolo `asd_admin` o superiore
- ASD associata all'utente (`asd_partners.admin_user_id`)

---

## 2. STRUTTURA FILE

```
frontend/src/
├── services/
│   ├── eventsApi.ts           # API pubbliche eventi (esistente)
│   └── asdDashboardApi.ts     # API dashboard ASD (NUOVO)
│
└── app/asd-dashboard/
    ├── page.tsx               # Dashboard principale
    ├── events/
    │   ├── page.tsx           # Lista eventi
    │   ├── new/
    │   │   └── page.tsx       # Crea evento
    │   └── [id]/
    │       └── page.tsx       # Dettaglio evento
    ├── earnings/
    │   └── page.tsx           # Report incassi
    └── stripe/
        └── page.tsx           # Gestione Stripe Connect
```

---

## 3. API SERVICE

### 3.1 File: `services/asdDashboardApi.ts`

#### Types Principali

```typescript
// Statistiche dashboard
interface DashboardStats {
  total_events: number;
  active_events: number;
  total_subscriptions: number;
  pending_subscriptions: number;
  total_earnings_cents: number;
  pending_payout_cents: number;
  last_payout_date?: string;
  conversion_rate: number;
}

// Statistiche evento
interface EventStats {
  event_id: string;
  title: string;
  total_capacity: number;
  current_subscriptions: number;
  confirmed_subscriptions: number;
  cancelled_subscriptions: number;
  refunded_subscriptions: number;
  waiting_list_count: number;
  total_revenue_cents: number;
  asd_revenue_cents: number;
  platform_fee_cents: number;
  fill_rate: number;
}

// Dettaglio iscrizione (per admin)
interface SubscriptionDetail extends EventSubscription {
  user_email: string;
  user_name: string;
  user_phone?: string;
  option_name: string;
  asd_amount_cents: number;
  platform_amount_cents: number;
  payment_date?: string;
  refund_requested: boolean;
  refund_status?: 'pending' | 'approved' | 'rejected' | 'processed';
}

// Report incassi
interface EarningsReport {
  period_start: string;
  period_end: string;
  total_revenue_cents: number;
  asd_share_cents: number;
  platform_fee_cents: number;
  stripe_fee_cents: number;
  net_payout_cents: number;
  subscriptions_count: number;
  refunds_count: number;
  refunds_amount_cents: number;
  events_breakdown: EventEarnings[];
}

// Info payout Stripe
interface PayoutInfo {
  stripe_account_id: string;
  stripe_account_status: 'pending' | 'active' | 'restricted';
  available_balance_cents: number;
  pending_balance_cents: number;
  last_payout_date?: string;
  last_payout_amount_cents?: number;
  next_payout_date?: string;
}
```

#### Funzioni API

| Funzione | Endpoint | Descrizione |
|----------|----------|-------------|
| `getDashboardStats(asdId)` | `GET /asd/{id}/dashboard` | Stats aggregate |
| `getMyASD()` | `GET /asd/me` | Info ASD corrente |
| `getASDEvents(asdId, params)` | `GET /asd/{id}/events` | Lista eventi |
| `createEvent(asdId, data)` | `POST /asd/{id}/events` | Crea evento |
| `updateEvent(eventId, data)` | `PATCH /events/{id}` | Aggiorna evento |
| `publishEvent(eventId)` | `POST /events/{id}/publish` | Pubblica |
| `cancelEvent(eventId, reason)` | `POST /events/{id}/cancel` | Annulla |
| `getEventStats(eventId)` | `GET /events/{id}/stats` | Stats evento |
| `getEventSubscriptions(eventId)` | `GET /events/{id}/subscriptions` | Lista iscritti |
| `exportSubscriptionsCSV(eventId)` | `GET /events/{id}/subscriptions/export` | Export CSV |
| `getEarningsReport(asdId, start, end)` | `GET /asd/{id}/earnings` | Report incassi |
| `getPayoutInfo(asdId)` | `GET /asd/{id}/stripe/status` | Info Stripe |
| `startStripeOnboarding(asdId, returnUrl)` | `POST /asd/{id}/stripe/connect` | Avvia onboarding |
| `getStripeDashboardLink(asdId)` | `POST /asd/{id}/stripe/dashboard-link` | Link dashboard |

---

## 4. PAGINE

### 4.1 Dashboard Principale (`/asd-dashboard`)

**Componenti:**
- `StatCard` - Card con singola statistica
- `EventRow` - Riga tabella evento
- `RefundRow` - Riga rimborso pendente

**Dati caricati:**
- `getDashboardStats()` - Stats aggregate
- `getASDEvents(limit: 5)` - Ultimi 5 eventi
- `getRefundRequests(status: 'pending', limit: 5)` - Rimborsi pendenti

### 4.2 Lista Eventi (`/asd-dashboard/events`)

**Features:**
- Filtro per status (draft, open, presale, sold_out, completed, cancelled)
- Progress bar fill rate colorata
- Azioni rapide (Pubblica, Annulla)

### 4.3 Dettaglio Evento (`/asd-dashboard/events/[id]`)

**Tabs:**
1. **Overview** - Descrizione, location, stats breakdown
2. **Iscritti** - Tabella con export CSV
3. **Opzioni** - Lista opzioni prezzo
4. **Waiting List** - Lista attesa

### 4.4 Crea Evento (`/asd-dashboard/events/new`)

**Sezioni Form:**
1. Informazioni Base (titolo, descrizione, immagine)
2. Date (inizio, fine)
3. Location (nome, indirizzo, città, maps)
4. Capacità (posti, soglia minima)
5. Prevendita (toggle, date)

### 4.5 Report Incassi (`/asd-dashboard/earnings`)

**Features:**
- Filtro periodo (mese, trimestre, anno, custom)
- Riepilogo payout con calcolo netto
- Breakdown per evento

### 4.6 Stripe Connect (`/asd-dashboard/stripe`)

**States:**
1. **No Account** - CTA onboarding
2. **Pending** - Warning completamento
3. **Active** - Saldo e azioni

---

## 5. FLUSSI UTENTE

### 5.1 Creazione Evento

```
1. Dashboard → Click "+ Nuovo Evento"
2. Form creazione → Compila campi obbligatori
3. Submit → Evento creato in stato DRAFT
4. Redirect → Dettaglio evento
5. Aggiungi opzioni prezzo
6. Click "Pubblica" → Evento OPEN/PRESALE
```

### 5.2 Gestione Iscritti

```
1. Dashboard → Click evento dalla tabella
2. Dettaglio → Tab "Iscritti"
3. Visualizza lista con status
4. Export CSV per liste presenze
```

### 5.3 Onboarding Stripe

```
1. Dashboard → Quick Action "Stripe Connect"
2. Stripe page → Click "Inizia Configurazione"
3. Redirect → Stripe Onboarding (esterno)
4. Completa dati su Stripe
5. Redirect back → Account attivo
```

---

## 6. INTEGRAZIONE BACKEND

### 6.1 Endpoint Richiesti

```python
# Dashboard
GET  /api/v1/events/asd/me                    # ASD corrente
GET  /api/v1/events/asd/{id}/dashboard        # Stats dashboard
GET  /api/v1/events/asd/{id}/events           # Lista eventi ASD
GET  /api/v1/events/asd/{id}/earnings         # Report incassi

# Eventi
POST /api/v1/events/asd/{id}/events           # Crea evento
GET  /api/v1/events/{id}/stats                # Stats evento
GET  /api/v1/events/{id}/subscriptions        # Lista iscritti
GET  /api/v1/events/{id}/subscriptions/export # Export CSV

# Stripe
GET  /api/v1/events/asd/{id}/stripe/status    # Info account
POST /api/v1/events/asd/{id}/stripe/connect   # Avvia onboarding
POST /api/v1/events/asd/{id}/stripe/dashboard-link # Link dashboard
```

---

## 7. TESTING

### 7.1 Test Coverage Target

| Area | Target |
|------|--------|
| API Service | 90% |
| Pages | 80% |
| Components | 85% |

---

**Ultimo aggiornamento:** 11 Gennaio 2026

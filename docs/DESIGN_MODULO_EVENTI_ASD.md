# 🎯 DESIGN MODULO EVENTI/ASD - MEDIA CENTER

**Data:** 11 Gennaio 2026  
**Versione:** 1.0  
**Stato:** APPROVATO - Pronto per sviluppo  
**Priorità:** CRITICA (90% ricavi LIBRA)

---

## 📋 INDICE

1. [Contesto e Obiettivi](#1-contesto-e-obiettivi)
2. [Requisiti Funzionali](#2-requisiti-funzionali)
3. [Configurazioni Globali](#3-configurazioni-globali)
4. [Schema Database](#4-schema-database)
5. [Flussi Principali](#5-flussi-principali)
6. [API Endpoints](#6-api-endpoints)
7. [Stripe Connect Integration](#7-stripe-connect-integration)
8. [Effort Stimato](#8-effort-stimato)

---

## 1. CONTESTO E OBIETTIVI

### Perché questo modulo

LIBRA (prospect) guadagna principalmente vendendo **bundle = stage fisico (ASD) + corso digitale (LIBRA)**.

Il Media Center attuale NON ha:
- Gestione eventi/stage
- Collegamento evento ↔ corso digitale
- Split payment ASD/LIBRA
- Dashboard ASD

### Obiettivo

Creare sistema **completamente configurabile** per:
- Vendere eventi fisici (stage, workshop, seminari)
- Abbinare corsi digitali (bundle)
- Splittare pagamenti tra ASD e LIBRA
- Gestire prevendite, waiting list, annullamenti

---

## 2. REQUISITI FUNZIONALI

### 2.1 Gestione Eventi

| # | Requisito | Note |
|---|-----------|------|
| E1 | Opzioni durata multiple | 5gg, 3gg, 2gg, "4 weekend" - configurabile |
| E2 | Capacità condivisa | Posti totali consumati da qualsiasi opzione |
| E3 | Soglia minima | Alert manuale X giorni prima, admin decide |
| E4 | Stati evento | BOZZA → PREVENDITA → APERTO → COMPLETO → ANNULLATO |

### 2.2 Prevendita

| # | Requisito | Note |
|---|-----------|------|
| P1 | Periodo riservato | Data inizio/fine prevendita |
| P2 | Criteri configurabili | Lista email, abbonamento attivo, corso acquistato, percorso studio |
| P3 | Logica criteri | AND (tutti) oppure OR (almeno uno) |

### 2.3 Bundle e Prezzi

| # | Requisito | Note |
|---|-----------|------|
| B1 | Bundle stage + corso | Ogni opzione può avere corso diverso |
| B2 | Vendita singola opzionale | ASD sceglie se vendere solo stage |
| B3 | Prezzi separati | Quota ASD + Quota LIBRA configurabili |

### 2.4 Pagamenti

| # | Requisito | Note |
|---|-----------|------|
| $1 | Split Stripe Connect | Ogni soggetto incassa diretto |
| $2 | Refund parte ASD | Via Stripe o "gestito da ASD" |
| $3 | Refund parte LIBRA | Solo admin LIBRA |

### 2.5 Annullamenti

| # | Requisito | Note |
|---|-----------|------|
| A1 | Annulla singolo (ASD) | Con approvazione LIBRA configurabile |
| A2 | Annulla evento intero | Solo admin LIBRA, refund massivo |
| A3 | Corso su annullamento | Configurabile: rimborsa o mantieni |
| A4 | Modalità approvazione | "sempre" / "mai" / "per_evento" |

### 2.6 Waiting List

| # | Requisito | Note |
|---|-----------|------|
| W1 | Iscrizione a lista | Quando posti esauriti |
| W2 | Notifica collettiva | Email a TUTTI quando posto libero |
| W3 | Primo che paga vince | No prenotazione, chi arriva prima |

---

## 3. CONFIGURAZIONI GLOBALI

```yaml
# Config LIBRA Admin - a livello piattaforma
eventi_asd:
  
  # Approvazione rimborsi ASD
  rimborsi:
    modalita_default: "approvazione_libra"  # "approvazione_libra" | "automatico" | "per_evento"
  
  # Cosa succede al corso se evento annullato
  corso_su_annullamento:
    default: "configurabile"  # "rimborsa_tutto" | "mantieni_corso" | "configurabile"
  
  # Alert soglia minima
  soglia_minima:
    tipo: "alert_manuale"  # Mai automatico
    giorni_prima_default: 20
  
  # Waiting list
  waiting_list:
    notifica: "tutti"  # Notifica tutti, primo che paga vince
    
  # Stripe Connect
  stripe:
    platform_fee_percent: 0  # LIBRA non prende fee su parte ASD
```

---

## 4. SCHEMA DATABASE

### 4.1 Tabella: `events`

```sql
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relazioni
    asd_id UUID NOT NULL REFERENCES asd_partners(id),
    created_by_admin_id UUID NOT NULL REFERENCES users(id),
    
    -- Info base
    title VARCHAR(255) NOT NULL,
    description TEXT,
    location VARCHAR(500),
    location_url VARCHAR(500),  -- Google Maps link
    
    -- Date
    start_date DATE NOT NULL,
    end_date DATE NOT NULL,
    
    -- Capacità
    total_capacity INTEGER NOT NULL,
    occupied_seats INTEGER DEFAULT 0,  -- Calcolato da trigger
    
    -- Soglia minima (opzionale)
    min_threshold_euros INTEGER,  -- NULL = nessuna soglia
    min_threshold_participants INTEGER,
    threshold_alert_days INTEGER DEFAULT 20,
    threshold_alert_sent BOOLEAN DEFAULT FALSE,
    
    -- Stato
    status VARCHAR(20) DEFAULT 'draft',  -- draft, presale, open, full, cancelled
    cancellation_reason VARCHAR(50),
    cancellation_notes TEXT,
    
    -- Prevendita
    presale_enabled BOOLEAN DEFAULT FALSE,
    presale_start TIMESTAMP WITH TIME ZONE,
    presale_end TIMESTAMP WITH TIME ZONE,
    presale_criteria JSONB,  -- Vedi struttura sotto
    
    -- Config annullamenti
    course_on_cancellation VARCHAR(20) DEFAULT 'default',  -- default, refund, keep
    refund_approval_mode VARCHAR(20) DEFAULT 'default',  -- default, always, never
    
    -- Metadata
    cover_image_url VARCHAR(500),
    tags VARCHAR(50)[],
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    published_at TIMESTAMP WITH TIME ZONE,
    cancelled_at TIMESTAMP WITH TIME ZONE
);

-- Indici
CREATE INDEX idx_events_asd ON events(asd_id);
CREATE INDEX idx_events_status ON events(status);
CREATE INDEX idx_events_dates ON events(start_date, end_date);
```

### 4.2 Struttura `presale_criteria` (JSONB)

```json
{
  "logic": "or",
  "criteria": [
    {
      "type": "email_list",
      "emails": ["mario@example.com", "luigi@example.com"]
    },
    {
      "type": "active_subscription",
      "tiers": ["premium", "standard"]
    },
    {
      "type": "course_purchased",
      "course_ids": ["uuid1", "uuid2"]
    },
    {
      "type": "study_path",
      "path_id": "uuid"
    }
  ]
}
```

### 4.3 Tabella: `event_options`

```sql
CREATE TABLE event_options (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    
    -- Info
    name VARCHAR(255) NOT NULL,  -- "5 giorni completi", "Solo weekend"
    description TEXT,
    
    -- Date incluse
    included_dates DATE[] NOT NULL,  -- ["2026-01-20", "2026-01-21", ...]
    
    -- Prezzi (in centesimi)
    price_asd_cents INTEGER NOT NULL,  -- Quota ASD
    price_course_cents INTEGER DEFAULT 0,  -- Quota LIBRA (0 se no corso)
    
    -- Corso abbinato (opzionale)
    linked_course_id UUID REFERENCES courses(id),
    
    -- Config vendita
    sellable_standalone BOOLEAN DEFAULT TRUE,  -- Vendibile senza corso?
    max_seats INTEGER,  -- NULL = usa capacità evento
    
    -- Stato
    is_active BOOLEAN DEFAULT TRUE,
    sort_order INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_event_options_event ON event_options(event_id);
```

### 4.4 Tabella: `event_subscriptions`

```sql
CREATE TABLE event_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relazioni
    event_id UUID NOT NULL REFERENCES events(id),
    option_id UUID NOT NULL REFERENCES event_options(id),
    user_id UUID NOT NULL REFERENCES users(id),
    
    -- Tipo acquisto
    purchase_type VARCHAR(20) NOT NULL,  -- bundle, stage_only
    
    -- Pagamenti (centesimi)
    paid_asd_cents INTEGER NOT NULL,
    paid_course_cents INTEGER DEFAULT 0,
    total_paid_cents INTEGER NOT NULL,
    
    -- Stripe
    stripe_payment_intent_id VARCHAR(255),
    stripe_asd_transfer_id VARCHAR(255),
    
    -- Stato
    status VARCHAR(30) DEFAULT 'active',
    -- active, cancelled_user, cancelled_asd, cancelled_event, refunded
    
    -- Annullamento
    cancelled_at TIMESTAMP WITH TIME ZONE,
    cancellation_reason VARCHAR(50),
    cancellation_notes TEXT,
    
    -- Refund
    refund_asd_status VARCHAR(20),  -- pending, completed, manual
    refund_asd_stripe_id VARCHAR(255),
    refund_course_status VARCHAR(20),
    refund_course_stripe_id VARCHAR(255),
    refund_handled_by VARCHAR(20),  -- stripe, asd_manual
    
    -- Accesso corso
    course_access_granted BOOLEAN DEFAULT FALSE,
    course_access_revoked BOOLEAN DEFAULT FALSE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_event_subs_event ON event_subscriptions(event_id);
CREATE INDEX idx_event_subs_user ON event_subscriptions(user_id);
CREATE INDEX idx_event_subs_status ON event_subscriptions(status);
CREATE UNIQUE INDEX idx_event_subs_unique ON event_subscriptions(event_id, option_id, user_id) 
    WHERE status = 'active';
```

### 4.5 Tabella: `event_waiting_list`

```sql
CREATE TABLE event_waiting_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    event_id UUID NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    option_id UUID REFERENCES event_options(id),  -- NULL = qualsiasi opzione
    user_id UUID NOT NULL REFERENCES users(id),
    email VARCHAR(255) NOT NULL,
    
    -- Notifiche
    notified_at TIMESTAMP WITH TIME ZONE,
    notification_count INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(event_id, user_id)
);

CREATE INDEX idx_waiting_list_event ON event_waiting_list(event_id);
```

### 4.6 Tabella: `asd_refund_requests`

```sql
CREATE TABLE asd_refund_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Relazioni
    subscription_id UUID NOT NULL REFERENCES event_subscriptions(id),
    asd_id UUID NOT NULL REFERENCES asd_partners(id),
    
    -- Richiesta
    reason VARCHAR(50) NOT NULL,
    notes TEXT,
    
    -- Stato
    status VARCHAR(20) DEFAULT 'pending',  -- pending, approved, rejected
    
    -- Gestione
    handled_by_admin_id UUID REFERENCES users(id),
    admin_notes TEXT,
    handled_at TIMESTAMP WITH TIME ZONE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_refund_requests_status ON asd_refund_requests(status);
CREATE INDEX idx_refund_requests_asd ON asd_refund_requests(asd_id);
```

### 4.7 Tabella: `asd_partners`

```sql
CREATE TABLE asd_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Info
    name VARCHAR(255) NOT NULL,
    legal_name VARCHAR(255),
    tax_code VARCHAR(50),  -- Codice fiscale / P.IVA
    
    -- Contatti
    email VARCHAR(255) NOT NULL,
    phone VARCHAR(50),
    address TEXT,
    
    -- Stripe Connect
    stripe_account_id VARCHAR(255),  -- acct_xxxxx
    stripe_onboarding_complete BOOLEAN DEFAULT FALSE,
    stripe_charges_enabled BOOLEAN DEFAULT FALSE,
    stripe_payouts_enabled BOOLEAN DEFAULT FALSE,
    
    -- Admin riferimento
    admin_user_id UUID REFERENCES users(id),
    
    -- Config
    refund_approval_mode VARCHAR(20) DEFAULT 'default',
    
    -- Stato
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_asd_stripe ON asd_partners(stripe_account_id) WHERE stripe_account_id IS NOT NULL;
```

---

## 5. FLUSSI PRINCIPALI

### 5.1 Creazione Evento (Admin LIBRA)

```
1. Admin apre "Nuovo Evento"
2. Seleziona ASD partner
3. Compila info base (titolo, date, location, capacità)
4. Configura opzioni:
   - Opzione 1: "5 giorni" - €200 ASD + €100 corso
   - Opzione 2: "Weekend" - €100 ASD + €100 corso
5. Configura prevendita (opzionale):
   - Periodo: 1-10 gennaio
   - Criteri: lista email OR abbonamento premium
6. Configura soglia minima (opzionale):
   - €2000 minimo, alert 20gg prima
7. Configura annullamenti:
   - Corso se annullato: mantieni / rimborsa
   - Approvazione ASD: sempre richiesta
8. Pubblica → stato PREVENDITA o APERTO
```

### 5.2 Acquisto Utente

```
1. Utente vede evento
2. Sistema verifica:
   - Se PREVENDITA → check criteri
   - Se criteri non soddisfatti → "Disponibile dal [data]"
3. Utente sceglie opzione (5gg, weekend, etc)
4. Utente sceglie:
   - Bundle (stage + corso) → totale €300
   - Solo stage (se permesso) → totale €200
5. Checkout Stripe:
   - Payment Intent con transfer_data per split
   - €200 → ASD Stripe account
   - €100 → LIBRA Stripe account
6. Successo:
   - Crea event_subscription
   - Aggiorna posti occupati
   - Se bundle → grant accesso corso
   - Email conferma
7. Se waiting list attiva → rimuovi utente da lista
```

### 5.3 Annullamento Singolo (richiesta ASD)

```
1. ASD da dashboard → "Annulla Mario Rossi"
2. Inserisce motivo
3. Sistema verifica config approvazione:

   SE "sempre" o "per_evento con approvazione":
   → Crea asd_refund_request (pending)
   → Notifica admin LIBRA
   → Admin approva/rifiuta
   → Se approvato → procedi refund
   
   SE "mai":
   → Refund diretto parte ASD
   → Gestione corso secondo config

4. Refund:
   - Stripe refund €200 → utente
   - Se corso "rimborsa" → Stripe refund €100 + revoca accesso
   - Se corso "mantieni" → utente tiene corso
5. Posto liberato → notifica waiting list
```

### 5.4 Annullamento Evento Intero (Admin LIBRA)

```
1. Admin → "Annulla Evento"
2. Seleziona motivo:
   - Minimo partecipanti non raggiunto
   - Maestro indisponibile
   - Forza maggiore
   - Altro
3. Conferma
4. Sistema per OGNI iscrizione:
   - Refund parte ASD (da conto ASD)
   - Refund parte LIBRA (da conto LIBRA)
   - Gestione corso secondo config
5. Email a tutti i partecipanti con motivo
6. Notifica waiting list "evento annullato"
7. Evento → stato CANCELLED
```

### 5.5 Waiting List

```
1. Utente tenta acquisto → posti esauriti
2. Opzione "Avvisami quando disponibile"
3. Utente inserisce email (o usa account)
4. Crea record waiting_list

QUANDO POSTO SI LIBERA:
5. Trigger su decremento posti_occupati
6. Email a TUTTI in waiting list per quell'evento/opzione
7. Primo che completa acquisto → prende posto
8. Acquirente rimosso da waiting list
```

### 5.6 Alert Soglia Minima

```
CRON giornaliero:
1. Trova eventi con soglia_minima configurata
2. Per ogni evento:
   - Calcola giorni a evento
   - Se giorni <= threshold_alert_days AND NOT alert_sent:
     - Calcola totale incassato / partecipanti
     - Se sotto soglia → Alert admin
     - Marca threshold_alert_sent = TRUE
3. Admin riceve alert con opzioni:
   - "Procedi comunque"
   - "Annulla evento"
```

---

## 6. API ENDPOINTS

### 6.1 Eventi (Admin LIBRA)

```
POST   /api/v1/events
       Body: { asd_id, title, description, location, start_date, end_date, 
               total_capacity, presale_config, threshold_config, ... }
       Response: Event

GET    /api/v1/events
       Query: ?status=open&asd_id=xxx&from_date=xxx
       Response: { items: Event[], total, page }

GET    /api/v1/events/{event_id}
       Response: Event con options, stats

PUT    /api/v1/events/{event_id}
       Body: { ...campi da aggiornare }
       Response: Event

POST   /api/v1/events/{event_id}/publish
       Response: Event (status → presale/open)

POST   /api/v1/events/{event_id}/cancel
       Body: { reason, notes }
       Response: { success, refunds_initiated: number }
```

### 6.2 Opzioni Evento

```
POST   /api/v1/events/{event_id}/options
       Body: { name, included_dates, price_asd_cents, price_course_cents,
               linked_course_id, sellable_standalone }
       Response: EventOption

PUT    /api/v1/events/{event_id}/options/{option_id}
       Body: { ...campi }
       Response: EventOption

DELETE /api/v1/events/{event_id}/options/{option_id}
       Response: { success }
```

### 6.3 Iscrizioni / Acquisti

```
POST   /api/v1/events/{event_id}/checkout
       Body: { option_id, purchase_type: "bundle"|"stage_only" }
       Response: { checkout_url }  // Stripe Checkout Session

GET    /api/v1/events/{event_id}/participants
       Auth: Admin o ASD owner
       Response: { items: Subscription[], total }

GET    /api/v1/my/event-subscriptions
       Auth: User
       Response: { items: Subscription[] }
```

### 6.4 Annullamenti

```
POST   /api/v1/subscriptions/{sub_id}/cancel
       Auth: User (self-cancel, se permesso)
       Body: { reason }
       Response: { success, refund_status }

POST   /api/v1/asd/refund-requests
       Auth: ASD
       Body: { subscription_id, reason, notes }
       Response: RefundRequest

GET    /api/v1/admin/refund-requests
       Auth: Admin
       Query: ?status=pending
       Response: { items: RefundRequest[] }

POST   /api/v1/admin/refund-requests/{req_id}/approve
       Auth: Admin
       Body: { admin_notes }
       Response: RefundRequest

POST   /api/v1/admin/refund-requests/{req_id}/reject
       Auth: Admin
       Body: { admin_notes }
       Response: RefundRequest
```

### 6.5 Waiting List

```
POST   /api/v1/events/{event_id}/waiting-list
       Body: { option_id?, email? }  // email se non loggato
       Response: WaitingListEntry

DELETE /api/v1/events/{event_id}/waiting-list
       Auth: User
       Response: { success }

GET    /api/v1/events/{event_id}/waiting-list
       Auth: Admin
       Response: { items: WaitingListEntry[], total }
```

### 6.6 Dashboard ASD

```
GET    /api/v1/asd/dashboard
       Auth: ASD
       Response: { 
         events: Event[], 
         total_earnings_cents,
         pending_earnings_cents,
         upcoming_payouts 
       }

GET    /api/v1/asd/events/{event_id}/participants
       Auth: ASD (solo suoi eventi)
       Response: { items: Subscription[] }

GET    /api/v1/asd/earnings
       Auth: ASD
       Query: ?from=xxx&to=xxx
       Response: { items: EarningEntry[], total_cents }
```

---

## 7. STRIPE CONNECT INTEGRATION

### 7.1 Onboarding ASD

```python
# Crea account Connect per ASD
account = stripe.Account.create(
    type="express",  # o "standard" per più controllo
    country="IT",
    email=asd.email,
    capabilities={
        "card_payments": {"requested": True},
        "transfers": {"requested": True},
    },
    business_type="non_profit",  # o "company" per ASD
    metadata={
        "asd_id": str(asd.id),
        "platform": "media_center"
    }
)

# Genera link onboarding
account_link = stripe.AccountLink.create(
    account=account.id,
    refresh_url="https://app.example.com/asd/onboarding/refresh",
    return_url="https://app.example.com/asd/onboarding/complete",
    type="account_onboarding",
)

# Salva account.id in asd_partners.stripe_account_id
```

### 7.2 Split Payment (Checkout)

```python
# Crea Checkout Session con split
session = stripe.checkout.Session.create(
    mode="payment",
    line_items=[
        {
            "price_data": {
                "currency": "eur",
                "unit_amount": total_cents,  # 30000 = €300
                "product_data": {
                    "name": f"{event.title} - {option.name}",
                },
            },
            "quantity": 1,
        }
    ],
    payment_intent_data={
        "transfer_group": f"event_{event.id}_{subscription.id}",
    },
    success_url="https://app.example.com/events/success?session_id={CHECKOUT_SESSION_ID}",
    cancel_url="https://app.example.com/events/cancel",
    metadata={
        "event_id": str(event.id),
        "subscription_id": str(subscription.id),
        "asd_amount_cents": str(price_asd_cents),
        "course_amount_cents": str(price_course_cents),
    }
)

# Dopo pagamento (webhook), crea transfer ad ASD
transfer = stripe.Transfer.create(
    amount=price_asd_cents,
    currency="eur",
    destination=asd.stripe_account_id,
    transfer_group=f"event_{event.id}_{subscription.id}",
    metadata={
        "event_id": str(event.id),
        "subscription_id": str(subscription.id),
    }
)
```

### 7.3 Refund Split

```python
# Refund parte ASD (da account ASD)
refund_asd = stripe.Refund.create(
    charge=original_charge_id,
    amount=price_asd_cents,
    reverse_transfer=True,  # Reversa il transfer ad ASD
    metadata={
        "subscription_id": str(subscription.id),
        "type": "asd_cancellation"
    }
)

# Refund parte LIBRA (da account LIBRA)
refund_libra = stripe.Refund.create(
    charge=original_charge_id,
    amount=price_course_cents,
    metadata={
        "subscription_id": str(subscription.id),
        "type": "course_refund"
    }
)
```

---

## 8. SISTEMA ALERT E NOTIFICHE

### 8.1 Tipi di Alert

| Alert | Destinatario | Canale | Timing |
|-------|--------------|--------|--------|
| **Promemoria evento** | Utente iscritto | Email + Push | 7gg, 3gg, 1gg prima |
| **Soglia non raggiunta** | Admin LIBRA | Email + Dashboard | X giorni prima (config) |
| **Posto disponibile** | Waiting list | Email + Push | Immediato |
| **Richiesta rimborso** | Admin LIBRA | Email + Dashboard | Immediato |
| **Rimborso approvato** | Utente + ASD | Email | Immediato |
| **Evento annullato** | Tutti iscritti + WL | Email + Push | Immediato |
| **Nuova iscrizione** | ASD | Email (opzionale) | Immediato |
| **Prevendita termina** | Admin | Dashboard | 1gg prima |

### 8.2 Template Alert Utente

**7 giorni prima:**
```
📅 Promemoria: tra 7 giorni hai lo stage "[NOME EVENTO]"

 Ciao [NOME],

 Ti ricordiamo che tra 7 giorni inizia:
 
 🥋 [NOME EVENTO]
 📍 [LOCATION]
 📆 [DATA INIZIO] - [DATA FINE]
 🎫 La tua opzione: [NOME OPZIONE]
 
 Dettagli utili:
 - [INFO LOGISTICA SE PRESENTE]
 
 A presto!
```

**3 giorni prima:**
```
⏰ Mancano solo 3 giorni a "[NOME EVENTO]"!

 [STESSE INFO + EVENTUALI REMINDER SPECIFICI]
```

**1 giorno prima:**
```
🔔 Domani inizia "[NOME EVENTO]"!

 [INFO ESSENZIALI + ORARIO RITROVO]
```

### 8.3 Configurazione Alert - TUTTO PARAMETRIZZABILE

**Livelli di configurazione:**
1. **Piattaforma** (default globali Media Center)
2. **Evento** (override per singolo evento)

```yaml
# CONFIG GLOBALE PIATTAFORMA (Admin Media Center decide)
alert_defaults:
  
  # Promemoria partecipanti
  reminders:
    enabled: true  # true/false
    days_before: [7, 3, 1]  # Array libero: [20, 10, 5, 1] o [30] o []
    channels:
      email: true
      push: true
  
  # Alert ASD nuove iscrizioni  
  asd_new_subscription:
    enabled: true
    channels:
      email: true
      push: false
  
  # Alert soglia minima
  threshold_alert:
    enabled: true
    days_before: 20  # Qualsiasi numero
    channels:
      email: true
      dashboard: true
      push: false
  
  # Posto disponibile (waiting list)
  spot_available:
    enabled: true
    channels:
      email: true
      push: true
  
  # Evento annullato
  event_cancelled:
    enabled: true  # Sempre true consigliato
    channels:
      email: true
      push: true
  
  # Richiesta rimborso ASD
  refund_request:
    enabled: true
    channels:
      email: true
      dashboard: true
  
  # Rimborso approvato
  refund_approved:
    enabled: true
    channels:
      email: true
      push: false
  
  # Prevendita in scadenza
  presale_ending:
    enabled: true
    days_before: 1
    channels:
      dashboard: true
      email: false

# OVERRIDE PER SINGOLO EVENTO
# Se non specificato, usa default piattaforma
event_alert_override:
  reminders:
    enabled: false  # Questo evento: niente promemoria
  # oppure
  reminders:
    days_before: [20, 10, 3]  # Promemoria diversi
```

### 8.4 Tabella Config Piattaforma

```sql
CREATE TABLE platform_alert_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Tipo alert
    alert_type VARCHAR(50) NOT NULL UNIQUE,
    -- reminders, asd_new_subscription, threshold_alert,
    -- spot_available, event_cancelled, refund_request,
    -- refund_approved, presale_ending
    
    -- Abilitato
    enabled BOOLEAN DEFAULT TRUE,
    
    -- Timing (per alert con giorni)
    days_before INTEGER[],  -- Es: {7, 3, 1} o {20}
    
    -- Canali
    channel_email BOOLEAN DEFAULT TRUE,
    channel_push BOOLEAN DEFAULT TRUE,
    channel_dashboard BOOLEAN DEFAULT FALSE,
    
    -- Metadata
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

-- Seed defaults
INSERT INTO platform_alert_config (alert_type, enabled, days_before, channel_email, channel_push, channel_dashboard) VALUES
('reminders', true, '{7,3,1}', true, true, false),
('asd_new_subscription', true, NULL, true, false, false),
('threshold_alert', true, '{20}', true, false, true),
('spot_available', true, NULL, true, true, false),
('event_cancelled', true, NULL, true, true, false),
('refund_request', true, NULL, true, false, true),
('refund_approved', true, NULL, true, false, false),
('presale_ending', true, '{1}', false, false, true);
```

### 8.5 Override per Evento

```sql
-- Aggiunta colonna in events
ALTER TABLE events ADD COLUMN alert_overrides JSONB;

-- Esempio override
-- Evento senza promemoria:
-- alert_overrides: {"reminders": {"enabled": false}}
--
-- Evento con promemoria ogni 20 giorni:
-- alert_overrides: {"reminders": {"days_before": [20, 10, 5]}}
```

### 8.6 API Config Alert

```
# Admin Media Center gestisce default piattaforma
GET    /api/v1/admin/alert-config
PUT    /api/v1/admin/alert-config/{alert_type}
       Body: { enabled, days_before, channel_email, channel_push, channel_dashboard }

# Override per evento (in creazione/modifica evento)
PUT    /api/v1/events/{event_id}
       Body: { ..., alert_overrides: { reminders: { enabled: false } } }
```

### 8.7 Tabella Database Notifiche

```sql
CREATE TABLE event_notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Riferimenti
    event_id UUID NOT NULL REFERENCES events(id),
    user_id UUID REFERENCES users(id),  -- NULL per alert admin
    subscription_id UUID REFERENCES event_subscriptions(id),
    
    -- Tipo
    notification_type VARCHAR(50) NOT NULL,
    -- reminder_7d, reminder_3d, reminder_1d, 
    -- spot_available, refund_request, refund_approved,
    -- event_cancelled, new_subscription, threshold_alert
    
    -- Canali
    channel VARCHAR(20) NOT NULL,  -- email, push, dashboard
    
    -- Stato
    status VARCHAR(20) DEFAULT 'pending',  -- pending, sent, failed
    sent_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    
    -- Scheduling
    scheduled_for TIMESTAMP WITH TIME ZONE NOT NULL,
    
    -- Metadata
    payload JSONB,  -- Dati per template
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_notifications_scheduled ON event_notifications(scheduled_for) 
    WHERE status = 'pending';
CREATE INDEX idx_notifications_event ON event_notifications(event_id);
```

### 8.8 Cron Jobs

```python
# Ogni ora: invia notifiche scheduled
@scheduler.scheduled_job('interval', hours=1)
async def send_scheduled_notifications():
    """
    Trova notifiche pending con scheduled_for <= now
    e le invia via email/push.
    """
    pending = await db.execute(
        select(EventNotification)
        .where(EventNotification.status == 'pending')
        .where(EventNotification.scheduled_for <= datetime.utcnow())
        .limit(100)
    )
    
    for notification in pending.scalars():
        try:
            if notification.channel == 'email':
                await send_email(notification)
            elif notification.channel == 'push':
                await send_push(notification)
            
            notification.status = 'sent'
            notification.sent_at = datetime.utcnow()
        except Exception as e:
            notification.status = 'failed'
            notification.error_message = str(e)
    
    await db.commit()


# Ogni giorno alle 9:00: crea reminder per eventi prossimi
@scheduler.scheduled_job('cron', hour=9)
async def schedule_event_reminders():
    """
    Per ogni evento nei prossimi 7 giorni,
    crea notifiche reminder se non esistono già.
    """
    upcoming_events = await get_events_in_range(
        from_date=date.today(),
        to_date=date.today() + timedelta(days=7)
    )
    
    for event in upcoming_events:
        days_until = (event.start_date - date.today()).days
        
        if days_until in event.alert_config.reminders.days_before:
            await create_reminders_for_event(event, days_until)


# Ogni giorno: check soglie minime
@scheduler.scheduled_job('cron', hour=10)
async def check_threshold_alerts():
    """
    Verifica eventi con soglia minima non raggiunta.
    """
    events = await get_events_with_threshold()
    
    for event in events:
        days_until = (event.start_date - date.today()).days
        
        if days_until <= event.threshold_alert_days and not event.threshold_alert_sent:
            if not threshold_reached(event):
                await send_threshold_alert(event)
                event.threshold_alert_sent = True
    
    await db.commit()
```

---

## 9. EFFORT STIMATO

| Componente | Giorni | Note |
|------------|--------|------|
| **Database & Models** | 2-3 | Tabelle, relazioni, migrazioni |
| **ASD Partners CRUD** | 2 | Gestione partner + Stripe onboarding |
| **Eventi CRUD** | 3-4 | Creazione, modifica, pubblicazione |
| **Opzioni Evento** | 2 | Gestione opzioni multiple |
| **Checkout & Split** | 4-5 | Stripe Connect integration |
| **Iscrizioni & Acquisti** | 3 | Flusso completo acquisto |
| **Annullamenti Singoli** | 3 | Richieste ASD, approvazione, refund |
| **Annullamento Evento** | 2 | Refund massivo, notifiche |
| **Waiting List** | 2 | Iscrizione, notifiche, gestione |
| **Dashboard ASD** | 3 | Vista eventi, partecipanti, incassi |
| **Prevendita & Criteri** | 2 | Logica criteri, verifica |
| **Alert Soglia** | 1 | Cron job, notifiche |
| **Test Suite** | 4-5 | Test ZERO MOCK completi |
| **Sistema Alert** | 3-4 | Notifiche, cron jobs, template |

**TOTALE: 36-43 giorni**

---

## 📎 ALLEGATI

### A. Checklist Pre-Sviluppo

- [ ] Stripe Connect account LIBRA configurato
- [ ] Webhook endpoints configurati
- [ ] Template email definiti
- [ ] UI/UX mockup approvati

### B. Domande - RISOLTE

1. **Self-cancel utente:** ❌ NO, non permesso. Utente deve contattare ASD.
2. **Fee Stripe:** Ognuno paga le sue. ASD paga fee su sua quota, LIBRA su sua quota.
3. **Notifiche:** Email + Push, entrambe configurabili per tipo notifica.

---

**Documento approvato il:** 11 Gennaio 2026  
**Prossimo step:** Sviluppo dopo completamento test suite (95% pass rate)

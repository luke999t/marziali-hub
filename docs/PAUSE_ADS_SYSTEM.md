# Sistema Pause Ads - Documentazione Tecnica

## Panoramica

Il sistema Pause Ads implementa un modello di monetizzazione Netflix-style che mostra overlay pubblicitari quando l'utente mette in pausa un video. Il sistema include:

- **Pause Ad Overlay**: UI 50/50 con video suggerito (sinistra) e sponsor ad (destra)
- **Blockchain Tracking**: Aggregazione settimanale e pubblicazione su Polygon
- **Revenue Model**: CPM (Cost Per Mille) con bonus per click

---

## Architettura

```
┌─────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (Next.js)                          │
├─────────────────────────────────────────────────────────────────────┤
│  PauseAdOverlay.tsx  │  adsApi.ts  │  usePauseAds.ts (hook)        │
└──────────────┬───────────────────────────────────────────────────────┘
               │ REST API
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         BACKEND (FastAPI)                           │
├─────────────────────────────────────────────────────────────────────┤
│  api/v1/ads.py       │  Endpoints REST per pause ads               │
├──────────────────────┼──────────────────────────────────────────────┤
│  modules/ads/        │  Business logic                              │
│  ├─ pause_ad_service.py    │  Gestione pause ads                   │
│  ├─ ads_service.py         │  Gestione batch sessions              │
│  └─ __init__.py            │  Module exports                       │
├──────────────────────┼──────────────────────────────────────────────┤
│  modules/blockchain/ │  Consensus & pubblicazione                   │
│  ├─ blockchain_service.py  │  Batch aggregation, Polygon publish   │
│  └─ __init__.py            │  Module exports                       │
├──────────────────────┼──────────────────────────────────────────────┤
│  models/ads.py       │  SQLAlchemy models                          │
│  ├─ PauseAd               │  Configurazione ads in pausa           │
│  ├─ PauseAdImpression     │  Tracking impressioni                  │
│  ├─ AdsSession            │  Sessioni batch unlock                 │
│  ├─ BlockchainBatch       │  Batch settimanali                     │
│  ├─ StoreNode             │  Nodi validatori                       │
│  └─ NodeValidation        │  Voti consensus                        │
└─────────────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         DATABASE (PostgreSQL)                       │
└─────────────────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         BLOCKCHAIN (Polygon)                        │
│  Smart Contract per certificazione revenue                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Tier Utente e Visibilità Ads

| Tier | Vede Pause Ads | Vede Batch Ads | Note |
|------|----------------|----------------|------|
| FREE | ✅ | ✅ | Monetizzazione completa |
| HYBRID_LIGHT | ✅ | ✅ | Monetizzazione parziale |
| HYBRID_STANDARD | ✅ | ✅ | Monetizzazione parziale |
| PREMIUM | ❌ | ❌ | Nessuna pubblicità |
| BUSINESS | ❌ | ❌ | Nessuna pubblicità |

---

## API Endpoints

### Pause Ads

#### GET `/api/v1/ads/pause-ad`
Ottiene pause ad e video suggerito per l'overlay.

**Query Parameters:**
- `video_id` (UUID, required): ID del video in pausa

**Response:**
```json
{
  "suggested_video": {
    "id": "uuid",
    "title": "Kata Heian Shodan - Lezione 3",
    "thumbnail_url": "https://...",
    "duration": 300,
    "maestro_name": "Sensei Tanaka",
    "style": "karate",
    "category": "kata"
  },
  "sponsor_ad": {
    "id": "uuid",
    "advertiser": "Decathlon",
    "title": "Kimono -30%",
    "description": "Offerta speciale",
    "image_url": "https://...",
    "click_url": "https://decathlon.it/kimono"
  },
  "impression_id": "uuid",
  "show_overlay": true
}
```

#### POST `/api/v1/ads/pause-ad/impression`
Registra impression (conferma visualizzazione).

**Body:**
```json
{
  "impression_id": "uuid",
  "video_id": "uuid"
}
```

#### POST `/api/v1/ads/pause-ad/click`
Registra click su ad o video suggerito.

**Body:**
```json
{
  "impression_id": "uuid",
  "click_type": "ad" | "suggested"
}
```

### Batch Ads Sessions

#### POST `/api/v1/ads/sessions/start`
Avvia sessione batch per sbloccare video.

**Body:**
```json
{
  "batch_type": "3_video" | "5_video" | "10_video"
}
```

#### POST `/api/v1/ads/sessions/{session_id}/view`
Registra visualizzazione ad in sessione batch.

**Query Parameters:**
- `ad_id` (UUID): ID dell'ad visualizzato
- `duration` (int): Durata in secondi

#### POST `/api/v1/ads/sessions/{session_id}/complete`
Completa sessione e sblocca video.

#### GET `/api/v1/ads/sessions/active`
Ottiene sessione attiva corrente.

---

## Modello Revenue

### Pause Ads CPM
- **CPM Rate**: €5.00 per 1000 impressioni
- **Click Bonus**: €0.02 per click
- **Revenue per impression**: €0.005

### Batch Ads CPM
- **CPM Rate**: €3.00 per 1000 views
- **Fraud Penalty**: Riduzione fino al 50% per comportamenti sospetti

### Configurazione Batch

| Batch Type | Video Sbloccati | Durata Richiesta | Validità |
|------------|-----------------|------------------|----------|
| BATCH_3 | 3 video | 180 secondi (3 min) | 24 ore |
| BATCH_5 | 5 video | 300 secondi (5 min) | 24 ore |
| BATCH_10 | 10 video | 600 secondi (10 min) | 48 ore |

---

## Sistema Anti-Fraud

Il sistema implementa rilevamento frodi multi-livello:

### Fraud Score Calculation
```python
def _calculate_fraud_score(duration, session):
    adjustment = 0.0

    # Duration troppo breve (< 5s) = probabile skip
    if duration < 5:
        adjustment += 0.1

    # Duration impossibile (> 120s) = probabile bot
    if duration > 120:
        adjustment += 0.05

    # Troppi ads in poco tempo = automazione
    if ads_per_minute > 5:
        adjustment += 0.15

    return min(0.3, adjustment)
```

### Threshold
- **Fraud Score > 0.7**: Sessione bloccata, video non sbloccati
- **Fraud Score applicato**: Revenue ridotta proporzionalmente

---

## Blockchain Consensus

### Flow Settimanale

```
1. AGGREGAZIONE (Domenica 00:00 UTC)
   └─ Raccolta dati: impressions, clicks, revenue
   └─ Calcolo hash SHA256 del batch

2. BROADCAST (Domenica 01:00 UTC)
   └─ Invio batch a tutti i nodi attivi
   └─ Status: PENDING → VALIDATING

3. VALIDAZIONE (Domenica 01:00-23:59 UTC)
   └─ Ogni nodo calcola hash e firma
   └─ Raccolta voti (agreement/disagreement)

4. CONSENSUS CHECK (Lunedì 00:00 UTC)
   └─ Se >= 51% agreement → CONSENSUS_REACHED
   └─ Se < 51% → CONSENSUS_FAILED

5. PUBBLICAZIONE (se consensus raggiunto)
   └─ Smart contract call su Polygon
   └─ Registrazione tx_hash e block_number
   └─ Status: PUBLISHED
```

### Costanti Consensus
- **CONSENSUS_THRESHOLD**: 0.51 (51%)
- **MIN_VALIDATORS**: 3
- **BATCH_PERIOD_DAYS**: 7

### Hash Calculation
```python
def calculate_batch_hash(data: Dict) -> str:
    json_str = json.dumps(data, sort_keys=True, separators=(',', ':'))
    hash_bytes = hashlib.sha256(json_str.encode('utf-8')).digest()
    return '0x' + hash_bytes.hex()  # 66 caratteri totali
```

---

## Frontend Component

### PauseAdOverlay Props

```typescript
interface PauseAdOverlayProps {
  visible: boolean;
  suggestedVideo: SuggestedVideo | null;
  sponsorAd: SponsorAd | null;
  impressionId: string;
  onSuggestedClick: (videoId: string) => void;
  onAdClick: (adId: string, url: string) => void;
  onClose: () => void;
  onResume: () => void;
  onImpression: (impressionId: string) => void;
}
```

### Layout
```
┌─────────────────────────────────────────────────────────────────┐
│                         [X] Close                               │
├───────────────────────────────┬─────────────────────────────────┤
│                               │                                 │
│      SUGGESTED VIDEO          │        SPONSOR AD               │
│      (50% width)              │        (50% width)              │
│                               │                                 │
│  ┌─────────────────────┐     │  ┌─────────────────────┐        │
│  │                     │     │  │                     │        │
│  │    Thumbnail        │     │  │    Ad Image         │        │
│  │                     │     │  │                     │        │
│  └─────────────────────┘     │  └─────────────────────┘        │
│                               │                                 │
│  Title: Kata Heian...         │  Title: Kimono -30%            │
│  Maestro: Sensei Tanaka       │  Advertiser: Decathlon         │
│  Duration: 5:00               │  "Offerta speciale..."         │
│                               │                                 │
│  [Consigliato]                │  [Sponsor]                     │
│                               │                                 │
├───────────────────────────────┴─────────────────────────────────┤
│            Press ESC or click outside to resume                 │
└─────────────────────────────────────────────────────────────────┘
```

### Keyboard Navigation
- **ESC**: Resume video
- **Tab**: Navigazione tra elementi
- **Enter**: Attiva elemento selezionato
- **Click backdrop**: Resume video

### Accessibility (ARIA)
- `role="dialog"`
- `aria-modal="true"`
- `aria-label="Pause overlay with suggestions"`
- Focus trap attivo

---

## Database Schema

### PauseAd
```sql
CREATE TABLE pause_ads (
    id UUID PRIMARY KEY,
    advertiser VARCHAR(255) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    image_url VARCHAR(500) NOT NULL,
    click_url VARCHAR(500) NOT NULL,
    cpm_rate DECIMAL(10,2) DEFAULT 5.00,
    target_tiers VARCHAR[] DEFAULT ARRAY['free', 'hybrid_light', 'hybrid_standard'],
    target_styles VARCHAR[],
    is_active BOOLEAN DEFAULT true,
    budget_total DECIMAL(10,2),
    budget_spent DECIMAL(10,2) DEFAULT 0,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### PauseAdImpression
```sql
CREATE TABLE pause_ad_impressions (
    id UUID PRIMARY KEY,
    pause_ad_id UUID REFERENCES pause_ads(id),
    user_id UUID REFERENCES users(id),
    video_id UUID REFERENCES videos(id),
    impression_confirmed BOOLEAN DEFAULT false,
    clicked BOOLEAN DEFAULT false,
    click_type VARCHAR(20),  -- 'ad' or 'suggested'
    suggested_video_id UUID,
    revenue_earned DECIMAL(10,6) DEFAULT 0,
    blockchain_batch_id UUID,
    created_at TIMESTAMP DEFAULT NOW(),
    confirmed_at TIMESTAMP,
    clicked_at TIMESTAMP
);
```

### BlockchainBatch
```sql
CREATE TABLE blockchain_batches (
    id UUID PRIMARY KEY,
    batch_date DATE NOT NULL,
    period_start TIMESTAMP NOT NULL,
    period_end TIMESTAMP NOT NULL,
    total_views INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    total_watch_time INTEGER DEFAULT 0,
    total_revenue DECIMAL(12,2) DEFAULT 0,
    data_hash VARCHAR(66) NOT NULL,  -- 0x + 64 hex chars
    merkle_root VARCHAR(66),
    consensus_status VARCHAR(20) DEFAULT 'pending',
    consensus_threshold DECIMAL(3,2) DEFAULT 0.51,
    validations_received INTEGER DEFAULT 0,
    validations_required INTEGER DEFAULT 3,
    published_to_blockchain BOOLEAN DEFAULT false,
    blockchain_tx_hash VARCHAR(66),
    blockchain_block_number BIGINT,
    published_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

---

## Test Suite

### Coverage Report

| File | Tests | Pass Rate |
|------|-------|-----------|
| `test_ads_service.py` | 46 | 100% |
| `test_pause_ad_service.py` | 32 | 100% |
| `test_blockchain_service.py` | 35 | 100% |
| `test_pause_ad_api.py` | 38 | 100% |
| **TOTALE** | **151** | **100%** |

### Run Tests
```bash
cd backend
python -m pytest tests/unit/test_ads_service.py \
                 tests/unit/test_pause_ad_service.py \
                 tests/unit/test_blockchain_service.py \
                 tests/integration/test_pause_ad_api.py \
                 -v
```

---

## Metriche Business

### KPI Target
| Metrica | Target | Descrizione |
|---------|--------|-------------|
| Impression Fill Rate | >= 95% | % richieste con ad disponibile |
| Click-Through Rate | >= 2% | % impressioni con click |
| Fraud Detection Rate | >= 95% | % frodi rilevate |
| Session Completion Rate | >= 70% | % sessioni completate |
| Consensus Achievement | >= 95% | % batch con consensus |

### Revenue Projection
- **5M views/mese** @ €3 CPM = €15,000/mese (batch ads)
- **1M pause impressions/mese** @ €5 CPM = €5,000/mese
- **20K clicks/mese** @ €0.02 = €400/mese
- **Totale stimato**: ~€20,400/mese

---

## Deployment

### Environment Variables
```env
# Pause Ads
PAUSE_AD_CPM=5.0
BATCH_AD_CPM=3.0
CLICK_BONUS=0.02

# Blockchain
POLYGON_RPC_URL=https://polygon-rpc.com
POLYGON_CONTRACT_ADDRESS=0x...
POLYGON_PRIVATE_KEY=0x...
CONSENSUS_THRESHOLD=0.51
MIN_VALIDATORS=3
```

### Cron Jobs
```bash
# Aggregazione settimanale (Domenica 00:00 UTC)
0 0 * * 0 python -m scripts.create_weekly_batch

# Broadcast a nodi (Domenica 01:00 UTC)
0 1 * * 0 python -m scripts.broadcast_batch

# Consensus check (Lunedì 00:00 UTC)
0 0 * * 1 python -m scripts.check_and_publish
```

---

## Changelog

### v1.0.0 (2025-12-09)
- Implementazione iniziale sistema Pause Ads
- Overlay 50/50 frontend (React/Next.js)
- Backend services (FastAPI/SQLAlchemy)
- Blockchain consensus su Polygon
- Test suite completa (151 tests, 100% pass rate)

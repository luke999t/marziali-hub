# 🥋 MEDIA CENTER ARTI MARZIALI - MEGA PROMPT v3.0

**Versione**: 3.0
**Data**: 10 Novembre 2025
**Target**: Claude Code Web + Produzione
**Stato Progetto**: 80% completato (aggiornato da analisi dettagliata)

---

## 📋 INDICE RAPIDO

1. **VISIONE**: Obiettivi e caratteristiche uniche
2. **ARCHITETTURA**: Stack tecnologico completo + Mobile App
3. **STATO CODICE**: Cosa c'è e funziona (80% - molte sorprese positive!)
4. **GAP ANALYSIS**: Cosa manca realmente (20%)
5. **REGOLE AI-FIRST**: Template documentazione obbligatoria
6. **GUIDELINES**: Best practices sviluppo
7. **STRUTTURA**: Organizzazione cartelle produzione
8. **ROADMAP**: Priorità sviluppo (Backend → Frontend PC → Mobile → AR)
9. **TESTING**: Strategy completa
10. **DEPLOYMENT**: Docker Compose + Mobile deployment

---

## 1. VISIONE E OBIETTIVI

### 🎯 Obiettivo Principale

Piattaforma modulare **AI-First** per arti marziali con 4 componenti principali:

**A. STAFF PLATFORM** (Maestri creano contenuti)
- Upload 30+ video stessa forma
- Multi-video fusion → Avatar "perfetto" 360°
- Estrazione tecniche automatica
- **Generazione immagini tecniche con frecce e transizioni** (killer feature!)
- Publish verso studenti

**B. STUDENT PLATFORM** (Allievi apprendono)
- Upload proprio video
- Confronto automatico vs maestro/avatar
- Feedback AI dettagliato con correzioni contestuali
- Progress tracking gamificato
- Chat con maestro e richieste correzione

**C. MOBILE APP** (Fondamentale - iOS e Android)
- Tutte le funzionalità desktop disponibili su mobile
- Upload video da smartphone
- AR mobile (ARKit per iOS, ARCore per Android)
- Proiezione avatar 3D davanti a te
- Notifiche push per correzioni/messaggi

**D. AR COACHING** (Occhiali + Mobile AR)
- **Mobile AR** (fase 1): Avatar proiettato via smartphone
- **Occhiali AR** (fase 2, opzionale): XReal/RokID
- Linee guida rosse per forma
- Overlay correzioni real-time
- Voice coaching

### 🌟 Caratteristiche Uniche

- **AI-First**: Ogni modulo documentato per AI training futuro
- **Modulare**: Architettura monolite modulare (NON microservizi)
- **Cross-platform**: Web + Mobile (iOS/Android) + AR
- **Scalabile**: 1 maestro → migliaia studenti
- **Multi-stile**: Tai Chi, Karate, Wing Chun, Kung Fu, Shaolin, etc
- **Comunicazione integrata**: Chat, video feedback, traduzioni live
- **Sistema donazioni**: Integrato con blockchain per trasparenza

---

## 2. ARCHITETTURA SISTEMA

### 🏗️ Stack Tecnologico Completo

```yaml
Backend:
  Architecture: Monolite modulare (NON microservices)
  Approach: Single FastAPI app con moduli separati
  Database: PostgreSQL condiviso tra tutti i moduli

  Core:
    - Python 3.11+
    - FastAPI (async web framework)
    - SQLAlchemy 2.0 (ORM async)
    - PostgreSQL 15 / SQLite (dev)
    - Redis (caching, sessions)
    - Celery (background tasks)

  AI/ML:
    - MediaPipe Holistic (pose detection 75 landmarks)
      └─ 33 body + 21 left hand + 21 right hand
    - OpenCV (video processing)
    - NumPy, SciPy (math)
    - fastdtw (Dynamic Time Warping)
    - scikit-learn (ML utilities)
    - OpenAI GPT-4 (Q&A, translations, feedback)
    - ChromaDB (vector database per RAG)

  Video:
    - FFmpeg (encoding, transcoding)
    - HLS (streaming protocol)
    - RTMP (live streaming)

Frontend:
  Desktop:
    - Next.js 14 (App Router)
    - React 18 + TypeScript
    - Tailwind CSS + shadcn/ui
    - Three.js (3D skeleton rendering)
    - Canvas API (skeleton overlay)
    - TanStack Query (data fetching)
    - Zustand (state management)

  Mobile:
    - React Native + Expo (iOS + Android)
    - expo-ar (ARKit/ARCore per AR mobile)
    - expo-camera (video recording/upload)
    - React Navigation (navigazione)
    - NativeWind (Tailwind per RN)
    - expo-notifications (push notifications)
    - Three.js via expo-gl (3D rendering su mobile)

AR:
  Mobile AR (Fase 1):
    - ARKit (iOS) via expo-ar
    - ARCore (Android) via expo-ar
    - Avatar projection 3D su mobile
    - Spatial anchoring

  Glasses AR (Fase 2, opzionale):
    - XREAL SDK / RokID SDK
    - Unity3D per rendering AR su occhiali
    - Controllo da mobile/PC

Payment & Blockchain:
  - Stripe (subscriptions, payments)
  - Numia (payout fiscally compliant)
  - Polygon blockchain (donation batches transparency)
  - IPFS (metadata storage)
```

### 📊 Architettura Monolite Modulare

**IMPORTANTE**: NON microservizi, ma **monolite modulare**

```
media-center-arti-marziali/
│
├── backend/                           # Single FastAPI application
│   ├── main.py                        # Entry point UNICO
│   ├── database.py                    # Shared database connection
│   │
│   ├── core/                          # Core utilities (condivise)
│   │   ├── security.py                # JWT, auth, hashing
│   │   ├── logging.py                 # Logging config
│   │   └── middleware.py              # CORS, rate limiting
│   │
│   ├── models/                        # SQLAlchemy models (UNIFICATI)
│   │   ├── user.py                    # User + Subscription (6 tiers!)
│   │   ├── maestro.py                 # Maestro + ASD
│   │   ├── video.py                   # Video + Skeleton
│   │   ├── donation.py                # ✅ Donazioni + Wallet (95% completo!)
│   │   ├── communication.py           # ✅ Message + CorrectionRequest (80% completo!)
│   │   └── live.py                    # LiveEvent + Streaming
│   │
│   ├── api/v1/                        # API routes (UNIFICATE)
│   │   ├── auth.py
│   │   ├── videos.py
│   │   ├── skeleton.py
│   │   ├── donations.py               # ✅ Già implementato
│   │   ├── communication.py           # ✅ Modelli ci sono, API da completare
│   │   └── ... (87 endpoints totali)
│   │
│   ├── services/                      # Business logic (modulare)
│   │   ├── video_studio/              # Video processing
│   │   │   ├── skeleton_extraction.py # ✅ MediaPipe Holistic 75 landmarks
│   │   │   ├── comparison_engine.py   # ✅ DTW comparison
│   │   │   ├── technique_extractor.py # ✅ Pattern recognition
│   │   │   └── ai_agent.py            # ✅ AI Q&A (retrieval da fixare)
│   │   │
│   │   ├── knowledge/                 # Knowledge extraction
│   │   │   ├── pdf_extractor.py       # 🔄 PDF → text (da estendere)
│   │   │   ├── ocr_engine.py          # OCR
│   │   │   └── image_processor.py     # Image extraction
│   │   │
│   │   ├── streaming/                 # Live streaming
│   │   │   ├── rtmp_handler.py        # RTMP ingestion
│   │   │   └── hls_generator.py       # HLS segmentation
│   │   │
│   │   ├── translation/               # ✅ Translation system (85% completo!)
│   │   │   ├── dataset_processor.py   # ✅ TranslationDataset
│   │   │   ├── glossary_manager.py    # ✅ GlossaryTerm multi-lingua
│   │   │   └── realtime_translator.py # Real-time translation
│   │   │
│   │   ├── payment/                   # ✅ Payment (90% completo)
│   │   │   ├── stripe_service.py      # Stripe
│   │   │   └── stelline_wallet.py     # ✅ Wallet stelline
│   │   │
│   │   └── blockchain/                # ✅ Blockchain (90% completo)
│   │       └── polygon_publisher.py   # ✅ Polygon publishing
│   │
│   └── tests/                         # Test suite
│
├── frontend/                          # Next.js 14 Desktop
│   ├── src/
│   │   ├── app/
│   │   │   ├── skeleton-viewer/       # ✅ Funzionante
│   │   │   ├── skeleton-editor/       # ✅ 3D editor
│   │   │   └── upload/                # ✅ Upload
│   │   └── components/
│   │       └── SkeletonEditor3D.tsx   # ✅ Avatar 3D (352 righe)
│   │
│   └── package.json
│
├── mobile/                            # 📱 React Native + Expo (FONDAMENTALE)
│   ├── App.tsx
│   ├── app.json                       # Expo config
│   ├── package.json
│   │
│   ├── src/
│   │   ├── screens/                   # Screens
│   │   │   ├── HomeScreen.tsx
│   │   │   ├── UploadScreen.tsx
│   │   │   ├── ViewerScreen.tsx
│   │   │   ├── ARScreen.tsx           # AR mobile screen
│   │   │   └── ChatScreen.tsx
│   │   │
│   │   ├── components/                # Components
│   │   │   ├── VideoPlayer.tsx
│   │   │   ├── SkeletonOverlay.tsx
│   │   │   └── ARAvatar.tsx           # 3D avatar AR
│   │   │
│   │   ├── navigation/                # Navigation
│   │   ├── services/                  # API calls
│   │   └── utils/
│   │
│   └── ios/                           # iOS native code
│       └── android/                   # Android native code
│
├── docker-compose.yml                 # Orchestrazione
└── docs/                              # Documentation
```

### 🔗 Servizi e Porte

```yaml
Backend API:         localhost:8000   # Single FastAPI app (monolite modulare)
Frontend Desktop:    localhost:3000   # Next.js
PostgreSQL:          localhost:5432   # Shared database
Redis:               localhost:6379   # Cache + Celery broker
ChromaDB:            localhost:8001   # Vector DB per AI

Mobile App:
  - iOS: TestFlight/App Store
  - Android: Play Store
```

---

## 3. STATO ATTUALE CODICE - AGGIORNATO

### 🎉 SORPRESA: Sei all'80%, non 70%!

**Analisi dettagliata ha rivelato**:
- Molte feature richieste sono **GIÀ IMPLEMENTATE** al 80-95%!
- Sistema comunicazione completo (Message, CorrectionRequest, LiveChat)
- Sistema donazioni ASD quasi completo (95%)
- Sistema traduzioni con fine-tuning (85%)
- Subscription tiers completi (6 tier: FREE→BUSINESS)
- AI Q&A funzionante (solo retrieval da fixare)

### ✅ IMPLEMENTATO E FUNZIONANTE (80%)

#### A. Backend - Video Studio (Core Completo)

**File chiave** (aggiornati novembre 2025):

```python
# ✅ Pose Detection & Skeleton (100%)
skeleton_extraction_holistic.py      # MediaPipe Holistic 75 landmarks
  └─ 33 body + 21 left hand + 21 right hand
pose_detection.py                     # MediaPipe Pose base
skeleton_viewer_simple.py             # Visualizzazione skeleton

# ✅ Comparison & Analysis (90%)
comparison_engine.py (31KB)           # DTW comparison COMPLETO
comparison_tool.py                    # Tools confronto
technique_extractor.py (26KB)         # Estrazione tecniche
motion_analyzer.py                    # Analisi movimento
style_classifier.py                   # 🔄 Classificazione stili (da estendere)

# ✅ AI & Conversational (100%)
ai_conversational_agent.py (36KB!)    # AI Q&A arti marziali
  └─ 77 items: 66 Q&A, 6 forms, 5 sequences
  └─ 11 stili: Tai Chi, Karate, Kung Fu, Wing Chun, etc
  └─ ⚠️ RETRIEVAL BROKEN (high priority fix!)
knowledge_extractor.py                # 🔄 Estrazione knowledge (da estendere)

# ✅ Real-time Features (95%)
realtime_pose_corrector.py            # Correzione pose real-time
websocket_manager.py (8.7KB)          # WebSocket real-time
ar_quick_demo.py                      # Demo AR base

# ✅ Advanced Features (90%)
batch_processor.py                    # Processing batch
advanced_analytics.py                 # Analytics (heat maps, motion trails)
cache_manager.py                      # Caching system

# ✅ API & Infrastructure (85%)
upload_api.py (28KB)                  # Upload video + skeleton API COMPLETO
video_studio_api.py                   # API principale
database.py, db_models.py             # Database layer
auth.py                               # JWT authentication
celery_tasks.py                       # Background tasks Celery
```

**Funzionalità Backend**:
- ✅ Upload video + validazione
- ✅ Estrazione skeleton MediaPipe Holistic (75 landmarks)
- ✅ Comparison DTW tra skeleton
- ✅ Technique extraction automatica
- ✅ AI conversational agent (Q&A) - ⚠️ retrieval broken (fix needed)
- ✅ Real-time pose correction
- ✅ WebSocket per aggiornamenti live
- ✅ Batch processing video multipli
- ✅ Database PostgreSQL/SQLite
- ✅ Authentication JWT
- ✅ Background tasks Celery
- ✅ HLS streaming
- ✅ Advanced analytics (heat maps, motion trails)
- ✅ Caching Redis-ready

#### B. Sistema Comunicazione (80% - Sorpresa!)

**File**: `streaming_platform/backend/models/communication.py` (380 righe, 14KB)

```python
# ✅ Message: Chat 1-to-1 studente-maestro
class Message(Base):
    """
    Chat messaging system COMPLETO
    - Allegati: VIDEO, IMAGE, DOCUMENT
    - Read receipts
    - Moderation flags
    """
    from_user_id, to_user_id
    content, attachment_type, attachment_url
    is_read, read_at
    is_flagged, flagged_reason

# ✅ CorrectionRequest: Richiesta correzione video
class CorrectionRequest(Base):
    """
    Sistema COMPLETO richiesta correzione
    - Studente carica video
    - Maestro vede e risponde
    - Status: PENDING → IN_PROGRESS → COMPLETED
    - Feedback: text, video, audio
    - Annotazioni timestamp
    - Parental approval per minori
    """
    student_id, maestro_id
    video_url, video_duration
    status (PENDING/IN_PROGRESS/COMPLETED/REJECTED)
    feedback_text, feedback_video_url, feedback_audio_url
    feedback_annotations = [{"timestamp": 5.2, "text": "Gomito alto"}]
    parent_approval_required, parent_approved_at

# ✅ LiveChatMessage: Chat pubblica live
class LiveChatMessage(Base):
    """
    Chat durante eventi live
    - Display name anonymized per minori
    - Moderation (soft delete)
    """
    event_id, user_id
    display_name, content
    is_deleted, deleted_reason

# ✅ TranslationDataset: Dataset pre-live per traduzioni accurate
class TranslationDataset(Base):
    """
    Sistema AVANZATO traduzioni con fine-tuning
    - Upload glossari/documenti pre-evento
    - Processing automatico chunks
    - Fine-tuning OpenAI se >10k words
    - Vector DB ChromaDB per RAG
    """
    event_id, maestro_id
    files = [{"filename": "glossario.pdf", "url": "s3://...", "type": "glossary"}]
    processing_status (PENDING/PROCESSING/COMPLETED/FAILED)
    chunks_count, embedding_complete
    fine_tune_job_id, fine_tune_model_id  # OpenAI custom model
    chromadb_collection_id

# ✅ GlossaryTerm: Glossario multi-lingua
class GlossaryTerm(Base):
    """
    Termini tecnici traduzioni accurate
    - 6 lingue: EN, ZH, ES, FR, DE, JA
    - Context e usage examples
    """
    term, original_language
    translation_en, translation_zh, translation_es, ...
    context, discipline, category
    usage_count
```

**Status**: ✅ **Modelli 100%, API 60%**
- Modelli database ci sono e sono completi
- Serve completare API endpoints (1-2 settimane)
- UI frontend da creare

#### C. Sistema Donazioni ASD (95% - Quasi Completo!)

**File**:
- `streaming_platform/backend/models/donation.py` (392 righe, 15KB)
- `streaming_platform/backend/api/v1/asd.py` (605 righe)
- `streaming_platform/backend/modules/blockchain/blockchain_service.py` (21KB)

```python
# ✅ StellineWallet: 1 stellina = €0.01
class StellineWallet(Base):
    """
    Wallet virtuale per micro-donazioni
    - 1 stellina = €0.01
    - Top-up via Stripe
    - Spesa per donazioni
    """
    user_id
    balance_stelline: Decimal
    total_topup_eur: Decimal
    total_spent_stelline: Decimal

# ✅ Donation: Donazione con split automatico
class Donation(Base):
    """
    Sistema donazioni COMPLETO con split
    - Maestro: 40%
    - ASD: 50%
    - Piattaforma: 10%
    """
    donor_id, maestro_id, asd_id
    amount_stelline, amount_eur
    splits = {
        "maestro_percentage": 40,
        "asd_percentage": 50,
        "platform_percentage": 10
    }
    blockchain_batch_id  # Collegamento batch blockchain

# ✅ WithdrawalRequest: Prelievo fondi
class WithdrawalRequest(Base):
    """
    Prelievo con soglie e metodi multipli
    - Soglia minima: €100
    - Metodi: SEPA, PayPal, Stripe, Numia
    - Fiscalità compliant (Art. 83 CTS)
    """
    user_id, amount_eur
    withdrawal_method (SEPA/PAYPAL/STRIPE/NUMIA)
    bank_details, status
    processed_at

# ✅ DonationBlockchainBatch: Batch blockchain trasparenza
class DonationBlockchainBatch(Base):
    """
    Batch per trasparenza blockchain
    - Polygon network
    - Merkle root per integrità
    - IPFS per metadata
    """
    batch_size, total_amount_eur
    merkle_root
    polygon_tx_hash, polygon_block_number
    ipfs_metadata_url
```

**Status**: ✅ **95% COMPLETO**
- Backend completo
- API completa (12 endpoints in asd.py)
- Blockchain service completo
- Manca solo UI frontend (1-2 settimane)

#### D. Subscription Plans (90%)

**File**: `streaming_platform/backend/models/user.py`

```python
class UserTier(str, enum.Enum):
    """
    🎯 MONETIZATION MODEL completo:

    FREE: Ads ogni video, 720p max
    HYBRID_LIGHT: Ads ogni 3 video, 1080p, €2.99/mese
    HYBRID_STANDARD: Ads ogni 5 video, 1080p, download limitati, €5.99/mese
    PREMIUM: No ads, 4K, download unlimited, €9.99/mese
    PAY_PER_VIEW: Acquisti singoli video
    BUSINESS: Multi-user, analytics, API access, €49.99/mese
    """
    FREE = "free"
    HYBRID_LIGHT = "hybrid_light"
    HYBRID_STANDARD = "hybrid_standard"
    PREMIUM = "premium"
    PAY_PER_VIEW = "pay_per_view"
    BUSINESS = "business"

class User(Base):
    tier = Enum(UserTier)
    subscription_end, auto_renew

    # ADS BATCH UNLOCK (guarda ads, sblocca N video)
    ads_unlocked_videos
    ads_unlock_valid_until
```

**Status**: ✅ **90% COMPLETO**
- Tier system completo
- Manca solo: subscription per maestro/corso specifico (1-2 settimane)

#### E. Frontend - Next.js (60%)

**Pagine implementate**:
```typescript
/skeleton-viewer     # ✅ FUNZIONANTE (backup 24 ott)
                     # - Sincronizzazione video-skeleton automatica
                     # - Navigazione frame-by-frame
                     # - Rendering 3D skeleton Canvas HTML5

/skeleton-editor     # ✅ Editor skeleton 3D
/upload              # ✅ Upload video
/pose-detection      # ✅ Pose detection real-time
```

**Componenti**:
```typescript
SkeletonEditor3D.tsx  # ✅ Avatar 3D con Three.js (352 righe)
  └─ 12 body parts colorati
  └─ Orbit controls, zoom, shadow mapping
  └─ Edit mode per landmarks
```

#### F. Streaming Platform (95%)

**Struttura completa**:
```
streaming_platform/backend/
├── api/v1/              # ✅ 87 endpoints totali
│   ├── admin.py         # 19 endpoints
│   ├── maestro.py       # 15 endpoints
│   ├── asd.py           # 12 endpoints (605 righe)
│   └── ... (altri 8 file)
│
├── models/              # ✅ 31 tabelle database
│   ├── communication.py # ✅ 380 righe (Message, CorrectionRequest, etc)
│   ├── donation.py      # ✅ 392 righe (Wallet, Donation, etc)
│   └── user.py          # ✅ Subscription tiers
│
└── modules/             # ✅ Business logic
    ├── blockchain/      # ✅ 21KB blockchain service
    └── ...
```

---

## 4. GAP ANALYSIS - AGGIORNATO (Solo 20% Manca!)

### 📊 Breakdown Reale

**Dopo analisi dettagliata**:
- ✅ **Completato**: 80% (molte sorprese positive!)
- 🔄 **Parziale**: 10% (feature esistono ma incomplete)
- ❌ **Mancante**: 10% (da sviluppare ex novo)

### ❌ PRIORITÀ ALTA (Da Fare Subito)

#### A. Fix AI Agent Retrieval (CRITICO)

**Status**: ⚠️ **1 settimana**
- Codice esiste (36KB)
- Retrieval broken
- High priority fix

#### B. Complete Chat System API

**Status**: 🔄 **1 settimana**
- Modelli ci sono (100%)
- API endpoints da creare
- UI frontend da sviluppare

#### C. Traduzioni Live UI

**Status**: 🔄 **2 settimane**
- Backend 85% fatto
- Serve UI upload dataset
- Sottotitoli real-time rendering

#### D. Generazione Immagini Tecniche con Frecce (KILLER FEATURE!)

**Richiesto**:
- Creare immagini di tecniche/forme/stili
- **Transizioni** tra tecniche (tecnica 1 → tecnica 2)
- Molte immagini di transizione per vedere movimento
- **Frecce** che mostrano movimento:
  - Braccio scende → freccia scende
  - Gamba indietro → freccia indietro
- Descrizioni movimenti scritte e parlate
- **Animazioni**

**Status**: ❌ **0% IMPLEMENTATO**

**Complessità**: ALTA (4-6 settimane)

**Componenti**:
1. **Image Generation System**:
   - Pose estimation su video maestro
   - Frame extraction per keyframes (inizio/fine tecnica)
   - Arrow overlay generation
   - Text annotations

2. **Transition Generator**:
   - Interpola N frames tra tecnica A e tecnica B
   - Optical flow per smooth transitions
   - Multiple angle views (front, side, top)

3. **Animation System**:
   - Frame sequencing
   - Arrow animation (movimento progressivo)
   - TTS per descrizioni parlate

**Tecnologie**:
- MediaPipe per pose
- OpenCV per image processing
- PIL/Pillow per arrows/text
- FFmpeg per animation export
- Azure TTS per voice

**Esempio Output**:
```
Tecnica 1: "Brush Knee and Push" (Tai Chi)
├── Frame 1: Posizione iniziale (con frecce: "peso su sx")
├── Transition frames (5-10 immagini intermedie)
│   ├── Frame T1: "Ginocchio inizia a salire" (freccia su)
│   ├── Frame T2: "Mano destra inizia rotazione" (freccia circolare)
│   └── ...
└── Frame 2: Tecnica 2 "Parry and Punch"
    └── Voice: "Dalla posizione precedente, ruotiamo il busto..."
```

#### E. Mobile App (FONDAMENTALE - Dopo Frontend PC)

**Status**: ❌ **0% IMPLEMENTATO**

**Effort**: 8-12 settimane

**Stack**:
- React Native + Expo
- expo-ar per AR mobile (ARKit/ARCore)
- expo-camera per video recording
- React Navigation
- Push notifications

**Features Must-Have**:
- Upload video da smartphone
- Skeleton viewer mobile
- Chat e notifiche
- Progress tracking
- **AR mobile**: Avatar projection 3D (ARKit/ARCore)

**Development Order**:
1. Backend Core → Frontend PC → **Mobile App** → AR features

#### F. Multi-Video Fusion Engine

**Status**: ❌ **0% IMPLEMENTATO**

**Effort**: 4-6 settimane

**Componenti**:
- DTW alignment multipli video
- Weighted averaging per qualità
- Outlier removal automatico
- Consensus skeleton generation

### 🔄 PRIORITÀ MEDIA (Estendere Esistente)

#### G. Correzione AI Feedback Automatico

**Status**: 🔄 **60% fatto**
- comparison_engine.py esiste
- Genera differenze numeriche
- Manca: feedback testuale automatico tipo "Gomito 15° troppo alto al secondo 3.2"

**Effort**: 2-3 settimane

#### H. Riconoscimento Stili da Video

**Status**: 🔄 **20% fatto**
- technique_extractor.py esiste
- Manca: style classifier ML

**Effort**: 3-4 settimane (serve ML training)

#### I. Estrazione da PDF/Libri/Immagini

**Status**: 🔄 **40% fatto**
- knowledge_extractor.py esiste
- Da estendere: OCR, image extraction, entity linking

**Effort**: 2-3 settimane

### 📊 PRIORITÀ BASSA (Future/Optional)

#### J. Integrazione YouTube

**Status**: ❌ **0%**
**Effort**: 2 settimane

#### K. Occhiali AR (XReal/RokID)

**Status**: ❌ **5%**
**Effort**: 8-12 settimane (dopo mobile AR!)

**Note**: Mobile AR viene PRIMA (ARKit/ARCore via expo-ar)

---

## 5. REGOLE AI-FIRST SYSTEM

### 📜 Template OBBLIGATORIO per Ogni Modulo

```python
"""
🎓 AI_MODULE: [Nome Modulo Chiaro]
🎓 AI_DESCRIPTION: [Cosa fa in 1 frase semplice]
🎓 AI_BUSINESS: [Perché è importante per il business]
🎓 AI_TEACHING: [Concetti chiave che l'AI deve imparare]

📄 ALTERNATIVE_VALUTATE:
- Alternativa 1: Scartata perché [motivo concreto]
- Alternativa 2: Scartata perché [motivo concreto]

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Motivo 1: [beneficio tecnico specifico]
- Motivo 2: [beneficio performance]
- Motivo 3: [beneficio maintainability]

🔧 DEPENDENCIES:
- Library 1 (version): [perché necessaria]

⚠️ LIMITAZIONI_NOTE:
- Limitazione 1: [descrizione + workaround]

🎯 METRICHE_SUCCESSO:
- Metrica 1: [target numerico]

📊 PERFORMANCE:
- Tempo esecuzione tipico: [X secondi/ms]
- Memory usage tipico: [X MB]

🧪 TEST_COVERAGE:
- Unit tests: [X test implementati]
- Edge cases coperti: [lista]
"""
```

### 🎯 Esempio Concreto

```python
"""
🎓 AI_MODULE: Image Generation with Arrows and Transitions
🎓 AI_DESCRIPTION: Genera sequenze immagini tecniche con frecce movimento e transizioni smooth
🎓 AI_BUSINESS: Killer feature - didattica visuale superiore a video, permette apprendimento frame-by-frame
🎓 AI_TEACHING: Pose estimation → Keyframe extraction → Arrow overlay → Optical flow transitions

📄 ALTERNATIVE_VALUTATE:
- Video slow-motion: Scartato, non permette focus su singoli frame
- GIF animate: Scartato, troppo pesanti e non permettono controllo frame
- Screenshot manuali: Scartato, non scalabile per centinaia tecniche

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Keyframe extraction automatica da MediaPipe landmarks
- Frecce overlay mostrano direzione movimento chiaramente
- Optical flow interpola transizioni realistiche
- Utente può navigare frame-by-frame avanti/indietro
- Exportabile come PDF/PNG sequence per stampa/condivisione

🔧 DEPENDENCIES:
- mediapipe==0.10.7: Pose estimation 75 landmarks
- opencv-python==4.8.1: Image processing + optical flow
- pillow==10.1.0: Arrow drawing + text overlay
- ffmpeg-python==0.2.0: Animation export video
- azure-cognitiveservices-speech==1.31.0: TTS descrizioni

⚠️ LIMITAZIONI_NOTE:
- Max 100 transizioni per sequenza (limite RAM 8GB)
  Workaround: Batch processing per sequenze lunghe
- Arrow overlay non distingue tra movimenti simultanei
  Workaround: Multiple views (front, side, top) con frecce separate

🎯 METRICHE_SUCCESSO:
- Generazione 10 frame transizione: <30 secondi
- Qualità arrow overlay: >90% accuracy direzione
- User satisfaction: >4.5/5 per chiarezza didattica

📊 PERFORMANCE:
- Tempo generazione sequenza 20 frame: 1-2 minuti
- Memory usage: 2-4 GB RAM per sequenza
- Storage: ~500KB per frame PNG

🧪 TEST_COVERAGE:
- Unit tests: 12 test (test_image_generation.py)
  - test_keyframe_extraction()
  - test_arrow_overlay()
  - test_optical_flow_transition()
  - test_text_annotation()
- Edge cases:
  - Movimento veloce (blur detection)
  - Occlusioni parziali (fallback arrows)
  - Multi-person in frame (isolation target)
"""
```

### 🔥 IMPORTANZA CRITICA

**Perché OGNI modulo DEVE avere questa documentazione**:

1. **AI Training Future**: Tag permettono estrazione automatica di:
   - Decision making (Alternative vs Soluzione)
   - Trade-offs (Limitazioni vs Benefici)
   - Best practices

2. **RAG Simulato**: Tag strutturati = retrieval preciso
   ```python
   # Query: "Come generare immagini tecniche con frecce?"
   # RAG trova: AI_DESCRIPTION "Genera sequenze immagini tecniche con frecce movimento"
   ```

3. **Onboarding Automatico**: Nuovo dev/AI capisce subito cosa fa

4. **Debugging Intelligente**: AI può leggere `LIMITAZIONI_NOTE` per capire se è limite noto

---

## 6. GUIDELINES SVILUPPO

### 🎯 Workflow Standard

```yaml
Per ogni nuovo feature:
  1. ✅ Leggi documentazione esistente
  2. ✅ Controlla codice simile riusabile
  3. ✅ Scrivi docstring AI-First PRIMA del codice
  4. ✅ Implementa con commenti esplicativi
  5. ✅ Scrivi test (3 minimo: happy path, edge case, performance)
  6. ✅ Esegui test localmente
  7. ✅ Commit con messaggio descrittivo (feat/fix/docs)
  8. ✅ Aggiorna CHANGELOG.md
```

### 📝 Commit Message Format

```bash
# ✅ GOOD
feat: Add image generation with arrows and transitions
fix: Resolve AI agent retrieval broken ChromaDB query
refactor: Extract DTW logic into separate service
docs: Update API documentation for communication endpoints
test: Add edge case tests for multi-video fusion

# ❌ BAD
fix bug
update code
wip
```

### 🚫 Cosa NON Fare

```python
# ❌ NON mentire su implementazione
"""This module is fully implemented"""  # Ma manca metà codice

# ❌ NON lasciare placeholder
def important_function():
    pass  # TODO: implement later

# ❌ NON hardcodare valori
VIDEO_PATH = "C:\\Users\\me\\Desktop\\video.mp4"  # ❌

# ✅ USA configurazione
VIDEO_PATH = os.getenv("VIDEO_PATH", "storage/videos/")  # ✅
```

### 🔐 Sicurezza

```python
# ❌ Secrets in codice
API_KEY = "sk_live_123456789"

# ✅ Environment variables
API_KEY = os.getenv("API_KEY")
if not API_KEY:
    raise ValueError("API_KEY not set")

# ❌ SQL injection vulnerable
query = f"SELECT * FROM users WHERE id = {user_id}"

# ✅ Parametrized query (SQLAlchemy)
query = select(User).where(User.id == user_id)
```

---

## 7. STRUTTURA PRODUZIONE UNIFICATA

### 🗂️ Organizzazione Proposta

```
C:\Users\utente\Desktop\GESTIONALI\
└── media-center-arti-marziali/           # ← Nuovo progetto pulito
    │
    ├── docker-compose.yml                # Orchestrazione
    ├── .env.example                      # Template environment
    ├── .gitignore
    ├── README.md
    │
    ├── backend/                          # Backend monolite modulare
    │   ├── main.py                       # Entry point UNICO
    │   ├── requirements.txt              # Dependencies unificate
    │   ├── database.py                   # Shared DB connection
    │   │
    │   ├── core/                         # Core utilities
    │   │   ├── security.py
    │   │   ├── logging.py
    │   │   └── middleware.py
    │   │
    │   ├── models/                       # SQLAlchemy models UNIFICATI
    │   │   ├── user.py                   # User + Subscription
    │   │   ├── video.py                  # Video + Skeleton
    │   │   ├── donation.py               # ✅ Donazioni
    │   │   ├── communication.py          # ✅ Message + CorrectionRequest
    │   │   └── ...
    │   │
    │   ├── api/v1/                       # API routes unificate
    │   │   ├── auth.py
    │   │   ├── videos.py
    │   │   ├── skeleton.py
    │   │   ├── donations.py
    │   │   ├── communication.py
    │   │   └── ...
    │   │
    │   ├── services/                     # Business logic modulare
    │   │   ├── video_studio/             # Video processing
    │   │   ├── knowledge/                # Knowledge extraction
    │   │   ├── streaming/                # Live streaming
    │   │   ├── translation/              # ✅ Translation system
    │   │   ├── payment/                  # ✅ Payment
    │   │   └── blockchain/               # ✅ Blockchain
    │   │
    │   └── tests/                        # Test suite
    │       ├── unit/
    │       └── integration/
    │
    ├── frontend/                         # Frontend Next.js
    │   ├── src/
    │   │   ├── app/
    │   │   │   ├── skeleton-viewer/
    │   │   │   ├── skeleton-editor/
    │   │   │   └── upload/
    │   │   └── components/
    │   │       └── SkeletonEditor3D.tsx
    │   │
    │   └── package.json
    │
    ├── mobile/                           # 📱 React Native + Expo
    │   ├── App.tsx
    │   ├── app.json
    │   ├── package.json
    │   │
    │   ├── src/
    │   │   ├── screens/
    │   │   │   ├── HomeScreen.tsx
    │   │   │   ├── UploadScreen.tsx
    │   │   │   ├── ViewerScreen.tsx
    │   │   │   ├── ARScreen.tsx          # AR mobile
    │   │   │   └── ChatScreen.tsx
    │   │   │
    │   │   ├── components/
    │   │   │   ├── VideoPlayer.tsx
    │   │   │   ├── SkeletonOverlay.tsx
    │   │   │   └── ARAvatar.tsx
    │   │   │
    │   │   └── navigation/
    │   │
    │   ├── ios/                          # iOS native
    │   └── android/                      # Android native
    │
    ├── scripts/                          # Utility scripts
    │   ├── init_db.sh
    │   ├── migrate.sh
    │   └── seed_data.py
    │
    └── docs/                             # Documentation
        ├── MEGA_PROMPT_CLAUDE_CODE_WEB_v3.md (questo file)
        ├── ANALISI_GAP_FUNZIONALITA_DETTAGLIATA.md
        ├── ARCHITETTURA_PRODUZIONE_UNIFICATA.md
        └── LISTA_FILE_DA_COPIARE_VERIFICATA.md
```

---

## 8. ROADMAP PRIORITÀ - AGGIORNATA

### 🎯 FASE 1: Consolidamento Base (2 mesi)

**Obiettivo**: Sistema base stabile e testato al 100%, portare 80% → 85%

```yaml
Settimana 1-2:
  - ✅ Fix AI agent retrieval (CRIT - 1 settimana)
  - ✅ Complete Chat API endpoints (1 settimana)

Settimana 3-4:
  - ✅ Traduzioni live UI upload dataset (1-2 settimane)
  - ✅ Subscription per maestro/corso (1 settimana)

Settimana 5-6:
  - ✅ Sharing limiti parametrabili (1-2 settimane)
  - ✅ Donazioni ASD UI frontend (1 settimana)

Settimana 7-8:
  - ✅ Testing & bug fixes
  - ✅ Deploy staging
  - ✅ CI/CD pipeline

Deliverables:
  - Sistema base 85% funzionante
  - Tutte feature comunicazione complete
  - Staging operativo
```

### 🚀 FASE 2: Core AI Features + Mobile (4-5 mesi)

**Obiettivo**: Potenziare AI, generazione immagini, mobile app (85% → 95%)

```yaml
Settimana 9-12 (Mese 3):
  - ✅ Correzione AI feedback automatico (2-3 settimane)
  - ✅ Estrazione da PDF/libri (2-3 settimane)

Settimana 13-18 (Mese 4-5):
  - ✅ **GENERAZIONE IMMAGINI TECNICHE** (4-6 settimane, 2 dev paralleli)
    - Dev 1: Pose extraction + keyframes
    - Dev 2: Arrows overlay + annotations
  - ✅ Transizioni con frecce
  - ✅ TTS descrizioni movimenti

Settimana 19-26 (Mese 5-6):
  - ✅ **MOBILE APP** (8 settimane, 2 dev)
    - Settimana 1-2: Setup Expo + Navigation + Auth
    - Settimana 3-4: Upload video + Skeleton viewer
    - Settimana 5-6: Chat + Notifications
    - Settimana 7-8: AR mobile (expo-ar + avatar 3D)

Settimana 27-28:
  - ✅ Riconoscimento stili (ML training - 3-4 settimane)

Deliverables:
  - Generazione immagini tecniche funzionante
  - Mobile app iOS + Android
  - AR mobile con avatar projection
  - Progetto 95% completo
```

### 🎓 FASE 3: Multi-Video Fusion + Polish (2 mesi)

**Obiettivo**: Staff platform completo, integrazioni (95% → 98%)

```yaml
Settimana 29-34 (Mese 7-8):
  - ✅ Multi-video fusion engine (4-6 settimane)
    - DTW alignment multipli video
    - Weighted averaging
    - Consensus skeleton generation
  - ✅ Integrazione YouTube (2 settimane)

Settimana 35-36:
  - ✅ UI/UX polish
  - ✅ Performance optimization
  - ✅ Test coverage 80%
  - ✅ Deploy production

Deliverables:
  - Staff platform completo (fusion 30+ video)
  - Sistema production-ready
  - Progetto 98% completo
```

### 🥽 FASE 4: Hardware AR (Opzionale, 3-4 mesi)

**Obiettivo**: Occhiali AR XReal/RokID (98% → 100%)

```yaml
Settimana 37-48 (Mese 9-12):
  - ✅ XReal SDK integration (4 settimane)
  - ✅ Avatar projection AR su occhiali (4 settimane)
  - ✅ Control apps mobile/desktop (2 settimane)
  - ✅ Testing hardware + beta users (2 settimane)

Deliverables:
  - Occhiali AR funzionanti
  - Progetto 100% completo
```

### 📊 Timeline Riassuntiva

```
Development Order: Backend Core → Frontend PC → Mobile App → AR Mobile → AR Glasses

FASE 1: Consolidamento Base (Mese 1-2)
[████████░░░░░░░░░░] 80% → 85%

FASE 2: AI Features + Mobile (Mese 3-6)
[████████████░░░░░░] 85% → 95%
├─ Generazione immagini tecniche (killer feature!)
└─ Mobile app iOS + Android con AR

FASE 3: Fusion + Polish (Mese 7-8)
[████████████████░░] 95% → 98%
└─ Multi-video fusion + production deploy

FASE 4: Hardware AR (Mese 9-12, Opzionale)
[██████████████████] 98% → 100%
└─ Occhiali XReal/RokID

TOTALE: 8-12 mesi (con team 3 dev part-time)
```

---

## 9. TESTING STRATEGY

### 🧪 Pyramid Testing

```
      /\       E2E Tests (5%)
     /  \      - User workflows completi
    /____\     - Playwright automation
   /      \
  / INTEGRATION\   Integration Tests (15%)
 /______________\  - API + Database
/                \
/      UNIT      \ Unit Tests (80%)
/________________\- Funzioni singole
```

### 📝 Test Requirements (Minimo)

**Coverage minimo**: 80% per ogni modulo

```python
# tests/unit/test_image_generation.py

def test_keyframe_extraction():
    """Test extraction keyframes standard"""
    video_path = "test_data/tai_chi_form.mp4"
    keyframes = extract_keyframes(video_path, num_frames=10)

    assert len(keyframes) == 10
    assert all(isinstance(kf, np.ndarray) for kf in keyframes)
    assert keyframes[0].shape == (480, 640, 3)

def test_arrow_overlay():
    """Test arrow overlay generation"""
    frame = load_test_frame()
    landmarks_start = get_test_landmarks(frame=0)
    landmarks_end = get_test_landmarks(frame=10)

    result = generate_arrow_overlay(
        frame, landmarks_start, landmarks_end
    )

    # Verifica arrows presenti
    assert has_arrows(result) == True
    # Verifica direzioni corrette
    assert arrow_direction(result, landmark_id=15) == "down"  # Right elbow

def test_no_person_in_frame():
    """Test edge case: frame vuoto"""
    empty = np.zeros((480, 640, 3), dtype=np.uint8)
    result = extract_keyframes(empty)
    assert result is None

@pytest.mark.slow
def test_performance():
    """Test performance: <30s per 10 frame transizione"""
    import time
    start = time.time()
    generate_transition_sequence(
        video_path="test_data/technique.mp4",
        num_transitions=10
    )
    elapsed = time.time() - start
    assert elapsed < 30.0
```

### 🤖 CI/CD GitHub Actions

```yaml
# .github/workflows/test.yml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r backend/requirements.txt

      - name: Run tests
        run: pytest backend/tests/ --cov=backend --cov-report=xml

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

---

## 10. DEPLOYMENT

### 🐳 Docker Compose Production

```yaml
# docker-compose.yml (già mostrato in ARCHITETTURA)

version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    # ... (vedi ARCHITETTURA sezione completa)

  backend:
    build: ./backend
    # ... monolite modulare

  frontend:
    build: ./frontend
    # ... Next.js

  # Mobile: Deploy su App Store + Play Store
```

### 📱 Mobile Deployment

```bash
# iOS (App Store)
cd mobile
eas build --platform ios --profile production
eas submit --platform ios

# Android (Play Store)
eas build --platform android --profile production
eas submit --platform android

# TestFlight (beta iOS)
eas build --platform ios --profile preview
```

### 🚀 Script Deploy Production

```bash
#!/bin/bash
# scripts/deploy.sh

set -e

echo "🚀 Deploying..."

# Backup database
docker-compose exec postgres pg_dump -U martial_user martial_arts_db > "backups/db_$(date +%Y%m%d_%H%M%S).sql"

# Build new images
docker-compose build --no-cache

# Run migrations
docker-compose run --rm backend alembic upgrade head

# Restart services
docker-compose down
docker-compose up -d

# Health checks
sleep 10
curl -f http://localhost:8000/health || exit 1
curl -f http://localhost:3000 || exit 1

echo "✅ Deployment successful!"
```

---

## 🎯 PROSSIMI PASSI IMMEDIATI

### ✅ Setup Iniziale (Questa Settimana)

1. **Crea struttura in GESTIONALI**:
   ```bash
   cd C:\Users\utente\Desktop\GESTIONALI
   mkdir media-center-arti-marziali
   ```

2. **Copia codice attivo** (usando LISTA_FILE_DA_COPIARE_VERIFICATA.md):
   - Backend: 119 file Python verificati
   - Frontend: Next.js completo
   - Docs: Tutti i documenti analisi

3. **Setup Git**:
   ```bash
   cd media-center-arti-marziali
   git init
   git add .
   git commit -m "Initial commit: clean project structure v3.0 - 80% complete"
   ```

4. **Primi task sviluppo** (FASE 1):
   - Fix AI Agent retrieval (CRIT - 1 settimana)
   - Complete Chat API (1 settimana)
   - Traduzioni live UI (1-2 settimane)

---

## 📚 RIFERIMENTI

### Documentazione Tecnica

- **MediaPipe Holistic**: https://google.github.io/mediapipe/solutions/holistic
- **FastAPI**: https://fastapi.tiangolo.com/
- **Next.js 14**: https://nextjs.org/docs
- **React Native + Expo**: https://docs.expo.dev/
- **expo-ar**: https://docs.expo.dev/versions/latest/sdk/ar/
- **Three.js**: https://threejs.org/docs/

### File Importanti Progetto

```
GESTIONALI/media-center-arti-marziali/
├── README.md
├── CHANGELOG.md
├── backend/
│   ├── main.py                              # Entry point
│   ├── models/
│   │   ├── communication.py                 # ✅ Message, CorrectionRequest
│   │   ├── donation.py                      # ✅ Donazioni ASD
│   │   └── user.py                          # ✅ Subscription tiers
│   │
│   └── services/
│       └── video_studio/
│           ├── skeleton_extraction_holistic.py  # ✅ 75 landmarks
│           ├── comparison_engine.py             # ✅ DTW
│           └── ai_conversational_agent.py       # ✅ AI Q&A (fix retrieval)
│
├── frontend/src/
│   ├── app/skeleton-viewer/page.tsx         # ✅ Funzionante
│   └── components/SkeletonEditor3D.tsx      # ✅ Avatar 3D
│
├── mobile/                                  # ❌ Da creare (FASE 2)
│
└── docs/
    ├── MEGA_PROMPT_CLAUDE_CODE_WEB_v3.md    # ← Questo file
    ├── ANALISI_GAP_FUNZIONALITA_DETTAGLIATA.md
    ├── ARCHITETTURA_PRODUZIONE_UNIFICATA.md
    └── LISTA_FILE_DA_COPIARE_VERIFICATA.md
```

---

## 🎉 CONCLUSIONE

### ✅ Cosa Hai (Sorprese Positive!)

**Sistema 80% completo** con:
- ✅ Backend core video processing (MediaPipe Holistic 75 landmarks)
- ✅ Sistema comunicazione completo (Message, CorrectionRequest, LiveChat)
- ✅ Sistema donazioni ASD quasi completo (95%)
- ✅ Sistema traduzioni con fine-tuning (85%)
- ✅ Subscription tiers completi (6 tier)
- ✅ AI Q&A funzionante (solo retrieval da fixare)
- ✅ Avatar 3D editor (SkeletonEditor3D.tsx)
- ✅ Streaming platform (95% - 87 endpoints)

### 🚀 Cosa Serve (Solo 20%!)

**FASE 1** (2 mesi): Fix & Complete → 85%
- Fix AI agent retrieval
- Complete Chat API
- Traduzioni live UI

**FASE 2** (4-5 mesi): AI + Mobile → 95%
- **Generazione immagini tecniche con frecce** (killer feature!)
- **Mobile app iOS + Android**
- **AR mobile** (ARKit/ARCore)

**FASE 3** (2 mesi): Fusion + Polish → 98%
- Multi-video fusion
- Production deploy

**FASE 4** (3-4 mesi, opzionale): AR Glasses → 100%
- Occhiali XReal/RokID

### 💡 Prossimo Step

1. **Leggi questo MEGA_PROMPT v3.0 completo**
2. **Setup struttura in GESTIONALI** con file attivi
3. **Inizia FASE 1**: Fix AI agent + Chat API
4. **Segui roadmap**: Backend → Frontend PC → **Mobile** → AR

### 🎯 Obiettivo

**Sistema production-ready** cross-platform (Web + Mobile + AR) per insegnamento arti marziali con AI-First approach e generazione automatica immagini didattiche.

---

**Versione**: 3.0
**Data**: 10 Novembre 2025
**Status**: Production Active Development
**Completamento**: 80% → Target 100% in 8-12 mesi
**Architettura**: Monolite modulare (NON microservices)
**Piattaforme**: Web (Next.js) + Mobile (React Native/Expo) + AR (ARKit/ARCore + XReal/RokID)

**🥋 Ready to build the future of martial arts teaching! 🚀**

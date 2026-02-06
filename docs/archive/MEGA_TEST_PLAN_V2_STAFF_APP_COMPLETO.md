# 🧪 MEGA TEST PLAN V2.0 - STAFF APP COMPLETA
## Test End-to-End di TUTTE le Funzionalità
## Data: 31 Gennaio 2026 | Versione: 2.0 COMPLETA

---

# 📋 OBIETTIVO

Testare **TUTTE** le funzionalità dell'app Staff Media Center Arti Marziali:

| Area | Funzionalità | Priorità |
|------|-------------|----------|
| 1. Auth & Users | Login, Register, Profili, Tier | 🔴 |
| 2. Video Management | Upload, Streaming, Library | 🔴 |
| 3. Skeleton Extraction | MediaPipe 75 landmarks | 🔴 |
| 4. Multi-Video Fusion | DTW + Avatar 360° | 🔴 |
| 5. Knowledge Extraction | OCR libri, Synapse System | 🟡 |
| 6. Translation & Subtitles | Multi-lingua, TTS | 🔴 |
| 7. Voice Cloning | XTTS, ENG→ITA→altre lingue | 🟡 |
| 8. Avatar 3D | GLB models, Blender export | 🔴 |
| 9. Eventi Ibridi | Presenziale + Online, Bundle | 🟡 |
| 10. Listini & Pricing | Subscription, PPV, Stelline | 🔴 |
| 11. Admin Dashboard | Analytics, Moderation | 🔴 |
| 12. Curriculum & Learning | Corsi, Livelli, Progress | 🟡 |
| 13. Live Streaming | RTMP, WebSocket, Chat | 🟡 |
| 14. Card Tecniche | Generazione PDF/PNG | 🟢 |
| 15. AI Coach | Feedback real-time | 🟢 |

---

# 🔧 PRE-REQUISITI

## 1. Avvio Servizi

```powershell
# Terminale 1: PostgreSQL (deve essere già attivo)
pg_isready -h localhost -p 5432

# Terminale 2: Backend FastAPI
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000

# Terminale 3: Frontend Next.js
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev

# Verifica:
# - http://localhost:8000/health → {"status": "healthy"}
# - http://localhost:8000/docs → Swagger UI
# - http://localhost:3000 → Frontend
```

## 2. Utenti Test

| Ruolo | Email | Password | Tier |
|-------|-------|----------|------|
| Admin | admin@mediacenter.it | Test123! | BUSINESS |
| Maestro | tanaka.hiroshi@mediacenter.demo | Test123! | PREMIUM |
| Studente Premium | mario.rossi@example.com | Test123! | PREMIUM |
| Studente Free | giulia.bianchi@example.com | Test123! | FREE |
| ASD | presidente@karatemilano.it | Test123! | BUSINESS |

## 3. File Test Necessari

```
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\test_data\
├── video_test_karate.mp4          # Video breve (30s) con tecnica
├── video_test_taichi.mp4          # Video Tai Chi per fusion
├── audio_test_maestro.wav         # 30s audio per voice cloning
├── libro_test_scan.pdf            # PDF scansionato libro marziale
├── immagine_tecnica_01.jpg        # Immagine tecnica per OCR
└── skeleton_test.json             # Skeleton data per test
```

---

# 🚀 ROUND 1: AUTENTICAZIONE & UTENTI

## TEST-001: Login Admin
```
URL: http://localhost:3000/login
AZIONE:
  1. Email: admin@mediacenter.it
  2. Password: Test123!
  3. Click "Login"
VERIFICA:
  ✓ Redirect a dashboard
  ✓ Nome "admin" in header (fix del BUG-004!)
  ✓ Menu admin completo visibile
API: POST /api/v1/auth/login
```

## TEST-002: Verifica Token JWT
```
AZIONE: Dopo login, ispeziona DevTools > Application > Cookies
VERIFICA:
  ✓ Token "access_token" presente
  ✓ Token contiene: user_id, email, tier, is_admin
API: GET /api/v1/users/me (con Bearer token)
```

## TEST-003: Registrazione Nuovo Utente
```
URL: http://localhost:3000/register
DATI:
  - Username: TEST_User_Chrome_001
  - Email: test_chrome_001@example.com
  - Password: Test123!
VERIFICA:
  ✓ Registrazione completata
  ✓ Utente può fare login
  ✓ Tier default = FREE
```

## TEST-004: Upgrade Subscription (Simulato)
```
URL: http://localhost:3000/subscriptions
PREREQUISITO: Login come test_chrome_001@example.com
AZIONE: Simula upgrade a PREMIUM
API: POST /api/v1/subscriptions/upgrade/premium
VERIFICA:
  ✓ Tier cambia da FREE a PREMIUM
  ✓ subscription_end settato a +30 giorni
```

---

# 🎬 ROUND 2: VIDEO MANAGEMENT

## TEST-010: Lista Video Library
```
URL: http://localhost:3000/library
PREREQUISITO: Login admin
VERIFICA:
  ✓ Lista video carica (anche se vuota)
  ✓ Filtri per stile funzionano
  ✓ Search bar attiva
API: GET /api/v1/videos?limit=20
```

## TEST-011: Upload Video
```
URL: http://localhost:3000/ingest-studio
AZIONE:
  1. Crea progetto "TEST_Video_Upload_01"
  2. Step 2: Upload video_test_karate.mp4
  3. Step 3: Configura opzioni (lingue: it, en)
  4. Step 4: Avvia processing
VERIFICA:
  ✓ Upload completa senza errori
  ✓ Progress bar funziona
  ✓ Video appare in library dopo processing
API: POST /api/v1/ingest/projects/{id}/upload
```

## TEST-012: Video Player HLS
```
URL: http://localhost:3000/player/{video_id}
PREREQUISITO: Video caricato e processato
VERIFICA:
  ✓ Player carica video HLS
  ✓ Controlli play/pause/seek funzionano
  ✓ Qualità adattiva (se disponibile)
  ✓ Sottotitoli toggle (se presenti)
```

## TEST-013: Video Streaming Protection
```
AZIONE: Prova a scaricare video direttamente
VERIFICA:
  ✓ URL video non accessibile direttamente
  ✓ Richiede token valido
  ✓ Watermark visibile (se abilitato)
```

---

# 🦴 ROUND 3: SKELETON EXTRACTION

## TEST-020: Lista Skeleton
```
URL: http://localhost:3000/skeletons
PREREQUISITO: Login admin
VERIFICA:
  ✓ Lista skeleton con date CORRETTE (fix BUG-003!)
  ✓ Non più "1 gennaio 1970"
  ✓ Filtri funzionano
API: GET /api/v1/skeleton/list (endpoint nuovo!)
```

## TEST-021: Skeleton Viewer 3D
```
URL: http://localhost:3000/skeleton-viewer
AZIONE: Seleziona uno skeleton esistente
VERIFICA:
  ✓ Viewer 3D carica
  ✓ 75 landmarks visibili (MediaPipe Holistic)
  ✓ Colori per body parts (rosso=braccia, blu=gambe, verde=corpo)
  ✓ Rotazione/zoom funzionano
```

## TEST-022: Estrazione Skeleton da Video
```
URL: http://localhost:3000/skeleton-editor
AZIONE:
  1. Carica video_test_karate.mp4
  2. Avvia estrazione skeleton
  3. Attendi completamento
VERIFICA:
  ✓ Progress bar mostra avanzamento
  ✓ Skeleton generato con confidence >0.7
  ✓ File JSON salvato in data/skeletons/
API: POST /api/v1/skeleton/extract
```

## TEST-023: Verifica Dettagli Mani
```
DOPO TEST-022:
VERIFICA NEL VIEWER:
  ✓ 21 landmarks per mano visibili
  ✓ Dita distinguibili (pollice, indice, etc.)
  ✓ Confidence per ogni landmark
```

---

# 🔄 ROUND 4: MULTI-VIDEO FUSION

## TEST-030: Dashboard Fusion
```
URL: http://localhost:3000/fusion
PREREQUISITO: Login admin
VERIFICA:
  ✓ Lista progetti fusion
  ✓ Pulsante "Nuovo Progetto"
  ✓ Filtri per stato
API: GET /api/v1/fusion/projects
```

## TEST-031: Crea Progetto Fusion
```
URL: http://localhost:3000/fusion
AZIONE:
  1. Click "Nuovo Progetto"
  2. Nome: TEST_Fusion_Karate_01
  3. Stile: Karate
  4. Click "Crea"
VERIFICA:
  ✓ Progetto creato
  ✓ Status "draft"
  ✓ UUID generato
API: POST /api/v1/fusion/projects
```

## TEST-032: Aggiungi Video a Fusion
```
URL: http://localhost:3000/fusion/{project_id}
AZIONE:
  1. Click "Aggiungi Video"
  2. Seleziona 2+ video dalla library
  3. Assegna peso (1.0 default)
VERIFICA:
  ✓ Video aggiunti con peso
  ✓ Count aggiorna
API: POST /api/v1/fusion/projects/{id}/videos
```

## TEST-033: Avvia Fusion Process
```
PREREQUISITO: Progetto con 2+ video
AZIONE:
  1. Click "Avvia Fusione"
  2. Attendi completamento (può richiedere minuti)
VERIFICA:
  ✓ WebSocket progress funziona
  ✓ Status cambia: draft → processing → completed
  ✓ Result skeleton generato
API: POST /api/v1/fusion/projects/{id}/process
WS: ws://localhost:8000/api/v1/fusion/ws/{project_id}
```

## TEST-034: Preview Avatar 360°
```
DOPO FUSION COMPLETATA:
URL: http://localhost:3000/fusion/{project_id}/preview
VERIFICA:
  ✓ Avatar 3D carica
  ✓ Rotazione 360° funziona
  ✓ Timeline con keyframes
  ✓ Play/pause movimento
API: GET /api/v1/fusion/projects/{id}/preview
```

---

# 📚 ROUND 5: KNOWLEDGE EXTRACTION (da Libri e Immagini)

## TEST-040: Upload PDF Libro
```
URL: http://localhost:3000/ingest-studio
AZIONE:
  1. Crea progetto "TEST_Libro_Karate"
  2. Tab "Document Upload"
  3. Carica libro_test_scan.pdf
VERIFICA:
  ✓ PDF accettato
  ✓ OCR avviato automaticamente
  ✓ Pagine estratte
API: POST /api/v1/ingest/projects/{id}/documents
```

## TEST-041: OCR Multi-lingua
```
PREREQUISITO: PDF caricato
VERIFICA OUTPUT:
  ✓ Testo italiano estratto
  ✓ Caratteri cinesi/giapponesi riconosciuti (se presenti)
  ✓ Confidence per ogni blocco
  ✓ Layout preservato (titoli, paragrafi)
```

## TEST-042: Estrazione Immagini da Libro
```
VERIFICA:
  ✓ Immagini tecniche estratte
  ✓ Diagrammi posture isolati
  ✓ Didascalie collegate a immagini
OUTPUT: Lista di {immagine, didascalia, pagina}
```

## TEST-043: Knowledge Graph Generation
```
DOPO OCR:
VERIFICA:
  ✓ Tecniche identificate (Named Entity Recognition)
  ✓ Relazioni tra tecniche (es. "Mae Geri precede Yoko Geri")
  ✓ Maestri/scuole riconosciuti
  ✓ JSON strutturato per AI Agent
```

## TEST-044: Estrazione da Singola Immagine
```
URL: http://localhost:3000/ingest-studio
AZIONE:
  1. Upload immagine_tecnica_01.jpg
  2. Avvia OCR + Pose Detection
VERIFICA:
  ✓ Testo estratto (nomi tecniche)
  ✓ Skeleton estratto dalla figura (se disegno)
  ✓ Traduzione automatica (ZH → IT se necessario)
```

---

# 🌐 ROUND 6: TRADUZIONE & SOTTOTITOLI

## TEST-050: Translation Dashboard
```
URL: http://localhost:3000/translation
VERIFICA:
  ✓ Pagina carica
  ✓ Selezione lingua source/target
  ✓ Input testo/file
```

## TEST-051: Traduzione Testo Marziale
```
AZIONE:
  1. Input: "Mae Geri è un calcio frontale nel Karate. Deriva dal termine giapponese 前蹴り."
  2. Target: English
  3. Click "Traduci"
VERIFICA:
  ✓ Traduzione completata
  ✓ Termini tecnici preservati: "Mae Geri", "Karate"
  ✓ Caratteri giapponesi tradotti correttamente
API: POST /api/v1/translation/translate
```

## TEST-052: Generazione Sottotitoli da Video
```
URL: http://localhost:3000/ingest-studio
PREREQUISITO: Video con audio uploadato
AZIONE:
  1. Step 3: Abilita "Generate Subtitles"
  2. Lingue: IT, EN, ZH, JA
  3. Avvia processing
VERIFICA:
  ✓ Sottotitoli generati per ogni lingua
  ✓ Timing corretto (SRT/VTT)
  ✓ Termini marziali preservati
API: Speech-to-Text (Whisper) + Translation
```

## TEST-053: Sottotitoli Live (WebSocket)
```
URL: http://localhost:3000/live-player/{event_id}
PREREQUISITO: Evento live attivo (simulato)
VERIFICA:
  ✓ Sottotitoli appaiono in real-time
  ✓ Cambio lingua funziona
  ✓ Latenza <2 secondi
WS: ws://localhost:8000/api/v1/live-translation/events/{id}/subtitles
```

---

# 🎤 ROUND 7: VOICE CLONING & TTS

## TEST-060: Audio TTS Base
```
URL: http://localhost:3000/audio-studio (se esiste) o API
AZIONE:
  1. Testo: "Questa è una tecnica di Karate chiamata Mae Geri"
  2. Lingua: Italiano
  3. Engine: Edge TTS
  4. Click "Genera"
VERIFICA:
  ✓ Audio generato
  ✓ Pronuncia comprensibile
  ✓ File scaricabile
API: POST /api/v1/audio/tts/generate
```

## TEST-061: Voice Cloning Setup
```
PREREQUISITO: audio_test_maestro.wav (30s di parlato chiaro)
AZIONE:
  1. Upload sample audio
  2. Avvia training voice clone
  3. Attendi completamento (può richiedere minuti)
VERIFICA:
  ✓ Voice profile creato
  ✓ Sample quality sufficiente (>30s)
API: POST /api/v1/audio/voice-clone/train
```

## TEST-062: Genera Audio con Voce Clonata
```
PREREQUISITO: Voice profile creato
AZIONE:
  1. Testo: "Benvenuti al corso di Tai Chi Chen style"
  2. Voice: Seleziona profilo clonato
  3. Genera
VERIFICA:
  ✓ Audio generato con voce del maestro
  ✓ Intonazione simile all'originale
  ✓ Qualità accettabile (non robotica)
API: POST /api/v1/audio/voice-clone/generate
```

## TEST-063: Traduzione Video con Voice Cloning
```
SCENARIO: Video in inglese → Italiano con voce clonata
AZIONE:
  1. Seleziona video in inglese
  2. Target: Italiano
  3. Voice: Profilo clonato maestro
  4. Genera versione doppiata
VERIFICA:
  ✓ Audio italiano generato
  ✓ Sincronizzazione con video
  ✓ Termini tecnici pronunciati correttamente
  ✓ Voce riconoscibile come "del maestro"
```

## TEST-064: Multi-lingua Batch
```
SCENARIO: Da 1 video → 5 lingue
LINGUE: IT, EN, ZH, JA, ES
VERIFICA:
  ✓ 5 tracce audio generate
  ✓ Termini marziali preservati in tutte le lingue
  ✓ Pronuncia nativa corretta (es. "氣" in cinese)
```

---

# 🎭 ROUND 8: AVATAR 3D

## TEST-070: Avatar Gallery
```
URL: http://localhost:3000/avatar-gallery
VERIFICA:
  ✓ Lista avatar disponibili
  ✓ Filtri per stile (Karate, Tai Chi, Kung Fu)
  ✓ Preview 3D per ogni avatar
```

## TEST-071: Avatar Viewer 3D Dettagliato
```
URL: http://localhost:3000/avatar-gallery/{avatar_id}
AZIONE: Click su avatar per preview
VERIFICA:
  ✓ Modello GLB carica
  ✓ Mani con dita visibili (21 bones per mano)
  ✓ Rotazione 360° fluida
  ✓ Zoom su dettagli (piedi, mani)
```

## TEST-072: Applica Skeleton ad Avatar
```
PREREQUISITO: Skeleton estratto + Avatar selezionato
AZIONE:
  1. Vai a fusion project completato
  2. Click "Esporta ad Avatar"
  3. Seleziona modello avatar
VERIFICA:
  ✓ Avatar si muove secondo skeleton
  ✓ Dita seguono hand landmarks
  ✓ Transizioni smooth
API: POST /api/v1/avatars/apply-skeleton
```

## TEST-073: Export Blender
```
PREREQUISITO: Avatar + Skeleton combinati
AZIONE:
  1. Click "Esporta per Blender"
  2. Formato: GLB o FBX
VERIFICA:
  ✓ File esportato
  ✓ Importabile in Blender
  ✓ Rig completo con animazione
API: GET /api/v1/export/blender/{project_id}
```

---

# 📅 ROUND 9: EVENTI IBRIDI

## TEST-080: Lista Eventi
```
URL: http://localhost:3000/events
VERIFICA:
  ✓ Lista eventi (presenziali + online)
  ✓ Filtri per data, tipo, stile
  ✓ Calendar view
API: GET /api/v1/live/events
```

## TEST-081: Crea Evento Ibrido
```
PREREQUISITO: Login admin
AZIONE:
  1. Click "Nuovo Evento"
  2. Compila:
     - Titolo: TEST_Evento_Ibrido_01
     - Tipo: Seminario
     - Data: [futuro]
     - Capacità presenziale: 50
     - Capacità online: unlimited
     - Bundle: Stage 2gg + Corso online
VERIFICA:
  ✓ Evento creato
  ✓ Opzioni multiple (5gg, 3gg, 2gg)
  ✓ Bundle configurato
API: POST /api/v1/events (se implementato)
```

## TEST-082: Prevendita Riservata
```
CONFIGURAZIONE EVENTO:
  - Fase 1 (giorni 1-10): Solo studenti del maestro
  - Fase 2 (giorno 11+): Aperto a tutti
VERIFICA:
  ✓ Utente non autorizzato non può comprare in Fase 1
  ✓ Utente con tag "studente_maestro" può comprare
  ✓ Dopo giorno 11, tutti possono comprare
```

## TEST-083: Split Payment (ASD + LIBRA)
```
SCENARIO: Utente compra bundle €300
VERIFICA:
  ✓ €200 vanno a conto ASD (Stripe Connect)
  ✓ €100 vanno a conto LIBRA
  ✓ Tracking corretto in database
```

## TEST-084: Waiting List
```
SCENARIO: Evento pieno
AZIONE: Utente tenta iscrizione
VERIFICA:
  ✓ Messaggio "Evento completo"
  ✓ Opzione "Aggiungi a waiting list"
  ✓ Notifica se posto si libera
```

---

# 💰 ROUND 10: LISTINI & PRICING

## TEST-090: Subscription Plans
```
URL: http://localhost:3000/subscriptions
VERIFICA PIANI:
  ✓ FREE: Con pubblicità, video limitati
  ✓ HYBRID_LIGHT: €7/mese, video limitati, no eventi
  ✓ HYBRID_STANDARD: €12/mese, più video
  ✓ PREMIUM: €24/mese, accesso illimitato
  ✓ BUSINESS: €49/mese, features ASD
API: GET /api/v1/subscriptions/plans
```

## TEST-091: Pay-Per-View (PPV)
```
SCENARIO: Utente FREE vuole vedere video Premium
AZIONE:
  1. Click su video locked
  2. Mostra prezzo singolo (€5-20)
  3. Acquista con Stelline o Stripe
VERIFICA:
  ✓ Video sbloccato dopo pagamento
  ✓ Accesso permanente (o a tempo)
API: POST /api/v1/payments/video/{id}/purchase
```

## TEST-092: Sistema Stelline
```
URL: http://localhost:3000/stelline (o wallet)
VERIFICA:
  ✓ Saldo stelline visibile
  ✓ Acquisto pacchetti (small/medium/large)
  ✓ Uso per PPV, donazioni, eventi
API: POST /api/v1/payments/stelline/purchase
```

## TEST-093: Donazioni a Maestri
```
URL: Pagina profilo maestro
AZIONE:
  1. Click "Dona"
  2. Scegli importo (€5, €10, €20, custom)
  3. Conferma
VERIFICA:
  ✓ Donazione registrata
  ✓ Maestro riceve notifica
  ✓ Revenue split corretto
API: POST /api/v1/donations
```

---

# 👑 ROUND 11: ADMIN DASHBOARD

## TEST-100: Admin Analytics
```
URL: http://localhost:3000/admin/analytics
PREREQUISITO: Login admin
VERIFICA:
  ✓ Pagina carica (fix BUG-001!)
  ✓ Overview con total_views, revenue, new_users
  ✓ Grafici funzionano
  ✓ Filtro periodo (7d, 30d, 90d)
API: GET /api/v1/admin/analytics/platform
```

## TEST-101: Admin Users Management
```
URL: http://localhost:3000/admin/users
VERIFICA:
  ✓ Lista utenti con search
  ✓ Filtri per tier, status
  ✓ Dettaglio utente cliccabile
  ✓ Azioni: ban, upgrade, delete
```

## TEST-102: Content Moderation
```
URL: http://localhost:3000/admin/moderation
VERIFICA:
  ✓ Coda video in attesa
  ✓ Preview video
  ✓ Pulsanti Approva/Rifiuta
  ✓ Note di moderazione
```

## TEST-103: System Settings
```
URL: http://localhost:3000/admin/system
VERIFICA:
  ✓ Configurazioni globali
  ✓ Toggle features (ads, live, etc.)
  ✓ Salvataggio funziona
```

---

# 📖 ROUND 12: CURRICULUM & LEARNING

## TEST-110: Lista Curriculum
```
URL: http://localhost:3000/curriculum
VERIFICA:
  ✓ Lista corsi (fix BUG-002 paths!)
  ✓ Filtri per arte marziale
  ✓ Card con info livelli
API: GET /api/v1/curricula
```

## TEST-111: Dettaglio Curriculum
```
AZIONE: Click su curriculum
VERIFICA:
  ✓ Livelli visibili (cinture, gradi)
  ✓ Video per ogni livello
  ✓ Progress tracking
  ✓ Pulsante "Iscriviti"
API: GET /api/v1/curricula/{id}
```

## TEST-112: Enrollment & Progress
```
AZIONE:
  1. Iscriviti a curriculum
  2. Completa primo video
  3. Verifica progress
VERIFICA:
  ✓ Enrollment registrato
  ✓ Progress % aggiorna
  ✓ Badge/XP guadagnati (se gamification attiva)
API: POST /api/v1/curricula/{id}/enroll
```

---

# 📡 ROUND 13: LIVE STREAMING

## TEST-120: Live Events List
```
URL: http://localhost:3000/live-player
VERIFICA:
  ✓ Lista eventi live/scheduled
  ✓ Badge "LIVE" per eventi attivi
  ✓ Countdown per prossimi eventi
```

## TEST-121: Live Player (Simulato)
```
PREREQUISITO: Evento live attivo
VERIFICA:
  ✓ Player HLS funziona
  ✓ Chat real-time
  ✓ Sottotitoli multi-lingua
  ✓ Viewer count
WS: Chat WebSocket funzionante
```

## TEST-122: Broadcaster Interface
```
URL: http://localhost:3000/broadcast (admin/maestro)
VERIFICA:
  ✓ Stream key visibile
  ✓ RTMP URL configurato
  ✓ Start/Stop stream
  ✓ Viewer analytics real-time
```

---

# 🎴 ROUND 14: CARD TECNICHE & MINI-LIBRI

## TEST-130: Genera Card Tecnica
```
PREREQUISITO: Tecnica estratta da libro/video
AZIONE:
  1. Seleziona tecnica "Mae Geri"
  2. Click "Genera Card"
VERIFICA OUTPUT:
  ✓ PNG con:
    - Nome tecnica (IT + originale)
    - Immagine posizione (da video o disegno)
    - Descrizione breve
    - Punti chiave
    - QR code a video tutorial
```

## TEST-131: Export PDF Tecniche
```
AZIONE:
  1. Seleziona 10 tecniche
  2. Click "Esporta PDF"
VERIFICA:
  ✓ PDF generato con layout professionale
  ✓ Una pagina per tecnica
  ✓ Indice navigabile
  ✓ Immagini alta qualità
```

## TEST-132: Mini-Libro Automatico
```
SCENARIO: Da knowledge base → Mini-libro
AZIONE:
  1. Seleziona stile "Karate Shotokan"
  2. Livello: Principiante
  3. Genera mini-libro
VERIFICA:
  ✓ PDF con:
    - Copertina
    - Introduzione
    - 10-20 tecniche base
    - Immagini/diagrammi
    - Glossario termini
```

---

# 🤖 ROUND 15: AI COACH (se implementato)

## TEST-140: AI Coach Chat
```
URL: http://localhost:3000/ai-coach
AZIONE:
  1. Domanda: "Come si esegue Mae Geri?"
VERIFICA:
  ✓ Risposta con spiegazione
  ✓ Link a video tutorial
  ✓ Termini tecnici corretti
API: POST /api/v1/ai-coach/chat
```

## TEST-141: Feedback su Video Utente
```
SCENARIO: Utente carica video esecuzione
AZIONE:
  1. Upload video utente
  2. Richiedi analisi AI
VERIFICA:
  ✓ Skeleton estratto
  ✓ Confronto con "tecnica perfetta"
  ✓ Feedback: "Alza di più il ginocchio a 45°"
  ✓ Punti di miglioramento evidenziati
```

---

# 🔒 ROUND 16: SECURITY & COMPLIANCE

## TEST-150: SQL Injection Prevention
```
AZIONE: Invia input malevolo
INPUT: admin@mediacenter.it'; DROP TABLE users;--
VERIFICA:
  ✓ Nessun crash
  ✓ Input sanitizzato
  ✓ Login fallisce normalmente
```

## TEST-151: Unauthorized Access
```
AZIONE: Accedi a endpoint admin senza login
URL: http://localhost:8000/api/v1/admin/users
VERIFICA:
  ✓ Status 401 Unauthorized
  ✓ Nessun dato esposto
```

## TEST-152: Rate Limiting
```
AZIONE: Invia 100 richieste in 10 secondi
VERIFICA:
  ✓ Rate limit scatta (429 Too Many Requests)
  ✓ Sistema non crasha
```

---

# 🧹 CLEANUP

## Dopo tutti i test:

```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

# 1. Dry-run (mostra cosa verrà eliminato)
python cleanup_test_data.py --dry-run

# 2. Se ok, esegui pulizia
python cleanup_test_data.py --execute
```

Eliminerà:
- Utenti con email "test_*"
- Progetti con nome "TEST_*"
- Video di test
- Dati creati nelle ultime 24 ore

---

# 📊 REPORT FINALE

```
═══════════════════════════════════════════════════════════════
MEDIA CENTER STAFF APP - TEST REPORT
Data: _______________
Tester: Chrome Extension (Claude)
═══════════════════════════════════════════════════════════════

ROUND 1 - Auth & Users:        ___/4 test passati
ROUND 2 - Video Management:    ___/4 test passati
ROUND 3 - Skeleton:            ___/4 test passati
ROUND 4 - Fusion:              ___/5 test passati
ROUND 5 - Knowledge Extract:   ___/5 test passati
ROUND 6 - Translation:         ___/4 test passati
ROUND 7 - Voice Cloning:       ___/5 test passati
ROUND 8 - Avatar 3D:           ___/4 test passati
ROUND 9 - Eventi Ibridi:       ___/5 test passati
ROUND 10 - Pricing:            ___/4 test passati
ROUND 11 - Admin:              ___/4 test passati
ROUND 12 - Curriculum:         ___/3 test passati
ROUND 13 - Live Streaming:     ___/3 test passati
ROUND 14 - Card & Mini-libri:  ___/3 test passati
ROUND 15 - AI Coach:           ___/2 test passati
ROUND 16 - Security:           ___/3 test passati

═══════════════════════════════════════════════════════════════
TOTALE: ___/62 test passati (___%)
═══════════════════════════════════════════════════════════════

BUG CRITICI: ___
BUG MAGGIORI: ___
BUG MINORI: ___

APPROVATO PER PRODUZIONE: ☐ SÌ  ☐ NO

NOTE:
_______________________________________________________________
_______________________________________________________________
_______________________________________________________________

═══════════════════════════════════════════════════════════════
```

---

# 📝 NOTE IMPLEMENTAZIONE

## Funzionalità da verificare se esistono:

| Feature | Endpoint Atteso | Pagina Frontend |
|---------|-----------------|-----------------|
| Knowledge Extract | POST /api/v1/knowledge/extract | /ingest-studio |
| Voice Clone Train | POST /api/v1/audio/voice-clone/train | /audio-studio |
| Eventi Ibridi | POST /api/v1/events | /events/create |
| Card Generator | POST /api/v1/cards/generate | /cards |
| AI Coach | POST /api/v1/ai-coach/chat | /ai-coach |
| Mini-libro | POST /api/v1/books/generate | /books |

## API già verificate funzionanti (da session precedente):

- ✅ GET /api/v1/admin/analytics/platform
- ✅ GET /api/v1/skeleton/list
- ✅ GET /api/v1/curricula
- ✅ POST /api/v1/auth/login
- ✅ GET /api/v1/users/me

---

**Fine Test Plan V2.0 - 31 Gennaio 2026**
**Totale Test: 62 | Tempo Stimato: 4-6 ore**

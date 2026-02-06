# 🔄 DOCUMENTO MIGRAZIONE CHAT - MEDIA CENTER ARTI MARZIALI
## Data: 31 Gennaio 2026
## Motivo: Chat satura, continuare in nuova conversazione

---

# SEZIONE 1: STATO PROGETTO

## 📍 OVERVIEW

| Campo | Valore |
|-------|--------|
| **Progetto** | Media Center Arti Marziali |
| **Tipo** | Gestionale AI-First per contenuti arti marziali |
| **Completamento** | ~80% |
| **Backend** | FastAPI + Python 3.11 |
| **Frontend** | Next.js 14 + React + TypeScript |
| **Path** | `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\` |

## 🚀 COMANDI AVVIO

```powershell
# Backend (porta 8000)
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000

# Frontend (porta 3000 o 3100)
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev
```

---

# SEZIONE 2: COSA È STATO COMPLETATO

## ✅ Backend (95%)

| Modulo | Stato |
|--------|-------|
| Auth JWT + refresh | ✅ 100% |
| User management | ✅ 100% |
| Skeleton extraction (75 landmarks) | ✅ 100% |
| Multi-video fusion (DTW) | ✅ 100% |
| Anonimizzazione (Forgetting by Design) | ✅ 100% |
| Blender export | ⚠️ 80% |
| **Classificazione contenuti** | ✅ **APPENA FATTO** |

## ✅ Frontend (87.5%)

| Pagina | Stato |
|--------|-------|
| Home `/` | ✅ |
| Login `/login` | ✅ |
| Register `/register` | ✅ |
| Avatar Gallery `/avatar-gallery` | ✅ |
| Ingest Studio `/ingest-studio` | ✅ |
| Skeleton Library `/skeletons` | ⚠️ Date errate |
| Multi-Video Fusion `/fusion` | ✅ |
| Admin Dashboard `/admin` | ✅ |
| Admin Analytics `/admin/analytics` | ❌ Crash |
| Translation `/translation` | ✅ |
| Live Player `/live-player` | ✅ |
| Events `/events` | ✅ |
| Profilo `/me` | ✅ |
| Curriculum `/curriculum` | ⚠️ API 401 |

## ✅ CLASSIFICAZIONE CONTENUTI (Claude Code - 31 Gen 2026)

**File creati:**

```
backend/
├── models/
│   ├── content_type.py         # Enum 5 tipi
│   └── video_section.py        # Modello sezioni video
├── routers/
│   └── content_classification.py   # API CRUD
└── tests/
    └── test_content_classification.py  # Test suite
```

**Enum ContentType:**
- `FORMA_COMPLETA` - Sequenza intera (es. "81 posizioni")
- `MOVIMENTO_SINGOLO` - Movimento isolato (es. "Nuvola che spinge")
- `TECNICA_A_DUE` - Applicazione vs avversario
- `SPIEGAZIONE` - Maestro che parla
- `VARIANTE` - Stesso movimento, scuola diversa

**API Endpoints nuovi:**
- `GET /api/v1/content-types`
- `POST /api/v1/sections`
- `GET /api/v1/sections`
- `GET /api/v1/sections/{id}`
- `PATCH /api/v1/sections/{id}`
- `DELETE /api/v1/sections/{id}`

---

# SEZIONE 3: COSA MANCA

## 🔴 Priorità ALTA

| Task | Effort | Descrizione |
|------|--------|-------------|
| UI creazione progetto | 2 giorni | Wizard selezione tipo + upload |
| Editor tagging video | 3 giorni | Player + timeline + marcatori |
| Visualizzatore fusion | 2 giorni | Avatar 3D risultato |

## 🟡 Priorità MEDIA

| Task | Effort | Descrizione |
|------|--------|-------------|
| Pipeline Blender automatica | 3 giorni | Render headless batch |
| Tecnica a due (2 skeleton) | 5 giorni | Multi-person tracking |
| TTS multilingua | 3 giorni | Voce sintetica |
| Overlay didattici | 4 giorni | Frecce, angoli, annotazioni |
| Knowledge extraction | 5 giorni | OCR → ChromaDB → RAG |

## 🐛 Bug Noti

| ID | Pagina | Problema | Severità |
|----|--------|----------|----------|
| BUG-001 | `/admin/analytics` | Crash "Ops!" | 🔴 |
| BUG-002 | `/curriculum` | API 401 | 🔴 |
| BUG-003 | `/skeletons` | Date "1970" | 🟡 |
| BUG-004 | Header | Nome utente mancante | 🟡 |

---

# SEZIONE 4: WORKFLOW MEDIA CENTER (VALIDATO)

## Flusso Completo

```
FASE 1: ACQUISIZIONE
├── Video nostri (stage, eventi)
├── Video maestri (autorizzati)
├── Libri digitalizzati
└── Tutto in /temp → Cancellato dopo processing

FASE 2: ESTRAZIONE
├── Audio → Whisper → Trascrizione
├── Skeleton → MediaPipe Holistic (75 landmarks)
├── Fotogrammi → Immagini chiave
└── Tecniche → Auto-detection

FASE 3: CLASSIFICAZIONE (APPENA IMPLEMENTATO)
├── FORMA_COMPLETA
├── MOVIMENTO_SINGOLO
├── TECNICA_A_DUE
├── SPIEGAZIONE
└── VARIANTE

FASE 4: PROGETTO
├── Crea progetto con tipo
├── Carica 40+ video stessa forma
└── Sistema processa automaticamente

FASE 5: MULTI-VIDEO FUSION
├── DTW Alignment (velocità diverse)
├── Quality Scoring (peso 0-100)
├── Weighted Averaging
├── Outlier Removal
└── OUTPUT: Consensus Skeleton "perfetto"

FASE 6: ANONIMIZZAZIONE
├── Rimuovi riferimenti fonti
├── Parafrasa (mai copia)
├── Mescola ordine
└── LLM stateless (no history)

FASE 7: PRODUZIONE VIDEO
├── Avatar 3D stilizzato (non fotorealistico)
├── Voce TTS sintetica (NON clonata)
├── Overlay didattici (frecce, angoli)
└── Export MP4 multilingua
```

## Caso Speciale: Stage con Maestri

```
Video stage nostro → Voice cloning voce maestro → Traduzione multilingua
OUTPUT: Maestro "parla" in più lingue con SUA voce
(Solo per eventi nostri, NON per video didattici)
```

---

# SEZIONE 5: REGOLE SVILUPPO

## AI-First System V2.0

Ogni file DEVE avere:

```python
"""
🎓 AI_MODULE: Nome
🎓 AI_DESCRIPTION: Cosa fa
🎓 AI_BUSINESS: Valore business
🎓 AI_TEACHING: Concetto tecnico

🔄 ALTERNATIVE_VALUTATE:
- Opzione A: Scartata perché [motivo]

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Vantaggio 1
- Vantaggio 2

📊 BUSINESS_IMPACT:
- Metrica: valore
"""
```

## Enterprise Test Suite

| Metrica | Target |
|---------|--------|
| Coverage | ≥ 90% |
| Pass Rate | ≥ 95% |
| Categorie | Unit, Integration, Security, Performance, Stress, Holistic |

## ⛔ LEGGE ZERO MOCK

**VIETATO:**
- `jest.mock()`, `jest.fn()`
- `MagicMock()`, `AsyncMock()`, `patch()`
- Qualsiasi simulazione API/DB

**OBBLIGATORIO:**
- Test con backend REALE attivo
- Se backend spento → test DEVONO fallire

---

# SEZIONE 6: DOCUMENTI SALVATI

| File | Contenuto |
|------|-----------|
| `MEDIA_CENTER_WORKFLOW_COMPLETO.md` | Processo validato |
| `MEDIA_CENTER_COSA_MANCA.md` | TODO dettagliato |
| `MEGAPROMPT_COMPLETO_CLAUDE_CODE.md` | Regole + task classificazione |

---

# SEZIONE 7: PROSSIMI PASSI

## Opzione A: UI Creazione Progetto (Frontend)

Wizard React/Next.js:
1. Step 1: Scegli stile (Tai Chi, Wing Chun...)
2. Step 2: Scegli tipo (FORMA, MOVIMENTO...)
3. Step 3: Nome + descrizione
4. Step 4: Upload video

## Opzione B: Editor Tagging Video

Player video con:
- Timeline interattiva
- Marcatori inizio/fine sezione
- Dropdown selezione tipo
- Lista sezioni create

## Opzione C: Fix Bug

- BUG-001: Admin Analytics crash
- BUG-002: Curriculum API 401

---

# SEZIONE 8: UTENTI TEST

| Ruolo | Email | Password |
|-------|-------|----------|
| Admin | admin@mediacenter.it | Test123! |
| Studente Free | giulia.bianchi@example.com | Test123! |
| Studente Premium | mario.rossi@example.com | Test123! |
| Maestro | tanaka.hiroshi@mediacenter.demo | Test123! |
| ASD | presidente@karatemilano.it | Test123! |

---

# SEZIONE 9: COME CONTINUARE

## In Nuova Chat

1. **Incolla questo documento** come primo messaggio
2. **Specifica cosa vuoi fare:**
   - "Continua con UI creazione progetto"
   - "Fix bug Analytics"
   - "Editor tagging video"
3. **Claude leggerà** e riprenderà da dove eravamo

## Con Claude Code

1. Apri Claude Code
2. Passa megaprompt per task specifico
3. Conferma piano prima che scriva
4. Testa dopo implementazione

---

# FINE DOCUMENTO MIGRAZIONE

**Data creazione:** 31 Gennaio 2026
**Stato chat:** SATURA → Continuare in nuova conversazione
**Prossimo task suggerito:** UI Creazione Progetto (Frontend)

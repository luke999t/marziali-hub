# 🤝 COORDINAMENTO CLAUDE DESKTOP ↔ CLAUDE WEB

**Data Creazione**: 19 Novembre 2025
**Progetto**: Media Center Arti Marziali v3.0
**Completamento**: 88%

---

## 📊 STATO ATTUALE PROGETTO

### Completamento Generale: 88%

| Componente | % | Status | Note |
|------------|---|--------|------|
| **Backend Core** | 90% | ✅ | FastAPI, MediaPipe, ChromaDB |
| **Backend API** | 95% | ✅ | 13 routers, 87 endpoints |
| **Database Models** | 100% | ✅ | 8 models completi |
| **Test Suite** | 95% | ✅ | 143+ tests, coverage 95% |
| **Frontend Desktop** | 70% | ⚠️ | Next.js, React, Three.js |
| **Mobile App** | 0% | ❌ | FASE 2 (da fare) |
| **AI Features** | 30% | ⚠️ | ChromaDB OK, multi-video fusion manca |

---

## 🎯 DIVISIONE RESPONSABILITÀ

### CLAUDE CODE DESKTOP (Backend)
**Path**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\`

**Responsabilità**:
- ✅ API REST endpoints (FastAPI)
- ✅ Database models & migrations (SQLAlchemy)
- ✅ Business logic (services/)
- ✅ AI processing (MediaPipe, OpenAI, ChromaDB)
- ✅ WebSocket real-time
- ✅ Background tasks (Celery)
- ✅ Testing (pytest)

**File Principali**:
```
backend/
├── main.py              # Entry point FastAPI
├── api/v1/              # 13 API routers
├── models/              # 8 SQLAlchemy models
├── services/
│   ├── video_studio/    # 54 file Python (video processing)
│   └── live_translation/# 7 file (traduzioni)
├── core/                # Database, security, Sentry
└── tests/               # 143+ tests
```

### CLAUDE CODE WEB (Frontend - TU)
**Path**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend\`

**Responsabilità**:
- ⚠️ UI Components (React/Next.js)
- ⚠️ Pages & Routing (App Router)
- ⚠️ State Management (Context API / Zustand)
- ⚠️ API Integration (axios / fetch)
- ⚠️ 3D Visualization (Three.js)
- ⚠️ Styling (Tailwind CSS)
- ⚠️ PWA Features (service worker)

**File Principali**:
```
frontend/
├── src/
│   ├── app/
│   │   ├── chat/            # ✅ Chat UI (fatto)
│   │   ├── donations/       # ✅ Donations UI (fatto)
│   │   ├── skeleton-viewer/ # ✅ 3D Viewer (fatto)
│   │   ├── skeleton-editor/ # ⚠️ Editor (da completare)
│   │   ├── upload/          # ⚠️ Upload UI (da completare)
│   │   └── ...              # Altri 10+ pages
│   └── components/
│       ├── SkeletonViewer3D.tsx      # ✅ OK
│       ├── SkeletonEditor3D.tsx      # ⚠️ Da testare
│       ├── MessageThread.tsx         # ✅ OK
│       ├── ConversationList.tsx      # ✅ OK
│       └── LiveSubtitles.tsx         # ⚠️ Da completare
├── package.json
└── next.config.js
```

---

## 🔄 WORKFLOW COORDINAMENTO

### FASE 1: DEFINIZIONE CONTRATTO API

**Prima di sviluppare qualsiasi feature, SEMPRE definire il contratto:**

```yaml
STEP 1: Discutere insieme cosa serve
  - Feature da implementare
  - Endpoint necessari
  - Request/Response schema
  - Autenticazione richiesta
  - Error codes

STEP 2: Desktop scrive API schema
  File: backend/api/v1/schemas.py
  - Pydantic models Request/Response
  - Validation rules
  - Examples

STEP 3: Desktop crea endpoint VUOTO
  File: backend/api/v1/[modulo].py
  - Route con decoratori
  - Docstring completo
  - Return mock data

STEP 4: Web testa con mock data
  - Chiamate API con fetch/axios
  - Gestione loading/error
  - UI rendering

STEP 5: Desktop implementa logica
  - Business logic
  - Database queries
  - Error handling

STEP 6: Test integrazione insieme
  - Backend running
  - Frontend calling
  - Verifiche end-to-end
```

### FASE 2: FILE CONDIVISI CRITICI

**Creare cartella `shared/` nella root progetto:**

```
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\shared\
├── api_contracts.yaml       # SINGLE SOURCE OF TRUTH
├── types.ts                # TypeScript types da Pydantic
├── error_codes.md          # Codici errore standard
└── dev_status.json         # Chi sta facendo cosa ORA
```

#### File: `dev_status.json` - AGGIORNARE SEMPRE

```json
{
  "last_update": "2025-11-19T15:30:00Z",
  "claude_desktop": {
    "current_task": "Implement video transcoding pipeline",
    "file_working_on": "backend/services/video_studio/massive_video_processor.py",
    "status": "in_progress",
    "blocking": false,
    "eta_completion": "2 hours",
    "next_task": "Add HLS segmentation"
  },
  "claude_web": {
    "current_task": "Build upload progress UI",
    "file_working_on": "frontend/src/app/upload/page.tsx",
    "status": "waiting_api",
    "blocking_on": "GET /api/v1/videos/upload-progress/:id endpoint",
    "will_resume_when": "Desktop completes upload progress API",
    "alternative_work": "Can work on skeleton viewer improvements meanwhile"
  }
}
```

---

## 🚨 REGOLE CRITICHE

### DO ✅

1. **SEMPRE leggere `dev_status.json` prima di iniziare**
2. **SEMPRE aggiornare `dev_status.json` quando cambi task**
3. **SEMPRE definire API contract PRIMA di sviluppare**
4. **SEMPRE testare localmente prima di push**
5. **SEMPRE scrivere test per nuovo codice**
6. **SEMPRE commit messaggi descrittivi**
7. **SEMPRE AI-First comments (vedi regole project knowledge)**
8. **SEMPRE type hints (Python) e types (TypeScript)**

### DON'T ❌

1. **MAI modificare `api_contracts.yaml` senza consenso**
2. **MAI push su `main` senza test**
3. **MAI placeholder code (TODO, FIXME)**
4. **MAI hardcode credenziali**
5. **MAI commit node_modules, __pycache__, .env**
6. **MAI skipare validation input**
7. **MAI dimenticare error handling**
8. **MAI codice senza AI-First comments**

---

## 🎯 PROSSIMI STEP IMMEDIATI

### TU (Frontend - Questa Settimana)

1. **Completare Skeleton Editor UI** 
   - File: `frontend/src/app/skeleton-editor/page.tsx`
   - Test editing landmarks
   - Save/Load functionality

2. **Implementare Upload Progress**
   - Polling o WebSocket per progress
   - Progress bar UI
   - Cancel upload button

3. **Test Integrazione**
   - Tutti endpoint backend
   - Gestione errori
   - Loading states

### Desktop (Backend - Già fatto / in corso)

1. ✅ ChromaDB Semantic Retrieval - FATTO
2. ✅ Chat System API - FATTO
3. ⚠️ Traduzioni live API - IN CORSO

---

## 📖 RISORSE UTILI

### API Documentation
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Documentation Files
- **MEGA_PROMPT**: `docs/MEGA_PROMPT_CLAUDE_CODE_WEB_v3.md`
- **Gap Analysis**: `docs/ANALISI_GAP_FUNZIONALITA_DETTAGLIATA.md`
- **API Contracts**: `shared/api_contracts.yaml` (da creare)

---

**Preparato da**: Claude Code Assistant
**Data**: 19 Novembre 2025
**Versione**: 1.0
**Status**: ✅ Pronto per coordinamento

🤝 **Buon lavoro coordinato!**

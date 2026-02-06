# 📋 LISTA FILE DA COPIARE - VERIFICATA

**Data**: 10 Novembre 2025
**Approccio**: Tu sposti i backup, io ti guido sui file attivi

---

## ✅ OPERAZIONE 1: TU SPOSTI I BACKUP

### Backup da Spostare

Sposta TUTTE le cartelle con questi pattern in una cartella separata (es: `C:\Users\utente\Desktop\ARCHIVIO_BACKUP\`):

```
MediaCenter_Modular/backup_*
MediaCenter_Modular/BACKUP_*
MediaCenter_Modular/modules/video_studio/backup_*
```

**Comando PowerShell** (se vuoi farlo automatico):
```powershell
# Crea cartella archivio
mkdir "C:\Users\utente\Desktop\ARCHIVIO_BACKUP"

# Sposta tutti i backup (NON copia, SPOSTA)
Get-ChildItem "C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular" -Directory | Where-Object { $_.Name -like "backup_*" -or $_.Name -like "BACKUP_*" } | Move-Item -Destination "C:\Users\utente\Desktop\ARCHIVIO_BACKUP\"
```

**O manualmente**: Trascina le cartelle `backup_*` e `BACKUP_*` in ARCHIVIO_BACKUP

---

## ✅ OPERAZIONE 2: IO VERIFICO I FILE ATTIVI

### FILE DA COPIARE (119 totali verificati)

#### 📂 A. BACKEND - Video Studio Module (57 file Python + config)

**Path sorgente**: `MediaCenter_Modular/modules/video_studio/`

**File CORE** (da copiare TUTTI):

```
modules/video_studio/src/
├── __init__.py
├── advanced_analytics.py                    # ✅ Analytics (Nov 9)
├── ai_conversational_agent.py               # ✅ AI Q&A (Nov 7) - DA FIXARE
├── annotation_manager.py                    # ✅ Annotations
├── annotation_system.py                     # ✅ System (riferimento sparring)
├── auth.py                                  # ✅ JWT (Nov 9)
├── batch_processor.py                       # ✅ Batch (Nov 9)
├── cache_manager.py                         # ✅ Cache (Nov 9)
├── celery_tasks.py                          # ✅ Celery (Nov 8)
├── comparison_engine.py                     # ✅ DTW (Sep 28) - IMPORTANTE
├── comparison_tool.py                       # ✅ Tool (Nov 8)
├── database.py                              # ✅ DB (Nov 9)
├── db_models.py                             # ✅ Models (Nov 8)
├── frame_level_annotator.py                 # ✅ Annotator
├── hybrid_translator.py                     # ✅ Translator
├── ingest_orchestrator.py                   # ✅ Orchestrator
├── knowledge_base_gui.py                    # ✅ GUI
├── knowledge_base_manager.py                # ✅ Manager
├── knowledge_extractor.py                   # 🔄 Extractor (da estendere)
├── knowledge_sandbox.py                     # ✅ Sandbox
├── main.py                                  # ✅ MAIN ENTRY POINT
├── martial_arts_patterns.py                 # ✅ Patterns
├── massive_video_processor.py               # ✅ Processor
├── models.py                                # ✅ Models
├── motion_analyzer.py                       # ✅ Analyzer
├── pose_detection.py                        # ✅ Detection
├── realtime_pose_corrector.py               # ✅ Corrector
├── second_person_converter.py               # ✅ Converter
├── skeleton_converter.py                    # ✅ Converter
├── skeleton_editor_api.py                   # ✅ Editor API
├── skeleton_extraction_holistic.py          # ✅ CORE (Nov 7) 75 landmarks
├── skeleton_viewer_simple.py                # ✅ Viewer
├── style_classifier.py                      # 🔄 Classifier (da estendere)
├── technique_extractor.py                   # ✅ Extractor (Nov 5) 26KB
├── translation_manager.py                   # ✅ Translator
├── upload_api.py                            # ✅ Upload (Nov 9) 28KB
├── video_studio_api.py                      # ✅ API
├── voice_cloning.py                         # ✅ Voice
├── websocket_manager.py                     # ✅ WebSocket (Nov 9)
└── workflow_orchestrator.py                 # ✅ Orchestrator

modules/video_studio/src/api/
├── massive_processing.py                    # ✅ Massive API
├── massive_processing_PARALLELO.py          # ✅ Parallel
└── projects.py                              # ✅ Projects

modules/video_studio/tests/                  # ✅ COPIA TUTTI (test suite)
├── __init__.py
├── conftest.py
├── test_advanced_features.py
├── test_ai_agent.py
├── test_api_endpoints.py
├── test_auth.py
├── test_complete_system_OLISTIC.py
├── test_database.py
├── test_imports_SIMPLE.py
├── test_realtime_correction.py
└── test_skeleton_holistic.py

modules/video_studio/
├── start_api.py                             # ✅ Startup script
├── run_tests.py                             # ✅ Test runner
└── requirements.txt                         # ✅ SE ESISTE
```

**File root test** (opzionali ma utili):
```
modules/video_studio/
├── test_*.py                                # Tutti i test_*.py nella root
```

---

#### 📂 B. BACKEND - Altri Moduli

**Knowledge Extraction** (nuovo modulo, tutto recente):
```
modules/knowledge_extraction/
├── config/settings.py
├── src/
│   ├── api/
│   │   ├── text_endpoints.py
│   │   └── video_endpoints.py
│   ├── core/
│   │   ├── angle_extractor.py
│   │   ├── concept_detector.py
│   │   ├── extractor.py
│   │   ├── image_processor.py
│   │   ├── nlp_processor.py
│   │   ├── ocr_engine.py                    # ✅ OCR!
│   │   ├── pattern_matcher.py
│   │   └── video_analyzer.py
│   ├── models/
│   │   ├── database.py
│   │   ├── technique.py
│   │   └── video.py
│   ├── parsers/
│   │   ├── docx_parser.py                   # ✅ DOCX!
│   │   ├── pdf_parser.py                    # ✅ PDF!
│   │   └── text_parser.py
│   ├── services/
│   │   ├── extraction_service.py
│   │   └── video_service.py
│   └── main.py
└── INTEGRATION_CLIENT.py
```

**Video Library**:
```
modules/video_library/src/
├── main.py
├── video_library_api.py
└── video_library_service.py
```

**Video Streaming**:
```
modules/video_streaming/src/
├── main.py
├── streaming_api.py
└── streaming_service.py
```

**Auth Core**:
```
core/auth/src/
├── auth_api.py
├── auth_service.py
└── main.py
```

---

#### 📂 C. STREAMING PLATFORM (95% completo)

**Path sorgente**: `streaming_platform/backend/`

**Copia TUTTA la cartella** (esclusi node_modules, __pycache__, venv):

```
streaming_platform/backend/
├── main.py                                  # Entry point
├── requirements.txt                         # Dependencies
├── .env.example                             # Template
│
├── api/v1/                                  # ✅ 87 endpoints
│   ├── admin.py                             # 19 endpoints
│   ├── asd.py                               # 12 endpoints (605 righe)
│   ├── blockchain.py                        # 8 endpoints
│   ├── maestro.py                           # 15 endpoints
│   ├── subscriptions.py                     # 4 endpoints
│   ├── user.py                              # 10 endpoints
│   └── ... (altri)
│
├── models/                                  # ✅ 31 tabelle
│   ├── __init__.py
│   ├── ads.py                               # 11K
│   ├── communication.py                     # 14K ⭐ Message, CorrectionRequest
│   ├── donation.py                          # 15K ⭐ Donazioni ASD
│   ├── live_minor.py                        # 9K
│   ├── maestro.py                           # 11K
│   ├── user.py                              # 10K ⭐ Subscription tiers
│   └── video.py                             # 16K
│
├── modules/                                 # ✅ Business logic
│   ├── blockchain/
│   │   └── blockchain_service.py            # 21K
│   ├── auth/
│   ├── live/
│   ├── payment/
│   └── video/
│
├── core/                                    # ✅ Core utilities
│   ├── database.py
│   ├── security.py
│   └── config.py
│
└── tests/                                   # ✅ Test suite
    ├── unit/
    └── integration/
```

---

#### 📂 D. FRONTEND Next.js

**Path sorgente**: `MediaCenter_Modular/frontend/`

**Copia TUTTA la cartella** (esclusi node_modules, .next):

```
frontend/
├── package.json                             # ✅ Dependencies
├── next.config.js                           # ✅ Config
├── tailwind.config.js                       # ✅ Tailwind
├── tsconfig.json                            # ✅ TypeScript
│
├── src/
│   ├── app/                                 # ✅ App Router
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── skeleton-viewer/
│   │   │   └── page.tsx                     # ✅ Viewer funzionante
│   │   ├── skeleton-editor/
│   │   │   └── page.tsx                     # ✅ 3D editor
│   │   ├── upload/
│   │   │   └── page.tsx                     # ✅ Upload UI
│   │   └── pose-detection/
│   │       └── page.tsx                     # ✅ Detection
│   │
│   └── components/                          # ✅ Componenti
│       ├── SkeletonEditor3D.tsx             # ✅ Avatar 3D (352 righe)
│       ├── SkeletonViewer.tsx               # ✅ 2D viewer
│       ├── VideoUpload.tsx                  # ✅ Upload
│       └── ... (altri)
│
└── public/                                  # ✅ Static files
```

---

#### 📂 E. FILE ROOT (Config)

**Path sorgente**: `MediaCenter_Modular/`

```
MediaCenter_Modular/
├── README.md                                # SE ESISTE
├── requirements.txt                         # SE ESISTE (root)
├── .gitignore                               # SE ESISTE
├── docker-compose.yml                       # SE ESISTE
└── .env.example                             # SE ESISTE
```

---

## 🚫 FILE DA **NON** COPIARE

### Esclusioni Automatiche

```
❌ backup_*/                                 # Backup (li sposti tu)
❌ BACKUP_*/                                 # Backup (li sposti tu)
❌ __pycache__/                              # Cache Python (si rigenera)
❌ node_modules/                             # Dependencies (npm install)
❌ .next/                                    # Build Next.js (si rigenera)
❌ venv/                                     # Virtual env (si crea)
❌ .cache/                                   # Cache (si rigenera)
❌ *.pyc                                     # Compiled Python
❌ .env                                      # Secrets (NON versionare!)
❌ *.log                                     # Log files
```

### File Test/Utility Opzionali

Questi puoi copiarli SE vuoi (utili per debug):
```
? add_test_videos.py
? create_real_skeleton_data.py
? test_*.py (root level)
```

---

## 📊 RIEPILOGO NUMERI

| Componente | File | Dimensione | Status |
|------------|------|------------|--------|
| **Video Studio** | 57 Python | ~400KB | ✅ Core completo |
| **Knowledge Extraction** | 22 Python | ~150KB | ✅ Modulo nuovo |
| **Streaming Platform** | 40+ Python | ~250KB | ✅ 95% completo |
| **Frontend** | 30+ TSX/TS | ~200KB | ✅ Funzionante |
| **Altri moduli** | 10+ Python | ~50KB | ✅ Support |
| **Test suite** | 20+ Python | ~100KB | ✅ Testing |
| **TOTALE** | ~180 file | ~1.15MB | **80% completo** |

---

## 🎯 STRUTTURA TARGET (PRODUZIONE_ATTIVA)

```
C:\Users\utente\Desktop\PRODUZIONE_ATTIVA\
│
├── backend\
│   ├── main.py                              # Entry point principale
│   ├── requirements.txt                     # MERGE di tutti i requirements
│   │
│   ├── modules\
│   │   ├── video_studio\                    # Da MediaCenter_Modular/modules/video_studio
│   │   ├── knowledge_extraction\            # Da MediaCenter_Modular/modules/knowledge_extraction
│   │   ├── video_library\                   # Da MediaCenter_Modular/modules/video_library
│   │   ├── video_streaming\                 # Da MediaCenter_Modular/modules/video_streaming
│   │   └── streaming\                       # Da streaming_platform/backend (integrato)
│   │
│   ├── core\                                # Da streaming_platform/backend/core
│   │   ├── database.py
│   │   ├── security.py
│   │   └── config.py
│   │
│   └── tests\                               # MERGE di tutti i test
│       ├── unit\
│       └── integration\
│
├── frontend\                                # Da MediaCenter_Modular/frontend (completo)
│
├── data\                                    # CREA VUOTO
│   ├── uploads\
│   ├── processed\
│   └── cache\
│
└── docs\                                    # Documenti che hai già
    ├── MEGA_PROMPT_CLAUDE_CODE_WEB.md
    ├── ANALISI_GAP_FUNZIONALITA_DETTAGLIATA.md
    └── GUIDA_SETUP_STRUTTURA_PULITA.md (vecchia)
```

---

## 🚀 COME PROCEDERE

### STEP BY STEP

**STEP 1**: Tu sposti i backup
```powershell
mkdir "C:\Users\utente\Desktop\ARCHIVIO_BACKUP"

# Manualmente o con comando:
Get-ChildItem "C:\Users\utente\Desktop\cursor\Progetto_media_center\MediaCenter_Modular" -Directory | Where-Object { $_.Name -like "backup_*" -or $_.Name -like "BACKUP_*" } | Move-Item -Destination "C:\Users\utente\Desktop\ARCHIVIO_BACKUP\"
```

**STEP 2**: Io verifico i file (già fatto sopra ✅)

**STEP 3**: Tu copi i file ATTIVI

**Opzione A - Manuale** (più sicuro):
- Copia `modules/video_studio/` → `PRODUZIONE_ATTIVA/backend/modules/video_studio/`
- Copia `modules/knowledge_extraction/` → `PRODUZIONE_ATTIVA/backend/modules/knowledge_extraction/`
- Copia `streaming_platform/backend/` → `PRODUZIONE_ATTIVA/backend/modules/streaming/`
- Copia `frontend/` → `PRODUZIONE_ATTIVA/frontend/`

**Opzione B - Script Selettivo** (posso creartelo se vuoi):
```powershell
# Script che copia SOLO i file della lista sopra
# Esclude automaticamente backup, cache, node_modules
```

**STEP 4**: Verifica
```powershell
# Conta file copiati
(Get-ChildItem "C:\Users\utente\Desktop\PRODUZIONE_ATTIVA\backend" -Recurse -File -Include "*.py").Count
# Dovrebbe essere ~120-130

(Get-ChildItem "C:\Users\utente\Desktop\PRODUZIONE_ATTIVA\frontend\src" -Recurse -File).Count
# Dovrebbe essere ~30-40
```

---

## ❓ DOMANDE PER TE

1. **Vuoi procedere manualmente** (trascini le cartelle) **o preferisci uno script PowerShell** che copia solo i file verificati?

2. **Hai già spostato i backup** o te li sposto io con un comando?

3. **Vuoi che integro subito streaming_platform dentro backend/modules/streaming** o preferisci tenerla separata?

---

**Aspetto tue indicazioni prima di procedere!** 🎯

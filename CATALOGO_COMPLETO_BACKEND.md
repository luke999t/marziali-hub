# CATALOGO COMPLETO BACKEND
## Media Center Arti Marziali

**Data analisi**: 2025-12-13
**Analizzato da**: Claude Opus 4.5

---

## RIEPILOGO CONTEGGI

| Area | File | Righe Stimate |
|------|------|---------------|
| Services | 87 | ~25.000 |
| API v1 | 22 | ~8.000 |
| Models | 12 | ~3.000 |
| Modules | 10 | ~2.500 |
| Core | 7 | ~1.500 |
| Tests | 66 | ~15.000 |
| Root scripts | 20 | ~2.000 |
| **TOTALE** | **224** | **~57.000** |

---

## 1. KNOWLEDGE ENRICHMENT SERVICES (Priorità)

### 1.1 temp_zone_manager.py
```
RIGHE: 1153
STATUS: ✅ COMPLETO
TESTS: 29 passed

CLASSI:
- BatchStatus (Enum): PROCESSING, COMPLETED, FAILED, EXPIRED, ARCHIVED
- BatchType (Enum): BILINGUAL_BOOK, MANGA_PROCESSING, DVD_EXTRACTION, etc.
- TempBatch (dataclass): id, batch_type, created_at, status, size_bytes
- TempZoneConfig (dataclass): auto_cleanup, retention, limits, security
- AuditEntry (dataclass): timestamp, action, target_id, user_id
- TempZoneManager: Singleton, async, GDPR compliant

METODI PRINCIPALI:
- create_batch()
- complete_batch()
- fail_batch()
- delete_batch()
- get_stats()
- update_config()
- get_audit_log()

FEATURES:
✅ Privacy by Design (GDPR)
✅ Audit trail completo
✅ Auto-cleanup configurabile
✅ Secure delete (overwrite)
✅ Singleton + factory testing
```

### 1.2 bilingual_book_processor.py
```
RIGHE: 824
STATUS: ✅ COMPLETO
TESTS: 42 passed

CLASSI:
- ProcessingStatus (Enum)
- ColumnLayout (Enum): LEFT_RIGHT, RIGHT_LEFT, TOP_BOTTOM, INTERLEAVED
- LanguagePair (Enum): JA_IT, JA_EN, ZH_IT, ZH_EN, EN_IT, KO_IT
- SentencePair (dataclass)
- PageContent (dataclass)
- BookProcessingResult (dataclass)
- ProcessingOptions (dataclass)
- BilingualBookProcessor

METODI PRINCIPALI:
- process_pdf() - Entry point
- _extract_page_content()
- _split_columns()
- _align_sentences()
- export_to_json()
- export_to_csv()
- export_to_tmx()

DIPENDENZE OPZIONALI:
- PyPDF2, pytesseract, PIL, NLTK, pdf2image

EXPORT: JSON, CSV, TMX
```

### 1.3 ideogram_database.py
```
RIGHE: 1542
STATUS: ✅ COMPLETO
TESTS: 51 passed

FEATURES:
- SQLite con FTS5 full-text search
- 214 Kangxi radicals con meanings
- CRUD ideograms, readings, radicals
- Search by character, reading, meaning, radical, stroke count
- JLPT/HSK level filtering
- Mnemonic system con voting
- Import da KANJIDIC2
```

### 1.4 grammar_merger.py
```
RIGHE: 1203
STATUS: ✅ COMPLETO
TESTS: 43 passed

FEATURES:
- Aggregazione regole grammaticali da più fonti
- Fuzzy similarity con SequenceMatcher
- Auto-deduplicazione configurabile
- Rule merging con version history
- Export: Anki TSV, JSON, TMX
```

### 1.5 manga_bilingual_processor.py
```
RIGHE: 892
STATUS: ✅ COMPLETO
TESTS: 48 passed

FEATURES:
- Speech bubble detection (OpenCV contours)
- OCR integration (tesseract)
- Reading order sorting (right-to-left manga)
- Dialogue alignment by position/order
- Export: JSON, Anki, TMX
```

### 1.6 dual_video_alignment.py
```
RIGHE: 1064
STATUS: ✅ COMPLETO
TESTS: 79 passed

FEATURES:
- Scene detection (frame difference)
- Audio fingerprinting (librosa MFCC)
- Subtitle parsing (SRT, ASS)
- Offset calculation (scene, audio, subtitle, combined)
- Quality scoring (EXCELLENT, GOOD, FAIR, POOR, FAILED)
- Export: JSON, Anki TSV, TMX
```

---

## 2. SERVICES VIDEO STUDIO

### 2.1 video_studio/ (54 files)
```
SOTTOCARTELLE/FILE PRINCIPALI:

CORE:
- ingest_orchestrator.py - Orchestrazione ingest video
- pose_detection.py - Rilevamento pose MediaPipe
- skeleton_extraction_holistic.py - Estrazione skeleton
- technique_extractor.py - Estrazione tecniche
- motion_analyzer.py - Analisi movimento

TRANSLATION:
- hybrid_translator.py - Traduzione ibrida
- translation_engine.py - Engine traduzione
- translation_manager.py - Manager traduzioni
- translation_memory.py - Memoria traduzione
- translation_debate.py - Debate system

AI/KNOWLEDGE:
- ai_conversational_agent.py - Agente conversazionale
- knowledge_extractor.py - Estrazione knowledge
- knowledge_base_manager.py - Manager knowledge base
- chroma_retriever.py - ChromaDB retriever

EDITING/ANNOTATION:
- skeleton_editor_api.py - API editor skeleton
- annotation_system.py - Sistema annotazioni
- annotation_manager.py - Manager annotazioni
- frame_level_annotator.py - Annotatore frame

VOICE/AUDIO:
- voice_cloning.py - Clonazione voce

DATABASE/INFRA:
- db_models.py - Modelli DB
- database.py - Connessione DB
- celery_tasks.py - Task Celery
- websocket_manager.py - WebSocket
- cache_manager.py - Cache
```

---

## 3. SERVICES LIVE TRANSLATION

### 3.1 live_translation/ (9 files)
```
- __init__.py
- google_speech_service.py - Google Speech-to-Text
- google_translation_service.py - Google Translate
- nllb_service.py - Meta NLLB
- whisper_service.py - OpenAI Whisper
- protocols.py - Protocolli interfacce
- service_factory.py - Factory servizi
- translation_manager.py - Manager traduzione live
- translation_memory.py - Memoria traduzione
```

---

## 4. SERVICES CURRICULUM

### 4.1 curriculum/ (3 files)
```
- __init__.py
- exam_analyzer.py - Analisi esami
- access_manager.py - Gestione accessi
```

---

## 5. ALTRI SERVICES

```
- anonymizer.py - Anonimizzazione dati
- llm_debate.py - Sistema debate LLM
- pdf_processor.py - Processamento PDF
- blender_export.py - Export Blender
- avatar_import.py - Import avatar
- dvd_processor.py - Processamento DVD
```

---

## 6. API ENDPOINTS (api/v1/)

### 6.1 Lista completa (22 files)
```
FILE                    DESCRIZIONE
----                    -----------
__init__.py            Package init
admin.py               Endpoint admin
admin_continued.py     Admin estesi
ads.py                 Gestione pubblicità
asd.py                 ASD endpoints
auth.py                Autenticazione
blockchain.py          Blockchain/NFT
communication.py       Messaggistica
curriculum.py          Curriculum/percorsi
ingest_projects.py     Progetti ingest
library.py             Libreria video
live.py                Live streaming
live_translation.py    Traduzione live
maestro.py             Dashboard maestro
moderation.py          Moderazione video
payments.py            Pagamenti Stripe
schemas.py             Pydantic schemas base
schemas_ingest.py      Schemas ingest
subscriptions.py       Abbonamenti
temp_zone.py           Temp zone API
users.py               Gestione utenti
videos.py              Video CRUD
```

---

## 7. MODELS (12 files)

```
FILE                ENTITÀ
----                ------
__init__.py        Package
user.py            User, UserRole, Profile
video.py           Video, VideoCategory, Skeleton
payment.py         Payment, Subscription, Invoice
curriculum.py      Curriculum, Level, Progress
communication.py   Message, Conversation, Notification
ads.py             Ad, AdCampaign, Impression
maestro.py         Maestro, School, Certification
donation.py        Donation
live_minor.py      LiveStream, LiveSession
user_video.py      UserVideoProgress, Favorite
ingest_project.py  IngestProject, IngestBatch, IngestAsset
```

---

## 8. MODULES (10 files)

### 8.1 auth/
```
- __init__.py
- auth_service.py - Servizio autenticazione JWT
```

### 8.2 ads/
```
- __init__.py
- ads_service.py - Servizio gestione ads
- pause_ad_service.py - Ads durante pausa
```

### 8.3 blockchain/
```
- __init__.py
- blockchain_service.py - NFT/blockchain
```

### 8.4 video_moderation/
```
- __init__.py
- validation.py - Validazione video
```

---

## 9. CORE (7 files)

```
FILE                FUNZIONE
----                --------
__init__.py        Package
database.py        SQLAlchemy setup, engine
security.py        JWT, password hashing
cache.py           Redis cache
email.py           Email SMTP/SendGrid
stripe_config.py   Stripe payments config
sentry_config.py   Sentry error tracking
```

---

## 10. TESTS (66 files)

### 10.1 Struttura tests/
```
tests/
├── unit/              (18 files)
├── integration/       (12 files)
├── regression/        (5 files)
├── stress/            (5 files)
├── security/          (5 files)
├── performance/       (2 files)
├── slow/              (1 file)
├── system/            (2 files)
├── e2e/               (2 files)
└── root tests         (14 files)

KNOWLEDGE ENRICHMENT TESTS:
- test_temp_zone_api.py
- test_temp_zone_service.py
- test_bilingual_book_processor.py
- test_ideogram_database.py
- test_grammar_merger.py
- test_manga_bilingual_processor.py
- test_dual_video_alignment.py
```

---

## 11. ROOT SCRIPTS (20 files)

```
SETUP/INIT:
- main.py               FastAPI app entry point
- init_database.py      Initialize DB
- seed_database.py      Seed test data

USER SETUP:
- create_test_users.py
- create_test_users_via_api.py
- setup_admin_simple.py
- setup_asd_profile.py
- setup_maestro_profile.py
- setup_test_users_roles.py
- setup_test_users_roles_simple.py
- reset_test_passwords.py
- check_passwords.py

TESTING:
- run_tests.py
- validate_code.py
- test_api_detailed.py
- test_api_endpoints.py
- test_auth_quick.py
- test_endpoints_debug.py
- test_login.py
- test_routing_fix.py
```

---

## 12. MIDDLEWARE (2 files)

```
- __init__.py
- compression.py - Gzip compression middleware
```

---

## 13. SCRIPTS (1 file)

```
- backup_db.py - Database backup utility
```

---

## PROBLEMI TROVATI

### TODO/FIXME
```
(Da analizzare in dettaglio - grep su tutti i file)
```

### File Potenzialmente Deprecati
```
- test_* in root (dovrebbero essere in tests/)
- setup_*_simple.py (duplicati?)
```

### Placeholder/Stub
```
- bilingual_book_processor._ocr_page() - Placeholder per OCR
```

---

## METRICHE

| Metrica | Valore |
|---------|--------|
| File Python totali | 224 |
| Righe stimate | ~57.000 |
| Test files | 66 |
| Test KE passed | 292 |
| Coverage KE | ~90%+ |
| API endpoints | 22 router files |
| Models | 12 |

---

*Catalogo generato il 2025-12-13*

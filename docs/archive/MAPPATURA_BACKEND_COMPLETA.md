# MAPPATURA BACKEND COMPLETA

**Data**: 2025-12-13
**Path**: C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

---

## STRUTTURA DIRECTORY

```
backend/
├── api/
│   └── v1/                    # 22 file API
├── core/                      # Config, security, database
├── models/                    # SQLAlchemy models
├── modules/
│   ├── auth/
│   └── video_moderation/
├── services/
│   ├── audio_system/          # 7 file - NUOVO
│   ├── curriculum/
│   ├── live_translation/      # 8 file
│   ├── staff_contribution/    # 7 file - NUOVO
│   └── video_studio/          # ~55 file
├── tests/
│   ├── e2e/
│   ├── integration/
│   ├── performance/
│   ├── regression/
│   ├── security/
│   ├── slow/
│   ├── stress/
│   ├── system/
│   └── unit/
├── main.py                    # 250 righe - Entry point
└── requirements.txt           # 87 righe - Dipendenze
```

---

## SERVICES - MAPPATURA COMPLETA

### 1. audio_system/ (4,642 righe)

#### __init__.py (100 righe)
- Package exports
- Version: 1.0.0

#### audio_manager.py (717 righe)
- **Classe**: AudioManager (Singleton/Facade)
- **Dataclass**: AudioSystemConfig, AudioGenerationResult
- **Metodi principali**:
  - generate_tts() - Genera TTS
  - clone_voice() - Clona voce con XTTS
  - apply_style() - Applica effetti audio
  - get_pronunciation() - Ottieni pronuncia termine
  - generate_tutorial_audio() - Genera audio tutorial completo

#### audio_storage.py (758 righe)
- **Enum**: AudioFormat, AudioCategory
- **Dataclass**: AudioMetadata, StorageConfig, StorageStats
- **Classe**: AudioStorage (Singleton)
- **Features**: Dedup SHA256, cleanup automatico, secure delete

#### pronunciation_db.py (934 righe)
- **Enum**: LanguageCode (9 lingue), MartialArtStyle (10 stili), TermCategory
- **Dataclass**: PronunciationEntry, PronunciationStats
- **Classe**: PronunciationDB (Singleton)
- **Database**: SQLite con FTS5
- **Features**: Import/export JSON/CSV, sistema voting, seed termini base

#### tts_generator.py (773 righe)
- **Enum**: TTSEngine (EDGE, COQUI, PYTTSX3, AUTO)
- **Dataclass**: TTSVoice, TTSRequest, TTSResult
- **Classi**:
  - TTSEngineBase (Abstract)
  - EdgeTTSEngine
  - CoquiTTSEngine
  - Pyttsx3Engine
  - TTSGenerator
- **Pattern**: Strategy con fallback automatico

#### voice_cloner.py (696 righe)
- **Dataclass**: VoiceProfile, VoiceCloningResult, ReferenceValidation
- **Classe**: VoiceCloner
- **Engine**: XTTS v2 (Coqui)
- **Features**: Zero-shot cloning, profile management, batch cloning

#### voice_styler.py (664 righe)
- **Enum**: StylePreset (11 preset)
- **Dataclass**: AudioStyle, StyleResult
- **Classe**: VoiceStyler
- **Library**: Pedalboard (Spotify)
- **Preset**: DOJO_REVERB, CLEAR_VOICE, WARM_NARRATOR, etc.

---

### 2. staff_contribution/ (4,177 righe)

#### __init__.py (113 righe)
- Package exports
- Version: 1.0.0

#### schemas.py (459 righe)
- **Enum**:
  - StaffRole (ADMIN, MODERATOR, TRANSLATOR, REVIEWER, CONTRIBUTOR, VIEWER)
  - Permission (24 permessi granulari)
  - ContributionType (10 tipi)
  - ContributionStatus (8 stati)
  - ReviewStatus (4 stati)
  - AuditAction (23 azioni)
- **Dataclass**: StaffMember, Contribution, ContributionVersion, ReviewComment, AuditEntry, ReviewRequest
- **Costanti**: ROLE_HIERARCHY, VALID_STATUS_TRANSITIONS

#### rbac.py (575 righe)
- **Dataclass**: RolePermissions
- **Classe**: RBAC
- **Costanti**: DEFAULT_ROLE_PERMISSIONS, ROLE_HIERARCHY
- **Features**: Cache permessi, check gerarchia, permessi custom

#### audit_log.py (661 righe)
- **Classe**: AuditLog (Singleton)
- **Database**: SQLite append-only
- **Features**: Hash chain SHA256 per immutabilita, export JSON/CSV

#### versioning.py (631 righe)
- **Dataclass**: VersionDiff
- **Classe**: VersionControl (Singleton)
- **Pattern**: Copy-on-write
- **Features**: Diff tra versioni, restore, merge a 3 vie

#### review_workflow.py (784 righe)
- **Enum**: ReviewDecision
- **Classe**: ReviewWorkflow (Singleton)
- **Features**: SLA tracking, callbacks hooks, commenti inline

#### contribution_manager.py (954 righe)
- **Classe**: ContributionManager (Singleton/Facade)
- **Coordina**: RBAC, AuditLog, VersionControl, ReviewWorkflow
- **Sezioni**: Staff Management, Contributions, Workflow, Access Control, Queries

---

### 3. video_studio/ (~55 file, ~25,000+ righe)

#### Core Files
| File | Righe | Descrizione |
|------|-------|-------------|
| main.py | ~200 | FastAPI entry point studio |
| database.py | ~150 | SQLAlchemy setup |
| db_models.py | ~300 | ORM models |
| models.py | ~200 | Pydantic schemas |
| auth.py | ~100 | JWT authentication |

#### Processing
| File | Descrizione |
|------|-------------|
| ingest_orchestrator.py | Orchestrazione ingest video |
| workflow_orchestrator.py | Workflow processing |
| batch_processor.py | Batch video processing |
| massive_video_processor.py | Processing massivo |

#### Skeleton & Pose
| File | Descrizione |
|------|-------------|
| pose_detection.py | MediaPipe pose detection |
| skeleton_extraction_holistic.py | Holistic extraction |
| skeleton_converter.py | Formato skeleton |
| skeleton_editor_api.py | API editing skeleton |
| realtime_pose_corrector.py | Correzione real-time |

#### Translation
| File | Descrizione |
|------|-------------|
| translation_engine.py | Engine traduzione |
| translation_manager.py | Manager traduzioni |
| translation_memory.py | Translation memory |
| translation_correction_system.py | Sistema correzioni |
| hybrid_translator.py | Traduttore ibrido |
| translation_debate.py | LLM debate traduzioni |

#### Knowledge
| File | Descrizione |
|------|-------------|
| knowledge_extractor.py | Estrazione knowledge |
| knowledge_base_manager.py | Manager KB |
| knowledge_sandbox.py | Sandbox testing |
| chroma_retriever.py | ChromaDB retrieval |

#### Analysis
| File | Descrizione |
|------|-------------|
| motion_analyzer.py | Analisi movimento |
| technique_extractor.py | Estrazione tecniche |
| comparison_engine.py | Confronto video |
| style_classifier.py | Classificazione stile |
| grammar_extractor.py | Estrazione grammatica |

#### AI
| File | Descrizione |
|------|-------------|
| ai_conversational_agent.py | Agente conversazionale |
| llm_config.py | Config LLM (Ollama) |
| martial_arts_patterns.py | Pattern arti marziali |

#### Other
| File | Descrizione |
|------|-------------|
| voice_cloning.py | Voice cloning |
| annotation_system.py | Sistema annotazioni |
| annotation_manager.py | Manager annotazioni |
| frame_level_annotator.py | Annotazione frame |
| glossary_service.py | Servizio glossario |
| second_person_converter.py | Conversione persona |
| cache_manager.py | Cache management |
| websocket_manager.py | WebSocket manager |
| advanced_analytics.py | Analytics avanzate |
| upload_api.py | API upload |

---

### 4. live_translation/ (8 file, ~2,500 righe)

| File | Righe | Descrizione |
|------|-------|-------------|
| __init__.py | ~50 | Package init |
| protocols.py | ~100 | Interface definitions |
| service_factory.py | ~150 | Factory pattern |
| whisper_service.py | ~400 | Faster-Whisper STT |
| nllb_service.py | ~350 | NLLB translation |
| google_speech_service.py | ~300 | Google Cloud STT |
| google_translation_service.py | ~300 | Google Translate |
| translation_manager.py | ~400 | Manager orchestrazione |
| translation_memory.py | ~300 | TM storage |

---

### 5. curriculum/ (~10 file, ~3,000 righe)

Gestione curriculum formativi con:
- Livelli progressione (cinture)
- Esami e certificazioni
- AI feedback
- Tracking progresso studenti

---

## API ENDPOINTS COMPLETI

### Registrati in main.py (17 routers)

```python
# Core routers
auth      -> /api/v1/auth
users     -> /api/v1/users
videos    -> /api/v1/videos
maestro   -> /api/v1/maestro

# Business routers
subscriptions  -> /api/v1/subscriptions
payments       -> /api/v1/payments
ads            -> /api/v1/ads
library        -> /api/v1

# Feature routers
communication    -> /api/v1/communication
moderation       -> /api/v1/moderation
curriculum       -> /api/v1/curriculum (in api file)
ingest_projects  -> /api/v1/ingest
temp_zone        -> /api/v1/admin/temp-zone
live_translation -> /api/v1/live-translation

# Admin routers
admin      -> /api/v1/admin
asd        -> /api/v1/asd
blockchain -> /api/v1/blockchain
live       -> /api/v1/live
```

### File API piu grandi

| File | Bytes | Endpoints principali |
|------|-------|---------------------|
| curriculum.py | 58KB | CRUD curriculum, levels, exams, AI feedback |
| ingest_projects.py | 51KB | Projects, batches, mix, DVD import, Blender |
| videos.py | 32KB | CRUD videos, upload, streaming, search |
| payments.py | 30KB | Stripe, stelline, subscriptions, PPV |
| admin.py | 23KB | User management, stats, config |
| communication.py | 19KB | Messages, threads, WebSocket chat |

---

## MODELS DATABASE

### File models/ principali

| File | Tabelle | Descrizione |
|------|---------|-------------|
| user.py | users | Utenti con ruoli |
| video.py | videos | Video con metadata |
| user_video.py | user_videos | Progress, saved, history |
| maestro.py | maestros | Profili maestri |
| payment.py | payments, subscriptions | Pagamenti Stripe |
| donation.py | donations | Donazioni |
| communication.py | messages, threads | Messaggistica |
| ads.py | pause_ads, sponsor_ads | Sistema pubblicitario |
| live_minor.py | minors, parent_approvals | Gestione minori |
| curriculum.py | curricula, levels, enrollments, exams | Curriculum formativi |
| ingest_project.py | ingest_projects, batches, assets, mix_versions | Ingest studio |

---

## CORE FILES

| File | Descrizione |
|------|-------------|
| core/database.py | SQLAlchemy async setup |
| core/security.py | JWT, password hashing |
| core/email.py | Email service |
| core/cache.py | Redis cache |
| core/sentry_config.py | Sentry integration |
| core/stripe_config.py | Stripe configuration |

---

## TEST STRUCTURE

### Directory test/

```
tests/
├── conftest.py           # Fixtures ZERO MOCK
├── e2e/
│   └── test_skeleton_workflow.py
├── integration/
│   ├── test_communication_api.py
│   ├── test_curriculum_api.py
│   ├── test_grammar_extractor_integration.py
│   ├── test_ingest_skeleton_api.py
│   ├── test_library_integration.py
│   ├── test_moderation_api.py
│   ├── test_pause_ad_api.py
│   ├── test_payments_integration.py
│   ├── test_translation_debate_integration.py
│   ├── test_translation_pipeline.py
│   ├── test_users_api.py
│   └── test_videos_api.py
├── performance/
│   ├── test_auth_performance.py
│   └── test_payment_performance.py
├── regression/
│   ├── test_auth_regression.py
│   ├── test_known_bugs.py
│   ├── test_library_regression.py
│   └── test_payment_regression.py
├── security/
│   ├── test_auth_security.py
│   ├── test_payment_security.py
│   ├── test_privacy_leaks.py
│   └── test_translation_security.py
├── slow/
│   └── test_performance.py
├── stress/
│   ├── test_auth_stress.py
│   ├── test_ingest_stress.py
│   ├── test_library_stress.py
│   └── test_payment_stress.py
├── system/
│   ├── test_end_to_end.py
│   └── test_translation_system.py
└── unit/
    ├── test_ads_service.py
    ├── test_audio_system.py           # 56 test
    ├── test_auth_email.py
    ├── test_blockchain_service.py
    ├── test_dictionaries.py
    ├── test_grammar_extractor.py
    ├── test_library.py
    ├── test_llm_config.py
    ├── test_models_extended.py
    ├── test_pause_ad_service.py
    ├── test_payment_logic.py
    ├── test_security.py
    ├── test_skeleton_extraction.py
    ├── test_staff_contribution.py     # 51 test
    ├── test_translation_debate.py
    ├── test_translation_engine.py
    ├── test_translation_memory.py
    └── test_video_moderation_validation.py
```

### Test Knowledge Enrichment

| File | Test | Status |
|------|------|--------|
| test_temp_zone_service.py | 29 | PASSED |
| test_bilingual_book_processor.py | 42 | PASSED |
| test_ideogram_database.py | 51 | PASSED |
| test_grammar_merger.py | 43 | PASSED |
| test_manga_bilingual_processor.py | 48 | PASSED |
| test_dual_video_alignment.py | 79 | PASSED |
| test_audio_system.py | 54 | PASSED (2 skipped) |
| test_staff_contribution.py | 51 | PASSED |

**TOTALE**: ~400+ test ZERO MOCK

---

*Mappatura generata automaticamente - 2025-12-13*

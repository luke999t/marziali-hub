# MAPPATURA COMPLETA PROGETTO MEDIA CENTER ARTI MARZIALI

**Data**: 10 Gennaio 2025
**PATH**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali`
**Versione**: 1.0

---

## INDICE

1. [Panoramica Progetto](#panoramica-progetto)
2. [Statistiche Generali](#statistiche-generali)
3. [Backend Python/FastAPI](#backend-pythonfastapi)
4. [Frontend React/Next.js](#frontend-reactnextjs)
5. [Flutter App](#flutter-app)
6. [Mobile React Native](#mobile-react-native)
7. [Infrastruttura](#infrastruttura)
8. [Livello di Sviluppo per Modulo](#livello-di-sviluppo-per-modulo)

---

## PANORAMICA PROGETTO

### Descrizione
Media Center Arti Marziali e' una piattaforma streaming/e-learning dedicata alle arti marziali con funzionalita' avanzate:
- Streaming video con traduzione real-time
- Analisi movimento con skeleton tracking 3D
- Sistema curriculum per maestri e studenti
- Supporto occhiali AR per pratica
- Sistema royalties blockchain
- AI Coach conversazionale

### Stack Tecnologico
| Componente | Tecnologia | Versione |
|------------|------------|----------|
| Backend | Python FastAPI | 3.11+ |
| Database | PostgreSQL | 15+ |
| Cache | Redis | 7+ |
| Frontend Web | Next.js 14 + React 18 | Latest |
| Mobile Flutter | Flutter/Dart | 3.x |
| Mobile RN | React Native/Expo | SDK 49+ |
| Container | Docker + Docker Compose | Latest |
| Payments | Stripe | API v2023 |
| Monitoring | Sentry | Latest |
| AI/ML | OpenAI, Whisper, MediaPipe | Various |

---

## STATISTICHE GENERALI

### Conteggio Codice Sorgente

| Stack | File | Righe Codice | Righe Test |
|-------|------|--------------|------------|
| Backend Python | 304 | 62.028 | 38.319 |
| Frontend Next.js | 159 | 33.368 | ~5.000 |
| Flutter/Dart | 121 | 24.013 | 10.038 |
| Mobile React Native | 23 | 8.757 | 3.600 |
| Documentazione | 61 | ~35.000 | - |
| **TOTALE** | **~690** | **~166.000** | **~57.000** |

### GRAND TOTAL: ~223.000 righe di codice

---

## BACKEND PYTHON/FASTAPI

**Path**: `/backend`
**Righe totali**: 62.028
**File Python**: 304

### Struttura Cartelle

```
/backend
├── main.py                 (315 righe) - Entry point FastAPI
├── requirements.txt        (86 righe)  - Dipendenze Python
├── /api/v1                 (26 file, 16.173 righe) - Endpoint REST
├── /core                   (7 file, 1.717 righe)   - Configurazioni core
├── /models                 (12 file, 4.799 righe)  - Modelli SQLAlchemy
├── /modules                (25 file, 10.418 righe) - Moduli business
├── /services               (105 file, ~35.000 righe) - Servizi
├── /middleware             (2 file) - Middleware
└── /tests                  (84 file, 38.319 righe) - Test suite
```

---

### /backend/core - CONFIGURAZIONI CORE

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `database.py` | 89 | Engine SQLAlchemy async, gestione connessioni PostgreSQL, session factory | COMPLETO |
| `security.py` | 289 | JWT authentication, password hashing con bcrypt, decoratori protezione endpoint | COMPLETO |
| `email.py` | 638 | Servizio invio email SMTP, template HTML, verifica email, reset password | COMPLETO |
| `cache.py` | 81 | Cache Redis, decoratore cache_response per endpoint | COMPLETO |
| `stripe_config.py` | 371 | Configurazione Stripe, checkout session, webhook handler, subscription management | COMPLETO |
| `sentry_config.py` | 246 | Inizializzazione Sentry, error tracking, performance monitoring | COMPLETO |

---

### /backend/api/v1 - ENDPOINT REST API

| File | Righe | Cosa Fa | Endpoint | Livello |
|------|-------|---------|----------|---------|
| `auth.py` | 428 | Login, registrazione, refresh token, logout, verifica email | `/auth/*` | COMPLETO |
| `users.py` | 27 | CRUD utenti base | `/users/*` | BASE |
| `admin.py` | 796 | Dashboard admin, statistiche, gestione utenti, moderazione | `/admin/*` | COMPLETO |
| `admin_continued.py` | 458 | Funzionalita' admin estese, report, export dati | `/admin/*` | COMPLETO |
| `videos.py` | 1206 | CRUD video, upload, streaming, metadata, ricerca | `/videos/*` | COMPLETO |
| `curriculum.py` | 1794 | Gestione curriculum, livelli, esami, certificazioni, inviti | `/curriculum/*` | COMPLETO |
| `payments.py` | 874 | Checkout Stripe, webhook, abbonamenti, fatture | `/payments/*` | COMPLETO |
| `ads.py` | 436 | Gestione pubblicita', pause ads, sponsor ads, analytics | `/ads/*` | COMPLETO |
| `library.py` | 379 | Libreria personale utente, preferiti, cronologia | `/library/*` | COMPLETO |
| `live.py` | 281 | Streaming live, sessioni, chat | `/live/*` | PARZIALE |
| `live_translation.py` | 371 | Traduzione real-time audio/video, WebSocket | `/translation/*` | COMPLETO |
| `glasses_ws.py` | 507 | WebSocket per occhiali AR, sync movimento, comandi | `/glasses/ws` | COMPLETO |
| `maestro.py` | 511 | Profilo maestro, upload contenuti, studenti | `/maestro/*` | COMPLETO |
| `moderation.py` | 523 | Moderazione contenuti, segnalazioni, ban | `/moderation/*` | COMPLETO |
| `communication.py` | 593 | Messaggi, notifiche, thread conversazioni | `/communication/*` | COMPLETO |
| `contributions.py` | 1086 | Contributi staff, revisioni, versioning | `/contributions/*` | COMPLETO |
| `ingest_projects.py` | 1551 | Upload massivo video, processing pipeline, DVD import | `/ingest/*` | COMPLETO |
| `video_studio.py` | 714 | Editor video, annotazioni, confronto tecniche | `/studio/*` | COMPLETO |
| `audio.py` | 937 | TTS, voice cloning, audio processing | `/audio/*` | COMPLETO |
| `blockchain.py` | 167 | Tracking royalties su blockchain | `/blockchain/*` | PARZIALE |
| `asd.py` | 605 | Gestione ASD (Associazioni Sportive) | `/asd/*` | COMPLETO |
| `temp_zone.py` | 577 | Zona temporanea upload, elaborazione | `/temp-zone/*` | COMPLETO |
| `subscriptions.py` | 48 | Abbonamenti base | `/subscriptions/*` | BASE |

---

### /backend/models - MODELLI DATABASE

| File | Righe | Cosa Fa | Tabelle Principali | Livello |
|------|-------|---------|-------------------|---------|
| `user.py` | 300 | Modello utente con ruoli, preferenze, profilo | `users`, `user_roles` | COMPLETO |
| `video.py` | 474 | Video con metadata, traduzioni, skeleton | `videos`, `video_metadata`, `video_translations` | COMPLETO |
| `curriculum.py` | 1148 | Curriculum, livelli, requisiti, iscrizioni, esami | `curricula`, `levels`, `enrollments`, `exam_submissions` | COMPLETO |
| `payment.py` | 272 | Pagamenti, transazioni, subscription | `payments`, `subscriptions` | COMPLETO |
| `ads.py` | 519 | Pubblicita', impressions, clicks | `ads`, `pause_ads`, `sponsor_ads`, `ad_impressions` | COMPLETO |
| `maestro.py` | 325 | Profilo maestro, credenziali, specializzazioni | `maestros`, `maestro_credentials` | COMPLETO |
| `communication.py` | 380 | Messaggi, thread, notifiche | `messages`, `threads`, `notifications` | COMPLETO |
| `donation.py` | 392 | Donazioni, campagne | `donations`, `donation_campaigns` | COMPLETO |
| `ingest_project.py` | 355 | Progetti ingest, task processing | `ingest_projects`, `ingest_tasks` | COMPLETO |
| `live_minor.py` | 254 | Streaming live, sessioni | `live_streams`, `live_sessions` | PARZIALE |

---

### /backend/modules - MODULI BUSINESS

#### /modules/royalties (7 file, 4.318 righe) - SISTEMA ROYALTIES

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `models.py` | 735 | Modelli: RoyaltyConfig, RoyaltyTransaction, RoyaltyPayout | COMPLETO |
| `service.py` | 980 | Calcolo royalties, distribuzione, payout automatici | COMPLETO |
| `router.py` | 627 | API endpoints royalties | COMPLETO |
| `schemas.py` | 610 | Schemi Pydantic request/response | COMPLETO |
| `config.py` | 460 | Configurazione percentuali, regole distribuzione | COMPLETO |
| `blockchain_tracker.py` | 811 | Tracking transazioni su blockchain, verifica integrita' | PARZIALE |

**Descrizione Modulo**: Sistema completo per gestione royalties dei contenuti. Calcola automaticamente le percentuali dovute a maestri/creatori basandosi su views, durata, subscription revenue. Supporta payout automatici via Stripe e tracking opzionale su blockchain.

**Livello Sviluppo**: 90% - Manca integrazione blockchain completa

---

#### /modules/special_projects (8 file, 3.166 righe) - PROGETTI SPECIALI

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `models.py` | 390 | Modelli: SpecialProject, ProjectParticipation, Milestone | COMPLETO |
| `service.py` | 528 | Gestione ciclo vita progetto, partecipazioni | COMPLETO |
| `router.py` | 611 | API endpoints progetti speciali | COMPLETO |
| `eligibility.py` | 433 | Verifica eleggibilita' utenti per progetti | COMPLETO |
| `analytics.py` | 473 | Analytics e metriche progetti | COMPLETO |
| `schemas.py` | 383 | Schemi Pydantic | COMPLETO |
| `config.py` | 267 | Configurazione progetti | COMPLETO |

**Descrizione Modulo**: Gestisce progetti speciali come documentari, eventi, collaborazioni. Include sistema di milestone, partecipazione con requisiti, e analytics dedicati.

**Livello Sviluppo**: 95% - Completo

---

#### /modules/video_moderation (2 file, 258 righe) - MODERAZIONE VIDEO

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `validation.py` | 251 | Validazione contenuti, check copyright, content policy | COMPLETO |

**Descrizione Modulo**: Validazione automatica contenuti video prima della pubblicazione. Verifica policy, potenziali violazioni copyright, contenuti inappropriati.

**Livello Sviluppo**: 85% - Manca AI content detection avanzata

---

#### /modules/ads (3 file, 1.373 righe) - SISTEMA PUBBLICITA'

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `ads_service.py` | 589 | Gestione campagne pubblicitarie, targeting | COMPLETO |
| `pause_ad_service.py` | 759 | Pause ads durante video, overlay, skip logic | COMPLETO |

**Descrizione Modulo**: Sistema pubblicitario con pause ads (mostrati quando utente mette in pausa), sponsor ads, e targeting basato su interessi/demografia.

**Livello Sviluppo**: 95% - Completo

---

#### /modules/auth (2 file, 411 righe) - AUTENTICAZIONE

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `auth_service.py` | 407 | Login, registrazione, JWT, refresh token, OAuth | COMPLETO |

**Descrizione Modulo**: Autenticazione completa con JWT, refresh token, verifica email, reset password. Supporta OAuth per login social.

**Livello Sviluppo**: 100% - Completo

---

#### /modules/blockchain (2 file, 891 righe) - BLOCKCHAIN

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `blockchain_service.py` | 868 | Interazione blockchain, smart contract, NFT | PARZIALE |

**Descrizione Modulo**: Integrazione blockchain per certificazione contenuti, NFT per certificati, tracking royalties immutabile.

**Livello Sviluppo**: 40% - Struttura presente, integrazione da completare

---

### /backend/services - SERVIZI APPLICATIVI

#### /services/video_studio (65 file, 33.474 righe) - STUDIO VIDEO

**Descrizione**: Suite completa per editing, analisi e processing video arti marziali.

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `video_studio_api.py` | 1357 | API principale studio, orchestrazione | COMPLETO |
| `knowledge_extractor.py` | 1385 | Estrazione conoscenza da video (tecniche, movimenti) | COMPLETO |
| `translation_engine.py` | 1125 | Motore traduzione multilingua | COMPLETO |
| `hybrid_translator.py` | 1107 | Traduttore ibrido (ML + regole) | COMPLETO |
| `workflow_orchestrator.py` | 1044 | Orchestrazione pipeline processing | COMPLETO |
| `grammar_extractor.py` | 1041 | Estrazione pattern grammaticali da sottotitoli | COMPLETO |
| `ingest_orchestrator.py` | 1025 | Orchestrazione ingest massivo | COMPLETO |
| `realtime_pose_corrector.py` | 1020 | Correzione pose in tempo reale | COMPLETO |
| `multi_video_fusion.py` | 988 | Fusione multiple angolazioni video | COMPLETO |
| `technique_image_generator.py` | 974 | Generazione immagini statiche da tecniche | COMPLETO |
| `ai_conversational_agent.py` | 1083 | Agente AI conversazionale per domande | COMPLETO |
| `translation_debate.py` | 930 | Debate tra LLM per traduzione ottimale | COMPLETO |
| `comparison_engine.py` | 910 | Confronto tecniche tra video | COMPLETO |
| `glossary_service.py` | 949 | Gestione glossario termini arti marziali | COMPLETO |
| `annotation_system.py` | 875 | Sistema annotazioni frame-by-frame | COMPLETO |
| `project_manager.py` | 863 | Gestione progetti video studio | COMPLETO |
| `motion_analyzer.py` | 858 | Analisi movimento con MediaPipe | COMPLETO |
| `upload_api.py` | 843 | API upload con chunking | COMPLETO |
| `martial_arts_patterns.py` | 795 | Database pattern arti marziali | COMPLETO |
| `skeleton_extraction_holistic.py` | 508 | Estrazione skeleton 3D da video | COMPLETO |
| `pose_detection.py` | 285 | Detection pose con MediaPipe | COMPLETO |
| `skeleton_converter.py` | 302 | Conversione formati skeleton | COMPLETO |
| `skeleton_editor_api.py` | 432 | API editor skeleton | COMPLETO |
| `voice_cloning.py` | 484 | Clonazione voce per doppiaggio | PARZIALE |
| `mix_generator.py` | 682 | Generatore mix audio/video | COMPLETO |
| `style_classifier.py` | 566 | Classificatore stili arti marziali | COMPLETO |
| `chroma_retriever.py` | 465 | Retrieval semantico con ChromaDB | COMPLETO |
| `websocket_manager.py` | 228 | Gestione WebSocket real-time | COMPLETO |

**Livello Sviluppo Modulo**: 92% - Quasi completo, voice cloning da affinare

---

#### /services/audio_system (7 file, 4.635 righe) - SISTEMA AUDIO

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `audio_manager.py` | 716 | Gestione audio, mixing, normalizzazione | COMPLETO |
| `pronunciation_db.py` | 933 | Database pronunce termini arti marziali | COMPLETO |
| `audio_storage.py` | 757 | Storage e streaming audio | COMPLETO |
| `tts_generator.py` | 772 | Text-to-Speech multilingua | COMPLETO |
| `voice_cloner.py` | 695 | Clonazione voce maestri | PARZIALE |
| `voice_styler.py` | 663 | Stile e tono voce | PARZIALE |

**Descrizione**: Sistema audio completo per TTS, voice cloning, gestione pronunce corrette termini giapponesi/cinesi/coreani.

**Livello Sviluppo**: 80% - TTS completo, voice cloning da affinare

---

#### /services/live_translation (8 file, 2.364 righe) - TRADUZIONE LIVE

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `translation_manager.py` | 257 | Manager traduzione real-time | COMPLETO |
| `whisper_service.py` | 323 | Speech-to-text con Whisper | COMPLETO |
| `google_speech_service.py` | 234 | Speech-to-text Google | COMPLETO |
| `google_translation_service.py` | 249 | Traduzione Google Translate | COMPLETO |
| `nllb_service.py` | 456 | Traduzione con NLLB (Meta) | COMPLETO |
| `translation_memory.py` | 454 | Memoria traduzione per consistenza | COMPLETO |
| `service_factory.py` | 235 | Factory per provider traduzione | COMPLETO |
| `protocols.py` | 152 | Protocolli interfacce | COMPLETO |

**Descrizione**: Sistema traduzione real-time per streaming live. Supporta multiple provider (Google, Whisper, NLLB), con memoria traduzione per consistenza terminologica.

**Livello Sviluppo**: 95% - Completo

---

#### /services/staff_contribution (7 file, 4.170 righe) - CONTRIBUTI STAFF

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `contribution_manager.py` | 953 | Gestione contributi collaborativi | COMPLETO |
| `review_workflow.py` | 783 | Workflow revisione contributi | COMPLETO |
| `audit_log.py` | 660 | Log audit modifiche | COMPLETO |
| `versioning.py` | 630 | Versionamento contenuti | COMPLETO |
| `rbac.py` | 574 | Role-Based Access Control | COMPLETO |
| `schemas.py` | 458 | Schemi dati | COMPLETO |

**Descrizione**: Sistema per contributi collaborativi dello staff (traduttori, moderatori, editor). Include workflow di revisione, versionamento, e RBAC granulare.

**Livello Sviluppo**: 95% - Completo

---

#### /services/curriculum (3 file, 1.764 righe) - CURRICULUM

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `access_manager.py` | 836 | Gestione accessi contenuti per livello | COMPLETO |
| `exam_analyzer.py` | 905 | Analisi esami video con AI | COMPLETO |

**Descrizione**: Gestione accessi contenuti basato su livello curriculum, analisi automatica esami video con feedback AI.

**Livello Sviluppo**: 90% - Completo

---

#### Altri Servizi Importanti

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `ideogram_database.py` | 1542 | Database ideogrammi CJK con pronunce | COMPLETO |
| `grammar_merger.py` | 1203 | Merge pattern grammaticali | COMPLETO |
| `temp_zone_manager.py` | 1152 | Gestione zona temporanea elaborazione | COMPLETO |
| `dual_video_alignment.py` | 1064 | Allineamento video dual-camera | COMPLETO |
| `manga_bilingual_processor.py` | 892 | Processore manga bilingue | COMPLETO |
| `bilingual_book_processor.py` | 824 | Processore libri bilingue | COMPLETO |
| `dvd_processor.py` | 585 | Import e processing DVD | COMPLETO |
| `pdf_processor.py` | 482 | Estrazione contenuti da PDF | COMPLETO |
| `blender_export.py` | 557 | Export skeleton per Blender | COMPLETO |
| `anonymizer.py` | 435 | Anonimizzazione dati GDPR | COMPLETO |

---

### /backend/tests - TEST SUITE

| Categoria | File | Righe | Copertura |
|-----------|------|-------|-----------|
| Unit Tests | 22 | ~7.500 | Modelli, servizi, utilities |
| Integration Tests | 16 | ~5.200 | API endpoints |
| Security Tests | 5 | ~1.800 | Auth, injection, CSRF |
| Performance Tests | 3 | ~900 | Response time, load |
| Stress Tests | 5 | ~1.500 | Concurrent users, memory |
| Regression Tests | 5 | ~1.200 | Bug fix verification |
| System/E2E Tests | 3 | ~1.100 | Full workflow |
| Real DB Tests | 2 | ~1.500 | Test con database reale |

**Coverage Target**: 90%
**Coverage Attuale Stimato**: ~85%

---

## FRONTEND REACT/NEXT.JS

**Path**: `/frontend`
**Righe totali**: 33.368
**File TS/TSX**: 159

### Struttura Cartelle

```
/frontend
├── src/
│   ├── app/                 (50 file, 16.021 righe) - Pages App Router
│   ├── components/          (18 file, 5.333 righe)  - Componenti React
│   ├── contexts/            (3 file, 956 righe)     - Context providers
│   ├── hooks/               (13 file, 2.505 righe)  - Custom hooks
│   ├── services/            (3 file, 1.726 righe)   - API services
│   ├── types/               (3 file, 1.312 righe)   - TypeScript types
│   ├── lib/                 (5 file, 469 righe)     - Utilities
│   ├── locales/             (2 file)                - i18n JSON
│   └── __tests__/           (65 file, ~5.000 righe) - Test suite
├── public/                  - Static assets
├── cypress/                 - E2E tests Cypress
└── e2e/                     - E2E tests Playwright
```

---

### /frontend/src/app - PAGINE NEXT.JS

#### Autenticazione e Onboarding

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `login/page.tsx` | 166 | Form login con validazione | COMPLETO |
| `register/page.tsx` | 261 | Registrazione multi-step | COMPLETO |
| `onboarding/page.tsx` | 259 | Onboarding nuovo utente, preferenze | COMPLETO |

#### Home e Landing

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `page.tsx` | 265 | Homepage con contenuti personalizzati | COMPLETO |
| `landing/page.tsx` | 336 | Landing page marketing | COMPLETO |

#### Sistema Curriculum

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `curriculum/page.tsx` | 264 | Lista curriculum disponibili | COMPLETO |
| `curriculum/[id]/page.tsx` | 340 | Dettaglio curriculum con livelli | COMPLETO |
| `curriculum/[id]/learn/page.tsx` | 398 | Interfaccia apprendimento | COMPLETO |
| `my-learning/page.tsx` | 403 | I miei corsi, progresso | COMPLETO |
| `manage/curricula/page.tsx` | 313 | Gestione curricula (maestro) | COMPLETO |
| `manage/curricula/[id]/page.tsx` | 652 | Dettaglio gestione curriculum | COMPLETO |
| `manage/curricula/[id]/students/page.tsx` | 659 | Gestione studenti iscritti | COMPLETO |
| `manage/exams/page.tsx` | 565 | Gestione esami da valutare | COMPLETO |

#### Video Studio e Skeleton

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `skeleton-editor/page.tsx` | 1714 | Editor skeleton 3D completo | COMPLETO |
| `skeleton-viewer/page.tsx` | 723 | Visualizzatore skeleton 3D | COMPLETO |
| `skeletons/page.tsx` | 309 | Lista skeleton salvati | COMPLETO |
| `skeleton-library/page.tsx` | 571 | Libreria skeleton pubblici | COMPLETO |

#### Ingest e Upload

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `ingest-studio/page.tsx` | 538 | Studio ingest completo | COMPLETO |
| `ingest-studio/components/DvdImportTab.tsx` | 706 | Import da DVD | COMPLETO |
| `ingest-studio/components/MixPanel.tsx` | 255 | Pannello mix audio/video | COMPLETO |
| `upload/page.tsx` | 157 | Upload video semplice | COMPLETO |
| `maestro/upload/page.tsx` | 520 | Upload contenuti maestro | COMPLETO |

#### Admin

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `admin/page.tsx` | 262 | Dashboard admin | COMPLETO |
| `admin/analytics/page.tsx` | 262 | Analytics piattaforma | COMPLETO |
| `admin/moderation/page.tsx` | 539 | Moderazione contenuti | COMPLETO |
| `admin/users/page.tsx` | 330 | Gestione utenti | COMPLETO |

#### Altri

| Pagina | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `live-player/page.tsx` | 217 | Player streaming live | PARZIALE |
| `translation/page.tsx` | 352 | Interfaccia traduzione | COMPLETO |
| `chat/page.tsx` | 90 | Chat con AI Coach | COMPLETO |
| `donations/page.tsx` | 382 | Pagina donazioni | COMPLETO |
| `special-projects/page.tsx` | 543 | Progetti speciali | COMPLETO |
| `monitor/page.tsx` | 354 | Monitor sistema | COMPLETO |

---

### /frontend/src/components - COMPONENTI REACT

#### Componenti Curriculum

| Componente | Righe | Cosa Fa | Livello |
|------------|-------|---------|---------|
| `InviteCodeGenerator.tsx` | 464 | Genera codici invito per studenti | COMPLETO |
| `ExamSubmissionModal.tsx` | 417 | Modal upload esame video | COMPLETO |
| `AIFeedbackPanel.tsx` | 401 | Pannello feedback AI su esame | COMPLETO |
| `CertificateCard.tsx` | 301 | Card certificato conseguito | COMPLETO |
| `RequirementsList.tsx` | 286 | Lista requisiti livello | COMPLETO |
| `LevelCard.tsx` | 280 | Card livello curriculum | COMPLETO |
| `CurriculumCard.tsx` | 278 | Card curriculum | COMPLETO |
| `LevelProgressBar.tsx` | 208 | Barra progresso livello | COMPLETO |
| `BeltBadge.tsx` | 178 | Badge cintura colorata | COMPLETO |

#### Componenti Video/3D

| Componente | Righe | Cosa Fa | Livello |
|------------|-------|---------|---------|
| `SkeletonViewer3D.tsx` | 429 | Viewer skeleton 3D con Three.js | COMPLETO |
| `SkeletonEditor3D.tsx` | 376 | Editor skeleton 3D | COMPLETO |
| `LiveSubtitles.tsx` | 287 | Sottotitoli live streaming | COMPLETO |

#### Altri Componenti

| Componente | Righe | Cosa Fa | Livello |
|------------|-------|---------|---------|
| `MessageThread.tsx` | 192 | Thread messaggi | COMPLETO |
| `ConversationList.tsx` | 131 | Lista conversazioni | COMPLETO |
| `LanguageSwitcher.tsx` | 118 | Cambio lingua UI | COMPLETO |
| `LazyVideo.tsx` | 72 | Video con lazy loading | COMPLETO |

---

### /frontend/src/hooks - CUSTOM HOOKS

| Hook | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `useIngestProjects.ts` | 613 | Gestione progetti ingest, upload, progress | COMPLETO |
| `useLiveSubtitles.ts` | 267 | WebSocket sottotitoli live | COMPLETO |
| `useExamSubmission.ts` | 301 | Submit esame, upload video | COMPLETO |
| `useAIFeedback.ts` | 280 | Richiesta feedback AI | COMPLETO |
| `useLevelProgress.ts` | 255 | Tracking progresso livello | COMPLETO |
| `useMyCurricula.ts` | 248 | Curricula utente corrente | COMPLETO |
| `useCurricula.ts` | 199 | Lista curricula | COMPLETO |
| `useAnalytics.ts` | 153 | Tracking analytics | COMPLETO |
| `useCurriculum.ts` | 148 | Singolo curriculum | COMPLETO |

---

### /frontend/src/services - API SERVICES

| Service | Righe | Cosa Fa | Livello |
|---------|-------|---------|---------|
| `curriculumApi.ts` | 920 | Tutte le API curriculum | COMPLETO |
| `ingestApi.ts` | 483 | API ingest progetti | COMPLETO |
| `adsApi.ts` | 323 | API pubblicita' | COMPLETO |

---

### /frontend - TEST

| Categoria | File | Cosa Testa |
|-----------|------|------------|
| Unit | 11 | Componenti, hooks |
| Integration | 8 | Flussi completi |
| Holistic | 6 | User journey |
| Security | 9 | XSS, CSRF, auth bypass |
| Performance | 4 | Render, FCP, TTI |
| Stress | 6 | Concurrent users, memory |
| Chaos | 5 | Network failure, timeout |
| Static | 6 | Bundle, a11y, deps |

---

## FLUTTER APP

**Path**: `/flutter_app`
**Righe lib**: 24.013
**Righe test**: 10.038
**File Dart**: 121 (lib) + 29 (test)

### Architettura

L'app segue **Clean Architecture** con:
- **Presentation Layer**: BLoC pattern, UI widgets
- **Domain Layer**: Entities, repositories interface, use cases
- **Data Layer**: Models, datasources, repository implementations

### Struttura Cartelle

```
/flutter_app/lib
├── core/
│   ├── config/          - Router, constants
│   ├── di/              - Dependency Injection (GetIt)
│   ├── error/           - Exceptions, Failures
│   ├── network/         - API client, connectivity
│   ├── theme/           - App theme
│   └── utils/           - Utilities
├── features/
│   ├── ads/             - Sistema pubblicita'
│   ├── auth/            - Autenticazione
│   ├── downloads/       - Download offline
│   ├── glasses/         - Controllo occhiali AR
│   ├── home/            - Home page
│   ├── library/         - Libreria personale
│   ├── live/            - Streaming live
│   ├── notifications/   - Notifiche push
│   ├── onboarding/      - Onboarding
│   ├── player/          - Video player
│   ├── profile/         - Profilo utente
│   ├── search/          - Ricerca
│   └── settings/        - Impostazioni
└── services/
    └── glasses_service.dart
```

---

### /flutter_app/lib/core - CORE

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `app_router.dart` | 333 | Routing con GoRouter, guards | COMPLETO |
| `api_client.dart` | 325 | Client HTTP Dio, interceptors | COMPLETO |
| `injection.dart` | 271 | Dependency Injection GetIt | COMPLETO |
| `app_theme.dart` | 462 | Tema Material Design 3 | COMPLETO |
| `exceptions.dart` | 75 | Eccezioni custom | COMPLETO |
| `failures.dart` | 70 | Failures per Either | COMPLETO |

---

### /flutter_app/lib/features - FEATURES

#### Feature: Player Video (7 file, 3.431 righe)

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `player_page.dart` | 598 | Pagina player completa | COMPLETO |
| `subtitles_overlay.dart` | 749 | Overlay sottotitoli multilingua sincronizzati | COMPLETO |
| `skeleton_overlay.dart` | 692 | Overlay skeleton 3D sovrapposto a video | COMPLETO |
| `player_settings_sheet.dart` | 581 | Bottom sheet impostazioni (qualita', velocita', sottotitoli) | COMPLETO |
| `player_controls.dart` | 527 | Controlli playback custom | COMPLETO |
| `player_bloc.dart` | 194 | State management player | COMPLETO |

**Descrizione**: Player video avanzato con sottotitoli multilingua sincronizzati, overlay skeleton 3D per confronto pose, controlli avanzati.

**Livello Sviluppo**: 95% - Completo

---

#### Feature: Glasses AR (1 file, 955 righe)

| File | Righe | Cosa Fa | Livello |
|------|-------|---------|---------|
| `glasses_control_panel.dart` | 955 | Pannello controllo occhiali AR | COMPLETO |

**Descrizione**: Interfaccia controllo occhiali AR per pratica. Sincronizza video, mostra overlay, feedback real-time.

**Livello Sviluppo**: 90% - Funzionale, da testare su device reali

---

#### Feature: Auth (14 file, 2.158 righe)

| Layer | Cosa Fa | Livello |
|-------|---------|---------|
| Data | Datasources locale/remoto, models, repository impl | COMPLETO |
| Domain | User entity, auth repository interface, use cases | COMPLETO |
| Presentation | Auth BLoC, Login/Register/Splash pages | COMPLETO |

**Descrizione**: Autenticazione completa con JWT, refresh token, persistenza locale sicura.

**Livello Sviluppo**: 100% - Completo

---

#### Feature: Ads (17 file, 1.993 righe)

| Layer | Cosa Fa | Livello |
|-------|---------|---------|
| Data | Datasources, models pause/sponsor ads | COMPLETO |
| Domain | Entities, repository, use cases | COMPLETO |
| Presentation | Pause ad BLoC, overlay widget | COMPLETO |

**Descrizione**: Sistema pause ads - mostra pubblicita' quando utente mette in pausa video.

**Livello Sviluppo**: 95% - Completo

---

#### Feature: Library (15 file, 2.028 righe)

| Cosa Fa | Livello |
|---------|---------|
| Libreria personale con preferiti, cronologia, watch later | COMPLETO |
| Cache locale per accesso offline | COMPLETO |
| Sync con backend | COMPLETO |

**Livello Sviluppo**: 95% - Completo

---

#### Feature: Live (10 file, 1.761 righe)

| Cosa Fa | Livello |
|---------|---------|
| Streaming live con chat | PARZIALE |
| Traduzione real-time sottotitoli | COMPLETO |
| Notifiche live in arrivo | COMPLETO |

**Livello Sviluppo**: 75% - Streaming base ok, chat da completare

---

#### Feature: Downloads (6 file, 1.058 righe)

| Cosa Fa | Livello |
|---------|---------|
| Download video per visione offline | COMPLETO |
| Gestione spazio storage | COMPLETO |
| Sync progress offline | COMPLETO |

**Livello Sviluppo**: 90% - Completo

---

#### Feature: Settings (12 file, 1.789 righe)

| Cosa Fa | Livello |
|---------|---------|
| Impostazioni app complete | COMPLETO |
| Qualita' video default | COMPLETO |
| Lingua UI e sottotitoli | COMPLETO |
| Notifiche preferences | COMPLETO |

**Livello Sviluppo**: 95% - Completo

---

#### Altre Features

| Feature | File | Righe | Livello |
|---------|------|-------|---------|
| Home | 6 | 1.870 | COMPLETO |
| Notifications | 10 | 1.486 | COMPLETO |
| Profile | 8 | 1.380 | COMPLETO |
| Search | 5 | 844 | COMPLETO |
| Onboarding | 3 | 444 | COMPLETO |

---

### /flutter_app - TEST

| Categoria | File | Righe | Cosa Testa |
|-----------|------|-------|------------|
| Unit (real) | 5 | 2.357 | Services con backend reale |
| Integration | 2 | 728 | Flussi auth, glasses |
| E2E | 1 | 471 | Glasses end-to-end |
| Holistic | 2 | 764 | User journey completi |
| Security | 2 | 702 | Auth security, glasses security |
| Performance | 2 | 633 | API response, glasses latency |
| Stress | 2 | 573 | Concurrent, glasses stress |
| Regression | 1 | 440 | Glasses regression |
| Penetration | 1 | 569 | Security penetration |
| Audit | 1 | 472 | Glasses audit |

---

## MOBILE REACT NATIVE

**Path**: `/mobile`
**Righe src**: 8.757
**Righe test**: 3.600
**Framework**: React Native + Expo

### Struttura

```
/mobile
├── src/
│   ├── screens/        (12 file, 5.473 righe)
│   ├── components/     (2 file, 1.376 righe)
│   ├── services/       (5 file, 1.532 righe)
│   ├── contexts/       (2 file, 251 righe)
│   ├── hooks/          (2 file, 241 righe)
│   └── navigation/     (1 file, 169 righe)
├── __tests__/          (9 file)
└── test/e2e/           (7 file)
```

---

### /mobile/src/screens

| Screen | Righe | Cosa Fa | Livello |
|--------|-------|---------|---------|
| `SearchScreen.tsx` | 687 | Ricerca video con filtri | COMPLETO |
| `TechniquePlayerScreen.tsx` | 677 | Player tecnica con skeleton | COMPLETO |
| `ProfileScreen.tsx` | 587 | Profilo utente, settings | COMPLETO |
| `GlassesPlayerScreen.tsx` | 520 | Player per occhiali AR | COMPLETO |
| `LibraryScreen.tsx` | 506 | Libreria personale | COMPLETO |
| `RegisterScreen.tsx` | 503 | Registrazione | COMPLETO |
| `LiveStreamScreen.tsx` | 423 | Streaming live | PARZIALE |
| `AICoachScreen.tsx` | 416 | Chat AI Coach | COMPLETO |
| `HomeScreen.tsx` | 343 | Home con contenuti | COMPLETO |
| `OfflineVideosScreen.tsx` | 262 | Video scaricati offline | COMPLETO |
| `LoginScreen.tsx` | 264 | Login | COMPLETO |

---

### /mobile/src/components

| Component | Righe | Cosa Fa | Livello |
|-----------|-------|---------|---------|
| `GlassesControlPanel.tsx` | 784 | Controllo occhiali AR | COMPLETO |
| `PauseAdOverlay.tsx` | 592 | Overlay pubblicita' pausa | COMPLETO |

---

### /mobile/src/services

| Service | Righe | Cosa Fa | Livello |
|---------|-------|---------|---------|
| `glassesService.ts` | 547 | Comunicazione occhiali AR | COMPLETO |
| `adsService.ts` | 323 | Gestione pubblicita' | COMPLETO |
| `offlineStorage.ts` | 245 | Storage offline AsyncStorage | COMPLETO |
| `api.ts` | 210 | Client API Axios | COMPLETO |
| `notifications.ts` | 207 | Push notifications Expo | COMPLETO |

---

## INFRASTRUTTURA

### /nginx (4 file, 495 righe)

| File | Righe | Cosa Fa |
|------|-------|---------|
| `conf.d/martial-arts.conf` | 278 | Proxy config principale, SSL, cache |
| `conf.d/default.conf` | 106 | Config default |
| `nginx.prod.conf` | 58 | Config produzione |
| `nginx.conf` | 53 | Config base |

### /.github/workflows (2 file, 446 righe)

| File | Righe | Cosa Fa |
|------|-------|---------|
| `deploy-production.yml` | 310 | Deploy automatico prod (Docker, SSH) |
| `ci.yml` | 136 | CI: lint, test, build |

### Docker

| File | Righe | Cosa Fa |
|------|-------|---------|
| `docker-compose.yml` | 125 | Sviluppo locale |
| `docker-compose.prod.yml` | 309 | Produzione |

### /scripts (2 file, 1.011 righe)

| File | Righe | Cosa Fa |
|------|-------|---------|
| `health_check.py` | 591 | Health check completo sistema |
| `setup_windows.ps1` | 420 | Setup ambiente Windows |

---

## LIVELLO DI SVILUPPO PER MODULO

### LEGENDA

| Livello | Significato | % |
|---------|-------------|---|
| COMPLETO | Funzionalita' complete, testato, production-ready | 95-100% |
| QUASI COMPLETO | Funzionalita' principali ok, dettagli minori mancanti | 85-94% |
| PARZIALE | Funzionalita' base ok, feature avanzate mancanti | 50-84% |
| BASE | Struttura presente, implementazione minima | 20-49% |
| STUB | Solo interfacce/placeholder | 0-19% |

---

### BACKEND - RIEPILOGO LIVELLI

| Modulo | Livello | % | Note |
|--------|---------|---|------|
| **Core (auth, db, security)** | COMPLETO | 100% | Production ready |
| **API Auth** | COMPLETO | 100% | JWT, OAuth, refresh |
| **API Videos** | COMPLETO | 95% | CRUD, streaming, search |
| **API Curriculum** | COMPLETO | 95% | Completo |
| **API Payments** | COMPLETO | 95% | Stripe integrato |
| **API Ads** | COMPLETO | 95% | Pause ads funzionanti |
| **API Admin** | COMPLETO | 95% | Dashboard completa |
| **API Ingest** | COMPLETO | 90% | Pipeline funzionante |
| **API Live** | PARZIALE | 70% | Streaming base ok |
| **Modulo Royalties** | QUASI COMPLETO | 90% | Manca blockchain full |
| **Modulo Special Projects** | COMPLETO | 95% | Completo |
| **Video Studio Service** | COMPLETO | 92% | Suite completa |
| **Audio System** | QUASI COMPLETO | 80% | Voice cloning da affinare |
| **Live Translation** | COMPLETO | 95% | Multi-provider |
| **Staff Contribution** | COMPLETO | 95% | Workflow completo |
| **Blockchain** | PARZIALE | 40% | Da completare |

**BACKEND TOTALE: ~88%**

---

### FRONTEND - RIEPILOGO LIVELLI

| Area | Livello | % | Note |
|------|---------|---|------|
| **Auth Pages** | COMPLETO | 100% | Login, register, onboarding |
| **Curriculum System** | COMPLETO | 95% | Tutti i flussi |
| **Video Studio/Skeleton** | COMPLETO | 95% | Editor 3D funzionante |
| **Ingest Studio** | COMPLETO | 90% | DVD import, mix |
| **Admin Dashboard** | COMPLETO | 95% | Analytics, moderation |
| **Components** | COMPLETO | 95% | Riutilizzabili |
| **API Services** | COMPLETO | 95% | Type-safe |
| **Test Coverage** | QUASI COMPLETO | 85% | Target 90% |

**FRONTEND TOTALE: ~92%**

---

### FLUTTER - RIEPILOGO LIVELLI

| Feature | Livello | % | Note |
|---------|---------|---|------|
| **Auth** | COMPLETO | 100% | Funzionante |
| **Player** | COMPLETO | 95% | Skeleton overlay ok |
| **Glasses AR** | QUASI COMPLETO | 90% | Da testare su device |
| **Library** | COMPLETO | 95% | Offline sync |
| **Ads** | COMPLETO | 95% | Pause ads |
| **Downloads** | QUASI COMPLETO | 90% | Funzionante |
| **Settings** | COMPLETO | 95% | Completo |
| **Live** | PARZIALE | 75% | Chat da fare |
| **Notifications** | COMPLETO | 95% | Push ok |

**FLUTTER TOTALE: ~90%**

---

### MOBILE RN - RIEPILOGO LIVELLI

| Area | Livello | % | Note |
|------|---------|---|------|
| **Auth Screens** | COMPLETO | 100% | Funzionante |
| **Player/Glasses** | COMPLETO | 95% | AR control ok |
| **Library/Search** | COMPLETO | 95% | Completo |
| **Offline** | QUASI COMPLETO | 90% | Storage ok |
| **Live** | PARZIALE | 70% | Base |
| **AI Coach** | COMPLETO | 95% | Chat funzionante |

**MOBILE TOTALE: ~88%**

---

### INFRASTRUTTURA - RIEPILOGO

| Area | Livello | % | Note |
|------|---------|---|------|
| **Docker Dev** | COMPLETO | 100% | Funzionante |
| **Docker Prod** | COMPLETO | 95% | Pronto |
| **Nginx** | COMPLETO | 95% | SSL, proxy |
| **CI/CD** | COMPLETO | 90% | GitHub Actions |
| **Monitoring** | QUASI COMPLETO | 85% | Sentry integrato |

**INFRA TOTALE: ~93%**

---

## RIEPILOGO FINALE

| Stack | Completamento | Note |
|-------|---------------|------|
| Backend Python | **88%** | Blockchain da completare, live da affinare |
| Frontend Next.js | **92%** | Quasi production-ready |
| Flutter App | **90%** | Test su device AR necessari |
| Mobile RN | **88%** | Live streaming da completare |
| Infrastruttura | **93%** | Pronta per deploy |
| Documentazione | **85%** | Aggiornata |
| Test Coverage | **85%** | Target 90% |

### PROGETTO TOTALE: ~89% COMPLETO

### Prossimi Step Prioritari

1. **Completare integrazione Blockchain** (royalties tracking)
2. **Affinare Live Streaming** (backend + mobile)
3. **Test su device AR reali** (Flutter glasses)
4. **Aumentare test coverage a 90%**
5. **Deploy staging per UAT**

---

*Mappatura generata il 10 Gennaio 2025*
*Totale righe codice: ~223.000*
*File mappati: ~690*

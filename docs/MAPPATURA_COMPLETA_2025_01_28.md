# MAPPATURA COMPLETA PROGETTO
## Media Center Arti Marziali

**Data**: 2025-01-28
**Generata automaticamente**

---

## Backend (~101.117 righe codice sorgente + ~80.577 righe test = ~181.694 righe totali Python, escluso venv)

### /backend/ (root scripts)
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| add_is_featured_column.py | 30 | 1 | Migrazione: aggiunta colonna is_featured |
| add_is_featured_to_model.py | 18 | 0.7 | Aggiornamento model per is_featured |
| add_missing_video_columns.py | 125 | 3.7 | Migrazione: colonne mancanti tabella video |
| check_admin_direct.py | 45 | 1.8 | Verifica diretta utente admin |
| check_column_types.py | 24 | 0.9 | Verifica tipi colonne database |
| check_enums.py | 23 | 0.8 | Verifica enum nel database |
| check_passwords.py | 28 | 1 | Verifica password utenti |
| check_tables.py | 23 | 0.7 | Verifica struttura tabelle |
| check_videos_columns.py | 11 | 0.4 | Verifica colonne tabella video |
| clean_royalties_complete.py | 39 | 1.4 | Pulizia completa tabelle royalties |
| create_admin_temp.py | 46 | 1.9 | Creazione utente admin temporaneo |
| create_royalty_tables.py | 32 | 1.5 | Creazione tabelle royalties |
| create_test_users.py | 505 | 17.1 | Creazione utenti di test |
| create_test_users_via_api.py | 396 | 13.8 | Creazione utenti test via API |
| debug_login.py | 24 | 0.8 | Debug processo di login |
| drop_all_royalty_enums.py | 24 | 0.8 | Drop enum royalties |
| drop_enum_final.py | 27 | 0.8 | Drop enum finale |
| drop_remaining_enums.py | 16 | 0.6 | Drop enum rimanenti |
| drop_royalties_tables.py | 38 | 1.9 | Drop tabelle royalties |
| drop_special_projects.py | 28 | 1.6 | Drop tabelle special projects |
| fix_enum_case.py | 96 | 3.4 | Fix case sensitivity enum PostgreSQL |
| fix_enum_in_model.py | 46 | 2.2 | Fix enum nei modelli |
| fix_event_type.py | 88 | 2.8 | Fix tipo evento |
| fix_maestro_schema.py | 26 | 0.9 | Fix schema maestro |
| fix_maestro_schema_full.py | 56 | 2.3 | Fix completo schema maestro |
| fix_royalties_final.py | 44 | 1.6 | Fix finale royalties |
| force_recreate_tables.py | 43 | 1.6 | Ricreazione forzata tabelle |
| init_database.py | 97 | 3.3 | Inizializzazione database |
| inspect_column.py | 22 | 0.9 | Ispezione colonne database |
| kill_connections.py | 16 | 0.6 | Terminazione connessioni DB |
| list_users.py | 9 | 0.3 | Lista utenti database |
| main.py | 433 | 19.6 | Entry point FastAPI, configurazione CORS, middleware, router |
| recreate_all_tables.py | 58 | 2.8 | Ricreazione tutte le tabelle |
| recreate_special_projects.py | 188 | 8.7 | Ricreazione tabelle special projects |
| reset_test_passwords.py | 33 | 1.2 | Reset password test |
| run_tests.py | 41 | 1.2 | Runner test suite |
| run_test_verification.py | 313 | 11.4 | Verifica esecuzione test |
| seed_database.py | 636 | 26.6 | Seed dati iniziali database |
| seed_test_users_api.py | 133 | 4.5 | Seed utenti test via API |
| setup_admin_simple.py | 88 | 3.6 | Setup admin semplificato |
| setup_asd_profile.py | 209 | 9.5 | Setup profilo ASD |
| setup_maestro_profile.py | 215 | 9.9 | Setup profilo maestro |
| setup_test_data_for_downloads.py | 313 | 13.3 | Setup dati test per download |
| setup_test_users_roles.py | 154 | 5.6 | Setup ruoli utenti test |
| setup_test_users_roles_simple.py | 139 | 5.6 | Setup semplificato ruoli test |
| set_admin_db.py | 20 | 0.8 | Set admin via database |
| set_admin_postgres.py | 28 | 1 | Set admin PostgreSQL |
| set_admin_simple.py | 32 | 1.2 | Set admin semplificato |
| test_admin_endpoint.py | 39 | 1.3 | Test endpoint admin |
| test_api_detailed.py | 696 | 30.5 | Test dettagliato API |
| test_api_endpoints.py | 419 | 19.5 | Test endpoint API |
| test_auth_quick.py | 23 | 0.7 | Test rapido autenticazione |
| test_endpoint.py | 37 | 1.3 | Test singolo endpoint |
| test_endpoints_debug.py | 43 | 1.5 | Debug test endpoint |
| test_login.py | 24 | 0.8 | Test login |
| test_routing_fix.py | 67 | 2.5 | Test fix routing |
| validate_code.py | 141 | 5.1 | Validazione codice sorgente |

### /backend/api/v1/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| admin.py | 756 | 26 | Dashboard admin, gestione utenti, ban, stats sistema |
| admin_continued.py | 377 | 12.9 | Dashboard admin (continuazione), backup, audit |
| ads.py | 607 | 21.2 | Sistema pubblicita, pause ads, sponsor, impressioni |
| ai_coach.py | 786 | 32.4 | AI Coach, analisi tecnica, feedback, conversazione |
| asd.py | 507 | 16.8 | Gestione ASD, profili associazioni sportive |
| audio.py | 806 | 30.1 | Sistema audio, TTS, voice cloning, pronuncia |
| auth.py | 371 | 12.7 | Autenticazione JWT, login, register, refresh token |
| blockchain.py | 164 | 6.3 | Verifica blockchain, certificati immutabili |
| communication.py | 514 | 19.3 | Messaggistica, conversazioni, allegati |
| contributions.py | 950 | 38 | Contributi staff, review, versioning |
| curriculum.py | 1496 | 57 | Gestione curricula, livelli, esami, certificati, progressi |
| downloads.py | 451 | 15.4 | Download offline, limiti, storage, qualita |
| export.py | 684 | 24.9 | Export video, Blender, formati multipli |
| fusion.py | 1130 | 45.6 | Multi-video fusion, progetti, stili, render |
| glasses_ws.py | 407 | 17.1 | WebSocket smart glasses AR |
| ingest_projects.py | 1340 | 49.5 | Ingest video, progetti, batch processing, DVDs |
| library.py | 376 | 12.2 | Libreria personale, preferiti, progresso |
| live.py | 213 | 7.9 | Live streaming, eventi dal vivo |
| live_translation.py | 349 | 14 | Traduzione live, sottotitoli real-time |
| maestro.py | 413 | 14.4 | Profilo maestro, qualifiche, stili |
| moderation.py | 445 | 15.5 | Moderazione video, approvazione, rifiuto |
| notifications.py | 468 | 19.1 | Notifiche push, preferenze, device token |
| payments.py | 715 | 28.9 | Pagamenti Stripe, checkout, stelline, cronologia |
| scheduler.py | 303 | 10.2 | Scheduler admin, job management, trigger |
| schemas.py | 547 | 23 | Schema Pydantic principali |
| schemas_ingest.py | 663 | 21.2 | Schema Pydantic per ingest |
| skeleton.py | 646 | 25.8 | Estrazione skeleton, pose detection, analisi |
| subscriptions.py | 40 | 1.4 | Abbonamenti base |
| temp_zone.py | 493 | 16.1 | Zona temporanea, batch upload, cleanup |
| users.py | 66 | 2.6 | Gestione utenti, profilo |
| videos.py | 1043 | 35.8 | CRUD video, streaming, categorie, tracking view |
| video_studio.py | 586 | 21.9 | Video studio, processing avanzato |
| __init__.py | 1 | 0.1 | Init package |

### /backend/core/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| auth.py | 22 | 0.6 | Dipendenze autenticazione core |
| cache.py | 64 | 2.2 | Sistema cache in-memory |
| database.py | 103 | 3.2 | Configurazione database PostgreSQL, sessioni |
| email.py | 574 | 24.3 | Servizio email, template, invio asincrono |
| helpers.py | 101 | 3.7 | Utility e helper functions |
| security.py | 276 | 10.5 | Hashing password, JWT, token generation |
| sentry_config.py | 203 | 7.3 | Configurazione Sentry monitoring |
| stripe_config.py | 299 | 9.3 | Configurazione Stripe payments |
| __init__.py | 3 | 0.1 | Init package |

### /backend/middleware/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| compression.py | 13 | 0.4 | Middleware compressione response |
| __init__.py | 3 | 0.1 | Init package |

### /backend/migrations/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| create_events_tables.py | 471 | 18.4 | Creazione tabelle eventi completa |
| quick_fix.py | 44 | 2.4 | Fix rapido migrazione |
| run_007_migration.py | 64 | 2.7 | Esecuzione migrazione 007 |
| run_migration.py | 59 | 2.4 | Runner migrazioni generico |

### /backend/models/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| ads.py | 397 | 18.6 | Modello SQLAlchemy pubblicita e pause ads |
| analytics.py | 172 | 7.9 | Modello analytics e statistiche |
| communication.py | 295 | 13.7 | Modello messaggi e conversazioni |
| curriculum.py | 920 | 40.4 | Modello curricula, livelli, esami, progressi |
| donation.py | 303 | 14.6 | Modello donazioni |
| download.py | 242 | 10.5 | Modello download offline |
| ingest_project.py | 285 | 12.5 | Modello progetti ingest |
| live_minor.py | 198 | 9.2 | Modello live streaming e minori |
| maestro.py | 256 | 11.5 | Modello profilo maestro |
| notification.py | 272 | 12.7 | Modello notifiche |
| payment.py | 207 | 10 | Modello pagamenti |
| user.py | 239 | 11.1 | Modello utente con ruoli |
| user_video.py | 46 | 2.1 | Relazione utente-video |
| video.py | 366 | 17.9 | Modello video con categorie |
| __init__.py | 323 | 7.8 | Init e import tutti i modelli |

### /backend/modules/

#### ads/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| ads_service.py | 525 | 20 | Servizio ads: targeting, sessioni, revenue |
| pause_ad_service.py | 628 | 24.6 | Servizio pause ads: gestione durante pausa video |
| __init__.py | 21 | 0.8 | Init modulo ads |

#### auth/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| auth_service.py | 326 | 11.7 | Servizio autenticazione: login, register, token |
| __init__.py | 3 | 0.1 | Init modulo auth |

#### blockchain/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| blockchain_service.py | 713 | 28.7 | Servizio blockchain: hash, verifica integrita |
| __init__.py | 19 | 0.7 | Init modulo blockchain |

#### downloads/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| download_service.py | 783 | 33.6 | Servizio download: limiti, qualita, storage |
| __init__.py | 10 | 0.4 | Init modulo downloads |

#### events/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| config.py | 309 | 12.3 | Configurazione modulo eventi |
| email_service.py | 440 | 17 | Servizio email per eventi: conferme, reminder |
| gdpr_router.py | 328 | 12.6 | Router GDPR: consenso, export dati, cancellazione |
| models.py | 625 | 28.7 | Modelli eventi, iscrizioni, opzioni, lista attesa |
| notifications.py | 950 | 39.3 | Notifiche eventi: push, email, reminder |
| router.py | 760 | 27.4 | Router API eventi: CRUD, iscrizioni, pagamenti |
| schemas.py | 514 | 20.4 | Schema Pydantic eventi |
| service.py | 1358 | 51.2 | Servizio eventi: business logic completa |
| stripe_connect.py | 727 | 29.1 | Integrazione Stripe Connect per eventi |
| __init__.py | 100 | 3.1 | Init modulo eventi con configurazione |

#### notifications/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| notification_service.py | 850 | 30.7 | Servizio notifiche: push, preferenze, batch |
| __init__.py | 6 | 0.2 | Init modulo notifiche |

#### royalties/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| blockchain_tracker.py | 682 | 26.3 | Tracking royalties su blockchain |
| config.py | 383 | 15.4 | Configurazione royalties e percentuali |
| models.py | 590 | 22.8 | Modelli royalties, payout, milestone |
| router.py | 542 | 18.2 | Router API royalties |
| schemas.py | 502 | 16.5 | Schema Pydantic royalties |
| service.py | 836 | 32.5 | Servizio royalties: calcolo, distribuzione |
| __init__.py | 86 | 2.4 | Init modulo royalties |

#### scheduler/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| jobs.py | 404 | 17.1 | Definizione job schedulati |
| scheduler_service.py | 358 | 14.3 | Servizio scheduler: gestione job |
| __init__.py | 42 | 1.2 | Init modulo scheduler |
| jobs/cleanup_downloads.py | 258 | 11.2 | Job pulizia download scaduti |
| jobs/cleanup_sessions.py | 183 | 8.1 | Job pulizia sessioni inattive |
| jobs/daily_analytics.py | 348 | 16.5 | Job analytics giornaliere |
| jobs/database_backup.py | 251 | 10.2 | Job backup database |
| jobs/health_check.py | 297 | 12.7 | Job health check sistema |
| jobs/__init__.py | 107 | 3.6 | Init job package |

#### special_projects/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| analytics.py | 410 | 15.2 | Analytics progetti speciali |
| config.py | 229 | 7.5 | Configurazione progetti speciali |
| eligibility.py | 364 | 14.6 | Verifica eleggibilita partecipanti |
| models.py | 310 | 12.1 | Modelli progetti speciali |
| router.py | 521 | 18.4 | Router API progetti speciali |
| schemas.py | 313 | 11 | Schema Pydantic progetti speciali |
| service.py | 438 | 17 | Servizio progetti speciali |
| __init__.py | 72 | 2.1 | Init modulo special projects |

#### video_moderation/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| validation.py | 180 | 7.4 | Validazione contenuto video |
| __init__.py | 5 | 0.2 | Init modulo moderazione |

### /backend/scripts/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| backup_db.py | 183 | 6.7 | Script backup database PostgreSQL |
| export_openapi.py | 62 | 2.5 | Export schema OpenAPI |
| export_patterns_to_json.py | 252 | 11.2 | Export pattern arti marziali in JSON |
| full_health_check.py | 320 | 12.5 | Health check completo sistema |
| load_test.py | 236 | 9.5 | Test di carico API |
| seed_events.py | 600 | 24.8 | Seed dati eventi |
| seed_test_data_complete.py | 401 | 15.9 | Seed completo dati test |
| setup_test_data.py | 86 | 2.7 | Setup dati test base |
| test_websocket_fusion.py | 200 | 8 | Test WebSocket fusion |

### /backend/services/

#### Root service files
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| anonymizer.py | 350 | 14.8 | Anonimizzazione dati GDPR |
| avatar_import.py | 294 | 11.6 | Import avatar utente |
| bilingual_book_processor.py | 684 | 24.8 | Processore libri bilingue |
| blender_export.py | 469 | 19 | Export per Blender 3D |
| dual_video_alignment.py | 873 | 34.9 | Allineamento dual video per comparazione |
| dvd_processor.py | 491 | 19.4 | Processore DVD import |
| grammar_merger.py | 1015 | 38.4 | Merger grammatiche multilingue |
| ideogram_database.py | 1336 | 50.6 | Database ideogrammi CJK |
| llm_debate.py | 485 | 17.9 | Debate LLM per traduzione |
| manga_bilingual_processor.py | 739 | 27 | Processore manga bilingue |
| pdf_processor.py | 395 | 15.6 | Processore PDF |
| temp_zone_manager.py | 938 | 38.3 | Manager zona temporanea upload |

#### audio_system/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| audio_manager.py | 612 | 23.2 | Manager sistema audio principale |
| audio_storage.py | 628 | 23.7 | Storage file audio |
| pronunciation_db.py | 802 | 31.4 | Database pronuncia arti marziali |
| tts_generator.py | 647 | 23.4 | Generatore Text-to-Speech |
| voice_cloner.py | 589 | 22.3 | Clonazione voce |
| voice_styler.py | 587 | 23.3 | Stilizzazione voce |
| __init__.py | 82 | 2.8 | Init audio system |

#### curriculum/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| access_manager.py | 694 | 26.2 | Gestione accessi curriculum |
| exam_analyzer.py | 750 | 30.9 | Analisi esami AI |
| __init__.py | 18 | 0.7 | Init curriculum service |

#### live_translation/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| google_speech_service.py | 196 | 8 | Servizio Google Speech-to-Text |
| google_translation_service.py | 210 | 8 | Servizio Google Translate |
| nllb_service.py | 400 | 15.5 | Servizio NLLB (Meta translation) |
| protocols.py | 125 | 4 | Protocolli interfacce traduzione |
| service_factory.py | 209 | 8.9 | Factory pattern per servizi traduzione |
| translation_manager.py | 211 | 8.8 | Manager traduzione live |
| translation_memory.py | 374 | 15.7 | Memoria traduzione per consistenza |
| whisper_service.py | 274 | 11.4 | Servizio Whisper ASR |
| __init__.py | 4 | 0.1 | Init live translation |

#### payments/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| stripe_production_check.py | 233 | 9.1 | Verifica configurazione Stripe produzione |
| __init__.py | 7 | 0.3 | Init payments |

#### staff_contribution/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| audit_log.py | 560 | 19.9 | Log audit contributi staff |
| contribution_manager.py | 814 | 31.7 | Manager contributi staff |
| rbac.py | 481 | 18.5 | Role-Based Access Control |
| review_workflow.py | 665 | 24.4 | Workflow revisione contributi |
| schemas.py | 389 | 15.1 | Schema contributi |
| versioning.py | 536 | 19.1 | Versioning contributi |
| __init__.py | 95 | 3.1 | Init staff contribution |

#### video_studio/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| advanced_analytics.py | 183 | 7.9 | Analytics avanzate video |
| ai_conversational_agent.py | 884 | 35.5 | Agente conversazionale AI |
| annotation_manager.py | 384 | 15.2 | Manager annotazioni video |
| annotation_system.py | 719 | 29.9 | Sistema annotazioni frame-by-frame |
| ar_quick_demo.py | 540 | 19.4 | Demo AR rapida |
| auth.py | 51 | 2.4 | Auth video studio |
| batch_processor.py | 244 | 10.3 | Processore batch video |
| cache_manager.py | 83 | 2.9 | Cache manager video studio |
| celery_tasks.py | 44 | 1.5 | Task Celery asincroni |
| chroma_retriever.py | 376 | 16.1 | Retriever ChromaDB per knowledge base |
| comparison_engine.py | 903 | 30.2 | Engine comparazione tecniche |
| comparison_tool.py | 197 | 9.3 | Tool comparazione video |
| create_test_video.py | 119 | 4.8 | Creazione video test |
| database.py | 44 | 1.2 | Database video studio |
| db_models.py | 149 | 7 | Modelli DB video studio |
| frame_level_annotator.py | 419 | 16.1 | Annotatore a livello frame |
| glossary_service.py | 781 | 30.4 | Servizio glossario arti marziali |
| grammar_extractor.py | 847 | 34.9 | Estrattore grammatiche da video |
| hybrid_translator.py | 1051 | 38.5 | Traduttore ibrido multi-engine |
| ingest_orchestrator.py | 996 | 39.8 | Orchestratore ingest video |
| init_db.py | 13 | 0.5 | Init database video studio |
| knowledge_base_gui.py | 300 | 13.7 | GUI knowledge base |
| knowledge_base_manager.py | 459 | 19.4 | Manager knowledge base |
| knowledge_extractor.py | 1167 | 52.7 | Estrattore conoscenza da video |
| knowledge_sandbox.py | 382 | 16.9 | Sandbox knowledge base |
| llm_config.py | 410 | 16.8 | Configurazione LLM |
| main.py | 133 | 4.2 | Entry point video studio |
| manual_test_holistic.py | 257 | 11.2 | Test manuale holistic |
| martial_arts_patterns.py | 722 | 26.9 | Pattern arti marziali per AI |
| massive_video_processor.py | 443 | 18.9 | Processore video massivo |
| migrate_to_db.py | 79 | 4 | Migrazione a database |
| mix_generator.py | 564 | 25.1 | Generatore mix audio |
| models.py | 219 | 7.8 | Modelli video studio |
| motion_analyzer.py | 697 | 31.4 | Analizzatore movimento |
| multi_video_fusion.py | 814 | 35.4 | Fusione multi-video |
| pose_detection.py | 252 | 11.2 | Rilevamento pose MediaPipe |
| project_manager.py | 712 | 27.9 | Manager progetti video |
| realtime_pose_corrector.py | 833 | 32 | Correttore pose real-time |
| second_person_converter.py | 228 | 8.2 | Convertitore seconda persona |
| skeleton_converter.py | 239 | 9.4 | Convertitore skeleton |
| skeleton_editor_api.py | 345 | 13 | API editor skeleton |
| skeleton_extraction_holistic.py | 417 | 15.8 | Estrazione skeleton holistic |
| skeleton_viewer_simple.py | 351 | 12.6 | Viewer skeleton semplificato |
| style_classifier.py | 454 | 20.2 | Classificatore stile arte marziale |
| technique_extractor.py | 746 | 25.7 | Estrattore tecniche da video |
| technique_image_generator.py | 804 | 31.3 | Generatore immagini tecniche |
| test_agent_integration.py | 141 | 5.5 | Test integrazione agente AI |
| test_comparison_api.py | 120 | 5 | Test API comparazione |
| test_comparison_ui.py | 95 | 3.5 | Test UI comparazione |
| test_complete_system.py | 94 | 3.7 | Test sistema completo |
| test_editor_api.py | 115 | 5.4 | Test API editor |
| test_upload_api.py | 205 | 9.1 | Test API upload |
| test_viewer.py | 50 | 2.1 | Test viewer |
| test_web_editor.py | 103 | 4.6 | Test editor web |
| translation_correction_system.py | 486 | 17.4 | Sistema correzione traduzione |
| translation_debate.py | 773 | 30 | Debate traduzione multi-LLM |
| translation_engine.py | 928 | 37.4 | Engine traduzione principale |
| translation_manager.py | 307 | 11.4 | Manager traduzione |
| translation_memory.py | 454 | 17.5 | Memoria traduzione |
| upload_api.py | 691 | 27.2 | API upload video |
| video_studio_api.py | 1335 | 49.4 | API principale video studio |
| voice_cloning.py | 467 | 17 | Clonazione voce per video |
| websocket_manager.py | 186 | 8.7 | Manager WebSocket |
| workflow_orchestrator.py | 1028 | 37.6 | Orchestratore workflow video |
| __init__.py | 77 | 1.9 | Init video studio |

### /backend/tests/ (191 file, ~80.577 righe)

#### Riepilogo per directory test:

| Directory | File | Righe | Descrizione |
|-----------|------|-------|-------------|
| tests/ (root) | 25 | 17.860 | Conftest, test specifici (eventi, royalties, traduzione, ecc.) |
| tests/api/ | 26 | 9.702 | Test unitari API per tutti i router |
| tests/audit/ | 2 | 547 | Test audit trail e compliance |
| tests/e2e/ | 3 | 612 | Test end-to-end journey utente |
| tests/fixtures/ | 4 | 797 | Fixture test (ASD, maestro, video) |
| tests/holistic/ | 2 | 394 | Test holistic user journey |
| tests/integration/ | 35 | 13.064 | Test integrazione API completi |
| tests/modules/ | 16 | 10.057 | Test copertura moduli (ads, auth, blockchain, events, royalties, special_projects, video_moderation) |
| tests/penetration/ | 1 | 224 | Test penetration (skeleton) |
| tests/performance/ | 7 | 1.842 | Test performance (auth, ads, fusion, glasses, payment, skeleton) |
| tests/real/ | 4 | 1.216 | Test reali con dati live |
| tests/regression/ | 8 | 2.221 | Test regressione (auth, payment, critical flows, known bugs) |
| tests/security/ | 12 | 4.621 | Test sicurezza (injection, privacy, auth, download) |
| tests/slow/ | 1 | 362 | Test performance lenti |
| tests/smoke/ | 2 | 242 | Test smoke critical paths |
| tests/stress/ | 11 | 3.280 | Test stress (concurrent, auth, fusion, glasses, ingest, library, payment) |
| tests/system/ | 3 | 1.043 | Test sistema end-to-end |
| tests/unit/ | 23 | 7.393 | Test unitari (modelli, servizi, logica) |

---

## Flutter App (~214.018 righe totali, di cui ~110.117 generate)

### /flutter_app/lib/api/generated/ (Auto-generated API client)

**675 file, ~110.117 righe** - Client API auto-generato da OpenAPI spec

Comprende:
- `lib/src/api/` - 42 file API client (admin, ads, ai_coach, asd, audio, auth, blockchain, communication, contributions, curriculum, downloads, events, export, fusion, gdpr, glasses, ingest, library, live, live_translation, maestro, masters, moderation, notifications, payments, royalties, scheduler, skeleton, special_projects, students, subscriptions, system, temp_zone, tracking, users, videos, video_studio)
- `lib/src/model/` - ~290 file modelli Dart (tutti i DTO)
- `lib/src/auth/` - 5 file autenticazione
- `test/` - ~330 file test generati
- `doc/` - ~240 file documentazione API generata

### /flutter_app/lib/core/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| config/app_router.dart | 461 | 16 | Router GoRouter, navigazione, deep linking |
| di/injection.dart | 692 | 28.2 | Dependency Injection con GetIt |
| error/exceptions.dart | 60 | 2 | Eccezioni personalizzate |
| error/failures.dart | 55 | 1.7 | Classi Failure per error handling |
| network/api_client.dart | 293 | 8.4 | Client HTTP con interceptor |
| network/network_info.dart | 17 | 0.6 | Info connettivita rete |
| offline/connectivity_service.dart | 116 | 4.2 | Servizio monitoring connettivita |
| offline/offline_manager.dart | 198 | 6.8 | Manager modalita offline |
| offline/offline_queue.dart | 236 | 7.7 | Coda operazioni offline |
| offline/offline_storage.dart | 208 | 6.2 | Storage dati offline |
| offline/sync_service.dart | 240 | 7.6 | Servizio sincronizzazione |
| theme/app_theme.dart | 423 | 13.1 | Tema app Material Design 3 |
| utils/bloc_observer.dart | 57 | 1.5 | Observer per debug BLoC |
| widgets/category_tabs.dart | 291 | 9.7 | Widget tabs categorie |
| widgets/top_app_bar.dart | 296 | 9 | Widget top app bar personalizzata |
| widgets/widgets.dart | 6 | 0.3 | Export widgets |

### /flutter_app/lib/features/

#### ads/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| ads.dart | 23 | 1.1 | Export feature ads |
| data/datasources/ads_remote_datasource.dart | 128 | 4 | Datasource remoto ads |
| data/models/pause_ad_model.dart | 70 | 2.4 | Modello pause ad |
| data/models/sponsor_ad_model.dart | 65 | 2.1 | Modello sponsor ad |
| data/models/suggested_video_model.dart | 70 | 2.3 | Modello video suggeriti |
| data/repositories/ads_repository_impl.dart | 108 | 3.7 | Implementazione repository ads |
| domain/entities/pause_ad.dart | 71 | 3 | Entita pause ad |
| domain/entities/sponsor_ad.dart | 51 | 1.6 | Entita sponsor ad |
| domain/entities/suggested_video.dart | 60 | 2 | Entita video suggerito |
| domain/repositories/ads_repository.dart | 61 | 2.3 | Interfaccia repository ads |
| domain/usecases/fetch_pause_ad_usecase.dart | 81 | 2.7 | UseCase fetch pause ad |
| domain/usecases/record_click_usecase.dart | 51 | 1.7 | UseCase registra click |
| domain/usecases/record_impression_usecase.dart | 55 | 1.9 | UseCase registra impression |
| presentation/bloc/pause_ad_bloc.dart | 205 | 7 | BLoC pause ad |
| presentation/bloc/pause_ad_event.dart | 95 | 3.2 | Eventi BLoC pause ad |
| presentation/bloc/pause_ad_state.dart | 92 | 3 | Stati BLoC pause ad |
| presentation/widgets/pause_ad_overlay.dart | 469 | 17.7 | Widget overlay pause ad |

#### auth/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| data/datasources/auth_local_datasource.dart | 92 | 3 | Storage locale token |
| data/datasources/auth_remote_datasource.dart | 230 | 5.9 | API autenticazione |
| data/models/auth_response_model.dart | 65 | 1.9 | Modello risposta auth |
| data/models/user_model.dart | 160 | 4.9 | Modello utente |
| data/repositories/auth_repository_impl.dart | 317 | 10.1 | Implementazione repository auth |
| domain/entities/user.dart | 167 | 4.4 | Entita utente |
| domain/repositories/auth_repository.dart | 57 | 2 | Interfaccia repository auth |
| domain/usecases/login_usecase.dart | 44 | 1.4 | UseCase login |
| domain/usecases/logout_usecase.dart | 10 | 0.3 | UseCase logout |
| domain/usecases/register_usecase.dart | 72 | 2.5 | UseCase registrazione |
| presentation/bloc/auth_bloc.dart | 269 | 8.5 | BLoC autenticazione |
| presentation/pages/login_page.dart | 293 | 12 | Pagina login |
| presentation/pages/register_page.dart | 258 | 11.2 | Pagina registrazione |
| presentation/pages/splash_page.dart | 79 | 2.6 | Pagina splash screen |

#### downloads/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| downloads.dart | 31 | 1.4 | Export feature downloads |
| data/datasources/ (2 file) | 296 | 10.1 | Datasource locale e remoto |
| data/models/ (3 file) | 220 | 8.4 | Modelli download, limiti, storage |
| data/repositories/ | 315 | 11.5 | Implementazione repository |
| domain/entities/ (3 file) | 531 | 17.6 | Entita download, limiti, storage |
| domain/repositories/ | 31 | 1.4 | Interfaccia repository |
| domain/usecases/ (3 file) | 138 | 4.9 | UseCase download, get, video |
| presentation/bloc/ (3 file) | 705 | 23.7 | BLoC, eventi, stati download |
| presentation/pages/ | 372 | 12.4 | Pagina downloads |
| presentation/widgets/ (6 file) | 1900 | 61.7 | Widget progress, quality, tile, empty, storage |

#### events/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| events.dart | 38 | 1.7 | Export feature eventi |
| data/datasources/ (2 file) | 448 | 14.9 | Datasource locale e remoto |
| data/models/ (7 file) | 879 | 31.1 | Modelli evento, opzioni, iscrizioni, lista attesa |
| data/repositories/ | 339 | 11.7 | Implementazione repository |
| domain/entities/ (9 file) | 1301 | 42.4 | Entita eventi, filtri, iscrizioni |
| domain/repositories/ | 112 | 4.1 | Interfaccia repository |
| domain/usecases/ (8 file) | 388 | 14.8 | UseCase eventi completi |
| presentation/bloc/ (3 file) | 1046 | 37.2 | BLoC, eventi, stati |
| presentation/pages/ (3 file) | 1344 | 44.8 | Pagine eventi, dettaglio, iscrizioni |
| presentation/screens/ (3 file) | 1554 | 51.7 | Screen eventi avanzati |
| presentation/widgets/ (9 file) | 2137 | 67.5 | Widget card, countdown, filtri, iscrizione |

#### fusion/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| fusion.dart | 36 | 1.7 | Export feature fusion |
| data/ (5 file) | 1303 | 43.6 | Datasource, modelli, repository fusion |
| domain/ (9 file) | 1241 | 39 | Entita, repository, use case fusion |
| presentation/bloc/ (3 file) | 1308 | 42.1 | BLoC fusione video |
| presentation/pages/ (4 file) | 2511 | 86.8 | Pagine progetti, dettaglio, risultato, wizard |
| presentation/widgets/ (4 file) | 1202 | 41.6 | Widget export, camera, progress, card |

#### glasses/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| presentation/widgets/glasses_control_panel.dart | 856 | 28.9 | Pannello controllo smart glasses AR |

#### home/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| data/ (6 file) | 1421 | 49.2 | Datasource, modelli (category, course, video, live) |
| domain/ (4 file) | 620 | 19.3 | Entita, repository, use case home |
| presentation/ (6 file) | 1610 | 50.8 | BLoC, pagine, widget (hero, content row, tabs) |

#### library/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| library.dart | 19 | 0.8 | Export feature library |
| data/ (4 file) | 465 | 15.6 | Datasource, modelli, repository |
| domain/ (5 file) | 170 | 5.4 | Entita, repository, use case |
| presentation/ (7 file) | 1218 | 38.5 | BLoC, pagine (library, category, video details), widget |

#### live/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| live.dart | 13 | 0.5 | Export feature live |
| data/ (3 file) | 502 | 16.3 | Datasource, modelli, repository |
| domain/ (3 file) | 321 | 9.5 | Entita, repository, use case |
| presentation/ (3 file) | 762 | 24.8 | BLoC, pagine live events |

#### notifications/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| notifications.dart | 40 | 1.9 | Export feature notifiche |
| data/ (5 file) | 742 | 24.4 | Datasource, modelli, repository |
| domain/ (10 file) | 849 | 24.2 | Entita, repository, use case completi |
| presentation/ (9 file) | 2126 | 73.5 | BLoC, pagine, screen, widget notifiche |
| services/ (2 file) | 396 | 13.6 | FCM service, notification handler |

#### onboarding/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| onboarding.dart | 5 | 0.2 | Export feature onboarding |
| presentation/pages/onboarding_page.dart | 233 | 7.4 | Pagina onboarding |
| presentation/widgets/onboarding_step.dart | 173 | 5 | Widget step onboarding |

#### player/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| data/ (6 file) | 2104 | 75.5 | Datasource, modelli (skeleton, video), repository |
| domain/ (8 file) | 1403 | 52.9 | Entita (chapter, playback, skeleton, quality), use case |
| presentation/bloc/ (3 file) | 1590 | 54.7 | BLoC player, enhanced player, skeleton analysis |
| presentation/pages/ (4 file) | 2040 | 73.5 | Player page, enhanced player, live player |
| presentation/widgets/ (16 file) | 7870 | 268.3 | Widget completi: angle, chapter, skeleton, controls, settings, subtitles, pose comparison, quality, skip |

#### profile/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| data/ (4 file) | 561 | 17.8 | Datasource, modelli, repository |
| domain/ (8 file) | 637 | 20.6 | Entita, repository, use case profilo |
| presentation/ (12 file) | 2843 | 92 | BLoC, pagine, screen, widget profilo |

#### search/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| data/ (3 file) | 353 | 11.6 | Datasource, modelli, repository |
| domain/ (3 file) | 283 | 8.2 | Entita, repository, use case |
| presentation/ (2 file) | 695 | 23.3 | BLoC, pagina ricerca |

#### settings/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| settings.dart | 16 | 0.7 | Export feature settings |
| data/ (4 file) | 634 | 23.9 | Datasource, modelli, repository |
| domain/ (4 file) | 396 | 12.8 | Entita, repository, use case |
| presentation/ (4 file) | 792 | 26 | BLoC, pagina impostazioni |

### /flutter_app/lib/services/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| glasses_service.dart | 485 | 19.1 | Servizio smart glasses WebSocket |

### /flutter_app/test/ (98 file, ~33.567 righe)

| Directory | File | Righe | Descrizione |
|-----------|------|-------|-------------|
| test/ (root) | 3 | 474 | Runner, config, widget test |
| test/core/offline/ | 4 | 850 | Test offline: connectivity, queue, storage, sync |
| test/downloads/ | 5 | 968 | Test download: modelli, entita, integrazione, BLoC, widget |
| test/features/ads/ | 2 | 922 | Test ads: use case, BLoC |
| test/features/auth/ | 1 | 709 | Test auth BLoC |
| test/features/downloads/ | 1 | 509 | Test downloads BLoC completo |
| test/features/events/ | 3 | 1.060 | Test eventi: BLoC, integrazione, repository |
| test/features/fusion/ | 2 | 793 | Test fusion: BLoC, widget progress |
| test/features/home/ | 2 | 896 | Test home: use case, BLoC |
| test/features/library/ | 2 | 1.244 | Test library: use case, BLoC |
| test/features/notifications/ | 4 | 906 | Test notifiche: helper, repository, integrazione, BLoC |
| test/features/player/ | 8 | 5.696 | Test player: entita, use case, BLoC, widget skeleton |
| test/features/profile/ | 2 | 326 | Test profile: BLoC, repository |
| test/features/search/ | 2 | 801 | Test search: use case, BLoC |
| test/helpers/ | 8 | 1.658 | Helper test: API, backend, fixtures, mock, setup |
| test/integration/ | 4 | 1.787 | Test integrazione: enhanced player, fusion, search, video |
| test/real/ | 19 | 7.406 | Test reali: audit, e2e, holistic, integration, penetration, performance, regression, security, stress, unit, widget |
| test/static_analysis/ | 1 | 311 | Test analisi statica codice |
| test/_deprecated/ | 12 | 4.194 | Test deprecati (ads, auth, holistic, integration, security, performance) |

### /flutter_app/integration_test/ (19 file, ~3.667 righe)

| Directory | File | Righe | Descrizione |
|-----------|------|-------|-------------|
| integration_test/ (root) | 1 | 135 | App test entry point |
| flows/ | 7 | 1.223 | Test flow: auth, events, home, profile, search, video |
| helpers/ | 3 | 341 | Helper: config, data |
| robots/ | 8 | 1.968 | Robot pattern: auth, base, events, home, player, profile, search |

---

## Frontend (~53.132 righe manuali + ~18.065 righe generate = ~71.197 righe totali TypeScript)

### /frontend/src/api/generated/ (Auto-generated API client)

**339 file, ~18.065 righe** - Client API auto-generato da OpenAPI spec

Comprende:
- `core/` - 6 file (ApiError, ApiRequestOptions, ApiResult, CancelablePromise, OpenAPI, request)
- `models/` - ~290 file modelli TypeScript (tutti i DTO)
- `services/` - ~40 file servizi API (AdminService, AdsService, AuthService, CurriculumService, EventsService, FusionService, ecc.)
- `index.ts` - 1 file export principale

### /frontend/src/ (non-generated)

#### Pages (app/)
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| page.tsx | 235 | 11.1 | Homepage principale |
| layout.tsx | 47 | 1.3 | Layout root |
| error.tsx | 39 | 1.1 | Error boundary |
| admin/page.tsx | 250 | 9.1 | Dashboard admin |
| admin/analytics/page.tsx | 244 | 11 | Pagina analytics admin |
| admin/moderation/page.tsx | 501 | 20.3 | Pagina moderazione video |
| admin/users/page.tsx | 311 | 12.8 | Gestione utenti admin |
| asd-dashboard/page.tsx | 412 | 15.9 | Dashboard ASD |
| asd-dashboard/earnings/page.tsx | 406 | 15.9 | Guadagni ASD |
| asd-dashboard/events/page.tsx | 328 | 11.7 | Eventi ASD |
| asd-dashboard/events/new/page.tsx | 401 | 14.5 | Nuovo evento ASD |
| asd-dashboard/events/[id]/page.tsx | 0 | 20.2 | Dettaglio evento ASD |
| asd-dashboard/events/[id]/edit/page.tsx | 0 | 20.5 | Modifica evento ASD |
| asd-dashboard/events/[id]/options/page.tsx | 0 | 20.1 | Opzioni evento ASD |
| asd-dashboard/stripe/page.tsx | 285 | 12.3 | Pagina Stripe Connect |
| asd-dashboard/stripe/cancel/page.tsx | 114 | 5 | Stripe cancellazione |
| asd-dashboard/stripe/success/page.tsx | 162 | 6.4 | Stripe successo |
| chat/page.tsx | 83 | 3.4 | Chat AI |
| curriculum/page.tsx | 270 | 9.7 | Lista curricula |
| curriculum/[id]/page.tsx | 0 | 12.2 | Dettaglio curriculum |
| curriculum/[id]/learn/page.tsx | 0 | 15.5 | Pagina apprendimento |
| dev/pose-detection/page.tsx | 184 | 8 | Dev: pose detection |
| dev/technique-annotation/page.tsx | 155 | 6.7 | Dev: annotazione tecniche |
| dev/voice-cloning/page.tsx | 210 | 8.5 | Dev: voice cloning |
| donations/page.tsx | 353 | 14.1 | Pagina donazioni |
| events/page.tsx | 256 | 9.9 | Lista eventi pubblici |
| events/[id]/page.tsx | 0 | 22.5 | Dettaglio evento |
| events/[id]/checkout/page.tsx | 0 | 8.1 | Checkout evento |
| fusion/page.tsx | 339 | 12.7 | Pagina fusion video |
| fusion/[id]/page.tsx | 0 | 31.6 | Dettaglio progetto fusion |
| ingest/page.tsx | 30 | 1 | Ingest base |
| ingest-studio/page.tsx | 498 | 18.6 | Ingest studio completo |
| landing/page.tsx | 320 | 13.4 | Landing page |
| live-player/page.tsx | 202 | 8.2 | Player live streaming |
| login/page.tsx | 152 | 7.1 | Pagina login |
| maestro/upload/page.tsx | 471 | 18.8 | Upload video maestro |
| manage/curricula/page.tsx | 294 | 12.4 | Gestione curricula maestro |
| manage/curricula/[id]/page.tsx | 0 | 22.9 | Dettaglio curriculum gestione |
| manage/curricula/[id]/students/page.tsx | 0 | 24.2 | Studenti curriculum |
| manage/exams/page.tsx | 524 | 20.6 | Gestione esami |
| me/subscriptions/page.tsx | 239 | 9.9 | Le mie iscrizioni |
| me/waiting-list/page.tsx | 271 | 11 | Lista attesa |
| monitor/page.tsx | 330 | 14.2 | Monitoraggio sistema |
| my-learning/page.tsx | 383 | 15.5 | Il mio apprendimento |
| onboarding/page.tsx | 239 | 8.7 | Onboarding |
| register/page.tsx | 237 | 10.6 | Pagina registrazione |
| skeleton-editor/page.tsx | 1651 | 68.7 | Editor skeleton 3D |
| skeleton-library/page.tsx | 530 | 21.7 | Libreria skeleton |
| skeleton-viewer/page.tsx | 651 | 25 | Viewer skeleton 3D |
| skeletons/page.tsx | 287 | 12 | Lista skeleton |
| special-projects/page.tsx | 494 | 18.3 | Progetti speciali |
| translation/page.tsx | 318 | 13 | Traduzione |
| upload/page.tsx | 146 | 5.8 | Upload video |

#### API Routes
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| api/ingest/route.ts | 61 | 1.9 | API route ingest |
| api/ingest-projects/[...path]/route.ts | 0 | 4.2 | API route ingest projects |
| api/studio/annotate/route.ts | 54 | 1.7 | API route annotazione |
| api/studio/pose-analysis/route.ts | 33 | 1.2 | API route analisi pose |
| api/studio/skeleton/[id]/route.ts | 0 | 1.4 | API route skeleton singolo |
| api/studio/skeletons/route.ts | 27 | 0.8 | API route skeleton lista |
| api/studio/text-to-speech/route.ts | 45 | 1.4 | API route TTS |

#### Ingest Studio Components
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| ingest-studio/components/index.ts | 10 | 0.4 | Export componenti |
| ingest-studio/components/DvdImportTab.tsx | 637 | 23.9 | Tab import DVD |
| ingest-studio/components/InputChannelTabs.tsx | 308 | 12.2 | Tab canali input |
| ingest-studio/components/MixPanel.tsx | 238 | 8.7 | Pannello mix audio |
| ingest-studio/components/ProcessingOptions.tsx | 321 | 13 | Opzioni processing |
| ingest-studio/components/ProgressPanel.tsx | 187 | 7.4 | Pannello progresso |
| ingest-studio/components/ProjectSelector.tsx | 226 | 8.8 | Selettore progetto |

#### Components
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| ConversationList.tsx | 117 | 4.2 | Lista conversazioni chat |
| LanguageSwitcher.tsx | 106 | 3.7 | Switcher lingua IT/EN |
| LazyVideo.tsx | 63 | 1.4 | Video lazy loading |
| LiveSubtitles.tsx | 252 | 8.7 | Sottotitoli live |
| MessageThread.tsx | 172 | 5.9 | Thread messaggi |
| SkeletonEditor3D.tsx | 332 | 12.4 | Editor skeleton 3D (Three.js) |
| SkeletonViewer3D.tsx | 393 | 12.4 | Viewer skeleton 3D (Three.js) |
| curriculum/ (8 file) | 2423 | 83.1 | Componenti curriculum: AI feedback, belt, certificate, card, exam, invite, level, progress, requirements |
| events/ (5 file) | 1197 | 46.8 | Componenti eventi: card, checkout, detail, list |
| _deprecated/ (2 file) | 836 | 29.5 | Componenti deprecati: PauseAdOverlay, VideoPlayer |

#### Hooks
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| useAnalytics.ts | 132 | 3.4 | Hook analytics |
| useEvents.ts | 229 | 7.5 | Hook eventi |
| useFusion.ts | 465 | 14.9 | Hook fusion |
| useIngestProjects.ts | 527 | 18.4 | Hook ingest projects |
| useLiveSubtitles.ts | 234 | 7 | Hook sottotitoli live |
| curriculum/ (7 file) | 1311 | 43.9 | Hook curriculum: AI feedback, curricula, curriculum, exam, progress, myCurricula |

#### Contexts
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| AuthContext.tsx | 269 | 8.8 | Context autenticazione |
| CurriculumContext.tsx | 494 | 16.1 | Context curriculum |
| I18nContext.tsx | 64 | 2.1 | Context internazionalizzazione |

#### Services
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| adsApi.ts | 293 | 8.4 | API ads |
| asdDashboardApi.ts | 441 | 12.6 | API dashboard ASD |
| curriculumApi.ts | 828 | 22.8 | API curriculum |
| eventsApi.ts | 384 | 10.8 | API eventi |
| ingestApi.ts | 430 | 12.4 | API ingest |

#### Types
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| curriculum.ts | 837 | 25.6 | Tipi curriculum |
| fusion.ts | 223 | 7 | Tipi fusion |
| ingest.ts | 392 | 10.7 | Tipi ingest |
| r3f.d.ts | 29 | 1 | Tipi React Three Fiber |
| vitest.d.ts | 36 | 1.4 | Tipi Vitest |

#### Config
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| api.ts | 127 | 4 | Configurazione API |
| lib/analytics-service.ts | 109 | 2.7 | Servizio analytics |
| lib/api-cache.ts | 61 | 1.5 | Cache API |
| lib/config.ts | 82 | 2.8 | Configurazione app |
| lib/i18n.ts | 34 | 1.1 | Configurazione i18n |
| lib/stripe.ts | 118 | 4.3 | Configurazione Stripe |

### /frontend/ (test - 73 file, ~6.395 righe)

| Directory | File | Righe | Descrizione |
|-----------|------|-------|-------------|
| cypress/e2e/ | 3 | 191 | Test E2E Cypress (admin, auth, landing) |
| cypress/support/ | 1 | 25 | Support Cypress |
| e2e/ | 1 | 270 | Test E2E Playwright (curriculum) |
| src/__tests__/setup.ts | 1 | 194 | Setup test |
| src/__tests__/curriculum/ | 24 | 1.854 | Test curriculum: componenti, holistic, hooks, integration, security, stress, chaos, performance, fixtures |
| src/__tests__/integration/ | 4 | 1.575 | Test integrazione: API, eventi, i18n, dashboard ASD |
| src/__tests__/static/ | 6 | 455 | Test statici: accessibilita, bundle, dependency, eslint, lighthouse, typescript |
| src/__tests__/performance/ | 1 | 10 | Test performance rendering |
| src/__tests__/regression/ | 1 | 128 | Test regressione visuale |
| src/__tests__/stress/ | 1 | 172 | Test stress carico |
| src/__tests__/unit/ | 2 | 404 | Test unitari: i18n, SkeletonViewer3D |

---

## Mobile (React Native/Expo) - Incluso in TypeScript

### /mobile/src/
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| App.tsx | 29 | 0.9 | Entry point app mobile |
| components/GlassesControlPanel.tsx | 707 | 22.4 | Pannello controllo smart glasses |
| components/PauseAdOverlay.tsx | 551 | 16.8 | Overlay pause ad mobile |
| components/events/EventCard.tsx | 306 | 8.9 | Card evento |
| components/events/EventFilters.tsx | 357 | 10 | Filtri eventi |
| components/events/SubscriptionStatus.tsx | 156 | 4.9 | Status iscrizione |
| components/events/index.ts | 17 | 0.6 | Export componenti eventi |
| contexts/AuthContext.tsx | 146 | 4.3 | Context autenticazione mobile |
| contexts/I18nContext.tsx | 73 | 2.5 | Context i18n mobile |
| navigation/RootNavigator.tsx | 207 | 6 | Navigazione root |
| screens/AICoachScreen.tsx | 394 | 11.6 | Schermata AI Coach |
| screens/EventDetailScreen.tsx | 645 | 18.8 | Dettaglio evento |
| screens/EventsScreen.tsx | 328 | 10.3 | Lista eventi |
| screens/GlassesPlayerScreen.tsx | 479 | 14.7 | Player smart glasses |
| screens/HomeScreen.tsx | 325 | 9.4 | Schermata home |
| screens/LibraryScreen.tsx | 481 | 12 | Libreria |
| screens/LiveStreamScreen.tsx | 396 | 11.4 | Live streaming |
| screens/LoginScreen.tsx | 248 | 6.8 | Login |
| screens/MySubscriptionsScreen.tsx | 459 | 13.1 | Le mie iscrizioni |
| screens/OfflineVideosScreen.tsx | 248 | 6.3 | Video offline |
| screens/ProfileScreen.tsx | 553 | 14.9 | Profilo |
| screens/RegisterScreen.tsx | 480 | 14.4 | Registrazione |
| screens/SearchScreen.tsx | 659 | 18.3 | Ricerca |
| screens/TechniquePlayerScreen.tsx | 620 | 19 | Player tecnica |
| screens/WaitingListScreen.tsx | 525 | 14.7 | Lista attesa |
| hooks/useNotifications.ts | 101 | 3.3 | Hook notifiche |
| hooks/useOfflineDownload.ts | 107 | 3.2 | Hook download offline |
| services/adsService.ts | 291 | 9.2 | Servizio ads |
| services/api.ts | 162 | 6.1 | Client API |
| services/eventsService.ts | 380 | 12.2 | Servizio eventi |
| services/glassesService.ts | 468 | 14.9 | Servizio glasses WebSocket |
| services/notifications.ts | 181 | 5.6 | Servizio notifiche |
| services/offlineStorage.ts | 215 | 7.1 | Storage offline |
| types/events.ts | 297 | 8.3 | Tipi eventi |

### /mobile/test/ e /mobile/__tests__/ (18 file, ~3.121 righe)
| Directory | File | Righe | Descrizione |
|-----------|------|-------|-------------|
| test/e2e/ | 4 | 585 | Test E2E: health, auth, pause ads, seed data |
| __tests__/ (root) | 5 | 615 | Test: App, AuthContext, HomeScreen, setup, mocks |
| __tests__/services/ | 2 | 1.029 | Test servizi: ads, glasses |
| __tests__/components/ | 1 | 398 | Test componenti: PauseAdOverlay |
| __tests__/screens/ | 1 | 268 | Test schermate: TechniquePlayerScreen |

---

## Infrastructure & Config (20 file, ~26.694 righe)

### Docker
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| docker-compose.yml | 53 | 1.3 | Docker compose sviluppo |
| docker-compose.prod.yml | 298 | 8.7 | Docker compose produzione |
| docker-compose.monitoring.yml | 137 | 4.6 | Docker compose monitoring |

### CI/CD
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| .github/workflows/ci.yml | 183 | 6.4 | CI pipeline principale |
| .github/workflows/deploy-production.yml | 272 | 9.7 | Deploy produzione |
| .github/workflows/test-backend.yml | 62 | 1.7 | Test backend pipeline |
| .github/workflows/test-flutter.yml | 38 | 0.9 | Test Flutter pipeline |

### Monitoring
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| monitoring/alertmanager.yml | 62 | 1.9 | Configurazione Alertmanager |
| monitoring/prometheus.yml | 74 | 2.8 | Configurazione Prometheus |
| monitoring/alerts/rules.yml | 176 | 7.6 | Regole alert Prometheus |
| monitoring/grafana/provisioning/dashboards/dashboards.yml | 19 | 0.7 | Provisioning dashboard Grafana |
| monitoring/grafana/provisioning/datasources/prometheus.yml | 20 | 0.7 | Datasource Prometheus Grafana |

### OpenAPI & Config
| File | Righe | KB | Descrizione |
|------|-------|-----|-------------|
| backend/docs/OPENAPI_SCHEMA.yaml | 1121 | 27.8 | Schema OpenAPI backend |
| docs/openapi/openapi.yaml | 23769 | 655.9 | Schema OpenAPI completo |
| flutter_app/analysis_options.yaml | 59 | 2 | Opzioni analisi Dart |
| flutter_app/dart_test.yaml | 116 | 2.2 | Configurazione test Dart |
| flutter_app/pubspec.yaml | 116 | 3 | Dipendenze Flutter |
| flutter_app/lib/api/generated/pubspec.yaml | 16 | 0.4 | Dipendenze API generata |
| backend/pyproject.toml | 94 | 2.3 | Configurazione Python/pytest |

---

## Documentazione (523 file, ~76.651 righe)

### Root docs (92 file)
Documenti principali di progetto:
- Analisi completamento, criticita, valore, architettura
- Report SAL periodici (20241129, 20251129, ecc.)
- Lessons learned (multipli)
- Setup guide, deployment guide, quick start
- Test report, enterprise suite report
- Inventari, mappature, statistiche
- Workflow moderazione, roadmap MVP

### /backend/ docs (17 file)
- Report test, coverage, bug fix
- Quick start testing, istruzioni Claude Code
- README setup profili, utenti test
- Migration code, test status

### /docs/ (42 file)
- API documentation completa per tutti i moduli
- Design modulo eventi ASD
- Guide: live translation, provider system, Sentry
- Mega prompt Claude Code
- Analisi gap funzionalita, pre-release checklist
- Session summary, performance baseline

### /flutter_app/ docs (249 file)
- Documentazione API generata (doc/) - ~240 file
- README, progetto summary, test report

### /docs/api/ (30 file)
Documentazione per ogni endpoint API: admin, ads, ai_coach, asd, audio, auth, blockchain, communication, contributions, curriculum, downloads, events, export, fusion, gdpr, glasses, ingest, library, live, live_translation, maestro, masters, moderation, notifications, payments, royalties, scheduler, skeleton, special_projects, students, subscriptions, system, temp_zone, tracking, users, videos, video_studio

---

## STATISTICHE FINALI

| Linguaggio | File | Righe | Note |
|------------|------|-------|------|
| Python (.py) | 473 | 181.694 | Backend (282 sorgente + 191 test) |
| Dart (.dart) totale | 1.114 | 214.018 | Flutter App (incluso generated) |
| Dart (.dart) manual | 439 | 103.901 | Flutter App (escluso generated) |
| Dart (.dart) generated | 675 | 110.117 | Flutter API client auto-generato |
| TypeScript/JS totale | 609 | 71.197 | Frontend + Mobile (incluso generated) |
| TypeScript/JS manual | 270 | 53.132 | Frontend + Mobile (escluso generated) |
| TypeScript/JS generated | 339 | 18.065 | Frontend API client auto-generato |
| YAML/Config | 20 | 26.694 | Docker, CI/CD, monitoring, OpenAPI |
| Markdown (.md) | 523 | 76.651 | Documentazione |
| JSON | 957 | 7.079.718 | Dati (skeleton JSON molto grandi) |
| HTML/CSS (web) | 151 | 74.395 | Coverage report, template email, htmlcov |
| Other (txt, sh, etc.) | 51 | 42.029 | Script shell, requirements, log test |
| **TOTALE** | **3.898** | **7.766.396** | |

### Riepilogo codice sorgente (escluso generato, docs, data, web reports):

| Componente | File | Righe | Note |
|------------|------|-------|------|
| Backend Python (sorgente) | 282 | 101.117 | API, modelli, servizi, moduli |
| Backend Python (test) | 191 | 80.577 | Test completi enterprise |
| Flutter Dart (manual) | 439 | 103.901 | App mobile, clean architecture |
| Flutter Dart (test manual) | 117 | 37.234 | Test + integration test |
| Frontend TS (manual) | 270 | 53.132 | Web app Next.js |
| **TOTALE CODICE MANUALE** | **~1.299** | **~375.961** | **Escluso generato** |

---

## FILE SOSPETTI/PLACEHOLDER

I seguenti file hanno **0 righe** e potrebbero essere placeholder o file con contenuto ma nessuna newline:

| File | KB | Note |
|------|-----|------|
| backend/tests/e2e/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/ads/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/auth/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/blockchain/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/events/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/royalties/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/special_projects/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/modules/video_moderation/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/performance/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/tests/security/__init__.py | 0 | Init vuoto (normale per Python) |
| backend/modules/__init__.py | 0 | Init vuoto (contiene 1 riga ma 0 KB) |
| flutter_app/lib/features/settings/domain/entities/app_settings_entity.dart | 0 | **PLACEHOLDER** - file vuoto |
| flutter_app/lib/features/settings/domain/usecases/update_settings_usecase.dart | 0 | **PLACEHOLDER** - file vuoto |
| flutter_app/flutter_analyze_output.txt | 0 | File output vuoto |
| frontend/src/app/asd-dashboard/events/[id]/page.tsx | 0 | 20.2 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/asd-dashboard/events/[id]/edit/page.tsx | 0 | 20.5 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/asd-dashboard/events/[id]/options/page.tsx | 0 | 20.1 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/curriculum/[id]/page.tsx | 0 | 12.2 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/curriculum/[id]/learn/page.tsx | 0 | 15.5 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/events/[id]/page.tsx | 0 | 22.5 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/events/[id]/checkout/page.tsx | 0 | 8.1 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/fusion/[id]/page.tsx | 0 | 31.6 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/manage/curricula/[id]/page.tsx | 0 | 22.9 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/manage/curricula/[id]/students/page.tsx | 0 | 24.2 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/api/ingest-projects/[...path]/route.ts | 0 | 4.2 KB ma 0 righe - probabile contenuto minificato |
| frontend/src/app/api/studio/skeleton/[id]/route.ts | 0 | 1.4 KB ma 0 righe - probabile contenuto minificato |

**Nota**: I file Next.js con 0 righe ma KB significativi (es. `[id]/page.tsx` con 20+ KB) sono probabilmente file scritti su una singola riga (minificati o generati senza newline). Non sono vuoti ma il conteggio righe risulta 0.

I file `.txt` nella directory `backend/data/uploads/` (24 file con 1 riga e 0 KB) sono placeholder per upload test.

---

*Mappatura generata il 2025-01-28*
*Progetto: Media Center Arti Marziali*
*Totale file analizzati: 3.898*

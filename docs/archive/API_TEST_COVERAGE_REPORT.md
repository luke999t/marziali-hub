# API INTEGRATION TEST COVERAGE REPORT
**Data**: 2026-01-23
**Progetto**: media-center-arti-marziali/backend

---

## RIEPILOGO

| Metrica | Valore |
|---------|--------|
| Router API totali | 30 |
| Router con test | 17 |
| Router senza test | 13 |
| **Coverage** | **57%** |

---

## DETTAGLIO COVERAGE

### Router CON Test Integration

| Router | Test File | Status |
|--------|-----------|--------|
| `ads.py` | `test_ads_api.py` | ✅ |
| `ai_coach.py` | `test_ai_coach_api.py` | ✅ |
| `asd.py` | `test_asd_api.py` | ✅ |
| `auth.py` | `test_auth_api.py` | ✅ |
| `blockchain.py` | `test_blockchain_api.py` | ✅ |
| `curriculum.py` | `test_curriculum_api.py` | ✅ |
| `curriculum.py` | `test_curricula_auth_api.py` | ✅ (auth tests) |
| `export.py` | `test_export_api.py` | ✅ |
| `fusion.py` | `test_fusion_api.py` | ✅ |
| `live_translation.py` | `test_live_translation_api.py` | ✅ |
| `maestro.py` | `test_maestro_api.py` | ✅ |
| `notifications.py` | `test_notifications_api.py` | ✅ |
| `scheduler.py` | `test_scheduler_api.py` | ✅ |
| `skeleton.py` | `test_skeleton_api.py` | ✅ |
| `users.py` | `test_users_api.py` | ✅ |
| `video_studio.py` | `test_video_studio_api.py` | ✅ |
| `videos.py` | `test_videos_api.py` | ✅ |

**Totale con test: 17 router**

---

### Router SENZA Test Integration

| Router | Priorita | Motivo |
|--------|----------|--------|
| `payments.py` | **CRITICO** | Stripe integration - gestisce pagamenti |
| `subscriptions.py` | **CRITICO** | Abbonamenti utente - revenue core |
| `admin.py` | ALTA | Funzioni amministrative |
| `admin_continued.py` | ALTA | Funzioni amministrative estese |
| `moderation.py` | ALTA | Workflow approvazione video |
| `downloads.py` | MEDIA | Download offline con DRM |
| `library.py` | MEDIA | Libreria utente, progress video |
| `contributions.py` | MEDIA | Staff contributions |
| `audio.py` | MEDIA | TTS, voice cloning |
| `communication.py` | BASSA | Comunicazioni interne |
| `live.py` | BASSA | Live streaming |
| `ingest_projects.py` | BASSA | Ingest studio |
| `glasses_ws.py` | BASSA | Smart glasses WebSocket |
| `temp_zone.py` | BASSA | Admin temp files |

**Totale senza test: 13 router**

---

## FILE NON-ROUTER (esclusi dal conteggio)

| File | Tipo |
|------|------|
| `__init__.py` | Package init |
| `schemas.py` | Pydantic schemas |
| `schemas_ingest.py` | Ingest schemas |

---

## RACCOMANDAZIONI

### Priorita 1 - CRITICO (Business Impact)
1. **`payments.py`** - Test pagamenti Stripe
   - Checkout flow
   - Webhook handling
   - Refund flow

2. **`subscriptions.py`** - Test abbonamenti
   - Create/cancel subscription
   - Tier upgrade/downgrade
   - Billing cycle

### Priorita 2 - ALTA (Core Features)
3. **`admin.py`** - Test admin functions
4. **`moderation.py`** - Test approval workflow

### Priorita 3 - MEDIA (Secondary Features)
5. **`downloads.py`** - Test offline downloads
6. **`library.py`** - Test user library
7. **`contributions.py`** - Test staff workflow
8. **`audio.py`** - Test TTS/cloning

### Priorita 4 - BASSA (Nice to Have)
9-13. Altri router con basso impatto business

---

## STATISTICHE TEST ESISTENTI

| Test File | Linee | Note |
|-----------|-------|------|
| `test_curriculum_api.py` | ~850 | Completo |
| `test_fusion_api.py` | ~700 | Completo |
| `test_export_api.py` | ~650 | Completo |
| `test_notifications_api.py` | ~650 | Completo |
| `test_ai_coach_api.py` | ~550 | Completo |
| `test_skeleton_api.py` | ~600 | Completo |
| `test_ads_api.py` | ~550 | Completo |
| `test_asd_api.py` | ~500 | Completo |
| `test_maestro_api.py` | ~520 | Completo |
| `test_scheduler_api.py` | ~490 | Completo |
| `test_videos_api.py` | ~500 | + trending tests |
| `test_blockchain_api.py` | ~400 | Completo |
| `test_auth_api.py` | ~400 | Completo |
| `test_users_api.py` | ~320 | Completo |
| `test_video_studio_api.py` | ~380 | Completo |
| `test_live_translation_api.py` | ~390 | Completo |
| `test_curricula_auth_api.py` | ~355 | Nuovo (auth focus) |

---

## PROSSIMI PASSI

1. [ ] Creare `test_payments_api.py` (CRITICO)
2. [ ] Creare `test_subscriptions_api.py` (CRITICO)
3. [ ] Creare `test_admin_api.py` (ALTA)
4. [ ] Creare `test_moderation_api.py` (ALTA)
5. [ ] Raggiungere 80% coverage

---

*Report generato il 2026-01-23*

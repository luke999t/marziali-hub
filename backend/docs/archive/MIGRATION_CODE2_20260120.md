# MIGRATION DOCUMENT - CODE 2
**Data**: 2026-01-20
**Progetto**: Media Center Arti Marziali - Backend
**Path**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend`

---

## 1. STATO ATTUALE TEST

### Risultati Globali
| Metrica | Valore |
|---------|--------|
| **Test Totali** | 892 |
| **Passed** | 786 |
| **Failed** | 70 |
| **Skipped** | 36 |
| **Pass Rate** | **91.8%** |

### Moduli 100% OK (20/31) - NON TOCCARE
- test_auth_integration_enterprise.py (22/22)
- test_users_api.py (26/26)
- test_admin_api.py (57/57)
- test_videos_api.py (28/28)
- test_curriculum_api.py (23/23)
- test_video_studio_api.py (22/22)
- test_fusion_api.py (19/19)
- test_communication_api.py (24/24)
- test_payments_integration.py (30/30)
- test_subscriptions_api.py (32/32)
- test_export_api.py (17/17)
- test_translation_pipeline.py (42/42)
- test_translation_debate_integration.py (34/34)
- test_glasses_ws.py (25/25)
- test_grammar_extractor_integration.py (35/35)
- test_pause_ad_api.py (39/39)
- test_skeleton_api.py (17/17)
- test_skeleton_holistic_api.py (33/33)
- test_ingest_skeleton_api.py (29/29)
- test_library_integration.py (13/14 - 1 error fixture)

---

## 2. TASK PER NUOVA CHAT

### Moduli da Fixare (Code 2)
| Modulo | Passed | Failed | API File | Test File |
|--------|--------|--------|----------|-----------|
| **Ads** | 27 | 8 | `api/v1/ads.py` | `tests/integration/test_ads_integration_enterprise.py` |
| **Live Translation** | 11 | 6 | `api/v1/live_translation.py` | `tests/integration/test_live_translation_api.py` |
| **Notifications** | 27 | 5 | `api/v1/notifications.py` | `tests/integration/test_notifications_api.py` |
| **Blockchain** | 12 | 4 | `api/v1/blockchain.py` | `tests/integration/test_blockchain_api.py` |

### Moduli Assegnati a Code 1 - NON TOCCARE
| Modulo | Passed | Failed | API File |
|--------|--------|--------|----------|
| AI Coach | 14 | 12 | `api/v1/ai_coach.py` |
| ASD | 5 | 12 | `api/v1/asd.py` |
| Maestro | 7 | 12 | `api/v1/maestro.py` |

---

## 3. ERRORI SPECIFICI DA FIXARE

### test_ads_integration_enterprise.py (8 FAILED)
```
test_start_batch_session_invalid_batch_type - 200 invece di [400, 422]
test_get_active_session - 500 invece di [200, 204, 404]
test_record_view_negative_duration - 200 invece di [400, 422]
test_record_view_missing_ad_id - 200 invece di [400, 422]
test_record_view_invalid_ad_id - 200 invece di [400, 422]
test_batch_expiration_check - 500 invece di [200, 404]
test_malformed_json_request - 500 invece di [400, 422]
test_empty_body_request - 200 invece di [400, 422]
```

### test_live_translation_api.py (6 FAILED)
```
test_supported_languages - 500 invece di 200
test_start_session_event_not_found - 500 invece di 404
test_switch_provider_invalid_provider - 200 invece di [400, 422]
test_start_session_empty_target_languages - 500 invece di [200, 404, 422]
test_start_session_invalid_source_language - 500 invece di [200, 400, 404, 422]
test_very_long_event_id - 200 invece di [400, 404, 414, 422]
```

### test_notifications_api.py (5 FAILED)
```
test_get_notifications_page_size_limit - 422 invece di 200 (validation troppo stretta)
test_get_device_tokens - 500 invece di 200
test_get_preferences_default - 500 invece di 200
test_update_preferences_invalid_quiet_hours_format - 200 invece di 422
test_broadcast_with_admin - 500 invece di [200, 401, 403, 422]
```

### test_blockchain_api.py (4 FAILED)
```
test_get_batch_status_not_found - 500 invece di 404
test_get_batch_status_invalid_id - 500 invece di [404, 422]
test_receive_validation_batch_not_found - 500 invece di [400, 404]
test_receive_validation_with_notes - 500 invece di [400, 404]
```

---

## 4. PATTERN FIX COMUNI

### Pattern A: current_user.get() AttributeError
```python
# SBAGLIATO - causa 500
user_id = current_user.get("id")

# CORRETTO
def get_user_id(current_user) -> str:
    if hasattr(current_user, 'id'):
        return str(current_user.id)
    elif isinstance(current_user, dict):
        return current_user.get("id", "")
    return ""

user_id = get_user_id(current_user)
```

### Pattern B: None check mancante
```python
# SBAGLIATO - causa 500
item = await db.get(Model, id)
return item.name  # Crash se None

# CORRETTO
item = await db.get(Model, id)
if item is None:
    raise HTTPException(status_code=404, detail="Not found")
return item.name
```

### Pattern C: Validation mancante
```python
# SBAGLIATO - accetta tutto, ritorna 200
@router.post("/endpoint")
async def endpoint(data: dict):
    return {"ok": True}

# CORRETTO - valida input
@router.post("/endpoint")
async def endpoint(data: MyPydanticModel):
    if not data.required_field:
        raise HTTPException(status_code=422, detail="required_field missing")
    return {"ok": True}
```

### Pattern D: Database session issue (GIA FIXATO)
Il fix in `core/database.py` ha risolto il problema "generator didn't stop after athrow()".
NON serve modificare ulteriormente questo file.

---

## 5. COMANDI UTILI

### Verifica Backend Attivo
```bash
curl http://localhost:8000/health
```

### Esegui Test Singolo Modulo
```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m pytest tests/integration/test_ads_integration_enterprise.py -v --tb=short
python -m pytest tests/integration/test_live_translation_api.py -v --tb=short
python -m pytest tests/integration/test_notifications_api.py -v --tb=short
python -m pytest tests/integration/test_blockchain_api.py -v --tb=short
```

### Esegui Tutti i Test
```bash
python -m pytest tests/integration/ -v --tb=short 2>&1 | tail -50
```

---

## 6. FILE CRITICI

### Da Modificare (Code 2)
- `api/v1/ads.py`
- `api/v1/live_translation.py`
- `api/v1/notifications.py`
- `api/v1/blockchain.py`

### Da NON Toccare
- `api/v1/ai_coach.py` (Code 1)
- `api/v1/asd.py` (Code 1)
- `api/v1/maestro.py` (Code 1)
- `core/database.py` (gia fixato)
- `core/security.py`
- `tests/conftest.py`
- Tutti i file in `tests/` (non modificare test)

---

## 7. REGOLE PROGETTO

1. **ZERO MOCK**: I test chiamano API reali, non usare mock/patch
2. **AI-FIRST Headers**: Ogni file deve avere header con AI_MODULE, AI_DESCRIPTION
3. **Backend Attivo**: Il server deve girare su localhost:8000
4. **No Test Modification**: Non modificare i test per farli passare
5. **HTTPException**: Usare sempre HTTPException per errori, mai return None

---

## 8. CHECKLIST NUOVA CHAT

- [ ] Leggere questo documento
- [ ] Verificare backend attivo (`curl localhost:8000/health`)
- [ ] Eseguire test Ads e identificare bug
- [ ] Fixare api/v1/ads.py
- [ ] Rieseguire test Ads (target: 35/35)
- [ ] Ripetere per Live Translation, Notifications, Blockchain
- [ ] Report finale con pass rate aggiornato

---

## 9. TARGET FINALE

| Metrica | Attuale | Target |
|---------|---------|--------|
| Pass Rate | 91.8% | **95%+** |
| Moduli 100% | 20/31 | **27/31** |
| Failed Tests | 70 | **<30** |

---

*Documento generato il 2026-01-20*
*Sessione: Code 2 - Test Coverage Backend*

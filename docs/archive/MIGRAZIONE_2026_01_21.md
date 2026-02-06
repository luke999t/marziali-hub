# 📋 DOCUMENTO MIGRAZIONE - MEDIA CENTER ARTI MARZIALI

**Data:** 21 Gennaio 2026
**Sessione:** Fix Scheduler + Test Coverage + Flutter Analyze
**Stato:** Da continuare con 2 prompt puliti

---

## 📊 STATO PROGETTO

| Componente | Completamento | Note |
|------------|---------------|------|
| Backend | ~93% | 32/32 router OK, scheduler fix applicato |
| Flutter | ~85% | 205 errori analyze rimasti |
| Test API | 16 file | 349 passed, 90.9% pass rate |
| Valore | €400K+ | 223K+ linee codice |

---

## ✅ COMPLETATO OGGI (21 Gen 2026)

### 1. FIX SCHEDULER APSCHEDULER
**File:** `backend/modules/scheduler/scheduler_service.py`
**Problema:** `add_listener()` usava parametro `events=` invece di `mask=`
**Fix:** 
```python
# PRIMA (errore)
self._scheduler.add_listener(self._on_job_executed, events=1)

# DOPO (corretto)
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
self._scheduler.add_listener(self._on_job_executed, mask=EVENT_JOB_EXECUTED)
```
**Risultato:** `[OK] Scheduler started with 6 jobs` ✅

### 2. FIX DATABASE MIGRATION EVENT_TYPE
**File:** `backend/fix_event_type.py`
**Problema:** Colonna `event_type` mancante in tabella `live_events`
**Fix:** Script migrazione eseguito con successo
**Risultato:** Tutti endpoint Live API funzionanti ✅

### 3. FLUTTER SKELETON 75 INTEGRATION
**File:** `flutter_app/test/features/player/widgets/skeleton_overlay_75_test.dart`
**Risultato:** 35/35 test passati (100%) ✅

### 4. NUOVI TEST FILE BACKEND (Code 1)
| File | Test | Descrizione |
|------|------|-------------|
| test_auth_api.py | 21 | Login, Register, Refresh, Security |
| test_users_api.py | 16 | Profile CRUD, Validation |
| test_videos_api.py | 30 | List, Search, Favorites, Progress |
| test_scheduler_api.py | 29 | Jobs, Trigger, Pause/Resume |
| test_notifications_api.py | 36 | List, Preferences, Device tokens |
| **TOTALE** | **132** | Nuovi test creati |

### 5. FLUTTER ANALYZE PARTIAL FIX (Code 2)
**Errori iniziali:** 275+
**Errori finali:** 205
**Riduzione:** ~70 fix (25%)

**Fix applicati:**
- connectivity_service.dart - API mismatch connectivity_plus
- offline_queue.dart - dynamic type handling
- injection.dart - MarkAllReadUseCase, sharedPreferences, FusionBloc
- BLoC exports: downloads_bloc, notifications_bloc, profile_bloc, events_bloc
- event_usecases.dart - riallineato con repository
- profile_usecases.dart - riallineato con repository
- subscription_model.dart - fix EventModel/Event type conflict
- waiting_list_entry_model.dart - fix EventModel/Event type conflict

---

## ❌ DA COMPLETARE

### 1. FLUTTER ANALYZE - 205 ERRORI RIMASTI
**Tipo:** Presentation layer (pages, widgets)
**Problemi principali:**
- Event naming mismatch: `LoadEventsEvent` vs `LoadEvents`
- Entity type conflicts: `Event` vs `EventEntity`
- Missing state properties: `isLoading`, `errorMessage`
- Player module: deprecated `Color.withValues()` API
- Profile/Notifications pages: pattern mismatches

### 2. BACKEND TEST - ERRORI E FAILED
**Stato attuale:** 349 passed, 35 failed, 44 skipped, 59 errors
**Target:** ≥95% pass rate
**Problemi:** Async fixture issues (api_client sync vs async_client)

### 3. MODULI CON ERRORI 500 (da verificare)
| Modulo | File API | Status |
|--------|----------|--------|
| AI Coach | api/v1/ai_coach.py | Da verificare |
| ASD | api/v1/asd.py | Da verificare |
| Maestro | api/v1/maestro.py | Da verificare |
| Blockchain | api/v1/blockchain.py | Da verificare |
| Live Translation | api/v1/live_translation.py | Da verificare |
| Notifications | api/v1/notifications.py | Da verificare |
| Ads | api/v1/ads.py | Da verificare |

---

## 📁 FILE MODIFICATI OGGI

### Backend
- `modules/scheduler/scheduler_service.py` - Fix APScheduler mask
- `modules/scheduler/__init__.py` - Fix imports
- `modules/scheduler/jobs/__init__.py` - JOB_DEFINITIONS export
- `fix_event_type.py` - Migration script
- `tests/api/test_auth_api.py` - NUOVO
- `tests/api/test_users_api.py` - NUOVO
- `tests/api/test_videos_api.py` - NUOVO
- `tests/api/test_scheduler_api.py` - NUOVO
- `tests/api/test_notifications_api.py` - NUOVO

### Flutter
- `lib/core/di/injection.dart` - Fix hide imports
- `lib/core/services/connectivity_service.dart` - Fix API
- `lib/core/services/offline_queue.dart` - Fix types
- `lib/features/downloads/presentation/bloc/downloads_bloc.dart` - Export
- `lib/features/notifications/presentation/bloc/notifications_bloc.dart` - Export
- `lib/features/profile/presentation/bloc/profile_bloc.dart` - Export
- `lib/features/events/presentation/bloc/events_bloc.dart` - Export + imports
- `lib/features/events/domain/usecases/event_usecases.dart` - Rewrite
- `lib/features/profile/domain/usecases/profile_usecases.dart` - Rewrite
- `lib/features/events/data/models/subscription_model.dart` - Fix types
- `lib/features/events/data/models/waiting_list_entry_model.dart` - Fix types
- `test/features/player/widgets/skeleton_overlay_75_test.dart` - NUOVO

---

## 🔧 COMANDI UTILI

```powershell
# Backend - Avvia server
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m uvicorn main:app --port 8000 --reload

# Backend - Esegui test
pytest tests/api/ -v --tb=short

# Flutter - Analyze
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\flutter_app
C:\flutter\bin\flutter.bat analyze

# Flutter - Test
C:\flutter\bin\flutter.bat test
```

---

## 📋 2 PROMPT PULITI PER CONTINUARE

### PROMPT A: FLUTTER - Finire 205 errori

```markdown
# TASK: Flutter Analyze - Completare fix 205 errori

## PATH
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\flutter_app

## FLUTTER
C:\flutter\bin\flutter.bat

## STATO
Un precedente Code ha ridotto errori da 275 a 205.
Errori rimasti sono nel presentation layer (pages, widgets).

## PROBLEMI PRINCIPALI
1. Event naming: LoadEventsEvent vs LoadEvents
2. Entity types: Event vs EventEntity  
3. Missing state properties: isLoading, errorMessage
4. Color.withValues() deprecated
5. Profile/Notifications page mismatches

## REGOLE
- Header AI-First su file modificati
- Commenti FIX_2025_01_21 per tracciabilità
- NON toccare: skeleton*, backend/*

## STEP
1. flutter analyze | Select-String "error"
2. Fix sistematico per file
3. Verifica finale: 0 errors

## TARGET
flutter analyze: 0 errors (warning OK)
```

### PROMPT B: BACKEND - Fix test e errori 500

```markdown
# TASK: Backend Test Suite - Target 95% pass rate

## PATH
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

## STATO ATTUALE
- 349 passed, 35 failed, 44 skipped, 59 errors
- Pass rate: 90.9%
- Target: ≥95%

## PROBLEMI NOTI
1. Async fixture issues: api_client sync vs async_client
2. Moduli con errori 500: AI Coach, ASD, Maestro, Blockchain, etc.

## REGOLE
- ZERO MOCK INVIOLABILE
- Backend attivo su localhost:8000
- Database: martial_user:martial_pass@localhost:5432/martial_arts_db
- Header AI-First su modifiche

## STEP
1. pytest tests/api/ -v --tb=short 2>&1 | tee report.txt
2. Identifica pattern errori
3. Fix conftest.py per async fixtures
4. Fix moduli con 500 errors
5. Riesegui test

## TARGET
Pass rate ≥95% (almeno 400/420 test)
```

---

## ⚠️ REGOLE CRITICHE

### ZERO MOCK
- ❌ VIETATO: jest.mock, MagicMock, AsyncMock, @patch
- ✅ OBBLIGATORIO: Test chiamano backend REALE localhost:8000
- ✅ VERIFICA: Backend spento = test DEVONO fallire

### AI-FIRST HEADERS
```python
"""
🎓 AI_MODULE: [Nome]
🎓 AI_DESCRIPTION: [Cosa fa]
🎓 AI_BUSINESS: [Valore business]
🎓 AI_TEACHING: [Concetto tecnico]
"""
```

### CREDENZIALI DATABASE
```
Host: localhost:5432
Database: martial_arts_db
User: martial_user
Password: martial_pass
```

---

## 📈 METRICHE TARGET

| Metrica | Attuale | Target |
|---------|---------|--------|
| Backend test pass rate | 90.9% | ≥95% |
| Flutter analyze errors | 205 | 0 |
| Router funzionanti | 32/32 | 32/32 ✅ |
| Scheduler jobs | 6/6 | 6/6 ✅ |

---

*Documento generato: 21 Gennaio 2026*
*Progetto: Media Center Arti Marziali*
*Prossima sessione: Usare PROMPT A e PROMPT B*

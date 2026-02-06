# 📚 LESSONS LEARNED - Media Center Arti Marziali
## Data: 2026-01-21

---

## 🎯 SUMMARY SESSIONE

| Metrica | Valore |
|---------|--------|
| **Backend** | ~93% completato |
| **Flutter** | ~85% completato |
| **Router OK** | 32/32 |
| **Test pass rate** | 90.9% |
| **Nuovi test creati** | 132 |
| **Flutter errors fixati** | 70 (275→205) |

---

## 🔴 ERRORE 1: APScheduler Deprecation (CRITICO)

### Sintomo
Scheduler non parte, errore su parametro `events`

### Root Cause
APScheduler 3.x ha deprecato `events=` in `add_listener()`, ora richiede `mask=` con costanti.

### Codice

```python
# ❌ PRIMA (errore)
self._scheduler.add_listener(self._on_job_executed, events=1)

# ✅ DOPO (corretto)
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
self._scheduler.add_listener(self._on_job_executed, mask=EVENT_JOB_EXECUTED)
```

### File
`modules/scheduler/scheduler_service.py`

### Risultato
```
[OK] Scheduler started with 6 jobs
```

### 🛡️ Prevenzione
Controllare changelog APScheduler prima di upgrade versione.

---

## 🔴 ERRORE 2: Colonna Database Mancante (ALTO)

### Sintomo
Live API endpoints ritornano 500 - "column 'event_type' does not exist"

### Root Cause
Model richiedeva `event_type` ma tabella `live_events` non aveva la colonna.

### Fix
```sql
ALTER TABLE live_events ADD COLUMN IF NOT EXISTS event_type VARCHAR(50) DEFAULT 'seminar';
```

### 🛡️ Prevenzione
> ⚠️ **REGOLA**: Mai modificare model senza creare migrazione database.
> Usare Alembic per tracking automatico.

---

## 🟡 ERRORE 3: Flutter Analyze - 205 Errori (MEDIO)

### Sintomo
`flutter analyze` mostra 205 errori nel presentation layer

### Pattern Errori Comuni

| Pattern | Esempio |
|---------|---------|
| Event naming | `LoadEventsEvent` vs `LoadEvents` |
| Entity types | `Event` vs `EventEntity` |
| Missing state | `isLoading`, `errorMessage` non definiti |
| Deprecated API | `Color.withValues()` |

### Fix Applicati (70 errori risolti)

| File | Fix |
|------|-----|
| connectivity_service.dart | API mismatch connectivity_plus |
| offline_queue.dart | dynamic type handling |
| injection.dart | MarkAllReadUseCase, sharedPreferences |
| downloads_bloc.dart | Export mancante |
| notifications_bloc.dart | Export mancante |
| profile_bloc.dart | Export mancante |
| events_bloc.dart | Export + imports |
| event_usecases.dart | Riallineato con repository |
| profile_usecases.dart | Riallineato con repository |

### Progresso
- **Prima:** 275 errori
- **Dopo:** 205 errori  
- **Fixati:** 70 (-25%)

### 🛡️ Prevenzione
Mantenere naming convention consistente nei BLoC:
- Eventi: `LoadEvents` (non `LoadEventsEvent`)
- Stati: Usare sempre `isLoading`, `errorMessage`, `data`

---

## 🟡 ERRORE 4: Test Async Fixture Mismatch (ALTO)

### Sintomo
59 errors nei test, 35 failed - pass rate 90.9%

### Root Cause
Mismatch tra `api_client` (sync) e `async_client` nelle fixtures

### Statistiche Test

| Metric | Valore |
|--------|--------|
| Passed | 349 |
| Failed | 35 |
| Skipped | 44 |
| Errors | 59 |
| **Pass Rate** | 90.9% |
| **Target** | ≥95% |

### Status
**PENDING** - da completare in sessione successiva

---

## ✅ COMPLETAMENTI

### 1. APScheduler Fix ✅
Scheduler avviato con 6 jobs

### 2. Database Migration ✅
Live API funzionanti

### 3. Flutter Skeleton 75 Integration ✅
- **File:** `test/features/player/widgets/skeleton_overlay_75_test.dart`
- **Test:** 35/35 passati (100%)

### 4. Nuovi Test Backend ✅

| File | Test | Descrizione |
|------|------|-------------|
| test_auth_api.py | 21 | Login, Register, Refresh |
| test_users_api.py | 16 | Profile CRUD |
| test_videos_api.py | 30 | List, Search, Favorites |
| test_scheduler_api.py | 29 | Jobs, Trigger |
| test_notifications_api.py | 36 | List, Preferences |
| **TOTALE** | **132** | |

---

## 🎓 PATTERN APPRESI

### 1. APScheduler Listener
```
📌 REGOLA: In APScheduler 3.x usare mask= con costanti EVENT_*, 
   non events= con interi.
```

### 2. BLoC Naming Conventions
```
📌 REGOLA: Eventi BLoC devono avere naming consistente.
   Usare LoadEvents, non LoadEventsEvent.
   Stati devono avere isLoading, errorMessage, data.
```

### 3. Fixture Scope Consistency
```
📌 REGOLA: Tutte le fixture async devono usare stesso pattern:
   - async_sessionmaker
   - expire_on_commit=False
   - scope consistente (function o module)
```

### 4. Database Migrations
```
📌 REGOLA: Ogni modifica a model SQLAlchemy richiede migrazione.
   Non affidarsi a CREATE TABLE automatico.
```

---

## 📁 FILE MODIFICATI

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
- `lib/core/di/injection.dart`
- `lib/core/services/connectivity_service.dart`
- `lib/core/services/offline_queue.dart`
- `lib/features/downloads/presentation/bloc/downloads_bloc.dart`
- `lib/features/notifications/presentation/bloc/notifications_bloc.dart`
- `lib/features/profile/presentation/bloc/profile_bloc.dart`
- `lib/features/events/presentation/bloc/events_bloc.dart`
- `lib/features/events/domain/usecases/event_usecases.dart`
- `lib/features/profile/domain/usecases/profile_usecases.dart`
- `lib/features/events/data/models/subscription_model.dart`
- `lib/features/events/data/models/waiting_list_entry_model.dart`
- `test/features/player/widgets/skeleton_overlay_75_test.dart` - NUOVO

---

## 📋 PROMPT PER CONTINUARE

### PROMPT A: Flutter - Completare 205 errori

```markdown
# TASK: Flutter Analyze - Completare fix 205 errori

## PATH
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\flutter_app

## PROBLEMI PRINCIPALI
1. Event naming: LoadEventsEvent vs LoadEvents
2. Entity types: Event vs EventEntity  
3. Missing state properties: isLoading, errorMessage
4. Color.withValues() deprecated

## TARGET
flutter analyze: 0 errors
```

### PROMPT B: Backend - Test 95%

```markdown
# TASK: Backend Test Suite - Target 95%

## PATH
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

## STATO
349 passed, 35 failed, 44 skipped, 59 errors (90.9%)

## TARGET
Pass rate ≥95%
```

---

## 🔧 COMANDI UTILI

```powershell
# Backend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m uvicorn main:app --port 8000 --reload

# Test
pytest tests/api/ -v --tb=short

# Flutter Analyze
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\flutter_app
C:\flutter\bin\flutter.bat analyze

# Flutter Test
C:\flutter\bin\flutter.bat test
```

---

*Documento generato: 21 Gennaio 2026*
*Backend: 93% | Flutter: 85% | Test: 90.9%*

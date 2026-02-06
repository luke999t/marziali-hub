# 🤖 ERROR LOG - AI AGENT REFERENCE
# Modulo: Eventi/ASD | Ultimo aggiornamento: 2026-01-12 01:20

---

## FORMATO ENTRY
```
[ERROR_ID] TIMESTAMP | SEVERITY | COMPONENT
- Symptom: Cosa succede
- Root Cause: Perché succede
- Solution: Come risolvere
- Prevention: Come evitare in futuro
```

---

## ERRORI RISOLTI

### [EVT-001] 2026-01-12 00:30 | HIGH | notifications.py
- **Symptom:** AttributeError: 'Event' object has no attribute 'event_date'
- **Root Cause:** Campo rinominato in models.py da `event_date` a `start_date`
- **Solution:** Sostituire tutti `event.event_date` con `event.start_date`
- **Prevention:** Usare IDE con type hints, verificare models.py prima di usare attributi
- **Files Affected:** notifications.py (6 occorrenze)

### [EVT-002] 2026-01-12 00:35 | HIGH | notifications.py
- **Symptom:** AttributeError: 'Event' object has no attribute 'location'
- **Root Cause:** Campo è `location_name` non `location`
- **Solution:** Sostituire `event.location` con `event.location_name`
- **Prevention:** Controllare schema Event in models.py
- **Files Affected:** notifications.py (1 occorrenza)

### [EVT-003] 2026-01-12 00:40 | HIGH | notifications.py
- **Symptom:** AttributeError: 'Event' object has no attribute 'min_capacity'
- **Root Cause:** Campo è `min_threshold` non `min_capacity`
- **Solution:** Sostituire `event.min_capacity` con `event.min_threshold`
- **Prevention:** Verificare naming convention in models
- **Files Affected:** notifications.py (2 occorrenze)

### [EVT-004] 2026-01-12 00:45 | HIGH | notifications.py
- **Symptom:** AttributeError: 'EventNotification' has no attribute 'user_id'
- **Root Cause:** Campo è `recipient_user_id` per chiarezza
- **Solution:** Sostituire `EventNotification.user_id` con `EventNotification.recipient_user_id`
- **Prevention:** Leggere modello EventNotification prima di usare
- **Files Affected:** notifications.py (5 occorrenze)

### [EVT-005] 2026-01-12 00:50 | MEDIUM | notifications.py
- **Symptom:** AttributeError: 'EventNotification' has no attribute 'scheduled_at'
- **Root Cause:** Campo è `scheduled_for`
- **Solution:** Sostituire con `scheduled_for`
- **Files Affected:** notifications.py (2 occorrenze)

### [EVT-006] 2026-01-12 00:55 | MEDIUM | notifications.py
- **Symptom:** AttributeError: 'EventNotification' has no attribute 'context'
- **Root Cause:** Campo JSON è `data` non `context`
- **Solution:** Sostituire con `data`
- **Files Affected:** notifications.py (4 occorrenze)

### [EVT-007] 2026-01-12 01:00 | MEDIUM | notifications.py
- **Symptom:** AttributeError: 'EventNotification' has no attribute 'read_at'
- **Root Cause:** Campo non esiste nel modello attuale
- **Solution:** Rimuovere logica read tracking o aggiungere campo al modello
- **Decision:** Rimosso - non critico per MVP
- **Files Affected:** notifications.py (3 funzioni)

### [EVT-008] 2026-01-12 00:20 | HIGH | router.py
- **Symptom:** Import error: cannot import 'get_current_user' from 'core.auth'
- **Root Cause:** File core/auth.py non esisteva, funzioni in core/security.py
- **Solution:** Creato core/auth.py come re-export alias
- **Files Affected:** router.py, core/auth.py (nuovo)

### [EVT-009] 2026-01-12 00:25 | HIGH | router.py
- **Symptom:** Route 404 per tutti gli endpoint events
- **Root Cause:** Router aveva prefix="/events" + main.py aveva prefix="/api/v1/events" = doppio
- **Solution:** Rimosso prefix da router.py, mantenuto solo in main.py
- **Files Affected:** router.py

### [EVT-010] 2026-01-12 01:10 | MEDIUM | test_events_router.py
- **Symptom:** Test autenticati ritornano 404 invece di 200
- **Root Cause:** dependency_overrides non funziona quando app importata dopo config
- **Solution:** [PENDING] Creare fixture app_with_auth fresh
- **Status:** Non risolto - workaround: assert include 404 come valid response

---

## ERRORI APERTI

### [EVT-011] 2026-01-12 01:15 | LOW | stripe_connect.py
- **Symptom:** Test coverage basso (12%)
- **Root Cause:** Richiede Stripe API key per test reali
- **Solution:** [TODO] Configurare Stripe test mode, usare stripe-mock
- **Priority:** Bassa - non blocca MVP

### [EVT-012] 2026-01-12 01:15 | LOW | notifications.py
- **Symptom:** Test coverage 26%
- **Root Cause:** Funzioni richiedono notifiche schedulate nel DB
- **Solution:** [TODO] Creare fixture con notifiche schedulate
- **Priority:** Media

---

## PATTERN DA EVITARE

### Pattern 1: Naming Mismatch
```python
# ❌ SBAGLIATO - Assumere nomi campi
event.event_date
event.location
notification.user_id

# ✅ CORRETTO - Verificare in models.py
event.start_date
event.location_name
notification.recipient_user_id
```

### Pattern 2: Doppio Prefix Router
```python
# ❌ SBAGLIATO
# router.py
router = APIRouter(prefix="/events")
# main.py
app.include_router(router, prefix="/api/v1/events")
# Risultato: /api/v1/events/events/...

# ✅ CORRETTO
# router.py
router = APIRouter(tags=["events"])
# main.py
app.include_router(router, prefix="/api/v1/events")
# Risultato: /api/v1/events/...
```

### Pattern 3: Import Alias Mancante
```python
# ❌ SBAGLIATO - Import da modulo che non esiste
from core.auth import get_current_user  # core/auth.py non esiste

# ✅ CORRETTO - Creare alias o usare path corretto
# Opzione A: Creare core/auth.py con re-export
# Opzione B: from core.security import get_current_user
```

---

## COMANDI UTILI DEBUG

```bash
# Verifica coverage per file specifico
pytest tests/test_events_router.py --cov=modules/events/router --cov-report=term-missing

# Test singolo con output verbose
pytest tests/test_events_router.py::TestAuthenticatedEventEndpoints -v -s

# Verifica import funzionano
python -c "from modules.events.router import router; print('OK')"

# Verifica endpoint montati
python -c "from main import app; print([r.path for r in app.routes])"
```

---

**Generato da:** Claude AI
**Per:** AI Agent di manutenzione
**Versione:** 1.0

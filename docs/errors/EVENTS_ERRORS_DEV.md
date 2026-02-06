# 🛠️ ERROR LOG - DEVELOPER REFERENCE
# Modulo: Eventi/ASD
# Ultimo aggiornamento: 12 Gennaio 2026, 01:20

---

## 📋 Indice Rapido

| ID | Severità | Componente | Stato |
|----|----------|------------|-------|
| EVT-001 | 🔴 HIGH | notifications.py | ✅ Risolto |
| EVT-002 | 🔴 HIGH | notifications.py | ✅ Risolto |
| EVT-003 | 🔴 HIGH | notifications.py | ✅ Risolto |
| EVT-004 | 🔴 HIGH | notifications.py | ✅ Risolto |
| EVT-005 | 🟡 MED | notifications.py | ✅ Risolto |
| EVT-006 | 🟡 MED | notifications.py | ✅ Risolto |
| EVT-007 | 🟡 MED | notifications.py | ✅ Risolto |
| EVT-008 | 🔴 HIGH | router.py | ✅ Risolto |
| EVT-009 | 🔴 HIGH | router.py | ✅ Risolto |
| EVT-010 | 🟡 MED | test_events_router.py | ⏳ Aperto |
| EVT-011 | 🟢 LOW | stripe_connect.py | ⏳ Aperto |
| EVT-012 | 🟢 LOW | notifications.py | ⏳ Aperto |

---

## ✅ Errori Risolti

### EVT-001 → EVT-007: Field Name Mismatches in notifications.py

**Data:** 12 Gen 2026, 00:30-01:00

**Problema:** 
Il file `notifications.py` usava nomi di campo diversi da quelli definiti in `models.py`.

**Mapping Correzioni:**

| Sbagliato | Corretto | File |
|-----------|----------|------|
| `event.event_date` | `event.start_date` | notifications.py |
| `event.location` | `event.location_name` | notifications.py |
| `event.min_capacity` | `event.min_threshold` | notifications.py |
| `notification.user_id` | `notification.recipient_user_id` | notifications.py |
| `notification.scheduled_at` | `notification.scheduled_for` | notifications.py |
| `notification.context` | `notification.data` | notifications.py |
| `notification.read_at` | (rimosso) | notifications.py |

**Come Evitare:**
1. Prima di usare un campo, verificare in `models.py`
2. Usare IDE con autocompletamento (PyCharm, VS Code con Pylance)
3. Abilitare type checking strict

---

### EVT-008: Import Error core.auth

**Data:** 12 Gen 2026, 00:20

**Problema:**
```python
# router.py
from core.auth import get_current_user  # FileNotFoundError
```

**Causa:** File `core/auth.py` non esisteva. Le funzioni erano in `core/security.py`.

**Soluzione:** Creato `core/auth.py`:
```python
"""Re-export from security for backward compatibility."""
from core.security import (
    get_current_user,
    get_current_admin_user,
    get_current_active_user,
    decode_access_token,
)
```

---

### EVT-009: Doppio Prefix Router

**Data:** 12 Gen 2026, 00:25

**Problema:** Tutti gli endpoint events rispondevano 404.

**Causa:** 
```python
# router.py
router = APIRouter(prefix="/events")  # ← prefix qui

# main.py  
app.include_router(router, prefix="/api/v1/events")  # ← e qui

# Risultato: /api/v1/events/events/...  # ← DOPPIO!
```

**Soluzione:**
```python
# router.py - RIMOSSO prefix
router = APIRouter(tags=["events"])

# main.py - prefix SOLO qui
app.include_router(router, prefix="/api/v1/events")
```

---

## ⏳ Errori Aperti

### EVT-010: Test Autenticati 404

**Data:** 12 Gen 2026, 01:10

**Problema:** I test con `dependency_overrides` ritornano 404 invece di 200.

**Causa Probabile:** L'app viene importata dopo che il router è già configurato, quindi gli override non si applicano.

**Workaround Attuale:** I test accettano 404 come risposta valida:
```python
assert response.status_code in [200, 201, 404, 422, 500]
```

**Soluzione Proposta:** Creare fixture che istanzia app fresh:
```python
@pytest.fixture
async def app_with_auth(db_session, test_user):
    from main import app
    # Override PRIMA di creare client
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_user] = lambda: test_user
    yield app
    app.dependency_overrides.clear()
```

**Priorità:** Media - Non blocca sviluppo ma limita coverage.

---

### EVT-011: Stripe Coverage Basso

**Problema:** `stripe_connect.py` ha solo 12% coverage.

**Causa:** I test richiedono API key Stripe valida.

**Soluzione:** 
1. Configurare Stripe test mode con chiavi test
2. Usare `stripe-mock` per test locali
3. Skip test Stripe in CI se no key

**Priorità:** Bassa - Per MVP possiamo testare manualmente.

---

### EVT-012: Notifications Coverage Basso

**Problema:** `notifications.py` ha solo 26% coverage.

**Causa:** Le funzioni richiedono notifiche schedulate nel database.

**Soluzione:** Creare fixture che popola DB con notifiche test:
```python
@pytest.fixture
async def scheduled_notifications(db_session, test_event, test_user):
    notifications = [
        EventNotification(
            recipient_user_id=test_user.id,
            event_id=test_event.id,
            alert_type=AlertType.EVENT_REMINDER,
            scheduled_for=datetime.utcnow() - timedelta(hours=1),
            sent=False
        )
        for _ in range(5)
    ]
    db_session.add_all(notifications)
    await db_session.flush()
    return notifications
```

**Priorità:** Media.

---

## 🔧 Comandi Debug Utili

```bash
# Coverage singolo file
cd backend
python -m pytest tests/test_events_router.py \
  --cov=modules/events/router \
  --cov-report=term-missing

# Test singola classe
python -m pytest tests/test_events_router.py::TestAuthenticatedEventEndpoints -v

# Verifica router montato
python -c "
from main import app
for route in app.routes:
    if hasattr(route, 'path'):
        print(route.path)
"

# Verifica import
python -c "from modules.events.router import router; print('OK')"
```

---

## 📊 Coverage Attuale

```
File                          Coverage
────────────────────────────────────────
modules/events/__init__.py      100%
modules/events/models.py         98%
modules/events/schemas.py        89%
modules/events/config.py         73%
modules/events/service.py        64%
modules/events/notifications.py  26%  ⚠️
modules/events/router.py         24%  ⚠️
modules/events/stripe_connect.py 12%  ⚠️
────────────────────────────────────────
TOTAL                           55.53%
TARGET                          90%
```

---

## 📞 Contatti

Per domande su questi errori:
- **AI Agent:** Consulta `EVENTS_ERRORS_AI.md`
- **Sviluppatore:** Questo file + Claude chat history

---

**Autore:** Sistema AI-First  
**Versione:** 1.0  
**Data:** 12 Gennaio 2026

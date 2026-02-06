# 📚 LESSONS LEARNED - Media Center Arti Marziali
## Data: 2025-01-09

---

## 🎯 SUMMARY SESSIONE

| Metrica | Valore |
|---------|--------|
| **Durata Debug** | ~6 ore |
| **Errori Critici Risolti** | 5 |
| **Test Prima** | 11/30 (37%) |
| **Test Dopo** | 18/18 special_projects (100%) |
| **Tempo Risparmiato Futuro** | ~10 ore |

---

## 🔴 ERRORE 1: SQLAlchemy Relationships Rotte (CRITICO)

### Sintomo
- Endpoint admin `/api/v1/special-projects/admin/config` ritorna **403 Forbidden**
- Utente ha `is_admin=True` nel database
- Login funziona, JWT valido
- Debug logging in `get_current_admin_user` **MAI CHIAMATO**

### Root Cause
Il modello `User` aveva relazioni commentate:
```python
# models/user.py
# payments = relationship("Payment", back_populates="user")  # COMMENTATO
# subscription = relationship("Subscription", back_populates="user")  # COMMENTATO
```

Ma altri modelli avevano ancora `back_populates` attivi:
```python
# models/payment.py
user = relationship("User", back_populates="payments")  # PUNTA A RELAZIONE MORTA!
```

SQLAlchemy falliva durante l'inizializzazione **PRIMA** di raggiungere il codice di autenticazione.

### Soluzione
```python
# RIMUOVERE back_populates da TUTTI i modelli che puntano a User

# models/payment.py
user = relationship("User")  # Senza back_populates

# models/communication.py  
from_user = relationship("User", foreign_keys=[from_user_id])  # Senza back_populates

# models/user_video.py
user = relationship("User")  # Senza back_populates
```

### 🛡️ Prevenzione
```bash
# Prima di commentare relazioni, cerca chi le usa:
grep -r 'back_populates=' models/ | grep 'NOME_RELAZIONE'
```

---

## 🔴 ERRORE 2: ENUM PostgreSQL Incompatibile (CRITICO)

### Sintomo
- **500 Internal Server Error** su tutti gli endpoint special_projects
- Errore: `InvalidTextRepresentationError: la sintassi per l'enumerazione project_status non è valida: "DRAFT"`

### Root Cause
- SQLAlchemy passa valori **UPPERCASE** (`DRAFT`, `ACTIVE`)
- PostgreSQL ENUM richiede **lowercase** (`draft`, `active`)
- Anche `native_enum=False` non risolve completamente
- SQLAlchemy genera comunque cast `::project_status`

### Soluzione
**RIMUOVERE COMPLETAMENTE SQLEnum e usare VARCHAR:**

```python
# PRIMA (problematico)
from sqlalchemy import Enum as SQLEnum
status = Column(SQLEnum(ProjectStatus, name='project_status'), default=ProjectStatus.DRAFT)

# DOPO (funzionante)
status = Column(String(50), default=ProjectStatus.DRAFT.value)
```

**Pulizia database:**
```sql
DROP TABLE IF EXISTS special_projects CASCADE;
DROP TYPE IF EXISTS project_status;
DROP TYPE IF EXISTS eligibility_status;
```

### 🛡️ Prevenzione
> ⚠️ **REGOLA D'ORO**: Mai usare `SQLEnum` con PostgreSQL async (asyncpg).
> Usare sempre `String(50)` con validazione Pydantic nel schema.

---

## 🟠 ERRORE 3: FastAPI Route Ordering (ALTO)

### Sintomo
- Endpoint `/my-eligibility`, `/my-vote`, `/my-history` ritornano **422 Unprocessable Entity**
- Errore: `value is not a valid uuid`

### Root Cause
FastAPI matcha le route **nell'ordine di definizione**:

```python
# ORDINE SBAGLIATO - /{project_id} cattura TUTTO!
@router.get("/{project_id}")      # ← Matcha anche "my-eligibility" come UUID!
async def get_project(...): ...

@router.get("/my-eligibility")    # ← Mai raggiunto!
async def check_eligibility(...): ...
```

### Soluzione
```python
# ORDINE CORRETTO - Specifiche PRIMA, dinamiche DOPO

@router.get("/health")            # 1. Static paths
@router.get("/my-eligibility")    # 2. Specific paths
@router.get("/my-vote")
@router.get("/my-history")
@router.get("/slug/{slug}")       # 3. Paths con parametri specifici
@router.get("/{project_id}")      # 4. Catch-all ULTIMO!
```

### 🛡️ Prevenzione
Aggiungere commento nel codice:
```python
# ⚠️ NOTE: Specific routes MUST come BEFORE /{param} routes!
```

---

## 🟡 ERRORE 4: AttributeError .value (MEDIO)

### Sintomo
- **500 Internal Server Error** dopo migrazione ENUM → VARCHAR
- Errore: `AttributeError: 'str' object has no attribute 'value'`

### Root Cause
Dopo il cambio da ENUM a VARCHAR, la colonna `status` è una **stringa**, non un enum:

```python
# PRIMA (con ENUM)
status = EligibilityStatusEnum(eligibility.status.value)  # .value necessario

# DOPO (con VARCHAR)  
status = EligibilityStatusEnum(eligibility.status)  # .value NON esiste!
```

### Soluzione
```python
# Rimuovere .value
status = EligibilityStatusEnum(eligibility.status)  # ✅
```

### 🛡️ Prevenzione
```bash
# Dopo migrazione ENUM → VARCHAR, cercare tutti i .value:
grep -r '\.status\.value' modules/
```

---

## 🟡 ERRORE 5: SQLAlchemy Load All Relationships (MEDIO)

### Sintomo
- `get_current_user` fallisce silenziosamente
- Errori di relazione durante query semplici

### Root Cause
SQLAlchemy carica **tutte le relazioni** di default, incluse quelle rotte.

### Soluzione
Usare `load_only()` per caricare solo i campi necessari:

```python
from sqlalchemy.orm import load_only

result = await db.execute(
    select(User).options(
        load_only(
            User.id, User.email, User.username, 
            User.hashed_password, User.is_admin, User.is_active
        )
    ).where(...)
)
```

---

## 📋 QUICK REFERENCE - Comandi Utili

### Debug Relazioni SQLAlchemy
```bash
# Trova tutti i back_populates
grep -r 'back_populates=' models/

# Trova back_populates a User
grep -r 'back_populates=' models/ | grep -i user
```

### Debug ENUM PostgreSQL
```sql
-- Lista tutti gli ENUM types
SELECT typname FROM pg_type WHERE typtype = 'e';

-- Valori di un ENUM
SELECT enumlabel FROM pg_enum WHERE enumtypid = 'project_status'::regtype;
```

### Debug Route FastAPI
```bash
# Test endpoint specifico
curl -s http://localhost:8000/api/v1/special-projects/my-eligibility

# Se ritorna 422 con "not a valid uuid", il problema è l'ordine delle route
```

### Test Suite
```bash
# Run tutti i test real
python -m pytest tests/real/ -v --tb=short

# Run solo special_projects
python -m pytest tests/real/test_special_projects_real.py -v

# Test singolo con output dettagliato
python -m pytest tests/real/test_special_projects_real.py::TestVoting::test_get_my_vote -v --tb=long
```

---

## 🎓 PATTERN APPRESI

### 1. SQLAlchemy Relationships
```
📌 REGOLA: Se commenti una relazione in Model A, 
   DEVI rimuovere back_populates in TUTTI i modelli che la referenziano.
```

### 2. PostgreSQL ENUM
```
📌 REGOLA: Mai usare SQLEnum con asyncpg.
   Usa String(50) + validazione Pydantic.
```

### 3. FastAPI Routing
```
📌 REGOLA: Route specifiche PRIMA, parametri dinamici DOPO.
   /health → /my-vote → /{id}
```

### 4. Migrazione Database
```
📌 REGOLA: Dopo cambio tipo colonna, cercare e aggiornare
   tutti gli accessi nel codice Python.
```

---

## 📊 IMPATTO

| Errore | Tempo Debug | Tempo Risparmiato Futuro |
|--------|-------------|--------------------------|
| SQLAlchemy Relationships | 4+ ore | 4 ore |
| ENUM PostgreSQL | 3+ ore | 3 ore |
| FastAPI Route Ordering | 30 min | 1 ora |
| AttributeError .value | 15 min | 30 min |
| load_only() | 1 ora | 1 ora |
| **TOTALE** | **~9 ore** | **~10 ore** |

---

## ✅ CHECKLIST FUTURA

Prima di committare codice con modifiche a:

- [ ] **Relazioni SQLAlchemy** → Verificare back_populates in altri file
- [ ] **Colonne ENUM** → Usare String(50), mai SQLEnum con asyncpg
- [ ] **Route FastAPI** → Verificare ordine (specifiche prima)
- [ ] **Tipo colonne DB** → Aggiornare codice Python che le accede

---

*Documento generato automaticamente - AI-First Knowledge System*
*Ultimo aggiornamento: 2025-01-09*

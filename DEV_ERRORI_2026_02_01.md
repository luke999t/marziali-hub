# 🔧 DEV ERRORI - 01/02/2026

## Documento per Sviluppatori

---

## 🔴 ERRORI CRITICI DA FIXARE

### 1. BUG-DB-001: Colonna `subscriptions.status` non esiste

**Gravità**: 🔴 CRITICA
**File**: `backend/api/v1/admin.py` linea 229
**Endpoint**: `GET /api/v1/admin/analytics/platform`

**Errore completo**:
```
asyncpg.exceptions.UndefinedColumnError: la colonna subscriptions.status non esiste
[SQL: SELECT count(*) AS count_1 FROM subscriptions 
      WHERE subscriptions.status IN ($1::subscriptionstatus, $2::subscriptionstatus)]
[parameters: ('ACTIVE', 'TRIALING')]
```

**Causa**: Il modello SQLAlchemy usa una colonna `status` che non esiste nel DB PostgreSQL. Probabilmente la migrazione Alembic non è stata eseguita.

**Fix**:
```bash
# Opzione 1: Esegui migrazione
cd backend
alembic upgrade head

# Opzione 2: Crea manualmente la colonna
psql -U postgres -d mediacenter -c "ALTER TABLE subscriptions ADD COLUMN status VARCHAR(20) DEFAULT 'ACTIVE';"

# Opzione 3: Fix nel codice admin.py - usa colonna esistente
# Verifica prima le colonne esistenti:
psql -U postgres -d mediacenter -c "\d subscriptions"
```

---

### 2. BUG-REDIRECT-307: Curricula perde token su redirect

**Gravità**: 🔴 CRITICA
**Endpoint**: `GET /api/v1/curricula` → redirect 307 → `/api/v1/curricula/`

**Log**:
```
INFO: "GET /api/v1/curricula HTTP/1.1" 307 Temporary Redirect
INFO: "GET /api/v1/curricula/ HTTP/1.1" 401 Unauthorized
```

**Causa**: FastAPI con `redirect_slashes=True` fa redirect, ma il browser non rinvia l'header `Authorization` nel secondo request.

**Fix Backend** (preferito):
```python
# main.py - disabilita redirect automatico
app = FastAPI(redirect_slashes=False)
```

**Fix Frontend** (alternativo):
```typescript
// curriculumApi.ts - aggiungi sempre trailing slash
const url = `${CURRICULUM_API_BASE}/`;  // NON senza slash
```

---

### 3. BUG-SKELETON-404: Endpoint skeleton errati nel frontend

**Gravità**: 🟡 MEDIA
**Endpoint chiamati sbagliati**:
- `/api/v1/skeletons` → 404
- `/api/v1/skeleton` → 404  
- `/api/studio/skeletons` → 404

**Endpoint CORRETTO**: `/api/v1/videos/skeletons` → 200 OK

**Fix Frontend**:
```typescript
// Cerca e correggi in:
// - frontend/src/services/skeletonApi.ts
// - frontend/src/hooks/useSkeleton*.ts

// SBAGLIATO:
const url = '/api/v1/skeletons';
const url = '/api/studio/skeletons';

// CORRETTO:
const url = '/api/v1/videos/skeletons';
```

---

### 4. BUG-AUTH-401: Token non inviato in alcune chiamate

**Gravità**: 🟡 MEDIA  
**Endpoint**: `GET /api/v1/users/me`, `GET /api/v1/sections`

**Log**:
```
=== GET_CURRENT_USER CALLED ===
INFO: "GET /api/v1/users/me HTTP/1.1" 401 Unauthorized
INFO: "GET /api/v1/sections HTTP/1.1" 401 Unauthorized
```

**Causa**: Il componente React chiama l'API prima che `AuthContext` abbia caricato il token da localStorage.

**Fix già presente ma da verificare**:
```typescript
// useIngestProjects.ts - pattern corretto
const { token, isLoading: authLoading } = useAuth();

useEffect(() => {
  // Attendi che auth sia pronto E token sia disponibile
  if (!authLoading && token) {
    fetchData();
  }
}, [token, authLoading]);
```

**Verifica**: Controlla che TUTTI gli hook che chiamano API autenticate usino questo pattern.

---

### 5. BUG-LOGIN-422: Login con payload errato

**Gravità**: 🟢 BASSA
**Endpoint**: `POST /api/v1/auth/login`

**Log**:
```
INFO: "POST /api/v1/auth/login HTTP/1.1" 422 Unprocessable Entity
```

**Causa**: Il frontend a volte manda payload malformato (campi mancanti o formato sbagliato).

**Fix**: Validare lato frontend prima di inviare:
```typescript
// Verifica che email e password siano presenti e validi
if (!email || !password) {
  throw new Error('Email e password richiesti');
}
```

---

## ⚠️ WARNING SISTEMA

### Risorse Critiche
```
Health check: Memory HIGH (95.7%)
Health check: Disk HIGH (99.7%)
```

**Azione**: 
1. Chiudi applicazioni non necessarie
2. Svuota cartella temp: `del /q/f/s %TEMP%\*`
3. Libera spazio disco

### Librerie Mancanti (opzionali)
```
WARNING: fastdtw not available
WARNING: web3 not installed - blockchain features disabled
WARNING: ipfshttpclient not installed - IPFS features disabled
```

**Azione**: Installa se necessario:
```bash
pip install fastdtw web3 ipfshttpclient merkletools
```

### Warning bcrypt (ignorabile)
```
WARNING:passlib.handlers.bcrypt:(trapped) error reading bcrypt version
AttributeError: module 'bcrypt' has no attribute '__about__'
```

**Causa**: Versione bcrypt incompatibile con passlib. Non impatta il funzionamento.

---

## 📋 CHECKLIST FIX

- [ ] Fix BUG-DB-001: Aggiungi colonna status a subscriptions
- [ ] Fix BUG-REDIRECT-307: Disabilita redirect_slashes o aggiungi trailing slash
- [ ] Fix BUG-SKELETON-404: Correggi URL skeleton nel frontend
- [ ] Verifica BUG-AUTH-401: Tutti gli hook usano pattern authLoading
- [ ] Libera memoria/disco se necessario

---

## 🧪 COME TESTARE I FIX

```bash
# 1. Riavvia backend
cd backend
python -m uvicorn main:app --port 8000 --reload

# 2. Testa endpoint
curl http://localhost:8000/api/v1/admin/analytics/platform -H "Authorization: Bearer TOKEN"
curl http://localhost:8000/api/v1/curricula/ -H "Authorization: Bearer TOKEN"
curl http://localhost:8000/api/v1/videos/skeletons

# 3. Testa nel browser
# - Login
# - Vai a /curriculum
# - Vai a /ingest-studio
# - Controlla console per errori 401/404
```

---

*Ultimo aggiornamento: 01/02/2026 21:30*

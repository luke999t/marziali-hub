# 📚 LESSONS LEARNED - Media Center Arti Marziali
## Data: 2025-01-10

---

## 🎯 SUMMARY SESSIONE

| Metrica | Valore |
|---------|--------|
| **Problema Principale** | Login timeout / Database non raggiungibile |
| **Root Cause** | Docker bloccava PostgreSQL locale |
| **Errori Risolti** | 4 |
| **Test Royalties Prima** | 9/12 (75%) + timeout |
| **Test Royalties Dopo** | 11/12 (92%) + 1 skip |
| **Login/Register** | ✅ Funzionante |

---

## 🔴 ERRORE 1: Docker Blocca PostgreSQL Locale (CRITICO)

### Sintomo
- Backend risponde a `/health` ma va in **timeout** su `/api/v1/auth/login`
- Nessun errore visibile nei log uvicorn
- Test falliscono con "asyncpg connection timeout"

### Diagnosi
```powershell
# Controlla chi usa la porta 5432
netstat -ano | findstr :5432
# Output: TCP 0.0.0.0:5432 ... PID 6120

# Controlla quale processo è
tasklist | findstr 6120
# Output: com.docker.backend.exe
```

### Root Cause
- Il progetto era configurato per PostgreSQL **LOCALE** (vedi `.env`)
- Docker Desktop aveva un container `mcam-postgres` che occupava porta 5432
- Il servizio Windows `postgresql-x64-15` era **STOPPED**
- Le connessioni andavano a Docker (che non rispondeva) invece che a PostgreSQL locale

### Soluzione
```powershell
# 1. Chiudi Docker Desktop completamente

# 2. Apri PowerShell come AMMINISTRATORE

# 3. Avvia PostgreSQL Windows
net start postgresql-x64-15

# 4. Verifica
psql -U postgres -c "\l"
```

### 🛡️ Prevenzione
> ⚠️ **REGOLA**: Scegliere Docker O PostgreSQL locale, MAI entrambi sulla stessa porta.
> Documentare la scelta nel README del progetto.

### Configurazione Attuale (`.env`)
```env
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db
```

---

## 🔴 ERRORE 2: Relationship Mancante (ALTO)

### Sintomo
```
InvalidRequestError: Mapper 'Mapper[Video(videos)]' has no property 'user_progress'
```

### Root Cause
In `models/user_video.py`:
```python
video = relationship("Video", back_populates="user_progress")
```

Ma in `models/video.py` **mancava** la relazione corrispondente.

### Soluzione
Aggiunto in `models/video.py` (linea 150):
```python
user_progress = relationship("UserVideo", back_populates="video")
```

### 🛡️ Prevenzione
```bash
# Prima di creare back_populates, verificare che esista nell'altro model
grep -r "user_progress" models/
```

---

## 🔴 ERRORE 3: Colonne Mancanti Tabella Users (ALTO)

### Sintomo
```
ProgrammingError: la colonna users.tier non esiste
```

### Root Cause
Il model `User` aveva nuove colonne che non esistevano nel database:
- `tier`
- `subscription_end`
- `auto_renew`
- `ads_unlocked_videos`
- `language_preference`
- etc.

### Soluzione
Creato ed eseguito script di migrazione:
```bash
python migrations/run_migration.py
```

Colonne aggiunte:
| Colonna | Tipo |
|---------|------|
| tier | usertier (enum) |
| subscription_end | timestamp |
| auto_renew | boolean |
| stripe_customer_id | varchar(100) |
| ads_unlocked_videos | integer |
| ads_unlock_valid_until | timestamp |
| language_preference | varchar(10) |
| subtitle_preference | varchar(10) |
| quality_preference | varchar(10) |
| last_seen | timestamp |

### 🛡️ Prevenzione
> ⚠️ **REGOLA**: Usare Alembic per migrazioni automatiche.
> Ogni modifica al model DEVE avere migrazione corrispondente.

---

## 🔴 ERRORE 4: ENUM Case Mismatch SQLAlchemy/PostgreSQL (CRITICO)

### Sintomo
```
'premium' is not among the defined enum values. 
Possible values: FREE, HYBRID_LIGHT, HYBRID_STANDARD, PREMIUM...
```

### Root Cause
- PostgreSQL ENUM `usertier` ha valori **lowercase**: `free`, `premium`, `hybrid_light`
- SQLAlchemy Enum usava i **NOMI** (uppercase): `FREE`, `PREMIUM`, `HYBRID_LIGHT`

```python
# PROBLEMA: SQLAlchemy usa enum.name (FREE) invece di enum.value (free)
tier = Column(Enum(UserTier), default=UserTier.FREE)
```

### Soluzione
Aggiungere `values_callable` per forzare i valori lowercase:

```python
# PRIMA (ERRATO)
tier = Column(Enum(UserTier), default=UserTier.FREE, nullable=False, index=True)

# DOPO (CORRETTO)
tier = Column(
    Enum(UserTier, values_callable=lambda x: [e.value for e in x], name='usertier', create_type=False),
    default=UserTier.FREE, nullable=False, index=True
)
```

### Spiegazione
- `values_callable=lambda x: [e.value for e in x]` → Usa `.value` (lowercase)
- `name='usertier'` → Nome del tipo ENUM esistente in PostgreSQL
- `create_type=False` → Non creare nuovo tipo, usa quello esistente

### Verifica
```bash
# Check valori nel DB
psql -U martial_user -d martial_arts_db -c "SELECT enum_range(NULL::usertier);"
# Output: {free,hybrid_light,hybrid_standard,premium,pay_per_view,business}

# Check valori Python
python -c "from models.user import UserTier; print([e.value for e in UserTier])"
# Output: ['free', 'hybrid_light', 'hybrid_standard', 'premium', 'pay_per_view', 'business']
```

### 🛡️ Prevenzione
> ⚠️ **REGOLA**: Quando un ENUM PostgreSQL esiste già, SEMPRE usare:
> ```python
> Enum(MyEnum, values_callable=lambda x: [e.value for e in x], name='enum_name', create_type=False)
> ```

---

## 📋 QUICK REFERENCE

### Avvio PostgreSQL Locale (Admin PowerShell)
```powershell
net start postgresql-x64-15
```

### Verifica Database
```powershell
psql -U martial_user -d martial_arts_db -c "\dt"
# Password: martial_pass
```

### Avvio Backend
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Test Login
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"test@test.com","password":"Test12345"}'
```

### Test Royalties
```powershell
python -m pytest tests/real/test_royalties_real.py -v
```

---

## ✅ STATO FINALE

| Componente | Stato |
|------------|-------|
| PostgreSQL locale | ✅ Attivo (porta 5432) |
| Docker | ❌ Chiuso (non necessario) |
| Backend FastAPI | ✅ Funzionante |
| Autenticazione | ✅ Login/Register OK |
| Test Royalties | ✅ 11/12 pass + 1 skip |
| Test Special Projects | ✅ 18/18 pass (sessione precedente) |

---

## 🎓 LEZIONI CHIAVE

1. **Docker vs Locale**: Mai usare entrambi sulla stessa porta
2. **Relationships SQLAlchemy**: Ogni `back_populates` richiede relazione nell'altro model
3. **Migrazioni DB**: Sempre sincronizzare model Python con schema PostgreSQL
4. **ENUM SQLAlchemy+PostgreSQL**: Usare `values_callable` per matchare case

---

*Documento generato: 2025-01-10*
*AI-First Knowledge System - Media Center Arti Marziali*

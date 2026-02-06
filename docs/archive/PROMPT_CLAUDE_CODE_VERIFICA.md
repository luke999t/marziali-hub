# 🔧 PROMPT PER CLAUDE CODE - VERIFICA POST-TEST

## CONTESTO

Stiamo eseguendo test utente massivi sull'App Staff del Media Center Arti Marziali.
Chrome Extension sta testando tutte le 35 pagine del frontend.
Tu (Claude Code) devi verificare:
1. Backend funziona correttamente
2. Database ha i dati corretti
3. Errori nei log
4. API endpoints rispondono

## COMANDI DA ESEGUIRE

### 1. Verifica Backend Attivo
```bash
curl -s http://localhost:8000/health | jq
```

### 2. Verifica Database
```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -c "
from core.database import SessionLocal
from sqlalchemy import text
db = SessionLocal()
result = db.execute(text('SELECT COUNT(*) FROM users')).scalar()
print(f'Utenti nel DB: {result}')
db.close()
"
```

### 3. Conta Dati di Test Creati
```bash
python cleanup_test_data.py --dry-run
```

### 4. Verifica Endpoint Principali
```bash
# Health
curl -s http://localhost:8000/health

# Auth
curl -s http://localhost:8000/api/v1/auth/me -H "Authorization: Bearer TOKEN"

# Videos
curl -s http://localhost:8000/api/v1/videos?limit=5

# Avatars
curl -s http://localhost:8000/api/v1/avatars?limit=5

# Fusion Projects
curl -s http://localhost:8000/api/v1/fusion/projects?limit=5
```

### 5. Controlla Log Errori
```bash
# Se ci sono log file
tail -100 logs/app.log | grep -i error

# Oppure controlla stderr uvicorn
```

### 6. Test API con Autenticazione
```bash
# Login e ottieni token
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mediacenter.it","password":"Test123!"}' | jq -r '.access_token')

echo "Token: $TOKEN"

# Usa token per chiamate autenticate
curl -s http://localhost:8000/api/v1/users/me -H "Authorization: Bearer $TOKEN"
```

## COSA VERIFICARE

1. **Backend risponde** a /health
2. **Login funziona** con credenziali test
3. **API restituiscono dati** (non errori 500)
4. **Database ha dati** (utenti, video, etc.)
5. **Nessun errore critico** nei log

## REPORT

Dopo le verifiche, riporta:
- ✅ Backend: OK/KO
- ✅ Database: OK/KO (count record)
- ✅ Auth: OK/KO
- ✅ API: OK/KO (quante funzionano)
- ✅ Errori: Lista errori trovati

## PATH PROGETTO

```
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\
├── backend\         # FastAPI
├── frontend\        # Next.js
└── MEGA_TEST_PLAN_STAFF_APP.md  # Test plan
```

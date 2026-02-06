# 🔑 Credenziali di Sviluppo - Media Center Arti Marziali

**Data**: 20 Novembre 2024

⚠️ **ATTENZIONE**: Queste credenziali sono SOLO per sviluppo locale!
⚠️ **NON usare in produzione**

---

## 🗄️ PostgreSQL Database

**Server**:
- Host: `localhost`
- Porta: `5432`
- Database: `martial_arts_db`

**Utente Applicazione**:
- Username: `martial_user`
- Password: `martial_pass`

**Superutente PostgreSQL**:
- Username: `postgres`
- Password: `postgres`

**Connessione diretta**:
```bash
psql -U martial_user -d martial_arts_db -h localhost -p 5432
# Password: martial_pass

# Oppure come superutente:
psql -U postgres -h localhost -p 5432
# Password: postgres
```

---

## 🔐 Backend API

**JWT Configuration**:
- SECRET_KEY: `dev-secret-key-change-in-production-12345678901234567890`
- ALGORITHM: `HS256`
- Access Token Expiry: `30 minuti` (1800 secondi)
- Refresh Token Expiry: `7 giorni`

**Endpoint Base**:
- Backend API: `http://127.0.0.1:8000`
- API Docs: `http://127.0.0.1:8000/docs`
- API v1: `http://127.0.0.1:8000/api/v1`

---

## 👥 Utenti di Test

Utenti già creati nel database per test:

1. **Mario**
   - Username: `mario`
   - Email: `mario@test.com`
   - Password: `Test1234`

2. **Luca**
   - Username: `luca`
   - Email: `luca@test.com`
   - Password: `Test1234`

3. **Giovanni**
   - Username: `giovanni`
   - Email: `giovanni@test.com`
   - Password: `Test1234`

---

## 📱 Frontend Mobile

**Expo Web**:
- URL: `http://localhost:19006`

**API Configuration**:
- API_BASE_URL: `http://127.0.0.1:8000/api/v1`

---

## 📄 File `.env`

**Location**: `backend/.env`

**Contenuto**:
```env
# === Environment ===
ENVIRONMENT=development
RELEASE=v1.0.0

# === Database (PostgreSQL on port 5432) ===
DATABASE_URL=postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db
DATABASE_URL_ASYNC=postgresql+asyncpg://martial_user:martial_pass@localhost:5432/martial_arts_db

# === JWT Authentication ===
SECRET_KEY=dev-secret-key-change-in-production-12345678901234567890
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# === CORS ===
CORS_ORIGINS=http://localhost:19006,http://localhost:3000,http://127.0.0.1:19006
```

---

## 🚀 Quick Start

### 1. Avviare Backend:
```bash
cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

### 2. Verificare Backend:
```bash
curl http://127.0.0.1:8000/health
```

### 3. Test Registrazione:
```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"Test1234"}'
```

### 4. Avviare Frontend Mobile:
```bash
cd mobile
npx serve web-build --listen 19006
```

---

## 🔧 Comandi Utili PostgreSQL

**Vedere tutti i database**:
```bash
psql -U postgres -l
```

**Connettersi al database**:
```bash
psql -U martial_user -d martial_arts_db
```

**Vedere tutte le tabelle**:
```sql
\dt
```

**Vedere tutti gli utenti nel database**:
```sql
SELECT username, email, tier, is_active, created_at FROM users;
```

**Eliminare tutti gli utenti di test**:
```sql
DELETE FROM users WHERE email LIKE '%@test.com';
```

---

## 📊 Database Schema

**Tabelle Principali**:
- `users` - Utenti registrati
- `videos` - Video caricati
- `maestros` - Maestri/istruttori
- `asds` - Associazioni sportive
- `courses` - Corsi
- `donations` - Donazioni
- `live_events` - Eventi live
- (31 tabelle in totale)

---

## ⚠️ Sicurezza

**DA FARE prima del deploy in produzione**:

- [ ] Cambiare TUTTE le password
- [ ] Generare nuovo SECRET_KEY (min 32 caratteri random)
- [ ] Configurare variabili d'ambiente (non hardcoded)
- [ ] Abilitare SSL/TLS
- [ ] Configurare firewall
- [ ] Setup backup automatici
- [ ] Limitare accessi al database
- [ ] Abilitare logging e monitoring

---

**Ultimo aggiornamento**: 20 Novembre 2024
**Stato**: ✅ Database configurato e funzionante
**Test**: ✅ Registrazione utente testata e funzionante

# QUICK START - Testing Backend
## Media Center Arti Marziali

**Data:** 23/11/2025
**Status:** Pronto per testing

---

## RIEPILOGO RAPIDO

Sono stati creati 3 deliverable principali:

1. **Report Completo** - Analisi dettagliata di tutti i test
2. **Suite di Test** - Script automatici per testare le API
3. **Script di Setup** - Tool per configurare profili Admin/Maestro/ASD

---

## FILE CREATI

### Documentazione

| File | Descrizione |
|------|-------------|
| `REPORT_TEST_FINALE.md` | Report completo con tutti i risultati dei test |
| `UTENTI_TEST_E_ACCESSI.md` | Credenziali di accesso per tutti gli utenti |
| `README_SETUP_PROFILI.md` | Guida completa per configurazione profili |
| `QUICK_START_TESTING.md` | Questo file - Quick start |

### Script di Test

| File | Descrizione |
|------|-------------|
| `test_api_endpoints.py` | Test base delle API (già usato) |
| `test_api_detailed.py` | Test approfonditi con 44 test case |
| `create_test_users_via_api.py` | Creazione utenti (già eseguito) |

### Script di Setup

| File | Descrizione |
|------|-------------|
| `setup_admin_simple.py` | Configura flag admin |
| `setup_maestro_profile.py` | Crea profilo Maestro completo |
| `setup_asd_profile.py` | Crea profilo ASD completo |

---

## STATO ATTUALE

### Cosa Funziona

- **Autenticazione**: 100% funzionante (tutti i 6 utenti possono fare login)
- **Infrastructure**: Health check, docs, API base - tutto OK
- **Utenti creati**: 6 utenti di test con tier diversi

### Cosa Richiede Configurazione

- **Profilo Admin**: Serve eseguire `setup_admin_simple.py`
- **Profilo Maestro**: Serve eseguire `setup_maestro_profile.py`
- **Profilo ASD**: Serve eseguire `setup_asd_profile.py`

---

## SETUP IN 3 MINUTI

### Step 1: Configura Profili (1 minuto)

```bash
cd backend

# Setup Admin
python setup_admin_simple.py

# Setup Maestro
python setup_maestro_profile.py

# Setup ASD
python setup_asd_profile.py
```

### Step 2: Riavvia Backend (30 secondi)

```bash
# Ferma il processo corrente (Ctrl+C)
# Poi riavvia:
python -m uvicorn main:app --reload
```

### Step 3: Testa API (1 minuto)

```bash
# Test rapido
python test_api_endpoints.py

# Test completo (opzionale)
python test_api_detailed.py
```

---

## CREDENZIALI UTENTI

### Admin
- Email: `admin@mediacenter.it`
- Password: `Admin2024!`
- Tier: PREMIUM
- Accesso: Tutti gli endpoint admin dopo setup

### Maestro Premium
- Email: `maestro.premium@mediacenter.it`
- Password: `Maestro2024!`
- Tier: PREMIUM
- Accesso: Endpoint maestro dopo setup

### Studente Premium
- Email: `studente.premium@mediacenter.it`
- Password: `Student2024!`
- Tier: PREMIUM
- Accesso: Tutti i contenuti

### Utente Hybrid
- Email: `utente.hybrid@mediacenter.it`
- Password: `Hybrid2024!`
- Tier: HYBRID_STANDARD
- Accesso: 10 video/mese

### Utente Free
- Email: `utente.free@mediacenter.it`
- Password: `Free2024!`
- Tier: FREE
- Accesso: Contenuti gratuiti

### ASD Manager
- Email: `asd.admin@mediacenter.it`
- Password: `Asd2024!`
- Tier: BUSINESS
- Accesso: Gestione associazione dopo setup

---

## TEST RAPIDI VIA CURL

### 1. Health Check
```bash
curl http://localhost:8000/health
```

### 2. Login
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mediacenter.it","password":"Admin2024!"}'
```

### 3. Get Profile
```bash
# Sostituisci TOKEN con il token ricevuto dal login
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer TOKEN"
```

---

## TEST VIA SWAGGER

1. Apri: http://localhost:8000/docs
2. Click su "Authorize" (lucchetto in alto a destra)
3. Fai login con uno degli utenti sopra
4. Copia il token dalla risposta
5. Incollalo nel campo "Value" (aggiungi "Bearer " prima)
6. Click "Authorize"
7. Testa gli endpoint

---

## STRUTTURA PROGETTO

```
backend/
├── REPORT_TEST_FINALE.md              # Report completo test
├── UTENTI_TEST_E_ACCESSI.md           # Credenziali utenti
├── README_SETUP_PROFILI.md            # Guida setup profili
├── QUICK_START_TESTING.md             # Questo file
│
├── test_api_endpoints.py              # Test base
├── test_api_detailed.py               # Test approfonditi
├── create_test_users_via_api.py       # Creazione utenti
│
├── setup_admin_simple.py              # Setup admin
├── setup_maestro_profile.py           # Setup maestro
├── setup_asd_profile.py               # Setup ASD
│
└── seed_database.py                   # Seed database (non usato)
```

---

## PROSSIMI PASSI CONSIGLIATI

### 1. Immediato (oggi)

1. Esegui gli script di setup profili
2. Testa login e profili
3. Verifica accesso endpoint specifici

### 2. Breve Termine (questa settimana)

1. Popola database con contenuti:
   - Video di esempio
   - Live events
   - Notifiche
2. Testa funzionalità complete
3. Verifica performance

### 3. Medio Termine (prossima settimana)

1. Test frontend/mobile integration
2. Test scenari end-to-end completi
3. Performance e load testing
4. Security audit

---

## METRICHE ATTUALI

### Test Results (da test_api_endpoints.py)
- **Total Tests**: 32
- **Passed**: 18 (56.2%)
- **Failed**: 14 (43.8%)

**Nota**: I test falliti sono principalmente per:
- Endpoint Maestro/Admin (richiedono setup profili)
- Alcuni endpoint video/comunicazione (errori 500)

### Test Results Attesi (dopo setup)
- **Expected Pass Rate**: 80%+
- **Core Features**: 100%
- **Advanced Features**: 60-80%

---

## TROUBLESHOOTING

### Backend non risponde
```bash
# Verifica che sia attivo
curl http://localhost:8000/health

# Se non risponde, verifica processo
ps aux | grep uvicorn

# Riavvia se necessario
cd backend
python -m uvicorn main:app --reload
```

### Database non accessibile
```bash
# Verifica PostgreSQL
psql -U martial_user -d martial_arts_db -c "SELECT 1;"

# Se Docker
docker ps | grep postgres
```

### 403 Forbidden su endpoint Admin
```bash
# Verifica setup admin
python setup_admin_simple.py

# Riavvia backend
```

### 403 Forbidden su endpoint Maestro
```bash
# Verifica setup maestro
python setup_maestro_profile.py --info

# Se non esiste, crealo
python setup_maestro_profile.py
```

---

## DOCUMENTAZIONE COMPLETA

Per dettagli approfonditi, consulta:

1. **Report Test Completo**: `REPORT_TEST_FINALE.md`
   - Tutti i risultati test
   - Analisi errori
   - Raccomandazioni

2. **Guida Setup Profili**: `README_SETUP_PROFILI.md`
   - Istruzioni dettagliate
   - Personalizzazione
   - Troubleshooting avanzato

3. **Credenziali**: `UTENTI_TEST_E_ACCESSI.md`
   - Tutte le credenziali
   - Scenari di test
   - Esempi API

---

## SUPPORTO

### Comandi Utili

```bash
# Lista utenti nel database
psql -U martial_user -d martial_arts_db -c "SELECT email, username, tier, is_admin FROM users;"

# Info profilo maestro
python setup_maestro_profile.py --info

# Info profilo ASD
python setup_asd_profile.py --info

# Test completo
python test_api_detailed.py

# Logs backend
# (vedi nel terminale dove è attivo uvicorn)
```

### Link Utili

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **Health Check**: http://localhost:8000/health

---

## NOTE IMPORTANTI

1. **Password di Test**: Le password sono per ambiente di test locale. NON usare in produzione.

2. **Riavvio Backend**: Dopo ogni setup di profili, riavvia il backend per applicare le modifiche.

3. **Database Vuoto**: Il database contiene solo utenti. Mancano video, eventi, messaggi. Questo è normale per l'ambiente di test iniziale.

4. **Errori 500**: Alcuni endpoint restituiscono 500 perché:
   - Database vuoto (nessun video per /videos/home)
   - Servizi non configurati (Redis, Elasticsearch)
   - Features avanzate non implementate

5. **Test Frontend/Mobile**: Questa documentazione copre solo il backend. Per test completi, serve anche avviare frontend e mobile app.

---

## CHECKLIST SETUP COMPLETO

- [ ] Backend attivo (http://localhost:8000/health risponde)
- [ ] Database accessibile
- [ ] Utenti di test creati (6 utenti)
- [ ] Profilo Admin configurato (`setup_admin_simple.py`)
- [ ] Profilo Maestro configurato (`setup_maestro_profile.py`)
- [ ] Profilo ASD configurato (`setup_asd_profile.py`)
- [ ] Backend riavviato dopo configurazioni
- [ ] Test base eseguiti (`test_api_endpoints.py`)
- [ ] Login testato per tutti gli utenti
- [ ] Swagger UI accessibile

Quando tutti i checkbox sono spuntati, il backend è pronto per:
- Test frontend integration
- Test mobile integration
- Sviluppo features avanzate
- Popolamento database con contenuti

---

**Ultima modifica:** 23/11/2025
**Versione:** 1.0.0

**Buon Testing!**

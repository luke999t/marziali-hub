# GUIDA SETUP PROFILI UTENTI
## Media Center Arti Marziali - Configurazione Manuale

**Data:** 23/11/2025
**Versione:** 1.0.0

---

## INDICE

1. [Panoramica](#panoramica)
2. [Prerequisiti](#prerequisiti)
3. [Script Disponibili](#script-disponibili)
4. [Setup Passo-Passo](#setup-passo-passo)
5. [Troubleshooting](#troubleshooting)
6. [Personalizzazione](#personalizzazione)

---

## PANORAMICA

Questa guida ti aiuta a configurare manualmente i profili speciali per gli utenti di test:

- **Admin**: Flag amministratore per accedere agli endpoint di amministrazione
- **Maestro**: Profilo completo per maestri con discipline, certificazioni, ecc.
- **ASD**: Profilo associazione sportiva per gestire membri e maestri

Gli utenti base sono già stati creati via API, ma richiedono configurazione aggiuntiva per ruoli speciali.

---

## PREREQUISITI

### 1. Backend Attivo

Il database PostgreSQL deve essere accessibile:

```bash
# Verifica che il database sia attivo
psql -U martial_user -d martial_arts_db -c "SELECT 1;"
```

### 2. Utenti Creati

Gli utenti di test devono essere stati creati:

```bash
cd backend
python create_test_users_via_api.py
```

Questo crea 6 utenti:
- admin@mediacenter.it
- maestro.premium@mediacenter.it
- studente.premium@mediacenter.it
- utente.hybrid@mediacenter.it
- utente.free@mediacenter.it
- asd.admin@mediacenter.it

### 3. Dipendenze Python

```bash
# Le dipendenze dovrebbero già essere installate, ma se necessario:
pip install asyncio sqlalchemy asyncpg
```

---

## SCRIPT DISPONIBILI

### 1. `setup_admin_simple.py`
**Scopo**: Imposta il flag `is_admin=true` per l'utente admin

**Cosa fa:**
- Trova l'utente admin@mediacenter.it
- Imposta `is_admin=true`
- Imposta `email_verified=true`
- Verifica la configurazione

**Quando usarlo:**
- Quando vuoi accedere agli endpoint `/api/v1/admin/*`
- Dopo aver creato gli utenti di test

**Esecuzione:**
```bash
cd backend
python setup_admin_simple.py
```

**Output atteso:**
```
======================================================================
SETUP UTENTE ADMIN
======================================================================

1. Cercando utente admin@mediacenter.it...
   OK - Utente trovato: admin (admin@mediacenter.it)

2. Impostando privilegi admin...
   OK - Flag admin impostato

3. Verificando configurazione...
   Username: admin
   Email: admin@mediacenter.it
   Is Admin: True
   Email Verified: True

======================================================================
SETUP COMPLETATO CON SUCCESSO!
======================================================================
```

---

### 2. `setup_maestro_profile.py`
**Scopo**: Crea un profilo Maestro completo nella tabella `maestros`

**Cosa fa:**
- Trova l'utente maestro.premium@mediacenter.it
- Crea un record nella tabella `maestros` con:
  - Discipline (array): ["KARATE", "JUDO"]
  - Disciplina primaria: KARATE
  - Anni esperienza: 10
  - Bio completa
  - Certificazioni (JSON)
  - Flag verificato
- Verifica la creazione

**Quando usarlo:**
- Quando vuoi accedere agli endpoint `/api/v1/maestros/*`
- Per testare funzionalità maestri (dashboard, earnings, video upload)

**Esecuzione:**
```bash
cd backend
python setup_maestro_profile.py
```

**Opzioni:**
```bash
# Visualizza info profilo esistente
python setup_maestro_profile.py --info
```

**Output atteso:**
```
======================================================================
SETUP PROFILO MAESTRO
======================================================================

1. Cercando utente maestro.premium@mediacenter.it...
   OK - Utente trovato: maestro_premium (Maestro Premium)

2. Verificando profilo Maestro esistente...
   OK - Nessun profilo esistente

3. Creando profilo Maestro...
   OK - Profilo Maestro creato (ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

4. Verificando profilo creato...
   ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Username: maestro_premium
   Email: maestro.premium@mediacenter.it
   Disciplina: KARATE
   Anni esperienza: 10
   Verificato: True

======================================================================
PROFILO MAESTRO CREATO CON SUCCESSO!
======================================================================
```

---

### 3. `setup_asd_profile.py`
**Scopo**: Crea un profilo ASD (Associazione Sportiva) completo

**Cosa fa:**
- Trova l'utente asd.admin@mediacenter.it
- Crea un record nella tabella `asds` con:
  - Nome: ASD Karate Milano
  - Ragione sociale completa
  - Codice Fiscale
  - Indirizzo, città, telefono
  - Conteggi membri e maestri
  - Flag verificato
- Verifica la creazione

**Quando usarlo:**
- Quando vuoi accedere agli endpoint `/api/v1/asd/*`
- Per testare gestione associazioni sportive

**Esecuzione:**
```bash
cd backend
python setup_asd_profile.py
```

**Opzioni:**
```bash
# Visualizza info profilo esistente
python setup_asd_profile.py --info
```

**Output atteso:**
```
======================================================================
SETUP PROFILO ASD
======================================================================

1. Cercando utente admin ASD asd.admin@mediacenter.it...
   OK - Utente trovato: asd_admin (ASD Admin)

2. Verificando profilo ASD esistente...
   OK - Nessun profilo esistente

3. Creando profilo ASD...
   OK - Profilo ASD creato (ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

4. Verificando profilo creato...
   ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
   Nome: ASD Karate Milano
   Ragione sociale: Associazione Sportiva Dilettantistica Karate Milano
   Codice Fiscale: 12345678901
   Città: Milano
   Verificata: True
   Membri: 100
   Admin: asd_admin (asd.admin@mediacenter.it)

======================================================================
PROFILO ASD CREATO CON SUCCESSO!
======================================================================
```

---

## SETUP PASSO-PASSO

### Setup Completo (Raccomandato)

Esegui tutti e 3 gli script in sequenza:

```bash
cd backend

# Passo 1: Setup Admin
python setup_admin_simple.py

# Passo 2: Setup Maestro
python setup_maestro_profile.py

# Passo 3: Setup ASD
python setup_asd_profile.py

# Passo 4: Riavvia il backend
# Ferma il processo corrente (Ctrl+C)
python -m uvicorn main:app --reload
```

### Setup Selettivo

Puoi eseguire solo gli script necessari per il tuo caso d'uso.

**Esempio: Solo Admin**
```bash
python setup_admin_simple.py
```

**Esempio: Admin + Maestro**
```bash
python setup_admin_simple.py
python setup_maestro_profile.py
```

---

## VERIFICA CONFIGURAZIONE

### 1. Verifica Database Direttamente

```bash
# Verifica flag admin
psql -U martial_user -d martial_arts_db -c "
  SELECT email, username, is_admin, email_verified
  FROM users
  WHERE email = 'admin@mediacenter.it';
"

# Verifica profilo maestro
psql -U martial_user -d martial_arts_db -c "
  SELECT m.id, u.email, m.primary_discipline, m.years_experience
  FROM maestros m
  JOIN users u ON u.id = m.user_id
  WHERE u.email = 'maestro.premium@mediacenter.it';
"

# Verifica profilo ASD
psql -U martial_user -d martial_arts_db -c "
  SELECT a.id, a.name, a.legal_name, u.email
  FROM asds a
  JOIN users u ON u.id = a.admin_user_id
  WHERE u.email = 'asd.admin@mediacenter.it';
"
```

### 2. Verifica tramite API

```bash
# Login come admin
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mediacenter.it","password":"Admin2024!"}'

# Salva il token ricevuto e prova endpoint admin
curl http://localhost:8000/api/v1/admin/dashboard \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

### 3. Verifica tramite Swagger UI

1. Apri http://localhost:8000/docs
2. Click su "Authorize" (icona lucchetto)
3. Fai login con uno degli utenti configurati
4. Testa gli endpoint corrispondenti

---

## TROUBLESHOOTING

### Errore: "Utente non trovato"

**Causa**: L'utente non è stato creato o l'email è errata

**Soluzione**:
```bash
# Verifica utenti esistenti
psql -U martial_user -d martial_arts_db -c "SELECT email, username FROM users;"

# Se mancano, crea gli utenti
python create_test_users_via_api.py
```

---

### Errore: "Profilo già esistente"

**Causa**: Il profilo è già stato creato in precedenza

**Opzioni**:

**Opzione 1**: Lo script chiede conferma prima di sovrascrivere (3 secondi per Ctrl+C)

**Opzione 2**: Elimina manualmente:
```bash
# Elimina profilo maestro
psql -U martial_user -d martial_arts_db -c "
  DELETE FROM maestros
  WHERE user_id = (SELECT id FROM users WHERE email = 'maestro.premium@mediacenter.it');
"

# Elimina profilo ASD
psql -U martial_user -d martial_arts_db -c "
  DELETE FROM asds
  WHERE admin_user_id = (SELECT id FROM users WHERE email = 'asd.admin@mediacenter.it');
"
```

**Opzione 3**: Visualizza info profilo esistente:
```bash
python setup_maestro_profile.py --info
python setup_asd_profile.py --info
```

---

### Errore: Database Connection Failed

**Causa**: PostgreSQL non è accessibile

**Soluzione**:
```bash
# Verifica che PostgreSQL sia attivo
docker ps | grep postgres  # Se usi Docker
# oppure
sudo systemctl status postgresql  # Linux
# oppure
pg_ctl status  # Windows/Mac

# Verifica credenziali in .env
cat .env | grep DATABASE_URL

# Testa connessione
psql -U martial_user -d martial_arts_db
```

---

### Errore: Column does not exist

**Causa**: Schema database non corrisponde al codice

**Soluzione**:
```bash
# Controlla schema tabella
psql -U martial_user -d martial_arts_db -c "\d maestros"
psql -U martial_user -d martial_arts_db -c "\d asds"
psql -U martial_user -d martial_arts_db -c "\d users"

# Se manca una colonna, potrebbero servire migration
cd backend
alembic upgrade head  # Se usi Alembic
```

---

### Endpoint restituisce 403 Forbidden

**Causa**: Profilo non configurato o backend non riavviato

**Soluzione**:
1. Verifica che lo script abbia completato con successo
2. Riavvia il backend
3. Riprova il login
4. Verifica il token JWT sia valido

---

## PERSONALIZZAZIONE

### Personalizzare Profilo Maestro

Modifica `setup_maestro_profile.py`, sezione `MAESTRO_CONFIG`:

```python
MAESTRO_CONFIG = {
    "user_email": "maestro.premium@mediacenter.it",
    "disciplines": ["TAEKWONDO", "HAPKIDO"],  # Cambia discipline
    "primary_discipline": "TAEKWONDO",        # Cambia principale
    "years_experience": 15,                    # Cambia esperienza
    "bio": "Il tuo testo personalizzato...",  # Cambia bio
    # ... altri campi
}
```

Poi riesegui:
```bash
python setup_maestro_profile.py
```

---

### Personalizzare Profilo ASD

Modifica `setup_asd_profile.py`, sezione `ASD_CONFIG`:

```python
ASD_CONFIG = {
    "admin_email": "asd.admin@mediacenter.it",
    "name": "La Tua ASD",                     # Cambia nome
    "legal_name": "Nome Legale Completo",     # Cambia ragione sociale
    "tax_code": "12345678901",                # Cambia CF
    "city": "Roma",                           # Cambia città
    # ... altri campi
}
```

Poi riesegui:
```bash
python setup_asd_profile.py
```

---

### Creare Utenti Aggiuntivi

Per creare nuovi utenti con profili personalizzati:

1. **Crea utente base via API**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "nuovo@test.it",
    "password": "Password123!",
    "username": "nuovoutente",
    "full_name": "Nuovo Utente",
    "tier": "PREMIUM"
  }'
```

2. **Copia e modifica uno degli script di setup**:
```bash
cp setup_maestro_profile.py setup_maestro_custom.py
# Modifica email e configurazione in setup_maestro_custom.py
python setup_maestro_custom.py
```

---

## DISCIPLINE DISPONIBILI

Per il campo `primary_discipline` in `MAESTRO_CONFIG`, usa uno di questi valori:

- `KARATE`
- `JUDO`
- `TAEKWONDO`
- `AIKIDO`
- `KENDO`
- `KUNG_FU`
- `MUAY_THAI`
- `BRAZILIAN_JIU_JITSU`
- `MMA`
- `BOXING`
- `KICKBOXING`
- `CAPOEIRA`
- `KRAV_MAGA`
- `WING_CHUN`
- `TAI_CHI`

---

## PROSSIMI PASSI

Dopo aver configurato i profili:

1. **Testa API**:
   ```bash
   python test_api_endpoints.py
   python test_api_detailed.py
   ```

2. **Popola Database**:
   - Crea video di esempio
   - Crea live events
   - Crea notifiche di test

3. **Test Frontend/Mobile**:
   - Avvia frontend Next.js
   - Avvia app mobile Expo
   - Testa integrazione completa

4. **Documentazione**:
   - Leggi `REPORT_TEST_FINALE.md` per dettagli completi
   - Consulta `UTENTI_TEST_E_ACCESSI.md` per credenziali

---

## SUPPORTO

### File di Riferimento

- **Credenziali**: `UTENTI_TEST_E_ACCESSI.md`
- **Report Test**: `REPORT_TEST_FINALE.md`
- **Script Test**: `test_api_endpoints.py`, `test_api_detailed.py`

### Problemi Comuni

1. **Token scaduto**: Rifai il login
2. **403 Forbidden**: Verifica profilo configurato
3. **404 Not Found**: Verifica che il backend sia attivo
4. **500 Server Error**: Controlla logs backend

### Logs Backend

```bash
# Se usi uvicorn con --reload
# I logs appariranno nel terminale

# Se vuoi salvare logs
python -m uvicorn main:app --reload > backend.log 2>&1
```

---

**Ultima modifica:** 23/11/2025
**Versione:** 1.0.0
**Autore:** Claude Code Assistant

# 📚 DOCUMENTAZIONE UTENTI TEST
## Media Center Arti Marziali - Ambiente Locale

**Data creazione:** 23/11/2025 15:34
**Environment:** Development (Locale)
**Backend URL:** http://localhost:8000
**Frontend URL:** http://localhost:3000 (se avviato)

---

## 🔑 CREDENZIALI ACCESSO

### Tabella Riassuntiva

| Ruolo | Email | Password | Tier | Permessi Principali |
|-------|-------|----------|------|---------------------|
| Admin/Superuser | `admin@mediacenter.it` | `Admin2024!` | PREMIUM | Full access - Gestione completa piattaforma |
| Maestro Premium | `maestro.premium@mediacenter.it` | `Maestro2024!` | PREMIUM | Upload video illimitati, Streaming live, Monetizzazione |
| Studente Premium | `studente.premium@mediacenter.it` | `Student2024!` | PREMIUM | Accesso completo catalogo, Live streaming, AI Coach |
| Utente Hybrid Standard | `utente.hybrid@mediacenter.it` | `Hybrid2024!` | HYBRID_STANDARD | 10 video/mese, Accesso limitato live, PPV disponibili |
| Utente Free | `utente.free@mediacenter.it` | `Free2024!` | FREE | 1 video/mese, Solo contenuti gratuiti |
| ASD Manager | `asd.admin@mediacenter.it` | `Asd2024!` | BUSINESS | Gestione membri, Streaming events, Multi-maestro support |

---

## 👥 DETTAGLIO UTENTI


### 1. Admin/Superuser

**Credenziali:**
- Email: `admin@mediacenter.it`
- Password: `Admin2024!`

**Caratteristiche:**
- Tier: **PREMIUM**
- Permessi: Full access - Gestione completa piattaforma

**Casi d'uso:**
- Gestione completa della piattaforma
- Moderazione contenuti
- Gestione utenti e ruoli
- Accesso a tutti i report e statistiche
- Configurazione sistema

### 2. Maestro Premium

**Credenziali:**
- Email: `maestro.premium@mediacenter.it`
- Password: `Maestro2024!`

**Caratteristiche:**
- Tier: **PREMIUM**
- Permessi: Upload video illimitati, Streaming live, Monetizzazione

**Casi d'uso:**
- Upload video illimitati
- Creazione corsi e live streaming
- Monetizzazione contenuti
- Gestione studenti
- Accesso statistiche personali

### 3. Studente Premium

**Credenziali:**
- Email: `studente.premium@mediacenter.it`
- Password: `Student2024!`

**Caratteristiche:**
- Tier: **PREMIUM**
- Permessi: Accesso completo catalogo, Live streaming, AI Coach

**Casi d'uso:**
- Accesso completo a tutti i video
- Partecipazione live streaming
- AI Coach per correzione postura
- Download video offline (mobile)
- Nessuna pubblicità

### 4. Utente Hybrid Standard

**Credenziali:**
- Email: `utente.hybrid@mediacenter.it`
- Password: `Hybrid2024!`

**Caratteristiche:**
- Tier: **HYBRID_STANDARD**
- Permessi: 10 video/mese, Accesso limitato live, PPV disponibili

**Casi d'uso:**
- Accesso limitato al catalogo (10 video/mese)
- Acquisto video singoli (PPV)
- Partecipazione limitata a live events
- Stelline per acquisti

### 5. Utente Free

**Credenziali:**
- Email: `utente.free@mediacenter.it`
- Password: `Free2024!`

**Caratteristiche:**
- Tier: **FREE**
- Permessi: 1 video/mese, Solo contenuti gratuiti

**Casi d'uso:**
- Accesso a contenuti gratuiti
- 1 video completo al mese
- Visualizzazione preview video a pagamento
- Sistema stelline base

### 6. ASD Manager

**Credenziali:**
- Email: `asd.admin@mediacenter.it`
- Password: `Asd2024!`

**Caratteristiche:**
- Tier: **BUSINESS**
- Permessi: Gestione membri, Streaming events, Multi-maestro support

**Casi d'uso:**
- Gestione associazione sportiva
- Gestione maestri e membri
- Organizzazione eventi e corsi
- Fatturazione e contabilità
- Multi-location support

---

## 🧪 TESTING API

### Quick Test Endpoints

#### 1. Health Check
```bash
curl http://localhost:8000/health
```

**Risposta attesa:**
```json
{
  "status": "healthy",
  "environment": "development",
  "release": "v1.0.0"
}
```

#### 2. Login (esempio con Admin)
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@mediacenter.it","password":"Admin2024!"}'
```

**Risposta attesa:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer"
}
```

#### 3. Get User Profile
```bash
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### 4. List Videos
```bash
curl http://localhost:8000/api/v1/videos/ \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## 📊 TIER COMPARISON

| Feature | FREE | HYBRID LIGHT | HYBRID STANDARD | PREMIUM | BUSINESS |
|---------|------|--------------|-----------------|---------|----------|
| Video/mese | 1 | 5 | 10 | ∞ | ∞ |
| Live streaming | ❌ | Limitato | Limitato | ✅ | ✅ |
| AI Coach | ❌ | ❌ | ❌ | ✅ | ✅ |
| PPV | ✅ | ✅ | ✅ | ✅ | ✅ |
| Download offline | ❌ | ❌ | ❌ | ✅ | ✅ |
| Pubblicità | ✅ | Limitata | Limitata | ❌ | ❌ |
| Stelline | 100 | 250 | 500 | 1000 | 2000 |
| Prezzo | €0 | €4.99 | €9.99 | €19.99 | €49.99 |

---

## 🔐 SICUREZZA

**IMPORTANTE:** Queste sono credenziali di TEST per ambiente LOCALE.

**NON usare in produzione!**

In produzione:
- Genera nuove password complesse
- Abilita 2FA
- Usa variabili d'ambiente per le password
- Abilita rate limiting
- Configura HTTPS
- Abilita CORS solo per domini autorizzati

---

## 📱 TEST CON SWAGGER UI

1. Apri browser: http://localhost:8000/docs
2. Click su "Authorize" (icona lucchetto)
3. Fai login con uno degli utenti sopra
4. Copia l'`access_token` dalla risposta
5. Incollalo nel campo "Value" (con prefisso "Bearer ")
6. Click "Authorize"
7. Ora puoi testare tutte le API protette

---

## 🎯 SCENARI DI TEST

### Scenario 1: Studente visualizza video
1. Login come `studente.premium@mediacenter.it`
2. GET `/api/v1/videos/` - Lista video disponibili
3. GET `/api/v1/videos/{id}` - Dettagli video specifico
4. POST `/api/v1/videos/{id}/view` - Registra visualizzazione

### Scenario 2: Maestro carica video
1. Login come `maestro.premium@mediacenter.it`
2. POST `/api/v1/videos/` - Upload nuovo video
3. PUT `/api/v1/videos/{id}` - Modifica metadata
4. GET `/api/v1/maestros/me/stats` - Statistiche personali

### Scenario 3: Admin modera contenuto
1. Login come `admin@mediacenter.it`
2. GET `/api/v1/admin/videos/pending` - Video in moderazione
3. POST `/api/v1/admin/videos/{id}/approve` - Approva video
4. POST `/api/v1/admin/videos/{id}/reject` - Rifiuta video

### Scenario 4: Utente acquista stelline
1. Login come `utente.hybrid@mediacenter.it`
2. GET `/api/v1/stelline/packages` - Pacchetti disponibili
3. POST `/api/v1/stelline/purchase` - Acquista stelline
4. GET `/api/v1/stelline/wallet` - Verifica saldo

---

## 🚀 PROSSIMI PASSI

Dopo aver verificato il funzionamento locale:

1. **Test Mobile App**
   - Configura Expo
   - Testa login su app mobile
   - Verifica sincronizzazione

2. **Test Frontend**
   - Avvia Next.js: `cd frontend && npm run dev`
   - Apri http://localhost:3000
   - Testa UI/UX

3. **Test Integrazioni**
   - Stripe (modalità test)
   - Email (mock o SMTP)
   - Storage (locale o S3)

4. **Performance Testing**
   - Load testing con k6 o Artillery
   - Verifica cache Redis
   - Ottimizza query lente

5. **Deploy Staging**
   - Segui `DEPLOYMENT_GUIDE.md`
   - Test su ambiente simile a production
   - Verifica con dati realistici

---

## 📞 SUPPORTO

- **Documentazione completa:** Vedi `SETUP_LOCALE_PASSO_PASSO.md`
- **Guide deployment:** Vedi `DEPLOYMENT_GUIDE.md`
- **Issues:** GitHub repository

---

**🎉 Buon Testing! 🎉**

*Generato automaticamente il 23/11/2025 alle 15:34*

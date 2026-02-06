# MEGA PROMPT - TEST UTENTE MEDIA CENTER ARTI MARZIALI

Copia questo prompt nella nuova chat Claude per iniziare i test utente.

---

```
# TEST UTENTE - MEDIA CENTER ARTI MARZIALI

## CONTESTO PROGETTO

Sto testando un sistema gestionale AI-First per l'insegnamento delle arti marziali.
Il sistema è stato verificato a livello di codice e test automatici (ZERO MOCK).
Ora serve il test utente manuale per validare i flussi reali.

### Stato Sistema (11 Dicembre 2025)

| Componente | Stato |
|------------|-------|
| Backend FastAPI | ✅ PRONTO (350 test, 100% pass) |
| Frontend Next.js | ✅ PRONTO (131 test, 100% pass) |
| Mobile React Native | ✅ PRONTO (120 test, 100% pass) |
| Flutter App | ✅ PRONTO (107 file, Clean Architecture) |

### Path Progetto
```
C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\
├── backend/          # FastAPI su porta 8000
├── frontend/         # Next.js su porta 3000
├── mobile/           # React Native + Expo
└── flutter_app/      # Flutter
```

### Documentazione Disponibile
- `TEST_UTENTE_MEDIA_CENTER.md` - Checklist completa scenari test
- `STATO_PROGETTO_20251211.md` - Stato tecnico dettagliato
- `CREDENZIALI_SVILUPPO.md` - Credenziali e configurazioni

## AVVIO SISTEMA

### Backend (OBBLIGATORIO - sempre primo)
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000
```
Verifica: http://localhost:8000/health

### Frontend
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev
```
URL: http://localhost:3000

### Mobile (opzionale)
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\mobile
npm start
```

## UTENTI TEST

| Ruolo | Email | Password | Tier |
|-------|-------|----------|------|
| Admin | admin@mediacenter.it | Test123! | BUSINESS |
| Studente Free | giulia.bianchi@example.com | Test123! | FREE |
| Studente Premium | mario.rossi@example.com | Test123! | PREMIUM |
| Maestro | tanaka.hiroshi@mediacenter.demo | Test123! | PREMIUM |

## SCENARI DA TESTARE

### Priorità ALTA
1. **Auth Flow**: Login, Logout, Registrazione
2. **Video Player**: Play, Pause, Seek, Fullscreen
3. **Pause Ads**: Overlay per user FREE, no overlay per PREMIUM
4. **Curriculum**: Iscrizione, progressione, completamento

### Priorità MEDIA
5. **Staff Dashboard**: Upload video, gestione curriculum
6. **Profilo**: Visualizza, modifica, abbonamento
7. **Search**: Ricerca video, filtri

### Priorità BASSA
8. **Notifiche**: In-app, push (mobile)
9. **Pagamenti**: Stripe test mode
10. **Traduzione Live**: Sottotitoli multi-lingua

## COSA SERVE DA TE

1. **Avviare il sistema** e verificare che funzioni
2. **Eseguire gli scenari** dalla checklist TEST_UTENTE_MEDIA_CENTER.md
3. **Segnalare bug** con template strutturato
4. **Validare UX** e suggerire miglioramenti
5. **Confermare PASS/FAIL** per ogni scenario

## REGOLE

- Leggi sempre `TEST_UTENTE_MEDIA_CENTER.md` per la checklist completa
- Usa gli utenti test forniti, non creare nuovi account random
- Se trovi bug, documenta con screenshot/errori console
- Se qualcosa non funziona, verifica prima che backend sia attivo
- Usa MCP filesystem per accedere ai file del progetto

## PRIMO STEP

1. Leggi il file `TEST_UTENTE_MEDIA_CENTER.md` nel progetto
2. Avvia backend e frontend
3. Testa lo scenario A1 (Login) come primo test
4. Reporta risultato

Iniziamo?
```

---

## NOTE PER L'USO

1. **Copia tutto** il testo tra i ``` e incollalo nella nuova chat
2. La nuova chat avrà accesso a MCP filesystem per leggere i file
3. Il file `TEST_UTENTE_MEDIA_CENTER.md` contiene 50+ scenari dettagliati
4. Ogni scenario ha checkbox per tracciare completamento

## ALTERNATIVE

Se preferisci, puoi anche:
- Chiedere di testare UN SOLO scenario alla volta
- Chiedere di generare script di test automatici E2E (Cypress/Playwright)
- Chiedere di fare solo smoke test rapido (10 minuti)

# 🧪 MEGA TEST PLAN - APP STAFF MEDIA CENTER ARTI MARZIALI
## Test Utente Completo con Chrome Extension

**Data**: 30 Gennaio 2026  
**Versione**: 1.0  
**Tipo**: Test End-to-End Massivo  
**Tool**: Chrome Extension (Claude in Chrome)

---

## 📋 PRE-REQUISITI

### 1. Avviare PostgreSQL
```powershell
# Verifica che PostgreSQL sia attivo
pg_isready -h localhost -p 5432
```

### 2. Avviare Backend
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000
```
**Verifica**: http://localhost:8000/health → `{"status": "healthy"}`

### 3. Avviare Frontend
```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev
```
**URL**: http://localhost:3000

### 4. Nota timestamp inizio test
```
TIMESTAMP_INIZIO_TEST: _____________ (es. 2026-01-30 10:00:00)
```
Servirà per il cleanup dopo i test.

---

## 👥 UTENTI DI TEST

| Ruolo | Email | Password | Tier |
|-------|-------|----------|------|
| Admin | admin@mediacenter.it | Test123! | BUSINESS |
| Studente Free | giulia.bianchi@example.com | Test123! | FREE |
| Studente Premium | mario.rossi@example.com | Test123! | PREMIUM |
| Maestro | tanaka.hiroshi@mediacenter.demo | Test123! | PREMIUM |
| ASD | presidente@karatemilano.it | Test123! | BUSINESS |

---

## 🔄 CONVENZIONE NOMI DATI TEST

Tutti i dati creati durante i test DEVONO usare questi prefissi:
- **Nome**: `TEST_` + descrizione (es. `TEST_Video_Kata_01`)
- **Email**: `test_` + timestamp (es. `test_1706612400@example.com`)
- **Progetto**: `TEST_` + tipo (es. `TEST_Fusion_Project_01`)

Questo permette di identificarli e cancellarli facilmente dopo i test.

---

## 📝 STRUTTURA TEST

Ogni test ha:
- **ID**: Identificativo unico
- **Pagina**: URL da navigare
- **Azione**: Cosa fare
- **Verifica**: Cosa controllare
- **Dati**: Dati da inserire (con prefisso TEST_)

---

# 🚀 ROUND 1: NAVIGAZIONE E LOGIN

## TEST-001: Home Page Staff
```
PAGINA: http://localhost:3000
AZIONE: Naviga alla home
VERIFICA:
  - [ ] Pagina carica senza errori
  - [ ] Header "Media Center Staff" visibile
  - [ ] 4 stat card visibili (Total Videos, Active Streams, Voice Models, Processing Jobs)
  - [ ] Backend status cards visibili (Streaming, Studio, Library, Auth)
  - [ ] Quick Actions grid visibile (9+ cards)
SCREENSHOT: Sì
```

## TEST-002: Login Admin
```
PAGINA: http://localhost:3000/login
AZIONE: 
  1. Inserisci email: admin@mediacenter.it
  2. Inserisci password: Test123!
  3. Click "Login"
VERIFICA:
  - [ ] Redirect a dashboard
  - [ ] Nome utente visibile in header
  - [ ] Menu admin accessibile
SCREENSHOT: Sì
```

## TEST-003: Login Maestro
```
PAGINA: http://localhost:3000/login
AZIONE:
  1. Logout se loggato
  2. Inserisci email: tanaka.hiroshi@mediacenter.demo
  3. Inserisci password: Test123!
  4. Click "Login"
VERIFICA:
  - [ ] Redirect a dashboard maestro
  - [ ] Menu maestro visibile
SCREENSHOT: Sì
```

## TEST-004: Registrazione Nuovo Utente Test
```
PAGINA: http://localhost:3000/register
AZIONE:
  1. Inserisci username: TEST_User_001
  2. Inserisci email: test_user_001@example.com
  3. Inserisci password: Test123!
  4. Conferma password: Test123!
  5. Click "Registrati"
VERIFICA:
  - [ ] Registrazione completata
  - [ ] Redirect a login o dashboard
  - [ ] Utente creato nel database
DATI_CREATI:
  - User: test_user_001@example.com
SCREENSHOT: Sì
```

---

# 🖼️ ROUND 2: AVATAR GALLERY

## TEST-010: Visualizza Avatar Gallery
```
PAGINA: http://localhost:3000/avatar-gallery
PREREQUISITO: Login come admin
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista avatar carica
  - [ ] Filtri per stile visibili
  - [ ] Search bar funzionante
  - [ ] Cards avatar con thumbnail
SCREENSHOT: Sì
```

## TEST-011: Filtra Avatar per Stile
```
PAGINA: http://localhost:3000/avatar-gallery
AZIONE:
  1. Click filtro "Karate"
  2. Verifica risultati
  3. Click filtro "Kung Fu"
  4. Verifica risultati
  5. Click "Tutti"
VERIFICA:
  - [ ] Filtro funziona
  - [ ] Count aggiorna
  - [ ] Nessun errore console
SCREENSHOT: Sì (per ogni filtro)
```

## TEST-012: Preview Avatar 3D
```
PAGINA: http://localhost:3000/avatar-gallery
AZIONE:
  1. Click su un avatar card
  2. Modal preview apre
  3. Verifica viewer 3D
  4. Click "Seleziona per Player"
VERIFICA:
  - [ ] Modal apre
  - [ ] Viewer 3D carica modello
  - [ ] Rotazione automatica funziona
  - [ ] Pulsante selezione funziona
  - [ ] Badge "Selezionato" appare
SCREENSHOT: Sì
```

## TEST-013: Cerca Avatar
```
PAGINA: http://localhost:3000/avatar-gallery
AZIONE:
  1. Digita "sensei" nella search bar
  2. Verifica risultati
  3. Pulisci ricerca
VERIFICA:
  - [ ] Ricerca filtra risultati
  - [ ] Nessun risultato mostra messaggio appropriato
SCREENSHOT: Sì
```

---

# 🎬 ROUND 3: INGEST STUDIO (Upload Video)

## TEST-020: Accedi a Ingest Studio
```
PAGINA: http://localhost:3000/ingest-studio
PREREQUISITO: Login come admin o maestro
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Wizard a 4 step visibile
  - [ ] Step 1 "Project" attivo
  - [ ] Lista progetti carica
SCREENSHOT: Sì
```

## TEST-021: Crea Nuovo Progetto Ingest
```
PAGINA: http://localhost:3000/ingest-studio
AZIONE:
  1. Click "Nuovo Progetto"
  2. Inserisci nome: TEST_Ingest_Project_01
  3. Inserisci descrizione: Progetto di test per ingest
  4. Click "Crea"
VERIFICA:
  - [ ] Progetto creato
  - [ ] Appare nella lista
  - [ ] Selezionabile
DATI_CREATI:
  - IngestProject: TEST_Ingest_Project_01
SCREENSHOT: Sì
```

## TEST-022: Upload Video (Step 2)
```
PAGINA: http://localhost:3000/ingest-studio
PREREQUISITO: Progetto TEST_Ingest_Project_01 selezionato
AZIONE:
  1. Avanza a Step 2 "Input"
  2. Tab "Video Upload" selezionato
  3. Drag & drop o seleziona un video di test (se disponibile)
  4. Oppure: Simula con file piccolo
VERIFICA:
  - [ ] Upload progress visibile
  - [ ] File accettato
  - [ ] Passa a Step 3
NOTE: Se non hai video di test, salta a TEST-024
SCREENSHOT: Sì
```

## TEST-023: Configura Processing Options (Step 3)
```
PAGINA: http://localhost:3000/ingest-studio
AZIONE:
  1. Seleziona preset: "Standard"
  2. Lingue target: it, en
  3. Confidence threshold: 0.65
  4. Abilita "Martial Dictionary"
  5. Click "Avanti"
VERIFICA:
  - [ ] Opzioni salvate
  - [ ] Passa a Step 4
SCREENSHOT: Sì
```

## TEST-024: Input Testo Manuale (Alternativa)
```
PAGINA: http://localhost:3000/ingest-studio
AZIONE:
  1. Torna a Step 2
  2. Seleziona tab "Manual Text"
  3. Inserisci testo: "TEST: Questa è una tecnica di Karate chiamata Mae Geri"
  4. Click "Avanti"
VERIFICA:
  - [ ] Testo accettato
  - [ ] Passa a Step 3
SCREENSHOT: Sì
```

---

# 🦴 ROUND 4: SKELETON MANAGEMENT

## TEST-030: Visualizza Skeleton Library
```
PAGINA: http://localhost:3000/skeletons
PREREQUISITO: Login come admin
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista skeleton carica
  - [ ] Filtri disponibili
  - [ ] Cards con preview
SCREENSHOT: Sì
```

## TEST-031: Skeleton Viewer
```
PAGINA: http://localhost:3000/skeleton-viewer
AZIONE:
  1. Naviga alla pagina
  2. Seleziona uno skeleton dalla lista (se presente)
  3. Visualizza in 3D
VERIFICA:
  - [ ] Viewer 3D carica
  - [ ] Skeleton renderizza
  - [ ] Controlli funzionano (rotate, zoom)
SCREENSHOT: Sì
```

## TEST-032: Skeleton Editor
```
PAGINA: http://localhost:3000/skeleton-editor
AZIONE:
  1. Naviga alla pagina
  2. Verifica toolbar di editing
  3. Verifica color coding arti
VERIFICA:
  - [ ] Editor carica
  - [ ] Body parts colorati visibili
  - [ ] Timeline visibile
SCREENSHOT: Sì
```

---

# 🎥 ROUND 5: MULTI-VIDEO FUSION

## TEST-040: Dashboard Fusion
```
PAGINA: http://localhost:3000/fusion
PREREQUISITO: Login come admin
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista progetti fusion carica
  - [ ] Pulsante "Nuovo Progetto" visibile
  - [ ] Filtri per stato funzionano
SCREENSHOT: Sì
```

## TEST-041: Crea Progetto Fusion
```
PAGINA: http://localhost:3000/fusion
AZIONE:
  1. Click "Nuovo Progetto"
  2. Nome: TEST_Fusion_Project_01
  3. Stile: Karate
  4. Click "Crea"
VERIFICA:
  - [ ] Progetto creato
  - [ ] Redirect a pagina progetto
  - [ ] Status "Bozza"
DATI_CREATI:
  - FusionProject: TEST_Fusion_Project_01
SCREENSHOT: Sì
```

## TEST-042: Aggiungi Video a Fusion
```
PAGINA: http://localhost:3000/fusion/[project_id]
PREREQUISITO: Progetto TEST_Fusion_Project_01 creato
AZIONE:
  1. Click "Aggiungi Video"
  2. Seleziona video dalla libreria (se presenti)
  3. Conferma selezione
VERIFICA:
  - [ ] Video aggiunto
  - [ ] Count video aggiorna
  - [ ] Preview thumbnail visibile
NOTE: Se non ci sono video, salta
SCREENSHOT: Sì
```

## TEST-043: Filtra Progetti Fusion
```
PAGINA: http://localhost:3000/fusion
AZIONE:
  1. Filtra per "Bozza"
  2. Verifica TEST_Fusion_Project_01 visibile
  3. Filtra per "Completato"
  4. Verifica lista cambia
VERIFICA:
  - [ ] Filtri funzionano
  - [ ] Count aggiorna
SCREENSHOT: Sì
```

---

# 👨‍💼 ROUND 6: ADMIN DASHBOARD

## TEST-050: Admin Home
```
PAGINA: http://localhost:3000/admin
PREREQUISITO: Login come admin@mediacenter.it
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Dashboard admin carica
  - [ ] Menu laterale visibile
  - [ ] KPI cards visibili
SCREENSHOT: Sì
```

## TEST-051: Admin - Gestione Utenti
```
PAGINA: http://localhost:3000/admin/users
AZIONE:
  1. Naviga alla lista utenti
  2. Cerca "test_user_001"
  3. Click per vedere dettagli
VERIFICA:
  - [ ] Lista utenti carica
  - [ ] Ricerca funziona
  - [ ] Dettaglio utente visibile
SCREENSHOT: Sì
```

## TEST-052: Admin - Modifica Utente
```
PAGINA: http://localhost:3000/admin/users
AZIONE:
  1. Seleziona utente test_user_001
  2. Modifica nome in "TEST_User_Modified"
  3. Salva
VERIFICA:
  - [ ] Modifica salvata
  - [ ] Nome aggiornato in lista
SCREENSHOT: Sì
```

## TEST-053: Admin - Gestione Avatar
```
PAGINA: http://localhost:3000/admin/avatars
AZIONE:
  1. Naviga alla pagina
  2. Verifica lista avatar
  3. Verifica opzioni di gestione
VERIFICA:
  - [ ] Lista carica
  - [ ] Azioni CRUD visibili
SCREENSHOT: Sì
```

## TEST-054: Admin - Content Moderation
```
PAGINA: http://localhost:3000/admin/moderation
AZIONE:
  1. Naviga alla pagina
  2. Verifica coda moderazione
VERIFICA:
  - [ ] Pagina carica
  - [ ] Lista video in attesa (se presenti)
  - [ ] Pulsanti Approva/Rifiuta visibili
SCREENSHOT: Sì
```

## TEST-055: Admin - Analytics
```
PAGINA: http://localhost:3000/admin/analytics
AZIONE:
  1. Naviga alla pagina
  2. Verifica grafici
VERIFICA:
  - [ ] Grafici caricano
  - [ ] Metriche visibili
  - [ ] Date range funziona
SCREENSHOT: Sì
```

## TEST-056: Admin - Subscriptions
```
PAGINA: http://localhost:3000/admin/subscriptions
AZIONE:
  1. Naviga alla pagina
  2. Verifica lista abbonamenti
VERIFICA:
  - [ ] Lista carica
  - [ ] Filtri per tipo
  - [ ] Statistiche visibili
SCREENSHOT: Sì
```

## TEST-057: Admin - System Settings
```
PAGINA: http://localhost:3000/admin/system
AZIONE:
  1. Naviga alla pagina
  2. Verifica impostazioni
VERIFICA:
  - [ ] Impostazioni visibili
  - [ ] Toggle funzionano
  - [ ] Salvataggio funziona
SCREENSHOT: Sì
```

---

# 📚 ROUND 7: CURRICULUM

## TEST-060: Lista Curriculum
```
PAGINA: http://localhost:3000/curriculum
PREREQUISITO: Login
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista curriculum carica
  - [ ] Cards con info livelli
  - [ ] Filtri per arte marziale
SCREENSHOT: Sì
```

## TEST-061: Dettaglio Curriculum
```
PAGINA: http://localhost:3000/curriculum
AZIONE:
  1. Click su un curriculum (se presente)
  2. Visualizza dettagli
VERIFICA:
  - [ ] Dettaglio apre
  - [ ] Livelli visibili
  - [ ] Pulsante "Iscriviti" visibile
SCREENSHOT: Sì
```

## TEST-062: My Learning
```
PAGINA: http://localhost:3000/my-learning
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Pagina carica
  - [ ] Lista corsi iscritti (può essere vuota)
  - [ ] Progress bar se iscritti
SCREENSHOT: Sì
```

---

# 🎤 ROUND 8: TRANSLATION

## TEST-070: Translation Dashboard
```
PAGINA: http://localhost:3000/translation
PREREQUISITO: Login
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Pagina carica
  - [ ] Selezione lingue visibile
  - [ ] Input testo visibile
SCREENSHOT: Sì
```

## TEST-071: Test Traduzione
```
PAGINA: http://localhost:3000/translation
AZIONE:
  1. Inserisci testo: "Mae Geri è un calcio frontale nel Karate"
  2. Seleziona lingua target: English
  3. Click "Traduci"
VERIFICA:
  - [ ] Traduzione eseguita
  - [ ] Risultato visibile
  - [ ] Termini tecnici preservati
SCREENSHOT: Sì
```

---

# 📡 ROUND 9: LIVE & EVENTS

## TEST-080: Live Player
```
PAGINA: http://localhost:3000/live-player
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Player carica
  - [ ] Lista eventi live (può essere vuota)
  - [ ] Controlli player visibili
SCREENSHOT: Sì
```

## TEST-081: Events
```
PAGINA: http://localhost:3000/events
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista eventi carica
  - [ ] Filtri per data
  - [ ] Cards evento con info
SCREENSHOT: Sì
```

---

# 👤 ROUND 10: PROFILO & MISC

## TEST-090: Profilo Utente
```
PAGINA: http://localhost:3000/me
PREREQUISITO: Login
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Profilo carica
  - [ ] Info utente visibili
  - [ ] Avatar/foto profilo
  - [ ] Tier abbonamento
  - [ ] Statistiche
SCREENSHOT: Sì
```

## TEST-091: Modifica Profilo
```
PAGINA: http://localhost:3000/me
AZIONE:
  1. Click "Modifica"
  2. Cambia nome in "TEST_Nome_Modificato"
  3. Salva
  4. Ripristina nome originale
VERIFICA:
  - [ ] Edit mode attivo
  - [ ] Salvataggio funziona
  - [ ] Nome aggiornato
SCREENSHOT: Sì
```

## TEST-092: Processing Monitor
```
PAGINA: http://localhost:3000/monitor
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista job carica
  - [ ] Status job visibili
  - [ ] Progress bars
SCREENSHOT: Sì
```

## TEST-093: Chat/Messaggistica
```
PAGINA: http://localhost:3000/chat
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Chat carica
  - [ ] Lista conversazioni
  - [ ] Input messaggio
SCREENSHOT: Sì
```

## TEST-094: Donations
```
PAGINA: http://localhost:3000/donations
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Pagina carica
  - [ ] Opzioni donazione
SCREENSHOT: Sì
```

## TEST-095: Special Projects
```
PAGINA: http://localhost:3000/special-projects
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Lista progetti speciali
  - [ ] Filtri e cards
SCREENSHOT: Sì
```

---

# 🎓 ROUND 11: MAESTRO DASHBOARD

## TEST-100: Maestro Home
```
PAGINA: http://localhost:3000/maestro
PREREQUISITO: Login come tanaka.hiroshi@mediacenter.demo
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Dashboard maestro carica
  - [ ] KPI visibili (video caricati, studenti, etc.)
  - [ ] Quick actions
SCREENSHOT: Sì
```

## TEST-101: Maestro Upload
```
PAGINA: http://localhost:3000/maestro/upload
AZIONE:
  1. Naviga alla pagina
  2. Verifica form upload
VERIFICA:
  - [ ] Form upload visibile
  - [ ] Campi metadata
  - [ ] Drag & drop zone
SCREENSHOT: Sì
```

---

# 🏢 ROUND 12: ASD DASHBOARD

## TEST-110: ASD Dashboard
```
PAGINA: http://localhost:3000/asd-dashboard
PREREQUISITO: Login come presidente@karatemilano.it
AZIONE: Naviga alla pagina
VERIFICA:
  - [ ] Dashboard ASD carica
  - [ ] Info associazione
  - [ ] Lista membri
  - [ ] Statistiche
SCREENSHOT: Sì
```

---

# 🔄 ROUND 13: SECONDO GIRO (Stress Test)

## TEST-120: Crea 5 Utenti Test
```
PAGINA: http://localhost:3000/register
AZIONE:
  Ripeti 5 volte:
  1. Registra utente con email test_user_00X@example.com
  2. Password: Test123!
VERIFICA:
  - [ ] 5 utenti creati
DATI_CREATI:
  - test_user_002@example.com
  - test_user_003@example.com
  - test_user_004@example.com
  - test_user_005@example.com
  - test_user_006@example.com
```

## TEST-121: Crea 3 Progetti Fusion
```
PAGINA: http://localhost:3000/fusion
AZIONE:
  Ripeti 3 volte:
  1. Crea progetto TEST_Fusion_0X
DATI_CREATI:
  - TEST_Fusion_02
  - TEST_Fusion_03
  - TEST_Fusion_04
```

## TEST-122: Crea 3 Progetti Ingest
```
PAGINA: http://localhost:3000/ingest-studio
AZIONE:
  Ripeti 3 volte:
  1. Crea progetto TEST_Ingest_0X
DATI_CREATI:
  - TEST_Ingest_02
  - TEST_Ingest_03
  - TEST_Ingest_04
```

---

# ✅ RIEPILOGO FINALE

## Totale Test: 40+
## Tempo Stimato: 2-3 ore

## Dati Creati Durante Test:
- [ ] Utenti: ~7 (test_user_001 ... test_user_006 + TEST_User_001)
- [ ] Progetti Fusion: ~4 (TEST_Fusion_01 ... TEST_Fusion_04)
- [ ] Progetti Ingest: ~4 (TEST_Ingest_01 ... TEST_Ingest_04)

---

# 🧹 CLEANUP POST-TEST

Dopo aver completato tutti i test:

```powershell
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

# 1. Dry-run (mostra cosa verrà eliminato)
python cleanup_test_data.py --dry-run

# 2. Se tutto ok, esegui pulizia
python cleanup_test_data.py --execute
```

Il cleanup eliminerà tutti i record con:
- Email che contiene "test_"
- Nome che inizia con "TEST_"
- Creati nelle ultime 24 ore

---

# 📊 REPORT FINALE

```
Data Test: ______________
Tester: Chrome Extension + Claude
Backend: ✅ / ❌
Frontend: ✅ / ❌

Test Passati: ___/40
Test Falliti: ___/40
Test Skipped: ___/40

Bug Critici: ___
Bug Maggiori: ___
Bug Minori: ___

Note:
_________________________________
_________________________________
_________________________________

APPROVATO PER PRODUZIONE: ☐ SÌ  ☐ NO
```

---

**Fine Test Plan v1.0**

# TEST PLAN - Avatar System (Chrome Extension / Manual Testing)

**Progetto**: Media Center Arti Marziali
**Componente**: Avatar 3D System
**Data**: 2026-01-29
**Versione**: 1.0

---

## Ambiente di Test

| Componente | URL | Stato |
|------------|-----|-------|
| Backend FastAPI | http://localhost:8000 | [ ] Attivo |
| Frontend Next.js | http://localhost:3000 | [ ] Attivo |
| Database PostgreSQL | localhost:5432 | [ ] Attivo |

### Prerequisiti
- [ ] Chrome/Edge browser aggiornato
- [ ] Backend avviato: `cd backend && uvicorn main:app --reload`
- [ ] Frontend avviato: `cd frontend && npm run dev`
- [ ] Almeno 2 avatar nel database (seed completato)

---

## SEZIONE 1: API Tests (10 scenari)

### Scenario 01: GET /avatars/ ritorna lista avatar
- **Precondizioni**: Backend attivo, almeno 1 avatar nel DB
- **Steps**:
  1. Aprire DevTools > Network
  2. Navigare a http://localhost:8000/api/v1/avatars/
- **Expected**:
  - Status 200
  - JSON con chiave `avatars` (array)
  - Campi: id, name, style, model_url, thumbnail_url
- **Pass/Fail**: [ ]

---

### Scenario 02: GET /avatars/?style=karate filtra correttamente
- **Precondizioni**: Avatar con stili diversi nel DB
- **Steps**:
  1. GET http://localhost:8000/api/v1/avatars/?style=karate
  2. GET http://localhost:8000/api/v1/avatars/?style=generic
- **Expected**:
  - Solo avatar con style corrispondente
  - Array vuoto se nessun match (no errore)
- **Pass/Fail**: [ ]

---

### Scenario 03: GET /avatars/{id} ritorna dettaglio
- **Precondizioni**: ID avatar valido dalla lista
- **Steps**:
  1. Ottenere ID da GET /avatars/
  2. GET http://localhost:8000/api/v1/avatars/{id}
- **Expected**:
  - Status 200
  - Oggetto singolo avatar
  - Campi aggiuntivi: license_type, attribution, updated_at
- **Pass/Fail**: [ ]

---

### Scenario 04: GET /avatars/{id}/file scarica GLB
- **Precondizioni**: Avatar con file GLB esistente
- **Steps**:
  1. GET http://localhost:8000/api/v1/avatars/{id}/file
  2. Verificare download
- **Expected**:
  - Content-Type: model/gltf-binary o application/octet-stream
  - File scaricabile (dimensione > 0)
- **Pass/Fail**: [ ]

---

### Scenario 05: GET /avatars/styles lista stili disponibili
- **Precondizioni**: Backend attivo
- **Steps**:
  1. GET http://localhost:8000/api/v1/avatars/styles
- **Expected**:
  - Status 200
  - JSON con chiave `styles` (array)
  - Ogni stile ha: value, label, description, avatar_count
  - Stili: karate, kung_fu, taekwondo, judo, generic
- **Pass/Fail**: [ ]

---

### Scenario 06: GET /avatars/bone-mapping 75 landmarks
- **Precondizioni**: Backend attivo
- **Steps**:
  1. GET http://localhost:8000/api/v1/avatars/bone-mapping
- **Expected**:
  - Status 200
  - Chiavi: body, left_hand, right_hand
  - total_landmarks = 75
  - body: 17 landmarks (0-32 sparse)
  - left_hand: 21 landmarks
  - right_hand: 21 landmarks
- **Pass/Fail**: [ ]

---

### Scenario 07: POST /avatars/ richiede autenticazione
- **Precondizioni**: Nessun token JWT
- **Steps**:
  1. POST http://localhost:8000/api/v1/avatars/ senza header Authorization
- **Expected**:
  - Status 401 Unauthorized o 403 Forbidden
- **Pass/Fail**: [ ]

---

### Scenario 08: PUT /avatars/{id} richiede ruolo admin
- **Precondizioni**: Token utente normale (non admin)
- **Steps**:
  1. Login come utente normale
  2. PUT http://localhost:8000/api/v1/avatars/{id} con token
- **Expected**:
  - Status 403 Forbidden
  - Messaggio: "Admin access required" o simile
- **Pass/Fail**: [ ]

---

### Scenario 09: DELETE /avatars/{id} richiede ruolo admin
- **Precondizioni**: Token utente normale
- **Steps**:
  1. DELETE http://localhost:8000/api/v1/avatars/{id} con token normale
- **Expected**:
  - Status 403 Forbidden
- **Pass/Fail**: [ ]

---

### Scenario 10: GET /avatars/invalid-id ritorna 404
- **Precondizioni**: Backend attivo
- **Steps**:
  1. GET http://localhost:8000/api/v1/avatars/00000000-0000-0000-0000-000000000000
  2. GET http://localhost:8000/api/v1/avatars/not-a-uuid
- **Expected**:
  - UUID valido non esistente: Status 404
  - UUID non valido: Status 422 (Validation Error)
- **Pass/Fail**: [ ]

---

## SEZIONE 2: Admin Pages (15 scenari)

### Scenario 11: Admin lista avatar - caricamento iniziale
- **Precondizioni**: Login come admin, navigare a /admin/avatars
- **Steps**:
  1. Navigare a http://localhost:3000/admin/avatars
  2. Attendere caricamento
- **Expected**:
  - Loading spinner mostrato durante fetch
  - Tabella/griglia avatar popolata
  - Conteggio totale visibile
- **Pass/Fail**: [ ]

---

### Scenario 12: Admin lista - filtro per stile
- **Precondizioni**: Pagina admin avatars caricata
- **Steps**:
  1. Selezionare filtro "Karate" dal dropdown
  2. Selezionare filtro "Generic"
  3. Selezionare "Tutti"
- **Expected**:
  - Lista si aggiorna ad ogni cambio
  - URL query param aggiornato (?style=karate)
  - Conteggio aggiornato
- **Pass/Fail**: [ ]

---

### Scenario 13: Admin lista - ordinamento colonne
- **Precondizioni**: Almeno 3 avatar nella lista
- **Steps**:
  1. Click su header "Nome" per ordinare A-Z
  2. Click di nuovo per Z-A
  3. Click su "Data creazione"
- **Expected**:
  - Indicatore freccia visibile
  - Ordinamento applicato correttamente
  - Mantiene filtro attivo
- **Pass/Fail**: [ ]

---

### Scenario 14: Admin lista - paginazione
- **Precondizioni**: Più di 10 avatar (o abbassare page_size)
- **Steps**:
  1. Navigare alla pagina 2
  2. Cambiare items per page
  3. Tornare a pagina 1
- **Expected**:
  - Paginazione funzionante
  - URL aggiornato con ?page=2
  - Items per page rispettato
- **Pass/Fail**: [ ]

---

### Scenario 15: Admin lista - azioni rapide
- **Precondizioni**: Lista avatar caricata
- **Steps**:
  1. Hover su riga avatar
  2. Click su icona "View"
  3. Click su icona "Edit"
  4. Click su icona "Delete" (verificare confirm dialog)
- **Expected**:
  - Icone azioni visibili su hover
  - View apre modal/pagina dettaglio
  - Edit naviga a form modifica
  - Delete mostra conferma prima di procedere
- **Pass/Fail**: [ ]

---

### Scenario 16: Admin dettaglio - caricamento dati
- **Precondizioni**: ID avatar valido
- **Steps**:
  1. Navigare a /admin/avatars/{id}
  2. Attendere caricamento
- **Expected**:
  - Tutti i campi popolati
  - Thumbnail/preview visibile
  - Metadati (created_at, file_size) mostrati
- **Pass/Fail**: [ ]

---

### Scenario 17: Admin dettaglio - form di modifica
- **Precondizioni**: Pagina dettaglio caricata
- **Steps**:
  1. Modificare campo "Nome"
  2. Modificare campo "Descrizione"
  3. Cambiare "Stile" dal dropdown
- **Expected**:
  - Form editabile
  - Validazione inline attiva
  - Pulsante "Salva" abilitato dopo modifica
- **Pass/Fail**: [ ]

---

### Scenario 18: Admin dettaglio - preview 3D viewer
- **Precondizioni**: Avatar con file GLB valido
- **Steps**:
  1. Localizzare sezione 3D preview
  2. Attendere caricamento modello
  3. Interagire con controlli orbit
- **Expected**:
  - Modello 3D caricato e visibile
  - Rotazione con drag
  - Zoom con scroll
- **Pass/Fail**: [ ]

---

### Scenario 19: Admin dettaglio - visualizzazione bone mapping
- **Precondizioni**: Avatar con bone mapping
- **Steps**:
  1. Espandere sezione "Bone Mapping" o tab dedicato
  2. Verificare lista bones
- **Expected**:
  - Lista bones del rig visibile
  - Bone count mostrato (es. 65 bones)
  - has_hand_bones indicato
- **Pass/Fail**: [ ]

---

### Scenario 20: Admin dettaglio - salvataggio modifiche
- **Precondizioni**: Modifiche nel form
- **Steps**:
  1. Modificare almeno un campo
  2. Click "Salva"
  3. Ricaricare pagina
- **Expected**:
  - Toast/notifica "Salvato con successo"
  - Modifiche persistite dopo reload
  - updated_at aggiornato
- **Pass/Fail**: [ ]

---

### Scenario 21: Admin upload - drag & drop file
- **Precondizioni**: Navigare a /admin/avatars/new
- **Steps**:
  1. Trascinare file .glb sulla dropzone
  2. Rilasciare
- **Expected**:
  - Dropzone evidenziata durante drag
  - File accettato se .glb/.gltf
  - Preview nome file mostrato
- **Pass/Fail**: [ ]

---

### Scenario 22: Admin upload - validazione 50MB limit
- **Precondizioni**: File GLB > 50MB disponibile
- **Steps**:
  1. Tentare upload file > 50MB
- **Expected**:
  - Errore "File troppo grande (max 50MB)"
  - Upload non inizia
  - Form non submitted
- **Pass/Fail**: [ ]

---

### Scenario 23: Admin upload - preview pre-submit
- **Precondizioni**: File GLB valido selezionato
- **Steps**:
  1. Selezionare file GLB valido
  2. Attendere generazione preview
- **Expected**:
  - Thumbnail preview generato
  - Info file mostrate (nome, dimensione)
  - Anteprima 3D se disponibile
- **Pass/Fail**: [ ]

---

### Scenario 24: Admin upload - compilazione form
- **Precondizioni**: File selezionato
- **Steps**:
  1. Compilare "Nome" (obbligatorio)
  2. Compilare "Descrizione"
  3. Selezionare "Stile"
  4. Toggle "Pubblico"
- **Expected**:
  - Validazione campo nome (min 3 char)
  - Dropdown stili popolato
  - Toggle funzionante
- **Pass/Fail**: [ ]

---

### Scenario 25: Admin upload - submit e creazione
- **Precondizioni**: Form valido compilato
- **Steps**:
  1. Click "Crea Avatar"
  2. Attendere upload
  3. Verificare redirect a lista
- **Expected**:
  - Progress bar durante upload
  - Success message
  - Redirect a /admin/avatars
  - Nuovo avatar visibile in lista
- **Pass/Fail**: [ ]

---

## SEZIONE 3: User Gallery (10 scenari)

### Scenario 26: Gallery - caricamento iniziale
- **Precondizioni**: Frontend attivo, utente loggato
- **Steps**:
  1. Navigare a /avatar-gallery
  2. Attendere caricamento
- **Expected**:
  - Loading skeleton/spinner
  - Griglia avatar popolata
  - Titolo "Avatar 3D" visibile
- **Pass/Fail**: [ ]

---

### Scenario 27: Gallery - visualizzazione griglia
- **Precondizioni**: Gallery caricata con avatar
- **Steps**:
  1. Verificare layout griglia
  2. Contare colonne su desktop
  3. Ridimensionare finestra a mobile
- **Expected**:
  - Desktop: 4 colonne
  - Tablet: 3 colonne
  - Mobile: 2 colonne
  - Card uniformi con thumbnail
- **Pass/Fail**: [ ]

---

### Scenario 28: Gallery - search bar funzionante
- **Precondizioni**: Almeno 3 avatar con nomi diversi
- **Steps**:
  1. Digitare "karate" nella search bar
  2. Digitare "xyz" (nessun match)
  3. Cancellare ricerca
- **Expected**:
  - Filtro applicato in tempo reale
  - Nessun risultato mostra empty state
  - Clear ripristina lista completa
- **Pass/Fail**: [ ]

---

### Scenario 29: Gallery - filter chips stili
- **Precondizioni**: Avatar con stili diversi
- **Steps**:
  1. Click chip "Karate"
  2. Click chip "Kung Fu"
  3. Click chip "Tutti"
- **Expected**:
  - Chip selezionato evidenziato
  - Lista filtrata per stile
  - "Tutti" mostra tutti
- **Pass/Fail**: [ ]

---

### Scenario 30: Gallery - responsive design
- **Precondizioni**: Gallery visibile
- **Steps**:
  1. Testare su viewport 1920px
  2. Testare su viewport 768px
  3. Testare su viewport 375px
- **Expected**:
  - Layout adattivo
  - Nessun overflow orizzontale
  - Touch friendly su mobile
- **Pass/Fail**: [ ]

---

### Scenario 31: Gallery preview - apertura modal
- **Precondizioni**: Gallery con avatar
- **Steps**:
  1. Click su card avatar
  2. Attendere apertura modal
- **Expected**:
  - Modal si apre con animazione
  - Background scurito
  - Focus intrappolato nel modal
- **Pass/Fail**: [ ]

---

### Scenario 32: Gallery preview - 3D viewer nel modal
- **Precondizioni**: Modal aperto
- **Steps**:
  1. Attendere caricamento 3D
  2. Verificare visualizzazione modello
- **Expected**:
  - Modello GLB caricato
  - Rotazione automatica o statica
  - Sfondo appropriato
- **Pass/Fail**: [ ]

---

### Scenario 33: Gallery preview - controlli 3D
- **Precondizioni**: 3D viewer caricato nel modal
- **Steps**:
  1. Drag per ruotare
  2. Scroll/pinch per zoom
  3. Click pulsante reset view
- **Expected**:
  - Rotazione smooth
  - Zoom in/out funzionante
  - Reset riporta a vista iniziale
- **Pass/Fail**: [ ]

---

### Scenario 34: Gallery preview - selezione avatar
- **Precondizioni**: Modal preview aperto
- **Steps**:
  1. Click pulsante "Seleziona questo avatar"
  2. Verificare feedback
- **Expected**:
  - Conferma selezione (toast/check)
  - Modal si chiude
  - Avatar marcato come selezionato in gallery
- **Pass/Fail**: [ ]

---

### Scenario 35: Gallery preview - chiusura modal
- **Precondizioni**: Modal aperto
- **Steps**:
  1. Click X in alto a destra
  2. Riaprire e click su backdrop
  3. Riaprire e premere ESC
- **Expected**:
  - Tutte e 3 le modalità chiudono il modal
  - Focus torna alla gallery
- **Pass/Fail**: [ ]

---

## SEZIONE 4: 3D Viewer (10 scenari)

### Scenario 36: 3D Viewer - caricamento GLB
- **Precondizioni**: Viewer inizializzato
- **Steps**:
  1. Passare URL file GLB al viewer
  2. Monitorare caricamento
- **Expected**:
  - Loading indicator durante fetch
  - Modello renderizzato dopo load
  - Nessun errore console
- **Pass/Fail**: [ ]

---

### Scenario 37: 3D Viewer - orbit controls
- **Precondizioni**: Modello caricato
- **Steps**:
  1. Click + drag sinistro (ruota)
  2. Click + drag destro (pan)
  3. Verificare limiti rotazione
- **Expected**:
  - Rotazione orbitale attorno al centro
  - Pan shifta il punto di vista
  - Limiti impediscono flip
- **Pass/Fail**: [ ]

---

### Scenario 38: 3D Viewer - zoom
- **Precondizioni**: Modello visibile
- **Steps**:
  1. Scroll wheel zoom in
  2. Scroll wheel zoom out
  3. Pinch gesture su touch
- **Expected**:
  - Zoom smooth
  - Limiti min/max rispettati
  - Non si perde il modello
- **Pass/Fail**: [ ]

---

### Scenario 39: 3D Viewer - reset view
- **Precondizioni**: Vista modificata (zoom/rotazione)
- **Steps**:
  1. Modificare vista liberamente
  2. Click pulsante "Reset" o doppio click
- **Expected**:
  - Vista torna alla posizione iniziale
  - Camera reset smooth
- **Pass/Fail**: [ ]

---

### Scenario 40: 3D Viewer - illuminazione
- **Precondizioni**: Modello caricato
- **Steps**:
  1. Osservare ombre e riflessi
  2. Ruotare modello 360°
- **Expected**:
  - Illuminazione coerente
  - Ombre morbide
  - Nessun artefatto visivo
- **Pass/Fail**: [ ]

---

### Scenario 41: 3D Viewer - performance load time
- **Precondizioni**: DevTools > Performance aperto
- **Steps**:
  1. Misurare tempo caricamento GLB (3MB)
  2. Ripetere 3 volte
- **Expected**:
  - Load time < 3 secondi su connessione veloce
  - Load time < 5 secondi su 3G simulato
- **Pass/Fail**: [ ]

---

### Scenario 42: 3D Viewer - smooth rotation (FPS)
- **Precondizioni**: DevTools > Rendering > FPS meter
- **Steps**:
  1. Abilitare FPS meter
  2. Ruotare modello continuamente per 10s
- **Expected**:
  - FPS stabile >= 30fps
  - Nessun frame drop significativo
  - Nessun stuttering
- **Pass/Fail**: [ ]

---

### Scenario 43: 3D Viewer - memory usage
- **Precondizioni**: DevTools > Memory
- **Steps**:
  1. Snapshot memoria prima di aprire viewer
  2. Caricare modello 3D
  3. Snapshot dopo caricamento
  4. Chiudere viewer e snapshot
- **Expected**:
  - Incremento memoria < 100MB per modello
  - Memoria rilasciata dopo chiusura
  - No memory leaks evidenti
- **Pass/Fail**: [ ]

---

### Scenario 44: 3D Viewer - gestione errori file
- **Precondizioni**: URL file invalido
- **Steps**:
  1. Tentare caricare URL inesistente
  2. Tentare caricare file corrotto
- **Expected**:
  - Messaggio errore user-friendly
  - Nessun crash viewer
  - Opzione retry disponibile
- **Pass/Fail**: [ ]

---

### Scenario 45: 3D Viewer - touch device
- **Precondizioni**: Device touch o emulazione Chrome
- **Steps**:
  1. Single finger drag (rotate)
  2. Two finger pinch (zoom)
  3. Two finger drag (pan)
- **Expected**:
  - Gesture riconosciute correttamente
  - Smooth come mouse
  - Nessun conflict con scroll pagina
- **Pass/Fail**: [ ]

---

## SEZIONE 5: Integration Tests (5 scenari)

### Scenario 46: Avatar selezionato persiste in localStorage
- **Precondizioni**: Gallery aperta, nessun avatar selezionato
- **Steps**:
  1. Selezionare un avatar
  2. Chiudere tab browser
  3. Riaprire pagina
- **Expected**:
  - localStorage contiene selectedAvatarId
  - Al reload avatar pre-selezionato
  - UI mostra selezione corrente
- **Pass/Fail**: [ ]

---

### Scenario 47: Cambio avatar aggiorna player video
- **Precondizioni**: Video player con avatar overlay attivo
- **Steps**:
  1. Aprire video con avatar attivo
  2. Navigare a gallery in altro tab
  3. Cambiare avatar selezionato
  4. Tornare al player
- **Expected**:
  - Player rileva cambio avatar
  - Nuovo modello 3D caricato
  - Skeleton sync continua
- **Pass/Fail**: [ ]

---

### Scenario 48: Skeleton sync con avatar selezionato
- **Precondizioni**: Video con skeleton data, avatar selezionato
- **Steps**:
  1. Play video con skeleton analysis
  2. Verificare avatar nel player
  3. Seek a timestamp diverso
- **Expected**:
  - Avatar segue pose skeleton
  - Sync in tempo reale
  - Seek aggiorna pose immediata
- **Pass/Fail**: [ ]

---

### Scenario 49: Multi-tab consistency
- **Precondizioni**: App aperta in 2 tab
- **Steps**:
  1. Tab 1: Selezionare avatar A
  2. Tab 2: Verificare selezione
  3. Tab 2: Selezionare avatar B
  4. Tab 1: Verificare aggiornamento
- **Expected**:
  - Selezione sincronizzata via localStorage event
  - UI aggiornata in entrambi i tab
  - Nessun conflitto
- **Pass/Fail**: [ ]

---

### Scenario 50: Offline fallback avatars
- **Precondizioni**: Almeno 1 avatar già visualizzato
- **Steps**:
  1. Caricare gallery (popola cache)
  2. DevTools > Network > Offline
  3. Ricaricare pagina
- **Expected**:
  - Avatar cached visibili
  - Modelli 3D già scaricati funzionano
  - Messaggio "Offline mode" se necessario
- **Pass/Fail**: [ ]

---

## Riepilogo Esecuzione

| Sezione | Totale | Passed | Failed | Blocked |
|---------|--------|--------|--------|---------|
| API Tests | 10 | | | |
| Admin Pages | 15 | | | |
| User Gallery | 10 | | | |
| 3D Viewer | 10 | | | |
| Integration | 5 | | | |
| **TOTALE** | **50** | | | |

---

## Note Tester

```
Data esecuzione: ____________________
Tester: ____________________
Browser: Chrome _______ / Edge _______ / Firefox _______
OS: Windows / macOS / Linux
Risoluzione: _____ x _____

Note generali:
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________

Bug trovati:
_________________________________________________________________
_________________________________________________________________
_________________________________________________________________
```

---

*Test Plan generato il 2026-01-29*
*Progetto: Media Center Arti Marziali - Avatar System*

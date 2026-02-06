# 🧪 TEST E2E COMPLETO - MEDIA CENTER ARTI MARZIALI
## 200+ Funzionalità da Testare con Claude Code Web + Chrome Extension

**Data:** 2026-02-02
**Versione:** 1.0
**Ambiente:** http://localhost:3100 (frontend) + http://localhost:8000 (backend)

---

# 📋 ISTRUZIONI GENERALI

## Prima di iniziare:
1. Assicurati che backend sia attivo: `http://localhost:8000/health` → deve rispondere `{"status":"healthy"}`
2. Assicurati che frontend sia attivo: `http://localhost:3100` → deve caricare la pagina
3. Per ogni test, registra: ✅ PASS, ❌ FAIL, ⚠️ PARZIALE, 🔒 RICHIEDE AUTH

## Credenziali Test:
- **Admin:** admin@mediacenter.it / Admin2024!
- **Maestro:** maestro@test.it / Maestro2024! (se esiste)
- **Studente:** studente@test.it / Student2024! (se esiste)

## Come testare:
1. Naviga alla pagina indicata
2. Verifica che la pagina carichi senza errori console
3. Testa le interazioni indicate
4. Registra risultato e eventuali errori

---

# 🔐 SEZIONE 1: AUTENTICAZIONE E AUTORIZZAZIONE (20 Test)

## 1.1 Login Page (/login)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 001 | Caricamento pagina login | Vai a /login | Pagina carica, form visibile |
| 002 | Validazione email vuota | Clicca Accedi senza email | Errore validazione |
| 003 | Validazione password vuota | Inserisci solo email, clicca Accedi | Errore validazione |
| 004 | Login con credenziali errate | admin@test.it / wrongpass | Errore "Not Found" o "Invalid credentials" |
| 005 | Login con credenziali corrette | admin@mediacenter.it / Admin2024! | Redirect a home |
| 006 | Mostra/nascondi password | Clicca icona occhio | Password visibile/nascosta |
| 007 | Checkbox "Ricordami" | Clicca checkbox | Stato toggle |
| 008 | Link "Password dimenticata" | Clicca link | Naviga a pagina recupero |
| 009 | Pulsante "Accedi con Google" | Visibile? Cliccabile? | Testa OAuth flow |
| 010 | Link "Registrati" | Clicca link | Naviga a /register |

## 1.2 Register Page (/register)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 011 | Caricamento pagina registrazione | Vai a /register | Form registrazione visibile |
| 012 | Validazione campi obbligatori | Submit form vuoto | Errori validazione |
| 013 | Validazione email formato | Inserisci "notanemail" | Errore formato email |
| 014 | Validazione password debole | Password "123" | Errore requisiti password |
| 015 | Conferma password mismatch | Password diverse | Errore mismatch |
| 016 | Registrazione nuovo utente | Compila correttamente | Account creato, redirect |
| 017 | Email già esistente | Usa email esistente | Errore duplicato |
| 018 | Link "Hai già un account?" | Clicca link | Naviga a /login |

## 1.3 Logout e Sessione
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 019 | Logout | Clicca logout nel menu | Redirect a login, token rimosso |
| 020 | Accesso pagina protetta senza auth | Vai a /curriculum senza login | Redirect a /login |

---

# 🏠 SEZIONE 2: HOME E NAVIGAZIONE (15 Test)

## 2.1 Home Page (/)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 021 | Caricamento home | Vai a / | Pagina carica correttamente |
| 022 | Header visibile | Controlla header | Logo, menu, user info |
| 023 | Footer visibile | Controlla footer | Link, copyright |
| 024 | Menu navigazione | Controlla menu | Tutti i link presenti |
| 025 | Responsive mobile | Ridimensiona a 375px | Layout adattato |
| 026 | Responsive tablet | Ridimensiona a 768px | Layout adattato |

## 2.2 Navigazione Generale
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 027 | Link a /curriculum | Clicca "Curricula" nel menu | Naviga correttamente |
| 028 | Link a /library | Clicca "Libreria" nel menu | Naviga correttamente |
| 029 | Link a /me | Clicca su avatar/profilo | Naviga a profilo |
| 030 | Link a /admin (se admin) | Clicca "Admin" | Naviga a dashboard admin |
| 031 | Breadcrumb navigation | Verifica breadcrumb | Mostra percorso corretto |
| 032 | Back button browser | Usa back button | Navigazione cronologia OK |
| 033 | Language switcher | Cambia lingua | UI tradotta |
| 034 | Dark/Light mode toggle | Cambia tema | Colori cambiano |
| 035 | Notifiche badge | Controlla icona notifiche | Badge con conteggio |

---

# 📚 SEZIONE 3: CURRICULA (30 Test)

## 3.1 Catalogo Curricula (/curriculum)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 036 | Caricamento catalogo | Vai a /curriculum (dopo login) | Lista curricula visibile |
| 037 | Skeleton loading | Osserva durante caricamento | Skeleton placeholders |
| 038 | Lista vuota | Se nessun curriculum | Messaggio "Nessun curriculum" |
| 039 | Card curriculum | Verifica card | Titolo, descrizione, thumbnail |
| 040 | Badge disciplina | Verifica badge | Karate, Judo, etc. |
| 041 | Badge cintura | Verifica badge | Colore cintura corretto |
| 042 | Prezzo visualizzato | Verifica prezzo | €XX.XX o "Gratis" |
| 043 | Rating stelle | Verifica rating | Stelle colorate (0-5) |
| 044 | Numero recensioni | Verifica conteggio | "(XX recensioni)" |
| 045 | Filtro per disciplina | Seleziona "Karate" | Lista filtrata |
| 046 | Filtro per livello | Seleziona "Principiante" | Lista filtrata |
| 047 | Ricerca testuale | Cerca "kata" | Risultati filtrati |
| 048 | Ordinamento | Ordina per prezzo/rating | Lista riordinata |
| 049 | Paginazione | Naviga pagine | Cambia pagina |
| 050 | Infinite scroll | Scrolla in basso | Carica altri curricula |

## 3.2 Dettaglio Curriculum (/curriculum/[id])
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 051 | Caricamento dettaglio | Clicca su un curriculum | Pagina dettaglio |
| 052 | Header curriculum | Verifica header | Titolo, maestro, rating |
| 053 | Descrizione completa | Leggi descrizione | Testo formattato |
| 054 | Elenco livelli | Verifica accordion | Lista livelli espandibili |
| 055 | Video preview | Clicca video preview | Player si apre |
| 056 | Requisiti | Verifica requisiti | Lista requisiti |
| 057 | Pulsante "Iscriviti" | Clicca pulsante | Flow iscrizione |
| 058 | Pulsante "Acquista" | Clicca pulsante | Flow pagamento |
| 059 | Recensioni lista | Verifica recensioni | Lista recensioni utenti |
| 060 | Scrivi recensione | Compila form recensione | Recensione salvata |
| 061 | Curriculum del maestro | Verifica info maestro | Nome, bio, avatar |
| 062 | Curricula correlati | Verifica sezione | Lista curricula simili |

## 3.3 Apprendimento (/curriculum/[id]/learn)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 063 | Caricamento pagina learn | Vai a learn | Player e sidebar |
| 064 | Video player | Verifica player | Controlli funzionanti |
| 065 | Play/Pause | Clicca play | Video parte/ferma |
| 066 | Seek bar | Trascina seek | Video salta |
| 067 | Volume | Regola volume | Audio cambia |
| 068 | Fullscreen | Clicca fullscreen | Player a schermo intero |
| 069 | Sidebar lezioni | Verifica sidebar | Lista lezioni |
| 070 | Cambio lezione | Clicca altra lezione | Video cambia |
| 071 | Progresso salvato | Esci e torna | Riprende da dove eri |
| 072 | Completamento lezione | Finisci video | Segna come completata |
| 073 | Pulsante "Prossima" | Clicca prossima | Avanza lezione |
| 074 | AI Feedback panel | Verifica panel | Feedback AI visibile |
| 075 | Quiz fine lezione | Completa quiz | Risultato mostrato |

---

# 🎬 SEZIONE 4: VIDEO E MEDIA (25 Test)

## 4.1 Libreria Video (/library)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 076 | Caricamento libreria | Vai a /library | Grid video visibile |
| 077 | Thumbnail video | Verifica thumbnail | Immagini caricate |
| 078 | Titolo e durata | Verifica info | Testo visibile |
| 079 | Filtri categoria | Filtra per categoria | Lista filtrata |
| 080 | Ricerca video | Cerca "punch" | Risultati filtrati |
| 081 | Player inline | Hover su card | Preview video |

## 4.2 Upload Video (/upload o /maestro/upload)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 082 | Caricamento pagina upload | Vai a /upload | Form upload visibile |
| 083 | Drag & Drop zone | Trascina file | File accettato |
| 084 | Click to upload | Clicca zona | File browser aperto |
| 085 | Validazione formato | Carica .txt | Errore formato |
| 086 | Validazione dimensione | Carica file enorme | Errore dimensione |
| 087 | Progress bar | Durante upload | Barra progresso |
| 088 | Metadati video | Compila form | Titolo, descrizione, tags |
| 089 | Thumbnail auto | Verifica thumbnail | Generato automaticamente |
| 090 | Thumbnail custom | Carica thumbnail | Accettato |
| 091 | Salva video | Clicca salva | Video salvato |

## 4.3 Player Video Avanzato
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 092 | Controlli player | Verifica controlli | Play, pause, seek, volume |
| 093 | Quality selector | Cambia qualità | Video cambia risoluzione |
| 094 | Playback speed | Cambia velocità | Video accelera/rallenta |
| 095 | Sottotitoli | Attiva sottotitoli | Testo visibile |
| 096 | Picture-in-Picture | Attiva PiP | Finestra mobile |
| 097 | Keyboard shortcuts | Premi spazio | Play/Pause |
| 098 | Double-click fullscreen | Doppio click | Fullscreen toggle |
| 099 | Loop video | Attiva loop | Video ricomincia |
| 100 | Timestamp URL | Copia link con tempo | URL con ?t=XX |

---

# 🦴 SEZIONE 5: SKELETON E POSE DETECTION (25 Test)

## 5.1 Skeleton Library (/skeleton-library)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 101 | Caricamento libreria skeleton | Vai a /skeleton-library | Lista skeleton visibile |
| 102 | Card skeleton | Verifica card | Preview, nome, data |
| 103 | Filtro per disciplina | Filtra per arte | Lista filtrata |
| 104 | Ricerca skeleton | Cerca "kick" | Risultati filtrati |
| 105 | Preview 3D | Hover su card | Anteprima 3D |

## 5.2 Skeleton Viewer (/skeleton-viewer)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 106 | Caricamento viewer | Vai a /skeleton-viewer | Canvas 3D visibile |
| 107 | Rotazione 3D | Trascina mouse | Modello ruota |
| 108 | Zoom | Scroll mouse | Modello zoom in/out |
| 109 | Pan | Click destro + trascina | Modello si sposta |
| 110 | Animazione play | Clicca play | Skeleton animato |
| 111 | Timeline scrubber | Trascina timeline | Frame cambia |
| 112 | Wireframe toggle | Attiva wireframe | Vista wireframe |
| 113 | Joints visibili | Toggle joints | Pallini articolazioni |
| 114 | Export JSON | Clicca export | File scaricato |

## 5.3 Skeleton Editor (/skeleton-editor)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 115 | Caricamento editor | Vai a /skeleton-editor | Editor con canvas |
| 116 | Import video | Carica video | Video nel canvas |
| 117 | Pose detection start | Avvia detection | Elaborazione inizia |
| 118 | Progress indicator | Durante detection | Percentuale mostrata |
| 119 | Skeleton overlay | Dopo detection | Skeleton su video |
| 120 | Modifica manuale joint | Trascina joint | Posizione cambia |
| 121 | Aggiungi keyframe | Clicca "Add keyframe" | Keyframe aggiunto |
| 122 | Delete keyframe | Elimina keyframe | Keyframe rimosso |
| 123 | Salva skeleton | Clicca salva | Skeleton salvato |
| 124 | Export MP4 con overlay | Export | Video con skeleton |
| 125 | Export JSON skeleton | Export JSON | File dati scaricato |

---

# 🔀 SEZIONE 6: FUSION VIDEO (20 Test)

## 6.1 Fusion Dashboard (/fusion)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 126 | Caricamento fusion | Vai a /fusion | Dashboard visibile |
| 127 | Lista progetti fusion | Verifica lista | Progetti esistenti |
| 128 | Crea nuovo progetto | Clicca "Nuovo" | Form creazione |
| 129 | Nome progetto | Inserisci nome | Campo accetta input |
| 130 | Selezione video source | Seleziona video | Video aggiunto a lista |

## 6.2 Fusion Editor (/fusion/[id])
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 131 | Caricamento editor fusion | Vai a /fusion/[id] | Editor multi-video |
| 132 | Timeline multi-track | Verifica timeline | Più tracce visibili |
| 133 | Sync video | Allinea video | Video sincronizzati |
| 134 | Split screen preview | Attiva split | Vista multipla |
| 135 | Skeleton extraction | Avvia estrazione | Progress per ogni video |
| 136 | Skeleton merge/average | Calcola media | Skeleton consenso |
| 137 | Export fused skeleton | Export | File skeleton unico |
| 138 | Export comparison video | Export video | Video side-by-side |
| 139 | Annotazioni | Aggiungi annotazione | Marker sulla timeline |
| 140 | Salva progetto | Clicca salva | Progetto salvato |

## 6.3 Ingest Studio (/ingest-studio)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 141 | Caricamento ingest studio | Vai a /ingest-studio | Interfaccia ingest |
| 142 | DVD Import tab | Clicca tab DVD | Form import DVD |
| 143 | Project selector | Seleziona progetto | Progetto caricato |
| 144 | Mix panel | Verifica mix panel | Opzioni mixing |
| 145 | Processing options | Configura opzioni | Settings salvate |

---

# 👤 SEZIONE 7: PROFILO UTENTE (15 Test)

## 7.1 Profilo (/me)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 146 | Caricamento profilo | Vai a /me | Pagina profilo |
| 147 | Avatar utente | Verifica avatar | Immagine visibile |
| 148 | Info base | Verifica nome, email | Dati corretti |
| 149 | Modifica avatar | Clicca avatar | Upload nuovo avatar |
| 150 | Modifica nome | Modifica campo | Salvataggio OK |
| 151 | Modifica bio | Modifica bio | Salvataggio OK |
| 152 | Cambio password | Compila form cambio | Password aggiornata |
| 153 | Email verificata badge | Verifica badge | Badge visibile |
| 154 | Statistiche utente | Verifica stats | Corsi, ore, etc. |

## 7.2 Subscriptions (/me/subscriptions)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 155 | Lista abbonamenti | Vai a /me/subscriptions | Lista abbonamenti |
| 156 | Stato abbonamento | Verifica stato | Attivo/Scaduto |
| 157 | Rinnova abbonamento | Clicca rinnova | Flow pagamento |
| 158 | Annulla abbonamento | Clicca annulla | Conferma richiesta |
| 159 | Storico pagamenti | Verifica storico | Lista transazioni |
| 160 | Scarica ricevuta | Clicca download | PDF scaricato |

---

# 👨‍🏫 SEZIONE 8: DASHBOARD MAESTRO (20 Test)

## 8.1 Dashboard ASD (/asd-dashboard)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 161 | Caricamento dashboard | Vai a /asd-dashboard | Dashboard maestro |
| 162 | Stats overview | Verifica stats | Studenti, guadagni, views |
| 163 | Grafico guadagni | Verifica grafico | Chart visibile |
| 164 | Lista studenti | Vai a /asd-dashboard/students | Lista studenti |
| 165 | Dettaglio studente | Clicca studente | Profilo studente |
| 166 | Progresso studente | Verifica progresso | Barra avanzamento |

## 8.2 Gestione Curricula Maestro (/manage/curricula)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 167 | Lista curricula propri | Vai a /manage/curricula | I miei curricula |
| 168 | Crea curriculum | Clicca "Nuovo" | Form creazione |
| 169 | Modifica curriculum | Clicca edit | Form modifica |
| 170 | Elimina curriculum | Clicca delete | Conferma eliminazione |
| 171 | Aggiungi livello | Aggiungi livello | Livello aggiunto |
| 172 | Aggiungi video a livello | Aggiungi video | Video collegato |
| 173 | Ordina livelli | Drag & drop | Ordine cambiato |
| 174 | Pubblica curriculum | Toggle pubblica | Stato pubblicato |

## 8.3 Eventi (/asd-dashboard/events)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 175 | Lista eventi | Vai a /asd-dashboard/events | I miei eventi |
| 176 | Crea evento | Clicca "Nuovo" | Form creazione |
| 177 | Dettaglio evento | Clicca evento | Pagina dettaglio |
| 178 | Modifica evento | Modifica campi | Salvataggio OK |
| 179 | Partecipanti evento | Verifica lista | Iscritti visibili |
| 180 | Cancella evento | Clicca cancella | Conferma richiesta |

---

# 🛡️ SEZIONE 9: ADMIN PANEL (30 Test)

## 9.1 Dashboard Admin (/admin)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 181 | Accesso admin | Vai a /admin (come admin) | Dashboard admin |
| 182 | Stats piattaforma | Verifica stats | Utenti, video, revenue |
| 183 | Grafici analytics | Verifica grafici | Charts visibili |
| 184 | Quick actions | Verifica azioni rapide | Bottoni funzionanti |

## 9.2 Gestione Utenti (/admin/users)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 185 | Lista utenti | Vai a /admin/users | Tabella utenti |
| 186 | Ricerca utente | Cerca per email | Risultati filtrati |
| 187 | Filtro per ruolo | Filtra "admin" | Solo admin |
| 188 | Dettaglio utente | Clicca utente | Pagina dettaglio |
| 189 | Modifica ruolo | Cambia ruolo | Ruolo aggiornato |
| 190 | Sospendi utente | Clicca sospendi | Utente sospeso |
| 191 | Riattiva utente | Clicca riattiva | Utente attivo |
| 192 | Elimina utente | Clicca elimina | Conferma eliminazione |

## 9.3 Moderazione (/admin/moderation)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 193 | Queue moderazione | Vai a /admin/moderation | Coda contenuti |
| 194 | Preview contenuto | Clicca contenuto | Anteprima |
| 195 | Approva contenuto | Clicca approva | Contenuto approvato |
| 196 | Rifiuta contenuto | Clicca rifiuta | Richiede motivo |
| 197 | Flag contenuto | Clicca flag | Aggiungi flag |

## 9.4 System Settings (/admin/system/settings)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 198 | Caricamento settings | Vai a /admin/system/settings | Form settings |
| 199 | Modifica site name | Cambia nome | Salvataggio OK |
| 200 | Toggle maintenance | Attiva maintenance | Flag salvato |
| 201 | Session timeout | Modifica timeout | Valore salvato |
| 202 | Max upload size | Modifica size | Valore salvato |
| 203 | Salva settings | Clicca salva | Tutto salvato |

## 9.5 Logs e Jobs (/admin/system/logs, /admin/system/jobs)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 204 | System logs | Vai a /admin/system/logs | Lista log |
| 205 | Filtro logs | Filtra per livello | Log filtrati |
| 206 | Background jobs | Vai a /admin/system/jobs | Lista jobs |
| 207 | Stato job | Verifica stati | Running, completed, failed |
| 208 | Retry job | Clicca retry | Job riavviato |
| 209 | Cancel job | Clicca cancel | Job cancellato |

## 9.6 Analytics (/admin/analytics)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 210 | Dashboard analytics | Vai a /admin/analytics | Charts analytics |
| 211 | Utenti attivi | Verifica metrica | Numero visibile |
| 212 | Video views | Verifica views | Conteggio views |
| 213 | Revenue chart | Verifica revenue | Grafico entrate |
| 214 | Export report | Clicca export | CSV/PDF scaricato |

---

# 💳 SEZIONE 10: PAGAMENTI E DONAZIONI (10 Test)

## 10.1 Checkout
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 215 | Flow acquisto curriculum | Inizia acquisto | Pagina checkout |
| 216 | Riepilogo ordine | Verifica riepilogo | Prezzo corretto |
| 217 | Metodi pagamento | Verifica metodi | Stripe, PayPal, etc. |
| 218 | Pagamento Stripe | Completa pagamento | Success page |
| 219 | Pagamento fallito | Simula fallimento | Errore gestito |

## 10.2 Donazioni (/donations)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 220 | Pagina donazioni | Vai a /donations | Form donazione |
| 221 | Importo custom | Inserisci importo | Accettato |
| 222 | Importi preset | Clicca €5, €10, €20 | Importo selezionato |
| 223 | Dona anonimo | Toggle anonimo | Opzione salvata |
| 224 | Completa donazione | Paga | Thank you page |

---

# 🔔 SEZIONE 11: NOTIFICHE E COMUNICAZIONI (10 Test)

## 11.1 Notifiche
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 225 | Badge notifiche | Verifica header | Badge con numero |
| 226 | Dropdown notifiche | Clicca icona | Lista notifiche |
| 227 | Notifica non letta | Verifica stile | Evidenziata |
| 228 | Segna come letta | Clicca notifica | Stile cambia |
| 229 | Segna tutte lette | Clicca "Segna tutte" | Tutte lette |

## 11.2 Chat (/chat)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 230 | Caricamento chat | Vai a /chat | Interfaccia chat |
| 231 | Lista conversazioni | Verifica lista | Conversazioni visibili |
| 232 | Apri conversazione | Clicca conversazione | Messaggi visibili |
| 233 | Invia messaggio | Scrivi e invia | Messaggio appare |
| 234 | Real-time update | Ricevi messaggio | Appare senza refresh |

---

# 🎭 SEZIONE 12: AVATAR E 3D (10 Test)

## 12.1 Avatar Gallery (/avatar-gallery)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 235 | Caricamento gallery | Vai a /avatar-gallery | Grid avatar |
| 236 | Preview 3D avatar | Hover su avatar | Anteprima 3D |
| 237 | Seleziona avatar | Clicca avatar | Avatar selezionato |
| 238 | Applica avatar | Clicca applica | Avatar aggiornato |

## 12.2 Admin Avatars (/admin/avatars)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 239 | Lista avatar admin | Vai a /admin/avatars | Tutti gli avatar |
| 240 | Crea avatar | Clicca "Nuovo" | Form creazione |
| 241 | Upload modello 3D | Carica .glb | File accettato |
| 242 | Preview 3D | Visualizza preview | Modello renderizzato |
| 243 | Pubblica avatar | Toggle pubblica | Avatar pubblico |
| 244 | Elimina avatar | Clicca elimina | Avatar rimosso |

---

# 🌐 SEZIONE 13: TRADUZIONE E LOCALIZZAZIONE (10 Test)

## 13.1 Translation Page (/translation)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 245 | Caricamento translation | Vai a /translation | Interfaccia traduzione |
| 246 | Seleziona lingua source | Seleziona italiano | Lingua selezionata |
| 247 | Seleziona lingua target | Seleziona inglese | Lingua selezionata |
| 248 | Input testo | Inserisci testo | Testo accettato |
| 249 | Avvia traduzione | Clicca traduci | Traduzione mostrata |
| 250 | Copia risultato | Clicca copia | Copiato in clipboard |

## 13.2 Live Translation (se disponibile)
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 251 | Attiva live subtitles | Toggle sottotitoli | Sottotitoli visibili |
| 252 | Cambia lingua sottotitoli | Seleziona lingua | Lingua cambiata |
| 253 | Text-to-speech | Attiva TTS | Audio riprodotto |
| 254 | Voice cloning (dev) | Vai a /dev/voice-cloning | Interfaccia cloning |

---

# 📱 SEZIONE 14: RESPONSIVE E PERFORMANCE (10 Test)

## 14.1 Mobile Testing
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 255 | Mobile menu | Apri menu hamburger | Menu slide-in |
| 256 | Touch gestures video | Swipe su player | Seek/volume |
| 257 | Form mobile | Compila form su mobile | Tastiera non copre |
| 258 | Scroll performance | Scrolla liste lunghe | No jank |

## 14.2 Performance
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 259 | First Contentful Paint | Misura FCP | < 2s |
| 260 | Largest Contentful Paint | Misura LCP | < 4s |
| 261 | Time to Interactive | Misura TTI | < 5s |
| 262 | Lazy loading immagini | Verifica network | Immagini lazy loaded |
| 263 | Code splitting | Verifica chunks | Chunks separati |
| 264 | Cache assets | Verifica cache | Assets cached |

---

# 🔧 SEZIONE 15: DEV TOOLS E TESTING (6 Test)

## 15.1 Dev Pages
| # | Test | Azione | Risultato Atteso |
|---|------|--------|------------------|
| 265 | Pose detection dev | Vai a /dev/pose-detection | Tool funzionante |
| 266 | Technique annotation | Vai a /dev/technique-annotation | Editor annotazioni |
| 267 | Monitor page | Vai a /monitor | Stats sistema |
| 268 | Live player | Vai a /live-player | Player streaming |
| 269 | Onboarding | Vai a /onboarding | Wizard onboarding |
| 270 | Landing page | Vai a /landing | Landing marketing |

---

# 📊 OUTPUT RICHIESTO

## Al termine dei test, genera due documenti:

### DOCUMENTO A: REPORT SVILUPPATORI (tecnico)
Nome file: `TEST_REPORT_DEV_2026-02-02_A.md`

Contenuto:
1. **Riepilogo esecuzione**
   - Data/ora esecuzione
   - Ambiente testato
   - Versione browser/sistema

2. **Risultati per sezione**
   - Tabella con tutti i test
   - Status: ✅ PASS / ❌ FAIL / ⚠️ PARZIALE

3. **Bug trovati** (per ogni bug):
   - ID test fallito
   - Descrizione problema
   - Screenshot se possibile
   - Stack trace console
   - Passi per riprodurre
   - Severità: CRITICAL / HIGH / MEDIUM / LOW

4. **Metriche**
   - Totale test: XXX
   - Passati: XXX (XX%)
   - Falliti: XXX (XX%)
   - Parziali: XXX (XX%)

5. **Raccomandazioni tecniche**
   - Fix prioritari
   - Refactoring suggeriti
   - Miglioramenti performance

### DOCUMENTO B: KNOWLEDGE BASE AI (per AI agent)
Nome file: `TEST_KNOWLEDGE_AI_2026-02-02_B.md`

Contenuto con header AI-First:
```markdown
# 🤖 AI KNOWLEDGE BASE - TEST RESULTS
## Data: 2026-02-02
## Progetto: Media Center Arti Marziali

### 🎓 AI_MODULE: Test E2E Results
### 🎓 AI_DESCRIPTION: Risultati test end-to-end sistema completo
### 🎓 AI_BUSINESS: Quality assurance, bug tracking, regression prevention
### 🎓 AI_TEACHING: Pattern di test, errori comuni, soluzioni applicate

## BUG_PATTERNS (per AI learning):
[Lista bug con pattern identificabili]

## ERROR_SOLUTIONS (per AI debugging):
[Mapping errore → soluzione]

## WORKING_FEATURES (baseline funzionante):
[Lista feature OK per non reintrodurre bug]

## REGRESSION_WATCH (attenzione):
[Feature fragili da monitorare]
```

---

# ⚠️ REGOLE ESECUZIONE TEST

1. **NON SALTARE TEST** - Esegui TUTTI i 270 test
2. **DOCUMENTA TUTTO** - Screenshot per ogni errore
3. **CONSOLE APERTA** - Monitora errori JavaScript
4. **NETWORK TAB** - Monitora chiamate API fallite
5. **PULISCI STATO** - Tra sezioni, pulisci localStorage se necessario
6. **TEMPI** - Registra tempo caricamento pagine lente (>3s)

---

# 🏁 CHECKLIST PRE-TEST

- [ ] Backend attivo su http://localhost:8000
- [ ] Frontend attivo su http://localhost:3100
- [ ] Browser DevTools aperto
- [ ] Account admin funzionante
- [ ] Spazio su disco per screenshot
- [ ] Connessione stabile

**INIZIA I TEST!**

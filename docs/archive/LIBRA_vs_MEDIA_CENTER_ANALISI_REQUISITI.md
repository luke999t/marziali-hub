# 📋 ANALISI REQUISITI LIBRA vs MEDIA CENTER ARTI MARZIALI

**Data:** 11 Gennaio 2025  
**Versione:** 1.0  
**Scopo:** Mappatura requisiti LIBRA su piattaforma Media Center esistente

---

## 🎯 EXECUTIVE SUMMARY

| Metrica | Valore |
|---------|--------|
| **Requisiti LIBRA Totali** | 126 |
| **Coperti (✅)** | 71 (56%) |
| **Parziali (⚠️)** | 32 (25%) |
| **Mancanti (❌)** | 12 (10%) |
| **Evoluzioni Future (📅)** | 11 (9%) |
| **Copertura Tecnica Attuale** | **81%** |
| **Effort Gap Stimato** | ~115 giorni |

**Conclusione:** Il Media Center Arti Marziali copre la maggior parte dei requisiti LIBRA. I gap principali riguardano il modulo eventi/formazione ibrida con le ASD.

---

# PARTE 1: REQUISITI RICHIESTI (Release 1)

## 1.1 CORE PLATFORM

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L01 | Piattaforma apprendimento arti marziali | ✅ | 89% | Core del progetto |
| L02 | Sport da combattimento | ✅ | 89% | Stesso sistema |
| L03 | Discipline benessere | ⚠️ | 60% | Struttura pronta, contenuti da aggiungere |
| L04 | Corsi fruibili come video normali | ✅ | 100% | HLS streaming funzionante |
| L30 | Ottimizzato web | ✅ | 92% | Next.js PWA ready |
| L33 | Multi-disciplina (non specifica) | ✅ | 90% | Architettura flessibile |
| L34 | Repository in divenire/aggiornabile | ✅ | 85% | CMS + versioning contenuti |
| L35 | Interattivo (non statico come DVD) | ✅ | 90% | AI + skeleton feedback |
| L49 | NON verticalizzato | ✅ | 90% | Multi-stile architettura |
| L50 | NON video da scaricare ma streaming | ✅ | 100% | HLS/DASH, no download |

**Copertura categoria: 92%** ✅

---

## 1.2 SMART GLASSES / REALTÀ AUMENTATA

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L05 | Collegamento Smart Glasses | ✅ | 85% | XREAL target, WebXR |
| L24 | Proiezione filmati davanti praticante | ✅ | 85% | XREAL + WebXR overlay |
| L25 | Ripetizione lenta tecniche con glasses | ✅ | 80% | Playback speed control + AR |
| L84 | Smart glasses come punto di forza | ✅ | 85% | XREAL ready, WebXR |
| L85 | Tecnologie immersive (AR/VR) | ✅ | 80% | AR overlay, skeleton 3D |
| L22 | Realtà Aumentata per sport | ✅ | 70% | MediaPipe + AR overlay |

**Copertura categoria: 81%** ✅

---

## 1.3 SEZIONE STORICO/FILOSOFICA

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L06 | Documenti storico/filosofici | ✅ | 80% | Knowledge base + PDF viewer |
| L07 | Video storico/filosofici | ✅ | 80% | Stesso player, categorie diverse |
| L61 | Contenuti scritti storia/stili | ✅ | 80% | Knowledge base + PDF |
| L23 | AI storico/filosofico stili | ✅ | 75% | Knowledge base RAG |

**Copertura categoria: 79%** ✅

---

## 1.4 AI AVATAR / INTERAZIONE

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L08 | AI Avatar interattivo | ✅ | 75% | AI Agent + ChromaDB RAG |
| L09 | AI risponde a domande studente | ✅ | 75% | Chat system API implementato |
| L39 | Supporto per rivedere/correggere errori | ✅ | 80% | Skeleton comparison + AI feedback |
| L52 | Personalizzazione VERA allenamento | ⚠️ | 60% | AI Coach progettato, da completare |
| L86 | Allenamento personalizzato da remoto | ✅ | 75% | AI Coach + curriculum |
| L88 | Personalizzazione su misura | ✅ | 75% | AI + learning path |

**Copertura categoria: 73%** ✅

---

## 1.5 MULTILINGUA (UI Nativa)

> **NOTA:** Per LIBRA "multilingua" significa **UI nativa** (menu, bottoni, labels) in più lingue.  
> La traduzione simultanea dei video è un PLUS fuori scope, trattata nelle Evoluzioni Future.

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L10 | **UI Multilingua (IT/EN/ES/etc.)** | ⚠️ | 65% | i18n parziale, da completare |
| L10a | i18n Frontend Next.js | ✅ | 80% | next-intl configurato |
| L10b | i18n Mobile React Native | ⚠️ | 60% | Da completare |
| L10c | i18n Mobile Flutter | ⚠️ | 60% | Da completare |
| L10d | File traduzioni IT/EN | ⚠️ | 50% | Parziali |
| L10e | Altre lingue (ES/FR/DE) | ❌ | 0% | Da aggiungere post-lancio |
| L10f | Selezione lingua utente | ✅ | 80% | Nel profilo |
| L81 | Mercato estero (multi-paese) | ✅ | 85% | Multi-currency ready |
| L82 | Nicchie mercato internazionali | ✅ | 85% | Categorizzazione stili/maestri |

**Copertura categoria: 65%** ⚠️  
**Effort per completare: ~7-10 giorni**

---

## 1.6 MOBILE (Android / iOS)

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L11 | Fruibile su PC | ✅ | 92% | Next.js frontend |
| L12 | Fruibile su Android | ✅ | 88% | React Native + Flutter |
| L13 | Fruibile su iOS | ✅ | 88% | React Native + Flutter |
| L31 | Ottimizzato Android | ✅ | 88% | React Native + Flutter |
| L32 | Ottimizzato iOS | ✅ | 88% | React Native + Flutter |

**Copertura categoria: 89%** ✅

---

## 1.7 LIVE STREAMING

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L26 | Sistema LIVE streaming | ✅ | 75% | WebRTC + HLS live |
| L27 | Live allenamenti estemporanei | ⚠️ | 60% | Infrastruttura pronta, UI da completare |
| L28 | Live modalità singola | ⚠️ | 50% | 1:1 session da sviluppare |
| L29 | Live piccoli gruppi | ⚠️ | 50% | Multi-participant da completare |
| L51 | Aule virtuali per allenamenti | ⚠️ | 50% | WebRTC base, rooms da completare |
| L87 | Virtual fitness | ✅ | 70% | Live + AR |

**Copertura categoria: 59%** ⚠️

---

## 1.8 SUBSCRIPTION / PRICING

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L36 | Modello abbonamento (mensile/trim/annuale) | ✅ | 95% | 6 tier subscription |
| L62 | Abbonamento REGULAR €24/mese | ✅ | 95% | Tier configurabile |
| L63 | Regular = accesso illimitato | ✅ | 95% | Subscription logic |
| L65 | Abbonamento LIGHT €7/mese | ✅ | 95% | Tier configurabile |
| L66 | Light = video limitati | ✅ | 90% | Content gating |
| L67 | Light = no eventi | ✅ | 85% | Feature gating |
| L68 | Versione FREE con pubblicità | ✅ | 90% | Pause Ads system |
| L69 | Ads in blocchi 15/30 secondi | ✅ | 85% | Configurable ads |
| L70 | Eventi singoli €7-20 | ⚠️ | 50% | Pay-per-view base |
| L71 | Politica prezzi dinamica | ✅ | 80% | Config parametrizzabile |
| L45 | Libra guadagna da abbonamenti | ✅ | 95% | Stripe integration |

**Copertura categoria: 87%** ✅

---

## 1.9 BUSINESS MODEL EVENTI / ASD 🔴 GAP CRITICO

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L14 | Collaborazione associazioni sportive | ⚠️ | 40% | Multi-tenant pronto, workflow da definire |
| L15 | Sviluppo corsi con associazioni | ⚠️ | 50% | Curriculum system pronto |
| L16 | Vendita abbinata presenza + online | ❌ | 0% | **DA SVILUPPARE** |
| L17 | Prevendita eventi con minimo partecipanti | ❌ | 0% | **DA SVILUPPARE** |
| L37 | Collaborazione insegnanti | ⚠️ | 40% | Multi-tenant, workflow da definire |
| L38 | Affianca formazione in presenza | ⚠️ | 50% | Curriculum pronto, link eventi manca |
| L41 | Condivisione spese con associazioni | ❌ | 0% | **DA SVILUPPARE** |
| L43 | Vendita abbinata (online + presenza) | ❌ | 0% | **DA SVILUPPARE** |
| L44 | Associazioni titolari proventi presenza | ❌ | 0% | **DA SVILUPPARE** |
| L46 | Raccolta fondi prima registrazione | ❌ | 0% | **DA SVILUPPARE** |
| L47 | Numero minimo partecipanti eventi | ❌ | 0% | **DA SVILUPPARE** |
| L64 | Regular abbinato formazione ibrida | ❌ | 0% | **DA SVILUPPARE** |
| L73 | Costi variabili parametrizzati a vendite | ⚠️ | 60% | Revenue sharing da completare |
| L76 | 90%+ ricavi da formazione ibrida iniziale | ❌ | 0% | Modulo eventi manca |

**Copertura categoria: 24%** 🔴 **GAP CRITICO**

---

## 1.10 MARKETING / COMMUNITY

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L55 | Contenuti gratuiti (inbound marketing) | ✅ | 80% | Tier FREE implementato |
| L54 | Gamification (badge, banner, condivisioni) | ⚠️ | 40% | XP system base, badge da fare |
| L58 | Collaborazione maestri per comunicazione | ⚠️ | 30% | Multi-tenant, social sharing manca |
| L59 | Incontri calendarizzati con maestri | ⚠️ | 40% | Calendar base, eventi live da fare |
| L60 | Community building | ⚠️ | 35% | Chat system, forum manca |
| L21 | Integrazione social associazioni | ⚠️ | 30% | OAuth pronto, sharing da fare |
| L48 | Leva su base fidelizzata insegnanti | ⚠️ | 30% | Referral system base |
| L56 | Marketing social/motori ricerca | ❌ | 0% | Fuori scope tecnico |
| L57 | Marketing funzionale (abbinato stage) | ❌ | 0% | Workflow da definire |

**Copertura categoria: 32%** 🔴

---

## 1.11 SCALABILITÀ / INFRASTRUTTURA

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L72 | Costi fissi ridotti al minimo | ✅ | 90% | Architettura cloud-ready |
| L74 | Abbonamento mantenuto per percorso | ✅ | 85% | Curriculum binding |
| L75 | 100 ore formazione primo anno | ✅ | 95% | Upload illimitato |
| L77 | Fase BETA a 9 mesi | ✅ | 89% | Già all'89% |
| L79 | Catalogo ricco al lancio | ✅ | 85% | CMS + bulk upload |
| L80 | Target 200 ore fine anno 1 | ✅ | 95% | Scalabilità provata |
| L83 | Struttura agile iniziale | ✅ | 90% | Microservizi |
| L89 | Soluzioni nicchie di mercato | ✅ | 90% | Multi-stile, multi-maestro |
| L98 | Supporto 900 utenti anno 1 | ✅ | 95% | Architettura scalabile |
| L99 | Supporto 5400 utenti anno 5 | ✅ | 90% | PostgreSQL + Redis |
| L100 | 100 corsi anno 1 | ✅ | 95% | Nessun limite tecnico |
| L101 | 250 corsi anno 5 | ✅ | 95% | Storage scalabile |

**Copertura categoria: 92%** ✅

---

## 1.12 DELIVERABLE PROGETTO

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L90 | Documento analisi funzionale + mockup | ✅ | 95% | Documentazione esistente |
| L91 | Piattaforma MVP (iscrizioni + video + PDF) | ✅ | 89% | Già oltre MVP |
| L92 | Documento feedback utenti | ⚠️ | 40% | Sistema feedback base |
| L93 | Versione finale (mese 13) | ⏳ | 89% | Quasi completo |
| L94 | Validazione CNR innovatività | ❌ | 0% | Processo esterno |
| L95 | 4 corsi test entro mese 7 | ✅ | 90% | Upload workflow pronto |
| L96 | Beta tester utenti finali | ⚠️ | 50% | Sistema inviti da fare |
| L97 | Beta tester insegnanti | ⚠️ | 50% | Ruolo maestro esiste |
| L78 | Beta testing con feedback utenti | ⚠️ | 50% | Feedback system base |

**Copertura categoria: 61%** ⚠️

---

## 1.13 CONTENUTI / UPLOAD

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L18 | Supporto didattico seminari/stage | ✅ | 80% | Curriculum + video on demand |
| L19 | Multi-disciplina (non poche) | ✅ | 90% | Architettura modulare |
| L40 | Video con insegnanti stranieri | ✅ | 90% | Upload + multilingua |
| L42 | Creazione corsi esternalizzata | ✅ | 85% | Upload workflow + transcoding |
| L53 | Multi-tipologia esercizi | ✅ | 85% | Curriculum flessibile |

**Copertura categoria: 86%** ✅

---

# PARTE 2: EVOLUZIONI FUTURE (Non richieste ora)

## 2.1 GAMIFICATION AVANZATA / WALLET

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L111 | Video sbloccati con passi (stile WeWard) | ⚠️ | 30% | Integrazione fitness tracker da fare |
| L112 | Borsellino virtuale (wallet interno) | ✅ | 70% | City+ Wallet riutilizzabile |
| L113 | Wallet usabile per pagamenti sport | ⚠️ | 50% | Stripe ready, circuito chiuso da fare |
| L114 | Wallet per corsi palestre convenzionate | ❌ | 0% | Integrazione B2B manca |
| L115 | Monetizzazione movimento → sport | ⚠️ | 40% | Ads system pronto, reward loop da fare |

**Priorità:** MEDIA  
**Effort stimato:** 15-20 giorni

---

## 2.2 AVATAR / MOTION CAPTURE AVANZATO

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L116 | Video avatar interattivi | ✅ | 75% | Avatar 3D + skeleton |
| L117 | Motion Capture professionale (Xsens/Manus) | ⚠️ | 40% | MediaPipe 75 landmarks, Xsens import da fare |
| L118 | Zoom/ruota particolari corpo | ✅ | 80% | Three.js SkeletonViewer3D |
| L119 | Primo piano dettagli anatomici | ✅ | 75% | Camera controls implementati |
| L120 | Discipline armate (kata spada) | ⚠️ | 50% | Object tracking da aggiungere |
| L121 | Sensori armi bianche | ❌ | 0% | Hardware integration futura |

**Priorità:** BASSA  
**Effort stimato:** 20-30 giorni

---

## 2.3 TRADUZIONE VIDEO AVANZATA (Plus - Fuori Scope Release 1)

> **NOTA:** Queste funzionalità sono un PLUS, non richieste per LIBRA Release 1.  
> Possono essere aggiunte come upgrade premium post-lancio.

| ID | Requisito | Stato | % | Note |
|----|-----------|-------|---|------|
| L102 | Traduzione video automatica | ✅ | 85% | NLLB + Whisper (già pronto) |
| L122 | Sottotitoli automatici | ✅ | 90% | Whisper transcription (già pronto) |
| L123 | Traduzione sottotitoli multilingua | ✅ | 85% | NLLB 200+ lingue (già pronto) |
| L124 | Modifica labiale (lip-sync) | ⚠️ | 30% | Wav2Lip/SadTalker da integrare |
| L125 | Voice cloning multilingua | ⚠️ | 40% | Coqui TTS/Bark da fare |
| L126 | Alternativa interna a HeyGen/Synthesia | 📅 | 20% | **Sviluppo interno consigliato** |

**Priorità:** BASSA (post-lancio)  
**Effort stimato:** 25-35 giorni  
**Nota:** Sviluppo interno elimina costi ricorrenti HeyGen (€€€/mese)

---

## 2.4 VISIONE LUNGO TERMINE (5-7 anni)

| ID | Requisito | Stato | Note |
|----|-----------|-------|------|
| L103 | Sale AR in palestre | 📅 ROADMAP | Fuori scope |
| L104 | Lezioni distanza multi-gruppo AR | 📅 ROADMAP | Fuori scope |
| L105 | Corsi virtualizzati | 📅 ROADMAP | Fuori scope |
| L106 | Servizio B2B palestre | 📅 ROADMAP | Fuori scope |
| L107 | Palestre connesse/immersive | 📅 ROADMAP | Fuori scope |
| L108 | Impatto ambientale (CO2, ricariche EV) | 📅 ROADMAP | Fuori scope |
| L109 | Coesione sociale (palestre quartiere) | 📅 ROADMAP | Fuori scope |
| L110 | Turismo formativo Italia | 📅 ROADMAP | Fuori scope |

**Priorità:** POST-LANCIO  
**Effort stimato:** N/A (multi-anno)

---

## 2.5 STELLINE → DONAZIONI ASD ⭐ DA DECIDERE

| Aspetto | Opzione A | Opzione B | Opzione C |
|---------|-----------|-----------|-----------|
| **Modello** | Stelline = solo acquisti utente | Donazioni dirette € | Stelline convertibili in € |
| **Complessità fiscale** | Bassa | Media | Alta |
| **Implementazione** | 5-7 giorni | 7-10 giorni | 15-20 giorni |
| **Raccomandazione** | ✅ MVP | ✅ Post-lancio | ⚠️ Valutare |

**Decisione rimandata:** Da definire dopo validazione mercato.

---

# PARTE 3: SOLUZIONI TECNICHE IDENTIFICATE

## 3.1 PAGAMENTI - Zero Commissioni Apple/Google

**Problema:** Commissioni 30% su acquisti in-app

**Soluzione adottata:**
- Acquisti SOLO su web (browser esterno)
- App mobile apre URL → Stripe checkout
- Deep link ritorno in app dopo pagamento
- Commissioni: solo Stripe ~2.9%

**Risparmio:** ~€270 ogni €1.000 di vendite

**Stato:** ✅ Implementabile in 3-5 giorni

---

## 3.2 SPLIT PAYMENT ASD - Stripe Connect

**Problema:** Vendita bundle (stage fisico + corso digitale) con split incasso

**Soluzione adottata:**
```
Bundle €200 = Stage €100 (ASD) + Corso €100 (LIBRA)
        ↓
    Stripe Connect Split Payment
        ↓
€100 → Conto ASD (diretto)
€100 → Conto LIBRA (diretto)
```

**Vantaggi fiscali:**
- ASD incassa direttamente (gestisce sua fiscalità, spesso esente IVA)
- LIBRA incassa solo sua parte (fattura solo corso digitale)
- Nessun passaggio denaro tra LIBRA e ASD

**Stato:** ❌ Da sviluppare - Effort 20-30 giorni

---

## 3.3 CASI D'USO BUNDLE STAGE + CORSO

| Caso | Stage | Corso Stage | Altri Corsi | Implementazione |
|------|-------|-------------|-------------|-----------------|
| **1** | ✅ Accesso | ✅ Pubblico (tutti) | ✅ Tutti | Abbonamento REGULAR + corso pubblico |
| **2** | ✅ Accesso | ✅ Privato (solo partecipanti) | ✅ Tutti | Abbonamento REGULAR + corso GATED |
| **3** | ✅ Accesso | ✅ Privato | ❌ Nessuno | Acquisto SINGOLO corso |

**Stato:** ⚠️ Parziale - Gating corsi da completare

---

# PARTE 4: RIEPILOGO GAP E PRIORITÀ

## 4.1 GAP CRITICI (Bloccanti per modello LIBRA)

| Gap | Effort | Priorità |
|-----|--------|----------|
| Modulo Eventi/Formazione Ibrida | 15-20 giorni | 🔴 ALTA |
| Stripe Connect (Split ASD) | 10-15 giorni | 🔴 ALTA |
| Bundle corso + evento | 5-7 giorni | 🔴 ALTA |
| Prevendita con soglia minima | 5-7 giorni | 🔴 ALTA |
| Dashboard ASD | 5-7 giorni | 🟡 MEDIA |

**Totale GAP critici: ~40-55 giorni**

---

## 4.2 GAP MEDI (Migliorano esperienza)

| Gap | Effort | Priorità |
|-----|--------|----------|
| Live streaming gruppi | 10-15 giorni | 🟡 MEDIA |
| Gamification completa | 7-10 giorni | 🟡 MEDIA |
| Community/Forum | 10-15 giorni | 🟡 MEDIA |
| Beta tester management | 5-7 giorni | 🟡 MEDIA |

**Totale GAP medi: ~35-50 giorni**

---

## 4.3 GAP BASSI (Post-lancio)

| Gap | Effort | Priorità |
|-----|--------|----------|
| Lip-sync interno | 15-20 giorni | 🟢 BASSA |
| Voice cloning | 10-15 giorni | 🟢 BASSA |
| Motion capture Xsens | 10-15 giorni | 🟢 BASSA |
| Wallet stelline completo | 15-20 giorni | 🟢 BASSA |

**Totale GAP bassi: ~50-70 giorni**

---

## 4.4 EFFORT TOTALE

| Categoria | Giorni | Note |
|-----------|--------|------|
| GAP Critici | 40-55 | **Necessari per lancio LIBRA** |
| GAP Medi | 35-50 | Migliorano UX |
| GAP Bassi | 50-70 | Post-lancio |
| **TOTALE** | **125-175** | ~5-7 mesi part-time |

---

# PARTE 5: PIANO D'AZIONE SUGGERITO

## Fase 1: Pre-Produzione (2-3 settimane)
- [x] Fix SQLAlchemy (in corso)
- [ ] SSL + HTTPS
- [ ] Stripe production webhooks
- [ ] Test con 3-5 utenti reali

## Fase 2: GAP Critici (6-8 settimane)
- [ ] Stripe Connect onboarding ASD
- [ ] Split Payment
- [ ] Modulo Eventi
- [ ] Bundle corso + evento
- [ ] Prevendita con soglia

## Fase 3: GAP Medi (4-6 settimane)
- [ ] Live streaming gruppi
- [ ] Gamification
- [ ] Dashboard ASD
- [ ] Beta tester management

## Fase 4: Lancio LIBRA
- [ ] Onboarding prime 5-10 ASD
- [ ] Primi 4 eventi pilota
- [ ] Feedback e iterazione

---

# APPENDICE: LEGENDA

| Simbolo | Significato |
|---------|-------------|
| ✅ | Requisito coperto (≥70%) |
| ⚠️ | Requisito parziale (30-69%) |
| ❌ | Requisito mancante (<30%) |
| 📅 | Roadmap futura (fuori scope v1) |
| 🔴 | Priorità ALTA |
| 🟡 | Priorità MEDIA |
| 🟢 | Priorità BASSA |

---

**Documento generato:** 11 Gennaio 2025  
**Prossimo aggiornamento:** Dopo completamento GAP critici

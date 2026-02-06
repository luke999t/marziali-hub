# 📋 DOCUMENTO MIGRAZIONE CHAT - 11 Gennaio 2025

**ID Sessione:** 2025-01-11-LIBRA-ANALISI  
**Progetto:** Media Center Arti Marziali + Ecosistema Gestionali AI-First  
**Durata sessione:** ~4 ore  
**Contesto:** Analisi comparativa LIBRA vs Media Center

---

# 🎯 EXECUTIVE SUMMARY

Sessione dedicata all'analisi completa dei requisiti LIBRA (pitch 90 giorni fa per piattaforma apprendimento arti marziali) confrontati con lo stato attuale del Media Center. Identificati 126 requisiti totali, copertura tecnica 81%, gap critico nel modulo eventi/ASD.

**Decisioni chiave prese:**
1. Media Center = unico prodotto configurabile (no 2 prodotti separati)
2. Pagamenti: SOLO su web (zero commissioni Apple/Google 30%)
3. Split payment ASD via Stripe Connect (ogni soggetto sua fiscalità)
4. UI multilingua in scope, traduzione video è PLUS fuori scope
5. Stelline → ASD: decisione rimandata post-validazione mercato

---

# 📊 STATO PROGETTI

## Media Center Arti Marziali

| Metrica | Valore |
|---------|--------|
| **Completamento** | 89% |
| **LOC** | 223.000+ |
| **Test** | 2.134 (98.96% pass) |
| **Moduli attivi** | 28/34 |
| **Status** | In fix SQLAlchemy relationship |

### Lavoro in corso (Claude Code)
- Fix SQLAlchemy relationship loops
- Test suite in esecuzione (lunga)
- Possibile interrompere e riprendere dopo

---

## Analisi LIBRA Completata

| Metrica | Valore |
|---------|--------|
| **Requisiti totali estratti** | 126 |
| **Coperti (✅)** | 71 (56%) |
| **Parziali (⚠️)** | 32 (25%) |
| **Mancanti (❌)** | 12 (10%) |
| **Evoluzioni future (📅)** | 11 (9%) |
| **Copertura tecnica** | 81% |
| **Effort gap stimato** | ~115-175 giorni |

---

# 🔴 GAP CRITICI IDENTIFICATI

## 1. Modulo Eventi/Formazione Ibrida (Bloccante)

**Cosa manca:**
- Vendita abbinata presenza + online (bundle)
- Prevendita con minimo partecipanti
- Gestione eventi/stage
- Link corso digitale ↔ evento fisico

**Perché critico:** 90% ricavi iniziali LIBRA da formazione ibrida

**Effort:** 15-20 giorni

---

## 2. Revenue Sharing ASD (Bloccante)

**Cosa manca:**
- Onboarding ASD su Stripe Connect
- Split payment al checkout
- Dashboard ASD (vede suoi incassi)
- Report vendite per ASD

**Soluzione identificata:** Stripe Connect con Separate Charges

**Effort:** 15-20 giorni

---

## 3. UI Multilingua (Importante)

**Stato attuale:**
- i18n Frontend Next.js: 80%
- i18n Mobile React Native: 60%
- i18n Mobile Flutter: 60%
- File traduzioni IT/EN: 50%
- Altre lingue: 0%

**Effort:** 7-10 giorni

---

# ✅ DECISIONI TECNICHE PRESE

## 1. Pagamenti: Zero Commissioni Apple/Google

**Problema:** Apple/Google prendono 30% su acquisti in-app

**Soluzione adottata:**
```
App mobile → click "Abbonati" → apre BROWSER ESTERNO → Stripe checkout → deep link ritorna in app
```

**Risultato:** Commissioni solo Stripe ~2.9% (risparmio €270 ogni €1000)

**Riferimento:** Come Netflix, Spotify, Amazon Kindle

---

## 2. Split Payment ASD - Stripe Connect

**Problema:** Vendita bundle (stage €100 ASD + corso €100 LIBRA)

**Soluzione adottata:**
```
Utente paga €200
    ↓ Stripe Connect Split
€100 → Conto ASD (diretto)
€100 → Conto LIBRA (diretto)
```

**Vantaggi fiscali:**
- ASD incassa direttamente (sua fiscalità, spesso esente IVA)
- LIBRA incassa solo sua parte
- Nessun passaggio denaro LIBRA → ASD
- Ogni soggetto emette sua fattura

---

## 3. Tre Casi d'Uso Bundle Stage

| Caso | Stage | Corso Stage | Altri Corsi | Come |
|------|-------|-------------|-------------|------|
| **1** | ✅ | Pubblico (tutti vedono) | ✅ Tutti | REGULAR + corso pubblico |
| **2** | ✅ | Privato (solo partecipanti) | ✅ Tutti | REGULAR + corso GATED |
| **3** | ✅ | Privato | ❌ Nessuno | Acquisto SINGOLO |

---

## 4. Multilingua: UI vs Traduzione Video

| Cosa | In Scope LIBRA R1? | Stato |
|------|-------------------|-------|
| **UI nativa** (menu, bottoni, labels IT/EN/ES) | ✅ SÌ | 65% |
| Sottotitoli automatici | ❌ NO (plus) | 90% già pronto |
| Traduzione sottotitoli | ❌ NO (plus) | 85% già pronto |
| Lip-sync/Voice cloning | ❌ NO (futuro) | 30-40% |

---

## 5. Stelline → ASD

**Decisione:** RIMANDATA

**Opzioni sul tavolo:**
- A) Stelline = solo acquisti utente (semplice)
- B) Donazioni dirette € via Stripe (media complessità)
- C) Stelline convertibili in € per ASD (complesso fiscalmente)

**Quando decidere:** Dopo validazione mercato

---

# 📁 DOCUMENTI GENERATI

| Documento | Contenuto | Path |
|-----------|-----------|------|
| **LIBRA_vs_MEDIA_CENTER_ANALISI_REQUISITI.md** | 126 requisiti mappati, copertura, gap, soluzioni | Outputs |

---

# 🔧 LAVORI IN CORSO

## Claude Code - Fix SQLAlchemy

**Stato:** Test in esecuzione (lunga durata)

**Cosa sta facendo:**
1. Fix relationship loops in models
2. Esecuzione test suite completa
3. Verifica import errors

**Opzioni:**
- Attendere completamento
- Interrompere (Ctrl+C) e riprendere dopo
- I fix sono già applicati, test sono verifica

---

# 📋 PROSSIMI STEP (Priorità)

## Immediati (prima di procedere)
1. [ ] Verificare esito test Claude Code
2. [ ] Se falliti, analizzare errori specifici
3. [ ] Commit fix funzionanti

## Breve termine (1-2 settimane)
4. [ ] Completare i18n (UI multilingua)
5. [ ] SSL + HTTPS produzione
6. [ ] Stripe webhooks produzione
7. [ ] Test con 3-5 utenti reali

## Medio termine - GAP Critici (4-6 settimane)
8. [ ] Stripe Connect setup
9. [ ] Onboarding ASD
10. [ ] Split payment
11. [ ] Modulo Eventi
12. [ ] Bundle corso + evento
13. [ ] Prevendita con soglia

## Post-lancio
14. [ ] Gamification completa
15. [ ] Live streaming gruppi
16. [ ] Community/Forum
17. [ ] Traduzione video avanzata

---

# 💡 NOTE TECNICHE IMPORTANTI

## Architettura Confermata

**Media Center = Unico prodotto configurabile**
- Multi-tenant per diversi "brand" (LIBRA, nostro, altri)
- Configurazione parametrica per tenant
- Stesso codebase, deployment diversi

## Fiscalità Split Payment

**Modello scelto:** Ogni soggetto incassa direttamente

```
ASD:
- Incassa €100 per stage
- Emette ricevuta/fattura (sua fiscalità, spesso regime 398/91)
- Gestisce sua IVA (spesso esente)

LIBRA:
- Incassa €100 per corso digitale
- Emette fattura con IVA 22%
- Nessun "giro" di soldi con ASD
```

## Deep Linking Mobile

```javascript
// React Native
Linking.openURL('https://libra.com/checkout?corso=123&user=456');

// Dopo pagamento, Stripe redirect a:
// libra://payment-success?session=xyz
// App intercetta e mostra conferma
```

---

# 🗂️ CONTESTO PER PROSSIMA CHAT

## Cosa sa la nuova chat

Se usi Claude con memoria, dovrebbe ricordare:
- Progetto Media Center 89%
- Analisi LIBRA completata
- Decisioni pagamenti/split

## Cosa passare esplicitamente

1. Questo documento di migrazione
2. LIBRA_vs_MEDIA_CENTER_ANALISI_REQUISITI.md
3. Esito test Claude Code (quando finiti)

## Prompt suggerito per nuova chat

```
Continuiamo il lavoro sul Media Center Arti Marziali.

Stato:
- Media Center: 89% completo
- Analisi LIBRA: completata (126 requisiti, 81% copertura)
- Claude Code: [esito test]

Documenti di riferimento allegati:
- MIGRAZIONE_CHAT_2025_01_11_LIBRA_ANALISI.md
- LIBRA_vs_MEDIA_CENTER_ANALISI_REQUISITI.md

Prossimo step: [cosa vuoi fare]
```

---

# ⚠️ ATTENZIONE

## Test Claude Code

Se i test stanno girando da molto (>30 minuti):
1. Probabilmente loop o test molto lenti
2. Puoi interrompere con Ctrl+C
3. I fix al codice sono già applicati
4. Riesegui test specifici invece di tutta la suite:
   ```bash
   cd backend
   python -m pytest tests/test_specific.py -v
   ```

## File System MCP

Se MCP non risponde:
1. Riavvia Claude Desktop
2. Verifica connessione a `/projects/Desktop/Dev/MediaCenterArtiMarziali`
3. Usa PowerShell come fallback

---

# 📈 METRICHE SESSIONE

| Metrica | Valore |
|---------|--------|
| Requisiti analizzati | 126 |
| Decisioni tecniche | 5 |
| Documenti generati | 2 |
| Gap critici identificati | 3 |
| Effort stimato gap | 115-175 giorni |

---

# 🏷️ TAG PER RICERCA

`#LIBRA` `#MediaCenter` `#GapAnalysis` `#StripeConnect` `#SplitPayment` `#Multilingua` `#i18n` `#ASD` `#FormazioneIbrida` `#Bundle` `#Pagamenti` `#ZeroCommissioni`

---

**Documento generato:** 11 Gennaio 2025, ore ~19:00  
**Autore:** Claude (Opus 4)  
**Versione:** 1.0

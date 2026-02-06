# 📋 DOCUMENTO MIGRAZIONE CHAT - REFACTORING GESTIONALI

**Data**: 11 Dicembre 2025
**Chat origine**: Sviluppo gestionali 5.0 Opus 4.1
**Scopo**: Continuare refactoring in nuova chat

---

## ✅ COMPLETATO IN QUESTA SESSIONE

### Media Center Arti Marziali - DONE ✅

| Componente | Codice | Test | ZERO MOCK | Stato |
|------------|--------|------|-----------|-------|
| Backend | 95% | 350 pass | ✅ | **PRONTO** |
| Frontend | 98% | 131 pass | ✅ | **PRONTO** |
| Mobile RN | 100% | 120 pass | ✅ | **PRONTO** |
| Flutter | 100% | 7 test | ✅ | **PRONTO** |

**Lavoro svolto**:
1. Backend: Fix test SQLAlchemy, async/await, creati test_curriculum_api.py, test_videos_api.py, test_users_api.py
2. Frontend: Spostati VideoPlayer.tsx e PauseAdOverlay.tsx in `_deprecated/`
3. Mobile RN: Convertiti 6 file test da mock a ZERO MOCK (120 test, 100% pass)
4. Flutter: Completate 6 features mancanti (library, settings, notifications, live, onboarding), deprecati 297 test mock, creati 7 test ZERO MOCK

**File creati**:
- `STATO_PROGETTO_20251211.md`
- `TEST_UTENTE_MEDIA_CENTER.md`
- `PROMPT_TEST_UTENTE.md`

---

## 🔄 DA FARE - ALTRI GESTIONALI

### Lista Progetti da Verificare

Basandomi sulla memoria del progetto, questi sono i gestionali da verificare con stessa metodologia:

| Progetto | Path Probabile | Priorità |
|----------|----------------|----------|
| Fumetteria | `Dev/fumetteria` o `GESTIONALI/fumetteria` | ALTA (89% completato) |
| Restaurant AI | `Dev/restaurant_ai_system` | ALTA (92% completato) |
| Comics Store | `Dev/comics_store` o simile | MEDIA |
| City+ Wallet | `progetti/Gestionali/city_plus_wallet` | MEDIA |
| EduPath AI | Da identificare | MEDIA |
| Agenzia Assicurativa | Da identificare | BASSA |
| Gym Management | Da identificare | BASSA |
| Car Rental | Da identificare | BASSA |

### Metodologia Standard per Ogni Progetto

```
PER OGNI GESTIONALE:

1. VERIFICA CODICE
   - Conta file sorgente
   - Cerca TODO/FIXME/placeholder
   - Verifica completezza features
   - Calcola % completamento

2. VERIFICA TEST
   - Esegui test esistenti
   - Conta pass/fail/skip
   - Calcola pass rate

3. VERIFICA ZERO MOCK
   - Cerca mock violations (jest.mock, MagicMock, mocktail, when/thenAnswer)
   - Lista file con mock
   - Conta violations

4. AZIONI
   - Se mock trovati → Deprecare e riscrivere ZERO MOCK
   - Se codice incompleto → Completare features mancanti
   - Se test insufficienti → Creare test enterprise

5. DOCUMENTAZIONE
   - Aggiornare STATO_PROGETTO_[DATA].md
   - Creare TEST_UTENTE se pronto
```

---

## 📜 REGOLE DA SEGUIRE

### LEGGE SUPREMA ZERO MOCK

```
⛔ VIETATO:
- jest.mock() per API/services
- MagicMock, AsyncMock per HTTP
- mocktail, mockito per repository
- when().thenAnswer() per chiamate backend
- Qualsiasi mock che simula risposta API

✅ CONSENTITO:
- Mock per WebGL, ResizeObserver (browser API non esistenti in test env)
- Mock per moduli nativi React Native (expo-av, expo-notifications, etc.)
- Mock per Platform channels Flutter (camera, video player nativo)

REGOLA D'ORO:
Se il test PASSA con backend SPENTO → È FINTO
Se il test FALLISCE con backend SPENTO → È REALE
```

### AI-FIRST DEVELOPMENT

```
Ogni file deve avere:
- Header con AI_MODULE, AI_DESCRIPTION, AI_BUSINESS, AI_TEACHING
- Commenti didattici che spiegano il PERCHÉ
- Alternative valutate e scartate
- Metriche di successo

Ogni modulo deve:
- Essere auto-descrivibile per AI agent
- Avere tag_dictionary.json per RAG
- Supportare AI logging
```

### STRUTTURA TEST ENTERPRISE

```
test/
├── unit/           # Test singole funzioni
├── integration/    # Test flussi completi
├── security/       # OWASP compliance
├── performance/    # Response time
├── stress/         # Concurrent requests
├── holistic/       # User journeys
└── _deprecated/    # Vecchi test con mock (NON USARE)
```

---

## 🛠️ COMANDI UTILI

### Windows PowerShell

```powershell
# Backend Python
cd [progetto]\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000
pytest tests/ -v --tb=short

# Frontend Next.js
cd [progetto]\frontend
npm install --legacy-peer-deps
npm run dev
npm test

# Mobile React Native
cd [progetto]\mobile
npm install --legacy-peer-deps
npm start
npm test

# Flutter
cd [progetto]\flutter_app
flutter pub get
flutter run
flutter test test/real/

# Cerca mock violations
Select-String -Path "**\*.py" -Pattern "MagicMock|AsyncMock|@patch" -Recurse
Select-String -Path "**\*.ts" -Pattern "jest.mock|mockImplementation" -Recurse
grep -r "when\(|thenAnswer" test/ --include="*.dart"
```

---

## 📊 TEMPLATE REPORT VERIFICA

```markdown
# VERIFICA [NOME PROGETTO]

**Data**: [data]
**Path**: [path]

## CODICE
- File sorgente: X
- TODO/FIXME: X
- Features complete: X/Y
- Completamento: X%

## TEST
- Test totali: X
- Test passati: X
- Test falliti: X
- Pass rate: X%

## ZERO MOCK
- Mock violations: X
- File con mock: [lista]
- Azione: [deprecare/convertire/ok]

## AZIONI RICHIESTE
1. [ ] Azione 1
2. [ ] Azione 2

## STATO FINALE
[PRONTO / IN PROGRESS / DA FARE]
```

---

## 🎯 PROMPT PER NUOVA CHAT

Copia questo nella nuova chat per continuare:

```
# CONTINUO REFACTORING GESTIONALI AI-FIRST

## CONTESTO
Sto continuando il refactoring dei gestionali AI-First.
Media Center Arti Marziali è COMPLETATO (backend, frontend, mobile, flutter tutti PRONTO).

## REGOLE
1. LEGGE SUPREMA ZERO MOCK - Nessun mock per API/HTTP
2. AI-FIRST - Codice commentato per AI agent
3. Test ENTERPRISE - unit, integration, security, performance, stress, holistic
4. Coverage target 90%

## METODOLOGIA
Per ogni progetto:
1. Verifica codice (TODO/FIXME/completezza)
2. Verifica test (pass rate)
3. Verifica ZERO MOCK (violations)
4. Azioni correttive
5. Documentazione

## PROSSIMO PROGETTO
Leggi il file `DOCUMENTO_MIGRAZIONE_REFACTORING.md` nel progetto e dimmi quale gestionale verificare.

Opzioni:
1. Fumetteria (89% completato)
2. Restaurant AI (92% completato)
3. Comics Store
4. City+ Wallet
5. Altro (specificare)

## FILE RIFERIMENTO
- Path Media Center: C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali
- Documenti: STATO_PROGETTO_20251211.md, TEST_UTENTE_MEDIA_CENTER.md
- Regole: LEGGE_SUPREMA_TEST_ZERO_MOCK.md (nei file progetto Claude)

Quale progetto verifico?
```

---

## 📁 STRUTTURA CARTELLE NOTA

```
C:\Users\utente\Desktop\
├── Dev\                    # Progetti sviluppo
│   ├── MediaCenterArtiMarziali\  # (vecchio path?)
│   ├── restaurant_ai_system\
│   └── ...
├── GESTIONALI\             # Gestionali principali
│   └── media-center-arti-marziali\  # (path attuale verificato)
└── progetti\
    └── Gestionali\
        └── city_plus_wallet\
```

**NOTA**: I path possono variare. Sempre verificare con `dir` o `ls` prima di operare.

---

**Documento creato**: 11 Dicembre 2025, ore 18:00
**Prossima azione**: Aprire nuova chat e continuare con prossimo gestionale

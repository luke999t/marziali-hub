# ANALISI RIUSO CODICE DA STREAMING_PLATFORM

## Data: 19 Novembre 2025
## Scopo: Decidere se prendere codice da STREAMING_PLATFORM o sviluppare da zero

---

## 1. INVENTARIO CODICE STREAMING_PLATFORM

### React Native Mobile (11 screens, ~1.500 righe)

| Screen | Righe | Riutilizzabile per Media Center? |
|--------|-------|----------------------------------|
| HomeScreen.tsx | 511 | ✅ ALTO - pattern Netflix-style |
| PlayerScreen.tsx | 259 | ⚠️ MEDIO - serve sync skeleton |
| DetailScreen.tsx | 178 | ✅ ALTO - dettaglio video/maestro |
| SearchScreen.tsx | 114 | ✅ ALTO - ricerca |
| ProfileScreen.tsx | 92 | ✅ ALTO - profilo utente |
| LibraryScreen.tsx | 83 | ✅ ALTO - libreria personale |
| AnimeScreen.tsx | ~100 | ⚠️ BASSO - specifico anime |
| MangaScreen.tsx | ~100 | ❌ NO - non serve |
| ReaderScreen.tsx | ~150 | ❌ NO - manga reader |
| RootNavigator.tsx | ~100 | ✅ ALTO - navigation |

**Riutilizzabile: ~1.100 righe (73%)**

### Frontend Web Componenti (4.149 righe principali)

| Componente | Righe | Riutilizzabile? |
|------------|-------|-----------------|
| AnimePlayer.tsx | 1.357 | ⚠️ MEDIO - 40% riutilizzabile |
| MangaReader.tsx | 1.053 | ❌ NO |
| BookingFlow.tsx | 1.739 | ⚠️ BASSO - eventi diversi |
| ContentCard/Row | ~500 | ✅ ALTO |
| ProfileSelector | ~200 | ✅ ALTO |

**Riutilizzabile: ~800 righe (19%)**

---

## 2. ANALISI COSTI/BENEFICI

### Opzione A: Prendere e Adattare

#### Mobile React Native

| Componente | Effort Adattamento | Risparmio vs Da Zero |
|------------|-------------------|----------------------|
| Struttura base (nav, config) | 1 giorno | 3 giorni |
| HomeScreen → VideoHome | 2-3 giorni | 5 giorni |
| DetailScreen → VideoDetail | 1-2 giorni | 3 giorni |
| ProfileScreen | 0.5 giorni | 2 giorni |
| SearchScreen | 0.5 giorni | 2 giorni |
| LibraryScreen → MyVideos | 1 giorno | 2 giorni |
| PlayerScreen → TechniquePlayer | 3-4 giorni | 7 giorni |
| **TOTALE** | **9-12 giorni** | **24 giorni** |

**Risparmio: 12-15 giorni (50-60%)**

#### Componenti Web

| Componente | Effort Adattamento | Risparmio |
|------------|-------------------|-----------|
| ContentCard/Row | 1 giorno | 2 giorni |
| ProfileSelector | 0.5 giorni | 1 giorno |
| Pattern AI-First (header/commenti) | 1 giorno | 3 giorni |
| AnimePlayer → TechniquePlayer | 4-5 giorni | 3 giorni |
| **TOTALE** | **6-8 giorni** | **9 giorni** |

**Risparmio: 1-3 giorni (15-25%)**

### Opzione B: Sviluppare Da Zero

| Area | Effort Stimato |
|------|----------------|
| Mobile React Native completo | 8-12 settimane |
| Componenti web mancanti | 3-4 settimane |
| **TOTALE** | **11-16 settimane** |

---

## 3. COSA PRENDERE (Raccomandazione)

### ✅ PRENDERE SICURAMENTE

1. **Struttura React Native**
   - navigation/RootNavigator.tsx
   - App.tsx + config
   - package.json dependencies
   - **Motivo**: Base solida, 3 giorni risparmiati

2. **HomeScreen pattern**
   - Hero banner
   - ContentCard/ContentRow
   - Animated scroll header
   - **Motivo**: UI Netflix-style già pronta, 5 giorni risparmiati

3. **Screen comuni**
   - ProfileScreen
   - SearchScreen
   - LibraryScreen
   - DetailScreen
   - **Motivo**: 80% riutilizzabile, 9 giorni risparmiati

4. **Pattern AI-First**
   - Header con AI_MODULE, AI_DESCRIPTION, etc.
   - Commenti didattici
   - **Motivo**: Standard qualità, 3 giorni risparmiati

5. **ContentCard/ContentRow (web)**
   - Componenti lista
   - **Motivo**: Pattern identico, 2 giorni risparmiati

### ⚠️ PRENDERE CON CAUTELA

1. **PlayerScreen → TechniquePlayer**
   - **Da tenere**: HLS streaming, controls, fullscreen
   - **Da modificare**: Aggiungere sync skeleton, slow-motion, frame-by-frame
   - **Effort**: 3-4 giorni adattamento
   - **Risparmio**: 3-4 giorni

2. **AnimePlayer.tsx (web)**
   - **Da tenere**: 40% (HLS, controls base)
   - **Da scartare**: Skip intro, multi-audio anime, watch party
   - **Da aggiungere**: Skeleton overlay, annotations
   - **Effort**: 4-5 giorni adattamento
   - **Risparmio**: Solo 1-2 giorni (meglio sviluppare parti specifiche da zero)

### ❌ NON PRENDERE

1. **MangaReader.tsx** - Non serve
2. **BookingFlow.tsx** - Troppo diverso
3. **Anime-specific screens** - Non applicabili
4. **Flutter app** - Era solo test

---

## 4. ROADMAP CONSIGLIATA

### Fase 1: Setup Mobile (2-3 giorni)
1. Copiare struttura base React Native
2. Adattare package.json
3. Configurare navigation

### Fase 2: Screen Base (5-7 giorni)
1. Adattare HomeScreen → VideoHome
2. Adattare DetailScreen → VideoDetail
3. Portare ProfileScreen, SearchScreen, LibraryScreen

### Fase 3: Player Specializzato (7-10 giorni)
1. Creare TechniquePlayer da zero (ispirandosi a pattern)
2. Implementare sync skeleton
3. Aggiungere slow-motion, frame-by-frame
4. Annotations timestamp

### Fase 4: Componenti Web (3-5 giorni)
1. Portare ContentCard/ContentRow
2. Applicare pattern AI-First a tutti i componenti
3. Collegare mock a API reali

**Totale: 17-25 giorni (3.5-5 settimane)**

vs

**Da zero: 11-16 settimane**

---

## 5. CONCLUSIONE

### Verdetto: PRENDERE STRUTTURA + SVILUPPARE SPECIFICO

| Area | Approccio | Motivo |
|------|-----------|--------|
| Mobile base | ✅ Prendere | 50-60% risparmio |
| Screen comuni | ✅ Prendere | 80% riutilizzabile |
| Player video | ⚠️ Ibrido | Pattern base + features custom |
| Skeleton viewer | ❌ Da zero | Unico per arti marziali |
| Pattern AI-First | ✅ Prendere | Standard qualità |

### Risparmio Totale Stimato

- **Con riuso**: 3.5-5 settimane
- **Da zero**: 11-16 settimane
- **Risparmio**: 7.5-11 settimane (65-70%)

### Raccomandazione Finale

**Prendere il codice da STREAMING_PLATFORM** per:
1. Struttura React Native completa
2. Screen comuni (Home, Profile, Search, Library, Detail)
3. Pattern UI (ContentCard, ContentRow)
4. Pattern AI-First

**Sviluppare da zero** per:
1. TechniquePlayer con sync skeleton (feature unica)
2. SkeletonViewer3D mobile (Three.js/expo-gl)
3. Features specifiche arti marziali

Questo approccio ibrido massimizza il valore del codice esistente (~1.100 righe React Native) evitando adattamenti forzati dove non ha senso.

---

## 6. PROSSIMI PASSI

1. **Creare branch** `feature/mobile-app`
2. **Copiare** da STREAMING_PLATFORM:
   - `mobile/` → `media-center/mobile/`
3. **Rinominare/adattare**:
   - StreamManga → MediaCenterMA
   - AnimeScreen → TechniquesScreen
   - Aggiornare navigation
4. **Sviluppare features specifiche**:
   - TechniquePlayer con skeleton sync
   - Integration con backend esistente

---

*Documento generato il 19 Novembre 2025*
*Analisi basata su confronto diretto del codice sorgente*

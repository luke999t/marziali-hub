# CATALOGO COMPLETO FRONTEND
## Media Center Arti Marziali

**Data analisi**: 2025-12-13
**Framework**: Next.js + React + TypeScript

---

## RIEPILOGO CONTEGGI

| Area | File |
|------|------|
| TSX (Pages/Components) | ~86 |
| TS (Services/Hooks/Types) | ~71 |
| **TOTALE** | **~157** |

---

## 1. APP PAGES (src/app/)

### 1.1 Pagine Principali
```
page.tsx              - Home page
layout.tsx            - Root layout
error.tsx             - Error boundary

login/page.tsx        - Login
register/page.tsx     - Registrazione
onboarding/page.tsx   - Onboarding wizard
landing/page.tsx      - Landing page
```

### 1.2 Admin Area
```
admin/
├── page.tsx              - Dashboard admin
├── moderation/page.tsx   - Moderazione video
├── users/page.tsx        - Gestione utenti
└── analytics/page.tsx    - Analytics
```

### 1.3 Curriculum System
```
curriculum/
├── page.tsx              - Lista curricula
├── [id]/page.tsx         - Dettaglio curriculum
└── [id]/learn/page.tsx   - Learning view

my-learning/page.tsx      - Miei progressi

manage/
├── curricula/page.tsx          - Gestione curricula
├── curricula/[id]/page.tsx     - Edit curriculum
├── curricula/[id]/students/page.tsx - Studenti
└── exams/page.tsx              - Gestione esami
```

### 1.4 Video/Skeleton Features
```
upload/page.tsx           - Upload video
skeletons/page.tsx        - Lista skeleton
skeleton-library/page.tsx - Libreria skeleton
skeleton-viewer/page.tsx  - Viewer 3D
skeleton-editor/page.tsx  - Editor skeleton
```

### 1.5 Communication
```
chat/page.tsx             - Chat/messaggi
```

### 1.6 Live Features
```
live-player/page.tsx      - Player live stream
translation/page.tsx      - Traduzione
```

### 1.7 Ingest Studio (Knowledge Enrichment)
```
ingest/page.tsx           - Ingest legacy

ingest-studio/
├── page.tsx                        - Main wizard
└── components/
    ├── ProjectSelector.tsx         - Step 1: Selezione progetto
    ├── InputChannelTabs.tsx        - Tabs input
    ├── DvdImportTab.tsx            - Import DVD
    ├── ProcessingOptions.tsx       - Step 3: Opzioni
    ├── ProgressPanel.tsx           - Step 4: Progress
    ├── MixPanel.tsx                - Panel mix
    └── index.ts                    - Exports
```

### 1.8 Dev Tools
```
dev/
├── voice-cloning/page.tsx        - Voice cloning demo
├── pose-detection/page.tsx       - Pose detection demo
└── technique-annotation/page.tsx - Annotation demo
```

### 1.9 Other
```
monitor/page.tsx          - System monitor
donations/page.tsx        - Donazioni
maestro/upload/page.tsx   - Upload maestro
```

---

## 2. API ROUTES (src/app/api/)

```
api/
├── ingest/route.ts                    - Ingest proxy
├── ingest-projects/[...path]/route.ts - Projects proxy
└── studio/
    ├── skeleton/[id]/route.ts         - Skeleton CRUD
    ├── skeletons/route.ts             - List skeletons
    ├── pose-analysis/route.ts         - Pose analysis
    ├── annotate/route.ts              - Annotate
    └── text-to-speech/route.ts        - TTS
```

---

## 3. COMPONENTS (src/components/)

### 3.1 Core Components
```
LazyVideo.tsx           - Video lazy loading
LanguageSwitcher.tsx    - Language switch
LiveSubtitles.tsx       - Sottotitoli live
MessageThread.tsx       - Thread messaggi
ConversationList.tsx    - Lista conversazioni
SkeletonViewer3D.tsx    - Viewer 3D Three.js
SkeletonEditor3D.tsx    - Editor 3D
```

### 3.2 Curriculum Components
```
curriculum/
├── BeltBadge.tsx           - Badge cintura
├── LevelProgressBar.tsx    - Progress bar
├── CurriculumCard.tsx      - Card curriculum
├── LevelCard.tsx           - Card livello
├── AIFeedbackPanel.tsx     - Feedback AI
├── ExamSubmissionModal.tsx - Modal esame
├── CertificateCard.tsx     - Certificato
├── RequirementsList.tsx    - Lista requisiti
├── InviteCodeGenerator.tsx - Generatore codici
└── index.ts                - Exports
```

### 3.3 Deprecated Components
```
_deprecated/
├── VideoPlayer.tsx     - Player deprecato
└── PauseAdOverlay.tsx  - Ads overlay deprecato
```

---

## 4. CONTEXTS (src/contexts/)

```
AuthContext.tsx         - Auth state
I18nContext.tsx         - Internazionalizzazione
CurriculumContext.tsx   - Curriculum state
```

---

## 5. HOOKS (src/hooks/)

### 5.1 Core Hooks
```
useAnalytics.ts         - Google Analytics
useLiveSubtitles.ts     - Live subtitles WS
useIngestProjects.ts    - Ingest projects API
```

### 5.2 Curriculum Hooks
```
curriculum/
├── useCurriculum.ts      - Single curriculum
├── useCurricula.ts       - List curricula
├── useMyCurricula.ts     - My curricula
├── useLevelProgress.ts   - Level progress
├── useExamSubmission.ts  - Exam submit
├── useAIFeedback.ts      - AI feedback
└── index.ts              - Exports
```

---

## 6. SERVICES (src/services/)

```
curriculumApi.ts        - Curriculum API client
ingestApi.ts            - Ingest API client
adsApi.ts               - Ads API client
```

---

## 7. LIB (src/lib/)

```
stripe.ts               - Stripe client
config.ts               - App config
api-cache.ts            - API cache utility
i18n.ts                 - i18n setup
analytics-service.ts    - Analytics service
```

---

## 8. TYPES (src/types/)

```
r3f.d.ts                - React Three Fiber types
curriculum.ts           - Curriculum types
ingest.ts               - Ingest types
```

---

## 9. CONFIG (src/config/)

```
api.ts                  - API configuration
```

---

## 10. TESTS (__tests__/)

### 10.1 Struttura
```
__tests__/
├── setup.ts                        - Test setup
├── unit/
│   ├── i18n.test.tsx
│   └── SkeletonViewer3D.test.tsx
├── integration/
│   ├── i18n-integration.test.tsx
│   └── api-integration.test.tsx
├── regression/
│   └── visual-regression.test.tsx
├── stress/
│   └── load.test.tsx
├── performance/
│   └── rendering.test.tsx
├── static/
│   ├── dependency-audit.test.ts
│   ├── bundle-size.test.ts
│   ├── typescript-strict.test.ts
│   ├── eslint-strict.test.ts
│   ├── lighthouse-scores.test.ts
│   └── accessibility-audit.test.ts
└── curriculum/
    ├── components/     (10 test files)
    ├── hooks/          (1 test file)
    ├── integration/    (6 test files)
    ├── holistic/       (5 test files)
    ├── chaos/          (5 test files)
    ├── security/       (8 test files)
    ├── stress/         (6 test files)
    ├── performance/    (3 test files)
    └── fixtures/       (3 files)
```

### 10.2 Curriculum Tests Coverage
```
COMPONENTS: 10 test files
- BeltBadge.test.tsx
- CurriculumCard.test.tsx
- ExamSubmissionModal.test.tsx
- AIFeedbackPanel.test.tsx
- RequirementsList.test.tsx
- LevelProgressBar.test.tsx
- LevelCard.test.tsx
- InviteCodeGenerator.test.tsx

INTEGRATION: 6 test files
- curriculum-flow.test.tsx
- enrollment-flow.test.tsx
- exam-submission-flow.test.tsx
- invite-code-flow.test.tsx
- progress-tracking-flow.test.tsx
- teacher-review-flow.test.tsx

HOLISTIC: 5 test files
- student-journey.test.tsx
- maestro-journey.test.tsx
- disaster-recovery.test.tsx
- data-consistency.test.tsx
- multi-tenant-isolation.test.tsx
- offline-sync.test.tsx

SECURITY: 8 test files
- auth-bypass.test.ts
- csrf-protection.test.ts
- file-upload-security.test.ts
- input-validation.test.ts
- privilege-escalation.test.ts
- rate-limiting.test.ts
- session-hijacking.test.ts
- sql-injection.test.ts
- xss-prevention.test.ts

CHAOS: 5 test files
- api-timeout.test.ts
- concurrent-mutations.test.ts
- network-failure.test.ts
- partial-data.test.ts
- service-degradation.test.ts

STRESS: 6 test files
- api-throttling.test.ts
- concurrent-users.test.ts
- large-dataset.test.ts
- memory-leak-detection.test.ts
- video-upload-stress.test.ts
- websocket-connections.test.ts

PERFORMANCE: 3 test files
- api-response-time.test.ts
- first-contentful-paint.test.ts
- memory-usage.test.ts
- time-to-interactive.test.ts
```

---

## 11. FILE DEPRECATI

```
src/DEPRECATED_PAUSE_ADS.ts
src/components/_deprecated/VideoPlayer.tsx
src/components/_deprecated/PauseAdOverlay.tsx
```

---

## METRICHE

| Metrica | Valore |
|---------|--------|
| File TSX/TS totali | ~157 |
| Pages | ~25 |
| Components | ~20 |
| Hooks | ~12 |
| Test files | ~50+ |
| API Routes | 7 |

---

*Catalogo generato il 2025-12-13*

# MAPPATURA COMPLETA FUNZIONALITÀ BACKEND API

**Progetto**: Media Center Arti Marziali
**Versione API**: v1
**Data Generazione**: 2026-01-29
**Totale Endpoints**: 218
**Base URL**: `/api/v1`

---

## INDICE AREE FUNZIONALI

1. [AUTH](#1-auth---autenticazione) - 8 endpoints
2. [USERS](#2-users---gestione-utenti) - 8 endpoints
3. [ADMIN](#3-admin---pannello-amministrazione) - 28 endpoints
4. [VIDEOS](#4-videos---gestione-video) - 18 endpoints
5. [SKELETON](#5-skeleton---estrazione-landmark-75) - 10 endpoints
6. [AVATARS](#6-avatars---avatar-3d) - 9 endpoints
7. [FUSION](#7-fusion---fusione-multi-video) - 6 endpoints
8. [EXPORT](#8-export---esportazione-3d) - 10 endpoints
9. [CURRICULUM](#9-curriculum---percorsi-didattici) - 12 endpoints
10. [MAESTRO](#10-maestro---pannello-istruttori) - 16 endpoints
11. [ASD](#11-asd---associazioni-sportive) - 10 endpoints
12. [LIVE](#12-live---eventi-streaming) - 8 endpoints
13. [LIVE_TRANSLATION](#13-live_translation---sottotitoli-tempo-reale) - 8 endpoints
14. [PAYMENTS](#14-payments---pagamenti-stripe) - 8 endpoints
15. [SUBSCRIPTIONS](#15-subscriptions---abbonamenti) - 6 endpoints
16. [DONATIONS](#16-donations---stelline-e-donazioni) - 8 endpoints
17. [NOTIFICATIONS](#17-notifications---notifiche-push) - 16 endpoints
18. [AI_COACH](#18-ai_coach---assistente-ai) - 10 endpoints
19. [BLOCKCHAIN](#19-blockchain---trasparenza-polygon) - 6 endpoints
20. [COMMUNICATION](#20-communication---chat-e-correzioni) - 8 endpoints
21. [AUDIO](#21-audio---elaborazione-audio) - 6 endpoints
22. [DOWNLOADS](#22-downloads---contenuti-offline) - 5 endpoints

---

## 1. AUTH - Autenticazione

**Router**: `auth.py`
**Prefix**: `/auth`
**Descrizione**: Gateway autenticazione piattaforma (JWT tokens)

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/auth/register` | No | Registrazione nuovo utente (tier FREE default) |
| 2 | POST | `/auth/login` | No | Login con email/password, ritorna JWT tokens |
| 3 | POST | `/auth/refresh` | No | Refresh access token usando refresh token |
| 4 | GET | `/auth/me` | User | Profilo utente corrente autenticato |
| 5 | POST | `/auth/logout` | No | Logout (client-side token deletion) |
| 6 | POST | `/auth/verify-email/{token}` | No | Verifica email con token da email link |
| 7 | POST | `/auth/forgot-password` | No | Richiesta reset password via email |
| 8 | POST | `/auth/reset-password/{token}` | No | Reset password con token |

**Parametri Principali**:
- `UserRegisterRequest`: email, username, password, full_name
- `UserLoginRequest`: email, password
- `RefreshTokenRequest`: refresh_token
- Token JWT: access_token (30min), refresh_token (7 giorni)

---

## 2. USERS - Gestione Utenti

**Router**: `users.py`
**Prefix**: `/users`
**Descrizione**: Profilo utente, preferenze, wallet

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/users/me` | User | Profilo utente completo con wallet |
| 2 | PUT | `/users/me` | User | Aggiorna profilo (nome, avatar, preferenze) |
| 3 | PUT | `/users/me/password` | User | Cambia password |
| 4 | GET | `/users/me/wallet` | User | Saldo stelline wallet |
| 5 | GET | `/users/me/subscription` | User | Dettagli abbonamento attivo |
| 6 | GET | `/users/me/purchases` | User | Lista acquisti video PPV |
| 7 | GET | `/users/me/activity` | User | Cronologia attività recente |
| 8 | DELETE | `/users/me` | User | Cancella account (soft delete) |

---

## 3. ADMIN - Pannello Amministrazione

**Router**: `admin.py`
**Prefix**: `/admin`
**Descrizione**: Gestione piattaforma completa (solo admin)

### Dashboard & Analytics

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/admin/dashboard` | Admin | KPIs: utenti, video, revenue 30d, code moderazione |
| 2 | GET | `/admin/analytics/platform` | Admin | Analytics piattaforma (7d/30d/90d/365d) |

### User Management

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 3 | GET | `/admin/users` | Admin | Lista utenti con paginazione e ricerca |
| 4 | GET | `/admin/users/{user_id}` | Admin | Dettaglio utente (profilo, maestro, wallet) |
| 5 | POST | `/admin/users/{user_id}/ban` | Admin | Banna utente (temporaneo/permanente) |
| 6 | POST | `/admin/users/{user_id}/unban` | Admin | Sbanna utente |

### Content Moderation

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 7 | GET | `/admin/moderation/videos` | Admin | Video in coda moderazione |
| 8 | POST | `/admin/moderation/videos/{video_id}` | Admin | Approva/rifiuta video |
| 9 | GET | `/admin/moderation/chat` | Admin | Messaggi chat segnalati |
| 10 | DELETE | `/admin/moderation/chat/{message_id}` | Admin | Elimina messaggio chat |

### Donations & Withdrawals

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 11 | GET | `/admin/donations` | Admin | Lista donazioni con filtri |
| 12 | GET | `/admin/donations/fraud-queue` | Admin | Donazioni sospette AML (>15k EUR) |
| 13 | GET | `/admin/withdrawals` | Admin | Lista richieste prelievo |
| 14 | GET | `/admin/withdrawals/{withdrawal_id}` | Admin | Dettaglio prelievo |
| 15 | POST | `/admin/withdrawals/{withdrawal_id}/action` | Admin | Approva/rifiuta prelievo |

### Maestro & ASD Management

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 16 | GET | `/admin/maestros` | Admin | Lista tutti maestri |
| 17 | GET | `/admin/asds` | Admin | Lista tutte ASD |

### Configuration

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 18 | GET | `/admin/config/tiers` | Admin | Configurazione tier prezzi |
| 19 | PUT | `/admin/config/tiers` | Admin | Aggiorna configurazione tier |

### Scheduler Jobs

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 20 | GET | `/admin/jobs` | Admin | Lista job scheduler |
| 21 | GET | `/admin/jobs/{job_id}` | Admin | Dettaglio job |
| 22 | GET | `/admin/jobs/{job_id}/history` | Admin | Storico esecuzioni job |
| 23 | POST | `/admin/jobs/{job_id}/trigger` | Admin | Esegui job manualmente |
| 24 | POST | `/admin/jobs/{job_id}/pause` | Admin | Pausa job schedulato |
| 25 | POST | `/admin/jobs/{job_id}/resume` | Admin | Riprendi job pausato |

---

## 4. VIDEOS - Gestione Video

**Router**: `videos.py`
**Prefix**: `/videos`
**Descrizione**: CRUD video, streaming HLS, preferiti, progresso

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/videos` | Optional | Lista video con filtri (categoria, difficoltà, tier) |
| 2 | GET | `/videos/search` | Optional | Ricerca full-text titolo/descrizione |
| 3 | GET | `/videos/trending` | Optional | Video più visti ultimi 7 giorni |
| 4 | GET | `/videos/home` | Optional | Home feed mobile (featured + righe per stile) |
| 5 | GET | `/videos/continue-watching` | User | Video iniziati ma non completati |
| 6 | GET | `/videos/favorites` | User | Lista preferiti (My List) |
| 7 | GET | `/videos/skeletons` | No | Lista skeleton estratti |
| 8 | GET | `/videos/skeleton/{asset_id}` | No | Dati skeleton per asset |
| 9 | GET | `/videos/{video_id}` | Optional | Dettaglio video singolo |
| 10 | POST | `/videos` | Admin | Crea nuovo video (metadata) |
| 11 | PUT | `/videos/{video_id}` | Admin | Aggiorna metadata video |
| 12 | DELETE | `/videos/{video_id}` | Admin | Elimina video + file |
| 13 | GET | `/videos/{video_id}/stream` | User | URL streaming HLS con token 1h |
| 14 | GET | `/videos/{video_id}/streaming` | User | Alias /stream |
| 15 | POST | `/videos/{video_id}/favorite` | User | Aggiungi a My List |
| 16 | DELETE | `/videos/{video_id}/favorite` | User | Rimuovi da My List |
| 17 | POST | `/videos/{video_id}/progress` | User | Aggiorna progresso visualizzazione |
| 18 | POST | `/videos/ingest` | No | Upload file + estrazione skeleton |

**Parametri Query**:
- `category`: technique, kata, combat, theory, workout, demo, other
- `difficulty`: beginner, intermediate, advanced, expert
- `tier`: free, hybrid_light, hybrid_standard, premium, business
- `sort_by`: created_at, view_count, title
- `sort_order`: asc, desc

---

## 5. SKELETON - Estrazione Landmark 75

**Router**: `skeleton.py`
**Prefix**: `/skeleton`
**Descrizione**: Estrazione MediaPipe Holistic (33 body + 21 left + 21 right hand)

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/skeleton/extract` | User | Avvia estrazione skeleton da video |
| 2 | GET | `/skeleton/status/{job_id}` | User | Stato job estrazione (progress %) |
| 3 | GET | `/skeleton/videos/{video_id}` | User | Recupera skeleton completo JSON |
| 4 | GET | `/skeleton/videos/{video_id}/metadata` | User | Solo metadata (fps, frames, etc) |
| 5 | GET | `/skeleton/videos/{video_id}/frame/{frame_number}` | User | Singolo frame 75 landmarks |
| 6 | GET | `/skeleton/videos/{video_id}/frames` | User | Range frame con paginazione |
| 7 | POST | `/skeleton/batch` | User | Estrazione batch multipli video |
| 8 | GET | `/skeleton/download/{video_id}` | User | Download skeleton JSON |
| 9 | GET | `/skeleton/health` | No | Health check API skeleton |

**Struttura Frame**:
```json
{
  "index": 0,
  "timestamp": 0.0,
  "body": [33 landmarks],
  "left_hand": [21 landmarks],
  "right_hand": [21 landmarks]
}
```

---

## 6. AVATARS - Avatar 3D

**Router**: `avatars.py`
**Prefix**: `/avatars`
**Descrizione**: Gestione avatar GLB/GLTF con bone mapping MediaPipe

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/avatars/bone-mapping` | No | Mapping 75 landmarks -> bones avatar |
| 2 | GET | `/avatars/styles` | No | Stili marziali disponibili con count |
| 3 | GET | `/avatars/` | Optional | Lista avatar (pubblici + owned) |
| 4 | GET | `/avatars/{avatar_id}` | Optional | Dettaglio avatar |
| 5 | POST | `/avatars/` | Admin | Upload nuovo avatar GLB (max 50MB) |
| 6 | PUT | `/avatars/{avatar_id}` | Admin | Aggiorna metadata avatar |
| 7 | DELETE | `/avatars/{avatar_id}` | Admin | Soft delete avatar |
| 8 | GET | `/avatars/{avatar_id}/file` | No | Download file GLB streaming |
| 9 | POST | `/avatars/{avatar_id}/apply-skeleton` | User | Applica skeleton per generare animazione |

**Stili Supportati**:
- karate, judo, aikido, taekwondo, kung_fu, mma, brazilian_jiu_jitsu, generic

---

## 7. FUSION - Fusione Multi-Video

**Router**: `fusion.py`
**Prefix**: `/fusion`
**Descrizione**: Fusione skeleton da video multipli con allineamento DTW

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/fusion/create` | User | Avvia fusione multi-video |
| 2 | GET | `/fusion/status/{job_id}` | User | Stato job fusione |
| 3 | GET | `/fusion/{fusion_id}` | User | Risultato fusione completo |
| 4 | GET | `/fusion/list` | User | Lista fusioni utente |
| 5 | DELETE | `/fusion/{fusion_id}` | User | Elimina fusione |
| 6 | GET | `/fusion/health` | No | Health check fusion service |

---

## 8. EXPORT - Esportazione 3D

**Router**: `export.py`
**Prefix**: `/export`
**Descrizione**: Export per Blender, FBX, BVH

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/export/formats` | No | Formati export disponibili |
| 2 | POST | `/export/blender` | User | Export formato Blender Python |
| 3 | POST | `/export/bvh` | User | Export formato BVH motion capture |
| 4 | POST | `/export/fbx` | User | Export formato FBX |
| 5 | POST | `/export/bulk` | User | Export bulk multipli video |
| 6 | GET | `/export/list` | User | Lista export utente |
| 7 | GET | `/export/status/{export_id}` | User | Stato export |
| 8 | GET | `/export/download/{export_id}` | User | Download file export |
| 9 | DELETE | `/export/{export_id}` | User | Elimina export |
| 10 | GET | `/export/health` | No | Health check export service |

---

## 9. CURRICULUM - Percorsi Didattici

**Router**: `curriculum.py`
**Prefix**: `/curriculum`
**Descrizione**: Percorsi di apprendimento strutturati per cintura/livello

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/curriculum/paths` | Optional | Lista percorsi disponibili |
| 2 | GET | `/curriculum/paths/{path_id}` | Optional | Dettaglio percorso con moduli |
| 3 | GET | `/curriculum/paths/{path_id}/modules` | User | Moduli del percorso |
| 4 | GET | `/curriculum/modules/{module_id}` | User | Dettaglio modulo con lezioni |
| 5 | GET | `/curriculum/lessons/{lesson_id}` | User | Dettaglio lezione |
| 6 | POST | `/curriculum/progress` | User | Aggiorna progresso lezione |
| 7 | GET | `/curriculum/my-progress` | User | Progresso complessivo utente |
| 8 | GET | `/curriculum/certificates` | User | Certificati ottenuti |
| 9 | POST | `/curriculum/paths` | Admin | Crea nuovo percorso |
| 10 | POST | `/curriculum/modules` | Admin | Crea nuovo modulo |
| 11 | POST | `/curriculum/lessons` | Admin | Crea nuova lezione |
| 12 | GET | `/curriculum/styles` | No | Stili marziali disponibili |

---

## 10. MAESTRO - Pannello Istruttori

**Router**: `maestro.py`
**Prefix**: `/maestro`
**Descrizione**: Dashboard e gestione per insegnanti certificati

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/maestro/dashboard` | Maestro | Dashboard KPIs (video, follower, earnings) |
| 2 | GET | `/maestro/videos` | Maestro | Lista video caricati |
| 3 | DELETE | `/maestro/videos/{video_id}` | Maestro | Elimina proprio video |
| 4 | POST | `/maestro/live-events` | Maestro | Crea evento live |
| 5 | GET | `/maestro/live-events` | Maestro | Lista eventi live |
| 6 | DELETE | `/maestro/live-events/{event_id}` | Maestro | Annulla evento live |
| 7 | GET | `/maestro/earnings` | Maestro | Report guadagni (7d/30d/90d/365d) |
| 8 | POST | `/maestro/withdrawals` | Maestro | Richiedi prelievo (min 10k stelline) |
| 9 | GET | `/maestro/withdrawals` | Maestro | Lista richieste prelievo |
| 10 | GET | `/maestro/corrections` | Maestro | Richieste correzione studenti |
| 11 | POST | `/maestro/corrections/{request_id}/feedback` | Maestro | Invia feedback correzione |
| 12 | GET | `/maestro/translations` | Maestro | Dataset traduzioni personalizzate |
| 13 | GET | `/maestro/glossary` | Maestro | Glossario termini tecnici |

---

## 11. ASD - Associazioni Sportive

**Router**: `asd.py`
**Prefix**: `/asd`
**Descrizione**: Gestione Associazioni Sportive Dilettantistiche

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/asd/` | User | Lista ASD pubbliche |
| 2 | GET | `/asd/{asd_id}` | User | Dettaglio ASD |
| 3 | POST | `/asd/` | Admin | Crea nuova ASD |
| 4 | PUT | `/asd/{asd_id}` | ASD Admin | Aggiorna ASD |
| 5 | GET | `/asd/{asd_id}/members` | ASD Admin | Lista membri ASD |
| 6 | POST | `/asd/{asd_id}/members` | ASD Admin | Aggiungi membro |
| 7 | DELETE | `/asd/{asd_id}/members/{user_id}` | ASD Admin | Rimuovi membro |
| 8 | GET | `/asd/{asd_id}/stats` | ASD Admin | Statistiche ASD |
| 9 | GET | `/asd/{asd_id}/events` | User | Eventi ASD |
| 10 | POST | `/asd/{asd_id}/events` | ASD Admin | Crea evento ASD |

---

## 12. LIVE - Eventi Streaming

**Router**: `live.py`
**Prefix**: `/live`
**Descrizione**: Gestione eventi live streaming

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/live/events` | Optional | Lista eventi live |
| 2 | GET | `/live/events/{event_id}` | Optional | Dettaglio evento |
| 3 | POST | `/live/events/{event_id}/start` | Maestro | Avvia streaming |
| 4 | POST | `/live/events/{event_id}/stop` | Maestro | Termina streaming |
| 5 | GET | `/live/events/{event_id}/viewers` | Maestro | Lista spettatori |
| 6 | POST | `/live/events/{event_id}/chat` | User | Invia messaggio chat |
| 7 | GET | `/live/events/{event_id}/chat` | User | Storico chat |
| 8 | WS | `/live/events/{event_id}/ws` | User | WebSocket streaming |

---

## 13. LIVE_TRANSLATION - Sottotitoli Tempo Reale

**Router**: `live_translation.py`
**Prefix**: `/live-translation`
**Descrizione**: Speech-to-text + traduzione multilingue per live

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | WS | `/live-translation/events/{event_id}/subtitles` | No | WebSocket ricezione sottotitoli |
| 2 | WS | `/live-translation/events/{event_id}/broadcast` | Maestro | WebSocket invio audio broadcaster |
| 3 | POST | `/live-translation/events/{event_id}/start` | Admin | Avvia sessione traduzione |
| 4 | POST | `/live-translation/events/{event_id}/stop` | Admin | Ferma sessione traduzione |
| 5 | GET | `/live-translation/events/{event_id}/stats` | User | Statistiche viewer per lingua |
| 6 | GET | `/live-translation/languages/supported` | No | Lingue supportate |
| 7 | GET | `/live-translation/providers/info` | No | Info provider (Whisper/NLLB/Google) |
| 8 | POST | `/live-translation/providers/switch` | Admin | Cambia provider speech/translation |

**Lingue Target Default**: it, en, es, fr, de

---

## 14. PAYMENTS - Pagamenti Stripe

**Router**: `payments.py`
**Prefix**: `/payments`
**Descrizione**: Payment intents, stelline, subscription Stripe

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/payments/stelline/purchase` | User | Crea payment intent acquisto stelline |
| 2 | POST | `/payments/stelline/confirm` | User | Conferma acquisto dopo pagamento |
| 3 | POST | `/payments/subscription/create` | User | Crea subscription Stripe |
| 4 | POST | `/payments/subscription/cancel` | User | Annulla subscription |
| 5 | GET | `/payments/history` | User | Storico pagamenti |
| 6 | POST | `/payments/video/{video_id}/purchase` | User | Acquista video PPV con stelline |
| 7 | POST | `/payments/webhook` | No | Webhook handler Stripe |

**Pacchetti Stelline**:
- small: 1000 stelline (€10)
- medium: 5000 stelline (€45)
- large: 10000 stelline (€80)

---

## 15. SUBSCRIPTIONS - Abbonamenti

**Router**: `subscriptions.py`
**Prefix**: `/subscriptions`
**Descrizione**: Gestione tier abbonamento

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/subscriptions/plans` | No | Lista piani disponibili |
| 2 | GET | `/subscriptions/current` | User | Abbonamento corrente |
| 3 | POST | `/subscriptions/upgrade` | User | Upgrade tier |
| 4 | POST | `/subscriptions/downgrade` | User | Downgrade tier |
| 5 | GET | `/subscriptions/invoices` | User | Storico fatture |
| 6 | POST | `/subscriptions/restore` | User | Ripristina abbonamento annullato |

**Tier Disponibili**:
| Tier | Prezzo | Features |
|------|--------|----------|
| FREE | €0 | 720p, ads |
| HYBRID_LIGHT | €4.99 | 1080p, no ads |
| HYBRID_STANDARD | €9.99 | 1080p, downloads |
| PREMIUM | €19.99 | 4K, all features |
| BUSINESS | €49.99 | Bulk licenses, API access |

---

## 16. DONATIONS - Stelline e Donazioni

**Router**: `donations.py`
**Prefix**: `/donations`
**Descrizione**: Sistema stelline, donazioni a maestri/ASD

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/donations/send` | User | Invia stelline a maestro/ASD |
| 2 | GET | `/donations/sent` | User | Donazioni inviate |
| 3 | GET | `/donations/received` | Maestro | Donazioni ricevute |
| 4 | GET | `/donations/wallet` | User | Saldo wallet stelline |
| 5 | GET | `/donations/transactions` | User | Storico transazioni wallet |
| 6 | POST | `/donations/goals` | Maestro | Crea obiettivo fundraising |
| 7 | GET | `/donations/goals/{goal_id}` | No | Dettaglio obiettivo |
| 8 | GET | `/donations/leaderboard` | No | Classifica donatori |

---

## 17. NOTIFICATIONS - Notifiche Push

**Router**: `notifications.py`
**Prefix**: `/notifications`
**Descrizione**: Sistema notifiche in-app e push

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | GET | `/notifications` | User | Lista notifiche utente |
| 2 | DELETE | `/notifications` | User | Elimina tutte notifiche |
| 3 | GET | `/notifications/unread-count` | User | Conteggio non lette |
| 4 | POST | `/notifications/mark-all-read` | User | Segna tutte come lette |
| 5 | GET | `/notifications/device-tokens` | User | Lista device token registrati |
| 6 | POST | `/notifications/device-tokens` | User | Registra device token push |
| 7 | DELETE | `/notifications/device-tokens/{token_id}` | User | Rimuovi device token |
| 8 | GET | `/notifications/preferences` | User | Preferenze notifiche |
| 9 | PATCH | `/notifications/preferences` | User | Aggiorna preferenze |
| 10 | GET | `/notifications/{notification_id}` | User | Dettaglio notifica |
| 11 | PATCH | `/notifications/{notification_id}/read` | User | Segna come letta |
| 12 | DELETE | `/notifications/{notification_id}` | User | Elimina notifica |
| 13 | POST | `/notifications/admin/broadcast` | Admin | Broadcast a tutti utenti |
| 14 | GET | `/notifications/admin/stats/{user_id}` | Admin | Statistiche notifiche utente |
| 15 | POST | `/notifications/admin/cleanup` | Admin | Cleanup notifiche vecchie |

---

## 18. AI_COACH - Assistente AI

**Router**: `ai_coach.py`
**Prefix**: `/ai-coach`
**Descrizione**: Coach conversazionale AI per arti marziali (RAG + LLM)

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/ai-coach/chat` | User | Chat con AI coach |
| 2 | POST | `/ai-coach/chat/stream` | User | Chat streaming SSE |
| 3 | GET | `/ai-coach/conversations` | User | Lista conversazioni |
| 4 | GET | `/ai-coach/conversations/{id}` | User | Storico conversazione |
| 5 | DELETE | `/ai-coach/conversations/{id}` | User | Elimina conversazione |
| 6 | POST | `/ai-coach/feedback/technique` | User | Analisi tecnica video |
| 7 | POST | `/ai-coach/feedback/pose` | User | Feedback posa real-time (<100ms) |
| 8 | GET | `/ai-coach/knowledge/search` | User | Ricerca knowledge base |
| 9 | GET | `/ai-coach/styles` | No | Stili marziali supportati |
| 10 | GET | `/ai-coach/health` | No | Health check AI service |

---

## 19. BLOCKCHAIN - Trasparenza Polygon

**Router**: `blockchain.py`
**Prefix**: `/blockchain`
**Descrizione**: Pubblicazione dati trasparenza su Polygon

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/blockchain/batches/create` | Admin | Crea batch settimanale dati |
| 2 | POST | `/blockchain/batches/{batch_id}/broadcast` | Admin | Broadcast a nodi store |
| 3 | POST | `/blockchain/batches/{batch_id}/validate` | Node | Ricevi validazione nodo |
| 4 | POST | `/blockchain/batches/{batch_id}/publish` | Admin | Pubblica su Polygon |
| 5 | GET | `/blockchain/batches/{batch_id}` | User | Stato batch |
| 6 | GET | `/blockchain/batches` | User | Lista batch pubblicati |

---

## 20. COMMUNICATION - Chat e Correzioni

**Router**: `communication.py`
**Prefix**: `/communication`
**Descrizione**: Chat live, richieste correzione, messaggi diretti

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/communication/corrections` | User | Richiedi correzione a maestro |
| 2 | GET | `/communication/corrections` | User | Lista richieste correzione |
| 3 | GET | `/communication/corrections/{id}` | User | Dettaglio correzione |
| 4 | POST | `/communication/messages` | User | Invia messaggio diretto |
| 5 | GET | `/communication/messages` | User | Lista conversazioni |
| 6 | GET | `/communication/messages/{thread_id}` | User | Messaggi thread |
| 7 | DELETE | `/communication/messages/{message_id}` | User | Elimina messaggio |
| 8 | POST | `/communication/report` | User | Segnala contenuto inappropriato |

---

## 21. AUDIO - Elaborazione Audio

**Router**: `audio.py`
**Prefix**: `/audio`
**Descrizione**: Estrazione e processamento tracce audio

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/audio/extract` | User | Estrai audio da video |
| 2 | GET | `/audio/status/{job_id}` | User | Stato job estrazione |
| 3 | GET | `/audio/{audio_id}` | User | Download audio estratto |
| 4 | POST | `/audio/transcribe` | User | Trascrizione speech-to-text |
| 5 | GET | `/audio/transcription/{id}` | User | Risultato trascrizione |
| 6 | DELETE | `/audio/{audio_id}` | User | Elimina audio |

---

## 22. DOWNLOADS - Contenuti Offline

**Router**: `downloads.py`
**Prefix**: `/downloads`
**Descrizione**: Download video per visualizzazione offline

| # | Metodo | Path | Autenticazione | Descrizione |
|---|--------|------|----------------|-------------|
| 1 | POST | `/downloads/videos/{video_id}` | User | Richiedi download video |
| 2 | GET | `/downloads/videos` | User | Lista video scaricabili |
| 3 | GET | `/downloads/status/{download_id}` | User | Stato download |
| 4 | GET | `/downloads/file/{download_id}` | User | Download file |
| 5 | DELETE | `/downloads/{download_id}` | User | Rimuovi download |

---

## RIEPILOGO TOTALE ENDPOINTS

| Area | Endpoints | Descrizione |
|------|-----------|-------------|
| AUTH | 8 | Autenticazione JWT |
| USERS | 8 | Profilo utente |
| ADMIN | 25 | Gestione piattaforma |
| VIDEOS | 18 | CRUD + streaming video |
| SKELETON | 10 | Estrazione 75 landmarks |
| AVATARS | 9 | Avatar 3D GLB |
| FUSION | 6 | Multi-video fusion |
| EXPORT | 10 | Blender/FBX/BVH export |
| CURRICULUM | 12 | Percorsi didattici |
| MAESTRO | 13 | Panel insegnanti |
| ASD | 10 | Associazioni sportive |
| LIVE | 8 | Eventi streaming |
| LIVE_TRANSLATION | 8 | Sottotitoli real-time |
| PAYMENTS | 7 | Stripe payments |
| SUBSCRIPTIONS | 6 | Abbonamenti |
| DONATIONS | 8 | Stelline e donazioni |
| NOTIFICATIONS | 15 | Push notifications |
| AI_COACH | 10 | Assistente AI |
| BLOCKCHAIN | 6 | Polygon transparency |
| COMMUNICATION | 8 | Chat e correzioni |
| AUDIO | 6 | Audio processing |
| DOWNLOADS | 5 | Contenuti offline |
| **TOTALE** | **218** | |

---

## AUTENTICAZIONE

### Livelli di Accesso

| Livello | Descrizione |
|---------|-------------|
| `No` | Endpoint pubblico, nessuna autenticazione richiesta |
| `Optional` | Autenticazione opzionale (più contenuti se autenticato) |
| `User` | Richiede JWT token valido |
| `Maestro` | Richiede JWT + ruolo Maestro attivo |
| `ASD Admin` | Richiede JWT + ruolo admin ASD |
| `Admin` | Richiede JWT + flag is_admin=true |

### Header Autenticazione
```
Authorization: Bearer <access_token>
```

### Codici Errore Comuni

| Codice | Descrizione |
|--------|-------------|
| 401 | Token mancante/invalido/scaduto |
| 403 | Permessi insufficienti per ruolo |
| 404 | Risorsa non trovata |
| 422 | Validazione parametri fallita |
| 429 | Rate limit superato |

---

## NOTE TECNICHE

### Stack Backend
- **Framework**: FastAPI (Python 3.11+)
- **Database**: PostgreSQL + SQLAlchemy 2.x async
- **Auth**: JWT (PyJWT) con refresh token rotation
- **Payments**: Stripe API
- **ML**: MediaPipe Holistic per skeleton extraction
- **AI**: LLM integration per coach conversazionale
- **Blockchain**: Polygon (ETH L2) per trasparenza

### Performance Targets
- API response: < 100ms (p95)
- Skeleton extraction: < 50ms/frame
- Pose feedback: < 100ms (real-time)
- WebSocket latency: < 50ms

### Documentazione Auto-Generata
- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI JSON: `/openapi.json`

---

*Documento generato automaticamente analizzando i router FastAPI in `/backend/api/v1/`*

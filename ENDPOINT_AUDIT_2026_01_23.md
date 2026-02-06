# ENDPOINT AUDIT REPORT
**Data**: 2026-01-23
**Progetto**: media-center-arti-marziali
**Tipo**: Read-Only Audit

---

## ROUTER REGISTRATI IN main.py

### Gruppo 1: routers_config (Linee 194-205)
| Router | Prefix | Tags |
|--------|--------|------|
| auth | `/api/v1/auth` | auth |
| users | `/api/v1/users` | users |
| videos | `/api/v1/videos` | videos |
| subscriptions | `/api/v1/subscriptions` | subscriptions |
| ads | `/api/v1/ads` | ads |
| blockchain | `/api/v1/blockchain` | blockchain |
| maestro | `/api/v1/maestro` | maestro |
| live | `/api/v1/live` | live |
| asd | `/api/v1/asd` | asd |
| admin | `/api/v1/admin` | admin |

### Gruppo 2: Router individuali
| Router | Prefix | Tags | Linea |
|--------|--------|------|-------|
| communication | `/api/v1/communication` | communication | 219 |
| library | `/api/v1` | library | 228 |
| moderation | `/api/v1/moderation` | moderation | 237 |
| payments | `/api/v1/payments` | payments | 246 |
| live_translation | `/api/v1/live-translation` | live-translation | 255 |
| ingest_projects | `/api/v1/ingest` | ingest | 267 |
| temp_zone | `/api/v1/admin/temp-zone` | temp-zone | 276 |
| audio | `/api/v1/audio` | audio | 285 |
| contributions | `/api/v1/contributions` | contributions | 297 |
| glasses_ws | `/api/v1` | glasses | 306 |
| video_studio | `/api/v1/video-studio` | video-studio | 315 |
| royalties | `/api/v1/royalties` | royalties | 327 |
| special_projects | `/api/v1` | special-projects | 339 |
| events | `/api/v1/events` | events | 351 |
| gdpr | `/api/v1` | gdpr | 363 |
| notifications | `/api/v1/notifications` | notifications | 375 |
| downloads | `/api/v1` | downloads | 384 |
| scheduler | `/api/v1` | scheduler | 393 |
| skeleton | `/api/v1/skeleton` | skeleton | 402 |
| fusion | `/api/v1/fusion` | fusion | 414 |
| export | `/api/v1/export` | export | 426 |
| ai_coach | `/api/v1/ai-coach` | ai-coach | 438 |

**Totale router registrati: 32**

---

## FILE ROUTER IN api/v1/

| File | Descrizione |
|------|-------------|
| `__init__.py` | Package init |
| `admin.py` | Admin endpoints |
| `admin_continued.py` | Admin esteso |
| `ads.py` | Sistema ads |
| `ai_coach.py` | AI Coach conversazionale |
| `asd.py` | Gestione ASD |
| `audio.py` | TTS, voice cloning |
| `auth.py` | Autenticazione |
| `blockchain.py` | Blockchain tracking |
| `communication.py` | Comunicazioni |
| `contributions.py` | Staff contributions |
| `curriculum.py` | **NON REGISTRATO** |
| `downloads.py` | Download offline |
| `export.py` | Export Blender/FBX |
| `fusion.py` | Multi-video fusion |
| `glasses_ws.py` | Smart glasses WS |
| `ingest_projects.py` | Unified ingest |
| `library.py` | User library |
| `live.py` | Live streaming |
| `live_translation.py` | Traduzione live |
| `maestro.py` | Maestro endpoints |
| `moderation.py` | Video moderation |
| `notifications.py` | Notifiche |
| `payments.py` | Stripe integration |
| `scheduler.py` | Job scheduler |
| `schemas.py` | Schema definitions |
| `schemas_ingest.py` | Ingest schemas |
| `skeleton.py` | Pose extraction |
| `subscriptions.py` | Abbonamenti |
| `temp_zone.py` | Temp file admin |
| `users.py` | User management |
| `video_studio.py` | Video studio |
| `videos.py` | Video CRUD + search |

**Totale file router: 32 (esclusi schemas)**

---

## ENDPOINT /search/*

### ESISTENTE: `/api/v1/videos/search`
- **File**: `backend/api/v1/videos.py`
- **Linea**: 255
- **Metodo**: GET
- **Response**: `VideoListResponse`
- **Descrizione**: Search videos by query string

```python
@router.get(
    "/search",
    response_model=VideoListResponse,
    summary="Search videos",
    description="Search videos by query string"
)
```

### ESISTENTE: `/api/v1/ai-coach/knowledge/search`
- **File**: `backend/api/v1/ai_coach.py`
- **Linea**: 783
- **Metodo**: GET
- **Response**: `List[KnowledgeSearchResult]`
- **Descrizione**: Search knowledge base

```python
@router.get(
    "/knowledge/search",
    response_model=List[KnowledgeSearchResult],
    summary="Search knowledge base",
)
```

---

## ENDPOINT /trending/*

### MANCANTE

Non esiste alcun endpoint `/trending` nel backend.

**Riferimenti trovati**:
- `backend/modules/ads/pause_ad_service.py:611` - Metodo interno `_get_trending_video()` (non esposto come API)

**Endpoint correlati esistenti**:
- `/api/v1/videos/home-feed` (videos.py:307) - Contiene `featured` video ma non `trending`

---

## RIEPILOGO

| Endpoint | Stato | Note |
|----------|-------|------|
| `/api/v1/videos/search` | ESISTENTE | Funzionante |
| `/api/v1/ai-coach/knowledge/search` | ESISTENTE | Funzionante |
| `/api/v1/*/trending` | **MANCANTE** | Da implementare |

---

## PROBLEMA CRITICO RILEVATO

### curriculum.py NON REGISTRATO

Il file `backend/api/v1/curriculum.py` esiste (619+ linee) ma **non e registrato in main.py**.

Questo significa che tutti gli endpoint curriculum non sono accessibili:
- `/api/v1/curriculum/*` - NON FUNZIONANTI

**Azione richiesta**: Aggiungere registrazione router in main.py

---

## SUGGERIMENTI

### 1. Implementare /trending
Creare endpoint in `videos.py`:
```python
@router.get("/trending")
async def get_trending_videos():
    # Logica per video trending basata su views/engagement
```

### 2. Registrare curriculum router
Aggiungere in `main.py`:
```python
try:
    from api.v1 import curriculum
    app.include_router(curriculum.router, prefix="/api/v1/curriculum", tags=["curriculum"])
    print("[OK] Curriculum router loaded")
except Exception as e:
    print(f"[ERROR] Curriculum router failed to load: {e}")
```

---

*Report generato automaticamente il 2026-01-23*

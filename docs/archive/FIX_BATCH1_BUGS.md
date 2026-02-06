# FIX BATCH 1 — 3 BUG DA RISOLVERE

## Progetto: Media Center Arti Marziali
## Path: C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali
## Backend: backend/  (FastAPI, porta 8000)
## Frontend: frontend/ (React, porta 3100)

---

## BUG 1: ENDPOINT /api/v1/library/stats MANCANTE (404)

**Problema:** Il frontend chiama `GET /api/v1/library/stats` ma il backend ritorna 404.
Lo si vede nei log: `GET /api/v1/library/stats HTTP/1.1" 404 Not Found`

**Cosa fare:**
1. Cerca nel frontend dove viene chiamato `/api/v1/library/stats` (grep ricorsivo)
2. Verifica se esiste già un router "library" nel backend (`backend/modules/`)
3. Se il router library esiste (`[OK] Library router loaded` — SÌ, esiste), manca solo l'endpoint `/stats`
4. Aggiungi endpoint GET `/stats` nel router library che ritorna statistiche base:
   - total_items (count totale risorse in libreria)
   - total_videos
   - total_documents
   - recent_additions (ultimi 5 items)

**File da modificare:**
- Backend: trova il file del Library router (probabilmente `backend/modules/library/router.py` o simile)
- Aggiungi endpoint con commenti AI-First

**Template endpoint:**
```python
@router.get("/stats")
async def get_library_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    🎓 AI_MODULE: Library Stats
    🎓 AI_DESCRIPTION: Ritorna statistiche aggregate della libreria contenuti
    🎓 AI_BUSINESS: Dashboard overview — utente vede attività libreria
    🎓 AI_TEACHING: Aggregazione SQL con count/group_by
    """
    # Implementa query reali sul DB
    return {
        "total_items": 0,  # SOSTITUISCI con query reale
        "total_videos": 0,
        "total_documents": 0,
        "recent_additions": []
    }
```

---

## BUG 2: ENDPOINT /api/v1/live/sessions MANCANTE (404)

**Problema:** Il frontend chiama `GET /api/v1/live/sessions` ma il backend ritorna 404.
Log: `GET /api/v1/live/sessions HTTP/1.1" 404 Not Found`

**Cosa fare:**
1. Cerca nel frontend dove viene chiamato `/api/v1/live/sessions`
2. Il router live esiste (`[OK] live router loaded`)
3. Manca l'endpoint `GET /sessions` nel router live
4. Aggiungi endpoint che ritorna lista sessioni live (anche vuota se non ce ne sono)

**File da modificare:**
- Backend: trova il file del Live router (`backend/modules/live/router.py` o simile)

**Template endpoint:**
```python
@router.get("/sessions")
async def get_live_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    🎓 AI_MODULE: Live Sessions List
    🎓 AI_DESCRIPTION: Ritorna lista sessioni live attive e programmate
    🎓 AI_BUSINESS: Utenti vedono lezioni live disponibili
    🎓 AI_TEACHING: Query con filtro stato attivo + ordinamento per data
    """
    # Implementa query reali
    return {
        "sessions": [],
        "total": 0,
        "active_now": 0
    }
```

---

## BUG 3: ROUTE FRONTEND /videos → 404

**Problema:** `GET http://localhost:3100/videos` ritorna 404.
Il frontend non ha una route `/videos`.

**Cosa fare:**
1. Cerca nel frontend il file di routing (es. `App.tsx`, `routes.tsx`, `router.tsx`)
2. Verifica quali route esistono per i video — potrebbe essere `/video-library`, `/library`, ecc.
3. OPZIONE A: Aggiungi route `/videos` che punta al componente video library esistente
4. OPZIONE B: Aggiungi redirect da `/videos` alla route corretta

**Esempio (React Router):**
```tsx
// Se il componente esiste con altro path, aggiungi redirect:
<Route path="/videos" element={<Navigate to="/video-library" replace />} />

// OPPURE aggiungi route diretta:
<Route path="/videos" element={<VideoLibrary />} />
```

---

## REGOLE DI SVILUPPO

1. **ZERO placeholder** — implementa query reali sul DB, non valori hardcoded
2. **Commenti AI-First** — ogni funzione con header 🎓 AI_MODULE, AI_DESCRIPTION, AI_BUSINESS, AI_TEACHING
3. **Testa dopo il fix** — verifica che gli endpoint rispondano 200
4. **Non rompere nulla** — fai solo le modifiche indicate, non refactoring

## VERIFICA

Dopo i fix, esegui:
```powershell
curl http://localhost:8000/api/v1/library/stats
curl http://localhost:8000/api/v1/live/sessions
curl http://localhost:3100/videos
```

Tutti devono rispondere 200 (o redirect 3xx per il frontend).

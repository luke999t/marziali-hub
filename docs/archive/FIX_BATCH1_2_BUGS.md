# FIX BUG BATCH 1 + BATCH 2 — PROMPT PER CLAUDE CODE

## Progetto: Media Center Arti Marziali
## Path: C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali
## Backend: backend/ (FastAPI, porta 8000)
## Frontend: frontend/ (React, porta 3100)

---

## BUG 1: ENDPOINT /api/v1/library/stats MANCANTE (404) [BATCH 1]

**Log backend:** `GET /api/v1/library/stats HTTP/1.1" 404 Not Found`
**Il router Library è caricato** (`[OK] Library router loaded`)

**Azione:**
1. Trova il file router library: `grep -r "Library router" backend/`
2. Apri il file e aggiungi endpoint GET `/stats`
3. Implementa query reali su DB (count items, videos, documents)

```python
@router.get("/stats")
async def get_library_stats(current_user = Depends(get_current_user), db = Depends(get_db)):
    """
    🎓 AI_MODULE: Library Stats
    🎓 AI_DESCRIPTION: Statistiche aggregate libreria contenuti
    🎓 AI_BUSINESS: Dashboard overview utente
    """
    # Query reali sul DB - adatta ai modelli esistenti
    return {"total_items": 0, "total_videos": 0, "recent_additions": []}
```

---

## BUG 2: ENDPOINT /api/v1/live/sessions MANCANTE (404) [BATCH 1]

**Log backend:** `GET /api/v1/live/sessions HTTP/1.1" 404 Not Found`
**Il router Live è caricato** (`[OK] live router loaded`)

**Azione:**
1. Trova il file router live: `grep -r "live router" backend/`
2. Aggiungi endpoint GET `/sessions`

```python
@router.get("/sessions")
async def get_live_sessions(current_user = Depends(get_current_user), db = Depends(get_db)):
    """
    🎓 AI_MODULE: Live Sessions
    🎓 AI_DESCRIPTION: Lista sessioni live attive/programmate
    🎓 AI_BUSINESS: Utenti vedono lezioni live disponibili
    """
    return {"sessions": [], "total": 0, "active_now": 0}
```

---

## BUG 3: ROUTE FRONTEND /videos → 404 [BATCH 1]

**La pagina video esiste su /library** (confermato dal test).

**Azione:**
1. Trova il file routing frontend: `grep -r "Route" frontend/src/App.tsx` (o routes.tsx)
2. Aggiungi redirect: `<Route path="/videos" element={<Navigate to="/library" replace />} />`

---

## BUG 4: DB CURRICULA VUOTO [BATCH 2]

**L'API /curricula/ risponde 200 ma con lista vuota (count=0).**
L'API funziona, mancano i dati.

**Azione:** Crea script seed per popolare il DB con 3-5 curricula di esempio:

```python
# backend/scripts/seed_curricula.py
"""Seed 5 curricula di esempio per testing"""

curricula_data = [
    {
        "title": "Wing Chun - Forme Base",
        "description": "Percorso completo delle forme base del Wing Chun: Siu Nim Tao, Chum Kiu, Biu Jee",
        "style": "wing_chun",
        "difficulty": "beginner",
        "levels": 3
    },
    {
        "title": "Karate Shotokan - Kata Fondamentali",
        "description": "I 26 kata Shotokan dal Taikyoku ai kata avanzati",
        "style": "karate",
        "difficulty": "intermediate",
        "levels": 5
    },
    {
        "title": "Tai Chi Chen - 18 Movimenti",
        "description": "Forma breve Tai Chi stile Chen per principianti",
        "style": "tai_chi",
        "difficulty": "beginner",
        "levels": 2
    },
    {
        "title": "Kung Fu Wushu - Combinazioni di Combattimento",
        "description": "Tecniche di combattimento e combinazioni per agonismo",
        "style": "wushu",
        "difficulty": "advanced",
        "levels": 4
    },
    {
        "title": "Judo - Tecniche di Proiezione",
        "description": "Le 40 tecniche di proiezione del Gokyo no Waza",
        "style": "judo",
        "difficulty": "intermediate",
        "levels": 4
    }
]
```

**Importante:** Guarda i modelli DB del curriculum (`grep -r "class Curriculum" backend/`) per capire i campi esatti, poi adatta il seed di conseguenza. Esegui il seed e verifica con `curl http://localhost:8000/api/v1/curricula/`.

---

## BUG 5: /videos/upload → 405 Method Not Allowed [BATCH 2]

**L'endpoint esiste ma non accetta POST con JSON** (probabilmente vuole multipart/form-data).

**Azione:**
1. Verifica: `grep -r "upload" backend/modules/videos/` — controlla il metodo HTTP (POST? PUT?)
2. Se il metodo è corretto ma vuole file: non è un bug, è il test che era impreciso
3. Se manca l'handler POST: aggiungilo

---

## BUG 6: NESSUN ENDPOINT /categories O /tags PER VIDEO [BATCH 2]

**Azione:**
1. Verifica se ci sono categorie nel modello Video: `grep -r "category\|tag" backend/modules/videos/`
2. Se il campo esiste nel modello, aggiungi endpoint:

```python
@router.get("/categories")
async def get_video_categories(db = Depends(get_db)):
    """
    🎓 AI_MODULE: Video Categories
    🎓 AI_DESCRIPTION: Lista categorie video distinte
    """
    # Query distinct categories dal DB
    return {"categories": []}
```

---

## REGOLE
- ZERO placeholder finali — query reali sul DB
- Commenti AI-First su ogni funzione
- Testa dopo ogni fix
- Non rompere codice esistente

## VERIFICA DOPO I FIX
```powershell
curl http://localhost:8000/api/v1/library/stats
curl http://localhost:8000/api/v1/live/sessions
curl http://localhost:8000/api/v1/curricula/
curl http://localhost:8000/api/v1/videos/categories
curl http://localhost:3100/videos
```

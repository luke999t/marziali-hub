# Allocazione Porte - Media Center Arti Marziali

**Data**: 29 Novembre 2025

---

## Porte Assegnate al Progetto

| Servizio | Porta | URL | Stato |
|----------|-------|-----|-------|
| **Backend FastAPI** | 8100 | http://localhost:8100 | Attivo |
| **Frontend Next.js** | 3200 | http://localhost:3200 | Attivo |

---

## Endpoint Backend (porta 8100)

| Endpoint | Descrizione |
|----------|-------------|
| `/health` | Health check |
| `/docs` | Swagger UI |
| `/api/v1/auth/*` | Autenticazione |
| `/api/v1/videos/*` | Gestione video |
| `/api/v1/videos/ingest` | Upload e ingest |
| `/api/v1/videos/skeletons` | Lista skeleton |
| `/api/v1/live/*` | Streaming live |
| `/api/v1/communication/*` | Messaggistica |
| `/api/v1/live-translation/*` | Traduzione real-time |

---

## WebSocket (porta 8100)

| Endpoint | Descrizione |
|----------|-------------|
| `ws://localhost:8100/api/v1/communication/ws/chat/{user_id}` | Chat real-time |
| `ws://localhost:8100/ws/live/{event_id}` | Sottotitoli live |

---

## Porte Riservate (NON usare)

| Porta | Occupata da |
|-------|-------------|
| 8000 | Altri progetti |
| 8001 | Altri progetti |
| 8002 | Altri progetti |
| 8003 | Altri progetti |
| 3100 | Altri progetti |

---

## File Configurazione Aggiornati

Tutti i seguenti file ora puntano a porta **8100**:

- `frontend/src/config/api.ts`
- `frontend/src/contexts/AuthContext.tsx`
- `frontend/src/components/LiveSubtitles.tsx`
- `frontend/src/components/MessageThread.tsx`
- `frontend/src/hooks/useLiveSubtitles.ts`
- `frontend/src/app/skeleton-editor/page.tsx`
- `frontend/src/app/donations/page.tsx`

---

## Comandi Avvio

### Backend
```bash
cd backend
venv\Scripts\python.exe -m uvicorn main:app --host 0.0.0.0 --port 8100 --reload
```

### Frontend
```bash
cd frontend
npm run dev -- -p 3200
```

---

## Verifica Funzionamento

```bash
# Health check backend
curl http://localhost:8100/health

# Lista skeleton
curl http://localhost:8100/api/v1/videos/skeletons

# Frontend
# Apri browser: http://localhost:3200
```

---

*Documento generato il 29/11/2025*

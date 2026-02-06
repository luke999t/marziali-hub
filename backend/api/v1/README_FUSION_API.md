# Multi-Video Fusion API

## Overview

REST API + WebSocket per creare avatar 360 "perfetti" fondendo multiple esecuzioni
della stessa tecnica da angolazioni diverse.

**Business Value:** Feature premium EUR 29/mese, +40% engagement istruttori.

## Quick Start

```bash
# Health check (no auth required)
curl http://localhost:8000/api/v1/fusion/health

# Get available styles (no auth required)
curl http://localhost:8000/api/v1/fusion/styles

# Get configuration presets (no auth required)
curl http://localhost:8000/api/v1/fusion/presets
```

## Authentication

Tutti gli endpoint (eccetto health/styles/presets) richiedono JWT Bearer token:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/v1/fusion/projects
```

## Endpoints Reference

### Health & Config (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/fusion/health` | Health check servizio |
| GET | `/api/v1/fusion/styles` | Stili arti marziali disponibili |
| GET | `/api/v1/fusion/presets` | Preset configurazione fusione |

### Projects CRUD (Auth Required)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/fusion/projects` | Lista progetti utente |
| POST | `/api/v1/fusion/projects` | Crea nuovo progetto |
| GET | `/api/v1/fusion/projects/{id}` | Dettaglio progetto |
| PUT | `/api/v1/fusion/projects/{id}` | Aggiorna progetto |
| DELETE | `/api/v1/fusion/projects/{id}` | Elimina progetto |

### Video Sources Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/fusion/projects/{id}/videos` | Lista video del progetto |
| POST | `/api/v1/fusion/projects/{id}/videos` | Aggiungi video sorgente |
| PUT | `/api/v1/fusion/projects/{id}/videos/{vid}` | Aggiorna parametri video |
| DELETE | `/api/v1/fusion/projects/{id}/videos/{vid}` | Rimuovi video |

### Fusion Processing

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/fusion/projects/{id}/process` | Avvia elaborazione fusione |
| GET | `/api/v1/fusion/projects/{id}/status` | Stato elaborazione |
| POST | `/api/v1/fusion/projects/{id}/cancel` | Cancella elaborazione |
| GET | `/api/v1/fusion/projects/{id}/result` | Scarica risultato fusione |
| GET | `/api/v1/fusion/projects/{id}/preview` | Dati preview 3D |

### WebSocket Real-time

```
WS /api/v1/fusion/ws/{project_id}
```

**Messaggi Ricevuti:**
```json
{
  "type": "progress",
  "progress": 45.5,
  "stage": "alignment",
  "phase": "dtw_processing",
  "message": "Allineamento DTW frame 450/1000",
  "processed_frames": 450,
  "total_frames": 1000,
  "estimated_seconds_remaining": 120
}
```

**Messaggi Inviabili:**
```json
{"type": "subscribe", "project_id": "xxx"}
{"type": "ping"}
```

## Request/Response Examples

### Create Project

```bash
curl -X POST http://localhost:8000/api/v1/fusion/projects \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Mae Geri Perfect Form",
       "description": "Fusione 5 esecuzioni calcio frontale",
       "style": "karate",
       "technique_name": "Mae Geri",
       "settings": {
         "alignment_method": "dtw",
         "outlier_detection": true,
         "quality": "high"
       }
     }'
```

**Response:**
```json
{
  "id": "proj_abc123",
  "name": "Mae Geri Perfect Form",
  "description": "Fusione 5 esecuzioni calcio frontale",
  "style": "karate",
  "technique_name": "Mae Geri",
  "status": "draft",
  "video_count": 0,
  "created_at": "2026-01-18T10:30:00Z",
  "updated_at": "2026-01-18T10:30:00Z",
  "owner_id": "user_xyz789"
}
```

### Add Video to Project

```bash
curl -X POST http://localhost:8000/api/v1/fusion/projects/proj_abc123/videos \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "video_id": "vid_def456",
       "label": "Execution Front View",
       "angle": "front",
       "weight": 1.0,
       "camera_params": {
         "angle_horizontal": 0,
         "angle_vertical": 15,
         "distance": 3.0,
         "fov": 60
       }
     }'
```

### Start Fusion Processing

```bash
curl -X POST http://localhost:8000/api/v1/fusion/projects/proj_abc123/process \
     -H "Authorization: Bearer TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "alignment_method": "dtw",
       "output_format": "json",
       "include_confidence": true,
       "export_blender": false
     }'
```

### Get Processing Status

```bash
curl http://localhost:8000/api/v1/fusion/projects/proj_abc123/status \
     -H "Authorization: Bearer TOKEN"
```

**Response:**
```json
{
  "status": "processing",
  "progress": 67.5,
  "current_phase": "averaging",
  "processed_frames": 675,
  "total_frames": 1000,
  "estimated_seconds_remaining": 45,
  "started_at": "2026-01-18T10:35:00Z"
}
```

### WebSocket Monitor (JavaScript)

```javascript
const projectId = 'proj_abc123';
const ws = new WebSocket(`ws://localhost:8000/api/v1/fusion/ws/${projectId}`);

ws.onopen = () => {
    console.log('Connected');
    ws.send(JSON.stringify({ type: 'subscribe', project_id: projectId }));
};

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    console.log(`Progress: ${data.progress}% - ${data.message}`);

    if (data.status === 'completed') {
        console.log('Fusion completed!');
        ws.close();
    }
};

ws.onerror = (error) => console.error('WebSocket error:', error);
ws.onclose = () => console.log('Disconnected');
```

## Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad request - invalid data or parameters |
| 401 | Unauthorized - missing or invalid JWT token |
| 403 | Forbidden - not project owner |
| 404 | Not found - project or video doesn't exist |
| 409 | Conflict - project already processing |
| 422 | Validation error - invalid field values |
| 429 | Rate limited - too many requests |
| 500 | Server error - internal failure |

## Rate Limits

- 100 requests/minute per user
- 10 concurrent fusion jobs per user
- Max 50 videos per project
- Max 10 projects in processing state

## Processing Stages

1. **validation** - Verifica video sorgenti
2. **extraction** - Estrazione skeleton 75 landmarks
3. **alignment** - Allineamento DTW temporale
4. **outlier** - Rilevamento outlier (se abilitato)
5. **averaging** - Media pesata frame
6. **export** - Generazione output finale

## Data Models

### FusionProject
```typescript
interface FusionProject {
  id: string;
  name: string;
  description?: string;
  style: MartialArtStyle;
  technique_name?: string;
  status: 'draft' | 'ready' | 'processing' | 'completed' | 'failed' | 'cancelled';
  video_count: number;
  settings: FusionSettings;
  result_url?: string;
  error_message?: string;
  created_at: string;
  updated_at: string;
  owner_id: string;
}
```

### FusionVideoSource
```typescript
interface FusionVideoSource {
  id: string;
  video_id: string;
  label: string;
  angle?: string;
  weight: number;
  camera_params: CameraParams;
  order_index: number;
  skeleton_status: 'pending' | 'extracted' | 'failed';
}
```

### CameraParams
```typescript
interface CameraParams {
  angle_horizontal: number;  // -180 to 180
  angle_vertical: number;    // -90 to 90
  distance: number;          // meters
  fov: number;               // degrees
}
```

## Related Files

| File | Description |
|------|-------------|
| `backend/api/v1/fusion.py` | API endpoints (~900 lines) |
| `backend/services/video_studio/multi_video_fusion.py` | Core fusion logic |
| `backend/services/video_studio/mix_generator.py` | Frame mixing |
| `frontend/src/app/fusion/` | React dashboard & wizard |
| `flutter_app/lib/features/fusion/` | Flutter mobile UI |
| `backend/scripts/test_websocket_fusion.py` | WebSocket tester |

## Changelog

- **v1.0.0** (2026-01-18): Initial release with full CRUD, processing, WebSocket

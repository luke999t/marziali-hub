# Fusion API

API endpoints for fusion functionality.

## Table of Contents

- [POST /api/v1/fusion/projects](#post--api-v1-fusion-projects) - Crea progetto fusione
- [GET /api/v1/fusion/projects](#get--api-v1-fusion-projects) - Lista progetti
- [GET /api/v1/fusion/projects/{project_id}](#get--api-v1-fusion-projects-project_id) - Dettaglio progetto
- [PUT /api/v1/fusion/projects/{project_id}](#put--api-v1-fusion-projects-project_id) - Aggiorna progetto
- [DELETE /api/v1/fusion/projects/{project_id}](#delete--api-v1-fusion-projects-project_id) - Elimina progetto
- [POST /api/v1/fusion/projects/{project_id}/videos](#post--api-v1-fusion-projects-project_id-videos) - Aggiungi video
- [GET /api/v1/fusion/projects/{project_id}/videos](#get--api-v1-fusion-projects-project_id-videos) - Lista video
- [PUT /api/v1/fusion/projects/{project_id}/videos/{video_id}](#put--api-v1-fusion-projects-project_id-videos-video_id) - Aggiorna video
- [DELETE /api/v1/fusion/projects/{project_id}/videos/{video_id}](#delete--api-v1-fusion-projects-project_id-videos-video_id) - Rimuovi video
- [POST /api/v1/fusion/projects/{project_id}/process](#post--api-v1-fusion-projects-project_id-process) - Avvia fusione
- [GET /api/v1/fusion/projects/{project_id}/status](#get--api-v1-fusion-projects-project_id-status) - Stato fusione
- [POST /api/v1/fusion/projects/{project_id}/cancel](#post--api-v1-fusion-projects-project_id-cancel) - Cancella fusione
- [GET /api/v1/fusion/projects/{project_id}/result](#get--api-v1-fusion-projects-project_id-result) - Download risultato
- [GET /api/v1/fusion/projects/{project_id}/preview](#get--api-v1-fusion-projects-project_id-preview) - Preview 3D data
- [GET /api/v1/fusion/styles](#get--api-v1-fusion-styles) - Stili disponibili
- [GET /api/v1/fusion/presets](#get--api-v1-fusion-presets) - Preset configurazione
- [GET /api/v1/fusion/health](#get--api-v1-fusion-health) - Health check

---

## POST /api/v1/fusion/projects

**Description**: Crea nuovo progetto per fusione multi-video

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Nome progetto |
| description | string | No | Descrizione |
| style | any | No | Stile arte marziale |
| technique_name | string | No | Nome tecnica |
| config | any | No | - |

**Request Example**:
```json
{
  "description": "Fusione 5 maestri karate",
  "name": "Gyaku-zuki perfetto",
  "style": "karate",
  "technique_name": "Gyaku-zuki"
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "style": "string",
  "technique_name": "string",
  "status": "string",
  "video_count": 1,
  "config": {},
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects

**Description**: Lista progetti fusione dell'utente

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 20) |
| offset | integer | No | - (default: 0) |
| status | string | No | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "name": "string",
    "description": "string",
    "style": "string",
    "technique_name": "string",
    "status": "string",
    "video_count": 1,
    "config": {},
    "created_at": "string",
    "updated_at": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects/{project_id}

**Description**: Dettaglio progetto con lista video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "style": "string",
  "technique_name": "string",
  "status": "string",
  "video_count": 1,
  "config": {},
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/fusion/projects/{project_id}

**Description**: Aggiorna proprietà progetto

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| style | any | No | - |
| technique_name | any | No | - |
| config | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "style": {},
  "technique_name": {},
  "config": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "description": "string",
  "style": "string",
  "technique_name": "string",
  "status": "string",
  "video_count": 1,
  "config": {},
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/fusion/projects/{project_id}

**Description**: Elimina progetto e tutti i dati associati

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/fusion/projects/{project_id}/videos

**Description**: Aggiungi video sorgente al progetto

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | ID video |
| label | string | No | Etichetta |
| camera_params | CameraParams | No | - |
| weight | number | No | - |

**Request Example**:
```json
{
  "video_id": "string",
  "label": "",
  "camera_params": {
    "angle_horizontal": 0,
    "angle_vertical": 0,
    "distance": 2.0
  },
  "weight": 1.0
}
```

**Response 201**:
Successful Response

```json
{
  "video_id": "string",
  "label": "",
  "camera_params": {
    "angle_horizontal": 0,
    "angle_vertical": 0,
    "distance": 2.0
  },
  "weight": 1.0,
  "skeleton_path": {},
  "added_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects/{project_id}/videos

**Description**: Lista video nel progetto

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

```json
{
  "project_id": "string",
  "videos": [
    {
      "video_id": "string",
      "label": "",
      "camera_params": "...",
      "weight": 1.0,
      "skeleton_path": {},
      "added_at": "string"
    }
  ],
  "count": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/fusion/projects/{project_id}/videos/{video_id}

**Description**: Aggiorna parametri video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |
| video_id | string | Yes | ID video |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| label | any | No | - |
| camera_params | any | No | - |
| weight | any | No | - |

**Request Example**:
```json
{
  "label": {},
  "camera_params": {},
  "weight": {}
}
```

**Response 200**:
Successful Response

```json
{
  "video_id": "string",
  "label": "",
  "camera_params": {
    "angle_horizontal": 0,
    "angle_vertical": 0,
    "distance": 2.0
  },
  "weight": 1.0,
  "skeleton_path": {},
  "added_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/fusion/projects/{project_id}/videos/{video_id}

**Description**: Rimuovi video dal progetto

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |
| video_id | string | Yes | ID video |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/fusion/projects/{project_id}/process

**Description**: Avvia processo di fusione multi-video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

```json
{
  "success": true,
  "project_id": "string",
  "message": "string",
  "status": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects/{project_id}/status

**Description**: Stato corrente del processo fusione

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

```json
{
  "project_id": "string",
  "status": "string",
  "progress": 0.0,
  "current_step": "",
  "steps_completed": 0,
  "total_steps": 5,
  "error": {},
  "started_at": {},
  "completed_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/fusion/projects/{project_id}/cancel

**Description**: Cancella processo fusione in corso

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

```json
{
  "success": true,
  "project_id": "string",
  "message": "string",
  "status": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects/{project_id}/result

**Description**: Download video avatar risultato

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/projects/{project_id}/preview

**Description**: Dati skeleton per preview 3D client-side

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | ID progetto |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/fusion/styles

**Description**: Lista stili rendering disponibili

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "name": "string",
    "description": "string",
    "thumbnail_url": {}
  }
]
```

---

## GET /api/v1/fusion/presets

**Description**: Preset configurazione pre-impostati

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "name": "string",
    "description": "string",
    "style": "string",
    "config": {
      "smoothing_window": 5,
      "outlier_threshold": 2.0,
      "exclude_outliers": true,
      "output_style": "wireframe",
      "output_resolution": [
        1280,
        720
      ],
      "output_fps": 30.0
    }
  }
]
```

---

## GET /api/v1/fusion/health

**Description**: Verifica stato servizio fusione

**Authentication**: None

**Response 200**:
Successful Response

---


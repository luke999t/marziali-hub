# Downloads API

API endpoints for downloads functionality.

## Table of Contents

- [POST /api/v1/downloads/request](#post--api-v1-downloads-request) - Richiedi nuovo download
- [GET /api/v1/downloads/url/{download_id}](#get--api-v1-downloads-url-download_id) - Ottieni URL download firmato
- [PATCH /api/v1/downloads/progress/{download_id}](#patch--api-v1-downloads-progress-download_id) - Aggiorna progresso download
- [GET /api/v1/downloads/list](#get--api-v1-downloads-list) - Lista download utente
- [DELETE /api/v1/downloads/{download_id}](#delete--api-v1-downloads-download_id) - Elimina download
- [POST /api/v1/downloads/refresh-drm/{download_id}](#post--api-v1-downloads-refresh-drm-download_id) - Rinnova token DRM
- [POST /api/v1/downloads/offline-view/{download_id}](#post--api-v1-downloads-offline-view-download_id) - Registra view offline
- [GET /api/v1/downloads/limits](#get--api-v1-downloads-limits) - Limiti download per tier
- [GET /api/v1/downloads/storage](#get--api-v1-downloads-storage) - Statistiche storage
- [POST /api/v1/downloads/admin/expire-check](#post--api-v1-downloads-admin-expire-check) - [Admin] Esegui check scadenza

---

## POST /api/v1/downloads/request

**Description**: Richiede un nuovo download per un video.

    **Limiti per tier:**
    - FREE: Nessun download (errore 403)
    - BASIC: Max 3 download, 720p
    - PREMIUM: Max 10 download, 1080p
    - VIP: Max 25 download, 4K

    **Errori possibili:**
    - 403: Tier non permette download / limite raggiunto
    - 507: Storage insufficiente

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | UUID del video da scaricare |
| device_id | string | Yes | ID univoco dispositivo |
| device_name | any | No | Nome dispositivo |
| quality | any | No | Qualita: 360p, 720p, 1080p, 4K |

**Request Example**:
```json
{
  "device_id": "iphone-15-abc123",
  "device_name": "iPhone 15 Pro",
  "quality": "1080p",
  "video_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response 200**:
Successful Response

```json
{
  "download_id": "string",
  "status": "string",
  "quality": {},
  "progress_percent": {},
  "file_size_bytes": {},
  "downloaded_bytes": {},
  "drm_expires_at": {},
  "offline_views_remaining": {},
  "is_playable": {},
  "needs_refresh": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/downloads/url/{download_id}

**Description**: Genera URL firmato per scaricare il file.
    URL valido per 24 ore.
    Supporta resume da ultimo byte scaricato.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| download_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/downloads/progress/{download_id}

**Description**: Aggiorna il progresso di un download in corso.
    Quando completed=true, genera token DRM.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| download_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| downloaded_bytes | integer | Yes | Bytes scaricati finora |
| completed | boolean | No | True se download completato |

**Request Example**:
```json
{
  "completed": false,
  "downloaded_bytes": 524288000
}
```

**Response 200**:
Successful Response

```json
{
  "download_id": "string",
  "status": "string",
  "quality": {},
  "progress_percent": {},
  "file_size_bytes": {},
  "downloaded_bytes": {},
  "drm_expires_at": {},
  "offline_views_remaining": {},
  "is_playable": {},
  "needs_refresh": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/downloads/list

**Description**: Ritorna lista di tutti i download dell'utente.
    Filtrabile per dispositivo e stato.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| device_id | string | No | Filtra per dispositivo |
| status | string | No | Filtra per stato |
| include_expired | boolean | No | Includi download scaduti (default: False) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/downloads/{download_id}

**Description**: Elimina un download e libera lo spazio.
    Il file locale sul dispositivo deve essere eliminato dal client.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| download_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/downloads/refresh-drm/{download_id}

**Description**: Rinnova il token DRM per un download completato.
    Richiede connessione online.
    Verifica che l'abbonamento sia ancora attivo.

    **Importante:** Se l'utente ha fatto downgrade a FREE,
    il download viene revocato.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| download_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/downloads/offline-view/{download_id}

**Description**: Registra una visualizzazione offline.
    Il client deve chiamare questo endpoint periodicamente
    durante la riproduzione offline.

    Decrementa le views rimanenti e segnala se serve refresh.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| download_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| drm_token | string | Yes | Token DRM per verifica |

**Request Example**:
```json
{
  "drm_token": "drm_abc123xyz..."
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/downloads/limits

**Description**: Ritorna i limiti di download per il tier dell'utente corrente.
    Utile per mostrare all'utente cosa puo fare e incentivare upgrade.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "tier": "string",
  "max_concurrent_downloads": 1,
  "max_stored_downloads": 1,
  "max_quality": {},
  "drm_validity_days": 1,
  "offline_views_per_download": 1,
  "max_storage_bytes": {}
}
```

---

## GET /api/v1/downloads/storage

**Description**: Ritorna statistiche sull'uso dello storage per download.
    Include spazio usato, limite, e percentuale.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "used_bytes": 1,
  "used_human": "string",
  "max_bytes": 1,
  "max_human": "string",
  "percentage": 1.0,
  "downloads_count": 1,
  "downloads_limit": 1
}
```

---

## POST /api/v1/downloads/admin/expire-check

**Description**: Esegue il job di check scadenza download.
    Normalmente eseguito da scheduler, disponibile per trigger manuale.
    Richiede permessi admin.

**Authentication**: Required

**Response 200**:
Successful Response

---


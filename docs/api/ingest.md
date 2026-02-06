# Ingest API

API endpoints for ingest functionality.

## Table of Contents

- [POST /api/v1/ingest/projects](#post--api-v1-ingest-projects) - Crea nuovo progetto
- [GET /api/v1/ingest/projects](#get--api-v1-ingest-projects) - Lista progetti
- [GET /api/v1/ingest/projects/{project_id}](#get--api-v1-ingest-projects-project_id) - Dettaglio progetto
- [PATCH /api/v1/ingest/projects/{project_id}](#patch--api-v1-ingest-projects-project_id) - Aggiorna progetto
- [DELETE /api/v1/ingest/projects/{project_id}](#delete--api-v1-ingest-projects-project_id) - Elimina progetto
- [POST /api/v1/ingest/projects/{project_id}/upload](#post--api-v1-ingest-projects-project_id-upload) - Upload files
- [GET /api/v1/ingest/projects/{project_id}/batches](#get--api-v1-ingest-projects-project_id-batches) - Lista batch
- [GET /api/v1/ingest/projects/{project_id}/batches/{batch_date}/status](#get--api-v1-ingest-projects-project_id-batches-batch_date-status) - Stato batch
- [GET /api/v1/ingest/projects/{project_id}/batches/{batch_date}/assets](#get--api-v1-ingest-projects-project_id-batches-batch_date-assets) - Lista asset batch
- [POST /api/v1/ingest/projects/{project_id}/mix](#post--api-v1-ingest-projects-project_id-mix) - Genera mix
- [GET /api/v1/ingest/projects/{project_id}/mix/versions](#get--api-v1-ingest-projects-project_id-mix-versions) - Lista versioni mix
- [GET /api/v1/ingest/projects/{project_id}/mix/current](#get--api-v1-ingest-projects-project_id-mix-current) - Mix corrente
- [DELETE /api/v1/ingest/projects/{project_id}/temp](#delete--api-v1-ingest-projects-project_id-temp) - Cancella temp
- [GET /api/v1/ingest/projects/{project_id}/health](#get--api-v1-ingest-projects-project_id-health) - Health check progetto
- [POST /api/v1/ingest/projects/{project_id}/export-blender](#post--api-v1-ingest-projects-project_id-export-blender) - Export skeleton per Blender
- [POST /api/v1/ingest/projects/{project_id}/import-avatar](#post--api-v1-ingest-projects-project_id-import-avatar) - Import video avatar da Blender
- [GET /api/v1/ingest/projects/{project_id}/avatars](#get--api-v1-ingest-projects-project_id-avatars) - Lista avatar progetto
- [GET /api/v1/ingest/projects/{project_id}/avatar/{avatar_id}/status](#get--api-v1-ingest-projects-project_id-avatar-avatar_id-status) - Stato avatar
- [POST /api/v1/ingest/dvd/analyze](#post--api-v1-ingest-dvd-analyze) - Analizza tracce DVD
- [POST /api/v1/ingest/dvd/extract](#post--api-v1-ingest-dvd-extract) - Estrai parallel corpus
- [GET /api/v1/ingest/dvd/pairs/{job_id}](#get--api-v1-ingest-dvd-pairs-job_id) - Recupera sentence pairs
- [POST /api/v1/ingest/dvd/import-to-vocab](#post--api-v1-ingest-dvd-import-to-vocab) - Importa in vocabolario
- [DELETE /api/v1/ingest/dvd/job/{job_id}](#delete--api-v1-ingest-dvd-job-job_id) - Cancella job DVD

---

## POST /api/v1/ingest/projects

**Description**: Crea progetto ingest con struttura cartelle automatica

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | Nome progetto univoco |
| description | any | No | Descrizione opzionale |
| target_languages | array[string] | No | Lingue target per traduzione |

**Request Example**:
```json
{
  "name": "string",
  "description": {},
  "target_languages": [
    "it",
    "en"
  ]
}
```

**Response 201**:
Successful Response

```json
{
  "id": {},
  "name": "string",
  "description": {},
  "target_languages": [
    "string"
  ],
  "storage_path": "string",
  "created_by": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "is_active": true,
  "current_mix_version": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects

**Description**: Lista progetti con paginazione e filtri

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | Offset (default: 0) |
| limit | integer | No | Limit (default: 20) |
| search | string | No | Cerca per nome |
| active_only | boolean | No | Solo progetti attivi (default: True) |

**Response 200**:
Successful Response

```json
{
  "projects": [
    {
      "id": {},
      "name": "string",
      "description": {},
      "target_languages": [
        "..."
      ],
      "storage_path": "string",
      "created_by": {},
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z",
      "is_active": true,
      "current_mix_version": {}
    }
  ],
  "total": 1,
  "skip": 0,
  "limit": 20
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}

**Description**: Ottiene dettagli progetto con batch e mix

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": {},
  "name": "string",
  "description": {},
  "target_languages": [
    "string"
  ],
  "storage_path": "string",
  "created_by": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "is_active": true,
  "current_mix_version": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/ingest/projects/{project_id}

**Description**: Aggiorna metadati progetto.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| target_languages | any | No | - |
| is_active | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "target_languages": {},
  "is_active": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": {},
  "name": "string",
  "description": {},
  "target_languages": [
    "string"
  ],
  "storage_path": "string",
  "created_by": {},
  "created_at": "2024-01-15T10:30:00Z",
  "updated_at": "2024-01-15T10:30:00Z",
  "is_active": true,
  "current_mix_version": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/ingest/projects/{project_id}

**Description**: Elimina progetto (richiede admin)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| delete_files | boolean | No | Elimina anche i file (default: False) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/projects/{project_id}/upload

**Description**: Upload multiplo di file con processing automatico

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| files | array[string] | Yes | File da caricare |
| preset | any | No | Preset processing |
| extract_skeleton | boolean | No | Estrai skeleton |
| target_languages | string | No | Lingue target |
| confidence_threshold | number | No | Soglia confidenza |
| use_martial_dictionary | boolean | No | Usa dizionario marziale |

**Request Example**:
```json
{
  "files": [
    "string"
  ],
  "preset": "standard",
  "extract_skeleton": true,
  "target_languages": "it,en",
  "confidence_threshold": 0.65,
  "use_martial_dictionary": true
}
```

**Response 200**:
Successful Response

```json
{
  "batch_id": {},
  "batch_date": "string",
  "items_uploaded": 1,
  "items_duplicated": 0,
  "total_size_bytes": 1,
  "status_url": "string",
  "message": "Upload completato"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/batches

**Description**: Lista batch del progetto

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| status | string | No | Filtra per status |

**Response 200**:
Successful Response

```json
{
  "batches": [
    {
      "id": {},
      "batch_date": "string",
      "status": "...",
      "video_count": 0,
      "audio_count": 0,
      "image_count": 0,
      "pdf_count": 0,
      "text_count": 0,
      "ai_paste_count": 0,
      "external_count": 0
    }
  ],
  "total": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/batches/{batch_date}/status

**Description**: Stato processing in tempo reale

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |
| batch_date | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "batch_date": "string",
  "status": "pending",
  "progress_percentage": 1,
  "current_step": {},
  "items_processed": 0,
  "items_total": 0,
  "items_failed": 0,
  "error_message": {},
  "estimated_remaining_seconds": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/batches/{batch_date}/assets

**Description**: Lista asset di un batch specifico.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |
| batch_date | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asset_type | string | No | Filtra per tipo |

**Response 200**:
Successful Response

```json
{
  "assets": [
    {
      "id": {},
      "filename": "string",
      "asset_type": "...",
      "input_channel": {},
      "file_size": 1,
      "mime_type": {},
      "status": "string",
      "error_message": {},
      "processing_results": {},
      "duration_seconds": {}
    }
  ],
  "total": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/projects/{project_id}/mix

**Description**: Genera nuova versione mix da batch processati

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
*No parameters*

**Request Example**:
```json
{
  "force_full": false
}
```

**Response 200**:
Successful Response

```json
{
  "id": {},
  "version": "string",
  "storage_path": "string",
  "is_incremental": true,
  "previous_version": {},
  "total_items": 0,
  "total_skeletons": 0,
  "total_transcriptions": 0,
  "total_knowledge_chunks": 0,
  "total_subtitles": 0
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/mix/versions

**Description**: Lista tutte le versioni mix del progetto.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "versions": [
    {
      "id": {},
      "version": "string",
      "storage_path": "string",
      "is_incremental": true,
      "previous_version": {},
      "total_items": 0,
      "total_skeletons": 0,
      "total_transcriptions": 0,
      "total_knowledge_chunks": 0,
      "total_subtitles": 0
    }
  ],
  "current_version": {},
  "total": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/mix/current

**Description**: Dettagli mix corrente con lista file

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "version": "string",
  "storage_path": "string",
  "skeleton_count": 0,
  "transcription_count": 0,
  "knowledge_count": 0,
  "subtitle_count": 0,
  "vocabulary_count": 0,
  "stats": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/ingest/projects/{project_id}/temp

**Description**: Cancella cartella temp (richiede admin)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| confirm | boolean | Yes | Conferma cancellazione (deve essere true) |
| batch_dates | any | No | Batch specifici (null = tutti) |

**Request Example**:
```json
{
  "confirm": true,
  "batch_dates": {}
}
```

**Response 200**:
Successful Response

```json
{
  "batches_deleted": 1,
  "items_deleted": 1,
  "bytes_freed": 1,
  "message": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/health

**Description**: Health check e statistiche progetto.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "project_id": {},
  "project_name": "string",
  "storage_exists": true,
  "storage_size_bytes": 1,
  "batches_pending": 1,
  "batches_processing": 1,
  "batches_processed": 1,
  "batches_failed": 1,
  "current_mix": {},
  "last_activity": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/projects/{project_id}/export-blender

**Description**: Genera pacchetto JSON + script Python per import in Blender

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| asset_id | string | Yes | ID asset skeleton (UUID) |
| include_script | boolean | No | Include Python script per import Blender |
| rig_type | string | No | Tipo rig: mixamo, rigify, custom |
| fps | integer | No | FPS target per animazione |

**Request Example**:
```json
{
  "asset_id": "string",
  "include_script": true,
  "rig_type": "mixamo",
  "fps": 30
}
```

**Response 200**:
Successful Response

```json
{
  "export_id": "string",
  "json_path": "string",
  "script_path": {},
  "total_frames": 1,
  "duration_seconds": 1.0,
  "bone_count": 1,
  "download_url": "string",
  "message": "Export pronto per Blender"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/projects/{project_id}/import-avatar

**Description**: Importa video renderizzato da Blender nel sistema

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video | string | Yes | Video MP4 da Blender |
| export_id | any | No | ID export originale |
| render_angles | integer | No | Angoli camera |

**Request Example**:
```json
{
  "video": "string",
  "export_id": {},
  "render_angles": 8
}
```

**Response 200**:
Successful Response

```json
{
  "avatar_id": "string",
  "project_id": "string",
  "status": "string",
  "duration_seconds": 1.0,
  "width": 1,
  "height": 1,
  "fps": 1.0,
  "render_angles": 1,
  "is_360": true,
  "thumbnail_url": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/avatars

**Description**: Lista tutti gli avatar di un progetto.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
{
  "avatars": [
    {
      "avatar_id": "string",
      "project_id": "string",
      "status": "string",
      "duration_seconds": 1.0,
      "width": 1,
      "height": 1,
      "fps": 1.0,
      "render_angles": 1,
      "is_360": true,
      "thumbnail_url": "string"
    }
  ],
  "total": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/projects/{project_id}/avatar/{avatar_id}/status

**Description**: Verifica stato di un avatar specifico.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |
| avatar_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "avatar_id": "string",
  "status": "string",
  "video_exists": true,
  "thumbnail_exists": true,
  "is_360": true,
  "duration_seconds": 1.0,
  "render_angles": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/dvd/analyze

**Description**: Rileva audio e sottotitoli disponibili

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video | string | Yes | Video DVD (MKV/MP4) |

**Request Example**:
```json
{
  "video": "string"
}
```

**Response 200**:
Successful Response

```json
{
  "job_id": "string",
  "audio_tracks": [
    {}
  ],
  "subtitle_tracks": [
    {}
  ],
  "video_duration_seconds": 1.0,
  "detected_languages": [
    "string"
  ]
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/dvd/extract

**Description**: Estrae e allinea coppie di sottotitoli

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| job_id | string | Yes | ID dal precedente analyze |
| source_language | string | Yes | Lingua sorgente (es: 'en', 'ja') |
| target_language | string | Yes | Lingua target (es: 'it') |
| subtitle_track_source | integer | No | Indice traccia sottotitoli sorgente |
| subtitle_track_target | integer | No | Indice traccia sottotitoli target |
| min_confidence | number | No | Confidenza minima per pair |

**Request Example**:
```json
{
  "job_id": "string",
  "source_language": "string",
  "target_language": "string",
  "subtitle_track_source": 0,
  "subtitle_track_target": 1,
  "min_confidence": 0.7
}
```

**Response 200**:
Successful Response

```json
{
  "job_id": "string",
  "status": "string",
  "pairs_extracted": 1,
  "pairs_high_confidence": 1,
  "average_confidence": 1.0,
  "processing_time_seconds": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ingest/dvd/pairs/{job_id}

**Description**: Ottiene le coppie tradotte estratte

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| min_confidence | number | No | - (default: 0.0) |
| limit | integer | No | - (default: 1000) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
{
  "job_id": "string",
  "source_language": "string",
  "target_language": "string",
  "pairs": [
    {
      "source": "string",
      "target": "string",
      "confidence": 1.0
    }
  ],
  "total_pairs": 1,
  "average_confidence": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ingest/dvd/import-to-vocab

**Description**: Importa pairs nel translation memory

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| job_id | string | Yes | ID job con pairs estratte |
| category | string | No | Categoria vocabolario |
| min_confidence | number | No | Confidenza minima per import |
| use_llm_validation | boolean | No | Valida con multi-LLM debate |

**Request Example**:
```json
{
  "job_id": "string",
  "category": "martial_arts",
  "min_confidence": 0.8,
  "use_llm_validation": true
}
```

**Response 200**:
Successful Response

```json
{
  "terms_imported": 1,
  "terms_rejected": 1,
  "terms_already_exist": 1,
  "validation_results": {},
  "message": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/ingest/dvd/job/{job_id}

**Description**: Cancella job e file temporanei

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


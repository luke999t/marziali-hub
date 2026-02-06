# Export API

API endpoints for export functionality.

## Table of Contents

- [GET /api/v1/export/formats](#get--api-v1-export-formats) - List export formats
- [POST /api/v1/export/blender](#post--api-v1-export-blender) - Create Blender export
- [POST /api/v1/export/bvh](#post--api-v1-export-bvh) - Create BVH export
- [POST /api/v1/export/fbx](#post--api-v1-export-fbx) - Create FBX export
- [POST /api/v1/export/bulk](#post--api-v1-export-bulk) - Bulk export
- [GET /api/v1/export/list](#get--api-v1-export-list) - List user exports
- [GET /api/v1/export/status/{export_id}](#get--api-v1-export-status-export_id) - Get export status
- [GET /api/v1/export/download/{export_id}](#get--api-v1-export-download-export_id) - Download export
- [DELETE /api/v1/export/{export_id}](#delete--api-v1-export-export_id) - Delete export
- [GET /api/v1/export/health](#get--api-v1-export-health) - Export API health check

---

## GET /api/v1/export/formats

**Description**: Lista formati di export supportati

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/export/blender

**Description**: Crea export skeleton per Blender.

    🎓 OUTPUT:
    - skeleton_blender.json: Dati skeleton con mapping Mixamo
    - metadata.json: Info export (fps, duration, quality)
    - import_blender.py: Script Python per import in Blender

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | any | No | Video ID to export skeleton from |
| skeleton_id | any | No | Direct skeleton ID if already extracted |
| format | any | No | Export format |
| options | any | No | - |
| project_name | string | No | Project name for export |

**Request Example**:
```json
{
  "format": "json",
  "options": {
    "fps": 30,
    "include_visibility": true,
    "scale": 1.0
  },
  "project_name": "Kata Heian Shodan",
  "video_id": "abc123-def456"
}
```

**Response 202**:
Successful Response

```json
{
  "success": true,
  "export_id": "",
  "video_id": "",
  "format": "",
  "status": "pending",
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/export/bvh

**Description**: Crea export BVH (BioVision Hierarchy) per motion capture software

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | any | No | Video ID to export skeleton from |
| skeleton_id | any | No | Direct skeleton ID if already extracted |
| format | any | No | Export format |
| options | any | No | - |
| project_name | string | No | Project name for export |

**Request Example**:
```json
{
  "format": "json",
  "options": {
    "fps": 30,
    "include_visibility": true,
    "scale": 1.0
  },
  "project_name": "Kata Heian Shodan",
  "video_id": "abc123-def456"
}
```

**Response 202**:
Successful Response

```json
{
  "success": true,
  "export_id": "",
  "video_id": "",
  "format": "",
  "status": "pending",
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/export/fbx

**Description**: Crea export FBX per Unity/Unreal Engine

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | any | No | Video ID to export skeleton from |
| skeleton_id | any | No | Direct skeleton ID if already extracted |
| format | any | No | Export format |
| options | any | No | - |
| project_name | string | No | Project name for export |

**Request Example**:
```json
{
  "format": "json",
  "options": {
    "fps": 30,
    "include_visibility": true,
    "scale": 1.0
  },
  "project_name": "Kata Heian Shodan",
  "video_id": "abc123-def456"
}
```

**Response 202**:
Successful Response

```json
{
  "success": true,
  "export_id": "",
  "video_id": "",
  "format": "",
  "status": "pending",
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/export/bulk

**Description**: Export multipli video in un'unica richiesta

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_ids | array[string] | Yes | - |
| format | any | No | - |
| options | any | No | - |

**Request Example**:
```json
{
  "video_ids": [
    "string"
  ],
  "format": "json",
  "options": {}
}
```

**Response 202**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/export/list

**Description**: Lista tutti gli export dell'utente

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 20) |
| offset | integer | No | - (default: 0) |
| status | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/export/status/{export_id}

**Description**: Stato di un job di export

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| export_id | string | Yes | Export job ID |

**Response 200**:
Successful Response

```json
{
  "export_id": "string",
  "video_id": "string",
  "format": "string",
  "status": "string",
  "progress": 0.0,
  "created_at": "",
  "completed_at": {},
  "download_url": {},
  "file_size": {},
  "error": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/export/download/{export_id}

**Description**: Download file export

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| export_id | string | Yes | Export job ID |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/export/{export_id}

**Description**: Elimina un export e i suoi file

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| export_id | string | Yes | Export job ID |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/export/health

**Description**: Check Export API health.

**Authentication**: None

**Response 200**:
Successful Response

---


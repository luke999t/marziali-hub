# Skeleton API

API endpoints for skeleton functionality.

## Table of Contents

- [POST /api/v1/skeleton/extract](#post--api-v1-skeleton-extract) - Start skeleton extraction
- [GET /api/v1/skeleton/status/{job_id}](#get--api-v1-skeleton-status-job_id) - Get extraction job status
- [GET /api/v1/skeleton/videos/{video_id}](#get--api-v1-skeleton-videos-video_id) - Get skeleton data
- [GET /api/v1/skeleton/videos/{video_id}/metadata](#get--api-v1-skeleton-videos-video_id-metadata) - Get skeleton metadata
- [GET /api/v1/skeleton/videos/{video_id}/frame/{frame_number}](#get--api-v1-skeleton-videos-video_id-frame-frame_number) - Get single frame
- [GET /api/v1/skeleton/videos/{video_id}/frames](#get--api-v1-skeleton-videos-video_id-frames) - Get frame range
- [POST /api/v1/skeleton/batch](#post--api-v1-skeleton-batch) - Batch skeleton extraction
- [GET /api/v1/skeleton/health](#get--api-v1-skeleton-health) - Skeleton API health check
- [GET /api/v1/skeleton/download/{video_id}](#get--api-v1-skeleton-download-video_id) - Download skeleton JSON

---

## POST /api/v1/skeleton/extract

**Description**: Avvia estrazione skeleton da video.

    **Holistic (default)**: 75 landmarks (33 body + 21 left hand + 21 right hand)
    **Pose**: 33 landmarks (body only) - backward compatible

    🎓 AI_MODULE: skeleton_extraction
    🎓 AI_BUSINESS: Feature premium per analisi tecnica dettagliata

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | Video ID to extract skeleton from |
| use_holistic | boolean | No | Use Holistic (75) vs Pose (33) |
| model_complexity | integer | No | Model complexity 0-2 |
| min_detection_confidence | number | No | - |
| min_tracking_confidence | number | No | - |

**Request Example**:
```json
{
  "min_detection_confidence": 0.5,
  "min_tracking_confidence": 0.5,
  "model_complexity": 1,
  "use_holistic": true,
  "video_id": "abc123-def456"
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "job_id": "",
  "video_id": "",
  "message": "",
  "status": "queued"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/status/{job_id}

**Description**: Check progress of skeleton extraction job

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | Job ID from /extract response |

**Response 200**:
Successful Response

```json
{
  "job_id": "string",
  "video_id": "string",
  "status": "string",
  "progress": 0.0,
  "frames_processed": 0,
  "total_frames": 0,
  "error": {},
  "created_at": "",
  "updated_at": "",
  "result_path": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/videos/{video_id}

**Description**: Recupera skeleton completo per un video.

    🎓 RESPONSE: JSON con 75 landmarks per frame (se Holistic)
    o 33 landmarks (se Pose legacy).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | Video ID |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/videos/{video_id}/metadata

**Description**: Solo metadata senza frame data (per preview)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | Video ID |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/videos/{video_id}/frame/{frame_number}

**Description**: Recupera singolo frame con 75 landmarks.

    🎓 USE CASE: Debug, preview, real-time overlay sync

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | Video ID |
| frame_number | integer | Yes | Frame index |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/videos/{video_id}/frames

**Description**: Recupera range di frame con paginazione

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | Video ID |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| start | integer | No | Start frame index (default: 0) |
| end | integer | No | End frame index (exclusive) |
| limit | integer | No | Max frames to return (default: 100) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/skeleton/batch

**Description**: Avvia estrazione skeleton per multipli video

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_ids | array[string] | Yes | - |
| use_holistic | boolean | No | - |
| model_complexity | integer | No | - |

**Request Example**:
```json
{
  "video_ids": [
    "string"
  ],
  "use_holistic": true,
  "model_complexity": 1
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "jobs": [
    {}
  ],
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/skeleton/health

**Description**: Check Skeleton API health.

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/skeleton/download/{video_id}

**Description**: Download skeleton data as JSON file

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | Video ID |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| format | string | No | Format: holistic or pose (default: holistic) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


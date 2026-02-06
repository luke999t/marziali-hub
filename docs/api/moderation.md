# Moderation API

API endpoints for moderation functionality.

## Table of Contents

- [GET /api/v1/moderation/videos/pending](#get--api-v1-moderation-videos-pending) - Lista video in moderazione
- [POST /api/v1/moderation/videos/{video_id}/approve](#post--api-v1-moderation-videos-video_id-approve) - Approva video
- [POST /api/v1/moderation/videos/{video_id}/reject](#post--api-v1-moderation-videos-video_id-reject) - Rifiuta video
- [POST /api/v1/moderation/videos/{video_id}/request-changes](#post--api-v1-moderation-videos-video_id-request-changes) - Richiedi modifiche
- [GET /api/v1/moderation/videos/{video_id}/history](#get--api-v1-moderation-videos-video_id-history) - Storico moderazione video
- [GET /api/v1/moderation/stats](#get--api-v1-moderation-stats) - Statistiche moderazione

---

## GET /api/v1/moderation/videos/pending

**Description**: Ottieni tutti i video in stato PENDING che richiedono moderazione

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "description": {},
    "category": "string",
    "difficulty": "string",
    "tags": [
      "string"
    ],
    "video_url": "string",
    "thumbnail_url": {},
    "duration": 1,
    "tier_required": "string"
  }
]
```

---

## POST /api/v1/moderation/videos/{video_id}/approve

**Description**: Approva video e pubblica sulla piattaforma

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| notes | any | No | - |

**Request Example**:
```json
{
  "notes": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/moderation/videos/{video_id}/reject

**Description**: Rifiuta video con motivazione

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| rejection_reason | string | Yes | - |

**Request Example**:
```json
{
  "rejection_reason": "string"
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/moderation/videos/{video_id}/request-changes

**Description**: Richiedi modifiche al maestro

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| required_changes | array[string] | Yes | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "required_changes": [
    "string"
  ],
  "notes": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/moderation/videos/{video_id}/history

**Description**: Ottieni storico completo moderazioni per un video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "action": "string",
    "moderator": {},
    "previous_status": "string",
    "new_status": "string",
    "moderation_notes": {},
    "rejection_reason": {},
    "required_changes": {},
    "metadata_validation": {},
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/moderation/stats

**Description**: Statistiche aggregate moderazione video

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "pending_count": 1,
  "approved_today": 1,
  "rejected_today": 1,
  "avg_review_time_minutes": 1.0,
  "by_moderator": [
    {}
  ]
}
```

---


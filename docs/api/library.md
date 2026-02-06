# Library API

API endpoints for library functionality.

## Table of Contents

- [GET /api/v1/library/saved](#get--api-v1-library-saved) - Get Saved Videos
- [GET /api/v1/library/saved](#get--api-v1-library-saved) - Get Saved Videos
- [GET /api/v1/library/in-progress](#get--api-v1-library-in-progress) - Get In Progress Videos
- [GET /api/v1/library/in-progress](#get--api-v1-library-in-progress) - Get In Progress Videos
- [GET /api/v1/library/completed](#get--api-v1-library-completed) - Get Completed Videos
- [GET /api/v1/library/completed](#get--api-v1-library-completed) - Get Completed Videos
- [GET /api/v1/library/downloaded](#get--api-v1-library-downloaded) - Get Downloaded Videos
- [GET /api/v1/library/downloaded](#get--api-v1-library-downloaded) - Get Downloaded Videos
- [POST /api/v1/library/save/{video_id}](#post--api-v1-library-save-video_id) - Save Video
- [POST /api/v1/library/save/{video_id}](#post--api-v1-library-save-video_id) - Save Video
- [DELETE /api/v1/library/save/{video_id}](#delete--api-v1-library-save-video_id) - Unsave Video
- [DELETE /api/v1/library/save/{video_id}](#delete--api-v1-library-save-video_id) - Unsave Video
- [POST /api/v1/library/progress/{video_id}](#post--api-v1-library-progress-video_id) - Update Progress
- [POST /api/v1/library/progress/{video_id}](#post--api-v1-library-progress-video_id) - Update Progress
- [POST /api/v1/library/download/{video_id}](#post--api-v1-library-download-video_id) - Download Video
- [POST /api/v1/library/download/{video_id}](#post--api-v1-library-download-video_id) - Download Video
- [DELETE /api/v1/library/download/{video_id}](#delete--api-v1-library-download-video_id) - Remove Download
- [DELETE /api/v1/library/download/{video_id}](#delete--api-v1-library-download-video_id) - Remove Download

---

## GET /api/v1/library/saved

**Description**: Get all videos saved by the current user.
Returns videos ordered by saved_at date (most recent first).

🎓 AI_TEACHING: Usa select() con and_() per SQLAlchemy 2.x async.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/saved

**Description**: Get all videos saved by the current user.
Returns videos ordered by saved_at date (most recent first).

🎓 AI_TEACHING: Usa select() con and_() per SQLAlchemy 2.x async.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/in-progress

**Description**: Get videos currently being watched (progress > 0 and < 100).
Returns videos ordered by last_watched date (most recent first).

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/in-progress

**Description**: Get videos currently being watched (progress > 0 and < 100).
Returns videos ordered by last_watched date (most recent first).

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/completed

**Description**: Get all videos completed by the user (progress = 100).
Returns videos ordered by completed_at date (most recent first).

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/completed

**Description**: Get all videos completed by the user (progress = 100).
Returns videos ordered by completed_at date (most recent first).

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/downloaded

**Description**: Get all videos downloaded for offline viewing.
Premium feature - returns empty list for free users.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## GET /api/v1/library/downloaded

**Description**: Get all videos downloaded for offline viewing.
Premium feature - returns empty list for free users.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": 1,
    "title": "string",
    "thumbnail_url": {},
    "duration": 1,
    "progress": 1,
    "style": "string",
    "level": "string",
    "maestro_name": "string",
    "saved_at": {},
    "completed_at": {}
  }
]
```

---

## POST /api/v1/library/save/{video_id}

**Description**: Save a video to user's library.
Creates UserVideo record if not exists, or updates is_saved flag.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/library/save/{video_id}

**Description**: Save a video to user's library.
Creates UserVideo record if not exists, or updates is_saved flag.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/library/save/{video_id}

**Description**: Remove a video from user's saved list.
Does not delete progress data.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/library/save/{video_id}

**Description**: Remove a video from user's saved list.
Does not delete progress data.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/library/progress/{video_id}

**Description**: Update video watching progress.
Progress is percentage 0-100.
Marks as completed when progress reaches 100.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| progress | integer | Yes | - |

**Request Example**:
```json
{
  "progress": 1
}
```

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/library/progress/{video_id}

**Description**: Update video watching progress.
Progress is percentage 0-100.
Marks as completed when progress reaches 100.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| progress | integer | Yes | - |

**Request Example**:
```json
{
  "progress": 1
}
```

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/library/download/{video_id}

**Description**: Mark video as downloaded for offline viewing.
Premium feature only.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/library/download/{video_id}

**Description**: Mark video as downloaded for offline viewing.
Premium feature only.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/library/download/{video_id}

**Description**: Remove video from downloads.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/library/download/{video_id}

**Description**: Remove video from downloads.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | integer | Yes | - |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---


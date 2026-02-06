# Videos API

API endpoints for videos functionality.

## Table of Contents

- [GET /api/v1/videos](#get--api-v1-videos) - List videos
- [POST /api/v1/videos](#post--api-v1-videos) - Create video
- [GET /api/v1/videos/search](#get--api-v1-videos-search) - Search videos
- [GET /api/v1/videos/trending](#get--api-v1-videos-trending) - Get trending videos
- [GET /api/v1/videos/home](#get--api-v1-videos-home) - Get home feed
- [GET /api/v1/videos/continue-watching](#get--api-v1-videos-continue-watching) - Get continue watching
- [GET /api/v1/videos/skeletons](#get--api-v1-videos-skeletons) - List extracted skeletons
- [GET /api/v1/videos/skeleton/{asset_id}](#get--api-v1-videos-skeleton-asset_id) - Get skeleton data by asset ID
- [GET /api/v1/videos/favorites](#get--api-v1-videos-favorites) - Get My List
- [GET /api/v1/videos/{video_id}](#get--api-v1-videos-video_id) - Get video details
- [PUT /api/v1/videos/{video_id}](#put--api-v1-videos-video_id) - Update video
- [DELETE /api/v1/videos/{video_id}](#delete--api-v1-videos-video_id) - Delete video
- [GET /api/v1/videos/{video_id}/streaming](#get--api-v1-videos-video_id-streaming) - Get streaming URL (alias)
- [GET /api/v1/videos/{video_id}/stream](#get--api-v1-videos-video_id-stream) - Get streaming URL
- [POST /api/v1/videos/{video_id}/favorite](#post--api-v1-videos-video_id-favorite) - Add to My List
- [DELETE /api/v1/videos/{video_id}/favorite](#delete--api-v1-videos-video_id-favorite) - Remove from My List
- [POST /api/v1/videos/{video_id}/progress](#post--api-v1-videos-video_id-progress) - Update viewing progress
- [POST /api/v1/videos/ingest](#post--api-v1-videos-ingest) - Ingest file upload
- [GET /api/v1/videos/ingest/status/{asset_id}](#get--api-v1-videos-ingest-status-asset_id) - Get ingest status

---

## GET /api/v1/videos

**Description**: Get paginated list of videos with filters

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | Number of items to skip (default: 0) |
| limit | integer | No | Number of items to return (default: 20) |
| category | string | No | Filter by category |
| difficulty | string | No | Filter by difficulty |
| tier | string | No | Filter by tier |
| search | string | No | Search in title/description |
| sort_by | string | No | Sort field (default: created_at) |
| sort_order | string | No | - (default: desc) |

**Response 200**:
Successful Response

```json
{
  "videos": [
    {
      "id": "string",
      "title": "string",
      "description": {},
      "slug": "string",
      "category": "string",
      "difficulty": "string",
      "style": {},
      "tags": [],
      "thumbnail_url": {},
      "video_url": "string"
    }
  ],
  "total": 1,
  "skip": 1,
  "limit": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/videos

**Description**: Upload new video (admin only)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| description | any | No | - |
| category | VideoCategory | Yes | - |
| difficulty | Difficulty | Yes | - |
| style | any | No | - |
| tags | array[string] | No | - |
| tier_required | string | No | - |
| is_premium | boolean | No | - |
| ppv_price | any | No | Pay-per-view price in EUR |
| instructor_name | any | No | - |

**Request Example**:
```json
{
  "title": "string",
  "description": {},
  "category": "technique",
  "difficulty": "beginner",
  "style": {},
  "tags": [
    "string"
  ],
  "tier_required": "free",
  "is_premium": false,
  "ppv_price": {},
  "instructor_name": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "title": "string",
  "description": {},
  "slug": "string",
  "category": "string",
  "difficulty": "string",
  "style": {},
  "tags": [],
  "thumbnail_url": {},
  "video_url": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/search

**Description**: Search videos by query string

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| q | string | Yes | Search query |
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |

**Response 200**:
Successful Response

```json
{
  "videos": [
    {
      "id": "string",
      "title": "string",
      "description": {},
      "slug": "string",
      "category": "string",
      "difficulty": "string",
      "style": {},
      "tags": [],
      "thumbnail_url": {},
      "video_url": "string"
    }
  ],
  "total": 1,
  "skip": 1,
  "limit": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/trending

**Description**: Get most viewed videos from the last 7 days

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | Number of videos to return (default: 10) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "description": {},
    "slug": "string",
    "category": "string",
    "difficulty": "string",
    "style": {},
    "tags": [],
    "thumbnail_url": {},
    "video_url": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/home

**Description**: Get featured video and categorized content rows for home screen

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/videos/continue-watching

**Description**: Get videos user has started but not finished

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 10) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "description": {},
    "slug": "string",
    "category": "string",
    "difficulty": "string",
    "style": {},
    "tags": [],
    "thumbnail_url": {},
    "video_url": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/skeletons

**Description**: Get list of all extracted skeleton files

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/videos/skeleton/{asset_id}

**Description**: Get skeleton JSON data for a specific asset

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asset_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/favorites

**Description**: Get user's favorite videos

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |

**Response 200**:
Successful Response

```json
{
  "videos": [
    {
      "id": "string",
      "title": "string",
      "description": {},
      "slug": "string",
      "category": "string",
      "difficulty": "string",
      "style": {},
      "tags": [],
      "thumbnail_url": {},
      "video_url": "string"
    }
  ],
  "total": 1,
  "skip": 1,
  "limit": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/{video_id}

**Description**: Get detailed information about a specific video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "title": "string",
  "description": {},
  "slug": "string",
  "category": "string",
  "difficulty": "string",
  "style": {},
  "tags": [],
  "thumbnail_url": {},
  "video_url": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/videos/{video_id}

**Description**: Update video metadata (admin only)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | any | No | - |
| description | any | No | - |
| category | any | No | - |
| difficulty | any | No | - |
| tags | any | No | - |
| tier_required | any | No | - |
| is_premium | any | No | - |
| ppv_price | any | No | - |

**Request Example**:
```json
{
  "title": {},
  "description": {},
  "category": {},
  "difficulty": {},
  "tags": {},
  "tier_required": {},
  "is_premium": {},
  "ppv_price": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "title": "string",
  "description": {},
  "slug": "string",
  "category": "string",
  "difficulty": "string",
  "style": {},
  "tags": [],
  "thumbnail_url": {},
  "video_url": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/videos/{video_id}

**Description**: Delete video (admin only)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

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

## GET /api/v1/videos/{video_id}/streaming

**Description**: Get HLS streaming URL with temporary token

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| quality | string | No | Preferred quality (360p, 720p, 1080p, 4k) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/{video_id}/stream

**Description**: Get HLS streaming URL with temporary token

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| quality | string | No | Preferred quality (360p, 720p, 1080p, 4k) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/videos/{video_id}/favorite

**Description**: Add video to user's favorites

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

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

## DELETE /api/v1/videos/{video_id}/favorite

**Description**: Remove video from favorites

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

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

## POST /api/v1/videos/{video_id}/progress

**Description**: Update user's viewing progress for video

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| position_seconds | integer | Yes | Current playback position in seconds |
| quality | any | No | Current quality setting |

**Request Example**:
```json
{
  "position_seconds": 1,
  "quality": {}
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

## POST /api/v1/videos/ingest

**Description**: Upload files for processing with optional skeleton extraction

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asset_type | string | No | - (default: video) |
| title | string | No | - (default: ) |
| author | string | No | - (default: ) |
| language | string | No | - (default: auto) |
| preset | string | No | - (default: standard) |
| extract_skeleton | boolean | No | - (default: True) |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| files | array[string] | Yes | - |

**Request Example**:
```json
{
  "files": [
    "string"
  ]
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/videos/ingest/status/{asset_id}

**Description**: Get status of an ingest job

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asset_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


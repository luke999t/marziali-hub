# Live API

API endpoints for live functionality.

## Table of Contents

- [POST /api/v1/live/events](#post--api-v1-live-events) - Create Live Event
- [GET /api/v1/live/events](#get--api-v1-live-events) - List Live Events
- [GET /api/v1/live/events/{event_id}](#get--api-v1-live-events-event_id) - Get Live Event
- [DELETE /api/v1/live/events/{event_id}](#delete--api-v1-live-events-event_id) - Delete Live Event
- [POST /api/v1/live/events/{event_id}/start](#post--api-v1-live-events-event_id-start) - Start Live Event
- [POST /api/v1/live/events/{event_id}/stop](#post--api-v1-live-events-event_id-stop) - Stop Live Event

---

## POST /api/v1/live/events

**Description**: Create a new live event.

Admin only endpoint.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| description | any | No | - |
| scheduled_start | string | Yes | - |
| scheduled_end | any | No | - |
| tier_required | string | No | - |
| max_viewers | any | No | - |
| recording_enabled | boolean | No | - |

**Request Example**:
```json
{
  "title": "string",
  "description": {},
  "scheduled_start": "2024-01-15T10:30:00Z",
  "scheduled_end": {},
  "tier_required": "free",
  "max_viewers": {},
  "recording_enabled": true
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "title": "string",
  "description": {},
  "stream_key": "string",
  "rtmp_url": "string",
  "hls_url": {},
  "is_active": true,
  "scheduled_start": "2024-01-15T10:30:00Z",
  "current_viewers": 1,
  "tier_required": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/live/events

**Description**: List live events.

Filter by active if needed.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| active_only | boolean | No | - (default: False) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "description": {},
    "stream_key": "string",
    "rtmp_url": "string",
    "hls_url": {},
    "is_active": true,
    "scheduled_start": "2024-01-15T10:30:00Z",
    "current_viewers": 1,
    "tier_required": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/live/events/{event_id}

**Description**: Get live event details.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "title": "string",
  "description": {},
  "stream_key": "string",
  "rtmp_url": "string",
  "hls_url": {},
  "is_active": true,
  "scheduled_start": "2024-01-15T10:30:00Z",
  "current_viewers": 1,
  "tier_required": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/live/events/{event_id}

**Description**: Delete live event (admin only).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

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

## POST /api/v1/live/events/{event_id}/start

**Description**: Start live event.

Admin only.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

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

## POST /api/v1/live/events/{event_id}/stop

**Description**: Stop live event.

Admin only.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

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


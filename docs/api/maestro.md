# Maestro API

API endpoints for maestro functionality.

## Table of Contents

- [GET /api/v1/maestro/dashboard](#get--api-v1-maestro-dashboard) - Get Maestro Dashboard
- [GET /api/v1/maestro/videos](#get--api-v1-maestro-videos) - List Maestro Videos
- [DELETE /api/v1/maestro/videos/{video_id}](#delete--api-v1-maestro-videos-video_id) - Delete Video
- [POST /api/v1/maestro/live-events](#post--api-v1-maestro-live-events) - Create Live Event
- [GET /api/v1/maestro/live-events](#get--api-v1-maestro-live-events) - List Live Events
- [DELETE /api/v1/maestro/live-events/{event_id}](#delete--api-v1-maestro-live-events-event_id) - Cancel Live Event
- [GET /api/v1/maestro/earnings](#get--api-v1-maestro-earnings) - Get Earnings
- [POST /api/v1/maestro/withdrawals](#post--api-v1-maestro-withdrawals) - Request Withdrawal
- [GET /api/v1/maestro/withdrawals](#get--api-v1-maestro-withdrawals) - List Withdrawals
- [GET /api/v1/maestro/corrections](#get--api-v1-maestro-corrections) - List Correction Requests
- [POST /api/v1/maestro/corrections/{request_id}/feedback](#post--api-v1-maestro-corrections-request_id-feedback) - Submit Correction Feedback
- [GET /api/v1/maestro/translations](#get--api-v1-maestro-translations) - List Translation Datasets
- [GET /api/v1/maestro/glossary](#get--api-v1-maestro-glossary) - List Glossary Terms

---

## GET /api/v1/maestro/dashboard

**Description**: 📊 Maestro dashboard with key metrics.

Returns:
- Total videos, followers, donations received
- Earnings (last 30 days)
- Pending correction requests
- Upcoming live events

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/maestro/videos

**Description**: 🎥 List maestro's videos.

Args:
    status: Filter by status (pending, processing, ready, failed)

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |
| status | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/maestro/videos/{video_id}

**Description**: 🗑️ Delete a video.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/maestro/live-events

**Description**: 📡 Create a new live event.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| description | any | No | - |
| event_type | string | Yes | - |
| scheduled_start | string | Yes | - |
| scheduled_end | any | No | - |
| donations_enabled | boolean | No | - |
| chat_enabled | boolean | No | - |
| translations_enabled | boolean | No | - |
| translation_languages | any | No | - |
| fundraising_goal | any | No | - |

**Request Example**:
```json
{
  "title": "string",
  "description": {},
  "event_type": "string",
  "scheduled_start": "2024-01-15T10:30:00Z",
  "scheduled_end": {},
  "donations_enabled": true,
  "chat_enabled": true,
  "translations_enabled": false,
  "translation_languages": {},
  "fundraising_goal": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/maestro/live-events

**Description**: 📡 List maestro's live events.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |
| upcoming_only | boolean | No | - (default: False) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/maestro/live-events/{event_id}

**Description**: ❌ Cancel a live event.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/maestro/earnings

**Description**: 💰 Get maestro earnings.

Returns donations received broken down by period.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| period | string | No | - (default: 30d) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/maestro/withdrawals

**Description**: 💸 Request withdrawal of earnings.

Minimum: 10,000 stelline (€100)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| stelline_amount | integer | Yes | - |
| payout_method | string | Yes | - |
| iban | any | No | - |
| paypal_email | any | No | - |

**Request Example**:
```json
{
  "stelline_amount": 1,
  "payout_method": "string",
  "iban": {},
  "paypal_email": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/maestro/withdrawals

**Description**: 💸 List withdrawal requests.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/maestro/corrections

**Description**: ✍️ List student correction requests.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |
| status | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/maestro/corrections/{request_id}/feedback

**Description**: ✅ Submit feedback for correction request.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| feedback_text | any | No | - |
| feedback_video_url | any | No | - |
| feedback_annotations | any | No | - |

**Request Example**:
```json
{
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_annotations": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/maestro/translations

**Description**: 🌐 List translation datasets.

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/maestro/glossary

**Description**: 📖 List glossary terms.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 100) |
| search | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


# Live Translation API

API endpoints for live translation functionality.

## Table of Contents

- [POST /api/v1/live-translation/events/{event_id}/start](#post--api-v1-live-translation-events-event_id-start) - Start Translation Session
- [POST /api/v1/live-translation/events/{event_id}/stop](#post--api-v1-live-translation-events-event_id-stop) - Stop Translation Session
- [GET /api/v1/live-translation/events/{event_id}/stats](#get--api-v1-live-translation-events-event_id-stats) - Get Translation Stats
- [GET /api/v1/live-translation/languages/supported](#get--api-v1-live-translation-languages-supported) - Get Supported Languages
- [GET /api/v1/live-translation/providers/info](#get--api-v1-live-translation-providers-info) - Get Providers Info
- [POST /api/v1/live-translation/providers/switch](#post--api-v1-live-translation-providers-switch) - Switch Service Provider

---

## POST /api/v1/live-translation/events/{event_id}/start

**Description**: Start a translation session (admin only)

This is a REST endpoint to initialize the session without WebSocket

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| source_language | string | No | - (default: it) |

**Request Body**:
*No parameters*

**Request Example**:
```json
[
  "en",
  "es",
  "fr",
  "de"
]
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/live-translation/events/{event_id}/stop

**Description**: Stop a translation session (admin only)

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

## GET /api/v1/live-translation/events/{event_id}/stats

**Description**: Get translation statistics for an event

Returns viewer count per language

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

## GET /api/v1/live-translation/languages/supported

**Description**: Get list of supported languages for speech and translation

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/live-translation/providers/info

**Description**: Get information about current speech and translation providers

Shows which provider is active and their features/costs

**Authentication**: None

**Response 200**:
Successful Response

---

## POST /api/v1/live-translation/providers/switch

**Description**: Switch service provider (admin only)

Args:
    service_type: "speech" or "translation"
    provider: Provider name (whisper, google, nllb)

Note:
    Requires application restart for full effect

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| service_type | string | Yes | - |
| provider | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


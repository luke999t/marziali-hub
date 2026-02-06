# Glasses API

API endpoints for glasses functionality.

## Table of Contents

- [GET /api/v1/glasses/rooms](#get--api-v1-glasses-rooms) - Lista room attive (debug)
- [GET /api/v1/glasses/room/{user_id}](#get--api-v1-glasses-room-user_id) - Stato room specifica

---

## GET /api/v1/glasses/rooms

**Description**: Ritorna lista room attive per debug/monitoring.

Non esporre in produzione senza autenticazione admin.

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/glasses/room/{user_id}

**Description**: Ritorna stato di una room specifica.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


# Tracking API

API endpoints for tracking functionality.

## Table of Contents

- [POST /api/v1/royalties/track-view](#post--api-v1-royalties-track-view) - Track video view milestone
- [GET /api/v1/royalties/verify/{view_id}](#get--api-v1-royalties-verify-view_id) - Verify view on blockchain

---

## POST /api/v1/royalties/track-view

**Description**: Track a view milestone for royalty calculation

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | ID video |
| view_session_id | string | Yes | ID sessione view |
| milestone | string | Yes | Milestone raggiunto (started, 25, 50, 75, completed) |
| watch_time_seconds | integer | Yes | Secondi guardati |
| video_duration_seconds | integer | Yes | Durata totale video |
| device_fingerprint | any | No | - |

**Request Example**:
```json
{
  "video_id": "550e8400-e29b-41d4-a716-446655440000",
  "view_session_id": "550e8400-e29b-41d4-a716-446655440000",
  "milestone": "string",
  "watch_time_seconds": 1,
  "video_duration_seconds": 1,
  "device_fingerprint": {}
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "royalty_id": {},
  "milestone": "started",
  "amount_cents": 1,
  "message": "string",
  "amount_eur": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/royalties/verify/{view_id}

**Description**: Verify a tracked view exists on blockchain

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| view_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "verified": true,
  "view_id": "550e8400-e29b-41d4-a716-446655440000",
  "batch_id": {},
  "tx_hash": {},
  "merkle_root": {},
  "merkle_proof": {},
  "ipfs_hash": {},
  "block_number": {},
  "confirmations": 1,
  "error": {}
}
```

**Error Codes**:
- **422**: Validation Error

---


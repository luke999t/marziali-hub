# Students API

API endpoints for students functionality.

## Table of Contents

- [GET /api/v1/royalties/students/{student_id}/subscriptions](#get--api-v1-royalties-students-student_id-subscriptions) - Get student subscriptions
- [POST /api/v1/royalties/students/{student_id}/subscriptions](#post--api-v1-royalties-students-student_id-subscriptions) - Create student subscription
- [DELETE /api/v1/royalties/students/{student_id}/subscriptions/{subscription_id}](#delete--api-v1-royalties-students-student_id-subscriptions-subscription_id) - Cancel subscription
- [GET /api/v1/royalties/students/{student_id}/available-masters](#get--api-v1-royalties-students-student_id-available-masters) - Get available masters

---

## GET /api/v1/royalties/students/{student_id}/subscriptions

**Description**: Retrieve all subscriptions for a student

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| student_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| active_only | boolean | No | - (default: True) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "student_id": "550e8400-e29b-41d4-a716-446655440000",
    "master_id": {},
    "subscription_type": "platform",
    "subscription_tier": "string",
    "price_paid_cents": 1,
    "currency": "string",
    "started_at": "2024-01-15T10:30:00Z",
    "expires_at": {},
    "cancelled_at": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/royalties/students/{student_id}/subscriptions

**Description**: Subscribe a student to a master or platform

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| student_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| student_id | string | Yes | ID studente |
| master_id | any | No | ID maestro (null = abbonamento piattaforma) |
| subscription_type | any | Yes | Tipo abbonamento |
| subscription_tier | string | Yes | Tier (monthly/yearly/lifetime/per_video) |
| video_id | any | No | ID video (solo per per_video) |
| auto_renew | boolean | No | Rinnovo automatico |

**Request Example**:
```json
{
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "master_id": {},
  "subscription_type": {},
  "subscription_tier": "string",
  "video_id": {},
  "auto_renew": true
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "master_id": {},
  "subscription_type": "platform",
  "subscription_tier": "string",
  "price_paid_cents": 1,
  "currency": "string",
  "started_at": "2024-01-15T10:30:00Z",
  "expires_at": {},
  "cancelled_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/royalties/students/{student_id}/subscriptions/{subscription_id}

**Description**: Cancel a student subscription

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| student_id | string | Yes | - |
| subscription_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/royalties/students/{student_id}/available-masters

**Description**: Get list of masters available for subscription

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| student_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| discipline | string | No | - |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

```json
[
  {
    "master_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "string",
    "avatar_url": {},
    "pricing_model": "free",
    "disciplines": [
      "string"
    ],
    "bio": {},
    "total_videos": 1,
    "total_subscribers": 1,
    "monthly_price_cents": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---


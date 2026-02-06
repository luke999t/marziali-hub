# Royalties API

API endpoints for royalties functionality.

## Table of Contents

- [GET /api/v1/royalties/admin/config](#get--api-v1-royalties-admin-config) - Get royalty configuration
- [PUT /api/v1/royalties/admin/config](#put--api-v1-royalties-admin-config) - Update royalty configuration
- [GET /api/v1/royalties/admin/stats](#get--api-v1-royalties-admin-stats) - Get global royalty statistics
- [POST /api/v1/royalties/masters/profile](#post--api-v1-royalties-masters-profile) - Create master royalty profile
- [GET /api/v1/royalties/masters/{master_id}/dashboard](#get--api-v1-royalties-masters-master_id-dashboard) - Get master royalty dashboard
- [GET /api/v1/royalties/masters/{master_id}/history](#get--api-v1-royalties-masters-master_id-history) - Get master payout history
- [PUT /api/v1/royalties/masters/{master_id}/config](#put--api-v1-royalties-masters-master_id-config) - Update master profile configuration
- [POST /api/v1/royalties/masters/{master_id}/request-payout](#post--api-v1-royalties-masters-master_id-request-payout) - Request royalty payout
- [GET /api/v1/royalties/students/{student_id}/subscriptions](#get--api-v1-royalties-students-student_id-subscriptions) - Get student subscriptions
- [POST /api/v1/royalties/students/{student_id}/subscriptions](#post--api-v1-royalties-students-student_id-subscriptions) - Create student subscription
- [DELETE /api/v1/royalties/students/{student_id}/subscriptions/{subscription_id}](#delete--api-v1-royalties-students-student_id-subscriptions-subscription_id) - Cancel subscription
- [GET /api/v1/royalties/students/{student_id}/available-masters](#get--api-v1-royalties-students-student_id-available-masters) - Get available masters
- [POST /api/v1/royalties/track-view](#post--api-v1-royalties-track-view) - Track video view milestone
- [GET /api/v1/royalties/verify/{view_id}](#get--api-v1-royalties-verify-view_id) - Verify view on blockchain
- [GET /api/v1/royalties/health](#get--api-v1-royalties-health) - Health check

---

## GET /api/v1/royalties/admin/config

**Description**: Retrieve current royalty system configuration (admin only)

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "student_master_mode": "string",
  "max_masters_per_student": 1,
  "master_switch_cooldown_days": 1,
  "subscription_types": {},
  "royalty_milestones": {},
  "revenue_split": {},
  "min_payout_cents": 1,
  "payout_frequency": "string",
  "payout_processing_days": 1,
  "blockchain_enabled": true
}
```

---

## PUT /api/v1/royalties/admin/config

**Description**: Update royalty system configuration (admin only)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| student_master_mode | any | No | - |
| max_masters_per_student | any | No | - |
| master_switch_cooldown_days | any | No | - |
| royalty_milestones | any | No | - |
| revenue_split | any | No | - |
| min_payout_cents | any | No | - |
| payout_frequency | any | No | - |
| blockchain_enabled | any | No | - |
| fraud_detection_enabled | any | No | - |

**Request Example**:
```json
{
  "student_master_mode": {},
  "max_masters_per_student": {},
  "master_switch_cooldown_days": {},
  "royalty_milestones": {},
  "revenue_split": {},
  "min_payout_cents": {},
  "payout_frequency": {},
  "blockchain_enabled": {},
  "fraud_detection_enabled": {}
}
```

**Response 200**:
Successful Response

```json
{
  "student_master_mode": "string",
  "max_masters_per_student": 1,
  "master_switch_cooldown_days": 1,
  "subscription_types": {},
  "royalty_milestones": {},
  "revenue_split": {},
  "min_payout_cents": 1,
  "payout_frequency": "string",
  "payout_processing_days": 1,
  "blockchain_enabled": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/royalties/admin/stats

**Description**: Retrieve platform-wide royalty statistics (admin only)

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| days | integer | No | Days to include (default: 30) |

**Response 200**:
Successful Response

```json
{
  "period_start": "2024-01-15T10:30:00Z",
  "period_end": "2024-01-15T10:30:00Z",
  "total_views": 1,
  "total_royalties_cents": 1,
  "total_platform_fees_cents": 1,
  "total_paid_out_cents": 1,
  "total_pending_cents": 1,
  "active_masters": 1,
  "masters_with_pending": 1,
  "avg_payout_cents": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/royalties/masters/profile

**Description**: Create a new master profile for royalty tracking

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_id | string | Yes | ID utente maestro |
| maestro_id | any | No | ID profilo Maestro esistente |
| pricing_model | any | No | Modello pricing contenuti |
| payout_method | any | No | Metodo pagamento preferito |
| wallet_address | any | No | Wallet address per pagamenti crypto |

**Request Example**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": {},
  "pricing_model": "included",
  "payout_method": "stripe",
  "wallet_address": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": {},
  "pricing_model": "free",
  "custom_prices": {},
  "royalty_override": {},
  "milestone_override": {},
  "payout_method": "blockchain",
  "wallet_address": {},
  "min_payout_override": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/royalties/masters/{master_id}/dashboard

**Description**: Retrieve royalty dashboard for a master

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| master_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| days | integer | No | - (default: 30) |

**Response 200**:
Successful Response

```json
{
  "master_id": "550e8400-e29b-41d4-a716-446655440000",
  "period_start": "2024-01-15T10:30:00Z",
  "period_end": "2024-01-15T10:30:00Z",
  "total_views": 1,
  "total_royalties_cents": 1,
  "pending_payout_cents": 1,
  "last_payout_amount_cents": 1,
  "last_payout_date": {},
  "milestone_breakdown": {},
  "daily_views": [
    {}
  ]
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/royalties/masters/{master_id}/history

**Description**: Retrieve payout history for a master

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| master_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "master_id": "550e8400-e29b-41d4-a716-446655440000",
    "gross_amount_cents": 1,
    "fees_cents": 1,
    "net_amount_cents": 1,
    "currency": "string",
    "period_start": "2024-01-15T10:30:00Z",
    "period_end": "2024-01-15T10:30:00Z",
    "views_count": 1,
    "method": "blockchain"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/royalties/masters/{master_id}/config

**Description**: Update master's royalty configuration

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| master_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| pricing_model | any | No | - |
| custom_prices | any | No | Override prezzi per subscription type |
| royalty_override | any | No | Override % royalty split |
| milestone_override | any | No | Override importi milestone |
| payout_method | any | No | - |
| wallet_address | any | No | - |
| min_payout_override | any | No | - |
| iban | any | No | - |
| paypal_email | any | No | - |

**Request Example**:
```json
{
  "pricing_model": {},
  "custom_prices": {},
  "royalty_override": {},
  "milestone_override": {},
  "payout_method": {},
  "wallet_address": {},
  "min_payout_override": {},
  "iban": {},
  "paypal_email": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": {},
  "pricing_model": "free",
  "custom_prices": {},
  "royalty_override": {},
  "milestone_override": {},
  "payout_method": "blockchain",
  "wallet_address": {},
  "min_payout_override": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/royalties/masters/{master_id}/request-payout

**Description**: Request a payout of accumulated royalties

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| master_id | string | Yes | - |

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "master_id": "550e8400-e29b-41d4-a716-446655440000",
  "gross_amount_cents": 1,
  "fees_cents": 1,
  "net_amount_cents": 1,
  "currency": "string",
  "period_start": "2024-01-15T10:30:00Z",
  "period_end": "2024-01-15T10:30:00Z",
  "views_count": 1,
  "method": "blockchain"
}
```

**Error Codes**:
- **422**: Validation Error

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

## GET /api/v1/royalties/health

**Description**: Check royalty system health

**Authentication**: None

**Response 200**:
Successful Response

---


# Masters API

API endpoints for masters functionality.

## Table of Contents

- [POST /api/v1/royalties/masters/profile](#post--api-v1-royalties-masters-profile) - Create master royalty profile
- [GET /api/v1/royalties/masters/{master_id}/dashboard](#get--api-v1-royalties-masters-master_id-dashboard) - Get master royalty dashboard
- [GET /api/v1/royalties/masters/{master_id}/history](#get--api-v1-royalties-masters-master_id-history) - Get master payout history
- [PUT /api/v1/royalties/masters/{master_id}/config](#put--api-v1-royalties-masters-master_id-config) - Update master profile configuration
- [POST /api/v1/royalties/masters/{master_id}/request-payout](#post--api-v1-royalties-masters-master_id-request-payout) - Request royalty payout

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


# Payments API

API endpoints for payments functionality.

## Table of Contents

- [POST /api/v1/payments/stelline/purchase](#post--api-v1-payments-stelline-purchase) - Create payment intent for stelline purchase
- [POST /api/v1/payments/stelline/confirm](#post--api-v1-payments-stelline-confirm) - Confirm stelline purchase
- [POST /api/v1/payments/subscription/create](#post--api-v1-payments-subscription-create) - Create subscription
- [POST /api/v1/payments/subscription/cancel](#post--api-v1-payments-subscription-cancel) - Cancel subscription
- [GET /api/v1/payments/history](#get--api-v1-payments-history) - Get payment history
- [POST /api/v1/payments/video/{video_id}/purchase](#post--api-v1-payments-video-video_id-purchase) - Purchase video with stelline (PPV)

---

## POST /api/v1/payments/stelline/purchase

**Description**: Step 1: Create Stripe Payment Intent for buying stelline

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| package | string | Yes | - |

**Request Example**:
```json
{
  "package": "string"
}
```

**Response 200**:
Successful Response

```json
{
  "payment_intent_id": "string",
  "client_secret": "string",
  "amount_eur": 1.0,
  "stelline_amount": 1,
  "payment_id": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/payments/stelline/confirm

**Description**: Step 2: Confirm payment succeeded and deliver stelline to wallet

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| payment_intent_id | string | Yes | - |

**Request Example**:
```json
{
  "payment_intent_id": "string"
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/payments/subscription/create

**Description**: Create Stripe subscription for tier upgrade

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tier | string | Yes | - |

**Request Example**:
```json
{
  "tier": "string"
}
```

**Response 200**:
Successful Response

```json
{
  "subscription_id": "string",
  "client_secret": "string",
  "amount_eur": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/payments/subscription/cancel

**Description**: Cancel user's active subscription

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/payments/history

**Description**: Get user's payment transaction history

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "type": "string",
    "amount_eur": 1.0,
    "status": "string",
    "description": {},
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/payments/video/{video_id}/purchase

**Description**: Buy access to premium video using stelline from wallet

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


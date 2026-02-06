# Asd API

API endpoints for asd functionality.

## Table of Contents

- [GET /api/v1/asd/{asd_id}/dashboard](#get--api-v1-asd-asd_id-dashboard) - Get Asd Dashboard
- [GET /api/v1/asd/{asd_id}/maestros](#get--api-v1-asd-asd_id-maestros) - List Asd Maestros
- [GET /api/v1/asd/{asd_id}/members](#get--api-v1-asd-asd_id-members) - List Members
- [POST /api/v1/asd/{asd_id}/members](#post--api-v1-asd-asd_id-members) - Add Member
- [GET /api/v1/asd/{asd_id}/members/{member_id}](#get--api-v1-asd-asd_id-members-member_id) - Get Member Detail
- [GET /api/v1/asd/{asd_id}/events](#get--api-v1-asd-asd_id-events) - List Asd Events
- [POST /api/v1/asd/{asd_id}/events](#post--api-v1-asd-asd_id-events) - Create Asd Event
- [GET /api/v1/asd/{asd_id}/earnings](#get--api-v1-asd-asd_id-earnings) - Get Asd Earnings
- [POST /api/v1/asd/{asd_id}/withdrawals](#post--api-v1-asd-asd_id-withdrawals) - Request Asd Withdrawal
- [GET /api/v1/asd/{asd_id}/withdrawals](#get--api-v1-asd-asd_id-withdrawals) - List Asd Withdrawals
- [GET /api/v1/asd/{asd_id}/reports/fiscal](#get--api-v1-asd-asd_id-reports-fiscal) - Generate Fiscal Report

---

## GET /api/v1/asd/{asd_id}/dashboard

**Description**: 📊 ASD dashboard with key metrics.

Returns:
- Total maestros, members
- Earnings (last 30 days)
- Upcoming events
- Membership status

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/asd/{asd_id}/maestros

**Description**: 👨‍🏫 List ASD affiliated maestros.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/asd/{asd_id}/members

**Description**: 👥 List ASD members.

Args:
    status: Filter by status (active, suspended, expired)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 50) |
| status | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/asd/{asd_id}/members

**Description**: ➕ Add a new member to ASD.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_id | string | Yes | - |
| member_number | any | No | - |
| membership_fee | any | No | - |
| fee_valid_until | any | No | - |

**Request Example**:
```json
{
  "user_id": "string",
  "member_number": {},
  "membership_fee": {},
  "fee_valid_until": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/asd/{asd_id}/members/{member_id}

**Description**: 🔍 Get member details.

Includes:
- Member info
- Payment history
- Medical certificate status
- Activity history

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |
| member_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/asd/{asd_id}/events

**Description**: 📅 List ASD events.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

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

## POST /api/v1/asd/{asd_id}/events

**Description**: 📡 Create ASD-organized event.

Must specify maestro who will conduct the event.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| description | any | No | - |
| event_type | string | Yes | - |
| maestro_id | string | Yes | - |
| scheduled_start | string | Yes | - |
| scheduled_end | any | No | - |
| fundraising_goal | any | No | - |

**Request Example**:
```json
{
  "title": "string",
  "description": {},
  "event_type": "string",
  "maestro_id": "string",
  "scheduled_start": "2024-01-15T10:30:00Z",
  "scheduled_end": {},
  "fundraising_goal": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/asd/{asd_id}/earnings

**Description**: 💰 Get ASD earnings from donations.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| period | string | No | - (default: 30d) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/asd/{asd_id}/withdrawals

**Description**: 💸 Request withdrawal for ASD.

Minimum: 10,000 stelline (€100)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

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

## GET /api/v1/asd/{asd_id}/withdrawals

**Description**: 💸 List ASD withdrawal requests.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

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

## GET /api/v1/asd/{asd_id}/reports/fiscal

**Description**: 📄 Generate fiscal year report for ASD.

Italian non-profit compliance:
- Total donations received
- Breakdown by donor type (anonymous vs with CF)
- Total withdrawals
- Member fees collected

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| year | integer | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


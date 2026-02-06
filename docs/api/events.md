# Events API

API endpoints for events functionality.

## Table of Contents

- [POST /api/v1/events/asd](#post--api-v1-events-asd) - Create Asd Partner
- [POST /api/v1/events/asd](#post--api-v1-events-asd) - Create Asd Partner
- [GET /api/v1/events/asd](#get--api-v1-events-asd) - List Asd Partners
- [GET /api/v1/events/asd](#get--api-v1-events-asd) - List Asd Partners
- [GET /api/v1/events/asd/{partner_id}](#get--api-v1-events-asd-partner_id) - Get Asd Partner
- [GET /api/v1/events/asd/{partner_id}](#get--api-v1-events-asd-partner_id) - Get Asd Partner
- [PATCH /api/v1/events/asd/{partner_id}](#patch--api-v1-events-asd-partner_id) - Update Asd Partner
- [PATCH /api/v1/events/asd/{partner_id}](#patch--api-v1-events-asd-partner_id) - Update Asd Partner
- [POST /api/v1/events/asd/{partner_id}/stripe/connect](#post--api-v1-events-asd-partner_id-stripe-connect) - Create Stripe Connect Account
- [POST /api/v1/events/asd/{partner_id}/stripe/connect](#post--api-v1-events-asd-partner_id-stripe-connect) - Create Stripe Connect Account
- [GET /api/v1/events/asd/{partner_id}/stripe/status](#get--api-v1-events-asd-partner_id-stripe-status) - Get Stripe Account Status
- [GET /api/v1/events/asd/{partner_id}/stripe/status](#get--api-v1-events-asd-partner_id-stripe-status) - Get Stripe Account Status
- [POST /api/v1/events/asd/{partner_id}/stripe/dashboard-link](#post--api-v1-events-asd-partner_id-stripe-dashboard-link) - Create Stripe Dashboard Link
- [POST /api/v1/events/asd/{partner_id}/stripe/dashboard-link](#post--api-v1-events-asd-partner_id-stripe-dashboard-link) - Create Stripe Dashboard Link
- [POST /api/v1/events/](#post--api-v1-events-) - Create Event
- [POST /api/v1/events/](#post--api-v1-events-) - Create Event
- [GET /api/v1/events/](#get--api-v1-events-) - List Events
- [GET /api/v1/events/](#get--api-v1-events-) - List Events
- [GET /api/v1/events/admin/stats](#get--api-v1-events-admin-stats) - Get Admin Stats
- [GET /api/v1/events/admin/stats](#get--api-v1-events-admin-stats) - Get Admin Stats
- [GET /api/v1/events/admin/refunds/pending](#get--api-v1-events-admin-refunds-pending) - Get Pending Refunds
- [GET /api/v1/events/admin/refunds/pending](#get--api-v1-events-admin-refunds-pending) - Get Pending Refunds
- [POST /api/v1/events/admin/notifications/process](#post--api-v1-events-admin-notifications-process) - Process Pending Notifications
- [POST /api/v1/events/admin/notifications/process](#post--api-v1-events-admin-notifications-process) - Process Pending Notifications
- [POST /api/v1/events/admin/notifications/cleanup](#post--api-v1-events-admin-notifications-cleanup) - Cleanup Old Notifications
- [POST /api/v1/events/admin/notifications/cleanup](#post--api-v1-events-admin-notifications-cleanup) - Cleanup Old Notifications
- [PATCH /api/v1/events/options/{option_id}](#patch--api-v1-events-options-option_id) - Update Event Option
- [PATCH /api/v1/events/options/{option_id}](#patch--api-v1-events-options-option_id) - Update Event Option
- [GET /api/v1/events/options/{option_id}/availability](#get--api-v1-events-options-option_id-availability) - Get Option Availability
- [GET /api/v1/events/options/{option_id}/availability](#get--api-v1-events-options-option_id-availability) - Get Option Availability
- [POST /api/v1/events/subscriptions](#post--api-v1-events-subscriptions) - Create Subscription
- [POST /api/v1/events/subscriptions](#post--api-v1-events-subscriptions) - Create Subscription
- [GET /api/v1/events/subscriptions](#get--api-v1-events-subscriptions) - List User Subscriptions
- [GET /api/v1/events/subscriptions](#get--api-v1-events-subscriptions) - List User Subscriptions
- [GET /api/v1/events/subscriptions/{subscription_id}](#get--api-v1-events-subscriptions-subscription_id) - Get Subscription
- [GET /api/v1/events/subscriptions/{subscription_id}](#get--api-v1-events-subscriptions-subscription_id) - Get Subscription
- [GET /api/v1/events/user/waiting-list](#get--api-v1-events-user-waiting-list) - List User Waiting List
- [GET /api/v1/events/user/waiting-list](#get--api-v1-events-user-waiting-list) - List User Waiting List
- [POST /api/v1/events/refunds](#post--api-v1-events-refunds) - Request Refund
- [POST /api/v1/events/refunds](#post--api-v1-events-refunds) - Request Refund
- [GET /api/v1/events/refunds](#get--api-v1-events-refunds) - List Refunds
- [GET /api/v1/events/refunds](#get--api-v1-events-refunds) - List Refunds
- [POST /api/v1/events/refunds/{refund_id}/approve](#post--api-v1-events-refunds-refund_id-approve) - Approve Refund
- [POST /api/v1/events/refunds/{refund_id}/approve](#post--api-v1-events-refunds-refund_id-approve) - Approve Refund
- [POST /api/v1/events/refunds/{refund_id}/reject](#post--api-v1-events-refunds-refund_id-reject) - Reject Refund
- [POST /api/v1/events/refunds/{refund_id}/reject](#post--api-v1-events-refunds-refund_id-reject) - Reject Refund
- [GET /api/v1/events/notifications](#get--api-v1-events-notifications) - Get User Notifications
- [GET /api/v1/events/notifications](#get--api-v1-events-notifications) - Get User Notifications
- [GET /api/v1/events/notifications/unread-count](#get--api-v1-events-notifications-unread-count) - Get Unread Notification Count
- [GET /api/v1/events/notifications/unread-count](#get--api-v1-events-notifications-unread-count) - Get Unread Notification Count
- [POST /api/v1/events/notifications/{notification_id}/read](#post--api-v1-events-notifications-notification_id-read) - Mark Notification Read
- [POST /api/v1/events/notifications/{notification_id}/read](#post--api-v1-events-notifications-notification_id-read) - Mark Notification Read
- [POST /api/v1/events/notifications/mark-all-read](#post--api-v1-events-notifications-mark-all-read) - Mark All Notifications Read
- [POST /api/v1/events/notifications/mark-all-read](#post--api-v1-events-notifications-mark-all-read) - Mark All Notifications Read
- [POST /api/v1/events/webhooks/stripe](#post--api-v1-events-webhooks-stripe) - Stripe Webhook
- [POST /api/v1/events/webhooks/stripe](#post--api-v1-events-webhooks-stripe) - Stripe Webhook
- [POST /api/v1/events/webhooks/stripe-connect](#post--api-v1-events-webhooks-stripe-connect) - Stripe Connect Webhook
- [POST /api/v1/events/webhooks/stripe-connect](#post--api-v1-events-webhooks-stripe-connect) - Stripe Connect Webhook
- [GET /api/v1/events/{event_id}](#get--api-v1-events-event_id) - Get Event
- [GET /api/v1/events/{event_id}](#get--api-v1-events-event_id) - Get Event
- [PATCH /api/v1/events/{event_id}](#patch--api-v1-events-event_id) - Update Event
- [PATCH /api/v1/events/{event_id}](#patch--api-v1-events-event_id) - Update Event
- [POST /api/v1/events/{event_id}/publish](#post--api-v1-events-event_id-publish) - Publish Event
- [POST /api/v1/events/{event_id}/publish](#post--api-v1-events-event_id-publish) - Publish Event
- [POST /api/v1/events/{event_id}/cancel](#post--api-v1-events-event_id-cancel) - Cancel Event
- [POST /api/v1/events/{event_id}/cancel](#post--api-v1-events-event_id-cancel) - Cancel Event
- [GET /api/v1/events/{event_id}/availability](#get--api-v1-events-event_id-availability) - Get Event Availability
- [GET /api/v1/events/{event_id}/availability](#get--api-v1-events-event_id-availability) - Get Event Availability
- [GET /api/v1/events/{event_id}/stats](#get--api-v1-events-event_id-stats) - Get Event Stats
- [GET /api/v1/events/{event_id}/stats](#get--api-v1-events-event_id-stats) - Get Event Stats
- [POST /api/v1/events/{event_id}/options](#post--api-v1-events-event_id-options) - Create Event Option
- [POST /api/v1/events/{event_id}/options](#post--api-v1-events-event_id-options) - Create Event Option
- [POST /api/v1/events/{event_id}/waiting-list](#post--api-v1-events-event_id-waiting-list) - Add To Waiting List
- [POST /api/v1/events/{event_id}/waiting-list](#post--api-v1-events-event_id-waiting-list) - Add To Waiting List
- [DELETE /api/v1/events/{event_id}/waiting-list](#delete--api-v1-events-event_id-waiting-list) - Remove From Waiting List
- [DELETE /api/v1/events/{event_id}/waiting-list](#delete--api-v1-events-event_id-waiting-list) - Remove From Waiting List
- [GET /api/v1/events/{event_id}/waiting-list](#get--api-v1-events-event_id-waiting-list) - Get Waiting List
- [GET /api/v1/events/{event_id}/waiting-list](#get--api-v1-events-event_id-waiting-list) - Get Waiting List

---

## POST /api/v1/events/asd

**Description**: Crea nuovo ASD partner.

Requires: Admin role

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| slug | any | No | - |
| description | any | No | - |
| logo_url | any | No | - |
| website | any | No | - |
| email | string | Yes | - |
| phone | any | No | - |
| address | any | No | - |
| city | any | No | - |
| province | any | No | - |
| postal_code | any | No | - |
| country | string | No | - |
| fiscal_code | any | No | - |
| vat_number | any | No | - |
| default_split_percentage | number | No | - |
| refund_approval_mode | any | No | - |

**Request Example**:
```json
{
  "name": "string",
  "slug": {},
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "address": {},
  "city": {},
  "province": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/asd

**Description**: Crea nuovo ASD partner.

Requires: Admin role

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| slug | any | No | - |
| description | any | No | - |
| logo_url | any | No | - |
| website | any | No | - |
| email | string | Yes | - |
| phone | any | No | - |
| address | any | No | - |
| city | any | No | - |
| province | any | No | - |
| postal_code | any | No | - |
| country | string | No | - |
| fiscal_code | any | No | - |
| vat_number | any | No | - |
| default_split_percentage | number | No | - |
| refund_approval_mode | any | No | - |

**Request Example**:
```json
{
  "name": "string",
  "slug": {},
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "address": {},
  "city": {},
  "province": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd

**Description**: Lista ASD partners.

Public endpoint (filtered data).

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| active_only | boolean | No | - (default: True) |
| verified_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "string",
    "slug": "string",
    "description": {},
    "logo_url": {},
    "website": {},
    "email": "string",
    "phone": {},
    "city": {},
    "country": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd

**Description**: Lista ASD partners.

Public endpoint (filtered data).

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| active_only | boolean | No | - (default: True) |
| verified_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "string",
    "slug": "string",
    "description": {},
    "logo_url": {},
    "website": {},
    "email": "string",
    "phone": {},
    "city": {},
    "country": "string"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd/{partner_id}

**Description**: Ottiene ASD partner per ID.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd/{partner_id}

**Description**: Ottiene ASD partner per ID.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/asd/{partner_id}

**Description**: Aggiorna ASD partner.

Requires: Admin role or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| logo_url | any | No | - |
| website | any | No | - |
| email | any | No | - |
| phone | any | No | - |
| address | any | No | - |
| city | any | No | - |
| province | any | No | - |
| postal_code | any | No | - |
| default_split_percentage | any | No | - |
| refund_approval_mode | any | No | - |
| is_active | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "logo_url": {},
  "website": {},
  "email": {},
  "phone": {},
  "address": {},
  "city": {},
  "province": {},
  "postal_code": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/asd/{partner_id}

**Description**: Aggiorna ASD partner.

Requires: Admin role or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| logo_url | any | No | - |
| website | any | No | - |
| email | any | No | - |
| phone | any | No | - |
| address | any | No | - |
| city | any | No | - |
| province | any | No | - |
| postal_code | any | No | - |
| default_split_percentage | any | No | - |
| refund_approval_mode | any | No | - |
| is_active | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "logo_url": {},
  "website": {},
  "email": {},
  "phone": {},
  "address": {},
  "city": {},
  "province": {},
  "postal_code": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "string",
  "slug": "string",
  "description": {},
  "logo_url": {},
  "website": {},
  "email": "string",
  "phone": {},
  "city": {},
  "country": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/asd/{partner_id}/stripe/connect

**Description**: Crea Stripe Connect account per ASD.

Returns URL per onboarding.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/asd/{partner_id}/stripe/connect

**Description**: Crea Stripe Connect account per ASD.

Returns URL per onboarding.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd/{partner_id}/stripe/status

**Description**: Ottiene status account Stripe.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/asd/{partner_id}/stripe/status

**Description**: Ottiene status account Stripe.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/asd/{partner_id}/stripe/dashboard-link

**Description**: Crea link per dashboard Stripe Express.

ASD può vedere transazioni e payouts.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/asd/{partner_id}/stripe/dashboard-link

**Description**: Crea link per dashboard Stripe Express.

ASD può vedere transazioni e payouts.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| partner_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/

**Description**: Crea nuovo evento.

Requires: ASD admin or platform admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| asd_id | string | Yes | - |
| title | string | Yes | - |
| slug | any | No | - |
| description | any | No | - |
| short_description | any | No | - |
| cover_image_url | any | No | - |
| start_date | string | Yes | - |
| end_date | string | Yes | - |
| presale_start | any | No | - |
| presale_end | any | No | - |
| sale_start | any | No | - |
| presale_enabled | boolean | No | - |
| presale_criteria | any | No | - |
| total_capacity | integer | Yes | - |
| min_threshold | any | No | - |
| location | any | No | - |
| bundle_course_id | any | No | - |
| bundle_discount_percent | number | No | - |
| split_percentage | any | No | - |
| requires_refund_approval | any | No | - |
| alert_config_override | any | No | - |
| discipline | any | No | - |
| instructor_name | any | No | - |
| instructor_bio | any | No | - |

**Request Example**:
```json
{
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": {},
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15",
  "presale_start": {},
  "presale_end": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/

**Description**: Crea nuovo evento.

Requires: ASD admin or platform admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| asd_id | string | Yes | - |
| title | string | Yes | - |
| slug | any | No | - |
| description | any | No | - |
| short_description | any | No | - |
| cover_image_url | any | No | - |
| start_date | string | Yes | - |
| end_date | string | Yes | - |
| presale_start | any | No | - |
| presale_end | any | No | - |
| sale_start | any | No | - |
| presale_enabled | boolean | No | - |
| presale_criteria | any | No | - |
| total_capacity | integer | Yes | - |
| min_threshold | any | No | - |
| location | any | No | - |
| bundle_course_id | any | No | - |
| bundle_discount_percent | number | No | - |
| split_percentage | any | No | - |
| requires_refund_approval | any | No | - |
| alert_config_override | any | No | - |
| discipline | any | No | - |
| instructor_name | any | No | - |
| instructor_bio | any | No | - |

**Request Example**:
```json
{
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": {},
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15",
  "presale_start": {},
  "presale_end": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/

**Description**: Lista eventi.

Public endpoint (solo eventi pubblicati).

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| status | string | No | - |
| upcoming_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_partner": {},
    "title": "string",
    "slug": "string",
    "description": {},
    "short_description": {},
    "cover_image_url": {},
    "start_date": "2024-01-15",
    "end_date": "2024-01-15"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/

**Description**: Lista eventi.

Public endpoint (solo eventi pubblicati).

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| status | string | No | - |
| upcoming_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_partner": {},
    "title": "string",
    "slug": "string",
    "description": {},
    "short_description": {},
    "cover_image_url": {},
    "start_date": "2024-01-15",
    "end_date": "2024-01-15"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/admin/stats

**Description**: Statistiche admin.

Requires: Platform admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| days | integer | No | - (default: 30) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/admin/stats

**Description**: Statistiche admin.

Requires: Platform admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| days | integer | No | - (default: 30) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/admin/refunds/pending

**Description**: Lista rimborsi pending.

Requires: Admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "string",
    "requested_amount_cents": {},
    "status": "pending",
    "requires_approval": true,
    "approved_at": {},
    "rejection_reason": {},
    "processed_at": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/admin/refunds/pending

**Description**: Lista rimborsi pending.

Requires: Admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| asd_id | string | No | - |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "string",
    "requested_amount_cents": {},
    "status": "pending",
    "requires_approval": true,
    "approved_at": {},
    "rejection_reason": {},
    "processed_at": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/admin/notifications/process

**Description**: Processa notifiche pending.

Manual trigger per scheduler.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_size | integer | No | - (default: 100) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/admin/notifications/process

**Description**: Processa notifiche pending.

Manual trigger per scheduler.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_size | integer | No | - (default: 100) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/admin/notifications/cleanup

**Description**: Rimuove notifiche vecchie.

Requires: Admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| days | integer | No | - (default: 90) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/admin/notifications/cleanup

**Description**: Rimuove notifiche vecchie.

Requires: Admin

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| days | integer | No | - (default: 90) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/options/{option_id}

**Description**: Aggiorna opzione evento.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| option_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| start_date | any | No | - |
| end_date | any | No | - |
| price_cents | any | No | - |
| early_bird_price_cents | any | No | - |
| early_bird_deadline | any | No | - |
| includes_bundle | any | No | - |
| is_active | any | No | - |
| sort_order | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "start_date": {},
  "end_date": {},
  "price_cents": {},
  "early_bird_price_cents": {},
  "early_bird_deadline": {},
  "includes_bundle": {},
  "is_active": {},
  "sort_order": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/options/{option_id}

**Description**: Aggiorna opzione evento.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| option_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| start_date | any | No | - |
| end_date | any | No | - |
| price_cents | any | No | - |
| early_bird_price_cents | any | No | - |
| early_bird_deadline | any | No | - |
| includes_bundle | any | No | - |
| is_active | any | No | - |
| sort_order | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "start_date": {},
  "end_date": {},
  "price_cents": {},
  "early_bird_price_cents": {},
  "early_bird_deadline": {},
  "includes_bundle": {},
  "is_active": {},
  "sort_order": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/options/{option_id}/availability

**Description**: Ottiene disponibilità opzione.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| option_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/options/{option_id}/availability

**Description**: Ottiene disponibilità opzione.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| option_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/subscriptions

**Description**: Crea iscrizione e inizia checkout.

Returns: checkout URL per pagamento Stripe

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| event_id | string | Yes | - |
| option_id | string | Yes | - |
| participant_info | any | No | - |
| success_url | string | Yes | - |
| cancel_url | string | Yes | - |

**Request Example**:
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "option_id": "550e8400-e29b-41d4-a716-446655440000",
  "participant_info": {},
  "success_url": "string",
  "cancel_url": "string"
}
```

**Response 201**:
Successful Response

```json
{
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "checkout_url": "string",
  "stripe_session_id": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/subscriptions

**Description**: Crea iscrizione e inizia checkout.

Returns: checkout URL per pagamento Stripe

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| event_id | string | Yes | - |
| option_id | string | Yes | - |
| participant_info | any | No | - |
| success_url | string | Yes | - |
| cancel_url | string | Yes | - |

**Request Example**:
```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "option_id": "550e8400-e29b-41d4-a716-446655440000",
  "participant_info": {},
  "success_url": "string",
  "cancel_url": "string"
}
```

**Response 201**:
Successful Response

```json
{
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "checkout_url": "string",
  "stripe_session_id": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/subscriptions

**Description**: Lista iscrizioni utente corrente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | No | - |
| active_only | boolean | No | - (default: True) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "option_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "amount_cents": 1,
    "currency": "string",
    "asd_amount_cents": 1,
    "platform_amount_cents": 1,
    "status": "pending",
    "participant_name": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/subscriptions

**Description**: Lista iscrizioni utente corrente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | No | - |
| active_only | boolean | No | - (default: True) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "option_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "amount_cents": 1,
    "currency": "string",
    "asd_amount_cents": 1,
    "platform_amount_cents": 1,
    "status": "pending",
    "participant_name": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/subscriptions/{subscription_id}

**Description**: Ottiene dettaglio iscrizione.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subscription_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "option_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "amount_cents": 1,
  "currency": "string",
  "asd_amount_cents": 1,
  "platform_amount_cents": 1,
  "status": "pending",
  "participant_name": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/subscriptions/{subscription_id}

**Description**: Ottiene dettaglio iscrizione.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| subscription_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "option_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "amount_cents": 1,
  "currency": "string",
  "asd_amount_cents": 1,
  "platform_amount_cents": 1,
  "status": "pending",
  "participant_name": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/user/waiting-list

**Description**: Lista waiting list entries utente corrente.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "preferred_option_id": {},
    "position": {},
    "is_active": true,
    "notified_at": {},
    "notification_count": 1,
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

---

## GET /api/v1/events/user/waiting-list

**Description**: Lista waiting list entries utente corrente.

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "event_id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "preferred_option_id": {},
    "position": {},
    "is_active": true,
    "notified_at": {},
    "notification_count": 1,
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

---

## POST /api/v1/events/refunds

**Description**: Richiede rimborso.

Auto-approves based on event refund policy.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| subscription_id | string | Yes | - |
| reason | string | Yes | - |
| requested_amount_cents | any | No | - |

**Request Example**:
```json
{
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "string",
  "requested_amount_cents": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "string",
  "requested_amount_cents": {},
  "status": "pending",
  "requires_approval": true,
  "approved_at": {},
  "rejection_reason": {},
  "processed_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/refunds

**Description**: Richiede rimborso.

Auto-approves based on event refund policy.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| subscription_id | string | Yes | - |
| reason | string | Yes | - |
| requested_amount_cents | any | No | - |

**Request Example**:
```json
{
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "string",
  "requested_amount_cents": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "reason": "string",
  "requested_amount_cents": {},
  "status": "pending",
  "requires_approval": true,
  "approved_at": {},
  "rejection_reason": {},
  "processed_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/refunds

**Description**: Lista richieste rimborso utente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | No | - |
| status | string | No | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "string",
    "requested_amount_cents": {},
    "status": "pending",
    "requires_approval": true,
    "approved_at": {},
    "rejection_reason": {},
    "processed_at": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/refunds

**Description**: Lista richieste rimborso utente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | No | - |
| status | string | No | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "subscription_id": "550e8400-e29b-41d4-a716-446655440000",
    "asd_id": "550e8400-e29b-41d4-a716-446655440000",
    "reason": "string",
    "requested_amount_cents": {},
    "status": "pending",
    "requires_approval": true,
    "approved_at": {},
    "rejection_reason": {},
    "processed_at": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/refunds/{refund_id}/approve

**Description**: Approva richiesta rimborso.

Requires: Admin or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| refund_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/refunds/{refund_id}/approve

**Description**: Approva richiesta rimborso.

Requires: Admin or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| refund_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/refunds/{refund_id}/reject

**Description**: Rifiuta richiesta rimborso.

Requires: Admin or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| refund_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/refunds/{refund_id}/reject

**Description**: Rifiuta richiesta rimborso.

Requires: Admin or ASD admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| refund_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/notifications

**Description**: Ottiene notifiche utente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| unread_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/notifications

**Description**: Ottiene notifiche utente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| unread_only | boolean | No | - (default: False) |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/notifications/unread-count

**Description**: Conta notifiche non lette.

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/events/notifications/unread-count

**Description**: Conta notifiche non lette.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/events/notifications/{notification_id}/read

**Description**: Segna notifica come letta.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notification_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/notifications/{notification_id}/read

**Description**: Segna notifica come letta.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notification_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/notifications/mark-all-read

**Description**: Segna tutte le notifiche come lette.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/events/notifications/mark-all-read

**Description**: Segna tutte le notifiche come lette.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/events/webhooks/stripe

**Description**: Stripe webhook endpoint.

Handles: checkout.session.completed, charge.refunded, account.updated

**Authentication**: None

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/webhooks/stripe

**Description**: Stripe webhook endpoint.

Handles: checkout.session.completed, charge.refunded, account.updated

**Authentication**: None

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/webhooks/stripe-connect

**Description**: Stripe Connect webhook endpoint.

Handles Connect-specific events (account.updated).

**Authentication**: None

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/webhooks/stripe-connect

**Description**: Stripe Connect webhook endpoint.

Handles Connect-specific events (account.updated).

**Authentication**: None

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/{event_id}

**Description**: Ottiene evento per ID.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| include_options | boolean | No | - (default: True) |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/{event_id}

**Description**: Ottiene evento per ID.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| include_options | boolean | No | - (default: True) |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/{event_id}

**Description**: Aggiorna evento.

Requires: ASD admin or platform admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | any | No | - |
| description | any | No | - |
| short_description | any | No | - |
| cover_image_url | any | No | - |
| start_date | any | No | - |
| end_date | any | No | - |
| presale_start | any | No | - |
| presale_end | any | No | - |
| sale_start | any | No | - |
| presale_enabled | any | No | - |
| presale_criteria | any | No | - |
| total_capacity | any | No | - |
| min_threshold | any | No | - |
| location | any | No | - |
| bundle_course_id | any | No | - |
| bundle_discount_percent | any | No | - |
| split_percentage | any | No | - |
| requires_refund_approval | any | No | - |
| alert_config_override | any | No | - |
| discipline | any | No | - |
| instructor_name | any | No | - |
| instructor_bio | any | No | - |

**Request Example**:
```json
{
  "title": {},
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": {},
  "end_date": {},
  "presale_start": {},
  "presale_end": {},
  "sale_start": {},
  "presale_enabled": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/events/{event_id}

**Description**: Aggiorna evento.

Requires: ASD admin or platform admin

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | any | No | - |
| description | any | No | - |
| short_description | any | No | - |
| cover_image_url | any | No | - |
| start_date | any | No | - |
| end_date | any | No | - |
| presale_start | any | No | - |
| presale_end | any | No | - |
| sale_start | any | No | - |
| presale_enabled | any | No | - |
| presale_criteria | any | No | - |
| total_capacity | any | No | - |
| min_threshold | any | No | - |
| location | any | No | - |
| bundle_course_id | any | No | - |
| bundle_discount_percent | any | No | - |
| split_percentage | any | No | - |
| requires_refund_approval | any | No | - |
| alert_config_override | any | No | - |
| discipline | any | No | - |
| instructor_name | any | No | - |
| instructor_bio | any | No | - |

**Request Example**:
```json
{
  "title": {},
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": {},
  "end_date": {},
  "presale_start": {},
  "presale_end": {},
  "sale_start": {},
  "presale_enabled": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/publish

**Description**: Pubblica evento.

Schedula anche alert/reminder.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/publish

**Description**: Pubblica evento.

Schedula anche alert/reminder.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_id": "550e8400-e29b-41d4-a716-446655440000",
  "asd_partner": {},
  "title": "string",
  "slug": "string",
  "description": {},
  "short_description": {},
  "cover_image_url": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/cancel

**Description**: Cancella evento.

Creates refunds and notifies subscribers.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/cancel

**Description**: Cancella evento.

Creates refunds and notifies subscribers.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/{event_id}/availability

**Description**: Ottiene disponibilità evento.

Returns: posti disponibili, fase vendita, waiting list count

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/{event_id}/availability

**Description**: Ottiene disponibilità evento.

Returns: posti disponibili, fase vendita, waiting list count

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/events/{event_id}/stats

**Description**: Ottiene statistiche evento.

Requires: ASD admin or platform admin

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

## GET /api/v1/events/{event_id}/stats

**Description**: Ottiene statistiche evento.

Requires: ASD admin or platform admin

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

## POST /api/v1/events/{event_id}/options

**Description**: Crea opzione per evento.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| description | any | No | - |
| start_date | string | Yes | - |
| end_date | string | Yes | - |
| price_cents | integer | Yes | - |
| early_bird_price_cents | any | No | - |
| early_bird_deadline | any | No | - |
| includes_bundle | boolean | No | - |
| sort_order | integer | No | - |

**Request Example**:
```json
{
  "name": "string",
  "description": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15",
  "price_cents": 1,
  "early_bird_price_cents": {},
  "early_bird_deadline": {},
  "includes_bundle": true,
  "sort_order": 0
}
```

**Response 201**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/options

**Description**: Crea opzione per evento.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| description | any | No | - |
| start_date | string | Yes | - |
| end_date | string | Yes | - |
| price_cents | integer | Yes | - |
| early_bird_price_cents | any | No | - |
| early_bird_deadline | any | No | - |
| includes_bundle | boolean | No | - |
| sort_order | integer | No | - |

**Request Example**:
```json
{
  "name": "string",
  "description": {},
  "start_date": "2024-01-15",
  "end_date": "2024-01-15",
  "price_cents": 1,
  "early_bird_price_cents": {},
  "early_bird_deadline": {},
  "includes_bundle": true,
  "sort_order": 0
}
```

**Response 201**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/waiting-list

**Description**: Aggiunge utente a waiting list.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "preferred_option_id": {},
  "position": {},
  "is_active": true,
  "notified_at": {},
  "notification_count": 1,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/events/{event_id}/waiting-list

**Description**: Aggiunge utente a waiting list.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| event_id | string | Yes | - |

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "preferred_option_id": {},
  "position": {},
  "is_active": true,
  "notified_at": {},
  "notification_count": 1,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/events/{event_id}/waiting-list

**Description**: Rimuove utente da waiting list.

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

## DELETE /api/v1/events/{event_id}/waiting-list

**Description**: Rimuove utente da waiting list.

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

## GET /api/v1/events/{event_id}/waiting-list

**Description**: Lista waiting list evento.

Requires: Admin

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

## GET /api/v1/events/{event_id}/waiting-list

**Description**: Lista waiting list evento.

Requires: Admin

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


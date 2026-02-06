# Admin API

API endpoints for admin functionality.

## Table of Contents

- [GET /api/v1/admin/dashboard](#get--api-v1-admin-dashboard) - Get Dashboard
- [GET /api/v1/admin/analytics/platform](#get--api-v1-admin-analytics-platform) - Get Platform Analytics
- [GET /api/v1/admin/users](#get--api-v1-admin-users) - List Users
- [GET /api/v1/admin/users/{user_id}](#get--api-v1-admin-users-user_id) - Get User Detail
- [POST /api/v1/admin/users/{user_id}/ban](#post--api-v1-admin-users-user_id-ban) - Ban User
- [POST /api/v1/admin/users/{user_id}/unban](#post--api-v1-admin-users-user_id-unban) - Unban User
- [GET /api/v1/admin/moderation/videos](#get--api-v1-admin-moderation-videos) - Get Pending Videos
- [POST /api/v1/admin/moderation/videos/{video_id}](#post--api-v1-admin-moderation-videos-video_id) - Moderate Video
- [GET /api/v1/admin/moderation/chat](#get--api-v1-admin-moderation-chat) - Get Flagged Chat Messages
- [DELETE /api/v1/admin/moderation/chat/{message_id}](#delete--api-v1-admin-moderation-chat-message_id) - Delete Chat Message
- [GET /api/v1/admin/donations](#get--api-v1-admin-donations) - List Donations
- [GET /api/v1/admin/donations/fraud-queue](#get--api-v1-admin-donations-fraud-queue) - Get Fraud Queue
- [GET /api/v1/admin/withdrawals](#get--api-v1-admin-withdrawals) - List Withdrawal Requests
- [GET /api/v1/admin/withdrawals/{withdrawal_id}](#get--api-v1-admin-withdrawals-withdrawal_id) - Get Withdrawal Detail
- [POST /api/v1/admin/withdrawals/{withdrawal_id}/action](#post--api-v1-admin-withdrawals-withdrawal_id-action) - Process Withdrawal
- [GET /api/v1/admin/maestros](#get--api-v1-admin-maestros) - List Maestros
- [GET /api/v1/admin/asds](#get--api-v1-admin-asds) - List Asds
- [GET /api/v1/admin/config/tiers](#get--api-v1-admin-config-tiers) - Get Tier Configuration
- [PUT /api/v1/admin/config/tiers](#put--api-v1-admin-config-tiers) - Update Tier Configuration
- [GET /api/v1/admin/jobs](#get--api-v1-admin-jobs) - List Scheduler Jobs
- [GET /api/v1/admin/jobs/{job_id}](#get--api-v1-admin-jobs-job_id) - Get Job Detail
- [GET /api/v1/admin/jobs/{job_id}/history](#get--api-v1-admin-jobs-job_id-history) - Get Job History
- [POST /api/v1/admin/jobs/{job_id}/trigger](#post--api-v1-admin-jobs-job_id-trigger) - Trigger Job Manually
- [POST /api/v1/admin/jobs/{job_id}/pause](#post--api-v1-admin-jobs-job_id-pause) - Pause Job
- [POST /api/v1/admin/jobs/{job_id}/resume](#post--api-v1-admin-jobs-job_id-resume) - Resume Job
- [GET /api/v1/royalties/admin/config](#get--api-v1-royalties-admin-config) - Get royalty configuration
- [PUT /api/v1/royalties/admin/config](#put--api-v1-royalties-admin-config) - Update royalty configuration
- [GET /api/v1/royalties/admin/stats](#get--api-v1-royalties-admin-stats) - Get global royalty statistics

---

## GET /api/v1/admin/dashboard

**Description**: 📊 Admin dashboard with comprehensive KPIs.

Returns:
- Total users, maestros, ASDs, videos
- Active subscriptions by tier
- Total revenue (last 30 days)
- Pending moderation queue sizes

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/admin/analytics/platform

**Description**: 📈 Platform-wide analytics.

Args:
    period: Time period (7d, 30d, 90d, 365d)

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

## GET /api/v1/admin/users

**Description**: 👥 List all users with pagination and search.

Args:
    skip: Number of users to skip
    limit: Max users to return (1-100)
    search: Search by username or email

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 50) |
| search | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/users/{user_id}

**Description**: 🔍 Get detailed user information.

Includes:
- Basic profile
- Maestro profile (if exists)
- Minor profile (if exists)
- Subscription tier
- Total donations sent/received
- Recent activity

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/users/{user_id}/ban

**Description**: 🚫 Ban a user temporarily or permanently.

Args:
    user_id: User to ban
    data: Ban reason and optional duration

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| reason | string | Yes | - |
| duration_days | any | No | - |

**Request Example**:
```json
{
  "reason": "string",
  "duration_days": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/users/{user_id}/unban

**Description**: ✅ Unban a user.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/moderation/videos

**Description**: 🎥 Get videos pending moderation.

Returns videos with status PENDING or PROCESSING that need review.

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

## POST /api/v1/admin/moderation/videos/{video_id}

**Description**: ✅/❌ Approve or reject a video.

Actions:
- "approve": Set status to READY
- "reject": Set status to FAILED with reason

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | - |
| reason | any | No | - |

**Request Example**:
```json
{
  "action": "string",
  "reason": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/moderation/chat

**Description**: 💬 Get flagged live chat messages for review.

**Authentication**: Required

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

## DELETE /api/v1/admin/moderation/chat/{message_id}

**Description**: 🗑️ Delete a live chat message.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/donations

**Description**: 💸 List donations with optional filters.

Args:
    min_amount: Filter donations >= amount (stelline)
    flagged_only: Show only suspicious donations

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 50) |
| min_amount | string | No | Min amount in stelline |
| flagged_only | boolean | No | - (default: False) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/donations/fraud-queue

**Description**: 🚨 Get donations flagged for potential fraud.

Flags:
- Donations over €15,000 requiring AML checks
- Repeated small donations (potential money laundering)
- Donations from banned users

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/admin/withdrawals

**Description**: 💰 List withdrawal requests.

Args:
    status: Filter by status (pending, approved, processing, completed, rejected)

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| status | string | No | - |
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/withdrawals/{withdrawal_id}

**Description**: 🔍 Get withdrawal request details.

Includes:
- Withdrawal info
- Maestro/ASD details
- Recent withdrawal history
- Total earnings

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| withdrawal_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/withdrawals/{withdrawal_id}/action

**Description**: ✅/❌ Approve or reject a withdrawal request.

Actions:
- "approve": Move to processing
- "reject": Reject with reason

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| withdrawal_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| action | string | Yes | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "action": "string",
  "notes": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/maestros

**Description**: 👨‍🏫 List all maestros.

**Authentication**: Required

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

## GET /api/v1/admin/asds

**Description**: 🏛️ List all ASDs.

**Authentication**: Required

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

## GET /api/v1/admin/config/tiers

**Description**: ⚙️ Get subscription tier configuration.

TODO: Implement tier configuration storage

**Authentication**: Required

**Response 200**:
Successful Response

---

## PUT /api/v1/admin/config/tiers

**Description**: ⚙️ Update tier prices and configuration.

TODO: Implement tier configuration storage

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| tier_prices | any | No | - |
| platform_fees | any | No | - |

**Request Example**:
```json
{
  "tier_prices": {},
  "platform_fees": {}
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/jobs

**Description**: AI_DESCRIPTION: List all scheduled maintenance jobs
AI_BUSINESS: Admin monitoring of background job status
AI_CREATED: 2025-01-17

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/admin/jobs/{job_id}

**Description**: AI_DESCRIPTION: Get detailed status of a specific job
AI_BUSINESS: Admin inspection of individual job status

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/jobs/{job_id}/history

**Description**: AI_DESCRIPTION: Get execution history for a job
AI_BUSINESS: Admin audit trail for job executions

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 10) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/jobs/{job_id}/trigger

**Description**: AI_DESCRIPTION: Manually trigger a job immediately
AI_BUSINESS: Admin manual execution for testing or urgent runs

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/jobs/{job_id}/pause

**Description**: AI_DESCRIPTION: Pause a scheduled job
AI_BUSINESS: Admin control to temporarily disable a job

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/jobs/{job_id}/resume

**Description**: AI_DESCRIPTION: Resume a paused job
AI_BUSINESS: Admin control to re-enable a paused job

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

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


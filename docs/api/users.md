# Users API

API endpoints for users functionality.

## Table of Contents

- [GET /api/v1/users/me](#get--api-v1-users-me) - Get Profile
- [PUT /api/v1/users/me](#put--api-v1-users-me) - Update Profile
- [PATCH /api/v1/users/me](#patch--api-v1-users-me) - Patch Profile

---

## GET /api/v1/users/me

**Description**: Get user profile.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "email": "user@example.com",
  "username": "string",
  "full_name": {},
  "tier": "string",
  "is_active": true,
  "is_admin": true,
  "email_verified": true,
  "created_at": "2024-01-15T10:30:00Z",
  "subscription_end": {}
}
```

---

## PUT /api/v1/users/me

**Description**: Update profile (PUT - full_name only).

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| full_name | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "email": "user@example.com",
  "username": "string",
  "full_name": {},
  "tier": "string",
  "is_active": true,
  "is_admin": true,
  "email_verified": true,
  "created_at": "2024-01-15T10:30:00Z",
  "subscription_end": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/users/me

**Description**: Update profile (PATCH - partial update).

**Authentication**: Required

**Request Body**:
*No parameters*

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "email": "user@example.com",
  "username": "string",
  "full_name": {},
  "tier": "string",
  "is_active": true,
  "is_admin": true,
  "email_verified": true,
  "created_at": "2024-01-15T10:30:00Z",
  "subscription_end": {}
}
```

**Error Codes**:
- **422**: Validation Error

---


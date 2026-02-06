# Auth API

API endpoints for auth functionality.

## Table of Contents

- [POST /api/v1/auth/register](#post--api-v1-auth-register) - Register new user
- [POST /api/v1/auth/login](#post--api-v1-auth-login) - Login user
- [POST /api/v1/auth/refresh](#post--api-v1-auth-refresh) - Refresh access token
- [GET /api/v1/auth/me](#get--api-v1-auth-me) - Get current user profile
- [POST /api/v1/auth/logout](#post--api-v1-auth-logout) - Logout user
- [POST /api/v1/auth/verify-email/{token}](#post--api-v1-auth-verify-email-token) - Verify email
- [POST /api/v1/auth/forgot-password](#post--api-v1-auth-forgot-password) - Request password reset
- [POST /api/v1/auth/reset-password/{token}](#post--api-v1-auth-reset-password-token) - Reset password

---

## POST /api/v1/auth/register

**Description**: Create new user account and return JWT tokens

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Valid email address |
| username | string | Yes | Unique username |
| password | string | Yes | Strong password |
| full_name | any | No | Full name |

**Request Example**:
```json
{
  "email": "user@example.com",
  "username": "string",
  "password": "string",
  "full_name": {}
}
```

**Response 201**:
User created successfully

```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "bearer",
  "expires_in": 1,
  "user": {
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
}
```

**Error Codes**:
- **400**: Invalid input data
- **409**: Email or username already exists
- **422**: Validation Error

---

## POST /api/v1/auth/login

**Description**: Authenticate user and return JWT tokens

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| email | string | Yes | Email address |
| password | string | Yes | Password |

**Request Example**:
```json
{
  "email": "user@example.com",
  "password": "string"
}
```

**Response 200**:
Login successful

```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "bearer",
  "expires_in": 1,
  "user": {
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
}
```

**Error Codes**:
- **401**: Invalid credentials
- **400**: Account disabled
- **422**: Validation Error

---

## POST /api/v1/auth/refresh

**Description**: Use refresh token to get new access token

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| refresh_token | string | Yes | Valid refresh token |

**Request Example**:
```json
{
  "refresh_token": "string"
}
```

**Response 200**:
Token refreshed successfully

```json
{
  "access_token": "string",
  "refresh_token": "string",
  "token_type": "bearer",
  "expires_in": 1,
  "user": {
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
}
```

**Error Codes**:
- **401**: Invalid or expired refresh token
- **422**: Validation Error

---

## GET /api/v1/auth/me

**Description**: Get authenticated user information

**Authentication**: Required

**Response 200**:
User profile retrieved

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
- **401**: Not authenticated

---

## POST /api/v1/auth/logout

**Description**: Logout user (client-side token deletion)

**Authentication**: None

**Response 200**:
Logout successful

```json
{
  "message": "string",
  "success": true
}
```

---

## POST /api/v1/auth/verify-email/{token}

**Description**: Verify user email with token

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| token | string | Yes | - |

**Response 200**:
Email verified

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **400**: Invalid or expired token
- **422**: Validation Error

---

## POST /api/v1/auth/forgot-password

**Description**: Send password reset email

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| email | string | Yes | - |

**Response 200**:
Reset email sent

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **404**: Email not found
- **422**: Validation Error

---

## POST /api/v1/auth/reset-password/{token}

**Description**: Reset password with token

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| token | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| new_password | string | Yes | - |

**Response 200**:
Password reset successful

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **400**: Invalid or expired token
- **422**: Validation Error

---


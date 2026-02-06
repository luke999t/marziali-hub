# Notifications API

API endpoints for notifications functionality.

## Table of Contents

- [GET /api/v1/notifications](#get--api-v1-notifications) - Get user notifications
- [DELETE /api/v1/notifications](#delete--api-v1-notifications) - Delete all notifications
- [GET /api/v1/notifications/unread-count](#get--api-v1-notifications-unread-count) - Get unread notification count
- [POST /api/v1/notifications/mark-all-read](#post--api-v1-notifications-mark-all-read) - Mark all notifications as read
- [GET /api/v1/notifications/device-tokens](#get--api-v1-notifications-device-tokens) - Get user device tokens
- [POST /api/v1/notifications/device-tokens](#post--api-v1-notifications-device-tokens) - Register device token
- [DELETE /api/v1/notifications/device-tokens/{token}](#delete--api-v1-notifications-device-tokens-token) - Unregister device token
- [GET /api/v1/notifications/preferences](#get--api-v1-notifications-preferences) - Get notification preferences
- [PATCH /api/v1/notifications/preferences](#patch--api-v1-notifications-preferences) - Update notification preferences
- [POST /api/v1/notifications/admin/broadcast](#post--api-v1-notifications-admin-broadcast) - Broadcast notification (Admin)
- [GET /api/v1/notifications/admin/stats/{user_id}](#get--api-v1-notifications-admin-stats-user_id) - Get user notification stats (Admin)
- [POST /api/v1/notifications/admin/cleanup](#post--api-v1-notifications-admin-cleanup) - Cleanup expired notifications (Admin)
- [GET /api/v1/notifications/{notification_id}](#get--api-v1-notifications-notification_id) - Get notification detail
- [DELETE /api/v1/notifications/{notification_id}](#delete--api-v1-notifications-notification_id) - Delete notification
- [PATCH /api/v1/notifications/{notification_id}/read](#patch--api-v1-notifications-notification_id-read) - Mark notification as read

---

## GET /api/v1/notifications

**Description**: Get paginated list of notifications for the current user

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| page | integer | No | Page number (1-indexed) (default: 1) |
| page_size | integer | No | Items per page (max 100) (default: 20) |
| unread_only | boolean | No | Filter to unread only (default: False) |
| notification_type | string | No | Filter by type |

**Response 200**:
Successful Response

```json
{
  "items": [
    {}
  ],
  "total": 1,
  "page": 1,
  "page_size": 1,
  "has_more": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/notifications

**Description**: Delete all notifications for the current user

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

---

## GET /api/v1/notifications/unread-count

**Description**: Get the count of unread notifications for the current user

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "count": 1
}
```

---

## POST /api/v1/notifications/mark-all-read

**Description**: Mark all notifications for the current user as read

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

---

## GET /api/v1/notifications/device-tokens

**Description**: Get list of registered device tokens for the current user

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "items": [
    {}
  ],
  "total": 1
}
```

---

## POST /api/v1/notifications/device-tokens

**Description**: Register a device token for push notifications

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| token | string | Yes | FCM/APNS token |
| device_type | string | Yes | Device type: ios, android, web |
| device_name | any | No | Device name |
| device_model | any | No | Device model |
| os_version | any | No | OS version |
| app_version | any | No | App version |

**Request Example**:
```json
{
  "token": "string",
  "device_type": "string",
  "device_name": {},
  "device_model": {},
  "os_version": {},
  "app_version": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "device_type": "string",
  "device_name": {},
  "device_model": {},
  "os_version": {},
  "app_version": {},
  "is_active": true,
  "last_used_at": {},
  "created_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/notifications/device-tokens/{token}

**Description**: Unregister a device token (on logout or uninstall)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| token | string | Yes | Device token to unregister |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/notifications/preferences

**Description**: Get notification preferences for the current user

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "system_enabled": true,
  "video_new_enabled": true,
  "live_start_enabled": true,
  "achievement_enabled": true,
  "subscription_enabled": true,
  "social_enabled": true,
  "promo_enabled": false,
  "push_enabled": true,
  "push_system": true,
  "push_video_new": true
}
```

---

## PATCH /api/v1/notifications/preferences

**Description**: Update notification preferences for the current user

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| system_enabled | any | No | - |
| video_new_enabled | any | No | - |
| live_start_enabled | any | No | - |
| achievement_enabled | any | No | - |
| subscription_enabled | any | No | - |
| social_enabled | any | No | - |
| promo_enabled | any | No | - |
| push_enabled | any | No | - |
| push_system | any | No | - |
| push_video_new | any | No | - |
| push_live_start | any | No | - |
| push_achievement | any | No | - |
| push_subscription | any | No | - |
| push_social | any | No | - |
| push_promo | any | No | - |
| quiet_hours_enabled | any | No | - |
| quiet_hours_start | any | No | - |
| quiet_hours_end | any | No | - |

**Request Example**:
```json
{
  "system_enabled": {},
  "video_new_enabled": {},
  "live_start_enabled": {},
  "achievement_enabled": {},
  "subscription_enabled": {},
  "social_enabled": {},
  "promo_enabled": {},
  "push_enabled": {},
  "push_system": {},
  "push_video_new": {}
}
```

**Response 200**:
Successful Response

```json
{
  "system_enabled": true,
  "video_new_enabled": true,
  "live_start_enabled": true,
  "achievement_enabled": true,
  "subscription_enabled": true,
  "social_enabled": true,
  "promo_enabled": false,
  "push_enabled": true,
  "push_system": true,
  "push_video_new": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/notifications/admin/broadcast

**Description**: Send a notification to multiple users (admin only)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_ids | array[string] | Yes | List of user UUIDs |
| notification_type | string | Yes | Notification type |
| title | string | Yes | Notification title |
| body | string | Yes | Notification body |
| priority | any | No | Priority level |
| image_url | any | No | Optional image URL |
| action_type | any | No | Action type |
| action_payload | any | No | Action payload JSON |
| send_push | boolean | No | Send push notifications |

**Request Example**:
```json
{
  "user_ids": [
    "string"
  ],
  "notification_type": "string",
  "title": "string",
  "body": "string",
  "priority": {},
  "image_url": {},
  "action_type": {},
  "action_payload": {},
  "send_push": true
}
```

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/notifications/admin/stats/{user_id}

**Description**: Get notification statistics for a specific user (admin only)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| user_id | string | Yes | User UUID |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/notifications/admin/cleanup

**Description**: Delete expired notifications and inactive device tokens (admin only)

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

---

## GET /api/v1/notifications/{notification_id}

**Description**: Get a specific notification by ID

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notification_id | string | Yes | Notification UUID |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "type": "string",
  "priority": "string",
  "title": "string",
  "body": "string",
  "image_url": {},
  "action_type": {},
  "action_payload": {},
  "is_read": true,
  "read_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/notifications/{notification_id}

**Description**: Delete a specific notification

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notification_id | string | Yes | Notification UUID |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/notifications/{notification_id}/read

**Description**: Mark a specific notification as read

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notification_id | string | Yes | Notification UUID |

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "success": true
}
```

**Error Codes**:
- **422**: Validation Error

---


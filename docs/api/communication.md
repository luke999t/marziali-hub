# Communication API

API endpoints for communication functionality.

## Table of Contents

- [POST /api/v1/communication/messages](#post--api-v1-communication-messages) - Send Message
- [POST /api/v1/communication/messages](#post--api-v1-communication-messages) - Send Message
- [GET /api/v1/communication/messages](#get--api-v1-communication-messages) - List Messages
- [GET /api/v1/communication/messages](#get--api-v1-communication-messages) - List Messages
- [PATCH /api/v1/communication/messages/{message_id}/read](#patch--api-v1-communication-messages-message_id-read) - Mark Message Read
- [PATCH /api/v1/communication/messages/{message_id}/read](#patch--api-v1-communication-messages-message_id-read) - Mark Message Read
- [GET /api/v1/communication/messages/unread/count](#get--api-v1-communication-messages-unread-count) - Get Unread Count
- [GET /api/v1/communication/messages/unread/count](#get--api-v1-communication-messages-unread-count) - Get Unread Count
- [DELETE /api/v1/communication/messages/{message_id}](#delete--api-v1-communication-messages-message_id) - Delete Message
- [DELETE /api/v1/communication/messages/{message_id}](#delete--api-v1-communication-messages-message_id) - Delete Message
- [POST /api/v1/communication/corrections](#post--api-v1-communication-corrections) - Create Correction Request
- [POST /api/v1/communication/corrections](#post--api-v1-communication-corrections) - Create Correction Request
- [GET /api/v1/communication/corrections](#get--api-v1-communication-corrections) - List Correction Requests
- [GET /api/v1/communication/corrections](#get--api-v1-communication-corrections) - List Correction Requests
- [GET /api/v1/communication/corrections/{request_id}](#get--api-v1-communication-corrections-request_id) - Get Correction Request
- [GET /api/v1/communication/corrections/{request_id}](#get--api-v1-communication-corrections-request_id) - Get Correction Request
- [PATCH /api/v1/communication/corrections/{request_id}](#patch--api-v1-communication-corrections-request_id) - Update Correction Request
- [PATCH /api/v1/communication/corrections/{request_id}](#patch--api-v1-communication-corrections-request_id) - Update Correction Request

---

## POST /api/v1/communication/messages

**Description**: Send a message to another user

**Rate Limit**: 100 messages/minute per user
**Max size**: 10MB for attachments

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| to_user_id | string | Yes | - |
| content | string | Yes | - |
| attachment_type | any | No | - |
| attachment_url | any | No | - |
| attachment_metadata | any | No | - |

**Request Example**:
```json
{
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "attachment_metadata": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "is_read": true,
  "read_at": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/communication/messages

**Description**: Send a message to another user

**Rate Limit**: 100 messages/minute per user
**Max size**: 10MB for attachments

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| to_user_id | string | Yes | - |
| content | string | Yes | - |
| attachment_type | any | No | - |
| attachment_url | any | No | - |
| attachment_metadata | any | No | - |

**Request Example**:
```json
{
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "attachment_metadata": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "is_read": true,
  "read_at": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/messages

**Description**: List messages for current user

**Filters**:
- `conversation_with`: Show conversation with specific user
- `unread_only`: Show only unread messages
- Pagination: page, page_size

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_with | string | No | Filter by conversation partner |
| unread_only | boolean | No | Show only unread messages (default: False) |
| page | integer | No | - (default: 1) |
| page_size | integer | No | - (default: 20) |

**Response 200**:
Successful Response

```json
{
  "messages": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
      "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
      "content": "string",
      "attachment_type": {},
      "attachment_url": {},
      "is_read": true,
      "read_at": {},
      "created_at": "2024-01-15T10:30:00Z"
    }
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

## GET /api/v1/communication/messages

**Description**: List messages for current user

**Filters**:
- `conversation_with`: Show conversation with specific user
- `unread_only`: Show only unread messages
- Pagination: page, page_size

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_with | string | No | Filter by conversation partner |
| unread_only | boolean | No | Show only unread messages (default: False) |
| page | integer | No | - (default: 1) |
| page_size | integer | No | - (default: 20) |

**Response 200**:
Successful Response

```json
{
  "messages": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
      "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
      "content": "string",
      "attachment_type": {},
      "attachment_url": {},
      "is_read": true,
      "read_at": {},
      "created_at": "2024-01-15T10:30:00Z"
    }
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

## PATCH /api/v1/communication/messages/{message_id}/read

**Description**: Mark message as read

**Authorization**: Only recipient can mark message as read

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "is_read": true,
  "read_at": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/communication/messages/{message_id}/read

**Description**: Mark message as read

**Authorization**: Only recipient can mark message as read

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "from_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "to_user_id": "550e8400-e29b-41d4-a716-446655440000",
  "content": "string",
  "attachment_type": {},
  "attachment_url": {},
  "is_read": true,
  "read_at": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/messages/unread/count

**Description**: Get count of unread messages

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/communication/messages/unread/count

**Description**: Get count of unread messages

**Authentication**: Required

**Response 200**:
Successful Response

---

## DELETE /api/v1/communication/messages/{message_id}

**Description**: Delete a message

**Authorization**: Only sender can delete message

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/communication/messages/{message_id}

**Description**: Delete a message

**Authorization**: Only sender can delete message

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| message_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/communication/corrections

**Description**: Create a correction request for a video

**Workflow**:
1. Student uploads video
2. Student creates correction request → maestro
3. Maestro reviews video
4. Maestro provides feedback (text, video, audio, annotations)
5. Student receives feedback

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| maestro_id | string | Yes | - |
| video_url | string | Yes | - |
| video_duration | any | No | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration": {},
  "notes": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/communication/corrections

**Description**: Create a correction request for a video

**Workflow**:
1. Student uploads video
2. Student creates correction request → maestro
3. Maestro reviews video
4. Maestro provides feedback (text, video, audio, annotations)
5. Student receives feedback

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| maestro_id | string | Yes | - |
| video_url | string | Yes | - |
| video_duration | any | No | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration": {},
  "notes": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/corrections

**Description**: List correction requests

**Filters**:
- `role=student`: Show requests I created
- `role=maestro`: Show requests assigned to me
- `status`: Filter by status

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| role | string | No | Filter by role (student or maestro) |
| status_filter | string | No | Filter by status |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "student_id": "550e8400-e29b-41d4-a716-446655440000",
    "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
    "video_url": "string",
    "video_duration_seconds": {},
    "status": "pending",
    "feedback_text": {},
    "feedback_video_url": {},
    "feedback_audio_url": {},
    "feedback_annotations": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/corrections

**Description**: List correction requests

**Filters**:
- `role=student`: Show requests I created
- `role=maestro`: Show requests assigned to me
- `status`: Filter by status

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| role | string | No | Filter by role (student or maestro) |
| status_filter | string | No | Filter by status |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "student_id": "550e8400-e29b-41d4-a716-446655440000",
    "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
    "video_url": "string",
    "video_duration_seconds": {},
    "status": "pending",
    "feedback_text": {},
    "feedback_video_url": {},
    "feedback_audio_url": {},
    "feedback_annotations": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/corrections/{request_id}

**Description**: Get correction request by ID

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/communication/corrections/{request_id}

**Description**: Get correction request by ID

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/communication/corrections/{request_id}

**Description**: Update correction request (maestro provides feedback)

**Authorization**: Only assigned maestro can update

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | CorrectionRequestStatus | Yes | - |
| feedback_text | any | No | - |
| feedback_video_url | any | No | - |
| feedback_audio_url | any | No | - |
| feedback_annotations | any | No | - |

**Request Example**:
```json
{
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PATCH /api/v1/communication/corrections/{request_id}

**Description**: Update correction request (maestro provides feedback)

**Authorization**: Only assigned maestro can update

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| request_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| status | CorrectionRequestStatus | Yes | - |
| feedback_text | any | No | - |
| feedback_video_url | any | No | - |
| feedback_audio_url | any | No | - |
| feedback_annotations | any | No | - |

**Request Example**:
```json
{
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "student_id": "550e8400-e29b-41d4-a716-446655440000",
  "maestro_id": "550e8400-e29b-41d4-a716-446655440000",
  "video_url": "string",
  "video_duration_seconds": {},
  "status": "pending",
  "feedback_text": {},
  "feedback_video_url": {},
  "feedback_audio_url": {},
  "feedback_annotations": {}
}
```

**Error Codes**:
- **422**: Validation Error

---


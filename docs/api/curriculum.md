# Curriculum API

API endpoints for curriculum functionality.

## Table of Contents

- [GET /api/v1/curricula/](#get--api-v1-curricula-) - List Curricula
- [POST /api/v1/curricula/](#post--api-v1-curricula-) - Create Curriculum
- [GET /api/v1/curricula/{curriculum_id}](#get--api-v1-curricula-curriculum_id) - Get Curriculum
- [PUT /api/v1/curricula/{curriculum_id}](#put--api-v1-curricula-curriculum_id) - Update Curriculum
- [DELETE /api/v1/curricula/{curriculum_id}](#delete--api-v1-curricula-curriculum_id) - Delete Curriculum
- [GET /api/v1/curricula/{curriculum_id}/levels](#get--api-v1-curricula-curriculum_id-levels) - List Curriculum Levels
- [POST /api/v1/curricula/{curriculum_id}/levels](#post--api-v1-curricula-curriculum_id-levels) - Create Curriculum Level
- [PUT /api/v1/curricula/{curriculum_id}/levels/{level_id}](#put--api-v1-curricula-curriculum_id-levels-level_id) - Update Curriculum Level
- [POST /api/v1/curricula/{curriculum_id}/levels/{level_id}/content](#post--api-v1-curricula-curriculum_id-levels-level_id-content) - Add Level Content
- [POST /api/v1/curricula/{curriculum_id}/enroll](#post--api-v1-curricula-curriculum_id-enroll) - Enroll In Curriculum
- [GET /api/v1/curricula/me/enrollments](#get--api-v1-curricula-me-enrollments) - Get My Enrollments
- [GET /api/v1/curricula/me/curricula/{curriculum_id}/progress](#get--api-v1-curricula-me-curricula-curriculum_id-progress) - Get My Progress
- [POST /api/v1/curricula/levels/{level_id}/start](#post--api-v1-curricula-levels-level_id-start) - Start Level
- [POST /api/v1/curricula/levels/{level_id}/progress](#post--api-v1-curricula-levels-level_id-progress) - Update Progress
- [POST /api/v1/curricula/levels/{level_id}/submit-exam](#post--api-v1-curricula-levels-level_id-submit-exam) - Submit Exam
- [POST /api/v1/curricula/submissions/{submission_id}/review](#post--api-v1-curricula-submissions-submission_id-review) - Review Exam
- [GET /api/v1/curricula/submissions/{submission_id}](#get--api-v1-curricula-submissions-submission_id) - Get Exam Submission
- [GET /api/v1/curricula/me/certificates](#get--api-v1-curricula-me-certificates) - Get My Certificates
- [GET /api/v1/curricula/certificates/verify/{verification_code}](#get--api-v1-curricula-certificates-verify-verification_code) - Verify Certificate
- [POST /api/v1/curricula/levels/{level_id}/issue-certificate](#post--api-v1-curricula-levels-level_id-issue-certificate) - Issue Certificate
- [POST /api/v1/curricula/{curriculum_id}/invite-codes](#post--api-v1-curricula-curriculum_id-invite-codes) - Create Invite Code
- [GET /api/v1/curricula/{curriculum_id}/invite-codes](#get--api-v1-curricula-curriculum_id-invite-codes) - List Invite Codes
- [DELETE /api/v1/curricula/{curriculum_id}/invite-codes/{code}](#delete--api-v1-curricula-curriculum_id-invite-codes-code) - Deactivate Invite Code

---

## GET /api/v1/curricula/

**Description**: List curricula with filters.

GET /api/v1/curricula

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| discipline | string | No | - |
| visibility | string | No | - |
| owner_type | string | No | - |
| featured | string | No | - |
| search | string | No | - |
| skip | integer | No | - (default: 0) |
| limit | integer | No | - (default: 20) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "name": "string",
    "slug": "string",
    "description": {},
    "discipline": "string",
    "style_variant": {},
    "owner_type": "string",
    "visibility": "string",
    "pricing_model": "string",
    "price": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/

**Description**: Create a new curriculum.

POST /api/v1/curricula

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| description | any | No | - |
| discipline | CurriculumDiscipline | Yes | - |
| style_variant | any | No | - |
| visibility | any | No | - |
| pricing_model | any | No | - |
| price | any | No | - |
| settings | any | No | - |
| thumbnail_url | any | No | - |
| banner_url | any | No | - |

**Request Example**:
```json
{
  "name": "string",
  "description": {},
  "discipline": "karate",
  "style_variant": {},
  "visibility": "public",
  "pricing_model": "free",
  "price": {},
  "settings": {},
  "thumbnail_url": {},
  "banner_url": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "slug": "string",
  "description": {},
  "discipline": "string",
  "style_variant": {},
  "owner_type": "string",
  "visibility": "string",
  "pricing_model": "string",
  "price": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/{curriculum_id}

**Description**: Get curriculum details.

GET /api/v1/curricula/{id}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "slug": "string",
  "description": {},
  "discipline": "string",
  "style_variant": {},
  "owner_type": "string",
  "visibility": "string",
  "pricing_model": "string",
  "price": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/curricula/{curriculum_id}

**Description**: Update a curriculum.

PUT /api/v1/curricula/{id}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| description | any | No | - |
| style_variant | any | No | - |
| visibility | any | No | - |
| pricing_model | any | No | - |
| price | any | No | - |
| settings | any | No | - |
| thumbnail_url | any | No | - |
| banner_url | any | No | - |
| is_active | any | No | - |
| is_featured | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "description": {},
  "style_variant": {},
  "visibility": {},
  "pricing_model": {},
  "price": {},
  "settings": {},
  "thumbnail_url": {},
  "banner_url": {},
  "is_active": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "slug": "string",
  "description": {},
  "discipline": "string",
  "style_variant": {},
  "owner_type": "string",
  "visibility": "string",
  "pricing_model": "string",
  "price": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/curricula/{curriculum_id}

**Description**: Delete (deactivate) a curriculum.

DELETE /api/v1/curricula/{id}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/{curriculum_id}/levels

**Description**: List all levels in a curriculum.

GET /api/v1/curricula/{id}/levels

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "name": "string",
    "order": 1,
    "belt_color": {},
    "description": {},
    "requirements": [
      "string"
    ],
    "exam_type": "string",
    "passing_score": 1,
    "estimated_hours": {},
    "is_free": true
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/{curriculum_id}/levels

**Description**: Create a new level in curriculum.

POST /api/v1/curricula/{id}/levels

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| belt_color | any | No | - |
| description | any | No | - |
| requirements | array[string] | No | - |
| exam_type | any | No | - |
| exam_instructions | any | No | - |
| passing_score | integer | No | - |
| reference_video_ids | array[string] | No | - |
| is_free | boolean | No | - |
| level_price | any | No | - |
| estimated_hours | any | No | - |
| min_practice_hours | any | No | - |

**Request Example**:
```json
{
  "name": "string",
  "belt_color": {},
  "description": {},
  "requirements": [],
  "exam_type": "video_submission",
  "exam_instructions": {},
  "passing_score": 70,
  "reference_video_ids": [],
  "is_free": false,
  "level_price": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "order": 1,
  "belt_color": {},
  "description": {},
  "requirements": [
    "string"
  ],
  "exam_type": "string",
  "passing_score": 1,
  "estimated_hours": {},
  "is_free": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/curricula/{curriculum_id}/levels/{level_id}

**Description**: Update a curriculum level.

PUT /api/v1/curricula/{id}/levels/{level_id}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |
| level_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | any | No | - |
| belt_color | any | No | - |
| description | any | No | - |
| requirements | any | No | - |
| exam_type | any | No | - |
| exam_instructions | any | No | - |
| passing_score | any | No | - |
| reference_video_ids | any | No | - |
| is_free | any | No | - |
| level_price | any | No | - |
| estimated_hours | any | No | - |
| min_practice_hours | any | No | - |

**Request Example**:
```json
{
  "name": {},
  "belt_color": {},
  "description": {},
  "requirements": {},
  "exam_type": {},
  "exam_instructions": {},
  "passing_score": {},
  "reference_video_ids": {},
  "is_free": {},
  "level_price": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "order": 1,
  "belt_color": {},
  "description": {},
  "requirements": [
    "string"
  ],
  "exam_type": "string",
  "passing_score": 1,
  "estimated_hours": {},
  "is_free": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/{curriculum_id}/levels/{level_id}/content

**Description**: Add courses/videos to a level.

POST /api/v1/curricula/{id}/levels/{level_id}/content

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |
| level_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| course_ids | array[string] | No | - |
| video_ids | array[string] | No | - |

**Request Example**:
```json
{
  "course_ids": [],
  "video_ids": []
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/{curriculum_id}/enroll

**Description**: Enroll current user in a curriculum.

POST /api/v1/curricula/{id}/enroll

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| invitation_code | string | No | - |

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "curriculum_id": "string",
  "current_level_id": {},
  "access_type": "string",
  "started_at": {},
  "completed_at": {},
  "is_active": true,
  "progress_percent": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/me/enrollments

**Description**: Get current user's enrollments.

GET /api/v1/curricula/me/enrollments

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "curriculum_id": "string",
    "current_level_id": {},
    "access_type": "string",
    "started_at": {},
    "completed_at": {},
    "is_active": true,
    "progress_percent": 1.0
  }
]
```

---

## GET /api/v1/curricula/me/curricula/{curriculum_id}/progress

**Description**: Get current user's progress in a curriculum.

GET /api/v1/curricula/me/curricula/{id}/progress

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "level_id": "string",
    "status": "string",
    "progress_percent": 1,
    "videos_watched": {},
    "courses_completed": {},
    "total_practice_minutes": 1,
    "started_at": {},
    "completed_at": {},
    "can_take_exam": true
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/levels/{level_id}/start

**Description**: Start a level (unlock it).

POST /api/v1/curricula/levels/{level_id}/start

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| level_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/levels/{level_id}/progress

**Description**: Update progress in a level (video watched, course completed, practice time).

POST /api/v1/curricula/levels/{level_id}/progress

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| level_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | any | No | - |
| video_progress_seconds | any | No | - |
| video_completed | boolean | No | - |
| course_id | any | No | - |
| course_score | any | No | - |
| practice_minutes | any | No | - |

**Request Example**:
```json
{
  "video_id": {},
  "video_progress_seconds": {},
  "video_completed": false,
  "course_id": {},
  "course_score": {},
  "practice_minutes": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "level_id": "string",
  "status": "string",
  "progress_percent": 1,
  "videos_watched": {},
  "courses_completed": {},
  "total_practice_minutes": 1,
  "started_at": {},
  "completed_at": {},
  "can_take_exam": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/levels/{level_id}/submit-exam

**Description**: Submit exam video for evaluation.

POST /api/v1/curricula/levels/{level_id}/submit-exam

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| level_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_url | string | Yes | - |
| video_duration | any | No | - |

**Request Example**:
```json
{
  "video_url": "string",
  "video_duration": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "string",
  "video_url": "string",
  "status": "string",
  "ai_score": {},
  "ai_feedback": {},
  "teacher_score": {},
  "teacher_feedback": {},
  "final_score": {},
  "passed": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/submissions/{submission_id}/review

**Description**: Teacher review of exam submission.

POST /api/v1/curricula/submissions/{submission_id}/review

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| submission_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| score | number | Yes | - |
| feedback | string | Yes | - |
| passed | boolean | Yes | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "score": 1.0,
  "feedback": "string",
  "passed": true,
  "notes": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "video_url": "string",
  "status": "string",
  "ai_score": {},
  "ai_feedback": {},
  "teacher_score": {},
  "teacher_feedback": {},
  "final_score": {},
  "passed": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/submissions/{submission_id}

**Description**: Get exam submission details.

GET /api/v1/curricula/submissions/{submission_id}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| submission_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "video_url": "string",
  "status": "string",
  "ai_score": {},
  "ai_feedback": {},
  "teacher_score": {},
  "teacher_feedback": {},
  "final_score": {},
  "passed": {},
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/me/certificates

**Description**: Get current user's certificates.

GET /api/v1/curricula/me/certificates

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "certificate_number": "string",
    "title": "string",
    "issued_at": "2024-01-15T10:30:00Z",
    "pdf_url": {},
    "is_valid": true,
    "verification_url": "string"
  }
]
```

---

## GET /api/v1/curricula/certificates/verify/{verification_code}

**Description**: Public certificate verification endpoint.

GET /api/v1/curricula/certificates/verify/{code}

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| verification_code | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/levels/{level_id}/issue-certificate

**Description**: Issue certificate for completed level.

POST /api/v1/curricula/levels/{level_id}/issue-certificate

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| level_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "certificate_number": "string",
  "title": "string",
  "issued_at": "2024-01-15T10:30:00Z",
  "pdf_url": {},
  "is_valid": true,
  "verification_url": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/curricula/{curriculum_id}/invite-codes

**Description**: Create invite code for curriculum.

POST /api/v1/curricula/{id}/invite-codes

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| max_uses | any | No | - |
| expires_days | any | No | - |

**Request Example**:
```json
{
  "max_uses": {},
  "expires_days": {}
}
```

**Response 201**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/curricula/{curriculum_id}/invite-codes

**Description**: List invite codes for curriculum.

GET /api/v1/curricula/{id}/invite-codes

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/curricula/{curriculum_id}/invite-codes/{code}

**Description**: Deactivate an invite code.

DELETE /api/v1/curricula/{id}/invite-codes/{code}

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| curriculum_id | string | Yes | - |
| code | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


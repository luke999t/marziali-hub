# 🥋 Media Center Arti Marziali - API Documentation

```
🎓 AI_MODULE: API Documentation
🎓 AI_DESCRIPTION: Complete REST API reference for all endpoints
🎓 AI_BUSINESS: Enables third-party integrations and frontend development
🎓 AI_TEACHING: RESTful API design, OpenAPI patterns, authentication flows

🔄 ALTERNATIVE_VALUTATE: GraphQL, gRPC, WebSocket-only
💡 PERCHÉ_QUESTA_SOLUZIONE: REST is standard, cacheable, tooling support
📊 METRICHE_SUCCESSO: Complete endpoint coverage, clear examples, versioning
```

## Base URL

```
Production: https://api.mediacenter-artimarziali.it/api/v1
Development: http://localhost:8000/api/v1
```

## Authentication

All protected endpoints require a Bearer token in the Authorization header:

```http
Authorization: Bearer <access_token>
```

### Token Lifecycle

| Token Type | Expiration | Refresh |
|------------|------------|---------|
| Access Token | 30 minutes | Use refresh token |
| Refresh Token | 7 days | Re-authenticate |

---

## 🔐 Auth Endpoints

### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "username": "martial_artist",
  "first_name": "Mario",
  "last_name": "Rossi"
}
```

**Response (201 Created):**
```json
{
  "id": "uuid-here",
  "email": "user@example.com",
  "username": "martial_artist",
  "role": "STUDENT",
  "subscription_tier": "FREE",
  "email_verified": false,
  "created_at": "2025-01-15T10:30:00Z"
}
```

**Errors:**
- `400` - Invalid input (password too weak, invalid email)
- `409` - Email or username already exists

---

### POST /auth/login
Authenticate and receive tokens.

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "uuid-here",
    "email": "user@example.com",
    "role": "STUDENT",
    "subscription_tier": "PREMIUM"
  }
}
```

**Errors:**
- `401` - Invalid credentials
- `403` - Account disabled or not verified

---

### POST /auth/refresh
Refresh an expired access token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 1800
}
```

---

### POST /auth/logout
Invalidate the current session.

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):**
```json
{
  "message": "Successfully logged out"
}
```

---

### POST /auth/forgot-password
Request password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "message": "If the email exists, a reset link has been sent"
}
```

---

### POST /auth/reset-password
Reset password with token from email.

**Request Body:**
```json
{
  "token": "reset-token-from-email",
  "new_password": "NewSecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "message": "Password successfully reset"
}
```

---

## 👤 Users Endpoints

### GET /users/me
Get current user profile.

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):**
```json
{
  "id": "uuid-here",
  "email": "user@example.com",
  "username": "martial_artist",
  "first_name": "Mario",
  "last_name": "Rossi",
  "role": "STUDENT",
  "subscription_tier": "PREMIUM",
  "avatar_url": "https://...",
  "bio": "Karate enthusiast",
  "stelline_balance": 1500,
  "created_at": "2025-01-15T10:30:00Z"
}
```

---

### PATCH /users/me
Update current user profile.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "first_name": "Mario",
  "last_name": "Rossi",
  "bio": "Updated bio",
  "avatar_url": "https://..."
}
```

**Response (200 OK):** Updated user object

---

### GET /users/{user_id}
Get user by ID (admin only or self).

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):** User object

---

## 🎬 Videos Endpoints

### GET /videos
List videos with pagination and filters.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `page` | int | Page number (default: 1) |
| `per_page` | int | Items per page (default: 20, max: 100) |
| `category` | string | TUTORIAL, COURSE, LIVE_REPLAY, WELLNESS |
| `difficulty` | string | BEGINNER, INTERMEDIATE, ADVANCED |
| `martial_art` | string | Karate, Judo, Aikido, etc. |
| `maestro_id` | uuid | Filter by maestro |
| `is_free` | boolean | Only free videos |
| `search` | string | Search in title/description |
| `sort_by` | string | created_at, rating, view_count |
| `order` | string | asc, desc |

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "video-uuid",
      "title": "Karate Basics",
      "description": "...",
      "thumbnail_url": "https://...",
      "duration_seconds": 1845,
      "category": "TUTORIAL",
      "difficulty": "BEGINNER",
      "martial_art": "Karate",
      "maestro": {
        "id": "maestro-uuid",
        "display_name": "Maestro Tanaka"
      },
      "is_free": true,
      "view_count": 15420,
      "rating": 4.8,
      "created_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "per_page": 20,
  "pages": 8
}
```

---

### GET /videos/{video_id}
Get video details.

**Response (200 OK):**
```json
{
  "id": "video-uuid",
  "title": "Karate Basics",
  "description": "Complete tutorial...",
  "video_url": "https://...",
  "thumbnail_url": "https://...",
  "duration_seconds": 1845,
  "category": "TUTORIAL",
  "difficulty": "BEGINNER",
  "martial_art": "Karate",
  "style": "Shotokan",
  "maestro": {
    "id": "maestro-uuid",
    "display_name": "Maestro Tanaka",
    "avatar_url": "https://..."
  },
  "is_free": true,
  "price_stelline": null,
  "view_count": 15420,
  "like_count": 1234,
  "rating": 4.8,
  "has_skeleton_data": true,
  "techniques_covered": ["Zenkutsu-dachi", "Oi-zuki"],
  "subtitles": ["en", "ja"],
  "created_at": "2025-01-15T10:30:00Z"
}
```

---

### POST /videos
Upload a new video (Maestro only).

**Headers:**
- `Authorization: Bearer <token>`
- `Content-Type: multipart/form-data`

**Form Data:**
| Field | Type | Required |
|-------|------|----------|
| `file` | file | Yes |
| `title` | string | Yes |
| `description` | string | Yes |
| `category` | string | Yes |
| `difficulty` | string | Yes |
| `martial_art` | string | Yes |
| `is_free` | boolean | No |
| `price_stelline` | int | No |

**Response (201 Created):**
```json
{
  "id": "video-uuid",
  "status": "PROCESSING",
  "message": "Video uploaded, processing started"
}
```

---

### POST /videos/{video_id}/like
Like/unlike a video.

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):**
```json
{
  "liked": true,
  "like_count": 1235
}
```

---

### GET /videos/{video_id}/skeleton
Get skeleton data for video (for pose comparison).

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):**
```json
{
  "video_id": "video-uuid",
  "skeleton_data": {
    "fps": 30,
    "total_frames": 5535,
    "landmarks_per_frame": 75,
    "frames": [
      {
        "timestamp_ms": 0,
        "landmarks": [
          {"x": 0.5, "y": 0.3, "z": 0.1, "visibility": 0.99}
        ]
      }
    ]
  }
}
```

---

## 📚 Curriculum Endpoints

### GET /curriculum
List available curricula.

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `martial_art` | string | Filter by martial art |
| `is_public` | boolean | Only public curricula |
| `maestro_id` | uuid | Filter by maestro |

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "curriculum-uuid",
      "name": "Karate Shotokan - Percorso Tradizionale",
      "martial_art": "Karate",
      "style": "Shotokan",
      "maestro": {
        "id": "maestro-uuid",
        "display_name": "Maestro Tanaka"
      },
      "total_levels": 10,
      "total_students": 1250,
      "is_public": true,
      "cover_image_url": "https://..."
    }
  ]
}
```

---

### GET /curriculum/{curriculum_id}
Get curriculum details with all levels.

**Response (200 OK):**
```json
{
  "id": "curriculum-uuid",
  "name": "Karate Shotokan - Percorso Tradizionale",
  "description": "...",
  "martial_art": "Karate",
  "style": "Shotokan",
  "levels": [
    {
      "id": "level-uuid",
      "level_number": 1,
      "name": "Cintura Bianca",
      "japanese_name": "Shiro Obi (9° Kyu)",
      "belt_color": "#FFFFFF",
      "requirements": [
        {
          "id": "req-uuid",
          "type": "TECHNIQUE",
          "name": "Posizioni Base",
          "description": "...",
          "is_mandatory": true,
          "passing_score": 60
        }
      ]
    }
  ]
}
```

---

### POST /curriculum/{curriculum_id}/enroll
Enroll in a curriculum.

**Headers:** `Authorization: Bearer <token>`

**Request Body (optional, for private curricula):**
```json
{
  "invite_code": "KARATE-XYZ123"
}
```

**Response (201 Created):**
```json
{
  "progress_id": "progress-uuid",
  "curriculum_id": "curriculum-uuid",
  "current_level": 1,
  "message": "Successfully enrolled"
}
```

---

### GET /curriculum/progress
Get user's curriculum progress.

**Headers:** `Authorization: Bearer <token>`

**Response (200 OK):**
```json
{
  "enrollments": [
    {
      "progress_id": "progress-uuid",
      "curriculum": {
        "id": "curriculum-uuid",
        "name": "Karate Shotokan"
      },
      "current_level": {
        "level_number": 3,
        "name": "Cintura Arancione"
      },
      "completion_percentage": 45,
      "requirements_completed": 12,
      "total_requirements": 27,
      "started_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

---

### POST /curriculum/exam/submit
Submit an exam (video) for review.

**Headers:**
- `Authorization: Bearer <token>`
- `Content-Type: multipart/form-data`

**Form Data:**
| Field | Type | Required |
|-------|------|----------|
| `requirement_id` | uuid | Yes |
| `video` | file | Yes |
| `notes` | string | No |

**Response (201 Created):**
```json
{
  "submission_id": "submission-uuid",
  "status": "PROCESSING",
  "message": "Submission received, AI analysis in progress"
}
```

---

## 🎙️ Live Translation Endpoints

### GET /live/sessions
List available live translation sessions.

**Response (200 OK):**
```json
{
  "sessions": [
    {
      "id": "session-uuid",
      "title": "Seminario Karate Internazionale",
      "source_language": "ja",
      "target_languages": ["it", "en", "es"],
      "status": "LIVE",
      "viewers": 125,
      "started_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

---

### WebSocket /live/{session_id}/stream
Connect to live translation stream.

**Connection:**
```javascript
const ws = new WebSocket('wss://api.example.com/live/session-uuid/stream');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  // data.type: 'transcript' | 'translation' | 'subtitle'
};
```

**Message Types:**
```json
{
  "type": "translation",
  "timestamp_ms": 12500,
  "original_text": "正拳突き",
  "translated_text": "Pugno diretto",
  "source_lang": "ja",
  "target_lang": "it",
  "confidence": 0.95
}
```

---

## 👨‍🏫 Maestro Endpoints

### GET /maestros
List verified maestros.

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "maestro-uuid",
      "display_name": "Maestro Hiroshi Tanaka",
      "specialization": "Karate Shotokan",
      "years_experience": 40,
      "rating": 4.9,
      "total_students": 1250,
      "total_videos": 87,
      "verified": true,
      "avatar_url": "https://..."
    }
  ]
}
```

---

### GET /maestros/{maestro_id}
Get maestro profile.

**Response (200 OK):** Full maestro profile with bio, certifications, etc.

---

### POST /maestros/{maestro_id}/correction-request
Request video correction from maestro.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "video_id": "video-uuid",
  "message": "Please review my kata execution",
  "timestamp_start": 30,
  "timestamp_end": 60
}
```

**Response (201 Created):**
```json
{
  "request_id": "request-uuid",
  "status": "PENDING",
  "estimated_response_days": 3
}
```

---

## 🛡️ Admin Endpoints

### GET /admin/users
List all users (admin only).

**Headers:** `Authorization: Bearer <admin_token>`

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `role` | string | Filter by role |
| `subscription_tier` | string | Filter by tier |
| `is_active` | boolean | Filter by status |

**Response (200 OK):** Paginated user list with admin details

---

### PATCH /admin/users/{user_id}
Update user (admin only).

**Request Body:**
```json
{
  "is_active": false,
  "role": "MAESTRO",
  "subscription_tier": "PREMIUM"
}
```

---

### GET /admin/analytics
Get platform analytics.

**Response (200 OK):**
```json
{
  "users": {
    "total": 15420,
    "new_this_month": 523,
    "active_today": 1250
  },
  "videos": {
    "total": 890,
    "views_this_month": 125000
  },
  "revenue": {
    "this_month_eur": 12500,
    "subscriptions_active": 2150
  }
}
```

---

## 💰 Payment Endpoints

### POST /payments/checkout
Create a checkout session for subscription.

**Headers:** `Authorization: Bearer <token>`

**Request Body:**
```json
{
  "tier": "PREMIUM",
  "billing_period": "monthly"
}
```

**Response (200 OK):**
```json
{
  "checkout_url": "https://checkout.stripe.com/...",
  "session_id": "cs_xxx"
}
```

---

### POST /payments/stelline/purchase
Purchase stelline (virtual currency).

**Request Body:**
```json
{
  "amount": 1000,
  "payment_method_id": "pm_xxx"
}
```

**Response (200 OK):**
```json
{
  "transaction_id": "tx-uuid",
  "stelline_credited": 1000,
  "new_balance": 2500
}
```

---

### GET /payments/history
Get payment history.

**Response (200 OK):**
```json
{
  "transactions": [
    {
      "id": "tx-uuid",
      "type": "SUBSCRIPTION",
      "amount_eur": 19.99,
      "status": "COMPLETED",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

---

## 📊 Health & Status

### GET /health
API health check.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2025-01-15T10:30:00Z",
  "services": {
    "database": "up",
    "redis": "up",
    "storage": "up"
  }
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid request data",
    "details": [
      {
        "field": "email",
        "message": "Invalid email format"
      }
    ]
  }
}
```

### Common Error Codes

| HTTP Status | Code | Description |
|-------------|------|-------------|
| 400 | VALIDATION_ERROR | Invalid request data |
| 401 | UNAUTHORIZED | Missing or invalid token |
| 403 | FORBIDDEN | Insufficient permissions |
| 404 | NOT_FOUND | Resource not found |
| 409 | CONFLICT | Resource already exists |
| 429 | RATE_LIMITED | Too many requests |
| 500 | INTERNAL_ERROR | Server error |

---

## Rate Limiting

- **Default:** 60 requests/minute per user
- **Burst:** 10 additional requests allowed
- **Headers returned:**
  - `X-RateLimit-Limit`: 60
  - `X-RateLimit-Remaining`: 55
  - `X-RateLimit-Reset`: 1642248000

---

## Versioning

API versions are included in the URL path:
- Current: `/api/v1/`
- Deprecated versions are supported for 6 months after deprecation notice

---

## OpenAPI Specification

Interactive documentation available at:
- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
- **OpenAPI JSON:** `http://localhost:8000/openapi.json`

---

*Last updated: December 2025*

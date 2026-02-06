# API Reference - Media Center Arti Marziali

**Version**: 1.0.0
**Base URL**: `https://api.example.com/api/v1`
**Last Updated**: 2026-01-17

---

## Table of Contents

1. [Authentication](#authentication)
2. [Users](#users)
3. [Videos](#videos)
4. [Ads](#ads)
5. [Payments](#payments)
6. [Live Streaming](#live-streaming)
7. [Blockchain](#blockchain)
8. [Communication](#communication)
9. [Moderation](#moderation)
10. [Admin](#admin)
11. [Subscriptions](#subscriptions)

---

## Authentication Overview

All authenticated endpoints require a Bearer token in the Authorization header:

```
Authorization: Bearer <access_token>
```

**Token Lifecycle**:
- Access Token: 30 minutes validity
- Refresh Token: 7 days validity

**User Tiers**:
- `free` - Basic access with ads
- `hybrid_light` - €2.99/month, no ads, 1080p
- `hybrid_standard` - €5.99/month, downloads enabled
- `premium` - €9.99/month, 4K, all features
- `business` - €49.99/month, bulk licenses, API access

---

## Authentication

### POST /auth/register

**Business Context**: User registration is the entry point for all platform users. New users start with FREE tier and can upgrade later. Email verification is required for full access.

Register a new user account.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "username": "martial_artist",
  "full_name": "John Doe"
}
```

**Response** (201 Created):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "martial_artist",
  "full_name": "John Doe",
  "tier": "free",
  "is_active": true,
  "is_verified": false,
  "created_at": "2026-01-17T10:00:00Z"
}
```

**Errors**:
- `400` - Invalid email format or weak password
- `409` - Email already registered

---

### POST /auth/login

**Business Context**: Login endpoint generates JWT tokens for authenticated access. Access token (30min) is used for API calls, refresh token (7 days) is used to obtain new access tokens without re-login. Critical for mobile app and web frontend.

Authenticate user and receive JWT tokens.

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "username": "martial_artist",
    "tier": "premium"
  }
}
```

**Errors**:
- `401` - Invalid credentials
- `403` - Account banned or inactive

---

### POST /auth/refresh

Refresh access token using refresh token.

**Request Body**:
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

---

### GET /auth/me

Get current authenticated user profile.

**Headers**: `Authorization: Bearer <token>`

**Response** (200 OK):
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com",
  "username": "martial_artist",
  "full_name": "John Doe",
  "tier": "premium",
  "is_verified": true,
  "avatar_url": "https://cdn.example.com/avatars/user.jpg",
  "subscription_end": "2026-02-17T10:00:00Z"
}
```

---

### POST /auth/logout

Logout and invalidate tokens.

**Headers**: `Authorization: Bearer <token>`

**Response** (200 OK):
```json
{
  "message": "Logged out successfully",
  "success": true
}
```

---

### POST /auth/verify-email

Verify email with token sent via email.

**Request Body**:
```json
{
  "token": "verification_token_from_email"
}
```

---

### POST /auth/forgot-password

Request password reset email.

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

---

### POST /auth/reset-password

Reset password with token from email.

**Request Body**:
```json
{
  "token": "reset_token",
  "new_password": "NewSecurePass123!"
}
```

---

## Users

### GET /users/me

Get current user's full profile.

**Headers**: `Authorization: Bearer <token>`

---

### PUT /users/me

Update current user's profile (full replace).

**Request Body**:
```json
{
  "full_name": "John Doe Updated",
  "avatar_url": "https://cdn.example.com/avatars/new.jpg",
  "bio": "Martial arts enthusiast"
}
```

---

### PATCH /users/me

Partially update current user's profile.

**Request Body**:
```json
{
  "bio": "Updated bio only"
}
```

---

## Videos

### GET /videos

**Business Context**: Main content discovery endpoint. Returns paginated video catalog with filters. Access control enforces tier restrictions - FREE users see only free public content, PREMIUM users see all content. This is the primary entry point for content consumption.

List videos with filters and pagination.

**Query Parameters**:
| Parameter | Type | Description |
|-----------|------|-------------|
| `skip` | int | Items to skip (default: 0) |
| `limit` | int | Items per page (1-100, default: 20) |
| `category` | string | Filter: technique, kata, combat, theory, workout, demo, other |
| `difficulty` | string | Filter: beginner, intermediate, advanced, expert |
| `tier` | string | Filter: free, hybrid_light, hybrid_standard, premium, business |
| `search` | string | Search in title/description (min 2 chars) |
| `sort_by` | string | Sort field: created_at, view_count, title |
| `sort_order` | string | asc or desc (default: desc) |

**Response** (200 OK):
```json
{
  "videos": [
    {
      "id": "video-uuid",
      "title": "Karate Kata Heian Shodan",
      "description": "Basic kata for beginners",
      "slug": "karate-kata-heian-shodan",
      "category": "kata",
      "difficulty": "beginner",
      "style": "Karate",
      "tags": ["kata", "beginner", "heian"],
      "thumbnail_url": "https://cdn.example.com/thumbs/video.jpg",
      "duration": 300,
      "view_count": 1500,
      "tier_required": "free",
      "created_at": "2026-01-15T10:00:00Z"
    }
  ],
  "total": 150,
  "skip": 0,
  "limit": 20
}
```

---

### GET /videos/search

Search videos by query string.

**Query Parameters**:
- `q` (required): Search query (min 2 chars)
- `skip`: Pagination offset
- `limit`: Items per page

---

### GET /videos/home

**Business Context**: Home feed optimized for mobile app. Returns featured hero video and content rows organized by martial arts style (Karate, Judo, Aikido, etc.). For authenticated users, includes "Continue Watching" row. This endpoint drives user engagement and content discovery on the home screen.

Get home feed for mobile app with featured video and content rows.

**Response** (200 OK):
```json
{
  "featured": {
    "id": "featured-video-uuid",
    "title": "Featured Championship Highlights",
    "thumbnail_url": "https://cdn.example.com/thumbs/featured.jpg"
  },
  "rows": [
    {
      "title": "Continua a guardare",
      "videos": [...]
    },
    {
      "title": "Karate",
      "videos": [...]
    },
    {
      "title": "Judo",
      "videos": [...]
    }
  ]
}
```

---

### GET /videos/continue-watching

Get videos user has started but not finished.

**Headers**: `Authorization: Bearer <token>`

---

### GET /videos/{video_id}

Get video details by ID.

**Path Parameters**:
- `video_id`: UUID of the video

---

### GET /videos/{video_id}/stream

**Business Context**: Returns HLS streaming URL with temporary token (1 hour validity). This is the core content delivery endpoint. Access control checks user tier against video requirements. For FREE/HYBRID users without access, checks if video was unlocked via ads batch. Supports quality selection based on user tier (FREE=720p, PREMIUM=4K).

Get streaming URL with temporary token.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `quality`: Preferred quality (360p, 720p, 1080p, 4k)

**Response** (200 OK):
```json
{
  "streaming_url": "https://cdn.example.com/hls/video/playlist.m3u8?token=xxx&quality=1080p",
  "token": "streaming_token",
  "expires_in": 3600,
  "quality": "1080p",
  "available_qualities": ["360p", "720p", "1080p", "4k"],
  "subtitles": {
    "it": "https://cdn.example.com/subs/video_it.vtt",
    "en": "https://cdn.example.com/subs/video_en.vtt"
  },
  "duration": 1800
}
```

**Errors**:
- `403` - Insufficient tier or ads unlock required

---

### POST /videos/{video_id}/favorite

Add video to My List.

**Headers**: `Authorization: Bearer <token>`

---

### DELETE /videos/{video_id}/favorite

Remove video from My List.

**Headers**: `Authorization: Bearer <token>`

---

### GET /videos/favorites

Get user's My List.

**Headers**: `Authorization: Bearer <token>`

---

### POST /videos/{video_id}/progress

Update viewing progress.

**Headers**: `Authorization: Bearer <token>`

**Request Body**:
```json
{
  "position_seconds": 450
}
```

---

### POST /videos (Admin)

Create new video entry.

**Headers**: `Authorization: Bearer <admin_token>`

**Request Body**:
```json
{
  "title": "New Video Title",
  "description": "Video description",
  "category": "technique",
  "difficulty": "intermediate",
  "style": "Karate",
  "tags": ["technique", "intermediate"],
  "tier_required": "premium",
  "is_premium": true,
  "ppv_price": 500,
  "instructor_name": "Sensei Mario"
}
```

---

### PUT /videos/{video_id} (Admin)

Update video metadata.

---

### DELETE /videos/{video_id} (Admin)

Delete video and associated files.

---

### POST /videos/ingest

Upload files for processing with optional skeleton extraction.

---

## Ads

### POST /ads/sessions/start

**Business Context**: Starts ads batch session for FREE/HYBRID users to unlock premium videos without subscription. Three batch types: 3_video (30s ads), 5_video (60s ads), 10_video (90s ads). User watches required ad duration, then gets temporary access to specified number of videos. This is the alternative monetization path for users who prefer ads over subscription.

Start ads batch session.

**Headers**: `Authorization: Bearer <token>`

**Request Body**:
```json
{
  "batch_type": "3_video"
}
```

**Response** (200 OK):
```json
{
  "session_id": "session-uuid",
  "batch_type": "3_video",
  "status": "active",
  "videos_to_unlock": 3,
  "ads_required_duration": 30
}
```

**Batch Types**:
| Type | Ads Duration | Videos Unlocked | Validity |
|------|-------------|-----------------|----------|
| `3_video` | 30s | 3 videos | 24h |
| `5_video` | 60s | 5 videos | 48h |
| `10_video` | 90s | 10 videos | 72h |

---

### POST /ads/sessions/{session_id}/view

Record ad view in batch session.

**Request Body**:
```json
{
  "ad_id": "ad-uuid",
  "duration": 30
}
```

---

### POST /ads/sessions/{session_id}/complete

Complete ads session and unlock videos.

---

### GET /ads/sessions/active

Get active ads session for current user.

---

### GET /ads/pause-ad

**Business Context**: Netflix-style pause ad overlay. When user pauses video, returns sponsored ad (50% screen) + suggested video (50% screen). Premium users see `show_overlay: false`. Impressions and clicks are tracked for advertiser billing. This is a non-intrusive monetization that only activates on user pause action.

Get pause ad overlay data.

**Headers**: `Authorization: Bearer <token>`

**Query Parameters**:
- `video_id` (required): UUID of video being paused

**Response** (200 OK):
```json
{
  "suggested_video": {
    "id": "video-uuid",
    "title": "Recommended: Advanced Kata",
    "thumbnail_url": "https://cdn.example.com/thumbs/suggested.jpg"
  },
  "sponsor_ad": {
    "id": "ad-uuid",
    "image_url": "https://cdn.example.com/ads/sponsor.jpg",
    "click_url": "https://sponsor.example.com",
    "advertiser": "Martial Arts Gear"
  },
  "impression_id": "impression-uuid",
  "show_overlay": true
}
```

---

### POST /ads/pause-ad/impression

Record impression when overlay is shown.

---

### POST /ads/pause-ad/click

Record click on ad or suggested video.

---

### GET /ads/pause-ad/stats (Admin)

Get pause ads statistics.

---

## Payments

### POST /payments/stelline/purchase

**Business Context**: Stelline are the platform's virtual currency (1 Stellina = €0.01). Users purchase stelline packages to donate to Maestros, unlock Pay-Per-View videos, or support ASDs. This creates a two-step payment flow: (1) Stripe Payment Intent, (2) Confirm after payment. Stelline enable micro-donations that would be impractical with direct payments.

Create Stripe Payment Intent for stelline purchase.

**Headers**: `Authorization: Bearer <token>`

**Request Body**:
```json
{
  "package": "medium"
}
```

**Stelline Packages**:
| Package | Stelline | Price EUR |
|---------|----------|-----------|
| `small` | 100 | €1.00 |
| `medium` | 500 | €4.50 |
| `large` | 1000 | €8.00 |

**Response** (200 OK):
```json
{
  "payment_intent_id": "pi_xxx",
  "client_secret": "pi_xxx_secret_xxx",
  "amount_eur": 4.50,
  "stelline_amount": 500,
  "payment_id": "payment-uuid"
}
```

---

### POST /payments/stelline/confirm

Confirm stelline purchase after payment succeeded.

**Request Body**:
```json
{
  "payment_intent_id": "pi_xxx"
}
```

---

### POST /payments/subscription/create

Create Stripe subscription for tier upgrade.

**Request Body**:
```json
{
  "tier": "PREMIUM"
}
```

---

### POST /payments/subscription/cancel

Cancel active subscription (remains active until period end).

---

### GET /payments/history

Get user's payment transaction history.

---

### POST /payments/video/{video_id}/purchase

Purchase video access with stelline (PPV).

---

### POST /payments/webhook

Stripe webhook handler (internal).

---

## Live Streaming

### POST /live/events (Admin)

Create a new live event.

**Request Body**:
```json
{
  "title": "Live Seminar: Advanced Kata",
  "description": "Interactive seminar with Q&A",
  "scheduled_start": "2026-01-20T18:00:00Z",
  "scheduled_end": "2026-01-20T20:00:00Z",
  "tier_required": "premium",
  "max_viewers": 500,
  "recording_enabled": true
}
```

**Response** (201 Created):
```json
{
  "id": "event-uuid",
  "title": "Live Seminar: Advanced Kata",
  "stream_key": "secret_stream_key_xxx",
  "rtmp_url": "rtmp://localhost:1935/live/secret_stream_key_xxx",
  "hls_url": null,
  "is_active": false,
  "scheduled_start": "2026-01-20T18:00:00Z"
}
```

---

### GET /live/events

List live events.

**Query Parameters**:
- `active_only`: Show only active streams

---

### GET /live/events/{event_id}

Get live event details.

---

### POST /live/events/{event_id}/start (Admin)

Start live event.

---

### POST /live/events/{event_id}/stop (Admin)

Stop live event.

---

### DELETE /live/events/{event_id} (Admin)

Delete live event.

---

### WebSocket /live/events/{event_id}/ws

WebSocket for live viewer count updates.

**Messages**:
```json
{"type": "viewer_count", "count": 150}
{"type": "ping", "message": "pong"}
```

---

## Blockchain

### POST /blockchain/batches/create (Admin)

**Business Context**: Weekly analytics data is aggregated and published to Polygon blockchain for transparency. This includes total views, unique users, watch time, and revenue. The hash serves as immutable proof of platform metrics. Useful for advertiser trust and regulatory compliance.

Create weekly batch for blockchain publication.

**Query Parameters**:
- `week_offset`: 0 = current week, -1 = last week

**Response** (200 OK):
```json
{
  "success": true,
  "batch_id": "batch-uuid",
  "week_start": "2026-01-13T00:00:00Z",
  "week_end": "2026-01-20T00:00:00Z",
  "message": "Batch created successfully"
}
```

---

### POST /blockchain/batches/{batch_id}/broadcast (Admin)

Broadcast batch to store nodes for validation.

---

### POST /blockchain/batches/{batch_id}/validate

Receive validation from a store node.

**Query Parameters**:
- `node_id`: ID of validating node
- `is_valid`: Validation result
- `computed_hash`: Hash computed by node
- `notes`: Optional notes

---

### POST /blockchain/batches/{batch_id}/publish (Admin)

Publish batch to Polygon blockchain after consensus (>51% nodes).

---

### GET /blockchain/batches/{batch_id}

Get batch status and details.

**Response** (200 OK):
```json
{
  "batch_id": "batch-uuid",
  "batch_date": "2026-01-17T00:00:00Z",
  "period_start": "2026-01-13T00:00:00Z",
  "period_end": "2026-01-20T00:00:00Z",
  "status": "published",
  "consensus_status": "published",
  "total_views": 150000,
  "unique_users": 5000,
  "total_watch_time": 450000,
  "total_revenue": 15000.00,
  "data_hash": "0x123abc...",
  "blockchain_tx_hash": "0x456def...",
  "published_at": "2026-01-17T12:00:00Z",
  "explorer_url": "https://polygonscan.com/tx/0x456def..."
}
```

---

## Communication

### POST /communication/messages

Send a message to another user.

**Request Body**:
```json
{
  "to_user_id": "recipient-uuid",
  "content": "Hello, I have a question about your kata video",
  "attachment_type": "video",
  "attachment_url": "https://cdn.example.com/uploads/question.mp4"
}
```

---

### GET /communication/messages

List messages for current user.

**Query Parameters**:
- `conversation_with`: Filter by conversation partner
- `unread_only`: Show only unread messages
- `page`: Page number
- `page_size`: Items per page

---

### PATCH /communication/messages/{message_id}/read

Mark message as read.

---

### GET /communication/messages/unread/count

Get count of unread messages.

---

### DELETE /communication/messages/{message_id}

Delete a message (sender only).

---

### POST /communication/corrections

**Business Context**: Correction request workflow enables students to submit practice videos to Maestros for personalized feedback. Maestros can respond with text, video, audio, or frame-by-frame annotations. This is a premium feature that differentiates the platform and enables direct student-maestro interaction.

Create a correction request for video feedback.

**Request Body**:
```json
{
  "maestro_id": "maestro-uuid",
  "video_url": "https://cdn.example.com/uploads/practice.mp4",
  "video_duration": 120.5,
  "notes": "Please review my kata form, especially the stances"
}
```

---

### GET /communication/corrections

List correction requests.

**Query Parameters**:
- `role`: Filter by role (student or maestro)
- `status_filter`: Filter by status

---

### GET /communication/corrections/{request_id}

Get correction request by ID.

---

### PATCH /communication/corrections/{request_id}

Update correction request (maestro provides feedback).

**Request Body**:
```json
{
  "status": "completed",
  "feedback_text": "Great progress! Focus on lowering your stance.",
  "feedback_video_url": "https://cdn.example.com/feedback/response.mp4",
  "feedback_annotations": [
    {"timestamp": 15.5, "note": "Lower stance here"},
    {"timestamp": 32.0, "note": "Good technique!"}
  ]
}
```

---

### WebSocket /communication/ws/chat/{user_id}

Real-time chat WebSocket.

**Send**:
```json
{"to_user_id": "recipient-uuid", "content": "Hello!"}
```

**Receive**:
```json
{"type": "new_message", "from_user_id": "sender-uuid", "content": "Hello!", "timestamp": "2026-01-17T10:00:00Z"}
```

---

## Moderation

### GET /moderation/videos/pending (Admin)

List videos pending moderation with validation info.

---

### POST /moderation/videos/{video_id}/approve (Admin)

Approve video and publish to platform.

**Request Body**:
```json
{
  "notes": "Approved - good content quality"
}
```

---

### POST /moderation/videos/{video_id}/reject (Admin)

Reject video with reason.

**Request Body**:
```json
{
  "rejection_reason": "Video quality too low, please re-upload in higher resolution"
}
```

---

### POST /moderation/videos/{video_id}/request-changes (Admin)

Request changes from video uploader.

**Request Body**:
```json
{
  "required_changes": [
    "Add better lighting",
    "Include audio explanation"
  ],
  "notes": "Good content, but needs some improvements"
}
```

---

### GET /moderation/videos/{video_id}/history (Admin)

Get moderation history for a video.

---

### GET /moderation/stats (Admin)

Get moderation statistics.

---

## Admin

### GET /admin/dashboard

Admin dashboard with comprehensive KPIs.

**Response** (200 OK):
```json
{
  "total_users": 15000,
  "total_maestros": 250,
  "total_asds": 50,
  "total_videos": 1200,
  "active_videos": 1100,
  "pending_moderation": {
    "videos": 25,
    "withdrawals": 10
  },
  "revenue_last_30_days": {
    "stelline": 1500000,
    "eur": 15000.00
  },
  "platform_status": "operational"
}
```

---

### GET /admin/analytics/platform

Platform-wide analytics.

**Query Parameters**:
- `period`: 7d, 30d, 90d, 365d

---

### GET /admin/users

List all users with pagination and search.

---

### GET /admin/users/{user_id}

Get detailed user information.

---

### POST /admin/users/{user_id}/ban

Ban a user.

**Request Body**:
```json
{
  "reason": "Violation of terms of service",
  "duration_days": 30
}
```

---

### POST /admin/users/{user_id}/unban

Unban a user.

---

### GET /admin/moderation/videos

Get videos pending moderation.

---

### POST /admin/moderation/videos/{video_id}

Approve or reject video.

---

### GET /admin/moderation/chat

Get flagged chat messages.

---

### DELETE /admin/moderation/chat/{message_id}

Delete chat message.

---

### GET /admin/donations

List donations with optional filters.

---

### GET /admin/donations/fraud-queue

Get donations flagged for AML review (>€15,000).

---

### GET /admin/withdrawals

List withdrawal requests.

---

### GET /admin/withdrawals/{withdrawal_id}

Get withdrawal request details.

---

### POST /admin/withdrawals/{withdrawal_id}/action

Approve or reject withdrawal.

---

### GET /admin/maestros

List all maestros.

---

### GET /admin/asds

List all ASDs (sports associations).

---

### GET /admin/config/tiers

Get tier configuration.

---

### PUT /admin/config/tiers

Update tier configuration.

---

## Subscriptions

### POST /subscriptions/upgrade/{tier}

Upgrade user subscription.

**Path Parameters**:
- `tier`: hybrid_light, hybrid_standard, premium, business

---

## Error Responses

All endpoints return consistent error responses:

```json
{
  "detail": "Error message describing the issue"
}
```

**Common HTTP Status Codes**:
| Code | Meaning |
|------|---------|
| `400` | Bad Request - Invalid input |
| `401` | Unauthorized - Missing or invalid token |
| `403` | Forbidden - Insufficient permissions |
| `404` | Not Found - Resource doesn't exist |
| `409` | Conflict - Resource already exists |
| `422` | Validation Error - Invalid request format |
| `500` | Internal Server Error |

---

## Rate Limits

| Endpoint Type | Limit |
|--------------|-------|
| Authentication | 10 requests/minute |
| API Calls | 100 requests/minute |
| File Uploads | 10 uploads/hour |
| WebSocket Messages | 100 messages/minute |

---

## WebSocket Endpoints Summary

| Endpoint | Purpose |
|----------|---------|
| `/live/events/{event_id}/ws` | Live viewer count |
| `/communication/ws/chat/{user_id}` | Real-time messaging |

---

*Documentation generated: 2026-01-17*
*API Version: 1.0.0*

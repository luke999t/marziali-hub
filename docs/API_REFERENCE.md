# Media Center Arti Marziali - API Reference

Complete API documentation for the Media Center Arti Marziali platform.

## Overview

- **Base URL**: `http://localhost:8000` (development) / `https://api.example.com` (production)
- **API Version**: v1
- **OpenAPI Version**: 3.1.0
- **Total Endpoints**: 547

## Authentication

Most endpoints require authentication via JWT Bearer token.

### Getting a Token

```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "password"}'
```

### Using the Token

```bash
curl http://localhost:8000/api/v1/users/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## API Sections

| Section | Endpoints | Description |
|---------|-----------|-------------|
| [Curriculum](api/curriculum.md) | 23 | Curriculum API |
| [Downloads](api/downloads.md) | 10 | Downloads API |
| [Gdpr](api/gdpr.md) | 4 | Gdpr API |
| [Scheduler Admin](api/scheduler_admin.md) | 10 | Scheduler Admin API |
| [Special Projects](api/special_projects.md) | 17 | Special Projects API |
| [Admin](api/admin.md) | 28 | Admin API |
| [Ads](api/ads.md) | 19 | Ads API |
| [Ai Coach](api/ai_coach.md) | 10 | Ai Coach API |
| [Asd](api/asd.md) | 11 | Asd API |
| [Audio](api/audio.md) | 23 | Audio API |
| [Auth](api/auth.md) | 8 | Auth API |
| [Blockchain](api/blockchain.md) | 5 | Blockchain API |
| [Communication](api/communication.md) | 18 | Communication API |
| [Contributions](api/contributions.md) | 19 | Contributions API |
| [Curriculum](api/curriculum.md) | 23 | Curriculum API |
| [Downloads](api/downloads.md) | 10 | Downloads API |
| [Events](api/events.md) | 78 | Events API |
| [Export](api/export.md) | 10 | Export API |
| [Fusion](api/fusion.md) | 17 | Fusion API |
| [Gdpr](api/gdpr.md) | 4 | Gdpr API |
| [Glasses](api/glasses.md) | 2 | Glasses API |
| [Ingest](api/ingest.md) | 23 | Ingest API |
| [Library](api/library.md) | 18 | Library API |
| [Live](api/live.md) | 6 | Live API |
| [Live Translation](api/live_translation.md) | 6 | Live Translation API |
| [Maestro](api/maestro.md) | 13 | Maestro API |
| [Masters](api/masters.md) | 5 | Masters API |
| [Moderation](api/moderation.md) | 6 | Moderation API |
| [Notifications](api/notifications.md) | 15 | Notifications API |
| [Payments](api/payments.md) | 6 | Payments API |
| [Royalties](api/royalties.md) | 15 | Royalties API |
| [Scheduler](api/scheduler.md) | 10 | Scheduler API |
| [Skeleton](api/skeleton.md) | 9 | Skeleton API |
| [Special Projects](api/special_projects.md) | 17 | Special Projects API |
| [Students](api/students.md) | 4 | Students API |
| [Subscriptions](api/subscriptions.md) | 1 | Subscriptions API |
| [System](api/system.md) | 1 | System API |
| [Temp Zone](api/temp_zone.md) | 10 | Temp Zone API |
| [Tracking](api/tracking.md) | 2 | Tracking API |
| [Untagged](api/untagged.md) | 3 | Untagged API |
| [Users](api/users.md) | 3 | Users API |
| [Video Studio](api/video_studio.md) | 6 | Video Studio API |
| [Videos](api/videos.md) | 19 | Videos API |

## Quick Links

- [Authentication](api/auth.md) - Login, register, token refresh
- [Users](api/users.md) - User management
- [Videos](api/videos.md) - Video content management
- [Live](api/live.md) - Live streaming
- [Payments](api/payments.md) - Payment processing
- [Admin](api/admin.md) - Administration

## Error Handling

All API errors follow a consistent format:

```json
{
  "detail": "Error message description",
  "status_code": 400
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| 400 | Bad Request - Invalid input |
| 401 | Unauthorized - Missing or invalid token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 422 | Validation Error - Invalid data format |
| 429 | Too Many Requests - Rate limited |
| 500 | Internal Server Error |

## Rate Limiting

API requests are rate limited:
- Anonymous: 100 requests/minute
- Authenticated: 1000 requests/minute
- Admin: 5000 requests/minute

## Pagination

List endpoints support pagination:

```
GET /api/v1/videos?skip=0&limit=20
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| skip | integer | 0 | Number of items to skip |
| limit | integer | 20 | Maximum items to return |

## OpenAPI Spec

The complete OpenAPI specification is available at:
- JSON: `/openapi.json`
- Swagger UI: `/docs`
- ReDoc: `/redoc`

---

*Generated automatically from OpenAPI specification*

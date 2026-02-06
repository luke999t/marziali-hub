# Ads API

API endpoints for ads functionality.

## Table of Contents

- [POST /api/v1/ads/batch/start](#post--api-v1-ads-batch-start) - Start Batch
- [POST /api/v1/ads/view](#post--api-v1-ads-view) - Record View
- [POST /api/v1/ads/batch/{session_id}/complete](#post--api-v1-ads-batch-session_id-complete) - Complete Batch
- [GET /api/v1/ads/batch/active](#get--api-v1-ads-batch-active) - Get Active Batch
- [GET /api/v1/ads/batch/expired](#get--api-v1-ads-batch-expired) - Get Expired Batches
- [GET /api/v1/ads/batch/{session_id}](#get--api-v1-ads-batch-session_id) - Get Batch Status
- [DELETE /api/v1/ads/batch/{session_id}](#delete--api-v1-ads-batch-session_id) - Abandon Batch
- [GET /api/v1/ads/next](#get--api-v1-ads-next) - Get Next Ad
- [GET /api/v1/ads/stats](#get--api-v1-ads-stats) - Get User Ads Stats
- [POST /api/v1/ads/sessions/start](#post--api-v1-ads-sessions-start) - Start Ads Session
- [POST /api/v1/ads/sessions/{session_id}/view](#post--api-v1-ads-sessions-session_id-view) - Record Ad View
- [POST /api/v1/ads/sessions/{session_id}/complete](#post--api-v1-ads-sessions-session_id-complete) - Complete Ads Session
- [GET /api/v1/ads/sessions/active](#get--api-v1-ads-sessions-active) - Get Active Session
- [GET /api/v1/ads/pause-ad](#get--api-v1-ads-pause-ad) - Get Pause Ad
- [POST /api/v1/ads/pause-ad/impression](#post--api-v1-ads-pause-ad-impression) - Record Pause Ad Impression
- [POST /api/v1/ads/pause-ad/click](#post--api-v1-ads-pause-ad-click) - Record Pause Ad Click
- [GET /api/v1/ads/pause-ad/stats](#get--api-v1-ads-pause-ad-stats) - Get Pause Ad Stats
- [GET /api/v1/ads/available](#get--api-v1-ads-available) - Get Available Ads
- [GET /api/v1/ads/sessions/history](#get--api-v1-ads-sessions-history) - Get Session History

---

## POST /api/v1/ads/batch/start

**Description**: Start ads batch session (alternative path).

Test compatibility endpoint for /batch/start

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/ads/view

**Description**: Record ad view (without session in path).

Test compatibility endpoint for /view

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/ads/batch/{session_id}/complete

**Description**: Complete ads batch session (alternative path).

Test compatibility endpoint for /batch/{id}/complete

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ads/batch/active

**Description**: Get active batch session for current user.

Alternative path for test compatibility.

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/ads/batch/expired

**Description**: Check for expired batch sessions.

Returns information about expired sessions.

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/ads/batch/{session_id}

**Description**: Get batch session status.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/ads/batch/{session_id}

**Description**: Abandon ads batch session.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ads/next

**Description**: Get next ad for user.

Returns ad based on user tier and position.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| position | string | No | Ad position (default: pre_roll) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ads/stats

**Description**: Get ads statistics for current user.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/ads/sessions/start

**Description**: Start ads batch session.

BUSINESS_PURPOSE: Utente FREE/HYBRID avvia sessione per sbloccare video

DECISION_TREE:
1. Se utente PREMIUM/BUSINESS -> 400 (non richiede ads)
2. Se sessione attiva esiste -> Ritorna esistente
3. Se tutto OK -> Crea nuova sessione

Args:
    data: Batch type (3_video, 5_video, 10_video)
    request: FastAPI request per IP/user-agent
    db: Database session
    current_user: Authenticated user

Returns:
    AdsSessionResponse con dettagli sessione

Raises:
    HTTPException 400: Se utente non puo vedere ads
    HTTPException 400: Se batch type invalido

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| batch_type | AdsBatchType | Yes | - |

**Request Example**:
```json
{
  "batch_type": "3_video"
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "batch_type": "string",
  "ads_required_duration": 1,
  "videos_to_unlock": 1,
  "validity_hours": 1,
  "status": "string",
  "total_duration_watched": 1,
  "progress_percentage": 1.0,
  "estimated_revenue": 1.0,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ads/sessions/{session_id}/view

**Description**: Record single ad view in batch session.

Args:
    session_id: UUID della sessione
    ad_id: UUID dell'ad visualizzato
    duration: Durata in secondi
    db: Database session
    current_user: Authenticated user

Returns:
    Updated session info

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| ad_id | string | Yes | - |
| duration | integer | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ads/sessions/{session_id}/complete

**Description**: Complete ads session and unlock videos.

BUSINESS_PURPOSE: Utente ha completato ads, sblocca video

Args:
    session_id: UUID della sessione
    db: Database session
    current_user: Authenticated user

Returns:
    MessageResponse con esito

Raises:
    HTTPException 400: Se sessione non completabile

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| session_id | string | Yes | - |

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

## GET /api/v1/ads/sessions/active

**Description**: Get active ads session for current user.

Returns:
    Active session or null

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/ads/pause-ad

**Description**: Get pause ad + suggested video per overlay.

BUSINESS_PURPOSE: Chiamato quando utente mette in pausa video
TECHNICAL_EXPLANATION: Ritorna dati per overlay 50/50

DECISION_TREE:
1. Se utente PREMIUM/BUSINESS -> show_overlay=false
2. Se no ads disponibili -> Solo suggested_video
3. Se tutto OK -> Full overlay data

Args:
    video_id: UUID del video corrente
    request: FastAPI request per context
    db: Database session
    current_user: Authenticated user

Returns:
    PauseAdResponse con suggested_video, sponsor_ad, impression_id

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| video_id | string | Yes | UUID del video in pausa |

**Response 200**:
Successful Response

```json
{
  "suggested_video": {},
  "sponsor_ad": {},
  "impression_id": "string",
  "show_overlay": false
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ads/pause-ad/impression

**Description**: Record impression quando overlay viene mostrato.

BUSINESS_PURPOSE: Conferma impression per billing advertiser

Args:
    data: impression_id, video_id
    db: Database session
    current_user: Authenticated user

Returns:
    MessageResponse con esito

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| impression_id | string | Yes | UUID impression da confermare |
| video_id | string | Yes | UUID video in cui e apparso overlay |

**Request Example**:
```json
{
  "impression_id": "string",
  "video_id": "string"
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

## POST /api/v1/ads/pause-ad/click

**Description**: Record click su ad o video suggerito.

BUSINESS_PURPOSE: Tracking conversioni per revenue bonus

Args:
    data: impression_id, click_type ("ad" | "suggested")
    db: Database session
    current_user: Authenticated user

Returns:
    MessageResponse con esito

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| impression_id | string | Yes | UUID impression |
| click_type | string | Yes | Tipo click: 'ad' (sponsor) o 'suggested' (video) |

**Request Example**:
```json
{
  "impression_id": "string",
  "click_type": "string"
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

## GET /api/v1/ads/pause-ad/stats

**Description**: Get pause ads statistics (admin only).

BUSINESS_PURPOSE: Analytics per dashboard admin

Args:
    start_date: Data inizio (default: 7 giorni fa)
    end_date: Data fine (default: ora)
    db: Database session
    current_user: Admin user

Returns:
    PauseAdStatsResponse con statistiche aggregate

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| start_date | string | No | Data inizio periodo |
| end_date | string | No | Data fine periodo |

**Response 200**:
Successful Response

```json
{
  "period": {},
  "impressions": {},
  "clicks": {},
  "revenue": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ads/available

**Description**: Get available ads for current user (for batch ads).

Args:
    limit: Max number of ads to return
    db: Database session
    current_user: Authenticated user

Returns:
    List of available ads

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 10) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ads/sessions/history

**Description**: Get ads session history for current user.

Args:
    limit: Max number of sessions to return
    db: Database session
    current_user: Authenticated user

Returns:
    List of past sessions

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 20) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


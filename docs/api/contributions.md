# Contributions API

API endpoints for contributions functionality.

## Table of Contents

- [POST /api/v1/contributions/staff](#post--api-v1-contributions-staff) - Crea membro staff
- [GET /api/v1/contributions/staff](#get--api-v1-contributions-staff) - Lista membri staff
- [GET /api/v1/contributions/staff/{member_id}](#get--api-v1-contributions-staff-member_id) - Get Staff Member
- [PUT /api/v1/contributions/staff/{member_id}](#put--api-v1-contributions-staff-member_id) - Update Staff Member
- [GET /api/v1/contributions/staff/me/profile](#get--api-v1-contributions-staff-me-profile) - Get My Staff Profile
- [GET /api/v1/contributions/admin/stats](#get--api-v1-contributions-admin-stats) - Statistiche sistema
- [GET /api/v1/contributions/admin/audit](#get--api-v1-contributions-admin-audit) - Audit log globale
- [GET /api/v1/contributions/my-contributions](#get--api-v1-contributions-my-contributions) - I miei contributi
- [POST /api/v1/contributions/](#post--api-v1-contributions-) - Crea contributo
- [GET /api/v1/contributions/](#get--api-v1-contributions-) - Lista contributi
- [GET /api/v1/contributions/{contribution_id}](#get--api-v1-contributions-contribution_id) - Get Contribution
- [PUT /api/v1/contributions/{contribution_id}](#put--api-v1-contributions-contribution_id) - Update Contribution
- [DELETE /api/v1/contributions/{contribution_id}](#delete--api-v1-contributions-contribution_id) - Elimina contributo
- [POST /api/v1/contributions/{contribution_id}/submit](#post--api-v1-contributions-contribution_id-submit) - Submit For Review
- [POST /api/v1/contributions/{contribution_id}/approve](#post--api-v1-contributions-contribution_id-approve) - Approve Contribution
- [POST /api/v1/contributions/{contribution_id}/reject](#post--api-v1-contributions-contribution_id-reject) - Reject Contribution
- [GET /api/v1/contributions/{contribution_id}/history](#get--api-v1-contributions-contribution_id-history) - Storico versioni
- [GET /api/v1/contributions/{contribution_id}/history/{version_number}](#get--api-v1-contributions-contribution_id-history-version_number) - Get Contribution Version
- [GET /api/v1/contributions/{contribution_id}/audit](#get--api-v1-contributions-contribution_id-audit) - Audit log contributo

---

## POST /api/v1/contributions/staff

**Description**: Crea un nuovo membro staff (solo admin).

Ruoli disponibili:
- **admin**: Accesso completo
- **moderator**: Approva/rifiuta contributi
- **translator**: Traduce contenuti
- **reviewer**: Revisiona traduzioni
- **contributor**: Contributi base
- **viewer**: Solo lettura

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| user_id | string | Yes | ID utente nel sistema principale |
| username | string | Yes | - |
| email | string | Yes | - |
| role | any | No | - |
| projects | any | No | Progetti assegnati |

**Request Example**:
```json
{
  "user_id": "string",
  "username": "string",
  "email": "user@example.com",
  "role": "contributor",
  "projects": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "user_id": "string",
  "username": "string",
  "email": "string",
  "role": "string",
  "permissions": [
    "string"
  ],
  "projects": [
    "string"
  ],
  "is_active": true,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/staff

**Description**: Lista tutti i membri staff con filtri.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| role | string | No | - |
| is_active | boolean | No | - (default: True) |
| limit | integer | No | - (default: 100) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/staff/{member_id}

**Description**: Ottiene dettagli membro staff.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| member_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "user_id": "string",
  "username": "string",
  "email": "string",
  "role": "string",
  "permissions": [
    "string"
  ],
  "projects": [
    "string"
  ],
  "is_active": true,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/contributions/staff/{member_id}

**Description**: Aggiorna membro staff (solo admin).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| member_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| username | any | No | - |
| email | any | No | - |
| role | any | No | - |
| projects | any | No | - |
| is_active | any | No | - |

**Request Example**:
```json
{
  "username": {},
  "email": {},
  "role": {},
  "projects": {},
  "is_active": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "user_id": "string",
  "username": "string",
  "email": "string",
  "role": "string",
  "permissions": [
    "string"
  ],
  "projects": [
    "string"
  ],
  "is_active": true,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/staff/me/profile

**Description**: Ottiene il proprio profilo staff.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "user_id": "string",
  "username": "string",
  "email": "string",
  "role": "string",
  "permissions": [
    "string"
  ],
  "projects": [
    "string"
  ],
  "is_active": true,
  "created_at": "string",
  "updated_at": "string"
}
```

---

## GET /api/v1/contributions/admin/stats

**Description**: Ottiene statistiche complete del sistema (solo admin).

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "staff": {},
  "contributions": {},
  "versioning": {},
  "workflow": {}
}
```

---

## GET /api/v1/contributions/admin/audit

**Description**: Ottiene l'audit log globale (solo admin).

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| actor_id | string | No | - |
| limit | integer | No | - (default: 100) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/my-contributions

**Description**: Ottiene i contributi dell'utente corrente.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| status | string | No | - |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/contributions/

**Description**: Crea un nuovo contributo.

Tipi disponibili:
- **translation**: Traduzione testo
- **transcription**: Trascrizione audio/video
- **annotation**: Annotazione video
- **correction**: Correzione contenuto
- **glossary**: Voce glossario
- **subtitle**: Sottotitoli
- **voiceover**: Voice over
- **knowledge**: Knowledge base entry
- **technique**: Descrizione tecnica
- **metadata**: Metadata video

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| content_type | ContributionTypeEnum | Yes | - |
| content | object | Yes | Contenuto strutturato |
| project_id | any | No | - |
| tags | any | No | - |

**Request Example**:
```json
{
  "title": "string",
  "content_type": "translation",
  "content": {},
  "project_id": {},
  "tags": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/

**Description**: Lista contributi con filtri.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contributor_id | string | No | - |
| project_id | string | No | - |
| status | string | No | - |
| content_type | string | No | - |
| limit | integer | No | - (default: 50) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/{contribution_id}

**Description**: Ottiene dettagli contributo.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/contributions/{contribution_id}

**Description**: Aggiorna contributo.

Crea automaticamente una nuova versione se il contenuto cambia.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | any | No | - |
| content | any | No | - |
| tags | any | No | - |
| change_summary | any | No | - |

**Request Example**:
```json
{
  "title": {},
  "content": {},
  "tags": {},
  "change_summary": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/contributions/{contribution_id}

**Description**: Elimina un contributo.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/contributions/{contribution_id}/submit

**Description**: Sottomette un contributo per revisione.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| priority | string | No | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "priority": "normal",
  "notes": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/contributions/{contribution_id}/approve

**Description**: Approva un contributo (richiede permesso APPROVE_CONTRIBUTION).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| notes | string | No | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/contributions/{contribution_id}/reject

**Description**: Rifiuta un contributo (richiede permesso REJECT_CONTRIBUTION).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| reason | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "contributor_id": "string",
  "project_id": {},
  "content_type": "string",
  "status": "string",
  "title": "string",
  "content": {},
  "current_version": 1,
  "created_at": "string",
  "updated_at": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/{contribution_id}/history

**Description**: Ottiene lo storico delle versioni di un contributo.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/{contribution_id}/history/{version_number}

**Description**: Ottiene una specifica versione di un contributo.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |
| version_number | integer | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/contributions/{contribution_id}/audit

**Description**: Ottiene l'audit log di un contributo.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| contribution_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 50) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


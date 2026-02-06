# Special Projects API

API endpoints for special projects functionality.

## Table of Contents

- [GET /api/v1/special-projects](#get--api-v1-special-projects) - Lista progetti speciali
- [GET /api/v1/special-projects/votable](#get--api-v1-special-projects-votable) - Lista progetti votabili
- [GET /api/v1/special-projects/health](#get--api-v1-special-projects-health) - Health check
- [GET /api/v1/special-projects/my-eligibility](#get--api-v1-special-projects-my-eligibility) - Verifica mia eligibilità voto
- [GET /api/v1/special-projects/my-vote](#get--api-v1-special-projects-my-vote) - Il mio voto corrente
- [GET /api/v1/special-projects/my-history](#get--api-v1-special-projects-my-history) - Storico miei voti
- [GET /api/v1/special-projects/slug/{slug}](#get--api-v1-special-projects-slug-slug) - Dettaglio progetto per slug
- [GET /api/v1/special-projects/{project_id}](#get--api-v1-special-projects-project_id) - Dettaglio progetto
- [POST /api/v1/special-projects/{project_id}/vote](#post--api-v1-special-projects-project_id-vote) - Vota per progetto
- [GET /api/v1/special-projects/admin/test-bypass](#get--api-v1-special-projects-admin-test-bypass) - Test Bypass
- [POST /api/v1/special-projects/admin/projects](#post--api-v1-special-projects-admin-projects) - Crea progetto (admin)
- [PUT /api/v1/special-projects/admin/projects/{project_id}](#put--api-v1-special-projects-admin-projects-project_id) - Aggiorna progetto (admin)
- [DELETE /api/v1/special-projects/admin/projects/{project_id}](#delete--api-v1-special-projects-admin-projects-project_id) - Elimina progetto (admin)
- [GET /api/v1/special-projects/admin/config](#get--api-v1-special-projects-admin-config) - Ottieni configurazione (admin)
- [PUT /api/v1/special-projects/admin/config](#put--api-v1-special-projects-admin-config) - Aggiorna configurazione (admin)
- [GET /api/v1/special-projects/admin/stats](#get--api-v1-special-projects-admin-stats) - Statistiche votazione (admin)
- [POST /api/v1/special-projects/admin/close-cycle](#post--api-v1-special-projects-admin-close-cycle) - Chiudi ciclo votazione (admin)

---

## GET /api/v1/special-projects

**Description**: Lista progetti speciali pubblici.

- Utenti vedono solo progetti attivi
- Ordinati per weighted_votes decrescente
- Paginazione standard

**Authentication**: None

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| status | string | No | Filtra per status |
| page | integer | No | Pagina (default: 1) |
| page_size | integer | No | Elementi per pagina (default: 20) |

**Response 200**:
Successful Response

```json
{
  "projects": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "string",
      "slug": "string",
      "description": "string",
      "short_description": {},
      "image_url": {},
      "video_url": {},
      "status": "...",
      "estimated_budget_cents": {},
      "estimated_days": {}
    }
  ],
  "total": 1,
  "page": 1,
  "page_size": 1,
  "total_pages": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/votable

**Description**: Lista progetti attualmente aperti al voto.

Solo progetti ACTIVE con date votazione valide.

**Authentication**: None

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "string",
    "slug": "string",
    "description": "string",
    "short_description": {},
    "image_url": {},
    "video_url": {},
    "status": "draft",
    "estimated_budget_cents": {},
    "estimated_days": {}
  }
]
```

---

## GET /api/v1/special-projects/health

**Description**: Health check endpoint.

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/special-projects/my-eligibility

**Description**: Verifica se utente corrente può votare.

Ritorna:
- Status eligibilità (eligible, not_eligible, pending)
- Peso voto
- Progress requisiti (per free users)

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| force_recalculate | boolean | No | Forza ricalcolo (default: False) |

**Response 200**:
Successful Response

```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "eligible",
  "vote_weight": 1,
  "subscription_tier": "string",
  "can_vote": true,
  "vote_cycle": "string",
  "watch_minutes_current": 1,
  "watch_minutes_required": {},
  "ads_watched_current": 1,
  "ads_watched_required": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/my-vote

**Description**: Ottiene voto corrente dell'utente.

Include:
- Voto attuale (se esiste)
- Possibilità di cambiare
- Peso voto attuale

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "has_voted": true,
  "current_vote": {},
  "can_change": true,
  "next_change_available": {},
  "vote_weight": 1,
  "eligibility_status": "eligible"
}
```

---

## GET /api/v1/special-projects/my-history

**Description**: Storico voti utente negli ultimi N cicli.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | Numero cicli (default: 12) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "project_id": "550e8400-e29b-41d4-a716-446655440000",
    "project_title": {},
    "vote_weight": 1,
    "subscription_tier_at_vote": "string",
    "vote_cycle": "string",
    "is_active": true,
    "voted_at": "2024-01-15T10:30:00Z",
    "changed_from_previous": true
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/slug/{slug}

**Description**: Ottiene progetto per URL slug.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| slug | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": "string",
  "description": "string",
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "status": "draft",
  "estimated_budget_cents": {},
  "estimated_days": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/{project_id}

**Description**: Ottiene dettaglio singolo progetto.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": "string",
  "description": "string",
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "status": "draft",
  "estimated_budget_cents": {},
  "estimated_days": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/special-projects/{project_id}/vote

**Description**: Registra voto per progetto.

Rules:
- 1 voto per ciclo
- Non può cambiare nello stesso mese (default)
- Peso basato su subscription tier

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| confirm_change | boolean | No | Conferma cambio voto (default: False) |

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_id": "550e8400-e29b-41d4-a716-446655440000",
  "project_title": {},
  "vote_weight": 1,
  "subscription_tier_at_vote": "string",
  "vote_cycle": "string",
  "is_active": true,
  "voted_at": "2024-01-15T10:30:00Z",
  "changed_from_previous": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/admin/test-bypass

**Description**: TEST: Endpoint senza auth per verificare routing

**Authentication**: None

**Response 200**:
Successful Response

---

## POST /api/v1/special-projects/admin/projects

**Description**: Crea nuovo progetto speciale.

Solo admin può creare progetti.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | string | Yes | - |
| description | string | Yes | - |
| short_description | any | No | - |
| image_url | any | No | - |
| video_url | any | No | - |
| estimated_budget_cents | any | No | - |
| estimated_days | any | No | - |
| funding_goal_cents | any | No | - |
| tags | any | No | - |
| voting_start_date | any | No | - |
| voting_end_date | any | No | - |

**Request Example**:
```json
{
  "title": "string",
  "description": "string",
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "estimated_budget_cents": {},
  "estimated_days": {},
  "funding_goal_cents": {},
  "tags": {},
  "voting_start_date": {}
}
```

**Response 201**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": "string",
  "description": "string",
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "status": "draft",
  "estimated_budget_cents": {},
  "estimated_days": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## PUT /api/v1/special-projects/admin/projects/{project_id}

**Description**: Aggiorna progetto esistente.

Può cambiare status, contenuto, date votazione.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| title | any | No | - |
| description | any | No | - |
| short_description | any | No | - |
| image_url | any | No | - |
| video_url | any | No | - |
| estimated_budget_cents | any | No | - |
| estimated_days | any | No | - |
| funding_goal_cents | any | No | - |
| status | any | No | - |
| tags | any | No | - |
| voting_start_date | any | No | - |
| voting_end_date | any | No | - |

**Request Example**:
```json
{
  "title": {},
  "description": {},
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "estimated_budget_cents": {},
  "estimated_days": {},
  "funding_goal_cents": {},
  "status": {},
  "tags": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "title": "string",
  "slug": "string",
  "description": "string",
  "short_description": {},
  "image_url": {},
  "video_url": {},
  "status": "draft",
  "estimated_budget_cents": {},
  "estimated_days": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/special-projects/admin/projects/{project_id}

**Description**: Soft delete progetto.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| project_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/admin/config

**Description**: Ottiene configurazione corrente sistema votazione.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "vote_weights": {},
  "free_user_requirements": {},
  "voting_rules": {},
  "project_settings": {}
}
```

---

## PUT /api/v1/special-projects/admin/config

**Description**: Aggiorna singola chiave configurazione.

Salva in database per override runtime.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| config_key | string | Yes | Chiave config da aggiornare |
| config_value | any | Yes | Nuovo valore |
| change_reason | any | No | - |

**Request Example**:
```json
{
  "config_key": "string",
  "config_value": {},
  "change_reason": {}
}
```

**Response 200**:
Successful Response

```json
{
  "vote_weights": {},
  "free_user_requirements": {},
  "voting_rules": {},
  "project_settings": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/special-projects/admin/stats

**Description**: Statistiche aggregate votazione.

Include partecipazione, breakdown per tier, top projects.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| cycle | string | No | Ciclo (es: 2024-01) |

**Response 200**:
Successful Response

```json
{
  "vote_cycle": "string",
  "total_eligible_voters": 1,
  "total_votes_cast": 1,
  "participation_rate": 1.0,
  "votes_by_tier": {},
  "weighted_votes_by_tier": {},
  "top_projects": [
    {}
  ],
  "votes_per_day": [
    {}
  ]
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/special-projects/admin/close-cycle

**Description**: Chiude ciclo votazione e determina vincitore.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| cycle | string | No | Ciclo da chiudere |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


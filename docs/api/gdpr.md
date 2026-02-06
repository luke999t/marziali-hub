# Gdpr API

API endpoints for gdpr functionality.

## Table of Contents

- [GET /api/v1/me/gdpr-data](#get--api-v1-me-gdpr-data) - Export Gdpr Data
- [DELETE /api/v1/me/gdpr-data](#delete--api-v1-me-gdpr-data) - Request Data Deletion
- [GET /api/v1/me/consent](#get--api-v1-me-consent) - Get Consent Status
- [POST /api/v1/me/consent](#post--api-v1-me-consent) - Update Consent

---

## GET /api/v1/me/gdpr-data

**Description**: Esporta tutti i dati personali dell'utente (Art. 15 GDPR).

Restituisce:
- Dati profilo utente
- Tutte le iscrizioni eventi
- Tutte le voci in waiting list

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "user": {},
  "subscriptions": [
    {
      "id": "string",
      "event_title": "string",
      "option_name": "string",
      "status": "string",
      "amount_cents": 1,
      "participant_name": {},
      "participant_email": {},
      "participant_phone": {},
      "dietary_requirements": {},
      "notes": {}
    }
  ],
  "waiting_list": [
    {
      "id": "string",
      "event_title": "string",
      "is_active": true,
      "notified_at": {},
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "exported_at": "2024-01-15T10:30:00Z"
}
```

---

## DELETE /api/v1/me/gdpr-data

**Description**: Richiesta cancellazione dati (Art. 17 GDPR - Diritto all'oblio).

NOTA: Non cancella fisicamente i record per motivi fiscali/legali.
Invece, anonimizza i dati personali:
- participant_name → "GDPR_DELETED"
- participant_email → null
- participant_phone → null
- dietary_requirements → null
- notes → null
- gdpr_consent → false
- marketing_consent → false

I record di pagamento sono mantenuti per obblighi fiscali (10 anni).

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| reason | any | No | Motivazione richiesta cancellazione |
| confirm | boolean | Yes | Conferma cancellazione |

**Request Example**:
```json
{
  "reason": {},
  "confirm": true
}
```

**Response 200**:
Successful Response

```json
{
  "message": "string",
  "anonymized_records": 1,
  "deletion_scheduled": true
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/me/consent

**Description**: Ottiene lo stato attuale dei consensi utente.

Restituisce i consensi dall'iscrizione più recente.

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "gdpr_consent": true,
  "gdpr_consent_at": {},
  "marketing_consent": true,
  "marketing_consent_at": {}
}
```

---

## POST /api/v1/me/consent

**Description**: Aggiorna preferenze consenso utente (Art. 7 GDPR).

Aggiorna il consenso su TUTTE le iscrizioni attive dell'utente.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| gdpr_consent | any | No | Consenso trattamento dati |
| marketing_consent | any | No | Consenso marketing |

**Request Example**:
```json
{
  "gdpr_consent": {},
  "marketing_consent": {}
}
```

**Response 200**:
Successful Response

```json
{
  "gdpr_consent": true,
  "gdpr_consent_at": {},
  "marketing_consent": true,
  "marketing_consent_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---


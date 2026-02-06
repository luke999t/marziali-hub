# Temp Zone API

API endpoints for temp zone functionality.

## Table of Contents

- [GET /api/v1/admin/temp-zone/stats](#get--api-v1-admin-temp-zone-stats) - Statistiche Temp Zone
- [GET /api/v1/admin/temp-zone/batches](#get--api-v1-admin-temp-zone-batches) - Lista Batch
- [GET /api/v1/admin/temp-zone/batches/{batch_id}](#get--api-v1-admin-temp-zone-batches-batch_id) - Dettaglio Batch
- [DELETE /api/v1/admin/temp-zone/batches/{batch_id}](#delete--api-v1-admin-temp-zone-batches-batch_id) - Cancella Batch
- [POST /api/v1/admin/temp-zone/cleanup](#post--api-v1-admin-temp-zone-cleanup) - Cleanup Bulk
- [GET /api/v1/admin/temp-zone/expiring](#get--api-v1-admin-temp-zone-expiring) - Batch in Scadenza
- [GET /api/v1/admin/temp-zone/audit](#get--api-v1-admin-temp-zone-audit) - Audit Log
- [GET /api/v1/admin/temp-zone/config](#get--api-v1-admin-temp-zone-config) - Configurazione Corrente
- [PATCH /api/v1/admin/temp-zone/config](#patch--api-v1-admin-temp-zone-config) - Aggiorna Configurazione
- [GET /api/v1/admin/temp-zone/batch-types](#get--api-v1-admin-temp-zone-batch-types) - Tipi Batch Supportati

---

## GET /api/v1/admin/temp-zone/stats

**Description**: Recupera statistiche aggregate della temp zone

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "total_batches": 1,
  "total_size_bytes": 1,
  "total_size_formatted": "string",
  "total_files": 1,
  "oldest_batch_days": 1,
  "expiring_soon": 1,
  "by_status": {},
  "by_type": {},
  "config": {},
  "limits": {}
}
```

---

## GET /api/v1/admin/temp-zone/batches

**Description**: Lista batch con filtri e paginazione

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| status | string | No | Filtra per status (processing, completed, failed, expired) |
| batch_type | string | No | Filtra per tipo batch |
| created_by | string | No | Filtra per creatore |
| limit | integer | No | Max risultati (default: 50) |
| offset | integer | No | Offset paginazione (default: 0) |

**Response 200**:
Successful Response

```json
{
  "batches": [
    {
      "id": "string",
      "batch_type": "string",
      "created_at": "2024-01-15T10:30:00Z",
      "status": "string",
      "size_bytes": 1,
      "size_formatted": "string",
      "file_count": 1,
      "created_by": "string",
      "updated_at": {},
      "expires_at": {}
    }
  ],
  "total": 1,
  "filtered": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/temp-zone/batches/{batch_id}

**Description**: Recupera dettagli di un singolo batch

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "batch_type": "string",
  "created_at": "2024-01-15T10:30:00Z",
  "status": "string",
  "size_bytes": 1,
  "size_formatted": "string",
  "file_count": 1,
  "created_by": "string",
  "updated_at": {},
  "expires_at": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/admin/temp-zone/batches/{batch_id}

**Description**: Cancella un batch e tutti i suoi file (richiede ADMIN)

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/admin/temp-zone/cleanup

**Description**: Cancella batch in bulk (richiede ADMIN)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| delete_completed | boolean | No | Cancella tutti i batch completati |
| delete_failed | boolean | No | Cancella tutti i batch falliti |
| older_than_days | any | No | Solo batch più vecchi di X giorni |
| confirm | boolean | Yes | Conferma operazione (deve essere true) |

**Request Example**:
```json
{
  "delete_completed": false,
  "delete_failed": false,
  "older_than_days": {},
  "confirm": true
}
```

**Response 200**:
Successful Response

```json
{
  "deleted_count": 1,
  "freed_bytes": 1,
  "freed_formatted": "string",
  "message": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/temp-zone/expiring

**Description**: Lista batch che scadranno entro il periodo di warning

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "batch_type": "string",
    "created_at": "2024-01-15T10:30:00Z",
    "status": "string",
    "size_bytes": 1,
    "size_formatted": "string",
    "file_count": 1,
    "created_by": "string",
    "updated_at": {},
    "expires_at": {}
  }
]
```

---

## GET /api/v1/admin/temp-zone/audit

**Description**: Recupera audit log delle operazioni (richiede ADMIN)

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| action | string | No | Filtra per action (CREATE, DELETE, CONFIG_CHANGE, etc.) |
| target_id | string | No | Filtra per target ID |
| limit | integer | No | - (default: 100) |

**Response 200**:
Successful Response

```json
{
  "entries": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "action": "string",
      "target_id": "string",
      "user_id": "string",
      "details": {}
    }
  ],
  "total": 1
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/temp-zone/config

**Description**: Recupera configurazione temp zone

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "auto_cleanup_enabled": true,
  "delete_after_days": 1,
  "warn_before_days": 1,
  "secure_delete": true,
  "temp_base_path": "string",
  "max_batch_size_gb": 1.0,
  "max_total_size_gb": 1.0
}
```

---

## PATCH /api/v1/admin/temp-zone/config

**Description**: Modifica configurazione temp zone (richiede ADMIN)

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| auto_cleanup_enabled | any | No | - |
| delete_after_days | any | No | - |
| warn_before_days | any | No | - |
| secure_delete | any | No | - |

**Request Example**:
```json
{
  "auto_cleanup_enabled": {},
  "delete_after_days": {},
  "warn_before_days": {},
  "secure_delete": {}
}
```

**Response 200**:
Successful Response

```json
{
  "auto_cleanup_enabled": true,
  "delete_after_days": 1,
  "warn_before_days": 1,
  "secure_delete": true,
  "temp_base_path": "string",
  "max_batch_size_gb": 1.0,
  "max_total_size_gb": 1.0
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/admin/temp-zone/batch-types

**Description**: Lista dei tipi di batch supportati

**Authentication**: None

**Response 200**:
Successful Response

---


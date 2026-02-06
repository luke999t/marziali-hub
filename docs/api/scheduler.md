# Scheduler API

API endpoints for scheduler functionality.

## Table of Contents

- [GET /api/v1/scheduler/jobs](#get--api-v1-scheduler-jobs) - List All Jobs
- [GET /api/v1/scheduler/jobs/{job_id}](#get--api-v1-scheduler-jobs-job_id) - Get Job Details
- [GET /api/v1/scheduler/jobs/{job_id}/history](#get--api-v1-scheduler-jobs-job_id-history) - Get Job History
- [POST /api/v1/scheduler/jobs/{job_id}/trigger](#post--api-v1-scheduler-jobs-job_id-trigger) - Trigger Job Manually
- [POST /api/v1/scheduler/jobs/{job_id}/pause](#post--api-v1-scheduler-jobs-job_id-pause) - Pause Job
- [POST /api/v1/scheduler/jobs/{job_id}/resume](#post--api-v1-scheduler-jobs-job_id-resume) - Resume Job
- [GET /api/v1/scheduler/running](#get--api-v1-scheduler-running) - Get Running Jobs
- [GET /api/v1/scheduler/health](#get--api-v1-scheduler-health) - Get System Health
- [GET /api/v1/scheduler/backups](#get--api-v1-scheduler-backups) - List Backups
- [GET /api/v1/scheduler/stats](#get--api-v1-scheduler-stats) - Get Scheduler Stats

---

## GET /api/v1/scheduler/jobs

**Description**: 📋 Lista tutti i job registrati con il loro stato attuale.

Returns:
- Lista di tutti i job con next_run_time, stato, ultimo risultato

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "job_id": "string",
    "name": "string",
    "description": {},
    "trigger_type": {},
    "next_run_time": {},
    "is_paused": true,
    "is_running": true,
    "enabled": true,
    "last_result": {}
  }
]
```

---

## GET /api/v1/scheduler/jobs/{job_id}

**Description**: 🔍 Dettaglio singolo job.

Args:
    job_id: ID del job (es. "health_check", "daily_analytics")

Returns:
    Dettagli completi del job incluso ultimo risultato

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "job_id": "string",
  "name": "string",
  "description": {},
  "trigger_type": {},
  "next_run_time": {},
  "is_paused": true,
  "is_running": true,
  "enabled": true,
  "last_result": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/scheduler/jobs/{job_id}/history

**Description**: 📜 Storico esecuzioni di un job.

Args:
    job_id: ID del job
    limit: Numero massimo di risultati (default 10, max 100)

Returns:
    Lista ultime esecuzioni con dettagli risultato

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 10) |

**Response 200**:
Successful Response

```json
[
  {
    "job_id": "string",
    "status": "string",
    "started_at": "string",
    "finished_at": {},
    "duration_seconds": {},
    "records_processed": 1,
    "error_message": {},
    "details": {}
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/scheduler/jobs/{job_id}/trigger

**Description**: ⚡ Trigger manuale immediato di un job.

Args:
    job_id: ID del job da eseguire

Returns:
    Risultato dell'esecuzione

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "success": true,
  "job_id": "string",
  "status": "string",
  "message": "string",
  "result": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/scheduler/jobs/{job_id}/pause

**Description**: ⏸️ Metti in pausa un job.

Args:
    job_id: ID del job da pausare

Il job non verrà più eseguito automaticamente finché non viene ripreso.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/scheduler/jobs/{job_id}/resume

**Description**: ▶️ Riprendi un job in pausa.

Args:
    job_id: ID del job da riprendere

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/scheduler/running

**Description**: 🏃 Lista job attualmente in esecuzione.

Returns:
    Lista di job running con dettagli esecuzione

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/scheduler/health

**Description**: 🏥 Stato salute servizi (PostgreSQL, Redis, Storage).

Returns:
    Stato ultimo health check con latenze e metriche sistema

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "status": "string",
  "services": {},
  "system": {},
  "checked_at": {}
}
```

---

## GET /api/v1/scheduler/backups

**Description**: 💾 Lista backup database disponibili.

Returns:
    Lista file backup con dimensioni e date

**Authentication**: Required

**Response 200**:
Successful Response

```json
[
  {
    "filename": "string",
    "path": "string",
    "size_bytes": 1,
    "size_mb": 1.0,
    "created_at": "string"
  }
]
```

---

## GET /api/v1/scheduler/stats

**Description**: 📊 Statistiche aggregate dello scheduler.

Returns:
    Conteggi job, successi, fallimenti, uptime

**Authentication**: Required

**Response 200**:
Successful Response

---


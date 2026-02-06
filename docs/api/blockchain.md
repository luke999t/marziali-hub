# Blockchain API

API endpoints for blockchain functionality.

## Table of Contents

- [POST /api/v1/blockchain/batches/create](#post--api-v1-blockchain-batches-create) - Create Weekly Batch
- [POST /api/v1/blockchain/batches/{batch_id}/broadcast](#post--api-v1-blockchain-batches-batch_id-broadcast) - Broadcast Batch
- [POST /api/v1/blockchain/batches/{batch_id}/validate](#post--api-v1-blockchain-batches-batch_id-validate) - Receive Validation
- [POST /api/v1/blockchain/batches/{batch_id}/publish](#post--api-v1-blockchain-batches-batch_id-publish) - Publish Batch
- [GET /api/v1/blockchain/batches/{batch_id}](#get--api-v1-blockchain-batches-batch_id) - Get Batch Status

---

## POST /api/v1/blockchain/batches/create

**Description**: Create weekly batch for blockchain publication.

Args:
    week_offset: 0 = current week, -1 = last week, -2 = 2 weeks ago, etc.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| week_offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/blockchain/batches/{batch_id}/broadcast

**Description**: Broadcast batch to store nodes for validation.

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

## POST /api/v1/blockchain/batches/{batch_id}/validate

**Description**: Receive validation from a store node.

NOTE: In production questo endpoint dovrebbe essere protetto
con firma digitale del nodo per evitare validazioni fake.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| node_id | string | Yes | - |
| is_valid | boolean | Yes | - |
| computed_hash | string | Yes | - |
| notes | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/blockchain/batches/{batch_id}/publish

**Description**: Publish batch to Polygon blockchain after consensus.

Requirements:
- Consensus must be reached (>51% nodes validated)
- Master wallet must be configured
- Smart contract must be deployed

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

## GET /api/v1/blockchain/batches/{batch_id}

**Description**: Get batch status and details.

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| batch_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---


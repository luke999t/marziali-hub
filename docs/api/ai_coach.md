# Ai Coach API

API endpoints for ai coach functionality.

## Table of Contents

- [POST /api/v1/ai-coach/chat](#post--api-v1-ai-coach-chat) - Send chat message
- [POST /api/v1/ai-coach/chat/stream](#post--api-v1-ai-coach-chat-stream) - Send message with streaming response
- [GET /api/v1/ai-coach/conversations](#get--api-v1-ai-coach-conversations) - List conversations
- [GET /api/v1/ai-coach/conversations/{conversation_id}](#get--api-v1-ai-coach-conversations-conversation_id) - Get conversation detail
- [DELETE /api/v1/ai-coach/conversations/{conversation_id}](#delete--api-v1-ai-coach-conversations-conversation_id) - Delete conversation
- [POST /api/v1/ai-coach/feedback/technique](#post--api-v1-ai-coach-feedback-technique) - Get technique feedback
- [POST /api/v1/ai-coach/feedback/pose](#post--api-v1-ai-coach-feedback-pose) - Get real-time pose feedback
- [GET /api/v1/ai-coach/knowledge/search](#get--api-v1-ai-coach-knowledge-search) - Search knowledge base
- [GET /api/v1/ai-coach/styles](#get--api-v1-ai-coach-styles) - Get supported styles
- [GET /api/v1/ai-coach/health](#get--api-v1-ai-coach-health) - Health check

---

## POST /api/v1/ai-coach/chat

**Description**: Invia messaggio all'AI Coach e ricevi risposta.

    BUSINESS: Core interaction - utente chiede, AI risponde
    METRICS: Response time <2s, accuracy >90%

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_id | string | No | Existing conversation ID |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| content | string | Yes | Message content |
| style | any | No | Martial art style context |
| language | string | No | Response language |
| context | any | No | Additional context |

**Request Example**:
```json
{
  "content": "Come si esegue un mae geri correttamente?",
  "language": "it",
  "style": "karate"
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "content": "string",
  "sources": [
    {}
  ],
  "confidence": 1.0,
  "suggestions": [
    "string"
  ],
  "timestamp": "2024-01-15T10:30:00Z"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ai-coach/chat/stream

**Description**: Invia messaggio e ricevi risposta in streaming (SSE).

    BUSINESS: UX migliore per risposte lunghe
    TEACHING: Server-Sent Events per streaming unidirezionale

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_id | string | No | - |

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| content | string | Yes | Message content |
| style | any | No | Martial art style context |
| language | string | No | Response language |
| context | any | No | Additional context |

**Request Example**:
```json
{
  "content": "Come si esegue un mae geri correttamente?",
  "language": "it",
  "style": "karate"
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ai-coach/conversations

**Description**: Lista conversazioni dell'utente

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| limit | integer | No | - (default: 20) |
| offset | integer | No | - (default: 0) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "style": "karate",
    "message_count": 1,
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:30:00Z"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ai-coach/conversations/{conversation_id}

**Description**: Dettaglio conversazione con tutti i messaggi

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/ai-coach/conversations/{conversation_id}

**Description**: Elimina conversazione

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| conversation_id | string | Yes | - |

**Response 204**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ai-coach/feedback/technique

**Description**: Analizza tecnica da video e fornisce feedback dettagliato.

    BUSINESS: Valore core - feedback personalizzato
    METRICS: Analysis time <5s, satisfaction >4/5

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | Video ID to analyze |
| technique_name | any | No | Specific technique to analyze |
| timestamp_start | number | No | Start timestamp in seconds |
| timestamp_end | any | No | End timestamp in seconds |
| focus_areas | array[string] | No | Areas to focus on |

**Request Example**:
```json
{
  "focus_areas": [
    "postura",
    "velocita",
    "potenza"
  ],
  "technique_name": "mae_geri",
  "timestamp_end": 5.0,
  "timestamp_start": 0,
  "video_id": "abc123"
}
```

**Response 200**:
Successful Response

```json
{
  "overall_score": 1.0,
  "strengths": [
    "string"
  ],
  "improvements": [
    "string"
  ],
  "drills": [
    {}
  ],
  "reference_videos": [
    "string"
  ],
  "detailed_analysis": "string"
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/ai-coach/feedback/pose

**Description**: Feedback real-time su pose (per app mobile/AR).

    BUSINESS: Differenziatore vs competitors
    METRICS: Response time <100ms
    TEACHING: Ottimizzato per bassa latenza

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| landmarks | array[object] | Yes | 75 or 33 landmarks with x,y,z coordinates |
| technique_name | string | Yes | Technique being performed |
| style | any | No | Martial art style |

**Request Example**:
```json
{
  "landmarks": [
    {
      "x": 0.5,
      "y": 0.5,
      "z": 0.0
    }
  ],
  "style": "karate",
  "technique_name": "mae_geri"
}
```

**Response 200**:
Successful Response

```json
{
  "is_correct": true,
  "score": 1.0,
  "corrections": [
    {
      "joint": "string",
      "issue": "string",
      "fix": "string",
      "severity": "medium"
    }
  ],
  "audio_cue": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ai-coach/knowledge/search

**Description**: Cerca nella knowledge base arti marziali.

    TEACHING: Endpoint utile per debug RAG e per UI search.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| query | string | Yes | Search query |
| style | string | No | Filter by style |
| limit | integer | No | Max results (default: 10) |

**Response 200**:
Successful Response

```json
[
  {
    "id": "string",
    "title": "string",
    "content": "string",
    "relevance": 1.0,
    "source": "string",
    "style": "karate"
  }
]
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/ai-coach/styles

**Description**: Lista stili arti marziali supportati

**Authentication**: None

**Response 200**:
Successful Response

---

## GET /api/v1/ai-coach/health

**Description**: Health check servizio AI Coach

**Authentication**: None

**Response 200**:
Successful Response

---


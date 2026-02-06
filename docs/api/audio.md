# Audio API

API endpoints for audio functionality.

## Table of Contents

- [POST /api/v1/audio/tts](#post--api-v1-audio-tts) - Genera audio TTS
- [GET /api/v1/audio/tts/voices](#get--api-v1-audio-tts-voices) - Lista voci TTS disponibili
- [GET /api/v1/audio/tts/engines](#get--api-v1-audio-tts-engines) - Lista engine TTS disponibili
- [GET /api/v1/audio/voice-profiles](#get--api-v1-audio-voice-profiles) - Lista profili voce
- [POST /api/v1/audio/voice-profiles](#post--api-v1-audio-voice-profiles) - Crea profilo voce
- [GET /api/v1/audio/voice-profiles/{profile_id}](#get--api-v1-audio-voice-profiles-profile_id) - Get Voice Profile
- [DELETE /api/v1/audio/voice-profiles/{profile_id}](#delete--api-v1-audio-voice-profiles-profile_id) - Elimina profilo voce
- [POST /api/v1/audio/clone](#post--api-v1-audio-clone) - Genera audio con voce clonata
- [POST /api/v1/audio/clone/validate](#post--api-v1-audio-clone-validate) - Valida audio per voice cloning
- [POST /api/v1/audio/style](#post--api-v1-audio-style) - Applica stile audio
- [GET /api/v1/audio/style/presets](#get--api-v1-audio-style-presets) - Lista preset stile disponibili
- [POST /api/v1/audio/analyze](#post--api-v1-audio-analyze) - Analizza caratteristiche audio
- [GET /api/v1/audio/pronunciation/{term}](#get--api-v1-audio-pronunciation-term) - Cerca pronuncia termine
- [POST /api/v1/audio/pronunciation](#post--api-v1-audio-pronunciation) - Aggiungi pronuncia
- [POST /api/v1/audio/pronunciation/{entry_id}/audio](#post--api-v1-audio-pronunciation-entry_id-audio) - Genera audio pronuncia
- [POST /api/v1/audio/pronunciation/seed](#post--api-v1-audio-pronunciation-seed) - Popola DB con termini base
- [GET /api/v1/audio/files/{audio_id}](#get--api-v1-audio-files-audio_id) - Download audio
- [DELETE /api/v1/audio/files/{audio_id}](#delete--api-v1-audio-files-audio_id) - Elimina audio
- [GET /api/v1/audio/files/{audio_id}/metadata](#get--api-v1-audio-files-audio_id-metadata) - Metadata audio
- [GET /api/v1/audio/storage/stats](#get--api-v1-audio-storage-stats) - Statistiche storage
- [POST /api/v1/audio/storage/cleanup](#post--api-v1-audio-storage-cleanup) - Cleanup file temporanei
- [GET /api/v1/audio/system/info](#get--api-v1-audio-system-info) - Info sistema audio
- [GET /api/v1/audio/system/health](#get--api-v1-audio-system-health) - Health check sistema audio

---

## POST /api/v1/audio/tts

**Description**: Genera audio Text-to-Speech.

Supporta multiple engine:
- **edge**: Microsoft Edge TTS (online, alta qualita)
- **coqui**: Coqui TTS (offline, customizzabile)
- **pyttsx3**: pyttsx3 (offline, basic)
- **auto**: Seleziona automaticamente la migliore disponibile

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| text | string | Yes | Testo da sintetizzare |
| language | string | No | Codice lingua ISO |
| voice_id | any | No | ID voce specifica |
| engine | any | No | Engine TTS |
| rate | number | No | Velocita parlato |
| pitch | number | No | Altezza voce |
| volume | number | No | Volume |
| store | boolean | No | Salva in storage |

**Request Example**:
```json
{
  "text": "string",
  "language": "it",
  "voice_id": {},
  "engine": "auto",
  "rate": 1.0,
  "pitch": 1.0,
  "volume": 1.0,
  "store": true
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "audio_id": {},
  "audio_path": {},
  "duration_seconds": {},
  "engine_used": {},
  "voice_used": {},
  "cached": false,
  "error": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/tts/voices

**Description**: Lista tutte le voci TTS disponibili, filtrate per lingua o engine.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| language | string | No | - |
| engine | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/tts/engines

**Description**: Restituisce gli engine TTS attualmente disponibili nel sistema.

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/audio/voice-profiles

**Description**: Lista tutti i profili voce disponibili.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/audio/voice-profiles

**Description**: Crea un nuovo profilo voce per cloning.

L'audio di riferimento deve essere:
- Formato: WAV
- Durata: 10-30 secondi
- Qualita: Parlato chiaro, senza rumore di fondo

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Yes | - |
| language | string | No | - |
| description | any | No | - |
| reference_audio | string | Yes | Audio di riferimento (WAV, 10-30 secondi) |

**Request Example**:
```json
{
  "name": "string",
  "language": "it",
  "description": {},
  "reference_audio": "string"
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "language": "string",
  "description": {},
  "reference_path": "string",
  "is_active": true,
  "created_at": "string",
  "created_by": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/voice-profiles/{profile_id}

**Description**: Ottiene dettagli profilo voce.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| profile_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "name": "string",
  "language": "string",
  "description": {},
  "reference_path": "string",
  "is_active": true,
  "created_at": "string",
  "created_by": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/audio/voice-profiles/{profile_id}

**Description**: Elimina un profilo voce (solo admin).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| profile_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/clone

**Description**: Genera audio usando una voce clonata.

Richiede un profilo voce creato precedentemente con /voice-profiles.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| text | string | Yes | - |
| profile_id | string | Yes | ID profilo voce |
| target_language | any | No | - |
| speed | number | No | - |
| store | boolean | No | - |

**Request Example**:
```json
{
  "text": "string",
  "profile_id": "string",
  "target_language": {},
  "speed": 1.0,
  "store": true
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "audio_id": {},
  "audio_path": {},
  "duration_seconds": {},
  "engine_used": {},
  "voice_used": {},
  "cached": false,
  "error": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/clone/validate

**Description**: Valida un file audio per uso come reference in voice cloning.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| audio | string | Yes | - |

**Request Example**:
```json
{
  "audio": "string"
}
```

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/style

**Description**: Applica uno stile predefinito a un audio esistente.

Stili disponibili:
- **dojo_reverb**: Riverbero tipo dojo
- **clear_voice**: Voce chiara per tutorial
- **warm_narrator**: Voce calda narratore
- **dramatic**: Effetto drammatico
- **meditation**: Calmo per meditazione

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| audio_id | string | Yes | ID audio da stylare |
| style | any | Yes | Preset stile |
| store | boolean | No | - |

**Request Example**:
```json
{
  "audio_id": "string",
  "style": {},
  "store": true
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "audio_id": {},
  "audio_path": {},
  "duration_seconds": {},
  "style_applied": {},
  "processing_time_ms": {},
  "error": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/style/presets

**Description**: Lista tutti i preset di stile audio disponibili.

**Authentication**: Required

**Response 200**:
Successful Response

---

## POST /api/v1/audio/analyze

**Description**: Analizza le caratteristiche di un file audio.

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| audio_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/pronunciation/{term}

**Description**: Cerca la pronuncia di un termine di arti marziali.

Ricerca per termine originale, romanizzazione, o full-text.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| term | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| language | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/pronunciation

**Description**: Aggiunge una nuova pronuncia al database.

**Authentication**: Required

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| term | string | Yes | - |
| language | LanguageCodeType | Yes | - |
| romanization | string | Yes | - |
| category | TermCategoryType | Yes | - |
| martial_art | MartialArtStyleType | Yes | - |
| phonetic | any | No | - |
| meaning | any | No | - |
| notes | any | No | - |

**Request Example**:
```json
{
  "term": "string",
  "language": "ja",
  "romanization": "string",
  "category": "technique",
  "martial_art": "karate",
  "phonetic": {},
  "meaning": {},
  "notes": {}
}
```

**Response 200**:
Successful Response

```json
{
  "id": "string",
  "term": "string",
  "language": "string",
  "romanization": "string",
  "phonetic": {},
  "category": "string",
  "martial_art": "string",
  "meaning": {},
  "notes": {},
  "audio_url": {}
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/pronunciation/{entry_id}/audio

**Description**: Genera audio per una entry di pronuncia.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| entry_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| voice_profile_id | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/audio/pronunciation/seed

**Description**: Popola il database pronuncie con i termini base (solo admin).

**Authentication**: Required

**Response 200**:
Successful Response

---

## GET /api/v1/audio/files/{audio_id}

**Description**: Scarica un file audio per ID.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| audio_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## DELETE /api/v1/audio/files/{audio_id}

**Description**: Elimina un file audio (solo admin).

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| audio_id | string | Yes | - |

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| secure | boolean | No | - (default: False) |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/files/{audio_id}/metadata

**Description**: Ottiene i metadata di un file audio.

**Authentication**: Required

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| audio_id | string | Yes | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/storage/stats

**Description**: Ottiene statistiche dello storage audio (solo admin).

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "total_files": 1,
  "total_size_mb": 1.0,
  "files_by_category": {},
  "size_by_category": {},
  "dedup_savings_bytes": 1
}
```

---

## POST /api/v1/audio/storage/cleanup

**Description**: Pulisce i file temporanei (solo admin).

**Authentication**: Required

**Query Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| max_age_hours | string | No | - |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/audio/system/info

**Description**: Ottiene informazioni complete sul sistema audio (solo admin).

**Authentication**: Required

**Response 200**:
Successful Response

```json
{
  "availability": {},
  "storage": {
    "total_files": 1,
    "total_size_mb": 1.0,
    "files_by_category": {},
    "size_by_category": {},
    "dedup_savings_bytes": 1
  },
  "pronunciation": {},
  "voice_profiles_count": 1,
  "supported_languages": [
    "string"
  ]
}
```

---

## GET /api/v1/audio/system/health

**Description**: Health check per il sistema audio.

**Authentication**: None

**Response 200**:
Successful Response

---


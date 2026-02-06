# Video Studio API

API endpoints for video studio functionality.

## Table of Contents

- [POST /api/v1/video-studio/generate-technique-image](#post--api-v1-video-studio-generate-technique-image) - Generate technique image with movement arrows
- [POST /api/v1/video-studio/generate-transition-sequence](#post--api-v1-video-studio-generate-transition-sequence) - Generate transition sequence of technique images
- [POST /api/v1/video-studio/fusion](#post--api-v1-video-studio-fusion) - Start multi-video fusion process
- [GET /api/v1/video-studio/fusion/{fusion_id}/status](#get--api-v1-video-studio-fusion-fusion_id-status) - Get fusion job status
- [GET /api/v1/video-studio/download/{file_type}/{file_id}](#get--api-v1-video-studio-download-file_type-file_id) - Download generated file
- [GET /api/v1/video-studio/health](#get--api-v1-video-studio-health) - Video Studio health check

---

## POST /api/v1/video-studio/generate-technique-image

**Description**: Generate a static image of a martial arts technique with directional arrows
    showing the movement direction.

    The arrows are color-coded by body region:
    - Red: Arms
    - Blue: Legs
    - Green: Torso
    - Cyan: Head

    **AI_MODULE**: technique_image_generator
    **AI_BUSINESS**: Visual teaching aids for technique instruction

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | ID of the video to process |
| num_frames | integer | No | Number of frames to generate |
| arrow_style | string | No | Arrow style: default, minimal, detailed |
| frame_index | any | No | Specific frame index (None for auto) |
| scale_factor | number | No | Arrow length multiplier |

**Request Example**:
```json
{
  "arrow_style": "default",
  "num_frames": 1,
  "scale_factor": 3.0,
  "video_id": "technique_punch_001"
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "images": [
    "string"
  ],
  "metadata": {},
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/video-studio/generate-transition-sequence

**Description**: Generate a sequence of images showing the technique's transition
    from start to finish, each with movement arrows.

    Useful for creating teaching materials that show step-by-step
    progression of a technique.

    **AI_MODULE**: technique_image_generator
    **AI_BUSINESS**: Step-by-step visual technique instruction

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_id | string | Yes | ID of the video to process |
| num_images | integer | No | Number of images in sequence |
| arrow_style | string | No | Arrow style |

**Request Example**:
```json
{
  "arrow_style": "default",
  "num_images": 5,
  "video_id": "technique_kata_001"
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "sequence_path": "",
  "images": [
    "string"
  ],
  "message": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## POST /api/v1/video-studio/fusion

**Description**: Fuse multiple videos of the same technique to create a consensus
    "perfect" avatar skeleton.

    The fusion process:
    1. Aligns videos temporally using DTW
    2. Detects and excludes outlier executions
    3. Calculates weighted average skeleton
    4. Generates smooth avatar video

    Returns a fusion_id to check progress.

    **AI_MODULE**: multi_video_fusion
    **AI_BUSINESS**: Create ideal technique reference from multiple masters

**Authentication**: None

**Request Body**:
| Field | Type | Required | Description |
|-------|------|----------|-------------|
| video_ids | array[string] | Yes | List of video IDs to fuse |
| fusion_config | any | No | Fusion configuration |

**Request Example**:
```json
{
  "fusion_config": {
    "exclude_outliers": true,
    "outlier_threshold": 2.0,
    "output_style": "wireframe",
    "smoothing_window": 5
  },
  "video_ids": [
    "punch_master1",
    "punch_master2",
    "punch_master3"
  ]
}
```

**Response 200**:
Successful Response

```json
{
  "success": true,
  "fusion_id": "",
  "message": "",
  "status": "queued"
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/video-studio/fusion/{fusion_id}/status

**Description**: Check the status of a fusion job.

    Status values:
    - queued: Job is waiting to start
    - processing: Fusion in progress
    - completed: Fusion finished successfully
    - failed: Fusion failed with error

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| fusion_id | string | Yes | - |

**Response 200**:
Successful Response

```json
{
  "fusion_id": "string",
  "status": "string",
  "progress": 0.0,
  "result": {},
  "error": {},
  "created_at": "",
  "updated_at": ""
}
```

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/video-studio/download/{file_type}/{file_id}

**Description**: Download a generated image or video file

**Authentication**: None

**Path Parameters**:
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| file_type | string | Yes | File type: image, video, report |
| file_id | string | Yes | File identifier |

**Response 200**:
Successful Response

**Error Codes**:
- **422**: Validation Error

---

## GET /api/v1/video-studio/health

**Description**: Check Video Studio service health.

**Authentication**: None

**Response 200**:
Successful Response

---


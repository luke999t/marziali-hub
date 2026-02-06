"""
Video Studio API - Technique Image Generation & Multi-Video Fusion

AI_MODULE: video_studio_api
AI_DESCRIPTION: REST API endpoints for advanced video studio features
AI_BUSINESS: Enable technique visualization and avatar fusion via API
AI_TEACHING: FastAPI endpoints + background tasks + file handling

ENDPOINTS:
- POST /generate-technique-image: Generate image with movement arrows
- POST /generate-transition-sequence: Generate sequence of technique images
- POST /fusion: Start multi-video fusion process
- GET /fusion/{fusion_id}/status: Get fusion job status

DEPENDENCIES:
- FastAPI for routing
- Background tasks for long-running operations
- services/video_studio/* for business logic
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Path as PathParam, File, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from pathlib import Path
import uuid
import logging
import os
import json
import shutil
from datetime import datetime

# Import services
import sys
backend_path = Path(__file__).parent.parent.parent
sys.path.insert(0, str(backend_path))

from services.video_studio.technique_image_generator import TechniqueImageGenerator
from services.video_studio.multi_video_fusion import (
    MultiVideoFusion,
    SkeletonSequence,
    load_skeleton_from_json,
    save_skeleton_to_json
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# Configuration
UPLOAD_DIR = Path("uploads/video_studio")
OUTPUT_DIR = Path("output/video_studio")
FUSION_JOBS_DIR = Path("data/fusion_jobs")

# Create directories
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
FUSION_JOBS_DIR.mkdir(parents=True, exist_ok=True)

# In-memory job store (in production, use Redis or DB)
fusion_jobs: Dict[str, Dict] = {}


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class TechniqueImageRequest(BaseModel):
    """
    Request model for technique image generation.

    AI_HEADER: Request to generate technique image with arrows
    """
    video_id: str = Field(..., description="ID of the video to process")
    num_frames: int = Field(default=1, ge=1, le=10, description="Number of frames to generate")
    arrow_style: str = Field(default="default", description="Arrow style: default, minimal, detailed")
    frame_index: Optional[int] = Field(None, description="Specific frame index (None for auto)")
    scale_factor: float = Field(default=3.0, ge=1.0, le=10.0, description="Arrow length multiplier")

    class Config:
        json_schema_extra = {
            "example": {
                "video_id": "technique_punch_001",
                "num_frames": 1,
                "arrow_style": "default",
                "scale_factor": 3.0
            }
        }


class TechniqueImageResponse(BaseModel):
    """Response model for technique image generation."""
    success: bool
    images: List[str] = Field(default_factory=list, description="List of generated image paths")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    message: str = ""


class TransitionSequenceRequest(BaseModel):
    """Request model for transition sequence generation."""
    video_id: str = Field(..., description="ID of the video to process")
    num_images: int = Field(default=5, ge=2, le=20, description="Number of images in sequence")
    arrow_style: str = Field(default="default", description="Arrow style")

    class Config:
        json_schema_extra = {
            "example": {
                "video_id": "technique_kata_001",
                "num_images": 5,
                "arrow_style": "default"
            }
        }


class TransitionSequenceResponse(BaseModel):
    """Response model for transition sequence."""
    success: bool
    sequence_path: str = ""
    images: List[str] = Field(default_factory=list)
    message: str = ""


class FusionConfig(BaseModel):
    """Configuration for multi-video fusion."""
    smoothing_window: int = Field(default=5, ge=3, le=15, description="Smoothing filter window size")
    outlier_threshold: float = Field(default=2.0, ge=1.0, le=5.0, description="Z-score threshold for outliers")
    exclude_outliers: bool = Field(default=True, description="Exclude detected outliers from fusion")
    output_style: str = Field(default="wireframe", description="Avatar video style: wireframe, silhouette")
    output_resolution: List[int] = Field(default=[640, 480], description="Video resolution [width, height]")


class FusionRequest(BaseModel):
    """
    Request model for multi-video fusion.

    AI_HEADER: Request to fuse multiple technique videos into avatar
    """
    video_ids: List[str] = Field(..., min_length=2, description="List of video IDs to fuse")
    fusion_config: Optional[FusionConfig] = Field(default=None, description="Fusion configuration")

    class Config:
        json_schema_extra = {
            "example": {
                "video_ids": ["punch_master1", "punch_master2", "punch_master3"],
                "fusion_config": {
                    "smoothing_window": 5,
                    "outlier_threshold": 2.0,
                    "exclude_outliers": True,
                    "output_style": "wireframe"
                }
            }
        }


class FusionResponse(BaseModel):
    """Response model for fusion request."""
    success: bool
    fusion_id: str = ""
    message: str = ""
    status: str = "queued"


class FusionStatusResponse(BaseModel):
    """Response model for fusion status check."""
    fusion_id: str
    status: str  # queued, processing, completed, failed
    progress: float = 0.0  # 0-100
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str = ""
    updated_at: str = ""


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def get_video_path(video_id: str) -> Optional[Path]:
    """
    Resolve video path from video ID.

    Looks in:
    1. uploads/video_studio/{video_id}.mp4
    2. data/videos/{video_id}.mp4
    3. storage/videos/{video_id}/*.mp4
    """
    # Direct path in uploads
    upload_path = UPLOAD_DIR / f"{video_id}.mp4"
    if upload_path.exists():
        return upload_path

    # Data directory
    data_path = Path("data/videos") / f"{video_id}.mp4"
    if data_path.exists():
        return data_path

    # Storage directory (glob for any video file)
    storage_dir = Path("storage/videos") / video_id
    if storage_dir.exists():
        mp4_files = list(storage_dir.glob("*.mp4"))
        if mp4_files:
            return mp4_files[0]

    return None


def get_skeleton_path(video_id: str) -> Optional[Path]:
    """
    Get skeleton JSON path for a video.

    Skeleton files are stored as {video_id}_skeleton.json
    """
    skeleton_path = Path("data/skeletons") / f"{video_id}_skeleton.json"
    if skeleton_path.exists():
        return skeleton_path

    # Also check uploads
    upload_skeleton = UPLOAD_DIR / f"{video_id}_skeleton.json"
    if upload_skeleton.exists():
        return upload_skeleton

    return None


def update_fusion_job(fusion_id: str, **kwargs):
    """Update fusion job status."""
    if fusion_id in fusion_jobs:
        fusion_jobs[fusion_id].update(kwargs)
        fusion_jobs[fusion_id]["updated_at"] = datetime.now().isoformat()

        # Persist to disk
        job_file = FUSION_JOBS_DIR / f"{fusion_id}.json"
        with open(job_file, 'w') as f:
            json.dump(fusion_jobs[fusion_id], f, indent=2)


# =============================================================================
# TECHNIQUE IMAGE ENDPOINTS
# =============================================================================

@router.post(
    "/generate-technique-image",
    response_model=TechniqueImageResponse,
    summary="Generate technique image with movement arrows",
    description="""
    Generate a static image of a martial arts technique with directional arrows
    showing the movement direction.

    The arrows are color-coded by body region:
    - Red: Arms
    - Blue: Legs
    - Green: Torso
    - Cyan: Head

    **AI_MODULE**: technique_image_generator
    **AI_BUSINESS**: Visual teaching aids for technique instruction
    """
)
async def generate_technique_image(request: TechniqueImageRequest):
    """
    Generate technique image with movement arrows.

    Steps:
    1. Locate video file
    2. Extract frames and detect skeleton
    3. Calculate movement vectors
    4. Draw arrows on image
    5. Save and return path
    """
    try:
        # Find video path
        video_path = get_video_path(request.video_id)
        if not video_path:
            raise HTTPException(
                status_code=404,
                detail=f"Video not found: {request.video_id}"
            )

        # Initialize generator
        output_dir = OUTPUT_DIR / "technique_images" / request.video_id
        generator = TechniqueImageGenerator(output_dir=output_dir)

        # Generate image(s)
        images = []
        metadata = {}

        try:
            result = generator.generate_technique_image(
                video_path,
                options={
                    "style": request.arrow_style,
                    "scale_factor": request.scale_factor,
                    "frame_index": request.frame_index
                }
            )

            images.append(result["output_path"])
            metadata = result["metadata"]
            metadata["movements"] = result.get("movements", {})

        finally:
            generator.close()

        logger.info(f"Generated technique image for {request.video_id}")

        return TechniqueImageResponse(
            success=True,
            images=images,
            metadata=metadata,
            message=f"Generated {len(images)} technique image(s)"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating technique image: {e}")
        return TechniqueImageResponse(
            success=False,
            message=str(e)
        )


@router.post(
    "/generate-transition-sequence",
    response_model=TransitionSequenceResponse,
    summary="Generate transition sequence of technique images",
    description="""
    Generate a sequence of images showing the technique's transition
    from start to finish, each with movement arrows.

    Useful for creating teaching materials that show step-by-step
    progression of a technique.

    **AI_MODULE**: technique_image_generator
    **AI_BUSINESS**: Step-by-step visual technique instruction
    """
)
async def generate_transition_sequence(request: TransitionSequenceRequest):
    """Generate sequence of technique images."""
    try:
        video_path = get_video_path(request.video_id)
        if not video_path:
            raise HTTPException(
                status_code=404,
                detail=f"Video not found: {request.video_id}"
            )

        output_dir = OUTPUT_DIR / "sequences" / request.video_id
        generator = TechniqueImageGenerator(output_dir=output_dir)

        try:
            paths = generator.generate_transition_sequence(
                video_path,
                output_dir=output_dir,
                num_images=request.num_images,
                style=request.arrow_style
            )

            logger.info(f"Generated {len(paths)} sequence images for {request.video_id}")

            return TransitionSequenceResponse(
                success=True,
                sequence_path=str(output_dir),
                images=paths,
                message=f"Generated {len(paths)} sequence images"
            )

        finally:
            generator.close()

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error generating sequence: {e}")
        return TransitionSequenceResponse(
            success=False,
            message=str(e)
        )


# =============================================================================
# FUSION ENDPOINTS
# =============================================================================

@router.post(
    "/fusion",
    response_model=FusionResponse,
    summary="Start multi-video fusion process",
    description="""
    Fuse multiple videos of the same technique to create a consensus
    "perfect" avatar skeleton.

    The fusion process:
    1. Aligns videos temporally using DTW
    2. Detects and excludes outlier executions
    3. Calculates weighted average skeleton
    4. Generates smooth avatar video

    Returns a fusion_id to check progress.

    **AI_MODULE**: multi_video_fusion
    **AI_BUSINESS**: Create ideal technique reference from multiple masters
    """
)
async def start_fusion(
    request: FusionRequest,
    background_tasks: BackgroundTasks
):
    """
    Start fusion process in background.

    Returns immediately with fusion_id.
    Use /fusion/{fusion_id}/status to check progress.
    """
    # Validate video IDs
    for video_id in request.video_ids:
        skeleton_path = get_skeleton_path(video_id)
        video_path = get_video_path(video_id)
        if not skeleton_path and not video_path:
            raise HTTPException(
                status_code=404,
                detail=f"Video or skeleton not found: {video_id}"
            )

    # Create fusion job
    fusion_id = f"fusion_{uuid.uuid4().hex[:12]}"

    fusion_jobs[fusion_id] = {
        "fusion_id": fusion_id,
        "status": "queued",
        "progress": 0.0,
        "video_ids": request.video_ids,
        "config": request.fusion_config.model_dump() if request.fusion_config else {},
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "result": None,
        "error": None
    }

    # Start background task
    background_tasks.add_task(
        run_fusion_task,
        fusion_id,
        request.video_ids,
        request.fusion_config
    )

    logger.info(f"Started fusion job {fusion_id} with {len(request.video_ids)} videos")

    return FusionResponse(
        success=True,
        fusion_id=fusion_id,
        message=f"Fusion started with {len(request.video_ids)} videos",
        status="queued"
    )


@router.get(
    "/fusion/{fusion_id}/status",
    response_model=FusionStatusResponse,
    summary="Get fusion job status",
    description="""
    Check the status of a fusion job.

    Status values:
    - queued: Job is waiting to start
    - processing: Fusion in progress
    - completed: Fusion finished successfully
    - failed: Fusion failed with error
    """
)
async def get_fusion_status(fusion_id: str):
    """Get status of a fusion job."""
    # Check memory cache
    if fusion_id in fusion_jobs:
        job = fusion_jobs[fusion_id]
        return FusionStatusResponse(
            fusion_id=job["fusion_id"],
            status=job["status"],
            progress=job["progress"],
            result=job.get("result"),
            error=job.get("error"),
            created_at=job["created_at"],
            updated_at=job["updated_at"]
        )

    # Check disk
    job_file = FUSION_JOBS_DIR / f"{fusion_id}.json"
    if job_file.exists():
        with open(job_file, 'r') as f:
            job = json.load(f)
        return FusionStatusResponse(
            fusion_id=job["fusion_id"],
            status=job["status"],
            progress=job["progress"],
            result=job.get("result"),
            error=job.get("error"),
            created_at=job["created_at"],
            updated_at=job["updated_at"]
        )

    raise HTTPException(
        status_code=404,
        detail=f"Fusion job not found: {fusion_id}"
    )


# =============================================================================
# BACKGROUND TASKS
# =============================================================================

async def run_fusion_task(
    fusion_id: str,
    video_ids: List[str],
    config: Optional[FusionConfig]
):
    """
    Run fusion process in background.

    Updates job status as it progresses.
    """
    try:
        update_fusion_job(fusion_id, status="processing", progress=5.0)

        # Load configuration
        cfg = config or FusionConfig()

        # Initialize fusion system
        output_dir = OUTPUT_DIR / "fusion" / fusion_id
        fusion = MultiVideoFusion(
            output_dir=output_dir,
            smoothing_window=cfg.smoothing_window,
            outlier_threshold=cfg.outlier_threshold
        )

        update_fusion_job(fusion_id, progress=10.0)

        # Load skeleton sequences
        sequences = []
        for i, video_id in enumerate(video_ids):
            skeleton_path = get_skeleton_path(video_id)

            if skeleton_path:
                seq = load_skeleton_from_json(skeleton_path)
            else:
                # TODO: Extract skeleton from video if not pre-computed
                logger.warning(f"No skeleton for {video_id}, skipping")
                continue

            sequences.append(seq)

            progress = 10 + (i + 1) / len(video_ids) * 20  # 10-30%
            update_fusion_job(fusion_id, progress=progress)

        if len(sequences) < 2:
            raise ValueError("Need at least 2 valid skeleton sequences for fusion")

        # Align sequences
        update_fusion_job(fusion_id, progress=35.0, status="processing:alignment")
        aligned = fusion.align_multiple_videos(sequences)

        # Detect outliers
        update_fusion_job(fusion_id, progress=50.0, status="processing:outliers")
        outliers = fusion.detect_outliers(aligned.aligned_sequences)

        # Calculate consensus (excluding outliers if configured)
        update_fusion_job(fusion_id, progress=65.0, status="processing:consensus")

        if cfg.exclude_outliers and outliers:
            clean_sequences = [
                s for i, s in enumerate(aligned.aligned_sequences)
                if i not in outliers
            ]
        else:
            clean_sequences = aligned.aligned_sequences

        consensus = fusion.calculate_consensus_skeleton(clean_sequences)

        # Generate avatar video
        update_fusion_job(fusion_id, progress=80.0, status="processing:video")

        resolution = tuple(cfg.output_resolution) if cfg.output_resolution else (640, 480)
        avatar_path = fusion.generate_avatar_video(
            consensus,
            style=cfg.output_style,
            resolution=resolution
        )

        # Generate report
        update_fusion_job(fusion_id, progress=90.0, status="processing:report")
        report = fusion.fusion_report(sequences, consensus, outliers)

        # Save consensus skeleton
        consensus_path = output_dir / "consensus_skeleton.json"
        save_skeleton_to_json(consensus, consensus_path)

        # Save report
        report_path = output_dir / "fusion_report.json"
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Complete
        result = {
            "avatar_video_path": avatar_path,
            "consensus_skeleton_path": str(consensus_path),
            "report_path": str(report_path),
            "outliers": outliers,
            "input_count": len(video_ids),
            "used_count": len(clean_sequences),
            "consensus_frames": consensus.frame_count,
            "recommendations": report.get("recommendations", [])
        }

        update_fusion_job(
            fusion_id,
            status="completed",
            progress=100.0,
            result=result
        )

        logger.info(f"Fusion {fusion_id} completed successfully")

    except Exception as e:
        logger.error(f"Fusion {fusion_id} failed: {e}")
        update_fusion_job(
            fusion_id,
            status="failed",
            error=str(e)
        )


# =============================================================================
# FILE ENDPOINTS
# =============================================================================

@router.get(
    "/download/{file_type}/{file_id}",
    summary="Download generated file",
    description="Download a generated image or video file"
)
async def download_file(
    file_type: str = PathParam(..., description="File type: image, video, report"),
    file_id: str = PathParam(..., description="File identifier")
):
    """Download generated file."""
    # Map file type to directory
    type_dirs = {
        "image": OUTPUT_DIR / "technique_images",
        "sequence": OUTPUT_DIR / "sequences",
        "video": OUTPUT_DIR / "fusion",
        "report": OUTPUT_DIR / "fusion"
    }

    if file_type not in type_dirs:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type: {file_type}"
        )

    base_dir = type_dirs[file_type]

    # Find file (simple glob)
    matching_files = list(base_dir.rglob(f"*{file_id}*"))

    if not matching_files:
        raise HTTPException(
            status_code=404,
            detail=f"File not found: {file_id}"
        )

    file_path = matching_files[0]

    # Determine media type
    suffix = file_path.suffix.lower()
    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".mp4": "video/mp4",
        ".json": "application/json"
    }

    return FileResponse(
        path=str(file_path),
        media_type=media_types.get(suffix, "application/octet-stream"),
        filename=file_path.name
    )


# =============================================================================
# HEALTH CHECK
# =============================================================================

@router.get(
    "/health",
    summary="Video Studio health check"
)
async def video_studio_health():
    """Check Video Studio service health."""
    return {
        "status": "healthy",
        "service": "video_studio",
        "features": {
            "technique_image_generation": True,
            "transition_sequence": True,
            "multi_video_fusion": True
        },
        "directories": {
            "upload": str(UPLOAD_DIR),
            "output": str(OUTPUT_DIR),
            "fusion_jobs": str(FUSION_JOBS_DIR)
        }
    }

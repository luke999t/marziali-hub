"""
Upload API - Video Upload and Processing
Handles video uploads, validation, metadata extraction, and skeleton processing
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict
from pathlib import Path
import shutil
import uuid
import cv2
import json
import logging
from datetime import datetime

from models import (
    Project, VideoItem, MaestroInfo, VideoMetadata, SkeletonData,
    ProjectStorage, MartialArtStyle, VideoStatus, ProjectStatus
)
from skeleton_extraction_holistic import SkeletonExtractorHolistic
from comparison_tool import SkeletonComparator, VideoComparator
from technique_extractor import TechniqueExtractor
from style_classifier import StyleClassifier
from websocket_manager import manager, build_message, video_processing_started, video_processing_progress, video_processing_completed

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Pydantic models for API
class UploadRequest(BaseModel):
    """Upload request metadata"""
    project_id: Optional[str] = None
    project_name: Optional[str] = None
    maestro_name: str
    martial_art_style: MartialArtStyle
    maestro_experience_years: Optional[int] = None
    maestro_certification: Optional[str] = None
    maestro_bio: Optional[str] = None
    video_tags: Optional[str] = None  # comma-separated
    video_notes: Optional[str] = None


class UploadResponse(BaseModel):
    """Upload response"""
    success: bool
    project_id: str
    video_id: str
    message: str
    video_info: Optional[Dict] = None


class ProcessingStatus(BaseModel):
    """Processing status"""
    video_id: str
    status: VideoStatus
    message: str
    progress: float  # 0.0 to 1.0


# FastAPI app
app = FastAPI(
    title="Video Upload API",
    description="API for uploading and processing martial arts videos",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
UPLOAD_DIR = Path("./uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

SKELETON_DIR = Path("./skeletons")
SKELETON_DIR.mkdir(parents=True, exist_ok=True)

MAX_VIDEO_SIZE = 500 * 1024 * 1024  # 500 MB
ALLOWED_EXTENSIONS = {'.mp4', '.avi', '.mov', '.mkv', '.wmv'}
ALLOWED_CODECS = {'h264', 'h265', 'vp8', 'vp9', 'mpeg4'}

# Storage
storage = ProjectStorage()

# Processing status tracking
processing_status: Dict[str, ProcessingStatus] = {}


def validate_video_file(file: UploadFile) -> tuple[bool, str]:
    """Validate uploaded video file"""

    # Check extension
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return False, f"Invalid file extension. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"

    # Check size (if available in headers)
    if hasattr(file, 'size') and file.size:
        if file.size > MAX_VIDEO_SIZE:
            return False, f"File too large. Max size: {MAX_VIDEO_SIZE // (1024*1024)} MB"

    return True, "OK"


def extract_video_metadata(video_path: Path) -> Optional[VideoMetadata]:
    """Extract metadata from video file using OpenCV"""
    try:
        cap = cv2.VideoCapture(str(video_path))

        if not cap.isOpened():
            logger.error(f"Could not open video: {video_path}")
            return None

        # Get properties
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = total_frames / fps if fps > 0 else 0

        # Get codec
        fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
        codec = "".join([chr((fourcc_int >> 8 * i) & 0xFF) for i in range(4)])

        # Get bitrate (approximate)
        bitrate = int(cap.get(cv2.CAP_PROP_BITRATE)) if cap.get(cv2.CAP_PROP_BITRATE) else None

        # Get file size
        size_bytes = video_path.stat().st_size

        cap.release()

        metadata = VideoMetadata(
            filename=video_path.name,
            filepath=str(video_path),
            size_bytes=size_bytes,
            duration_seconds=duration,
            width=width,
            height=height,
            fps=fps,
            total_frames=total_frames,
            codec=codec if codec.strip() else None,
            bitrate=bitrate
        )

        logger.info(f"Extracted metadata: {width}x{height}, {fps}fps, {total_frames} frames")
        return metadata

    except Exception as e:
        logger.error(f"Error extracting metadata: {e}")
        return None


def process_video_skeleton(
    video_id: str,
    video_path: Path,
    skeleton_output_path: Path,
    project_id: str
):
    """Background task: Extract skeleton from video"""
    try:
        # Update status
        processing_status[video_id] = ProcessingStatus(
            video_id=video_id,
            status=VideoStatus.PROCESSING,
            message="Extracting skeleton landmarks...",
            progress=0.0
        )

        # Load project
        project = storage.load_project(project_id)
        if not project:
            raise Exception(f"Project not found: {project_id}")

        # Update video status
        project.update_video_status(video_id, VideoStatus.PROCESSING, "Extracting skeleton...")
        storage.save_project(project)

        # Extract skeleton
        logger.info(f"Starting skeleton extraction for video: {video_path}")
        extractor = SkeletonExtractorHolistic()

        # Extract skeleton data
        import time
        start_time = time.time()
        result = extractor.extract_from_video(str(video_path))
        processing_time = time.time() - start_time

        # Save to JSON
        extractor.save_json(result, str(skeleton_output_path))

        # Calculate quality metrics from result
        frames = result.get('frames', [])
        frames_processed = len(frames)

        body_count = sum(1 for f in frames if f.get('body'))
        left_hand_count = sum(1 for f in frames if f.get('left_hand'))
        right_hand_count = sum(1 for f in frames if f.get('right_hand'))

        detection_rates = {
            'body': body_count / frames_processed if frames_processed > 0 else 0,
            'left_hand': left_hand_count / frames_processed if frames_processed > 0 else 0,
            'right_hand': right_hand_count / frames_processed if frames_processed > 0 else 0
        }

        # Calculate average confidence
        confidences = []
        for frame in frames:
            for lm in frame.get('body', []):
                confidences.append(lm.get('confidence', 0))
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        # Quality assessment
        quality_assessment = "excellent" if avg_confidence > 0.8 else "good" if avg_confidence > 0.6 else "fair"

        # Create skeleton data
        skeleton_data = SkeletonData(
            skeleton_filepath=str(skeleton_output_path),
            total_landmarks=75,
            frames_processed=frames_processed,
            detection_rates=detection_rates,
            avg_confidence=avg_confidence,
            quality_assessment=quality_assessment,
            processing_time_seconds=processing_time
        )

        # Update video with skeleton data
        video = project.get_video(video_id)
        if video:
            video.skeleton = skeleton_data
            video.status = VideoStatus.COMPLETED
            video.status_message = "Processing completed successfully"
            storage.save_project(project)

        # Update processing status
        processing_status[video_id] = ProcessingStatus(
            video_id=video_id,
            status=VideoStatus.COMPLETED,
            message="Processing completed successfully",
            progress=1.0
        )

        logger.info(f"Skeleton extraction completed for video: {video_id}")

    except Exception as e:
        logger.error(f"Error processing video skeleton: {e}")

        # Update video status to failed
        try:
            project = storage.load_project(project_id)
            if project:
                project.update_video_status(video_id, VideoStatus.FAILED, str(e))
                storage.save_project(project)
        except:
            pass

        # Update processing status
        processing_status[video_id] = ProcessingStatus(
            video_id=video_id,
            status=VideoStatus.FAILED,
            message=f"Processing failed: {str(e)}",
            progress=0.0
        )


@app.post("/api/upload", response_model=UploadResponse)
async def upload_video(
    background_tasks: BackgroundTasks,
    video_file: UploadFile = File(...),
    project_id: Optional[str] = Form(None),
    project_name: Optional[str] = Form(None),
    maestro_name: str = Form(...),
    martial_art_style: str = Form(...),
    maestro_experience_years: Optional[int] = Form(None),
    maestro_certification: Optional[str] = Form(None),
    maestro_bio: Optional[str] = Form(None),
    video_tags: Optional[str] = Form(None),
    video_notes: Optional[str] = Form(None)
):
    """
    Upload video and process automatically

    Creates or updates project, extracts metadata, and starts skeleton processing
    """
    try:
        # Validate file
        is_valid, error_msg = validate_video_file(video_file)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)

        # Validate martial art style
        try:
            style = MartialArtStyle(martial_art_style)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid martial art style. Allowed: {[s.value for s in MartialArtStyle]}"
            )

        # Generate IDs
        video_id = f"vid_{uuid.uuid4().hex[:12]}"

        # Load or create project
        if project_id:
            project = storage.load_project(project_id)
            if not project:
                raise HTTPException(status_code=404, detail="Project not found")
        else:
            # Create new project
            project_id = f"proj_{uuid.uuid4().hex[:12]}"
            project = Project(
                id=project_id,
                name=project_name or f"Project {style.value} - {datetime.now().strftime('%Y%m%d')}",
                description=f"Martial arts project - {style.value}",
                style=style,
                status=ProjectStatus.ACTIVE
            )

        # Save uploaded file
        video_filename = f"{video_id}_{video_file.filename}"
        video_path = UPLOAD_DIR / video_filename

        logger.info(f"Saving uploaded file: {video_path}")
        with open(video_path, 'wb') as f:
            shutil.copyfileobj(video_file.file, f)

        # Extract metadata
        logger.info("Extracting video metadata...")
        metadata = extract_video_metadata(video_path)
        if not metadata:
            # Cleanup
            video_path.unlink(missing_ok=True)
            raise HTTPException(status_code=500, detail="Failed to extract video metadata")

        # Create maestro info
        maestro = MaestroInfo(
            name=maestro_name,
            style=style,
            experience_years=maestro_experience_years,
            certification=maestro_certification,
            bio=maestro_bio
        )

        # Parse tags
        tags = [t.strip() for t in video_tags.split(',')] if video_tags else []

        # Create video item
        video_item = VideoItem(
            id=video_id,
            project_id=project_id,
            maestro=maestro,
            metadata=metadata,
            status=VideoStatus.VALIDATING,
            status_message="Video uploaded, validating...",
            tags=tags,
            notes=video_notes
        )

        # Add video to project
        project.add_video(video_item)
        storage.save_project(project)

        logger.info(f"Video added to project: {project_id}/{video_id}")

        # Start skeleton processing in background
        skeleton_output_path = SKELETON_DIR / f"{video_id}_skeleton.json"
        background_tasks.add_task(
            process_video_skeleton,
            video_id,
            video_path,
            skeleton_output_path,
            project_id
        )

        # Update status to processing
        project.update_video_status(video_id, VideoStatus.PROCESSING, "Processing skeleton...")
        storage.save_project(project)

        return UploadResponse(
            success=True,
            project_id=project_id,
            video_id=video_id,
            message="Video uploaded successfully. Processing started.",
            video_info={
                "filename": metadata.filename,
                "duration": metadata.duration_seconds,
                "resolution": f"{metadata.width}x{metadata.height}",
                "fps": metadata.fps,
                "total_frames": metadata.total_frames,
                "size_mb": round(metadata.size_bytes / (1024 * 1024), 2)
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading video: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/status/{video_id}", response_model=ProcessingStatus)
async def get_processing_status(video_id: str):
    """Get processing status for a video"""
    if video_id not in processing_status:
        raise HTTPException(status_code=404, detail="Video not found or not processing")

    return processing_status[video_id]


@app.get("/api/projects")
async def list_projects():
    """List all projects"""
    projects = storage.list_projects()
    return {
        "total": len(projects),
        "projects": [
            {
                "id": p.id,
                "name": p.name,
                "style": p.style,
                "status": p.status,
                "videos_count": len(p.videos),
                "created_at": p.created_at.isoformat(),
                "statistics": p.get_statistics()
            }
            for p in projects
        ]
    }


@app.get("/api/projects/{project_id}")
async def get_project(project_id: str):
    """Get project details"""
    project = storage.load_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "id": project.id,
        "name": project.name,
        "description": project.description,
        "style": project.style,
        "status": project.status,
        "created_at": project.created_at.isoformat(),
        "updated_at": project.updated_at.isoformat(),
        "videos": [
            {
                "id": v.id,
                "maestro_name": v.maestro.name,
                "filename": v.metadata.filename,
                "duration": v.metadata.duration_seconds,
                "status": v.status,
                "has_skeleton": v.skeleton is not None,
                "tags": v.tags
            }
            for v in project.videos
        ],
        "statistics": project.get_statistics()
    }


@app.delete("/api/projects/{project_id}")
async def delete_project(project_id: str):
    """Delete project and associated files"""
    project = storage.load_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    # Delete video files
    for video in project.videos:
        video_path = Path(video.metadata.filepath)
        if video_path.exists():
            video_path.unlink()

        if video.skeleton:
            skeleton_path = Path(video.skeleton.skeleton_filepath)
            if skeleton_path.exists():
                skeleton_path.unlink()

    # Delete project
    storage.delete_project(project_id)

    return {"message": f"Project {project_id} deleted successfully"}


@app.get("/")
async def root():
    """Serve upload interface"""
    web_dir = Path(__file__).parent / "web"
    index_file = web_dir / "upload_interface.html"

    if index_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(index_file, media_type="text/html")
    else:
        # Fallback to API info
        return {
            "name": "Video Upload API",
            "version": "1.0.0",
            "endpoints": {
                "upload": "POST /api/upload",
                "status": "GET /api/status/{video_id}",
                "list_projects": "GET /api/projects",
                "get_project": "GET /api/projects/{project_id}",
                "delete_project": "DELETE /api/projects/{project_id}"
            },
            "supported_formats": list(ALLOWED_EXTENSIONS),
            "max_file_size_mb": MAX_VIDEO_SIZE // (1024 * 1024),
            "martial_art_styles": [s.value for s in MartialArtStyle]
        }


@app.get("/upload_interface.js")
async def serve_upload_js():
    """Serve JavaScript file"""
    web_dir = Path(__file__).parent / "web"
    js_file = web_dir / "upload_interface.js"

    if js_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(js_file, media_type="application/javascript")
    else:
        raise HTTPException(status_code=404, detail="JavaScript file not found")


@app.get("/comparison")
async def serve_comparison_interface():
    """Serve comparison interface"""
    web_dir = Path(__file__).parent / "web"
    html_file = web_dir / "comparison_interface.html"

    if html_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(html_file, media_type="text/html")
    else:
        raise HTTPException(status_code=404, detail="Comparison interface not found")


@app.get("/comparison_interface.js")
async def serve_comparison_js():
    """Serve comparison JavaScript"""
    web_dir = Path(__file__).parent / "web"
    js_file = web_dir / "comparison_interface.js"

    if js_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(js_file, media_type="application/javascript")
    else:
        raise HTTPException(status_code=404, detail="JavaScript file not found")


@app.get("/dashboard")
async def serve_dashboard():
    """Serve analytics dashboard"""
    web_dir = Path(__file__).parent / "web"
    html_file = web_dir / "dashboard.html"

    if html_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(html_file, media_type="text/html")
    else:
        raise HTTPException(status_code=404, detail="Dashboard not found")


@app.get("/dashboard.js")
async def serve_dashboard_js():
    """Serve dashboard JavaScript"""
    web_dir = Path(__file__).parent / "web"
    js_file = web_dir / "dashboard.js"

    if js_file.exists():
        from fastapi.responses import FileResponse
        return FileResponse(js_file, media_type="application/javascript")
    else:
        raise HTTPException(status_code=404, detail="JavaScript file not found")


@app.get("/uploads/{filename}")
async def serve_video_file(filename: str):
    """Serve uploaded video files"""
    video_path = UPLOAD_DIR / filename

    if not video_path.exists():
        raise HTTPException(status_code=404, detail="Video file not found")

    from fastapi.responses import FileResponse
    return FileResponse(video_path, media_type="video/mp4")


@app.get("/api/videos/{video_id}/skeleton")
async def get_video_skeleton(video_id: str):
    """Get complete skeleton data for a video"""
    video_project = None
    video = None

    for project in storage.list_projects():
        for v in project.videos:
            if v.id == video_id:
                video_project = project
                video = v
                break
        if video:
            break

    if not video:
        raise HTTPException(status_code=404, detail="Video not found")

    if not video.skeleton:
        raise HTTPException(status_code=404, detail="Skeleton data not available")

    try:
        with open(video.skeleton.skeleton_filepath, 'r') as f:
            skeleton_data = json.load(f)
        return skeleton_data
    except Exception as e:
        logger.error(f"Error loading skeleton data: {e}")
        raise HTTPException(status_code=500, detail="Error loading skeleton data")


class ComparisonRequest(BaseModel):
    """Request to compare two videos"""
    video_id_1: str
    video_id_2: str
    create_video_output: bool = False


class ComparisonResult(BaseModel):
    """Comparison result"""
    video_id_1: str
    video_id_2: str
    total_frames_compared: int
    average_similarity: float
    average_position_error: float
    average_synchronization: float
    comparison_video_path: Optional[str] = None


@app.post("/api/compare", response_model=ComparisonResult)
async def compare_videos(request: ComparisonRequest):
    """Compare two videos from the same or different projects"""
    try:
        video1_project = None
        video2_project = None
        video1 = None
        video2 = None

        for project in storage.list_projects():
            for video in project.videos:
                if video.id == request.video_id_1:
                    video1_project = project
                    video1 = video
                if video.id == request.video_id_2:
                    video2_project = project
                    video2 = video

        if not video1 or not video2:
            raise HTTPException(status_code=404, detail="One or both videos not found")

        if not video1.skeleton or not video2.skeleton:
            raise HTTPException(status_code=400, detail="Both videos must have skeleton data")

        comparator = SkeletonComparator()
        data1 = comparator.load_skeleton_data(video1.skeleton.skeleton_filepath)
        data2 = comparator.load_skeleton_data(video2.skeleton.skeleton_filepath)

        results = comparator.compare_sequences(data1, data2)

        comparison_video_path = None
        if request.create_video_output:
            video_comparator = VideoComparator()
            output_filename = f"comparison_{request.video_id_1}_{request.video_id_2}.mp4"
            comparison_video_path = UPLOAD_DIR / output_filename

            video_comparator.create_side_by_side_video(
                video1.metadata.filepath,
                video2.metadata.filepath,
                video1.skeleton.skeleton_filepath,
                video2.skeleton.skeleton_filepath,
                str(comparison_video_path),
                show_skeleton=True
            )

        return ComparisonResult(
            video_id_1=request.video_id_1,
            video_id_2=request.video_id_2,
            total_frames_compared=results['total_frames_compared'],
            average_similarity=results['average_similarity'],
            average_position_error=results['average_position_error'],
            average_synchronization=results['average_synchronization'],
            comparison_video_path=str(comparison_video_path) if comparison_video_path else None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error comparing videos: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/projects/{project_id}/videos")
async def get_project_videos(project_id: str):
    """Get all videos in a project for comparison"""
    project = storage.load_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    return {
        "project_id": project.id,
        "project_name": project.name,
        "videos": [
            {
                "id": v.id,
                "maestro_name": v.maestro.name,
                "filename": v.metadata.filename,
                "duration": v.metadata.duration_seconds,
                "status": v.status,
                "has_skeleton": v.skeleton is not None,
                "tags": v.tags,
                "created_at": v.uploaded_at.isoformat()
            }
            for v in project.videos
            if v.status == VideoStatus.COMPLETED and v.skeleton is not None
        ]
    }


@app.post("/api/videos/{video_id}/analyze-techniques")
async def analyze_techniques(video_id: str):
    """Analyze and detect techniques in video"""
    try:
        video = None
        for project in storage.list_projects():
            for v in project.videos:
                if v.id == video_id:
                    video = v
                    break
            if video:
                break

        if not video or not video.skeleton:
            raise HTTPException(status_code=404, detail="Video or skeleton not found")

        technique_extractor = TechniqueExtractor()
        classifier = StyleClassifier()

        with open(video.skeleton.skeleton_filepath, 'r') as f:
            skeleton_data = json.load(f)

        detected_style = classifier.classify(skeleton_data)
        techniques = technique_extractor.extract(skeleton_data, detected_style)

        return {
            "video_id": video_id,
            "detected_style": detected_style,
            "techniques": techniques,
            "confidence": 0.85,
            "technique_count": len(techniques)
        }

    except Exception as e:
        logger.error(f"Error analyzing techniques: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# WebSocket Endpoints
@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates"""
    await manager.connect(websocket, client_id)

    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()

            # Handle subscription requests
            if data.get("action") == "subscribe_video":
                video_id = data.get("video_id")
                if video_id:
                    manager.subscribe_to_video(websocket, video_id)
                    await manager.send_personal_message({
                        "event": "subscribed",
                        "video_id": video_id
                    }, websocket)

            elif data.get("action") == "subscribe_project":
                project_id = data.get("project_id")
                if project_id:
                    manager.subscribe_to_project(websocket, project_id)
                    await manager.send_personal_message({
                        "event": "subscribed",
                        "project_id": project_id
                    }, websocket)

            elif data.get("action") == "ping":
                await manager.send_personal_message({
                    "event": "pong",
                    "timestamp": datetime.utcnow().isoformat()
                }, websocket)

    except WebSocketDisconnect:
        manager.disconnect(websocket, client_id)
        logger.info(f"Client {client_id} disconnected")
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {e}")
        manager.disconnect(websocket, client_id)


@app.get("/ws/stats")
async def websocket_stats():
    """Get WebSocket connection statistics"""
    return {
        "total_connections": manager.get_total_connections(),
        "active_clients": len(manager.active_connections),
        "video_subscriptions": len(manager.video_connections),
        "project_subscriptions": len(manager.project_connections)
    }


def main():
    """Run upload API server"""
    import uvicorn

    uvicorn.run(
        "upload_api:app",
        host="0.0.0.0",
        port=8081,
        reload=True,
        log_level="info"
    )


if __name__ == '__main__':
    main()

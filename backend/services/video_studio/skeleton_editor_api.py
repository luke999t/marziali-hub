"""
Skeleton Editor API - FastAPI Backend
REST API for web-based skeleton editor with 75-landmark visualization
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, List, Optional
from pathlib import Path
import json
import cv2
import numpy as np
import logging
import base64

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Pydantic models
class VideoInfo(BaseModel):
    """Video information"""
    filename: str
    width: int
    height: int
    fps: float
    total_frames: int
    duration: float


class SkeletonInfo(BaseModel):
    """Skeleton data information"""
    version: str
    source: str
    total_landmarks: int
    frames_count: int


class FrameSkeleton(BaseModel):
    """Skeleton data for a single frame"""
    index: int
    timestamp: float
    body: List[Dict]
    left_hand: List[Dict]
    right_hand: List[Dict]


class QualityMetrics(BaseModel):
    """Quality metrics for skeleton data"""
    total_frames: int
    frames_with_body: int
    frames_with_left_hand: int
    frames_with_right_hand: int
    body_detection_rate: float
    left_hand_detection_rate: float
    right_hand_detection_rate: float
    avg_body_confidence: float
    quality_assessment: str


# FastAPI app
app = FastAPI(
    title="Skeleton Editor API",
    description="API for web-based skeleton editor with 75-landmark visualization",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# In-memory storage (replace with database in production)
projects = {}


class SkeletonEditorProject:
    """Skeleton editor project"""

    def __init__(self, project_id: str, video_path: str, skeleton_path: str):
        self.project_id = project_id
        self.video_path = Path(video_path)
        self.skeleton_path = Path(skeleton_path)

        # Validate files
        if not self.video_path.exists():
            raise FileNotFoundError(f"Video not found: {video_path}")
        if not self.skeleton_path.exists():
            raise FileNotFoundError(f"Skeleton JSON not found: {skeleton_path}")

        # Load skeleton data
        with open(self.skeleton_path, 'r') as f:
            self.skeleton_data = json.load(f)

        # Open video
        self.cap = cv2.VideoCapture(str(self.video_path))
        if not self.cap.isOpened():
            raise RuntimeError(f"Could not open video: {video_path}")

        # Video properties
        self.width = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        self.height = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        self.fps = self.cap.get(cv2.CAP_PROP_FPS)
        self.total_frames = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT))
        self.duration = self.total_frames / self.fps if self.fps > 0 else 0

        logger.info(f"Project '{project_id}' initialized: {self.width}x{self.height}, {self.total_frames} frames")

    def get_video_info(self) -> VideoInfo:
        """Get video information"""
        return VideoInfo(
            filename=self.video_path.name,
            width=self.width,
            height=self.height,
            fps=self.fps,
            total_frames=self.total_frames,
            duration=self.duration
        )

    def get_skeleton_info(self) -> SkeletonInfo:
        """Get skeleton information"""
        return SkeletonInfo(
            version=self.skeleton_data.get('version', 'unknown'),
            source=self.skeleton_data.get('source', 'unknown'),
            total_landmarks=self.skeleton_data.get('total_landmarks', 0),
            frames_count=len(self.skeleton_data.get('frames', []))
        )

    def get_frame_skeleton(self, frame_idx: int) -> Optional[FrameSkeleton]:
        """Get skeleton data for specific frame"""
        frames = self.skeleton_data.get('frames', [])
        if 0 <= frame_idx < len(frames):
            frame_data = frames[frame_idx]
            return FrameSkeleton(**frame_data)
        return None

    def get_frame_image(self, frame_idx: int) -> Optional[np.ndarray]:
        """Get frame image"""
        self.cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
        ret, frame = self.cap.read()
        return frame if ret else None

    def get_frame_with_overlay(
        self,
        frame_idx: int,
        show_body: bool = True,
        show_hands: bool = True
    ) -> Optional[np.ndarray]:
        """Get frame with skeleton overlay"""
        frame = self.get_frame_image(frame_idx)
        if frame is None:
            return None

        skeleton = self.get_frame_skeleton(frame_idx)
        if not skeleton:
            return frame

        # Draw skeleton overlay
        frame = self._draw_skeleton_overlay(
            frame,
            skeleton,
            show_body=show_body,
            show_hands=show_hands
        )

        return frame

    def _draw_skeleton_overlay(
        self,
        frame: np.ndarray,
        skeleton: FrameSkeleton,
        show_body: bool = True,
        show_hands: bool = True
    ) -> np.ndarray:
        """Draw skeleton overlay on frame"""
        h, w = frame.shape[:2]

        # Color scheme (BGR)
        COLOR_BODY = (255, 100, 100)
        COLOR_LEFT_HAND = (100, 255, 100)
        COLOR_RIGHT_HAND = (100, 100, 255)

        # Draw body
        if show_body and skeleton.body:
            for lm in skeleton.body:
                x = int(lm['x'] * w)
                y = int(lm['y'] * h)
                cv2.circle(frame, (x, y), 4, COLOR_BODY, -1)

        # Draw left hand
        if show_hands and skeleton.left_hand:
            for lm in skeleton.left_hand:
                x = int(lm['x'] * w)
                y = int(lm['y'] * h)
                cv2.circle(frame, (x, y), 3, COLOR_LEFT_HAND, -1)

        # Draw right hand
        if show_hands and skeleton.right_hand:
            for lm in skeleton.right_hand:
                x = int(lm['x'] * w)
                y = int(lm['y'] * h)
                cv2.circle(frame, (x, y), 3, COLOR_RIGHT_HAND, -1)

        return frame

    def calculate_quality_metrics(self) -> QualityMetrics:
        """Calculate quality metrics"""
        frames = self.skeleton_data.get('frames', [])
        total = len(frames)

        if total == 0:
            return QualityMetrics(
                total_frames=0,
                frames_with_body=0,
                frames_with_left_hand=0,
                frames_with_right_hand=0,
                body_detection_rate=0.0,
                left_hand_detection_rate=0.0,
                right_hand_detection_rate=0.0,
                avg_body_confidence=0.0,
                quality_assessment="no data"
            )

        body_count = sum(1 for f in frames if f.get('body'))
        left_hand_count = sum(1 for f in frames if f.get('left_hand'))
        right_hand_count = sum(1 for f in frames if f.get('right_hand'))

        # Average confidence
        body_confidences = []
        for frame in frames:
            for lm in frame.get('body', []):
                body_confidences.append(lm['confidence'])

        avg_body_conf = np.mean(body_confidences) if body_confidences else 0

        quality = "excellent" if avg_body_conf > 0.8 else "good" if avg_body_conf > 0.6 else "fair"

        return QualityMetrics(
            total_frames=total,
            frames_with_body=body_count,
            frames_with_left_hand=left_hand_count,
            frames_with_right_hand=right_hand_count,
            body_detection_rate=body_count / total,
            left_hand_detection_rate=left_hand_count / total,
            right_hand_detection_rate=right_hand_count / total,
            avg_body_confidence=float(avg_body_conf),
            quality_assessment=quality
        )

    def close(self):
        """Cleanup resources"""
        if self.cap:
            self.cap.release()


# API Endpoints

@app.post("/api/projects")
async def create_project(
    video_path: str = Query(..., description="Path to video file"),
    skeleton_path: str = Query(..., description="Path to skeleton JSON file"),
    project_id: Optional[str] = Query(None, description="Optional project ID")
):
    """Create a new skeleton editor project"""
    try:
        if project_id is None:
            import uuid
            project_id = str(uuid.uuid4())

        project = SkeletonEditorProject(project_id, video_path, skeleton_path)
        projects[project_id] = project

        return {
            "project_id": project_id,
            "video_info": project.get_video_info(),
            "skeleton_info": project.get_skeleton_info()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/projects/{project_id}/info")
async def get_project_info(project_id: str):
    """Get project information"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]
    return {
        "video_info": project.get_video_info(),
        "skeleton_info": project.get_skeleton_info()
    }


@app.get("/api/projects/{project_id}/skeleton/{frame_idx}")
async def get_frame_skeleton(project_id: str, frame_idx: int):
    """Get skeleton data for specific frame"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]
    skeleton = project.get_frame_skeleton(frame_idx)

    if skeleton is None:
        raise HTTPException(status_code=404, detail="Frame not found")

    return skeleton


@app.get("/api/projects/{project_id}/frame/{frame_idx}")
async def get_frame(
    project_id: str,
    frame_idx: int,
    show_overlay: bool = Query(False, description="Show skeleton overlay"),
    show_body: bool = Query(True, description="Show body landmarks"),
    show_hands: bool = Query(True, description="Show hand landmarks")
):
    """Get frame image (optionally with skeleton overlay)"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]

    if show_overlay:
        frame = project.get_frame_with_overlay(frame_idx, show_body, show_hands)
    else:
        frame = project.get_frame_image(frame_idx)

    if frame is None:
        raise HTTPException(status_code=404, detail="Frame not found")

    # Encode frame as JPEG
    _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 90])

    return StreamingResponse(
        iter([buffer.tobytes()]),
        media_type="image/jpeg"
    )


@app.get("/api/projects/{project_id}/quality")
async def get_quality_metrics(project_id: str):
    """Get quality metrics for project"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]
    return project.calculate_quality_metrics()


@app.get("/api/projects/{project_id}/video")
async def get_video(project_id: str):
    """Serve video file"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]
    return FileResponse(project.video_path)


@app.delete("/api/projects/{project_id}")
async def close_project(project_id: str):
    """Close and remove project"""
    if project_id not in projects:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects[project_id]
    project.close()
    del projects[project_id]

    return {"message": "Project closed successfully"}


@app.get("/")
async def root():
    """Serve web editor"""
    web_dir = Path(__file__).parent / "web"
    index_file = web_dir / "skeleton_editor.html"

    if index_file.exists():
        return FileResponse(index_file, media_type="text/html")
    else:
        return {
            "name": "Skeleton Editor API",
            "version": "1.0.0",
            "endpoints": {
                "create_project": "POST /api/projects",
                "get_info": "GET /api/projects/{project_id}/info",
                "get_skeleton": "GET /api/projects/{project_id}/skeleton/{frame_idx}",
                "get_frame": "GET /api/projects/{project_id}/frame/{frame_idx}",
                "get_quality": "GET /api/projects/{project_id}/quality",
                "get_video": "GET /api/projects/{project_id}/video",
                "close_project": "DELETE /api/projects/{project_id}"
            }
        }


@app.get("/skeleton_editor.js")
async def serve_js():
    """Serve JavaScript file"""
    web_dir = Path(__file__).parent / "web"
    js_file = web_dir / "skeleton_editor.js"

    if js_file.exists():
        return FileResponse(js_file, media_type="application/javascript")
    else:
        raise HTTPException(status_code=404, detail="JavaScript file not found")


def main():
    """Run API server"""
    import uvicorn

    uvicorn.run(
        "skeleton_editor_api:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )


if __name__ == '__main__':
    main()

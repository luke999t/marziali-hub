"""
🎓 AI_MODULE: Overlay Schemas
🎓 AI_DESCRIPTION: Pydantic models per annotazioni didattiche su video/frame
🎓 AI_BUSINESS: Struttura dati per frecce, angoli, testo su contenuti martial arts
🎓 AI_TEACHING: Pydantic V2, discriminated unions per tipi annotazione

📁 POSIZIONE: backend/services/overlay/schemas.py
"""

from typing import List, Optional, Dict, Any, Tuple, Union, Literal
from enum import Enum
from pydantic import BaseModel, Field, field_validator
from datetime import datetime
import uuid


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ═══════════════════════════════════════════════════════════════════════════════

class AnnotationType(str, Enum):
    """Tipi di annotazione supportati"""
    ARROW = "arrow"
    CURVED_ARROW = "curved_arrow"
    ANGLE = "angle"
    TEXT = "text"
    HIGHLIGHT = "highlight"
    LINE = "line"
    TRAJECTORY = "trajectory"
    COMPARISON = "comparison"


class AnchorPoint(str, Enum):
    """
    Punti di ancoraggio per annotazioni.
    Mappano ai 33 landmark MediaPipe Pose.
    """
    # Testa
    NOSE = "nose"
    LEFT_EYE = "left_eye"
    RIGHT_EYE = "right_eye"
    LEFT_EAR = "left_ear"
    RIGHT_EAR = "right_ear"
    
    # Spalle
    LEFT_SHOULDER = "left_shoulder"
    RIGHT_SHOULDER = "right_shoulder"
    
    # Gomiti
    LEFT_ELBOW = "left_elbow"
    RIGHT_ELBOW = "right_elbow"
    
    # Polsi/Mani
    LEFT_WRIST = "left_wrist"
    RIGHT_WRIST = "right_wrist"
    
    # Fianchi
    LEFT_HIP = "left_hip"
    RIGHT_HIP = "right_hip"
    
    # Ginocchia
    LEFT_KNEE = "left_knee"
    RIGHT_KNEE = "right_knee"
    
    # Caviglie
    LEFT_ANKLE = "left_ankle"
    RIGHT_ANKLE = "right_ankle"
    
    # Punti calcolati
    CENTER_BODY = "center_body"
    CENTER_HIPS = "center_hips"
    CENTER_SHOULDERS = "center_shoulders"
    
    # Coordinate custom
    CUSTOM = "custom"


class ArrowStyle(str, Enum):
    SOLID = "solid"
    DASHED = "dashed"
    DOUBLE = "double"


class TextPosition(str, Enum):
    ABOVE = "above"
    BELOW = "below"
    LEFT = "left"
    RIGHT = "right"
    CENTER = "center"


# ═══════════════════════════════════════════════════════════════════════════════
# BASE MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ColorRGBA(BaseModel):
    """Colore RGBA"""
    r: int = Field(ge=0, le=255, default=255)
    g: int = Field(ge=0, le=255, default=100)
    b: int = Field(ge=0, le=255, default=0)
    a: float = Field(ge=0.0, le=1.0, default=1.0)
    
    def to_bgr(self) -> Tuple[int, int, int]:
        """Converti a BGR per OpenCV"""
        return (self.b, self.g, self.r)
    
    def to_bgra(self) -> Tuple[int, int, int, int]:
        """Converti a BGRA per OpenCV con alpha"""
        return (self.b, self.g, self.r, int(self.a * 255))
    
    def to_rgba(self) -> Tuple[int, int, int, int]:
        """Converti a RGBA per PIL"""
        return (self.r, self.g, self.b, int(self.a * 255))
    
    @classmethod
    def from_hex(cls, hex_color: str) -> "ColorRGBA":
        """Crea da stringa hex (#RRGGBB o #RRGGBBAA)"""
        hex_color = hex_color.lstrip('#')
        if len(hex_color) == 6:
            r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
            return cls(r=r, g=g, b=b)
        elif len(hex_color) == 8:
            r, g, b, a = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16), int(hex_color[6:8], 16)
            return cls(r=r, g=g, b=b, a=a/255)
        raise ValueError(f"Invalid hex color: {hex_color}")


class Point2D(BaseModel):
    """Punto 2D"""
    x: float
    y: float
    normalized: bool = Field(default=True, description="Se True, x/y sono 0.0-1.0")
    
    def to_pixels(self, width: int, height: int) -> Tuple[int, int]:
        """Converti a coordinate pixel"""
        if self.normalized:
            return (int(self.x * width), int(self.y * height))
        return (int(self.x), int(self.y))


# ═══════════════════════════════════════════════════════════════════════════════
# ANNOTATION MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class AnnotationBase(BaseModel):
    """Base per tutte le annotazioni"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: AnnotationType
    frame_index: int = Field(ge=0)
    frame_end: Optional[int] = Field(default=None, description="Per multi-frame")
    color: ColorRGBA = Field(default_factory=ColorRGBA)
    thickness: int = Field(default=3, ge=1, le=20)
    opacity: float = Field(default=1.0, ge=0.0, le=1.0)
    visible: bool = True
    label: Optional[str] = None
    z_index: int = Field(default=0, description="Ordine rendering")


class ArrowAnnotation(AnnotationBase):
    """
    Freccia direzionale per indicare movimento
    """
    type: Literal[AnnotationType.ARROW] = AnnotationType.ARROW
    
    start_anchor: AnchorPoint = AnchorPoint.CUSTOM
    start_point: Optional[Point2D] = None
    
    end_anchor: AnchorPoint = AnchorPoint.CUSTOM
    end_point: Optional[Point2D] = None
    
    style: ArrowStyle = ArrowStyle.SOLID
    head_size: int = Field(default=15, ge=5, le=50)


class CurvedArrowAnnotation(AnnotationBase):
    """
    Freccia curva per indicare rotazione
    """
    type: Literal[AnnotationType.CURVED_ARROW] = AnnotationType.CURVED_ARROW
    
    center_anchor: AnchorPoint = AnchorPoint.CUSTOM
    center_point: Optional[Point2D] = None
    
    radius: int = Field(default=50, ge=10, le=200)
    start_angle: float = Field(default=0, ge=0, le=360)
    end_angle: float = Field(default=90, ge=0, le=360)
    clockwise: bool = True
    head_size: int = Field(default=12, ge=5, le=40)


class AngleAnnotation(AnnotationBase):
    """
    Indicatore angolo articolazione con gradi
    """
    type: Literal[AnnotationType.ANGLE] = AnnotationType.ANGLE
    
    # Tre punti: A-vertex-B definiscono l'angolo
    point_a: AnchorPoint
    vertex: AnchorPoint
    point_b: AnchorPoint
    
    arc_radius: int = Field(default=40, ge=10, le=200)
    show_degrees: bool = True
    font_size: int = Field(default=18, ge=10, le=36)
    
    # Feedback visivo
    target_angle: Optional[float] = Field(default=None, ge=0, le=360)
    tolerance: float = Field(default=10.0, ge=1, le=45)
    color_correct: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=255, b=0))
    color_warning: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=255, b=0))
    color_error: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=0, b=0))


class TextAnnotation(AnnotationBase):
    """
    Testo didattico posizionabile
    """
    type: Literal[AnnotationType.TEXT] = AnnotationType.TEXT
    
    anchor: AnchorPoint = AnchorPoint.CUSTOM
    position: Optional[Point2D] = None
    text_position: TextPosition = TextPosition.ABOVE
    offset_x: int = 0
    offset_y: int = -30
    
    text: str
    font_size: int = Field(default=24, ge=8, le=72)
    font_family: str = "Arial"
    bold: bool = False
    
    background: bool = True
    background_color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=0, b=0, a=0.7))
    padding: int = Field(default=8, ge=0, le=30)
    border_radius: int = Field(default=4, ge=0, le=20)


class HighlightAnnotation(AnnotationBase):
    """
    Cerchio/ellisse per evidenziare zone
    """
    type: Literal[AnnotationType.HIGHLIGHT] = AnnotationType.HIGHLIGHT
    
    anchor: AnchorPoint
    position: Optional[Point2D] = None
    
    shape: Literal["circle", "ellipse", "rectangle"] = "circle"
    radius: int = Field(default=30, ge=5, le=200)
    width: Optional[int] = None
    height: Optional[int] = None
    
    filled: bool = False
    fill_opacity: float = Field(default=0.3, ge=0.0, le=1.0)


class LineAnnotation(AnnotationBase):
    """
    Linea semplice tra due punti
    """
    type: Literal[AnnotationType.LINE] = AnnotationType.LINE
    
    start_anchor: AnchorPoint = AnchorPoint.CUSTOM
    start_point: Optional[Point2D] = None
    
    end_anchor: AnchorPoint = AnchorPoint.CUSTOM
    end_point: Optional[Point2D] = None
    
    dashed: bool = False
    dash_length: int = Field(default=10, ge=2, le=50)


class TrajectoryAnnotation(AnnotationBase):
    """
    Traccia movimento nel tempo (multi-frame)
    """
    type: Literal[AnnotationType.TRAJECTORY] = AnnotationType.TRAJECTORY
    
    anchor: AnchorPoint
    
    frame_start: int = Field(ge=0)
    frame_end: int = Field(ge=0)
    
    fade_trail: bool = True
    trail_length: int = Field(default=30, ge=1, le=300)
    show_dots: bool = True
    dot_interval: int = Field(default=5, ge=1, le=30)
    dot_radius: int = Field(default=4, ge=2, le=15)


class ComparisonAnnotation(AnnotationBase):
    """
    Confronto tra pose (reference vs current)
    """
    type: Literal[AnnotationType.COMPARISON] = AnnotationType.COMPARISON
    
    reference_skeleton_id: str
    reference_frame: int
    
    reference_color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=255, b=0, a=0.5))
    reference_style: Literal["solid", "dashed", "dotted"] = "dashed"
    
    show_difference_arrows: bool = True
    highlight_major_differences: bool = True
    difference_threshold: float = Field(default=0.1, ge=0.01, le=0.5)


# Union type per discriminated union
Annotation = Union[
    ArrowAnnotation,
    CurvedArrowAnnotation,
    AngleAnnotation,
    TextAnnotation,
    HighlightAnnotation,
    LineAnnotation,
    TrajectoryAnnotation,
    ComparisonAnnotation
]


# ═══════════════════════════════════════════════════════════════════════════════
# PROJECT MODEL
# ═══════════════════════════════════════════════════════════════════════════════

class OverlayProject(BaseModel):
    """
    Progetto overlay: container per set di annotazioni
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    
    video_id: Optional[str] = None
    skeleton_id: Optional[str] = None
    
    width: int = 1920
    height: int = 1080
    fps: float = 30.0
    
    annotations: List[Annotation] = []
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    # Default styles
    default_color: ColorRGBA = Field(default_factory=ColorRGBA)
    default_thickness: int = 3
    default_font_size: int = 24
    
    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


# ═══════════════════════════════════════════════════════════════════════════════
# API REQUEST/RESPONSE
# ═══════════════════════════════════════════════════════════════════════════════

class RenderFrameRequest(BaseModel):
    """Request per rendering singolo frame"""
    skeleton_id: str
    frame_index: int
    annotations: List[Dict[str, Any]]
    output_format: Literal["png", "jpg", "webp"] = "png"
    quality: int = Field(default=95, ge=1, le=100)
    include_skeleton: bool = True
    include_video_frame: bool = True
    width: Optional[int] = None
    height: Optional[int] = None


class RenderFrameResponse(BaseModel):
    """Response rendering frame"""
    image_url: str
    width: int
    height: int
    frame_index: int
    annotations_count: int
    render_time_ms: float


class RenderVideoRequest(BaseModel):
    """Request per rendering video completo"""
    skeleton_id: str
    project_id: Optional[str] = None
    frame_start: int = 0
    frame_end: Optional[int] = None
    annotations: List[Dict[str, Any]] = []
    output_format: Literal["mp4", "webm"] = "mp4"
    fps: float = 30.0
    include_audio: bool = True


class RenderVideoResponse(BaseModel):
    """Response rendering video"""
    job_id: str
    status: str
    video_url: Optional[str] = None
    progress: float = 0.0
    total_frames: int = 0


class AutoAnnotateRequest(BaseModel):
    """Request per auto-generazione annotazioni"""
    skeleton_id: str
    frame_index: int
    detect_angles: bool = True
    detect_key_points: bool = False
    min_visibility: float = Field(default=0.7, ge=0.1, le=1.0)


class AutoAnnotateResponse(BaseModel):
    """Response auto-annotazioni"""
    annotations: List[Dict[str, Any]]
    detected_angles: Dict[str, float]


# ═══════════════════════════════════════════════════════════════════════════════
# MAPPING MEDIAPIPE
# ═══════════════════════════════════════════════════════════════════════════════

MEDIAPIPE_TO_ANCHOR: Dict[int, AnchorPoint] = {
    0: AnchorPoint.NOSE,
    2: AnchorPoint.LEFT_EYE,
    5: AnchorPoint.RIGHT_EYE,
    7: AnchorPoint.LEFT_EAR,
    8: AnchorPoint.RIGHT_EAR,
    11: AnchorPoint.LEFT_SHOULDER,
    12: AnchorPoint.RIGHT_SHOULDER,
    13: AnchorPoint.LEFT_ELBOW,
    14: AnchorPoint.RIGHT_ELBOW,
    15: AnchorPoint.LEFT_WRIST,
    16: AnchorPoint.RIGHT_WRIST,
    23: AnchorPoint.LEFT_HIP,
    24: AnchorPoint.RIGHT_HIP,
    25: AnchorPoint.LEFT_KNEE,
    26: AnchorPoint.RIGHT_KNEE,
    27: AnchorPoint.LEFT_ANKLE,
    28: AnchorPoint.RIGHT_ANKLE,
}

ANCHOR_TO_MEDIAPIPE: Dict[AnchorPoint, int] = {v: k for k, v in MEDIAPIPE_TO_ANCHOR.items()}

# Angoli comuni per auto-detect
COMMON_JOINT_ANGLES = [
    ("left_elbow", AnchorPoint.LEFT_SHOULDER, AnchorPoint.LEFT_ELBOW, AnchorPoint.LEFT_WRIST),
    ("right_elbow", AnchorPoint.RIGHT_SHOULDER, AnchorPoint.RIGHT_ELBOW, AnchorPoint.RIGHT_WRIST),
    ("left_knee", AnchorPoint.LEFT_HIP, AnchorPoint.LEFT_KNEE, AnchorPoint.LEFT_ANKLE),
    ("right_knee", AnchorPoint.RIGHT_HIP, AnchorPoint.RIGHT_KNEE, AnchorPoint.RIGHT_ANKLE),
    ("left_shoulder", AnchorPoint.LEFT_ELBOW, AnchorPoint.LEFT_SHOULDER, AnchorPoint.LEFT_HIP),
    ("right_shoulder", AnchorPoint.RIGHT_ELBOW, AnchorPoint.RIGHT_SHOULDER, AnchorPoint.RIGHT_HIP),
    ("left_hip", AnchorPoint.LEFT_SHOULDER, AnchorPoint.LEFT_HIP, AnchorPoint.LEFT_KNEE),
    ("right_hip", AnchorPoint.RIGHT_SHOULDER, AnchorPoint.RIGHT_HIP, AnchorPoint.RIGHT_KNEE),
]

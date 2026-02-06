"""
🎓 AI_MODULE: Overlay Package
🎓 AI_DESCRIPTION: Package per annotazioni didattiche su video/frame
"""

from .schemas import (
    AnnotationType,
    AnchorPoint,
    ArrowStyle,
    TextPosition,
    ColorRGBA,
    Point2D,
    Annotation,
    ArrowAnnotation,
    CurvedArrowAnnotation,
    AngleAnnotation,
    TextAnnotation,
    HighlightAnnotation,
    LineAnnotation,
    TrajectoryAnnotation,
    ComparisonAnnotation,
    OverlayProject,
    RenderFrameRequest,
    RenderFrameResponse,
    RenderVideoRequest,
    RenderVideoResponse,
    AutoAnnotateRequest,
    AutoAnnotateResponse,
    MEDIAPIPE_TO_ANCHOR,
    ANCHOR_TO_MEDIAPIPE,
    COMMON_JOINT_ANGLES,
)

from .calculator import OverlayCalculator
from .renderer import OverlayRenderer
from .service import OverlayService, get_overlay_service

__all__ = [
    # Enums
    "AnnotationType",
    "AnchorPoint",
    "ArrowStyle",
    "TextPosition",
    
    # Models
    "ColorRGBA",
    "Point2D",
    "Annotation",
    "ArrowAnnotation",
    "CurvedArrowAnnotation",
    "AngleAnnotation",
    "TextAnnotation",
    "HighlightAnnotation",
    "LineAnnotation",
    "TrajectoryAnnotation",
    "ComparisonAnnotation",
    "OverlayProject",
    
    # API Schemas
    "RenderFrameRequest",
    "RenderFrameResponse",
    "RenderVideoRequest",
    "RenderVideoResponse",
    "AutoAnnotateRequest",
    "AutoAnnotateResponse",
    
    # Mappings
    "MEDIAPIPE_TO_ANCHOR",
    "ANCHOR_TO_MEDIAPIPE",
    "COMMON_JOINT_ANGLES",
    
    # Classes
    "OverlayCalculator",
    "OverlayRenderer",
    "OverlayService",
    "get_overlay_service",
]

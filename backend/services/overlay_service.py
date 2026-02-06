"""
🎓 AI_MODULE: Overlay Didattici Service
🎓 AI_DESCRIPTION: Genera immagini annotate con frecce, angoli, testo su frame video/skeleton
🎓 AI_BUSINESS: Killer feature per contenuti didattici — differenziatore vs concorrenza
🎓 AI_TEACHING: OpenCV per disegno vettoriale, PIL per testo, NumPy per calcoli angoli

🔄 ALTERNATIVE_VALUTATE:
- Canvas HTML5 lato client: Scartato, no export alta qualità, no batch processing
- FFmpeg drawtext: Scartato, sintassi complessa, no frecce curve
- Matplotlib: Scartato, lento per batch, output non ottimale per video

💡 PERCHÉ_QUESTA_SOLUZIONE:
- OpenCV: Veloce, GPU-accelerabile, primitives grafiche complete
- PIL/Pillow: Font TrueType, testo multilingua (CJK)
- NumPy: Calcoli trigonometrici per angoli articolazioni
- Combinazione permette export PNG/JPG alta qualità + overlay su video

📊 BUSINESS_IMPACT:
- Differenziatore mercato: Nessun competitor ha auto-generazione frecce didattiche
- Risparmio tempo maestri: 10min manuale → 5sec automatico
- Qualità consistente: Stile uniforme su tutti i contenuti

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: skeleton service (landmarks), video service (frames)
- Downstream: video_studio, export API, frontend editor
- Storage: output in /storage/overlays/

📁 STRUTTURA FILE:
backend/services/overlay_service.py      ← QUESTO FILE (service principale)
backend/services/overlay_renderer.py     ← Rendering engine (OpenCV + PIL)
backend/services/overlay_calculator.py   ← Calcoli angoli e posizioni
backend/api/v1/overlays.py               ← API endpoints
backend/schemas/overlay_schemas.py       ← Pydantic schemas
frontend/src/components/OverlayEditor.tsx ← React editor component
"""

from typing import List, Optional, Dict, Any, Tuple
from enum import Enum
from pydantic import BaseModel, Field
from datetime import datetime
import uuid

# ═══════════════════════════════════════════════════════════════════════════════
# ENUMS — Tipi di annotazioni supportate
# ═══════════════════════════════════════════════════════════════════════════════

class AnnotationType(str, Enum):
    """
    🎓 AI_TEACHING: Enum dei tipi di annotazione supportati
    Ogni tipo ha rendering diverso in overlay_renderer.py
    """
    ARROW = "arrow"              # Freccia direzionale (movimento)
    CURVED_ARROW = "curved_arrow"  # Freccia curva (rotazione)
    ANGLE = "angle"              # Arco con gradi (angolo articolazione)
    TEXT = "text"                # Testo libero
    HIGHLIGHT = "highlight"      # Cerchio/ellisse evidenziatore
    LINE = "line"                # Linea semplice
    TRAJECTORY = "trajectory"    # Percorso movimento (multi-frame)
    COMPARISON = "comparison"    # Sovrapposizione due pose (correct vs user)


class AnchorPoint(str, Enum):
    """
    🎓 AI_TEACHING: Punti di ancoraggio per annotazioni
    Mappano ai 33 landmark MediaPipe Pose (subset più usati)
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
    
    # Polsi
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
    
    # Centro massa (calcolato)
    CENTER_BODY = "center_body"
    CENTER_HIPS = "center_hips"
    CENTER_SHOULDERS = "center_shoulders"
    
    # Coordinate custom (x, y assolute)
    CUSTOM = "custom"


class ArrowStyle(str, Enum):
    """Stili freccia disponibili"""
    SOLID = "solid"
    DASHED = "dashed"
    DOUBLE = "double"
    HOLLOW = "hollow"


class TextPosition(str, Enum):
    """Posizione testo rispetto all'ancora"""
    ABOVE = "above"
    BELOW = "below"
    LEFT = "left"
    RIGHT = "right"
    CENTER = "center"


# ═══════════════════════════════════════════════════════════════════════════════
# SCHEMAS — Modelli dati per annotazioni
# ═══════════════════════════════════════════════════════════════════════════════

class ColorRGBA(BaseModel):
    """Colore con alpha channel"""
    r: int = Field(ge=0, le=255, default=255)
    g: int = Field(ge=0, le=255, default=0)
    b: int = Field(ge=0, le=255, default=0)
    a: float = Field(ge=0.0, le=1.0, default=1.0)
    
    def to_bgr(self) -> Tuple[int, int, int]:
        """OpenCV usa BGR"""
        return (self.b, self.g, self.r)
    
    def to_rgba_tuple(self) -> Tuple[int, int, int, int]:
        """PIL usa RGBA"""
        return (self.r, self.g, self.b, int(self.a * 255))


class Point2D(BaseModel):
    """Punto 2D normalizzato (0.0-1.0) o assoluto"""
    x: float
    y: float
    normalized: bool = True  # Se True, x/y sono 0.0-1.0, altrimenti pixel


class AnnotationBase(BaseModel):
    """
    🎓 AI_TEACHING: Base class per tutte le annotazioni
    Ogni tipo specifico estende questa con campi aggiuntivi
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: AnnotationType
    frame_index: int = Field(ge=0, description="Frame a cui applicare l'annotazione")
    frame_end: Optional[int] = Field(None, description="Per annotazioni multi-frame (trajectory)")
    color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=100, b=0))
    thickness: int = Field(default=3, ge=1, le=20)
    opacity: float = Field(default=1.0, ge=0.0, le=1.0)
    visible: bool = True
    label: Optional[str] = None  # Etichetta opzionale
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ArrowAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Freccia direzionale
    🎓 AI_BUSINESS: Indica direzione movimento (es. "spingi qui", "muovi verso")
    """
    type: AnnotationType = AnnotationType.ARROW
    
    # Punto di partenza
    start_anchor: AnchorPoint = AnchorPoint.CUSTOM
    start_point: Optional[Point2D] = None  # Se anchor è CUSTOM
    
    # Punto di arrivo
    end_anchor: AnchorPoint = AnchorPoint.CUSTOM
    end_point: Optional[Point2D] = None
    
    # Stile
    style: ArrowStyle = ArrowStyle.SOLID
    head_size: int = Field(default=15, ge=5, le=50)
    curved: bool = False
    curve_amount: float = Field(default=0.3, ge=0.0, le=1.0)  # Curvatura se curved=True


class AngleAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Indicatore angolo articolazione
    🎓 AI_BUSINESS: Mostra gradi corretti per tecnica (es. "gomito a 90°")
    🎓 AI_TEACHING: Calcolo angolo tra 3 punti con arctan2
    """
    type: AnnotationType = AnnotationType.ANGLE
    
    # Tre punti che definiscono l'angolo (vertex è il punto centrale)
    point_a: AnchorPoint  # Primo estremo
    vertex: AnchorPoint   # Vertice (dove si misura l'angolo)
    point_b: AnchorPoint  # Secondo estremo
    
    # Visualizzazione
    arc_radius: int = Field(default=40, ge=10, le=200)
    show_degrees: bool = True
    target_angle: Optional[float] = Field(None, ge=0, le=360, description="Angolo target da evidenziare")
    tolerance: float = Field(default=10.0, ge=0, le=45, description="Tolleranza gradi per feedback")
    
    # Colori feedback
    color_correct: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=255, b=0))
    color_warning: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=255, b=0))
    color_error: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=0, b=0))


class TextAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Testo didattico
    🎓 AI_BUSINESS: Istruzioni, nomi tecniche, correzioni
    """
    type: AnnotationType = AnnotationType.TEXT
    
    # Posizione
    anchor: AnchorPoint = AnchorPoint.CUSTOM
    position: Optional[Point2D] = None
    text_position: TextPosition = TextPosition.ABOVE
    offset_x: int = 0
    offset_y: int = -20
    
    # Contenuto
    text: str
    font_size: int = Field(default=24, ge=8, le=72)
    font_family: str = "Arial"
    bold: bool = False
    italic: bool = False
    
    # Background
    background: bool = True
    background_color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=0, b=0, a=0.7))
    padding: int = Field(default=8, ge=0, le=30)
    border_radius: int = Field(default=4, ge=0, le=20)


class HighlightAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Evidenziatore zona
    🎓 AI_BUSINESS: Attira attenzione su parte specifica del corpo
    """
    type: AnnotationType = AnnotationType.HIGHLIGHT
    
    # Centro
    anchor: AnchorPoint
    position: Optional[Point2D] = None
    
    # Forma
    shape: str = Field(default="circle", pattern="^(circle|ellipse|rectangle)$")
    radius: int = Field(default=30, ge=5, le=200)
    width: Optional[int] = None   # Per ellipse/rectangle
    height: Optional[int] = None  # Per ellipse/rectangle
    
    # Stile
    filled: bool = False
    pulse_animation: bool = False  # Per video, effetto pulsante


class TrajectoryAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Traccia movimento nel tempo
    🎓 AI_BUSINESS: Mostra percorso di un punto attraverso più frame
    🎓 AI_TEACHING: Utile per movimenti fluidi (es. traiettoria pugno)
    """
    type: AnnotationType = AnnotationType.TRAJECTORY
    
    # Punto da tracciare
    anchor: AnchorPoint
    
    # Range frame
    frame_start: int = Field(ge=0)
    frame_end: int = Field(ge=0)
    
    # Stile traccia
    fade_trail: bool = True  # Sfuma verso l'inizio
    trail_length: int = Field(default=30, ge=1, le=300)  # Quanti frame mostrare
    show_dots: bool = True  # Punti lungo la traccia
    dot_interval: int = Field(default=5, ge=1, le=30)


class ComparisonAnnotation(AnnotationBase):
    """
    🎓 AI_MODULE: Confronto due pose
    🎓 AI_BUSINESS: Mostra differenza tra tecnica corretta e esecuzione utente
    """
    type: AnnotationType = AnnotationType.COMPARISON
    
    # Skeleton di riferimento (corretto)
    reference_skeleton_id: str
    reference_frame: int
    
    # Visualizzazione
    reference_color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=0, g=255, b=0, a=0.5))
    reference_style: str = "dashed"
    show_difference_arrows: bool = True  # Frecce che indicano correzione
    highlight_major_differences: bool = True
    difference_threshold: float = Field(default=0.1, ge=0.01, le=0.5)


# ═══════════════════════════════════════════════════════════════════════════════
# OVERLAY PROJECT — Container per set di annotazioni
# ═══════════════════════════════════════════════════════════════════════════════

class OverlayProject(BaseModel):
    """
    🎓 AI_MODULE: Progetto overlay completo
    🎓 AI_BUSINESS: Salva/carica set di annotazioni per un video
    """
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: Optional[str] = None
    
    # Video/Skeleton di riferimento
    video_id: Optional[str] = None
    skeleton_id: Optional[str] = None
    
    # Dimensioni output
    width: int = 1920
    height: int = 1080
    
    # Annotazioni
    annotations: List[AnnotationBase] = []
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    
    # Preset stile
    default_color: ColorRGBA = Field(default_factory=lambda: ColorRGBA(r=255, g=100, b=0))
    default_thickness: int = 3
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


# ═══════════════════════════════════════════════════════════════════════════════
# REQUEST/RESPONSE SCHEMAS — Per API endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class RenderOverlayRequest(BaseModel):
    """Request per rendering singolo frame con overlay"""
    skeleton_id: str
    frame_index: int
    annotations: List[Dict[str, Any]]  # Annotazioni da applicare
    output_format: str = Field(default="png", pattern="^(png|jpg|webp)$")
    quality: int = Field(default=95, ge=1, le=100)
    include_skeleton: bool = True  # Disegna anche lo skeleton
    include_video_frame: bool = True  # Usa frame video come background


class RenderOverlayResponse(BaseModel):
    """Response con immagine renderizzata"""
    image_url: str
    width: int
    height: int
    frame_index: int
    annotations_count: int
    render_time_ms: float


class BatchRenderRequest(BaseModel):
    """Request per rendering batch (più frame)"""
    skeleton_id: str
    project_id: Optional[str] = None
    frame_start: int = 0
    frame_end: Optional[int] = None  # None = tutti i frame
    frame_step: int = 1  # Ogni N frame
    annotations: List[Dict[str, Any]] = []
    output_format: str = "png"
    output_prefix: str = "frame_"


class BatchRenderResponse(BaseModel):
    """Response batch rendering"""
    job_id: str
    total_frames: int
    output_directory: str
    status: str = "queued"


class AutoAnnotateRequest(BaseModel):
    """
    🎓 AI_MODULE: Auto-generazione annotazioni
    🎓 AI_BUSINESS: AI suggerisce annotazioni basate su skeleton
    """
    skeleton_id: str
    frame_index: int
    annotation_types: List[AnnotationType] = [AnnotationType.ANGLE]
    
    # Opzioni auto-detect
    detect_angles: bool = True          # Trova angoli articolazioni significativi
    detect_movement: bool = False       # Richiede range frame
    highlight_key_points: bool = False  # Evidenzia punti chiave
    
    # Soglie
    min_angle_change: float = Field(default=15.0, ge=5, le=90)
    min_visibility: float = Field(default=0.7, ge=0.1, le=1.0)


class AutoAnnotateResponse(BaseModel):
    """Response con annotazioni suggerite"""
    suggested_annotations: List[Dict[str, Any]]
    confidence_scores: Dict[str, float]


# ═══════════════════════════════════════════════════════════════════════════════
# LANDMARK MAPPING — MediaPipe index to AnchorPoint
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

# Angoli articolazioni comuni per auto-detect
COMMON_ANGLES: List[Tuple[AnchorPoint, AnchorPoint, AnchorPoint, str]] = [
    (AnchorPoint.LEFT_SHOULDER, AnchorPoint.LEFT_ELBOW, AnchorPoint.LEFT_WRIST, "Left Elbow"),
    (AnchorPoint.RIGHT_SHOULDER, AnchorPoint.RIGHT_ELBOW, AnchorPoint.RIGHT_WRIST, "Right Elbow"),
    (AnchorPoint.LEFT_HIP, AnchorPoint.LEFT_KNEE, AnchorPoint.LEFT_ANKLE, "Left Knee"),
    (AnchorPoint.RIGHT_HIP, AnchorPoint.RIGHT_KNEE, AnchorPoint.RIGHT_ANKLE, "Right Knee"),
    (AnchorPoint.LEFT_ELBOW, AnchorPoint.LEFT_SHOULDER, AnchorPoint.LEFT_HIP, "Left Shoulder"),
    (AnchorPoint.RIGHT_ELBOW, AnchorPoint.RIGHT_SHOULDER, AnchorPoint.RIGHT_HIP, "Right Shoulder"),
    (AnchorPoint.LEFT_KNEE, AnchorPoint.LEFT_HIP, AnchorPoint.RIGHT_HIP, "Left Hip"),
    (AnchorPoint.RIGHT_KNEE, AnchorPoint.RIGHT_HIP, AnchorPoint.LEFT_HIP, "Right Hip"),
]

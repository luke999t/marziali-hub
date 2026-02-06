"""
🎓 AI_MODULE: Overlay Renderer
🎓 AI_DESCRIPTION: Engine di rendering per annotazioni su frame video
🎓 AI_BUSINESS: Produce immagini annotate di alta qualità per contenuti didattici
🎓 AI_TEACHING: OpenCV per grafica, PIL per testo con font TrueType

📁 POSIZIONE: backend/services/overlay/renderer.py

🔄 ALTERNATIVE_VALUTATE:
- Solo OpenCV: Scartato, testo con font limitati
- Solo PIL: Scartato, primitives grafiche lente
- Cairo/Pycairo: Scartato, dipendenza complessa
- Combinazione OpenCV+PIL: Scelto, best of both worlds

💡 PERCHÉ_QUESTA_SOLUZIONE:
- OpenCV: Linee, cerchi, archi, trasparenza veloce
- PIL: Testo TrueType, supporto Unicode/CJK perfetto
- NumPy: Blending e manipolazione array efficienti
"""

import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import math

from .schemas import (
    AnnotationType, AnchorPoint, ArrowStyle,
    ColorRGBA, Point2D, Annotation,
    ArrowAnnotation, CurvedArrowAnnotation, AngleAnnotation,
    TextAnnotation, HighlightAnnotation, LineAnnotation,
    TrajectoryAnnotation, ComparisonAnnotation
)
from .calculator import OverlayCalculator


class OverlayRenderer:
    """
    🎓 AI_MODULE: Renderer per annotazioni didattiche
    
    Responsabilità:
    - Disegno frecce (dritte e curve)
    - Disegno angoli con arco e gradi
    - Disegno testo con background
    - Highlight zones
    - Traiettorie multi-frame
    - Compositing con alpha channel
    """
    
    def __init__(
        self,
        width: int = 1920,
        height: int = 1080,
        default_font: str = "Arial"
    ):
        """
        Args:
            width: Larghezza frame
            height: Altezza frame
            default_font: Font di default per testo
        """
        self.width = width
        self.height = height
        self.default_font = default_font
        self.calculator = OverlayCalculator(width, height)
        
        # Cache font PIL
        self._font_cache: Dict[Tuple[str, int], ImageFont.FreeTypeFont] = {}
        
        # Path font di sistema
        self._font_paths = self._detect_font_paths()
    
    def _detect_font_paths(self) -> Dict[str, str]:
        """
        Rileva path font di sistema.
        
        🎓 AI_TEACHING: Windows/Linux/Mac hanno path diversi.
        """
        font_paths = {}
        
        # Windows
        win_fonts = Path("C:/Windows/Fonts")
        if win_fonts.exists():
            font_map = {
                "Arial": "arial.ttf",
                "Arial Bold": "arialbd.ttf",
                "Times New Roman": "times.ttf",
                "Verdana": "verdana.ttf",
                "Tahoma": "tahoma.ttf",
                "Segoe UI": "segoeui.ttf",
                "Microsoft YaHei": "msyh.ttc",  # Cinese
            }
            for name, filename in font_map.items():
                path = win_fonts / filename
                if path.exists():
                    font_paths[name] = str(path)
        
        # Linux
        linux_fonts = [
            Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
            Path("/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf"),
        ]
        for path in linux_fonts:
            if path.exists():
                font_paths["DejaVu Sans"] = str(path)
                break
        
        return font_paths
    
    def _get_font(self, family: str, size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
        """
        Ottiene font PIL con caching.
        """
        cache_key = (family, size, bold)
        
        if cache_key in self._font_cache:
            return self._font_cache[cache_key]
        
        # Cerca font
        font_key = f"{family} Bold" if bold else family
        font_path = self._font_paths.get(font_key, self._font_paths.get(family))
        
        try:
            if font_path:
                font = ImageFont.truetype(font_path, size)
            else:
                # Fallback
                font = ImageFont.load_default()
        except Exception:
            font = ImageFont.load_default()
        
        self._font_cache[cache_key] = font
        return font
    
    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN RENDER METHOD
    # ═══════════════════════════════════════════════════════════════════════════
    
    def render_annotations(
        self,
        background: np.ndarray,
        annotations: List[Annotation],
        landmarks: Optional[List[Dict[str, Any]]] = None
    ) -> np.ndarray:
        """
        Renderizza tutte le annotazioni su un frame.
        
        🎓 AI_TEACHING: Processo:
        1. Crea layer trasparente per overlay
        2. Disegna ogni annotazione sul layer
        3. Blenda layer con background
        
        Args:
            background: Frame BGR (HxWx3) o BGRA (HxWx4)
            annotations: Lista annotazioni da disegnare
            landmarks: Landmarks MediaPipe per anchor points
            
        Returns:
            Frame BGR con annotazioni
        """
        # Assicura che background sia nel formato giusto
        if background.shape[2] == 3:
            background = cv2.cvtColor(background, cv2.COLOR_BGR2BGRA)
        
        # Aggiorna dimensioni se diverse
        h, w = background.shape[:2]
        if w != self.width or h != self.height:
            self.width = w
            self.height = h
            self.calculator = OverlayCalculator(w, h)
        
        # Crea layer overlay trasparente
        overlay = np.zeros((h, w, 4), dtype=np.uint8)
        
        # Ordina per z_index
        sorted_annotations = sorted(annotations, key=lambda a: a.z_index)
        
        # Disegna ogni annotazione
        for ann in sorted_annotations:
            if not ann.visible:
                continue
            
            try:
                self._render_annotation(overlay, ann, landmarks)
            except Exception as e:
                print(f"[OverlayRenderer] Error rendering {ann.type}: {e}")
                continue
        
        # Blenda overlay con background
        result = self._alpha_blend(background, overlay)
        
        # Converti a BGR
        return cv2.cvtColor(result, cv2.COLOR_BGRA2BGR)
    
    def _render_annotation(
        self,
        overlay: np.ndarray,
        annotation: Annotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """Dispatch a metodo specifico per tipo annotazione"""
        
        if annotation.type == AnnotationType.ARROW:
            self._render_arrow(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.CURVED_ARROW:
            self._render_curved_arrow(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.ANGLE:
            self._render_angle(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.TEXT:
            self._render_text(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.HIGHLIGHT:
            self._render_highlight(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.LINE:
            self._render_line(overlay, annotation, landmarks)
        elif annotation.type == AnnotationType.TRAJECTORY:
            # Richiede landmarks multi-frame, gestito separatamente
            pass
        elif annotation.type == AnnotationType.COMPARISON:
            # Richiede skeleton reference, gestito separatamente
            pass
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ARROW RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _render_arrow(
        self,
        overlay: np.ndarray,
        ann: ArrowAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna freccia direzionale.
        """
        # Ottieni posizioni
        start = self.calculator.get_landmark_position(
            landmarks or [], ann.start_anchor, ann.start_point
        )
        end = self.calculator.get_landmark_position(
            landmarks or [], ann.end_anchor, ann.end_point
        )
        
        if not start or not end:
            return
        
        color = ann.color.to_bgra()
        color = (*color[:3], int(color[3] * ann.opacity))
        
        # Linea principale
        if ann.style == ArrowStyle.DASHED:
            self._draw_dashed_line(overlay, start, end, color, ann.thickness)
        else:
            cv2.line(overlay, start, end, color, ann.thickness, cv2.LINE_AA)
        
        # Punta freccia
        head_left, head_right = self.calculator.calculate_arrow_head(
            start, end, ann.head_size
        )
        
        # Disegna punta piena
        pts = np.array([end, head_left, head_right], np.int32)
        cv2.fillPoly(overlay, [pts], color, cv2.LINE_AA)
    
    def _render_curved_arrow(
        self,
        overlay: np.ndarray,
        ann: CurvedArrowAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna freccia curva (per indicare rotazione).
        """
        center = self.calculator.get_landmark_position(
            landmarks or [], ann.center_anchor, ann.center_point
        )
        
        if not center:
            return
        
        color = ann.color.to_bgra()
        color = (*color[:3], int(color[3] * ann.opacity))
        
        # Genera punti arco
        points = self.calculator.calculate_curved_arrow_points(
            center, ann.radius, ann.start_angle, ann.end_angle, ann.clockwise
        )
        
        if len(points) < 2:
            return
        
        # Disegna arco
        pts = np.array(points, np.int32)
        cv2.polylines(overlay, [pts], False, color, ann.thickness, cv2.LINE_AA)
        
        # Punta freccia all'estremità
        if len(points) >= 2:
            end_point = points[-1]
            prev_point = points[-2]
            
            head_left, head_right = self.calculator.calculate_arrow_head(
                prev_point, end_point, ann.head_size
            )
            
            pts = np.array([end_point, head_left, head_right], np.int32)
            cv2.fillPoly(overlay, [pts], color, cv2.LINE_AA)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ANGLE RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _render_angle(
        self,
        overlay: np.ndarray,
        ann: AngleAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna indicatore angolo con arco e gradi.
        
        🎓 AI_BUSINESS: Feature chiave per feedback postura.
        """
        if not landmarks:
            return
        
        # Ottieni posizioni
        pos_a = self.calculator.get_landmark_position(landmarks, ann.point_a)
        pos_v = self.calculator.get_landmark_position(landmarks, ann.vertex)
        pos_b = self.calculator.get_landmark_position(landmarks, ann.point_b)
        
        if not all([pos_a, pos_v, pos_b]):
            return
        
        # Calcola angolo
        angle = self.calculator.calculate_angle(pos_a, pos_v, pos_b)
        
        # Determina colore (feedback se target specificato)
        if ann.target_angle is not None:
            color = self.calculator.get_angle_feedback_color(
                angle, ann.target_angle, ann.tolerance,
                ann.color_correct, ann.color_warning, ann.color_error
            )
        else:
            color = ann.color
        
        color_bgra = color.to_bgra()
        color_bgra = (*color_bgra[:3], int(color_bgra[3] * ann.opacity))
        
        # Disegna linee ai punti A e B
        cv2.line(overlay, pos_v, pos_a, color_bgra, max(1, ann.thickness - 1), cv2.LINE_AA)
        cv2.line(overlay, pos_v, pos_b, color_bgra, max(1, ann.thickness - 1), cv2.LINE_AA)
        
        # Disegna arco
        arc_points = self.calculator.calculate_arc_points(
            pos_v, pos_a, pos_b, ann.arc_radius
        )
        
        if len(arc_points) >= 2:
            pts = np.array(arc_points, np.int32)
            cv2.polylines(overlay, [pts], False, color_bgra, ann.thickness, cv2.LINE_AA)
        
        # Testo con gradi
        if ann.show_degrees:
            text_pos = self.calculator.calculate_arc_text_position(
                pos_v, pos_a, pos_b, ann.arc_radius
            )
            
            text = f"{angle:.0f}°"
            self._draw_text_with_background(
                overlay, text, text_pos, ann.font_size, color, True
            )
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TEXT RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _render_text(
        self,
        overlay: np.ndarray,
        ann: TextAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna testo con background opzionale.
        """
        # Ottieni posizione
        pos = self.calculator.get_landmark_position(
            landmarks or [], ann.anchor, ann.position
        )
        
        if not pos:
            return
        
        # Applica offset
        pos = (pos[0] + ann.offset_x, pos[1] + ann.offset_y)
        
        self._draw_text_with_background(
            overlay, ann.text, pos, ann.font_size, ann.color,
            ann.background, ann.background_color, ann.padding
        )
    
    def _draw_text_with_background(
        self,
        overlay: np.ndarray,
        text: str,
        position: Tuple[int, int],
        font_size: int,
        text_color: ColorRGBA,
        background: bool = True,
        bg_color: Optional[ColorRGBA] = None,
        padding: int = 8
    ):
        """
        Disegna testo con PIL (per font TrueType) e composita su overlay.
        
        🎓 AI_TEACHING: PIL per testo, poi convertiamo a numpy per blending.
        """
        # Crea immagine PIL temporanea
        pil_img = Image.fromarray(overlay)
        draw = ImageDraw.Draw(pil_img, 'RGBA')
        
        # Font
        font = self._get_font(self.default_font, font_size)
        
        # Calcola dimensioni testo
        bbox = draw.textbbox((0, 0), text, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        
        # Posizione centrata
        x = position[0] - text_width // 2
        y = position[1] - text_height // 2
        
        # Background
        if background:
            bg = bg_color or ColorRGBA(r=0, g=0, b=0, a=0.7)
            rect = [
                x - padding, y - padding,
                x + text_width + padding, y + text_height + padding
            ]
            draw.rounded_rectangle(rect, radius=4, fill=bg.to_rgba())
        
        # Testo
        draw.text((x, y), text, font=font, fill=text_color.to_rgba())
        
        # Riconverti a numpy
        result = np.array(pil_img)
        np.copyto(overlay, result)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # HIGHLIGHT RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _render_highlight(
        self,
        overlay: np.ndarray,
        ann: HighlightAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna cerchio/ellisse evidenziatore.
        """
        center = self.calculator.get_landmark_position(
            landmarks or [], ann.anchor, ann.position
        )
        
        if not center:
            return
        
        color = ann.color.to_bgra()
        color = (*color[:3], int(color[3] * ann.opacity))
        
        if ann.shape == "circle":
            if ann.filled:
                fill_color = (*color[:3], int(ann.fill_opacity * 255))
                cv2.circle(overlay, center, ann.radius, fill_color, -1, cv2.LINE_AA)
            cv2.circle(overlay, center, ann.radius, color, ann.thickness, cv2.LINE_AA)
            
        elif ann.shape == "ellipse":
            w = ann.width or ann.radius * 2
            h = ann.height or ann.radius
            axes = (w // 2, h // 2)
            
            if ann.filled:
                fill_color = (*color[:3], int(ann.fill_opacity * 255))
                cv2.ellipse(overlay, center, axes, 0, 0, 360, fill_color, -1, cv2.LINE_AA)
            cv2.ellipse(overlay, center, axes, 0, 0, 360, color, ann.thickness, cv2.LINE_AA)
            
        elif ann.shape == "rectangle":
            w = ann.width or ann.radius * 2
            h = ann.height or ann.radius * 2
            pt1 = (center[0] - w // 2, center[1] - h // 2)
            pt2 = (center[0] + w // 2, center[1] + h // 2)
            
            if ann.filled:
                fill_color = (*color[:3], int(ann.fill_opacity * 255))
                cv2.rectangle(overlay, pt1, pt2, fill_color, -1, cv2.LINE_AA)
            cv2.rectangle(overlay, pt1, pt2, color, ann.thickness, cv2.LINE_AA)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # LINE RENDERING
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _render_line(
        self,
        overlay: np.ndarray,
        ann: LineAnnotation,
        landmarks: Optional[List[Dict[str, Any]]]
    ):
        """
        Disegna linea semplice.
        """
        start = self.calculator.get_landmark_position(
            landmarks or [], ann.start_anchor, ann.start_point
        )
        end = self.calculator.get_landmark_position(
            landmarks or [], ann.end_anchor, ann.end_point
        )
        
        if not start or not end:
            return
        
        color = ann.color.to_bgra()
        color = (*color[:3], int(color[3] * ann.opacity))
        
        if ann.dashed:
            self._draw_dashed_line(overlay, start, end, color, ann.thickness, ann.dash_length)
        else:
            cv2.line(overlay, start, end, color, ann.thickness, cv2.LINE_AA)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════════════════════
    
    def _draw_dashed_line(
        self,
        img: np.ndarray,
        pt1: Tuple[int, int],
        pt2: Tuple[int, int],
        color: Tuple[int, int, int, int],
        thickness: int = 2,
        dash_length: int = 10
    ):
        """
        Disegna linea tratteggiata.
        """
        dist = math.hypot(pt2[0] - pt1[0], pt2[1] - pt1[1])
        
        if dist < 1:
            return
        
        num_dashes = int(dist / dash_length)
        
        for i in range(0, num_dashes, 2):
            start_ratio = i * dash_length / dist
            end_ratio = min((i + 1) * dash_length / dist, 1.0)
            
            start = (
                int(pt1[0] + (pt2[0] - pt1[0]) * start_ratio),
                int(pt1[1] + (pt2[1] - pt1[1]) * start_ratio)
            )
            end = (
                int(pt1[0] + (pt2[0] - pt1[0]) * end_ratio),
                int(pt1[1] + (pt2[1] - pt1[1]) * end_ratio)
            )
            
            cv2.line(img, start, end, color, thickness, cv2.LINE_AA)
    
    def _alpha_blend(
        self,
        background: np.ndarray,
        overlay: np.ndarray
    ) -> np.ndarray:
        """
        Alpha blending di overlay su background.
        
        🎓 AI_TEACHING: Formula: result = overlay * alpha + background * (1 - alpha)
        """
        # Estrai alpha channel
        alpha = overlay[:, :, 3:4].astype(np.float32) / 255.0
        
        # Blending
        blended = (
            overlay[:, :, :3].astype(np.float32) * alpha +
            background[:, :, :3].astype(np.float32) * (1 - alpha)
        ).astype(np.uint8)
        
        # Ricomponi con alpha
        result = np.dstack([blended, np.maximum(background[:, :, 3], overlay[:, :, 3])])
        
        return result
    
    # ═══════════════════════════════════════════════════════════════════════════
    # SKELETON RENDERING (bonus)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def render_skeleton(
        self,
        overlay: np.ndarray,
        landmarks: List[Dict[str, Any]],
        color: ColorRGBA = None,
        thickness: int = 2,
        draw_points: bool = True,
        point_radius: int = 4
    ):
        """
        Disegna skeleton MediaPipe.
        
        🎓 AI_TEACHING: Connessioni standard pose MediaPipe.
        """
        if color is None:
            color = ColorRGBA(r=0, g=255, b=255, a=0.8)
        
        color_bgra = color.to_bgra()
        
        # Connessioni MediaPipe Pose
        connections = [
            (11, 12), (11, 13), (13, 15), (12, 14), (14, 16),  # Braccia
            (11, 23), (12, 24), (23, 24),  # Torso
            (23, 25), (25, 27), (24, 26), (26, 28),  # Gambe
        ]
        
        # Disegna connessioni
        for idx1, idx2 in connections:
            if idx1 < len(landmarks) and idx2 < len(landmarks):
                lm1 = landmarks[idx1]
                lm2 = landmarks[idx2]
                
                v1 = lm1.get('visibility', 1)
                v2 = lm2.get('visibility', 1)
                
                if v1 > 0.5 and v2 > 0.5:
                    pt1 = self.calculator.normalized_to_pixel(lm1['x'], lm1['y'])
                    pt2 = self.calculator.normalized_to_pixel(lm2['x'], lm2['y'])
                    cv2.line(overlay, pt1, pt2, color_bgra, thickness, cv2.LINE_AA)
        
        # Disegna punti
        if draw_points:
            point_color = (*color_bgra[:3], 255)
            for lm in landmarks:
                if lm.get('visibility', 1) > 0.5:
                    pt = self.calculator.normalized_to_pixel(lm['x'], lm['y'])
                    cv2.circle(overlay, pt, point_radius, point_color, -1, cv2.LINE_AA)

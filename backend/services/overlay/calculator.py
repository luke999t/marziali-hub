"""
🎓 AI_MODULE: Overlay Calculator
🎓 AI_DESCRIPTION: Calcoli matematici per angoli, posizioni, trasformazioni
🎓 AI_BUSINESS: Precisione matematica per feedback didattico accurato
🎓 AI_TEACHING: Trigonometria con NumPy, coordinate normalizate vs pixel

📁 POSIZIONE: backend/services/overlay/calculator.py

🔄 ALTERNATIVE_VALUTATE:
- Pure Python math: Scartato, lento su batch
- SymPy: Scartato, overhead per calcoli semplici
- NumPy: Scelto, vettorizzato, standard, veloce
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from .schemas import (
    AnchorPoint, Point2D, ColorRGBA,
    ANCHOR_TO_MEDIAPIPE, COMMON_JOINT_ANGLES
)


class OverlayCalculator:
    """
    🎓 AI_MODULE: Calculator per overlay didattici
    
    Responsabilità:
    - Calcolo angoli tra 3 punti (articolazioni)
    - Conversione coordinate normalizzate <-> pixel
    - Calcolo punti medi e centri
    - Interpolazione per traiettorie
    - Calcolo differenze tra pose
    """
    
    def __init__(self, width: int = 1920, height: int = 1080):
        """
        Args:
            width: Larghezza frame in pixel
            height: Altezza frame in pixel
        """
        self.width = width
        self.height = height
    
    # ═══════════════════════════════════════════════════════════════════════════
    # COORDINATE CONVERSION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def normalized_to_pixel(self, x: float, y: float) -> Tuple[int, int]:
        """
        Converte coordinate normalizzate (0-1) a pixel.
        
        🎓 AI_TEACHING: MediaPipe restituisce coordinate 0-1,
        dobbiamo convertirle per disegnare su immagine.
        """
        px = int(x * self.width)
        py = int(y * self.height)
        return (px, py)
    
    def pixel_to_normalized(self, px: int, py: int) -> Tuple[float, float]:
        """Converte pixel a normalizzate"""
        return (px / self.width, py / self.height)
    
    def point_to_pixel(self, point: Point2D) -> Tuple[int, int]:
        """Converte Point2D a coordinate pixel"""
        if point.normalized:
            return self.normalized_to_pixel(point.x, point.y)
        return (int(point.x), int(point.y))
    
    # ═══════════════════════════════════════════════════════════════════════════
    # LANDMARK EXTRACTION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_landmark_position(
        self,
        landmarks: List[Dict[str, Any]],
        anchor: AnchorPoint,
        custom_point: Optional[Point2D] = None
    ) -> Optional[Tuple[int, int]]:
        """
        Estrae posizione pixel da anchor point.
        
        🎓 AI_TEACHING: I landmarks MediaPipe sono lista di dict con x,y,z,visibility.
        Alcuni anchor sono calcolati (CENTER_*), altri mappano direttamente.
        
        Args:
            landmarks: Lista landmarks dal skeleton
            anchor: Tipo di punto richiesto
            custom_point: Punto custom se anchor == CUSTOM
            
        Returns:
            (x, y) in pixel o None se non trovato
        """
        if anchor == AnchorPoint.CUSTOM:
            if custom_point:
                return self.point_to_pixel(custom_point)
            return None
        
        # Punti calcolati
        if anchor == AnchorPoint.CENTER_BODY:
            return self._calculate_center_body(landmarks)
        elif anchor == AnchorPoint.CENTER_HIPS:
            return self._calculate_center(landmarks, 23, 24)  # left_hip, right_hip
        elif anchor == AnchorPoint.CENTER_SHOULDERS:
            return self._calculate_center(landmarks, 11, 12)  # left_shoulder, right_shoulder
        
        # Mapping diretto MediaPipe
        mp_index = ANCHOR_TO_MEDIAPIPE.get(anchor)
        if mp_index is None:
            return None
        
        if mp_index >= len(landmarks):
            return None
        
        lm = landmarks[mp_index]
        
        # Check visibility (soglia 0.5)
        visibility = lm.get('visibility', lm.get('v', 1.0))
        if visibility < 0.5:
            return None
        
        x = lm.get('x', lm.get('X', 0))
        y = lm.get('y', lm.get('Y', 0))
        
        return self.normalized_to_pixel(x, y)
    
    def _calculate_center(
        self,
        landmarks: List[Dict[str, Any]],
        idx1: int,
        idx2: int
    ) -> Optional[Tuple[int, int]]:
        """Calcola punto medio tra due landmark"""
        if idx1 >= len(landmarks) or idx2 >= len(landmarks):
            return None
        
        lm1 = landmarks[idx1]
        lm2 = landmarks[idx2]
        
        x = (lm1.get('x', 0) + lm2.get('x', 0)) / 2
        y = (lm1.get('y', 0) + lm2.get('y', 0)) / 2
        
        return self.normalized_to_pixel(x, y)
    
    def _calculate_center_body(self, landmarks: List[Dict[str, Any]]) -> Optional[Tuple[int, int]]:
        """
        Calcola centro corpo (media di spalle e fianchi).
        
        🎓 AI_TEACHING: Usato come punto di riferimento stabile
        per annotazioni "fluttuanti" sul corpo.
        """
        indices = [11, 12, 23, 24]  # spalle e fianchi
        
        x_sum = 0.0
        y_sum = 0.0
        count = 0
        
        for idx in indices:
            if idx < len(landmarks):
                lm = landmarks[idx]
                x_sum += lm.get('x', 0)
                y_sum += lm.get('y', 0)
                count += 1
        
        if count == 0:
            return None
        
        return self.normalized_to_pixel(x_sum / count, y_sum / count)
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ANGLE CALCULATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def calculate_angle(
        self,
        point_a: Tuple[int, int],
        vertex: Tuple[int, int],
        point_b: Tuple[int, int]
    ) -> float:
        """
        Calcola angolo tra tre punti (in gradi).
        
        🎓 AI_TEACHING: 
        L'angolo è al VERTEX, formato dai vettori vertex→A e vertex→B.
        Usiamo arctan2 per gestire tutti i quadranti correttamente.
        
        Formula:
        1. Vettore VA = A - V
        2. Vettore VB = B - V
        3. angle = arccos(VA · VB / (|VA| * |VB|))
        
        Args:
            point_a: Primo estremo
            vertex: Punto centrale (dove misuro l'angolo)
            point_b: Secondo estremo
            
        Returns:
            Angolo in gradi (0-180)
        """
        # Converti a numpy arrays
        a = np.array(point_a, dtype=np.float64)
        v = np.array(vertex, dtype=np.float64)
        b = np.array(point_b, dtype=np.float64)
        
        # Vettori dal vertex
        va = a - v
        vb = b - v
        
        # Lunghezze
        len_va = np.linalg.norm(va)
        len_vb = np.linalg.norm(vb)
        
        # Evita divisione per zero
        if len_va < 1e-6 or len_vb < 1e-6:
            return 0.0
        
        # Dot product normalizzato
        cos_angle = np.dot(va, vb) / (len_va * len_vb)
        
        # Clamp per errori numerici
        cos_angle = np.clip(cos_angle, -1.0, 1.0)
        
        # Angolo in gradi
        angle_rad = np.arccos(cos_angle)
        angle_deg = np.degrees(angle_rad)
        
        return float(angle_deg)
    
    def calculate_angle_from_landmarks(
        self,
        landmarks: List[Dict[str, Any]],
        anchor_a: AnchorPoint,
        anchor_vertex: AnchorPoint,
        anchor_b: AnchorPoint
    ) -> Optional[float]:
        """
        Calcola angolo articolazione da anchor points.
        
        Returns:
            Angolo in gradi o None se punti non visibili
        """
        pos_a = self.get_landmark_position(landmarks, anchor_a)
        pos_v = self.get_landmark_position(landmarks, anchor_vertex)
        pos_b = self.get_landmark_position(landmarks, anchor_b)
        
        if not all([pos_a, pos_v, pos_b]):
            return None
        
        return self.calculate_angle(pos_a, pos_v, pos_b)
    
    def calculate_all_joint_angles(
        self,
        landmarks: List[Dict[str, Any]]
    ) -> Dict[str, float]:
        """
        Calcola tutti gli angoli articolazioni comuni.
        
        🎓 AI_BUSINESS: Utile per auto-annotate e feedback postura.
        
        Returns:
            Dict con nome_articolazione: angolo_gradi
        """
        angles = {}
        
        for name, a, v, b in COMMON_JOINT_ANGLES:
            angle = self.calculate_angle_from_landmarks(landmarks, a, v, b)
            if angle is not None:
                angles[name] = round(angle, 1)
        
        return angles
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ARC CALCULATION (per disegno angoli)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def calculate_arc_points(
        self,
        vertex: Tuple[int, int],
        point_a: Tuple[int, int],
        point_b: Tuple[int, int],
        radius: int = 40,
        num_points: int = 30
    ) -> List[Tuple[int, int]]:
        """
        Genera punti per disegnare arco dell'angolo.
        
        🎓 AI_TEACHING: Per disegnare l'arco indicatore angolo,
        generiamo punti lungo la circonferenza tra le due direzioni.
        """
        v = np.array(vertex, dtype=np.float64)
        a = np.array(point_a, dtype=np.float64)
        b = np.array(point_b, dtype=np.float64)
        
        # Angoli dei vettori rispetto all'asse X
        va = a - v
        vb = b - v
        
        angle_a = np.arctan2(va[1], va[0])
        angle_b = np.arctan2(vb[1], vb[0])
        
        # Assicura che l'arco sia sempre il più corto
        diff = angle_b - angle_a
        if diff > np.pi:
            angle_b -= 2 * np.pi
        elif diff < -np.pi:
            angle_b += 2 * np.pi
        
        # Genera punti lungo l'arco
        angles = np.linspace(angle_a, angle_b, num_points)
        
        points = []
        for ang in angles:
            x = int(v[0] + radius * np.cos(ang))
            y = int(v[1] + radius * np.sin(ang))
            points.append((x, y))
        
        return points
    
    def calculate_arc_text_position(
        self,
        vertex: Tuple[int, int],
        point_a: Tuple[int, int],
        point_b: Tuple[int, int],
        radius: int = 40
    ) -> Tuple[int, int]:
        """
        Calcola posizione testo angolo (al centro dell'arco).
        """
        v = np.array(vertex, dtype=np.float64)
        a = np.array(point_a, dtype=np.float64)
        b = np.array(point_b, dtype=np.float64)
        
        # Direzioni normalizzate
        va = a - v
        vb = b - v
        
        va_norm = va / (np.linalg.norm(va) + 1e-6)
        vb_norm = vb / (np.linalg.norm(vb) + 1e-6)
        
        # Bisettrice
        bisector = va_norm + vb_norm
        bisector = bisector / (np.linalg.norm(bisector) + 1e-6)
        
        # Posizione testo
        text_pos = v + bisector * (radius + 20)
        
        return (int(text_pos[0]), int(text_pos[1]))
    
    # ═══════════════════════════════════════════════════════════════════════════
    # ARROW CALCULATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def calculate_arrow_head(
        self,
        start: Tuple[int, int],
        end: Tuple[int, int],
        head_size: int = 15,
        head_angle: float = 30.0
    ) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Calcola i due punti della punta della freccia.
        
        Returns:
            (punto_sinistro, punto_destro) della punta
        """
        s = np.array(start, dtype=np.float64)
        e = np.array(end, dtype=np.float64)
        
        # Direzione freccia
        direction = s - e
        length = np.linalg.norm(direction)
        
        if length < 1e-6:
            return (end, end)
        
        direction = direction / length
        
        # Angolo punta in radianti
        angle_rad = np.radians(head_angle)
        
        # Rotazione per i due punti
        cos_a = np.cos(angle_rad)
        sin_a = np.sin(angle_rad)
        
        # Punto sinistro
        left = np.array([
            direction[0] * cos_a - direction[1] * sin_a,
            direction[0] * sin_a + direction[1] * cos_a
        ]) * head_size + e
        
        # Punto destro
        right = np.array([
            direction[0] * cos_a + direction[1] * sin_a,
            -direction[0] * sin_a + direction[1] * cos_a
        ]) * head_size + e
        
        return (tuple(left.astype(int)), tuple(right.astype(int)))
    
    def calculate_curved_arrow_points(
        self,
        center: Tuple[int, int],
        radius: int,
        start_angle: float,
        end_angle: float,
        clockwise: bool = True,
        num_points: int = 50
    ) -> List[Tuple[int, int]]:
        """
        Genera punti per freccia curva (rotazione).
        """
        start_rad = np.radians(start_angle)
        end_rad = np.radians(end_angle)
        
        if clockwise:
            if end_rad > start_rad:
                end_rad -= 2 * np.pi
        else:
            if end_rad < start_rad:
                end_rad += 2 * np.pi
        
        angles = np.linspace(start_rad, end_rad, num_points)
        
        cx, cy = center
        points = []
        for ang in angles:
            x = int(cx + radius * np.cos(ang))
            y = int(cy + radius * np.sin(ang))
            points.append((x, y))
        
        return points
    
    # ═══════════════════════════════════════════════════════════════════════════
    # TRAJECTORY INTERPOLATION
    # ═══════════════════════════════════════════════════════════════════════════
    
    def interpolate_trajectory(
        self,
        frames_landmarks: List[List[Dict[str, Any]]],
        anchor: AnchorPoint,
        frame_start: int,
        frame_end: int
    ) -> List[Optional[Tuple[int, int]]]:
        """
        Estrae posizioni di un punto attraverso frame multipli.
        
        🎓 AI_TEACHING: Per disegnare traiettorie movimento.
        """
        positions = []
        
        for i in range(frame_start, min(frame_end + 1, len(frames_landmarks))):
            landmarks = frames_landmarks[i]
            pos = self.get_landmark_position(landmarks, anchor)
            positions.append(pos)
        
        return positions
    
    # ═══════════════════════════════════════════════════════════════════════════
    # POSE COMPARISON
    # ═══════════════════════════════════════════════════════════════════════════
    
    def calculate_pose_difference(
        self,
        landmarks_ref: List[Dict[str, Any]],
        landmarks_current: List[Dict[str, Any]],
        threshold: float = 0.1
    ) -> Dict[str, Dict[str, Any]]:
        """
        Calcola differenze tra pose.
        
        🎓 AI_BUSINESS: Per feedback "correggi qui" con frecce.
        
        Returns:
            Dict con anchor: {diff_x, diff_y, magnitude, needs_correction}
        """
        differences = {}
        
        for anchor in AnchorPoint:
            if anchor in [AnchorPoint.CUSTOM, AnchorPoint.CENTER_BODY, 
                         AnchorPoint.CENTER_HIPS, AnchorPoint.CENTER_SHOULDERS]:
                continue
            
            pos_ref = self.get_landmark_position(landmarks_ref, anchor)
            pos_cur = self.get_landmark_position(landmarks_current, anchor)
            
            if pos_ref is None or pos_cur is None:
                continue
            
            # Differenza normalizzata
            diff_x = (pos_cur[0] - pos_ref[0]) / self.width
            diff_y = (pos_cur[1] - pos_ref[1]) / self.height
            magnitude = np.sqrt(diff_x**2 + diff_y**2)
            
            differences[anchor.value] = {
                "diff_x": diff_x,
                "diff_y": diff_y,
                "magnitude": magnitude,
                "needs_correction": magnitude > threshold,
                "ref_position": pos_ref,
                "current_position": pos_cur
            }
        
        return differences
    
    # ═══════════════════════════════════════════════════════════════════════════
    # COLOR UTILITIES
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_angle_feedback_color(
        self,
        current_angle: float,
        target_angle: float,
        tolerance: float,
        color_correct: ColorRGBA,
        color_warning: ColorRGBA,
        color_error: ColorRGBA
    ) -> ColorRGBA:
        """
        Determina colore feedback basato su differenza angolo.
        
        🎓 AI_BUSINESS: Verde se corretto, giallo se vicino, rosso se sbagliato.
        """
        diff = abs(current_angle - target_angle)
        
        if diff <= tolerance:
            return color_correct
        elif diff <= tolerance * 2:
            return color_warning
        else:
            return color_error

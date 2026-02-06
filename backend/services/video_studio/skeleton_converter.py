# skeleton_converter.py
"""
🎓 AI_MODULE: Skeleton Converter (Second Person / Mirror Mode)
🎓 AI_DESCRIPTION: Converte skeleton da vista frontale a vista soggettiva per training
🎓 AI_BUSINESS: Facilita apprendimento permettendo agli allievi di seguire direttamente
🎓 AI_TEACHING: Mirror mode - inverte left/right per POV trainer

🔄 ALTERNATIVE_VALUTATE:
- Video mirroring: Scartato, distorce video e testo
- Real-time reprocessing: Scartato, troppo lento
- Pre-render entrambe le versioni: Scartato, doppio storage

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Conversione real-time dei landmark (< 1ms)
- No storage extra (calcolo al volo)
- Mantiene qualità video originale
- Toggle instant in UI
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import copy


# MediaPipe Holistic landmark indices (75 total)
# Reference: https://google.github.io/mediapipe/solutions/holistic.html

# Body landmarks that need left/right swap (33 total)
BODY_LANDMARK_PAIRS = [
    (1, 4),    # Left eye inner <-> Right eye inner
    (2, 5),    # Left eye <-> Right eye
    (3, 6),    # Left eye outer <-> Right eye outer
    (7, 8),    # Left ear <-> Right ear
    (9, 10),   # Mouth left <-> Mouth right
    (11, 12),  # Left shoulder <-> Right shoulder
    (13, 14),  # Left elbow <-> Right elbow
    (15, 16),  # Left wrist <-> Right wrist
    (17, 18),  # Left pinky <-> Right pinky
    (19, 20),  # Left index <-> Right index
    (21, 22),  # Left thumb <-> Right thumb
    (23, 24),  # Left hip <-> Right hip
    (25, 26),  # Left knee <-> Right knee
    (27, 28),  # Left ankle <-> Right ankle
    (29, 30),  # Left heel <-> Right heel
    (31, 32),  # Left foot index <-> Right foot index
]

# Landmarks that stay centered (no swap needed)
CENTERED_LANDMARKS = [0]  # Nose


@dataclass
class ConversionStats:
    """Statistiche conversione"""
    frames_converted: int
    landmarks_mirrored: int
    conversion_time_ms: float


class SkeletonConverter:
    """
    Converte skeleton da prima persona (frontale) a seconda persona (mirror/POV)
    """

    def __init__(self):
        """Inizializza converter"""
        self.conversion_cache = {}  # Cache per performance

    def mirror_skeleton_frame(
        self,
        frame_data: Dict[str, Any],
        cache_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Specchia un singolo frame di skeleton

        Args:
            frame_data: Frame skeleton con structure:
                {
                    'frame': int,
                    'timestamp': float,
                    'landmarks': List[Dict],  # 33 body landmarks
                    'left_hand': List[Dict],  # 21 left hand landmarks
                    'right_hand': List[Dict]  # 21 right hand landmarks
                }
            cache_key: Key per cache (opzionale)

        Returns:
            Frame skeleton specchiato
        """
        # Check cache
        if cache_key and cache_key in self.conversion_cache:
            return self.conversion_cache[cache_key]

        # Deep copy to avoid modifying original
        mirrored_frame = copy.deepcopy(frame_data)

        # 1. Mirror body landmarks (coordinate X + swap left/right)
        if 'landmarks' in mirrored_frame:
            landmarks = mirrored_frame['landmarks']

            # Mirror X coordinates for all landmarks
            for i, landmark in enumerate(landmarks):
                if 'x' in landmark:
                    landmark['x'] = 1.0 - landmark['x']

            # Swap left/right pairs
            for left_idx, right_idx in BODY_LANDMARK_PAIRS:
                if left_idx < len(landmarks) and right_idx < len(landmarks):
                    # Swap landmarks
                    landmarks[left_idx], landmarks[right_idx] = \
                        landmarks[right_idx], landmarks[left_idx]

        # 2. Swap hands (left becomes right, right becomes left)
        if 'left_hand' in mirrored_frame and 'right_hand' in mirrored_frame:
            left_hand = mirrored_frame['left_hand']
            right_hand = mirrored_frame['right_hand']

            # Mirror X coordinates
            for landmark in left_hand:
                if 'x' in landmark:
                    landmark['x'] = 1.0 - landmark['x']

            for landmark in right_hand:
                if 'x' in landmark:
                    landmark['x'] = 1.0 - landmark['x']

            # Swap hands
            mirrored_frame['left_hand'] = right_hand
            mirrored_frame['right_hand'] = left_hand

        # Cache result
        if cache_key:
            self.conversion_cache[cache_key] = mirrored_frame

        return mirrored_frame

    def mirror_skeleton_sequence(
        self,
        skeleton_data: List[Dict[str, Any]],
        use_cache: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Specchia un'intera sequenza di skeleton

        Args:
            skeleton_data: Lista di frame skeleton
            use_cache: Usa cache per performance

        Returns:
            Lista di frame skeleton specchiati
        """
        mirrored_sequence = []

        for i, frame in enumerate(skeleton_data):
            cache_key = f"frame_{i}" if use_cache else None
            mirrored_frame = self.mirror_skeleton_frame(frame, cache_key)
            mirrored_sequence.append(mirrored_frame)

        return mirrored_sequence

    def convert_skeleton_data(
        self,
        skeleton_data: Dict[str, Any],
        mode: str = "mirror"
    ) -> Dict[str, Any]:
        """
        Converte skeleton data completo (con metadata)

        Args:
            skeleton_data: Skeleton data completo con structure:
                {
                    'video_id': str,
                    'metadata': {...},
                    'poses': List[Dict]  # Frame data
                }
            mode: Modalità conversione ('mirror', 'original')

        Returns:
            Skeleton data convertito
        """
        if mode == "original":
            return skeleton_data  # No conversion

        # Deep copy
        converted_data = copy.deepcopy(skeleton_data)

        # Convert poses
        if 'poses' in converted_data:
            converted_data['poses'] = self.mirror_skeleton_sequence(
                converted_data['poses']
            )

        # Update metadata
        if 'metadata' not in converted_data:
            converted_data['metadata'] = {}

        converted_data['metadata']['converted'] = True
        converted_data['metadata']['conversion_mode'] = mode

        return converted_data

    def clear_cache(self):
        """Pulisce cache conversioni"""
        self.conversion_cache.clear()

    def get_cache_size(self) -> int:
        """Ottieni dimensione cache"""
        return len(self.conversion_cache)

    def compare_original_vs_mirrored(
        self,
        original_frame: Dict[str, Any],
        show_details: bool = False
    ) -> Dict[str, Any]:
        """
        Confronta frame originale vs specchiato (per debug/visualizzazione)

        Args:
            original_frame: Frame originale
            show_details: Mostra dettagli differenze

        Returns:
            Dictionary con confronto
        """
        mirrored_frame = self.mirror_skeleton_frame(original_frame)

        comparison = {
            'original': original_frame,
            'mirrored': mirrored_frame,
            'differences': {
                'hands_swapped': True,
                'x_coordinates_inverted': True,
                'left_right_pairs_swapped': len(BODY_LANDMARK_PAIRS)
            }
        }

        if show_details:
            # Calculate some example differences
            if 'landmarks' in original_frame and len(original_frame['landmarks']) > 12:
                orig_shoulder_left_x = original_frame['landmarks'][11].get('x', 0)
                orig_shoulder_right_x = original_frame['landmarks'][12].get('x', 0)

                mirr_shoulder_left_x = mirrored_frame['landmarks'][11].get('x', 0)
                mirr_shoulder_right_x = mirrored_frame['landmarks'][12].get('x', 0)

                comparison['details'] = {
                    'original_left_shoulder_x': round(orig_shoulder_left_x, 3),
                    'original_right_shoulder_x': round(orig_shoulder_right_x, 3),
                    'mirrored_left_shoulder_x': round(mirr_shoulder_left_x, 3),
                    'mirrored_right_shoulder_x': round(mirr_shoulder_right_x, 3),
                    'explanation': 'Left and right are swapped and X coordinates inverted'
                }

        return comparison


# Singleton per accesso globale
_skeleton_converter_instance: Optional[SkeletonConverter] = None


def get_skeleton_converter() -> SkeletonConverter:
    """
    Ottieni singleton SkeletonConverter

    Returns:
        SkeletonConverter instance
    """
    global _skeleton_converter_instance

    if _skeleton_converter_instance is None:
        _skeleton_converter_instance = SkeletonConverter()

    return _skeleton_converter_instance


def mirror_frame(frame_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Helper function: specchia un frame

    Args:
        frame_data: Frame skeleton

    Returns:
        Frame specchiato
    """
    converter = get_skeleton_converter()
    return converter.mirror_skeleton_frame(frame_data)


def mirror_sequence(frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Helper function: specchia una sequenza

    Args:
        frames: Lista frame skeleton

    Returns:
        Lista frame specchiati
    """
    converter = get_skeleton_converter()
    return converter.mirror_skeleton_sequence(frames)

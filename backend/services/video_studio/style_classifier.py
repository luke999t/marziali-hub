"""
🥋 Style Classifier - Riconoscimento Automatico Stile Arti Marziali

Analizza skeleton data (75 landmarks) e classifica lo stile:
- Tai Chi
- Wing Chun
- Shaolin
- Bagua Zhang
- Karate

Metodo:
1. Estrae features da skeleton frames
2. Confronta con pattern database
3. Calcola score per ogni stile
4. Restituisce classificazione con confidence
"""

import numpy as np
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
import logging

from martial_arts_patterns import (
    MartialArtStyle,
    TechniquePattern,
    MARTIAL_ARTS_DATABASE,
    get_style_characteristics,
    get_all_patterns
)

logger = logging.getLogger(__name__)


@dataclass
class StyleClassificationResult:
    """Risultato classificazione stile"""
    style: MartialArtStyle
    confidence: float  # 0.0 - 1.0
    secondary_style: Optional[MartialArtStyle] = None
    secondary_confidence: float = 0.0

    # Breakdown dettagliato
    style_scores: Dict[str, float] = None
    detected_patterns: List[str] = None
    features: Dict[str, float] = None

    # Reasoning
    reasoning: List[str] = None


class StyleClassifier:
    """
    Classificatore di stili di arti marziali basato su skeleton analysis
    """

    def __init__(self, confidence_threshold: float = 0.6):
        self.confidence_threshold = confidence_threshold
        self.patterns_db = MARTIAL_ARTS_DATABASE

        logger.info(f"StyleClassifier initialized with {len(get_all_patterns())} patterns")

    def classify_video(self, skeleton_frames: List[Dict[str, Any]]) -> StyleClassificationResult:
        """
        Classifica lo stile da un video completo

        Args:
            skeleton_frames: Lista di frame con landmarks (75 per frame)

        Returns:
            StyleClassificationResult con stile rilevato e confidence
        """
        if not skeleton_frames or len(skeleton_frames) < 10:
            logger.warning("Too few frames for classification")
            return StyleClassificationResult(
                style=MartialArtStyle.UNKNOWN,
                confidence=0.0,
                reasoning=["Insufficient frames (need at least 10)"]
            )

        # 1. Estrai features globali dal video
        features = self._extract_video_features(skeleton_frames)

        # 2. Calcola score per ogni stile
        style_scores = self._calculate_style_scores(features, skeleton_frames)

        # 3. Detect pattern specifici
        detected_patterns = self._detect_patterns(skeleton_frames)

        # 4. Combina score e pattern per classificazione finale
        final_style, confidence, reasoning = self._finalize_classification(
            style_scores, detected_patterns, features
        )

        # 5. Secondary style (se presente)
        secondary_style, secondary_conf = self._get_secondary_style(style_scores, final_style)

        result = StyleClassificationResult(
            style=final_style,
            confidence=confidence,
            secondary_style=secondary_style,
            secondary_confidence=secondary_conf,
            style_scores=style_scores,
            detected_patterns=detected_patterns,
            features=features,
            reasoning=reasoning
        )

        logger.info(f"Classified as {final_style.value} with {confidence:.2f} confidence")
        return result

    def _extract_video_features(self, frames: List[Dict]) -> Dict[str, float]:
        """
        Estrae features globali dal video per classificazione

        Features estratte:
        - average_velocity: velocità media movimento
        - movement_smoothness: fluidità movimento
        - circular_motion_ratio: percentuale movimenti circolari vs lineari
        - stance_width_avg: larghezza media stance
        - hand_activity: attività mani (movimenti)
        - vertical_variance: variazione altezza (salti, calci alti)
        - rotation_frequency: frequenza rotazioni corpo
        """
        features = {}

        # Velocità media
        velocities = []
        for i in range(1, len(frames)):
            prev_frame = frames[i-1]
            curr_frame = frames[i]

            if 'landmarks' in prev_frame and 'landmarks' in curr_frame:
                velocity = self._calculate_frame_velocity(
                    prev_frame['landmarks'],
                    curr_frame['landmarks']
                )
                velocities.append(velocity)

        features['average_velocity'] = np.mean(velocities) if velocities else 0.0
        features['velocity_variance'] = np.var(velocities) if velocities else 0.0

        # Smoothness (bassa varianza = più smooth)
        features['movement_smoothness'] = 1.0 / (1.0 + features['velocity_variance'])

        # Movimenti circolari vs lineari
        circular_ratio = self._calculate_circular_motion_ratio(frames)
        features['circular_motion_ratio'] = circular_ratio

        # Stance width medio
        stance_widths = []
        for frame in frames:
            if 'landmarks' in frame and len(frame['landmarks']) >= 24:
                # Distanza spalle (landmark 11 e 12)
                left_hip = frame['landmarks'][23]
                right_hip = frame['landmarks'][24]
                width = np.sqrt(
                    (left_hip['x'] - right_hip['x'])**2 +
                    (left_hip['y'] - right_hip['y'])**2
                )
                stance_widths.append(width)

        features['stance_width_avg'] = np.mean(stance_widths) if stance_widths else 0.0

        # Attività mani (movimento mani rispetto a corpo)
        hand_activity = self._calculate_hand_activity(frames)
        features['hand_activity'] = hand_activity

        # Variazione verticale (salti, calci alti)
        vertical_positions = []
        for frame in frames:
            if 'landmarks' in frame and len(frame['landmarks']) >= 1:
                # Y position del naso (landmark 0)
                nose_y = frame['landmarks'][0]['y']
                vertical_positions.append(nose_y)

        features['vertical_variance'] = np.var(vertical_positions) if vertical_positions else 0.0

        # Frequenza rotazioni corpo
        rotation_freq = self._calculate_rotation_frequency(frames)
        features['rotation_frequency'] = rotation_freq

        return features

    def _calculate_frame_velocity(self, prev_landmarks: List[Dict], curr_landmarks: List[Dict]) -> float:
        """Calcola velocità media tra due frame"""
        if len(prev_landmarks) != len(curr_landmarks):
            return 0.0

        distances = []
        for prev_lm, curr_lm in zip(prev_landmarks, curr_landmarks):
            dist = np.sqrt(
                (curr_lm['x'] - prev_lm['x'])**2 +
                (curr_lm['y'] - prev_lm['y'])**2 +
                (curr_lm['z'] - prev_lm['z'])**2
            )
            distances.append(dist)

        return np.mean(distances)

    def _calculate_circular_motion_ratio(self, frames: List[Dict]) -> float:
        """Calcola percentuale movimenti circolari vs lineari"""
        if len(frames) < 10:
            return 0.0

        # Analizza traiettoria polsi
        circular_score = 0.0
        linear_score = 0.0

        # Polso sinistro (landmark 15)
        wrist_positions = []
        for frame in frames:
            if 'landmarks' in frame and len(frame['landmarks']) >= 16:
                wrist = frame['landmarks'][15]
                wrist_positions.append((wrist['x'], wrist['y']))

        if len(wrist_positions) >= 10:
            # Calcola curvatura traiettoria
            for i in range(2, len(wrist_positions)):
                p0 = np.array(wrist_positions[i-2])
                p1 = np.array(wrist_positions[i-1])
                p2 = np.array(wrist_positions[i])

                # Vettori
                v1 = p1 - p0
                v2 = p2 - p1

                # Angolo tra vettori
                if np.linalg.norm(v1) > 0 and np.linalg.norm(v2) > 0:
                    cos_angle = np.dot(v1, v2) / (np.linalg.norm(v1) * np.linalg.norm(v2))
                    angle = np.arccos(np.clip(cos_angle, -1, 1))

                    # Angolo grande = movimento circolare
                    if angle > np.pi / 4:  # > 45 gradi
                        circular_score += 1
                    else:
                        linear_score += 1

        total = circular_score + linear_score
        return circular_score / total if total > 0 else 0.0

    def _calculate_hand_activity(self, frames: List[Dict]) -> float:
        """Calcola attività mani (quanto si muovono rispetto al corpo)"""
        if len(frames) < 10:
            return 0.0

        hand_movements = []

        for i in range(1, len(frames)):
            prev_frame = frames[i-1]
            curr_frame = frames[i]

            # Mano sinistra
            if 'left_hand' in prev_frame and 'left_hand' in curr_frame:
                if prev_frame['left_hand'] and curr_frame['left_hand']:
                    movement = self._calculate_frame_velocity(
                        prev_frame['left_hand'][:5],  # Prime 5 landmarks mano
                        curr_frame['left_hand'][:5]
                    )
                    hand_movements.append(movement)

            # Mano destra
            if 'right_hand' in prev_frame and 'right_hand' in curr_frame:
                if prev_frame['right_hand'] and curr_frame['right_hand']:
                    movement = self._calculate_frame_velocity(
                        prev_frame['right_hand'][:5],
                        curr_frame['right_hand'][:5]
                    )
                    hand_movements.append(movement)

        return np.mean(hand_movements) if hand_movements else 0.0

    def _calculate_rotation_frequency(self, frames: List[Dict]) -> float:
        """Calcola frequenza rotazioni corpo"""
        if len(frames) < 10:
            return 0.0

        rotations = 0
        prev_direction = None

        for frame in frames:
            if 'landmarks' in frame and len(frame['landmarks']) >= 24:
                # Direzione spalle (landmark 11 vs 12)
                left_shoulder = frame['landmarks'][11]
                right_shoulder = frame['landmarks'][12]

                direction = right_shoulder['x'] - left_shoulder['x']

                if prev_direction is not None:
                    if (prev_direction > 0) != (direction > 0):
                        rotations += 1

                prev_direction = direction

        # Rotazioni per secondo
        duration = frames[-1]['timestamp'] - frames[0]['timestamp'] if len(frames) > 1 else 1.0
        return rotations / duration if duration > 0 else 0.0

    def _calculate_style_scores(self, features: Dict[str, float], frames: List[Dict]) -> Dict[str, float]:
        """
        Calcola score per ogni stile basato su features

        Returns:
            Dict con score 0.0-1.0 per ogni stile
        """
        scores = {}

        # TAI CHI: lento, fluido, circolare
        tai_chi_score = 0.0
        if features['average_velocity'] < 0.05:  # Molto lento
            tai_chi_score += 0.3
        if features['movement_smoothness'] > 0.7:  # Molto fluido
            tai_chi_score += 0.3
        if features['circular_motion_ratio'] > 0.6:  # Molti movimenti circolari
            tai_chi_score += 0.4
        scores['tai_chi'] = min(tai_chi_score, 1.0)

        # WING CHUN: veloce, lineare, centerline
        wing_chun_score = 0.0
        if features['average_velocity'] > 0.1:  # Veloce
            wing_chun_score += 0.3
        if features['circular_motion_ratio'] < 0.3:  # Lineare
            wing_chun_score += 0.3
        if features['hand_activity'] > 0.08:  # Mani molto attive
            wing_chun_score += 0.4
        scores['wing_chun'] = min(wing_chun_score, 1.0)

        # SHAOLIN: veloce, dinamico, alta variazione verticale
        shaolin_score = 0.0
        if features['average_velocity'] > 0.12:  # Molto veloce
            shaolin_score += 0.3
        if features['vertical_variance'] > 0.05:  # Molti salti/calci alti
            shaolin_score += 0.4
        if features['hand_activity'] > 0.1:  # Mani dinamiche
            shaolin_score += 0.3
        scores['shaolin'] = min(shaolin_score, 1.0)

        # BAGUA: rotazioni, circolare, camminata
        bagua_score = 0.0
        if features['rotation_frequency'] > 0.5:  # Molte rotazioni
            bagua_score += 0.4
        if features['circular_motion_ratio'] > 0.5:  # Circolare
            bagua_score += 0.3
        if features['average_velocity'] > 0.05 and features['average_velocity'] < 0.12:  # Velocità media
            bagua_score += 0.3
        scores['bagua'] = min(bagua_score, 1.0)

        # KARATE: stance largo, movimenti esplosivi, linearità
        karate_score = 0.0
        if features['stance_width_avg'] > 0.35:  # Stance largo
            karate_score += 0.3
        if features['velocity_variance'] > 0.01:  # Esplosivo (alta varianza)
            karate_score += 0.4
        if features['circular_motion_ratio'] < 0.4:  # Più lineare
            karate_score += 0.3
        scores['karate'] = min(karate_score, 1.0)

        return scores

    def _detect_patterns(self, frames: List[Dict]) -> List[str]:
        """
        Rileva pattern specifici dal video

        Returns:
            Lista di pattern names rilevati
        """
        detected = []
        all_patterns = get_all_patterns()

        # Implementazione semplificata: cerca pattern per keywords e features
        # In produzione, questo sarebbe più sofisticato con ML

        # Per ora, usiamo un approccio basato su regole
        features = self._extract_video_features(frames)

        # Tai Chi patterns
        if features['average_velocity'] < 0.05 and features['circular_motion_ratio'] > 0.6:
            detected.append("yun_shou")  # Cloud hands

        if features['movement_smoothness'] > 0.8:
            detected.append("push_hands")  # Tai Chi push hands

        # Wing Chun patterns
        if features['hand_activity'] > 0.1 and features['average_velocity'] > 0.1:
            detected.append("chain_punches")

        # Shaolin patterns
        if features['vertical_variance'] > 0.05:
            detected.append("crane_kick")  # High kicks

        # Bagua patterns
        if features['rotation_frequency'] > 0.5:
            detected.append("circle_walking")

        # Karate patterns
        if features['stance_width_avg'] > 0.35 and features['velocity_variance'] > 0.01:
            detected.append("oi_zuki")  # Lunge punch

        return detected

    def _finalize_classification(
        self,
        style_scores: Dict[str, float],
        detected_patterns: List[str],
        features: Dict[str, float]
    ) -> Tuple[MartialArtStyle, float, List[str]]:
        """
        Finalizza classificazione combinando score e pattern

        Returns:
            (style, confidence, reasoning)
        """
        reasoning = []

        # Trova stile con score più alto
        if not style_scores or max(style_scores.values()) == 0:
            return MartialArtStyle.UNKNOWN, 0.0, ["No clear style indicators"]

        best_style_name = max(style_scores, key=style_scores.get)
        best_score = style_scores[best_style_name]

        # Converti nome stile a enum
        style_map = {
            'tai_chi': MartialArtStyle.TAI_CHI,
            'wing_chun': MartialArtStyle.WING_CHUN,
            'shaolin': MartialArtStyle.SHAOLIN,
            'bagua': MartialArtStyle.BAGUA,
            'karate': MartialArtStyle.KARATE
        }

        best_style = style_map.get(best_style_name, MartialArtStyle.UNKNOWN)

        # Boost confidence se pattern rilevati confermano
        confidence = best_score
        pattern_boost = 0.0

        all_patterns = get_all_patterns()
        for pattern_name in detected_patterns:
            if pattern_name in all_patterns:
                pattern = all_patterns[pattern_name]
                if pattern.style == best_style:
                    pattern_boost += 0.1
                    reasoning.append(f"Detected pattern: {pattern.name}")

        confidence = min(confidence + pattern_boost, 1.0)

        # Aggiungi reasoning basato su features
        if best_style == MartialArtStyle.TAI_CHI:
            if features['average_velocity'] < 0.05:
                reasoning.append("Very slow movements (characteristic of Tai Chi)")
            if features['circular_motion_ratio'] > 0.6:
                reasoning.append("High circular motion ratio")
            if features['movement_smoothness'] > 0.7:
                reasoning.append("Very smooth and flowing movements")

        elif best_style == MartialArtStyle.WING_CHUN:
            if features['hand_activity'] > 0.08:
                reasoning.append("High hand activity (chain punches)")
            if features['circular_motion_ratio'] < 0.3:
                reasoning.append("Linear movements on centerline")

        elif best_style == MartialArtStyle.SHAOLIN:
            if features['vertical_variance'] > 0.05:
                reasoning.append("High vertical variance (kicks, jumps)")
            if features['average_velocity'] > 0.12:
                reasoning.append("Very fast and dynamic movements")

        elif best_style == MartialArtStyle.BAGUA:
            if features['rotation_frequency'] > 0.5:
                reasoning.append("Frequent body rotations (circle walking)")
            if features['circular_motion_ratio'] > 0.5:
                reasoning.append("Circular movement patterns")

        elif best_style == MartialArtStyle.KARATE:
            if features['stance_width_avg'] > 0.35:
                reasoning.append("Wide stance (characteristic of Karate)")
            if features['velocity_variance'] > 0.01:
                reasoning.append("Explosive movements (kime)")

        return best_style, confidence, reasoning

    def _get_secondary_style(
        self,
        style_scores: Dict[str, float],
        primary_style: MartialArtStyle
    ) -> Tuple[Optional[MartialArtStyle], float]:
        """Trova secondary style (se presente)"""
        style_map = {
            'tai_chi': MartialArtStyle.TAI_CHI,
            'wing_chun': MartialArtStyle.WING_CHUN,
            'shaolin': MartialArtStyle.SHAOLIN,
            'bagua': MartialArtStyle.BAGUA,
            'karate': MartialArtStyle.KARATE
        }

        # Rimuovi primary style
        secondary_scores = {k: v for k, v in style_scores.items()
                            if style_map.get(k) != primary_style}

        if not secondary_scores or max(secondary_scores.values()) < 0.3:
            return None, 0.0

        secondary_name = max(secondary_scores, key=secondary_scores.get)
        secondary_conf = secondary_scores[secondary_name]

        return style_map.get(secondary_name), secondary_conf


# ===============================================
# UTILITY FUNCTIONS
# ===============================================

def classify_video_simple(skeleton_frames: List[Dict]) -> str:
    """
    Classificazione semplificata per quick usage

    Returns:
        String con nome stile (es. "tai_chi", "wing_chun", etc.)
    """
    classifier = StyleClassifier()
    result = classifier.classify_video(skeleton_frames)
    return result.style.value


def classify_with_confidence(skeleton_frames: List[Dict]) -> Tuple[str, float]:
    """
    Classificazione con confidence

    Returns:
        (style_name, confidence)
    """
    classifier = StyleClassifier()
    result = classifier.classify_video(skeleton_frames)
    return result.style.value, result.confidence


if __name__ == "__main__":
    # Test classifier
    print("🥋 Style Classifier Test")
    print("="*50)

    # Mock skeleton frames per test
    mock_frames = [
        {
            'frame': i,
            'timestamp': i * 0.033,  # 30 FPS
            'landmarks': [{'x': 0.5, 'y': 0.5, 'z': 0, 'visibility': 1.0}] * 75,
            'left_hand': [{'x': 0.3, 'y': 0.4, 'z': 0, 'visibility': 1.0}] * 21,
            'right_hand': [{'x': 0.7, 'y': 0.4, 'z': 0, 'visibility': 1.0}] * 21
        }
        for i in range(100)
    ]

    classifier = StyleClassifier()
    result = classifier.classify_video(mock_frames)

    print(f"\nClassified Style: {result.style.value}")
    print(f"Confidence: {result.confidence:.2f}")
    print(f"\nStyle Scores:")
    for style, score in result.style_scores.items():
        print(f"  {style}: {score:.2f}")
    print(f"\nDetected Patterns: {len(result.detected_patterns)}")
    for pattern in result.detected_patterns:
        print(f"  - {pattern}")
    print(f"\nReasoning:")
    for reason in result.reasoning:
        print(f"  - {reason}")

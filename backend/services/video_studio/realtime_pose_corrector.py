"""
Real-Time Pose Correction System
=================================

🎯 BUSINESS VALUE:
- Core value proposition del prodotto
- Feedback immediato durante allenamento
- Tracking progresso nel tempo
- Differentiation vs YouTube gratis

🔧 TECHNICAL:
- Real-time pose detection (webcam)
- Comparison con pose ideale da knowledge base
- Error identification (top 3 errori critici)
- Multi-modal feedback (audio + visual)

📊 METRICHE:
- Latency: <100ms per frame
- Accuracy: <5° deviation detection
- FPS: 30fps camera tracking
- CPU: <60% usage

🏗️ ARCHITECTURE:
- INPUT: webcam frame stream
- PROCESS: pose extraction → matching → deviation calc → feedback gen
- OUTPUT: real-time corrections (visual + audio)
- DEPENDENCIES: MediaPipe, pose_detection.py, knowledge_extractor.py
"""

import cv2
import numpy as np
import mediapipe as mp
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
import logging
import json
import math
from pathlib import Path
from collections import deque
import threading
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PoseDeviation:
    """Deviazione tra pose attuale e ideale"""
    landmark_name: str
    landmark_index: int
    deviation_degrees: float
    deviation_distance: float  # Normalized 0-1
    severity: str  # "low", "medium", "high", "critical"
    correction_text: str
    priority: int  # 1-10, 10 = most important


@dataclass
class CorrectionFeedback:
    """Feedback di correzione per l'utente"""
    timestamp: datetime
    technique_name: str
    deviations: List[PoseDeviation]
    top_errors: List[str]  # Top 3 errors human-readable
    overall_score: float  # 0-100
    improvement_tips: List[str]


@dataclass
class ProgressSession:
    """Sessione di allenamento per tracking progresso"""
    session_id: str
    technique_name: str
    start_time: datetime
    end_time: Optional[datetime] = None
    total_frames: int = 0
    average_score: float = 0.0
    improvements: List[str] = field(default_factory=list)
    corrections_history: List[CorrectionFeedback] = field(default_factory=list)


class IdealPoseMatcher:
    """
    Matcher per trovare la pose ideale più simile nel knowledge base

    🎯 ALGORITHM:
    1. Identifica tecnica corrente da movimento (rule-based)
    2. Retrieve pose ideale da knowledge base
    3. Time-based matching (quale frame della forma corrisponde)
    """

    def __init__(self, knowledge_base_path: Optional[Path] = None):
        """
        Args:
            knowledge_base_path: Path to JSON knowledge base con forme estratte
        """
        self.knowledge_base_path = knowledge_base_path
        self.forms_cache: Dict[str, Any] = {}
        self.sequences_cache: Dict[str, Any] = {}
        self.current_technique: Optional[str] = None
        self.frame_buffer = deque(maxlen=90)  # 3 seconds @ 30fps

        logger.info("IdealPoseMatcher initialized")

    def load_knowledge_base(self) -> bool:
        """Load knowledge base da file JSON"""
        if not self.knowledge_base_path or not self.knowledge_base_path.exists():
            logger.warning("Knowledge base not found, using built-in templates")
            self._load_builtin_templates()
            return True

        try:
            with open(self.knowledge_base_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.forms_cache = {form['name']: form for form in data.get('forms', [])}
            self.sequences_cache = {seq['name']: seq for seq in data.get('sequences', [])}

            logger.info(f"Loaded {len(self.forms_cache)} forms and {len(self.sequences_cache)} sequences")
            return True

        except Exception as e:
            logger.error(f"Failed to load knowledge base: {e}")
            self._load_builtin_templates()
            return False

    def _load_builtin_templates(self):
        """Load built-in templates per tecniche comuni"""
        # Template semplificati per punch, stance, kick
        self.sequences_cache = {
            'basic_punch': {
                'name': 'basic_punch',
                'style': 'generic',
                'ideal_landmarks': self._get_ideal_punch_landmarks(),
                'key_angles': {
                    'elbow': 160,  # gradi
                    'shoulder': 90,
                    'hip': 180
                }
            },
            'horse_stance': {
                'name': 'horse_stance',
                'style': 'generic',
                'ideal_landmarks': self._get_ideal_stance_landmarks(),
                'key_angles': {
                    'knee': 90,
                    'hip': 90,
                    'ankle': 90
                }
            },
            'front_kick': {
                'name': 'front_kick',
                'style': 'generic',
                'ideal_landmarks': self._get_ideal_kick_landmarks(),
                'key_angles': {
                    'hip': 90,
                    'knee': 180,
                    'ankle': 110
                }
            }
        }
        logger.info("Loaded 3 built-in technique templates")

    def _get_ideal_punch_landmarks(self) -> Dict[str, Tuple[float, float, float]]:
        """Ideal landmarks per punch (normalized 0-1)"""
        return {
            'right_shoulder': (0.6, 0.4, 0.0),
            'right_elbow': (0.75, 0.4, -0.2),
            'right_wrist': (0.9, 0.4, -0.4),
            'left_shoulder': (0.4, 0.4, 0.0),
            'left_hip': (0.4, 0.6, 0.0),
            'right_hip': (0.6, 0.6, 0.0)
        }

    def _get_ideal_stance_landmarks(self) -> Dict[str, Tuple[float, float, float]]:
        """Ideal landmarks per horse stance"""
        return {
            'left_hip': (0.4, 0.5, 0.0),
            'right_hip': (0.6, 0.5, 0.0),
            'left_knee': (0.35, 0.7, 0.0),
            'right_knee': (0.65, 0.7, 0.0),
            'left_ankle': (0.3, 0.9, 0.0),
            'right_ankle': (0.7, 0.9, 0.0)
        }

    def _get_ideal_kick_landmarks(self) -> Dict[str, Tuple[float, float, float]]:
        """Ideal landmarks per front kick"""
        return {
            'right_hip': (0.6, 0.5, 0.0),
            'right_knee': (0.6, 0.3, -0.3),
            'right_ankle': (0.6, 0.2, -0.5),
            'left_hip': (0.4, 0.6, 0.0),
            'left_knee': (0.4, 0.8, 0.0),
            'left_ankle': (0.4, 1.0, 0.0)
        }

    def identify_technique(self, current_landmarks: Dict[str, Tuple[float, float, float]]) -> str:
        """
        Identifica tecnica corrente da landmarks

        🎯 ALGORITHM: Rule-based classification
        - Punch: wrist velocity high + forward movement
        - Stance: low center of mass + wide leg spread
        - Kick: one leg elevated + hip rotation
        """
        # Add to buffer
        self.frame_buffer.append(current_landmarks)

        if len(self.frame_buffer) < 10:
            return 'unknown'

        # Analyze movement patterns
        right_wrist_movement = self._calculate_movement('right_wrist')
        leg_spread = self._calculate_leg_spread(current_landmarks)
        center_of_mass_y = self._calculate_center_of_mass_y(current_landmarks)

        # Rule-based classification
        if right_wrist_movement > 0.15:  # High forward wrist movement
            return 'basic_punch'
        elif leg_spread > 0.3 and center_of_mass_y > 0.6:  # Wide spread + low
            return 'horse_stance'
        elif self._is_leg_elevated(current_landmarks):
            return 'front_kick'
        else:
            return 'unknown'

    def _calculate_movement(self, landmark_name: str) -> float:
        """Calculate movement magnitude for landmark over buffer"""
        if len(self.frame_buffer) < 2:
            return 0.0

        first_frame = list(self.frame_buffer)[0]
        last_frame = list(self.frame_buffer)[-1]

        if landmark_name not in first_frame or landmark_name not in last_frame:
            return 0.0

        p1 = np.array(first_frame[landmark_name])
        p2 = np.array(last_frame[landmark_name])

        return np.linalg.norm(p2 - p1)

    def _calculate_leg_spread(self, landmarks: Dict) -> float:
        """Calculate horizontal distance between ankles"""
        if 'left_ankle' not in landmarks or 'right_ankle' not in landmarks:
            return 0.0

        left = landmarks['left_ankle'][0]
        right = landmarks['right_ankle'][0]

        return abs(right - left)

    def _calculate_center_of_mass_y(self, landmarks: Dict) -> float:
        """Calculate Y coordinate of center of mass"""
        if 'left_hip' not in landmarks or 'right_hip' not in landmarks:
            return 0.5

        left_hip_y = landmarks['left_hip'][1]
        right_hip_y = landmarks['right_hip'][1]

        return (left_hip_y + right_hip_y) / 2

    def _is_leg_elevated(self, landmarks: Dict) -> bool:
        """Check if one leg is elevated (for kick detection)"""
        if 'left_ankle' not in landmarks or 'right_ankle' not in landmarks:
            return False
        if 'left_hip' not in landmarks or 'right_hip' not in landmarks:
            return False

        left_ankle_y = landmarks['left_ankle'][1]
        right_ankle_y = landmarks['right_ankle'][1]
        left_hip_y = landmarks['left_hip'][1]
        right_hip_y = landmarks['right_hip'][1]

        # Check if ankle is significantly higher than normal stance
        left_elevated = (left_hip_y - left_ankle_y) < 0.3
        right_elevated = (right_hip_y - right_ankle_y) < 0.3

        return left_elevated or right_elevated

    def get_ideal_pose(self, technique_name: str) -> Optional[Dict]:
        """Retrieve ideal pose for technique"""
        if technique_name in self.sequences_cache:
            return self.sequences_cache[technique_name]
        elif technique_name in self.forms_cache:
            return self.forms_cache[technique_name]
        else:
            logger.warning(f"Technique '{technique_name}' not found in knowledge base")
            return None


class PoseDeviationAnalyzer:
    """
    Calcola deviazioni tra pose attuale e ideale

    🎯 ALGORITHM:
    1. Calculate Euclidean distance for each landmark
    2. Calculate angle deviations for joints
    3. Prioritize by body region importance
    4. Generate human-readable corrections
    """

    # Landmark importance weights per arti marziali
    LANDMARK_WEIGHTS = {
        'wrist': 10,
        'elbow': 9,
        'shoulder': 8,
        'knee': 9,
        'ankle': 8,
        'hip': 7,
        'nose': 3,
        'eye': 2,
        'ear': 2
    }

    # Severity thresholds (degrees)
    SEVERITY_THRESHOLDS = {
        'low': 5,
        'medium': 15,
        'high': 30,
        'critical': 45
    }

    def __init__(self):
        logger.info("PoseDeviationAnalyzer initialized")

    def calculate_deviations(
        self,
        current_landmarks: Dict[str, Tuple[float, float, float]],
        ideal_landmarks: Dict[str, Tuple[float, float, float]]
    ) -> List[PoseDeviation]:
        """
        Calculate all deviations between current and ideal pose

        Returns:
            List of PoseDeviation sorted by priority (worst first)
        """
        deviations = []

        for landmark_name in current_landmarks:
            if landmark_name not in ideal_landmarks:
                continue

            current_pos = np.array(current_landmarks[landmark_name])
            ideal_pos = np.array(ideal_landmarks[landmark_name])

            # Euclidean distance (normalized 0-1)
            distance = np.linalg.norm(current_pos - ideal_pos)

            # Convert to degrees (approximate)
            # 0.1 normalized distance ≈ 10 degrees deviation
            deviation_degrees = distance * 100

            # Determine severity
            severity = self._determine_severity(deviation_degrees)

            # Generate correction text
            correction_text = self._generate_correction_text(
                landmark_name, current_pos, ideal_pos
            )

            # Calculate priority (higher = more important)
            priority = self._calculate_priority(landmark_name, deviation_degrees)

            deviation = PoseDeviation(
                landmark_name=landmark_name,
                landmark_index=self._get_landmark_index(landmark_name),
                deviation_degrees=deviation_degrees,
                deviation_distance=distance,
                severity=severity,
                correction_text=correction_text,
                priority=priority
            )

            deviations.append(deviation)

        # Sort by priority (descending)
        deviations.sort(key=lambda d: d.priority, reverse=True)

        return deviations

    def _determine_severity(self, deviation_degrees: float) -> str:
        """Determine severity level from deviation degrees"""
        if deviation_degrees >= self.SEVERITY_THRESHOLDS['critical']:
            return 'critical'
        elif deviation_degrees >= self.SEVERITY_THRESHOLDS['high']:
            return 'high'
        elif deviation_degrees >= self.SEVERITY_THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'

    def _calculate_priority(self, landmark_name: str, deviation_degrees: float) -> int:
        """Calculate priority score (1-10)"""
        # Base priority from landmark type
        base_priority = 5
        for key, weight in self.LANDMARK_WEIGHTS.items():
            if key in landmark_name:
                base_priority = weight
                break

        # Increase priority based on severity
        severity_multiplier = min(deviation_degrees / 10.0, 2.0)

        priority = int(base_priority * severity_multiplier)
        return max(1, min(10, priority))

    def _generate_correction_text(
        self,
        landmark_name: str,
        current_pos: np.ndarray,
        ideal_pos: np.ndarray
    ) -> str:
        """Generate human-readable correction text"""
        diff = ideal_pos - current_pos

        # Determine direction
        direction_x = "sinistra" if diff[0] < -0.05 else "destra" if diff[0] > 0.05 else ""
        direction_y = "su" if diff[1] < -0.05 else "giù" if diff[1] > 0.05 else ""
        direction_z = "avanti" if diff[2] < -0.05 else "indietro" if diff[2] > 0.05 else ""

        # Clean landmark name
        clean_name = landmark_name.replace('_', ' ').title()

        # Generate text
        directions = [d for d in [direction_x, direction_y, direction_z] if d]

        if not directions:
            return f"{clean_name} è nella posizione corretta"
        elif len(directions) == 1:
            return f"Muovi {clean_name} verso {directions[0]}"
        else:
            return f"Muovi {clean_name} verso {directions[0]} e {directions[1]}"

    def _get_landmark_index(self, landmark_name: str) -> int:
        """Get MediaPipe landmark index from name"""
        # Mapping semplificato
        landmark_map = {
            'nose': 0,
            'left_shoulder': 11,
            'right_shoulder': 12,
            'left_elbow': 13,
            'right_elbow': 14,
            'left_wrist': 15,
            'right_wrist': 16,
            'left_hip': 23,
            'right_hip': 24,
            'left_knee': 25,
            'right_knee': 26,
            'left_ankle': 27,
            'right_ankle': 28
        }
        return landmark_map.get(landmark_name, 0)


class FeedbackGenerator:
    """
    Generate multi-modal feedback (text + audio ready)

    🎯 OUTPUT FORMATS:
    - Text: "Alza il gomito destro di 15 gradi"
    - Audio-ready: Short phrases for TTS
    - Visual: Coordinates for overlay rendering
    """

    def __init__(self):
        logger.info("FeedbackGenerator initialized")

    def generate_feedback(
        self,
        technique_name: str,
        deviations: List[PoseDeviation]
    ) -> CorrectionFeedback:
        """
        Generate complete feedback from deviations

        Returns:
            CorrectionFeedback with top 3 errors and improvement tips
        """
        # Select top 3 most important errors
        top_deviations = deviations[:3]

        top_errors = [d.correction_text for d in top_deviations]

        # Calculate overall score (0-100)
        overall_score = self._calculate_overall_score(deviations)

        # Generate improvement tips
        improvement_tips = self._generate_improvement_tips(top_deviations)

        feedback = CorrectionFeedback(
            timestamp=datetime.now(),
            technique_name=technique_name,
            deviations=deviations,
            top_errors=top_errors,
            overall_score=overall_score,
            improvement_tips=improvement_tips
        )

        return feedback

    def _calculate_overall_score(self, deviations: List[PoseDeviation]) -> float:
        """Calculate overall score 0-100"""
        if not deviations:
            return 100.0

        # Average deviation distance (normalized)
        avg_distance = np.mean([d.deviation_distance for d in deviations])

        # Convert to score (lower distance = higher score)
        score = max(0, 100 - (avg_distance * 200))

        return round(score, 1)

    def _generate_improvement_tips(self, top_deviations: List[PoseDeviation]) -> List[str]:
        """Generate actionable improvement tips"""
        tips = []

        for deviation in top_deviations:
            if deviation.severity in ['critical', 'high']:
                tip = f"⚠️ {deviation.correction_text} (priorità alta)"
                tips.append(tip)

        # Add general tips
        if any(d.severity == 'critical' for d in top_deviations):
            tips.append("💡 Fai pratica lentamente per memorizzare la posizione corretta")

        return tips[:5]  # Max 5 tips


class RealtimePoseCorrector:
    """
    Main class per real-time pose correction

    🎯 MAIN LOOP:
    1. Capture frame from webcam
    2. Extract pose landmarks (MediaPipe)
    3. Identify technique
    4. Match with ideal pose
    5. Calculate deviations
    6. Generate feedback
    7. Display overlay
    8. Log for progress tracking

    📊 PERFORMANCE:
    - Target: 30 FPS
    - Max latency: 100ms per frame
    - CPU usage: <60%
    """

    def __init__(
        self,
        knowledge_base_path: Optional[Path] = None,
        enable_audio: bool = False,
        enable_progress_tracking: bool = True
    ):
        """
        Args:
            knowledge_base_path: Path to knowledge base JSON
            enable_audio: Enable audio feedback (requires TTS)
            enable_progress_tracking: Enable session progress tracking
        """
        self.knowledge_base_path = knowledge_base_path
        self.enable_audio = enable_audio
        self.enable_progress_tracking = enable_progress_tracking

        # Components
        self.pose_matcher = IdealPoseMatcher(knowledge_base_path)
        self.deviation_analyzer = PoseDeviationAnalyzer()
        self.feedback_generator = FeedbackGenerator()

        # MediaPipe Pose
        self.mp_pose = mp.solutions.pose
        self.pose = self.mp_pose.Pose(
            static_image_mode=False,
            model_complexity=1,
            enable_segmentation=False,
            min_detection_confidence=0.5,
            min_tracking_confidence=0.5
        )

        # State
        self.is_running = False
        self.current_session: Optional[ProgressSession] = None
        self.feedback_history: deque = deque(maxlen=100)

        # Stats
        self.fps = 0
        self.frame_count = 0
        self.last_feedback_time = time.time()

        logger.info("RealtimePoseCorrector initialized")

    def start_session(self, technique_name: str) -> str:
        """Start a new correction session"""
        session_id = f"session_{int(time.time())}"

        self.current_session = ProgressSession(
            session_id=session_id,
            technique_name=technique_name,
            start_time=datetime.now()
        )

        logger.info(f"Started session {session_id} for technique '{technique_name}'")
        return session_id

    def process_frame(
        self,
        frame: np.ndarray,
        target_technique: Optional[str] = None
    ) -> Tuple[np.ndarray, Optional[CorrectionFeedback]]:
        """
        Process a single frame and return annotated frame + feedback

        Args:
            frame: RGB frame from camera
            target_technique: If provided, use this technique (else auto-detect)

        Returns:
            (annotated_frame, feedback) tuple
        """
        start_time = time.time()

        # Convert to RGB (MediaPipe expects RGB)
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        # Extract pose
        results = self.pose.process(frame_rgb)

        if not results.pose_landmarks:
            # No person detected
            annotated = self._draw_no_person_message(frame)
            return annotated, None

        # Convert landmarks to dict format
        current_landmarks = self._landmarks_to_dict(results.pose_landmarks)

        # Identify technique (or use provided)
        if target_technique:
            technique_name = target_technique
        else:
            technique_name = self.pose_matcher.identify_technique(current_landmarks)

        if technique_name == 'unknown':
            annotated = self._draw_unknown_technique_message(frame, results.pose_landmarks)
            return annotated, None

        # Get ideal pose
        ideal_pose = self.pose_matcher.get_ideal_pose(technique_name)
        if not ideal_pose:
            annotated = self._draw_no_ideal_pose_message(frame, results.pose_landmarks)
            return annotated, None

        ideal_landmarks = ideal_pose.get('ideal_landmarks', {})

        # Calculate deviations
        deviations = self.deviation_analyzer.calculate_deviations(
            current_landmarks, ideal_landmarks
        )

        # Generate feedback
        feedback = self.feedback_generator.generate_feedback(
            technique_name, deviations
        )

        # Draw annotated frame
        annotated = self._draw_corrections(
            frame, results.pose_landmarks, feedback
        )

        # Update session
        if self.current_session and self.enable_progress_tracking:
            self._update_session(feedback)

        # Calculate FPS
        processing_time = time.time() - start_time
        self.fps = 1.0 / processing_time if processing_time > 0 else 0
        self.frame_count += 1

        # Add feedback to history
        self.feedback_history.append(feedback)

        return annotated, feedback

    def _landmarks_to_dict(self, pose_landmarks) -> Dict[str, Tuple[float, float, float]]:
        """Convert MediaPipe landmarks to dict format"""
        landmark_dict = {}

        landmark_names = {
            11: 'left_shoulder',
            12: 'right_shoulder',
            13: 'left_elbow',
            14: 'right_elbow',
            15: 'left_wrist',
            16: 'right_wrist',
            23: 'left_hip',
            24: 'right_hip',
            25: 'left_knee',
            26: 'right_knee',
            27: 'left_ankle',
            28: 'right_ankle'
        }

        for idx, name in landmark_names.items():
            lm = pose_landmarks.landmark[idx]
            landmark_dict[name] = (lm.x, lm.y, lm.z)

        return landmark_dict

    def _draw_corrections(
        self,
        frame: np.ndarray,
        pose_landmarks,
        feedback: CorrectionFeedback
    ) -> np.ndarray:
        """Draw corrections overlay on frame"""
        annotated = frame.copy()
        h, w = annotated.shape[:2]

        # Draw skeleton
        mp.solutions.drawing_utils.draw_landmarks(
            annotated,
            pose_landmarks,
            self.mp_pose.POSE_CONNECTIONS,
            landmark_drawing_spec=mp.solutions.drawing_styles.get_default_pose_landmarks_style()
        )

        # Draw feedback text
        y_offset = 30

        # Score
        score_color = (0, 255, 0) if feedback.overall_score >= 80 else \
                      (0, 255, 255) if feedback.overall_score >= 60 else \
                      (0, 165, 255) if feedback.overall_score >= 40 else \
                      (0, 0, 255)

        cv2.putText(
            annotated,
            f"Score: {feedback.overall_score:.1f}/100",
            (10, y_offset),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            score_color,
            2
        )
        y_offset += 35

        # Technique
        cv2.putText(
            annotated,
            f"Technique: {feedback.technique_name}",
            (10, y_offset),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (255, 255, 255),
            2
        )
        y_offset += 35

        # Top errors
        cv2.putText(
            annotated,
            "Correzioni:",
            (10, y_offset),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (255, 255, 0),
            2
        )
        y_offset += 30

        for i, error in enumerate(feedback.top_errors[:3], 1):
            # Truncate long errors
            if len(error) > 50:
                error = error[:47] + "..."

            cv2.putText(
                annotated,
                f"{i}. {error}",
                (10, y_offset),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                (255, 255, 255),
                1
            )
            y_offset += 25

        # FPS
        cv2.putText(
            annotated,
            f"FPS: {self.fps:.1f}",
            (w - 120, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.6,
            (0, 255, 0),
            2
        )

        return annotated

    def _draw_no_person_message(self, frame: np.ndarray) -> np.ndarray:
        """Draw message when no person detected"""
        annotated = frame.copy()
        h, w = annotated.shape[:2]

        cv2.putText(
            annotated,
            "Nessuna persona rilevata",
            (w // 2 - 200, h // 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.0,
            (0, 0, 255),
            2
        )

        return annotated

    def _draw_unknown_technique_message(self, frame: np.ndarray, pose_landmarks) -> np.ndarray:
        """Draw message when technique not recognized"""
        annotated = frame.copy()

        # Draw skeleton
        mp.solutions.drawing_utils.draw_landmarks(
            annotated,
            pose_landmarks,
            self.mp_pose.POSE_CONNECTIONS
        )

        cv2.putText(
            annotated,
            "Tecnica non riconosciuta - inizia movimento",
            (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (0, 255, 255),
            2
        )

        return annotated

    def _draw_no_ideal_pose_message(self, frame: np.ndarray, pose_landmarks) -> np.ndarray:
        """Draw message when ideal pose not found"""
        annotated = frame.copy()

        # Draw skeleton
        mp.solutions.drawing_utils.draw_landmarks(
            annotated,
            pose_landmarks,
            self.mp_pose.POSE_CONNECTIONS
        )

        cv2.putText(
            annotated,
            "Pose ideale non disponibile",
            (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (0, 165, 255),
            2
        )

        return annotated

    def _update_session(self, feedback: CorrectionFeedback):
        """Update current session with new feedback"""
        if not self.current_session:
            return

        self.current_session.total_frames += 1
        self.current_session.corrections_history.append(feedback)

        # Update average score
        scores = [f.overall_score for f in self.current_session.corrections_history]
        self.current_session.average_score = np.mean(scores)

        # Detect improvements
        if len(scores) >= 10:
            recent_avg = np.mean(scores[-10:])
            early_avg = np.mean(scores[:10])

            if recent_avg > early_avg + 10:
                improvement = f"Miglioramento di {recent_avg - early_avg:.1f} punti"
                if improvement not in self.current_session.improvements:
                    self.current_session.improvements.append(improvement)

    def end_session(self) -> Optional[ProgressSession]:
        """End current session and return summary"""
        if not self.current_session:
            return None

        self.current_session.end_time = datetime.now()

        logger.info(f"Session {self.current_session.session_id} ended")
        logger.info(f"  Duration: {self.current_session.end_time - self.current_session.start_time}")
        logger.info(f"  Frames: {self.current_session.total_frames}")
        logger.info(f"  Avg Score: {self.current_session.average_score:.1f}")
        logger.info(f"  Improvements: {len(self.current_session.improvements)}")

        session = self.current_session
        self.current_session = None

        return session

    def run_camera_loop(
        self,
        camera_index: int = 0,
        target_technique: Optional[str] = None,
        window_name: str = "Real-Time Pose Correction"
    ):
        """
        Run main camera loop with live correction

        Args:
            camera_index: Camera device index (0 = default webcam)
            target_technique: If provided, correct for this technique
            window_name: OpenCV window name
        """
        # Open camera
        cap = cv2.VideoCapture(camera_index)

        if not cap.isOpened():
            logger.error(f"Failed to open camera {camera_index}")
            return

        # Set resolution (720p for performance)
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        cap.set(cv2.CAP_PROP_FPS, 30)

        logger.info("Camera opened successfully")
        logger.info("Press 'q' to quit, 's' to start session, 'e' to end session")

        self.is_running = True

        try:
            while self.is_running:
                ret, frame = cap.read()

                if not ret:
                    logger.warning("Failed to capture frame")
                    break

                # Process frame
                annotated, feedback = self.process_frame(frame, target_technique)

                # Show frame
                cv2.imshow(window_name, annotated)

                # Handle keyboard
                key = cv2.waitKey(1) & 0xFF

                if key == ord('q'):
                    logger.info("Quit requested")
                    break
                elif key == ord('s'):
                    tech = target_technique if target_technique else 'auto-detect'
                    self.start_session(tech)
                    logger.info("Session started")
                elif key == ord('e'):
                    session = self.end_session()
                    if session:
                        logger.info("Session ended successfully")

        finally:
            cap.release()
            cv2.destroyAllWindows()
            self.pose.close()
            logger.info("Camera loop ended")

    def cleanup(self):
        """Cleanup resources"""
        self.is_running = False
        if self.pose:
            self.pose.close()
        logger.info("RealtimePoseCorrector cleaned up")


# ==================== STANDALONE EXECUTION ====================

def main():
    """Main entry point for standalone testing"""
    import argparse

    parser = argparse.ArgumentParser(description="Real-Time Pose Correction System")
    parser.add_argument('--camera', type=int, default=0, help='Camera index (default: 0)')
    parser.add_argument('--technique', type=str, default=None,
                       help='Target technique (punch/stance/kick, default: auto-detect)')
    parser.add_argument('--knowledge-base', type=str, default=None,
                       help='Path to knowledge base JSON')

    args = parser.parse_args()

    # Initialize corrector
    knowledge_base_path = Path(args.knowledge_base) if args.knowledge_base else None

    corrector = RealtimePoseCorrector(
        knowledge_base_path=knowledge_base_path,
        enable_audio=False,  # TODO: Implement TTS
        enable_progress_tracking=True
    )

    # Load knowledge base
    corrector.pose_matcher.load_knowledge_base()

    # Run camera loop
    try:
        corrector.run_camera_loop(
            camera_index=args.camera,
            target_technique=args.technique
        )
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        corrector.cleanup()


if __name__ == '__main__':
    main()

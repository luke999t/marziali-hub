"""
AR Quick Demo - Augmented Reality Style Overlay
================================================

🎯 BUSINESS VALUE:
- Wow factor per marketing/demo
- Preview AR experience senza hardware speciale
- Works con webcam standard
- Foundation per full AR integration

🔧 TECHNICAL:
- OpenCV-based "AR-style" overlay
- Real-time pose comparison visualization
- Ideal skeleton overlay (semi-transparent)
- Visual correction arrows
- 3D-like rendering effects

📊 METRICS:
- FPS: 30fps target
- Latency: <100ms
- Visual clarity: overlay contrast optimized

🏗️ ARCHITECTURE:
- INPUT: webcam frame
- PROCESS: pose extraction → ideal overlay → correction arrows
- OUTPUT: AR-style annotated frame
- DEPENDENCIES: realtime_pose_corrector.py, OpenCV
"""

import cv2
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging
from pathlib import Path
import time

# Import real-time corrector components
from realtime_pose_corrector import (
    RealtimePoseCorrector,
    IdealPoseMatcher,
    PoseDeviationAnalyzer
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AROverlayRenderer:
    """
    Render AR-style overlay con skeleton ideale e correzioni

    🎯 RENDERING:
    - Current skeleton: verde (pose attuale)
    - Ideal skeleton: blu semi-trasparente (target)
    - Deviations: frecce rosse (correzioni)
    - Score: HUD style (top-right)
    - Tips: tooltip style (bottom)
    """

    # Colors (BGR format for OpenCV)
    COLOR_CURRENT_SKELETON = (0, 255, 0)  # Green
    COLOR_IDEAL_SKELETON = (255, 0, 0)  # Blue
    COLOR_DEVIATION_ARROW = (0, 0, 255)  # Red
    COLOR_GOOD = (0, 255, 0)  # Green
    COLOR_WARNING = (0, 165, 255)  # Orange
    COLOR_CRITICAL = (0, 0, 255)  # Red
    COLOR_HUD_BG = (0, 0, 0)  # Black
    COLOR_TEXT = (255, 255, 255)  # White

    def __init__(self, alpha_ideal: float = 0.5):
        """
        Args:
            alpha_ideal: Transparency for ideal skeleton overlay (0-1)
        """
        self.alpha_ideal = alpha_ideal
        logger.info("AROverlayRenderer initialized")

    def render_ar_frame(
        self,
        frame: np.ndarray,
        current_landmarks: Dict[str, Tuple[float, float, float]],
        ideal_landmarks: Optional[Dict[str, Tuple[float, float, float]]],
        deviations: List,
        score: float,
        technique_name: str
    ) -> np.ndarray:
        """
        Render complete AR overlay

        Args:
            frame: Input video frame
            current_landmarks: Current pose landmarks
            ideal_landmarks: Ideal pose landmarks
            deviations: List of PoseDeviation objects
            score: Overall score (0-100)
            technique_name: Current technique name

        Returns:
            AR-annotated frame
        """
        h, w = frame.shape[:2]
        output = frame.copy()

        # Create overlay layer for transparency effects
        overlay = np.zeros_like(output)

        # 1. Draw ideal skeleton (semi-transparent blue)
        if ideal_landmarks:
            self._draw_skeleton(overlay, ideal_landmarks, self.COLOR_IDEAL_SKELETON, h, w)

            # Blend with alpha
            cv2.addWeighted(output, 1.0, overlay, self.alpha_ideal, 0, output)

        # 2. Draw current skeleton (solid green)
        self._draw_skeleton(output, current_landmarks, self.COLOR_CURRENT_SKELETON, h, w)

        # 3. Draw deviation arrows
        if ideal_landmarks:
            self._draw_deviation_arrows(output, current_landmarks, ideal_landmarks, deviations, h, w)

        # 4. Draw HUD (score, technique, tips)
        self._draw_hud(output, score, technique_name, deviations[:3], w, h)

        # 5. Add AR grid effect (optional)
        self._add_ar_grid_effect(output, h, w)

        return output

    def _draw_skeleton(
        self,
        frame: np.ndarray,
        landmarks: Dict[str, Tuple[float, float, float]],
        color: Tuple[int, int, int],
        h: int,
        w: int
    ):
        """Draw skeleton on frame"""
        # Define connections
        connections = [
            ('left_shoulder', 'right_shoulder'),
            ('left_shoulder', 'left_elbow'),
            ('left_elbow', 'left_wrist'),
            ('right_shoulder', 'right_elbow'),
            ('right_elbow', 'right_wrist'),
            ('left_hip', 'right_hip'),
            ('left_shoulder', 'left_hip'),
            ('right_shoulder', 'right_hip'),
            ('left_hip', 'left_knee'),
            ('left_knee', 'left_ankle'),
            ('right_hip', 'right_knee'),
            ('right_knee', 'right_ankle')
        ]

        # Draw connections (lines)
        for start_name, end_name in connections:
            if start_name in landmarks and end_name in landmarks:
                start = landmarks[start_name]
                end = landmarks[end_name]

                # Convert normalized to pixel coordinates
                start_px = (int(start[0] * w), int(start[1] * h))
                end_px = (int(end[0] * w), int(end[1] * h))

                cv2.line(frame, start_px, end_px, color, 2)

        # Draw joints (circles)
        for name, (x, y, z) in landmarks.items():
            px = (int(x * w), int(y * h))
            cv2.circle(frame, px, 5, color, -1)

    def _draw_deviation_arrows(
        self,
        frame: np.ndarray,
        current_landmarks: Dict,
        ideal_landmarks: Dict,
        deviations: List,
        h: int,
        w: int
    ):
        """Draw arrows showing corrections"""
        # Draw only top 3 most important deviations
        top_deviations = sorted(deviations, key=lambda d: d.priority, reverse=True)[:3]

        for deviation in top_deviations:
            landmark_name = deviation.landmark_name

            if landmark_name not in current_landmarks or landmark_name not in ideal_landmarks:
                continue

            current_pos = current_landmarks[landmark_name]
            ideal_pos = ideal_landmarks[landmark_name]

            # Convert to pixel coordinates
            current_px = (int(current_pos[0] * w), int(current_pos[1] * h))
            ideal_px = (int(ideal_pos[0] * w), int(ideal_pos[1] * h))

            # Draw arrow from current to ideal
            color = self._get_severity_color(deviation.severity)
            cv2.arrowedLine(frame, current_px, ideal_px, color, 2, tipLength=0.3)

            # Draw label
            label = deviation.landmark_name.replace('_', ' ').title()
            cv2.putText(
                frame,
                label,
                (current_px[0] + 10, current_px[1] - 10),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.4,
                color,
                1
            )

    def _get_severity_color(self, severity: str) -> Tuple[int, int, int]:
        """Get color based on severity"""
        if severity == 'critical':
            return self.COLOR_CRITICAL
        elif severity == 'high':
            return self.COLOR_CRITICAL
        elif severity == 'medium':
            return self.COLOR_WARNING
        else:
            return self.COLOR_GOOD

    def _draw_hud(
        self,
        frame: np.ndarray,
        score: float,
        technique_name: str,
        top_deviations: List,
        w: int,
        h: int
    ):
        """Draw heads-up display"""
        # Top-right: Score and technique
        hud_w = 300
        hud_h = 120
        hud_x = w - hud_w - 20
        hud_y = 20

        # Semi-transparent background
        overlay = frame.copy()
        cv2.rectangle(overlay, (hud_x, hud_y), (hud_x + hud_w, hud_y + hud_h), self.COLOR_HUD_BG, -1)
        cv2.addWeighted(overlay, 0.7, frame, 0.3, 0, frame)

        # Score bar
        score_color = self.COLOR_GOOD if score >= 80 else \
                      self.COLOR_WARNING if score >= 60 else \
                      self.COLOR_CRITICAL

        cv2.putText(
            frame,
            f"Score: {score:.1f}/100",
            (hud_x + 10, hud_y + 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            self.COLOR_TEXT,
            2
        )

        # Score progress bar
        bar_x = hud_x + 10
        bar_y = hud_y + 45
        bar_w = hud_w - 20
        bar_h = 20

        cv2.rectangle(frame, (bar_x, bar_y), (bar_x + bar_w, bar_y + bar_h), self.COLOR_TEXT, 1)
        fill_w = int((score / 100) * bar_w)
        cv2.rectangle(frame, (bar_x, bar_y), (bar_x + fill_w, bar_y + bar_h), score_color, -1)

        # Technique name
        cv2.putText(
            frame,
            f"Technique: {technique_name}",
            (hud_x + 10, hud_y + 85),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            self.COLOR_TEXT,
            1
        )

        # Bottom: Top corrections tooltip
        if top_deviations:
            tooltip_h = len(top_deviations) * 25 + 40
            tooltip_y = h - tooltip_h - 20

            # Background
            overlay = frame.copy()
            cv2.rectangle(overlay, (20, tooltip_y), (w - 20, h - 20), self.COLOR_HUD_BG, -1)
            cv2.addWeighted(overlay, 0.7, frame, 0.3, 0, frame)

            # Title
            cv2.putText(
                frame,
                "Corrections:",
                (30, tooltip_y + 25),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.6,
                self.COLOR_WARNING,
                2
            )

            # List corrections
            for i, deviation in enumerate(top_deviations):
                text = f"{i+1}. {deviation.correction_text}"
                if len(text) > 70:
                    text = text[:67] + "..."

                y = tooltip_y + 50 + i * 25
                cv2.putText(
                    frame,
                    text,
                    (40, y),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.5,
                    self.COLOR_TEXT,
                    1
                )

    def _add_ar_grid_effect(self, frame: np.ndarray, h: int, w: int):
        """Add subtle AR grid effect for aesthetic"""
        # Draw corner markers (AR style)
        corner_size = 30
        corners = [
            (20, 20),  # Top-left
            (w - corner_size - 20, 20),  # Top-right
            (20, h - corner_size - 20),  # Bottom-left
            (w - corner_size - 20, h - corner_size - 20)  # Bottom-right
        ]

        for x, y in corners:
            # L-shaped corner markers
            cv2.line(frame, (x, y), (x + corner_size, y), self.COLOR_IDEAL_SKELETON, 2)
            cv2.line(frame, (x, y), (x, y + corner_size), self.COLOR_IDEAL_SKELETON, 2)


class ARQuickDemo:
    """
    Main AR Quick Demo application

    🎯 DEMO FEATURES:
    - Real-time AR-style overlay
    - Ideal pose visualization
    - Visual correction feedback
    - HUD with score and tips
    - Webcam-based (no special hardware)
    """

    def __init__(
        self,
        knowledge_base_path: Optional[Path] = None,
        camera_index: int = 0
    ):
        """
        Args:
            knowledge_base_path: Path to knowledge base
            camera_index: Camera device index
        """
        self.knowledge_base_path = knowledge_base_path
        self.camera_index = camera_index

        # Components
        self.corrector = RealtimePoseCorrector(
            knowledge_base_path=knowledge_base_path,
            enable_audio=False,
            enable_progress_tracking=False
        )

        self.renderer = AROverlayRenderer(alpha_ideal=0.4)

        # Load knowledge base
        if knowledge_base_path:
            self.corrector.pose_matcher.load_knowledge_base()
        else:
            # Load built-in templates
            self.corrector.pose_matcher._load_builtin_templates()

        # Stats
        self.fps = 0
        self.frame_count = 0

        logger.info("ARQuickDemo initialized")

    def run_demo(
        self,
        target_technique: Optional[str] = None,
        window_name: str = "AR Martial Arts Demo"
    ):
        """
        Run AR demo loop

        Args:
            target_technique: Target technique (or auto-detect)
            window_name: OpenCV window name
        """
        # Open camera
        cap = cv2.VideoCapture(self.camera_index)

        if not cap.isOpened():
            logger.error(f"Failed to open camera {self.camera_index}")
            return

        # Set resolution
        cap.set(cv2.CAP_PROP_FRAME_WIDTH, 1280)
        cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 720)
        cap.set(cv2.CAP_PROP_FPS, 30)

        logger.info("AR Demo started")
        logger.info("Controls:")
        logger.info("  'q' - Quit")
        logger.info("  'p' - Change to punch technique")
        logger.info("  's' - Change to stance technique")
        logger.info("  'k' - Change to kick technique")
        logger.info("  'a' - Auto-detect technique")

        current_technique = target_technique

        try:
            while True:
                ret, frame = cap.read()

                if not ret:
                    logger.warning("Failed to capture frame")
                    break

                start_time = time.time()

                # Process frame (get AR data)
                ar_frame = self._process_ar_frame(frame, current_technique)

                # Calculate FPS
                elapsed = time.time() - start_time
                self.fps = 1.0 / elapsed if elapsed > 0 else 0
                self.frame_count += 1

                # Add FPS to frame
                cv2.putText(
                    ar_frame,
                    f"FPS: {self.fps:.1f}",
                    (10, 30),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.7,
                    (0, 255, 0),
                    2
                )

                # Show frame
                cv2.imshow(window_name, ar_frame)

                # Handle keyboard
                key = cv2.waitKey(1) & 0xFF

                if key == ord('q'):
                    logger.info("Quit requested")
                    break
                elif key == ord('p'):
                    current_technique = 'basic_punch'
                    logger.info("Changed to punch technique")
                elif key == ord('s'):
                    current_technique = 'horse_stance'
                    logger.info("Changed to stance technique")
                elif key == ord('k'):
                    current_technique = 'front_kick'
                    logger.info("Changed to kick technique")
                elif key == ord('a'):
                    current_technique = None
                    logger.info("Auto-detect mode")

        finally:
            cap.release()
            cv2.destroyAllWindows()
            self.corrector.cleanup()
            logger.info("AR Demo ended")

    def _process_ar_frame(
        self,
        frame: np.ndarray,
        target_technique: Optional[str]
    ) -> np.ndarray:
        """Process frame and generate AR overlay"""
        # Convert to RGB for MediaPipe
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        # Extract pose
        results = self.corrector.pose.process(frame_rgb)

        if not results.pose_landmarks:
            # No person detected
            return self._draw_no_person_message(frame)

        # Get current landmarks
        current_landmarks = self.corrector._landmarks_to_dict(results.pose_landmarks)

        # Identify technique
        if target_technique:
            technique_name = target_technique
        else:
            technique_name = self.corrector.pose_matcher.identify_technique(current_landmarks)

        if technique_name == 'unknown':
            return self._draw_unknown_technique(frame, results.pose_landmarks)

        # Get ideal pose
        ideal_pose = self.corrector.pose_matcher.get_ideal_pose(technique_name)

        if not ideal_pose:
            return self._draw_no_ideal_pose(frame, results.pose_landmarks)

        ideal_landmarks = ideal_pose.get('ideal_landmarks', {})

        # Calculate deviations
        deviations = self.corrector.deviation_analyzer.calculate_deviations(
            current_landmarks, ideal_landmarks
        )

        # Generate feedback
        feedback = self.corrector.feedback_generator.generate_feedback(
            technique_name, deviations
        )

        # Render AR overlay
        ar_frame = self.renderer.render_ar_frame(
            frame,
            current_landmarks,
            ideal_landmarks,
            deviations,
            feedback.overall_score,
            technique_name
        )

        return ar_frame

    def _draw_no_person_message(self, frame: np.ndarray) -> np.ndarray:
        """Draw message when no person detected"""
        h, w = frame.shape[:2]

        cv2.putText(
            frame,
            "No person detected",
            (w // 2 - 150, h // 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.0,
            (0, 0, 255),
            2
        )

        cv2.putText(
            frame,
            "Stand in front of camera",
            (w // 2 - 180, h // 2 + 40),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.8,
            (255, 255, 255),
            2
        )

        return frame

    def _draw_unknown_technique(self, frame: np.ndarray, pose_landmarks) -> np.ndarray:
        """Draw message when technique not recognized"""
        import mediapipe as mp

        # Draw skeleton
        mp.solutions.drawing_utils.draw_landmarks(
            frame,
            pose_landmarks,
            self.corrector.mp_pose.POSE_CONNECTIONS
        )

        h, w = frame.shape[:2]

        cv2.putText(
            frame,
            "Technique not recognized",
            (w // 2 - 200, h // 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.0,
            (0, 255, 255),
            2
        )

        cv2.putText(
            frame,
            "Press: P=Punch, S=Stance, K=Kick",
            (w // 2 - 250, h // 2 + 40),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (255, 255, 255),
            2
        )

        return frame

    def _draw_no_ideal_pose(self, frame: np.ndarray, pose_landmarks) -> np.ndarray:
        """Draw message when ideal pose not found"""
        import mediapipe as mp

        # Draw skeleton
        mp.solutions.drawing_utils.draw_landmarks(
            frame,
            pose_landmarks,
            self.corrector.mp_pose.POSE_CONNECTIONS
        )

        h, w = frame.shape[:2]

        cv2.putText(
            frame,
            "Ideal pose not available",
            (w // 2 - 200, h // 2),
            cv2.FONT_HERSHEY_SIMPLEX,
            1.0,
            (0, 165, 255),
            2
        )

        return frame


# ==================== STANDALONE EXECUTION ====================

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description="AR Quick Demo for Martial Arts")
    parser.add_argument('--camera', type=int, default=0, help='Camera index')
    parser.add_argument('--technique', type=str, default=None,
                       choices=['basic_punch', 'horse_stance', 'front_kick'],
                       help='Target technique (auto-detect if not specified)')
    parser.add_argument('--knowledge-base', type=str, default=None,
                       help='Path to knowledge base JSON')

    args = parser.parse_args()

    # Initialize demo
    kb_path = Path(args.knowledge_base) if args.knowledge_base else None

    demo = ARQuickDemo(
        knowledge_base_path=kb_path,
        camera_index=args.camera
    )

    # Run demo
    try:
        demo.run_demo(target_technique=args.technique)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception(f"Error in demo: {e}")


if __name__ == '__main__':
    main()

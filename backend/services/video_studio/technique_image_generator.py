"""
Technique Image Generator - Movement Arrows Visualization

AI_MODULE: technique_image_generator
AI_DESCRIPTION: Generate static images of martial arts techniques with directional arrows
AI_BUSINESS: Visual teaching aids - show movement direction in technique snapshots
AI_TEACHING: OpenCV image processing + MediaPipe skeleton + vector math for directions

ALTERNATIVE_VALUTATE:
- Manual drawing: Time-consuming, not scalable
- 3D rendering: Complex, requires 3D models
- Video overlay only: Loses static reference value

PERCHE_QUESTA_SOLUZIONE:
- Extract keyframes from video at critical moments
- Use skeleton data to calculate movement vectors
- Draw intuitive colored arrows on images
- Output: PNG images ready for teaching materials

DEPENDENCIES:
- opencv-python: Image/video processing
- numpy: Array math for vectors
- Pillow: Image enhancement
- mediapipe: Skeleton detection (if not pre-extracted)

LIMITAZIONI_NOTE:
- Requires good video quality for accurate skeleton
- Arrow positioning depends on skeleton accuracy
- Fast movements may blur keyframes

METRICHE_SUCCESSO:
- Arrow direction accuracy: >90% match visual movement
- Processing time: <5s per technique image
- Output quality: 1080p PNG with clear arrows
"""

import cv2
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
import logging
import json
import math

# Try MediaPipe for skeleton detection
try:
    import mediapipe as mp
    MEDIAPIPE_AVAILABLE = True
except ImportError:
    MEDIAPIPE_AVAILABLE = False
    logging.warning("MediaPipe not available. Install with: pip install mediapipe")

# Try Pillow for image enhancement
try:
    from PIL import Image, ImageDraw, ImageFont
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    logging.warning("Pillow not available. Install with: pip install Pillow")

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class MovementVector:
    """
    Vector representing movement of a body joint.

    Attributes:
        joint_name: Name of the joint (e.g., "left_wrist", "right_ankle")
        start_pos: Starting position (x, y) in normalized coordinates [0-1]
        end_pos: Ending position (x, y) in normalized coordinates [0-1]
        dx: Horizontal displacement
        dy: Vertical displacement
        magnitude: Length of movement vector
        direction: Human-readable direction (e.g., "forward", "up-left")
        confidence: Detection confidence [0-1]
    """
    joint_name: str
    start_pos: Tuple[float, float]
    end_pos: Tuple[float, float]
    dx: float
    dy: float
    magnitude: float
    direction: str
    confidence: float


@dataclass
class ArrowStyle:
    """
    Configuration for arrow drawing style.

    Styles:
    - default: Standard colored arrows by body part
    - minimal: Thin arrows, less intrusive
    - detailed: Thick arrows with labels
    """
    name: str
    arrow_thickness: int
    arrow_tip_length: float
    min_magnitude: float  # Minimum movement to show arrow
    show_labels: bool
    colors: Dict[str, Tuple[int, int, int]]  # BGR colors by body region


# =============================================================================
# ARROW STYLE PRESETS
# =============================================================================

ARROW_STYLES = {
    "default": ArrowStyle(
        name="default",
        arrow_thickness=3,
        arrow_tip_length=0.3,
        min_magnitude=0.02,  # 2% of frame size
        show_labels=False,
        colors={
            "arms": (0, 0, 255),      # Red - BGR
            "legs": (255, 0, 0),      # Blue - BGR
            "torso": (0, 255, 0),     # Green - BGR
            "head": (255, 255, 0),    # Cyan - BGR
            "hands": (0, 165, 255),   # Orange - BGR
            "feet": (255, 0, 255),    # Magenta - BGR
        }
    ),
    "minimal": ArrowStyle(
        name="minimal",
        arrow_thickness=2,
        arrow_tip_length=0.2,
        min_magnitude=0.03,
        show_labels=False,
        colors={
            "arms": (100, 100, 255),
            "legs": (255, 100, 100),
            "torso": (100, 255, 100),
            "head": (200, 200, 100),
            "hands": (100, 200, 255),
            "feet": (200, 100, 200),
        }
    ),
    "detailed": ArrowStyle(
        name="detailed",
        arrow_thickness=4,
        arrow_tip_length=0.4,
        min_magnitude=0.01,
        show_labels=True,
        colors={
            "arms": (0, 0, 200),
            "legs": (200, 0, 0),
            "torso": (0, 200, 0),
            "head": (200, 200, 0),
            "hands": (0, 150, 200),
            "feet": (200, 0, 200),
        }
    )
}

# Joint to body region mapping (MediaPipe pose landmarks)
JOINT_REGIONS = {
    # Arms
    "left_shoulder": "arms",
    "right_shoulder": "arms",
    "left_elbow": "arms",
    "right_elbow": "arms",
    "left_wrist": "hands",
    "right_wrist": "hands",
    # Legs
    "left_hip": "legs",
    "right_hip": "legs",
    "left_knee": "legs",
    "right_knee": "legs",
    "left_ankle": "feet",
    "right_ankle": "feet",
    # Torso
    "nose": "head",
    "left_eye": "head",
    "right_eye": "head",
}

# MediaPipe landmark indices (subset for martial arts)
MEDIAPIPE_LANDMARKS = {
    0: "nose",
    11: "left_shoulder",
    12: "right_shoulder",
    13: "left_elbow",
    14: "right_elbow",
    15: "left_wrist",
    16: "right_wrist",
    23: "left_hip",
    24: "right_hip",
    25: "left_knee",
    26: "right_knee",
    27: "left_ankle",
    28: "right_ankle",
}


# =============================================================================
# MAIN CLASS
# =============================================================================

class TechniqueImageGenerator:
    """
    Generate technique images with movement arrows.

    WORKFLOW:
    1. Load video or skeleton data
    2. Extract keyframes at critical moments
    3. Calculate movement vectors between frames
    4. Draw colored arrows showing direction
    5. Save annotated images

    BUSINESS VALUE:
    - Teaching materials with visual movement guides
    - Technique documentation
    - Student feedback with visual direction cues
    """

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        default_style: str = "default"
    ):
        """
        Initialize the technique image generator.

        Args:
            output_dir: Directory for output images (created if not exists)
            default_style: Default arrow style ("default", "minimal", "detailed")
        """
        self.output_dir = output_dir or Path("output/technique_images")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.default_style = default_style

        # Initialize MediaPipe if available
        self.pose_detector = None
        if MEDIAPIPE_AVAILABLE:
            self.mp_pose = mp.solutions.pose
            self.pose_detector = self.mp_pose.Pose(
                static_image_mode=False,
                model_complexity=1,
                min_detection_confidence=0.5,
                min_tracking_confidence=0.5
            )
            logger.info("MediaPipe pose detector initialized")
        else:
            logger.warning("MediaPipe not available - skeleton must be provided")

        logger.info(f"TechniqueImageGenerator initialized. Output: {self.output_dir}")

    # =========================================================================
    # KEYFRAME EXTRACTION
    # =========================================================================

    def extract_keyframes(
        self,
        video_path: Path,
        num_frames: int = 5,
        method: str = "uniform"
    ) -> List[np.ndarray]:
        """
        Extract keyframes from a video file.

        Extracts frames at critical moments of a technique:
        - Start position (setup)
        - Peak moments (maximum extension/rotation)
        - End position (recovery)

        Args:
            video_path: Path to video file
            num_frames: Number of keyframes to extract (default 5)
            method: Extraction method:
                - "uniform": Evenly spaced frames
                - "motion": Frames with maximum motion change
                - "custom": Use specific frame indices

        Returns:
            List of numpy arrays (BGR images)

        Example:
            >>> generator = TechniqueImageGenerator()
            >>> frames = generator.extract_keyframes("punch.mp4", num_frames=5)
            >>> len(frames)
            5
        """
        video_path = Path(video_path)
        if not video_path.exists():
            raise FileNotFoundError(f"Video not found: {video_path}")

        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)

        logger.info(f"Video: {video_path.name}, frames={total_frames}, fps={fps}")

        # Calculate frame indices based on method
        if method == "uniform":
            # Evenly distributed frames including first and last
            if num_frames == 1:
                frame_indices = [total_frames // 2]
            else:
                frame_indices = [
                    int(i * (total_frames - 1) / (num_frames - 1))
                    for i in range(num_frames)
                ]
        elif method == "motion":
            # Find frames with maximum motion change
            frame_indices = self._find_motion_keyframes(cap, num_frames, total_frames)
        else:
            # Default to uniform
            frame_indices = [
                int(i * (total_frames - 1) / (num_frames - 1))
                for i in range(num_frames)
            ]

        # Extract frames
        keyframes = []
        for idx in frame_indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if ret:
                keyframes.append(frame)
            else:
                logger.warning(f"Failed to read frame {idx}")

        cap.release()

        logger.info(f"Extracted {len(keyframes)} keyframes at indices: {frame_indices}")
        return keyframes

    def _find_motion_keyframes(
        self,
        cap: cv2.VideoCapture,
        num_frames: int,
        total_frames: int
    ) -> List[int]:
        """
        Find keyframes based on motion analysis.

        Uses optical flow or frame difference to identify moments
        of maximum movement change (peaks in motion graph).
        """
        # Calculate motion scores for each frame
        motion_scores = []
        prev_frame = None

        for i in range(total_frames):
            ret, frame = cap.read()
            if not ret:
                break

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

            if prev_frame is not None:
                # Frame difference as motion measure
                diff = cv2.absdiff(gray, prev_frame)
                score = np.mean(diff)
                motion_scores.append((i, score))

            prev_frame = gray

        # Reset video position
        cap.set(cv2.CAP_PROP_POS_FRAMES, 0)

        if not motion_scores:
            # Fallback to uniform
            return list(range(0, total_frames, total_frames // num_frames))[:num_frames]

        # Sort by motion score and select top frames
        motion_scores.sort(key=lambda x: x[1], reverse=True)

        # Take top scoring frames, evenly distributed
        top_indices = [x[0] for x in motion_scores[:num_frames * 3]]
        top_indices.sort()

        # Select evenly spaced from top motion frames
        if len(top_indices) >= num_frames:
            step = len(top_indices) // num_frames
            selected = [top_indices[i * step] for i in range(num_frames)]
        else:
            selected = top_indices

        return selected

    # =========================================================================
    # SKELETON DETECTION
    # =========================================================================

    def detect_skeleton(self, frame: np.ndarray) -> Optional[Dict[str, Any]]:
        """
        Detect skeleton/pose in a frame using MediaPipe.

        Args:
            frame: BGR image as numpy array

        Returns:
            Dictionary with joint positions and confidence scores:
            {
                "landmarks": {
                    "left_wrist": {"x": 0.5, "y": 0.3, "confidence": 0.95},
                    ...
                },
                "detected": True/False
            }
        """
        if not MEDIAPIPE_AVAILABLE or self.pose_detector is None:
            logger.warning("MediaPipe not available for skeleton detection")
            return None

        # Convert to RGB for MediaPipe
        rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        results = self.pose_detector.process(rgb_frame)

        if not results.pose_landmarks:
            return {"landmarks": {}, "detected": False}

        # Extract relevant landmarks
        landmarks = {}
        for idx, name in MEDIAPIPE_LANDMARKS.items():
            landmark = results.pose_landmarks.landmark[idx]
            landmarks[name] = {
                "x": landmark.x,
                "y": landmark.y,
                "z": landmark.z,
                "confidence": landmark.visibility
            }

        return {"landmarks": landmarks, "detected": True}

    # =========================================================================
    # MOVEMENT DETECTION
    # =========================================================================

    def detect_movement_direction(
        self,
        frame1: np.ndarray,
        frame2: np.ndarray,
        skeleton1: Optional[Dict] = None,
        skeleton2: Optional[Dict] = None
    ) -> Dict[str, MovementVector]:
        """
        Detect movement direction between two consecutive frames.

        Compares skeleton positions between frames to calculate
        movement vectors for each joint.

        Args:
            frame1: First frame (BGR image)
            frame2: Second frame (BGR image)
            skeleton1: Pre-extracted skeleton for frame1 (optional)
            skeleton2: Pre-extracted skeleton for frame2 (optional)

        Returns:
            Dictionary mapping joint names to MovementVector objects:
            {
                "left_wrist": MovementVector(
                    dx=0.15, dy=-0.08,
                    direction="forward-up",
                    magnitude=0.17,
                    ...
                ),
                ...
            }

        Example:
            >>> movements = generator.detect_movement_direction(frame1, frame2)
            >>> movements["left_wrist"].direction
            "forward-up"
        """
        # Detect skeletons if not provided
        if skeleton1 is None:
            skeleton1 = self.detect_skeleton(frame1)
        if skeleton2 is None:
            skeleton2 = self.detect_skeleton(frame2)

        if not skeleton1 or not skeleton2:
            logger.warning("Could not detect skeletons in one or both frames")
            return {}

        if not skeleton1.get("detected") or not skeleton2.get("detected"):
            logger.warning("Skeleton not detected in one or both frames")
            return {}

        movements = {}
        landmarks1 = skeleton1.get("landmarks", {})
        landmarks2 = skeleton2.get("landmarks", {})

        for joint_name in landmarks1:
            if joint_name not in landmarks2:
                continue

            l1 = landmarks1[joint_name]
            l2 = landmarks2[joint_name]

            # Calculate displacement
            dx = l2["x"] - l1["x"]
            dy = l2["y"] - l1["y"]

            # Calculate magnitude
            magnitude = math.sqrt(dx**2 + dy**2)

            # Determine direction
            direction = self._calculate_direction(dx, dy)

            # Average confidence
            confidence = (l1.get("confidence", 0) + l2.get("confidence", 0)) / 2

            movements[joint_name] = MovementVector(
                joint_name=joint_name,
                start_pos=(l1["x"], l1["y"]),
                end_pos=(l2["x"], l2["y"]),
                dx=dx,
                dy=dy,
                magnitude=magnitude,
                direction=direction,
                confidence=confidence
            )

        return movements

    def _calculate_direction(self, dx: float, dy: float) -> str:
        """
        Convert displacement to human-readable direction.

        Uses 8-way direction compass:
        - forward (right), backward (left)
        - up, down
        - combinations: forward-up, backward-down, etc.

        Note: In image coordinates, y increases downward!
        """
        # Threshold for considering movement significant
        threshold = 0.01

        h_dir = ""
        v_dir = ""

        # Horizontal direction (positive x = forward/right in video frame)
        if dx > threshold:
            h_dir = "forward"
        elif dx < -threshold:
            h_dir = "backward"

        # Vertical direction (positive y = down in image coordinates)
        if dy < -threshold:
            v_dir = "up"
        elif dy > threshold:
            v_dir = "down"

        if h_dir and v_dir:
            return f"{h_dir}-{v_dir}"
        elif h_dir:
            return h_dir
        elif v_dir:
            return v_dir
        else:
            return "stationary"

    # =========================================================================
    # ARROW DRAWING
    # =========================================================================

    def draw_movement_arrows(
        self,
        image: np.ndarray,
        skeleton: Dict,
        movements: Dict[str, MovementVector],
        style: str = "default",
        scale_factor: float = 3.0
    ) -> np.ndarray:
        """
        Draw colored arrows on an image showing movement direction.

        Arrows start from joint positions and point in movement direction.
        Colors indicate body region (red=arms, blue=legs, green=torso).

        Args:
            image: Input image (BGR)
            skeleton: Skeleton data with joint positions
            movements: Movement vectors from detect_movement_direction()
            style: Arrow style ("default", "minimal", "detailed")
            scale_factor: Arrow length multiplier (higher = longer arrows)

        Returns:
            Image with arrows drawn (BGR)

        Example:
            >>> annotated = generator.draw_movement_arrows(frame, skeleton, movements)
            >>> cv2.imwrite("technique_with_arrows.png", annotated)
        """
        # Get style configuration
        arrow_style = ARROW_STYLES.get(style, ARROW_STYLES["default"])

        # Create copy to draw on
        output = image.copy()
        h, w = output.shape[:2]

        landmarks = skeleton.get("landmarks", {})

        for joint_name, movement in movements.items():
            # Skip small movements
            if movement.magnitude < arrow_style.min_magnitude:
                continue

            # Skip low confidence detections
            if movement.confidence < 0.5:
                continue

            # Get start position (current joint location from skeleton)
            if joint_name not in landmarks:
                continue

            start_x = int(landmarks[joint_name]["x"] * w)
            start_y = int(landmarks[joint_name]["y"] * h)

            # Calculate arrow end point
            # Scale the movement vector for visibility
            arrow_dx = movement.dx * w * scale_factor
            arrow_dy = movement.dy * h * scale_factor

            end_x = int(start_x + arrow_dx)
            end_y = int(start_y + arrow_dy)

            # Get color based on body region
            region = JOINT_REGIONS.get(joint_name, "torso")
            color = arrow_style.colors.get(region, (255, 255, 255))

            # Draw arrow
            cv2.arrowedLine(
                output,
                (start_x, start_y),
                (end_x, end_y),
                color,
                arrow_style.arrow_thickness,
                tipLength=arrow_style.arrow_tip_length
            )

            # Draw joint circle
            cv2.circle(output, (start_x, start_y), 5, color, -1)

            # Add label if detailed style
            if arrow_style.show_labels:
                label = f"{joint_name}: {movement.direction}"
                cv2.putText(
                    output, label,
                    (end_x + 5, end_y),
                    cv2.FONT_HERSHEY_SIMPLEX,
                    0.4, color, 1
                )

        return output

    # =========================================================================
    # MAIN PIPELINE
    # =========================================================================

    def generate_technique_image(
        self,
        video_path: Path,
        output_path: Optional[Path] = None,
        options: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Generate a single technique image with movement arrows.

        Complete pipeline:
        1. Extract key frame (middle of technique)
        2. Extract frames before/after for movement calculation
        3. Detect skeleton and calculate movement
        4. Draw arrows and save image

        Args:
            video_path: Path to technique video
            output_path: Where to save output image (optional)
            options: Configuration options:
                - frame_index: Specific frame to annotate (default: middle)
                - style: Arrow style ("default", "minimal", "detailed")
                - scale_factor: Arrow length multiplier
                - frame_delta: Frames before/after for movement calc

        Returns:
            Dictionary with:
            - output_path: Path to generated image
            - movements: Movement data for each joint
            - metadata: Frame info, skeleton confidence, etc.

        Example:
            >>> result = generator.generate_technique_image("punch.mp4")
            >>> print(result["output_path"])
            "output/technique_images/punch_frame_50.png"
        """
        video_path = Path(video_path)
        options = options or {}

        style = options.get("style", self.default_style)
        scale_factor = options.get("scale_factor", 3.0)
        frame_delta = options.get("frame_delta", 3)  # Frames before/after

        # Open video
        cap = cv2.VideoCapture(str(video_path))
        if not cap.isOpened():
            raise ValueError(f"Cannot open video: {video_path}")

        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))

        # Determine frame index
        frame_index = options.get("frame_index", total_frames // 2)
        frame_index = max(frame_delta, min(frame_index, total_frames - frame_delta - 1))

        # Extract frames for movement analysis
        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index - frame_delta)
        ret1, frame_before = cap.read()

        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
        ret2, frame_current = cap.read()

        cap.set(cv2.CAP_PROP_POS_FRAMES, frame_index + frame_delta)
        ret3, frame_after = cap.read()

        cap.release()

        if not all([ret1, ret2, ret3]):
            raise ValueError("Failed to read frames from video")

        # Detect skeletons
        skeleton_before = self.detect_skeleton(frame_before)
        skeleton_current = self.detect_skeleton(frame_current)
        skeleton_after = self.detect_skeleton(frame_after)

        # Calculate movements (combine before->current and current->after)
        movements_in = self.detect_movement_direction(
            frame_before, frame_current,
            skeleton_before, skeleton_current
        )
        movements_out = self.detect_movement_direction(
            frame_current, frame_after,
            skeleton_current, skeleton_after
        )

        # Combine movements (use the larger magnitude for each joint)
        combined_movements = {}
        for joint in set(movements_in.keys()) | set(movements_out.keys()):
            m_in = movements_in.get(joint)
            m_out = movements_out.get(joint)

            if m_in and m_out:
                # Use the larger movement
                combined_movements[joint] = m_in if m_in.magnitude > m_out.magnitude else m_out
            elif m_in:
                combined_movements[joint] = m_in
            elif m_out:
                combined_movements[joint] = m_out

        # Draw arrows on current frame
        annotated_image = self.draw_movement_arrows(
            frame_current,
            skeleton_current or {"landmarks": {}},
            combined_movements,
            style=style,
            scale_factor=scale_factor
        )

        # Determine output path
        if output_path is None:
            output_path = self.output_dir / f"{video_path.stem}_frame_{frame_index}.png"
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Save image
        cv2.imwrite(str(output_path), annotated_image)
        logger.info(f"Generated technique image: {output_path}")

        # Prepare metadata
        movements_data = {}
        for joint, mv in combined_movements.items():
            movements_data[joint] = {
                "dx": mv.dx,
                "dy": mv.dy,
                "direction": mv.direction,
                "magnitude": mv.magnitude,
                "confidence": mv.confidence
            }

        return {
            "output_path": str(output_path),
            "movements": movements_data,
            "metadata": {
                "video_path": str(video_path),
                "frame_index": frame_index,
                "total_frames": total_frames,
                "style": style,
                "skeleton_detected": skeleton_current.get("detected", False) if skeleton_current else False,
                "joints_with_movement": len(combined_movements)
            }
        }

    def generate_transition_sequence(
        self,
        video_path: Path,
        output_dir: Optional[Path] = None,
        num_images: int = 5,
        style: str = "default"
    ) -> List[str]:
        """
        Generate a sequence of images showing technique transition.

        Creates N images from start to end of technique, each with
        arrows showing the movement at that moment.

        Args:
            video_path: Path to technique video
            output_dir: Directory for output images
            num_images: Number of images in sequence (default 5)
            style: Arrow style

        Returns:
            List of output image paths in sequence order

        Example:
            >>> paths = generator.generate_transition_sequence("punch.mp4", num_images=5)
            >>> paths
            ["punch_001.png", "punch_002.png", "punch_003.png", "punch_004.png", "punch_005.png"]
        """
        video_path = Path(video_path)
        output_dir = output_dir or self.output_dir / video_path.stem
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Extract keyframes
        keyframes = self.extract_keyframes(video_path, num_frames=num_images + 1)

        if len(keyframes) < 2:
            raise ValueError("Not enough frames extracted from video")

        output_paths = []

        for i in range(min(num_images, len(keyframes) - 1)):
            frame_current = keyframes[i]
            frame_next = keyframes[i + 1]

            # Detect skeletons
            skeleton_current = self.detect_skeleton(frame_current)
            skeleton_next = self.detect_skeleton(frame_next)

            # Calculate movements
            movements = self.detect_movement_direction(
                frame_current, frame_next,
                skeleton_current, skeleton_next
            )

            # Draw arrows
            annotated = self.draw_movement_arrows(
                frame_current,
                skeleton_current or {"landmarks": {}},
                movements,
                style=style
            )

            # Save image
            output_path = output_dir / f"{video_path.stem}_{i+1:03d}.png"
            cv2.imwrite(str(output_path), annotated)
            output_paths.append(str(output_path))

            logger.info(f"Generated sequence image {i+1}/{num_images}: {output_path}")

        return output_paths

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def close(self):
        """Release resources."""
        if self.pose_detector:
            self.pose_detector.close()
            logger.info("Pose detector closed")


# =============================================================================
# STANDALONE EXECUTION / QUICK TEST
# =============================================================================

def main():
    """
    Quick test of TechniqueImageGenerator.

    Creates a simple test video and generates technique images.
    """
    print("=" * 60)
    print("TechniqueImageGenerator - Quick Test")
    print("=" * 60)

    # Create test video with simple motion
    test_dir = Path("test_output")
    test_dir.mkdir(exist_ok=True)
    test_video = test_dir / "test_motion.mp4"

    print("\n1. Creating test video...")

    # Create a simple video with a moving circle (simulating movement)
    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    out = cv2.VideoWriter(str(test_video), fourcc, 30.0, (640, 480))

    for i in range(90):  # 3 seconds at 30fps
        frame = np.zeros((480, 640, 3), dtype=np.uint8)

        # Moving circle (punch motion simulation)
        x = 200 + int(i * 3)  # Moving right
        y = 240 + int(20 * math.sin(i * 0.1))  # Slight wave

        # Draw body (simplified)
        cv2.circle(frame, (320, 200), 30, (200, 200, 200), -1)  # Head
        cv2.line(frame, (320, 230), (320, 350), (200, 200, 200), 5)  # Torso
        cv2.line(frame, (320, 260), (x, y), (200, 200, 200), 5)  # Arm
        cv2.circle(frame, (x, y), 15, (255, 255, 255), -1)  # Fist

        out.write(frame)

    out.release()
    print(f"   Created: {test_video}")

    # Test the generator
    print("\n2. Testing TechniqueImageGenerator...")

    generator = TechniqueImageGenerator(output_dir=test_dir)

    # Test keyframe extraction
    print("\n   Extracting keyframes...")
    keyframes = generator.extract_keyframes(test_video, num_frames=5)
    print(f"   Extracted {len(keyframes)} keyframes")

    # Test single image generation (without skeleton - will fail gracefully)
    print("\n   Generating technique image...")
    try:
        result = generator.generate_technique_image(
            test_video,
            options={"style": "default"}
        )
        print(f"   Output: {result['output_path']}")
        print(f"   Movements detected: {result['metadata']['joints_with_movement']}")
    except Exception as e:
        print(f"   Note: {e}")
        print("   (This is expected if MediaPipe cannot detect skeleton in simple test video)")

    # Test sequence generation
    print("\n   Generating transition sequence...")
    try:
        paths = generator.generate_transition_sequence(
            test_video,
            num_images=3
        )
        print(f"   Generated {len(paths)} sequence images")
    except Exception as e:
        print(f"   Note: {e}")

    generator.close()

    print("\n" + "=" * 60)
    print("Test complete! Check 'test_output' directory for results.")
    print("=" * 60)


if __name__ == "__main__":
    main()

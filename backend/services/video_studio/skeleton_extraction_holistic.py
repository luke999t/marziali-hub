"""
🎓 AI_MODULE: MediaPipe Holistic Skeleton Extraction (75 Landmarks)
🎓 AI_DESCRIPTION: Estrae 75 landmarks (33 body + 21 left hand + 21 right hand)
🎓 AI_BUSINESS: Precision hand tracking per arti marziali (dita, pugni, aperture mano)
🎓 AI_TEACHING: Upgrade from Pose (33) to Holistic (75) for complete tracking

📊 LANDMARKS BREAKDOWN:
- 33 body landmarks (MediaPipe Pose):
  * 0-10: Face (nose, eyes, ears, mouth)
  * 11-16: Arms (shoulders, elbows, wrists)
  * 17-22: Hands connection points
  * 23-28: Legs (hips, knees, ankles)
  * 29-32: Feet (heels, toes)

- 21 left_hand landmarks:
  * 0: wrist
  * 1-4: thumb (CMC, MCP, IP, TIP)
  * 5-8: index (MCP, PIP, DIP, TIP)
  * 9-12: middle (MCP, PIP, DIP, TIP)
  * 13-16: ring (MCP, PIP, DIP, TIP)
  * 17-20: pinky (MCP, PIP, DIP, TIP)

- 21 right_hand landmarks (mirror of left)

🎯 WHY HOLISTIC:
- Martial arts need finger precision (fist formation, open palm)
- Detect hand tension/relaxation
- Track weapon grip (staff, sword)
- Analyze hand speed/power
"""

import cv2
import mediapipe as mp
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MediaPipe solutions
mp_holistic = mp.solutions.holistic
mp_drawing = mp.solutions.drawing_utils
mp_drawing_styles = mp.solutions.drawing_styles


@dataclass
class Landmark3D:
    """Single 3D landmark with confidence"""
    id: int
    x: float  # Normalized 0-1
    y: float  # Normalized 0-1
    z: float  # Depth (relative to body center)
    confidence: float  # Visibility/presence score


@dataclass
class FrameData:
    """Complete frame data with all landmarks"""
    index: int
    timestamp: float
    body: List[Landmark3D] = field(default_factory=list)
    left_hand: List[Landmark3D] = field(default_factory=list)
    right_hand: List[Landmark3D] = field(default_factory=list)


@dataclass
class VideoMetadata:
    """Video file metadata"""
    filename: str
    width: int
    height: int
    fps: float
    total_frames: int
    duration: float


class SkeletonExtractorHolistic:
    """
    Extract 75 landmarks using MediaPipe Holistic

    Usage:
        extractor = SkeletonExtractorHolistic()
        result = extractor.extract_from_video("tai_chi.mp4")
        extractor.save_json(result, "tai_chi_skeleton.json")
    """

    def __init__(
        self,
        min_detection_confidence: float = 0.5,
        min_tracking_confidence: float = 0.5,
        model_complexity: int = 1,  # 0=lite, 1=full, 2=heavy
        enable_segmentation: bool = False
    ):
        """
        Args:
            min_detection_confidence: Minimum confidence for detection
            min_tracking_confidence: Minimum confidence for tracking
            model_complexity: 0 (fastest) to 2 (most accurate)
            enable_segmentation: Enable body segmentation (slower)
        """
        self.min_detection_confidence = min_detection_confidence
        self.min_tracking_confidence = min_tracking_confidence
        self.model_complexity = model_complexity
        self.enable_segmentation = enable_segmentation

        logger.info(f"Initializing MediaPipe Holistic (complexity={model_complexity})")

    def extract_from_video(
        self,
        video_path: str,
        progress_callback: Optional[callable] = None
    ) -> Dict:
        """
        Extract 75 landmarks from video

        Args:
            video_path: Path to video file
            progress_callback: Optional callback(frame_idx, total_frames)

        Returns:
            {
                "version": "2.0",
                "source": "MediaPipe Holistic",
                "total_landmarks": 75,
                "video_metadata": {...},
                "frames": [...]
            }
        """
        video_path = Path(video_path)

        if not video_path.exists():
            raise FileNotFoundError(f"Video not found: {video_path}")

        logger.info(f"Extracting skeleton from: {video_path.name}")

        # Open video
        cap = cv2.VideoCapture(str(video_path))

        if not cap.isOpened():
            raise RuntimeError(f"Could not open video: {video_path}")

        # Get video metadata
        metadata = self._get_video_metadata(cap, video_path.name)
        logger.info(f"Video: {metadata.width}x{metadata.height} @ {metadata.fps:.2f}fps, "
                   f"{metadata.total_frames} frames, {metadata.duration:.2f}s")

        # Initialize holistic
        holistic = mp_holistic.Holistic(
            min_detection_confidence=self.min_detection_confidence,
            min_tracking_confidence=self.min_tracking_confidence,
            model_complexity=self.model_complexity,
            enable_segmentation=self.enable_segmentation
        )

        frames_data = []
        frame_idx = 0
        start_time = time.time()

        try:
            while cap.isOpened():
                ret, frame = cap.read()

                if not ret:
                    break

                # Convert BGR to RGB
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

                # Process frame
                results = holistic.process(rgb_frame)

                # Extract landmarks
                frame_data = self._extract_frame_landmarks(
                    frame_idx,
                    frame_idx / metadata.fps,
                    results
                )

                frames_data.append(frame_data)

                # Progress callback
                if progress_callback:
                    progress_callback(frame_idx, metadata.total_frames)

                frame_idx += 1

                # Log progress every 100 frames
                if frame_idx % 100 == 0:
                    progress = (frame_idx / metadata.total_frames) * 100
                    logger.info(f"Progress: {progress:.1f}% ({frame_idx}/{metadata.total_frames})")

        finally:
            cap.release()
            holistic.close()

        elapsed = time.time() - start_time
        fps_processing = frame_idx / elapsed

        logger.info(f"Extraction complete: {frame_idx} frames in {elapsed:.2f}s "
                   f"({fps_processing:.2f} fps)")

        # Build result
        result = {
            "version": "2.0",
            "source": "MediaPipe Holistic",
            "total_landmarks": 75,
            "video_metadata": asdict(metadata),
            "extraction_info": {
                "frames_processed": frame_idx,
                "processing_time_seconds": elapsed,
                "processing_fps": fps_processing,
                "min_detection_confidence": self.min_detection_confidence,
                "min_tracking_confidence": self.min_tracking_confidence,
                "model_complexity": self.model_complexity
            },
            "frames": [self._frame_to_dict(f) for f in frames_data]
        }

        return result

    def _get_video_metadata(self, cap: cv2.VideoCapture, filename: str) -> VideoMetadata:
        """Extract video metadata"""
        width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        duration = total_frames / fps if fps > 0 else 0

        return VideoMetadata(
            filename=filename,
            width=width,
            height=height,
            fps=fps,
            total_frames=total_frames,
            duration=duration
        )

    def _extract_frame_landmarks(
        self,
        frame_idx: int,
        timestamp: float,
        results
    ) -> FrameData:
        """Extract landmarks from MediaPipe results"""

        frame_data = FrameData(
            index=frame_idx,
            timestamp=timestamp
        )

        # Body landmarks (33)
        if results.pose_landmarks:
            for idx, lm in enumerate(results.pose_landmarks.landmark):
                frame_data.body.append(Landmark3D(
                    id=idx,
                    x=lm.x,
                    y=lm.y,
                    z=lm.z,
                    confidence=lm.visibility
                ))

        # Left hand landmarks (21)
        if results.left_hand_landmarks:
            for idx, lm in enumerate(results.left_hand_landmarks.landmark):
                frame_data.left_hand.append(Landmark3D(
                    id=idx,
                    x=lm.x,
                    y=lm.y,
                    z=lm.z,
                    confidence=1.0  # Hand landmarks don't have visibility
                ))

        # Right hand landmarks (21)
        if results.right_hand_landmarks:
            for idx, lm in enumerate(results.right_hand_landmarks.landmark):
                frame_data.right_hand.append(Landmark3D(
                    id=idx,
                    x=lm.x,
                    y=lm.y,
                    z=lm.z,
                    confidence=1.0
                ))

        return frame_data

    def _frame_to_dict(self, frame: FrameData) -> Dict:
        """Convert FrameData to dict"""
        return {
            "index": frame.index,
            "timestamp": frame.timestamp,
            "body": [asdict(lm) for lm in frame.body],
            "left_hand": [asdict(lm) for lm in frame.left_hand],
            "right_hand": [asdict(lm) for lm in frame.right_hand]
        }

    def save_json(
        self,
        data: Dict,
        output_path: str,
        pretty: bool = True
    ):
        """Save extracted data to JSON"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, ensure_ascii=False)

        file_size = output_path.stat().st_size / 1024  # KB
        logger.info(f"Saved skeleton to {output_path} ({file_size:.1f} KB)")

    def visualize_frame(
        self,
        frame: np.ndarray,
        results,
        show_body: bool = True,
        show_hands: bool = True
    ) -> np.ndarray:
        """
        Draw landmarks on frame for visualization

        Args:
            frame: Video frame (BGR)
            results: MediaPipe results
            show_body: Draw body landmarks
            show_hands: Draw hand landmarks

        Returns:
            Annotated frame
        """
        annotated = frame.copy()

        # Draw pose landmarks
        if show_body and results.pose_landmarks:
            mp_drawing.draw_landmarks(
                annotated,
                results.pose_landmarks,
                mp_holistic.POSE_CONNECTIONS,
                landmark_drawing_spec=mp_drawing_styles.get_default_pose_landmarks_style()
            )

        # Draw left hand
        if show_hands and results.left_hand_landmarks:
            mp_drawing.draw_landmarks(
                annotated,
                results.left_hand_landmarks,
                mp_holistic.HAND_CONNECTIONS,
                landmark_drawing_spec=mp_drawing_styles.get_default_hand_landmarks_style()
            )

        # Draw right hand
        if show_hands and results.right_hand_landmarks:
            mp_drawing.draw_landmarks(
                annotated,
                results.right_hand_landmarks,
                mp_holistic.HAND_CONNECTIONS,
                landmark_drawing_spec=mp_drawing_styles.get_default_hand_landmarks_style()
            )

        return annotated


# ==================== UTILITY FUNCTIONS ====================

def compare_pose_vs_holistic(
    pose_json_path: str,
    holistic_json_path: str
) -> Dict:
    """
    Compare old 33 landmarks vs new 75 landmarks

    Returns:
        {
            "pose_landmarks": 33,
            "holistic_landmarks": 75,
            "additional_landmarks": 42,
            "hand_precision_gain": "21 points per hand"
        }
    """
    with open(pose_json_path, 'r') as f:
        pose_data = json.load(f)

    with open(holistic_json_path, 'r') as f:
        holistic_data = json.load(f)

    pose_count = len(pose_data['frames'][0]['landmarks']) if pose_data['frames'] else 0

    hol_frame = holistic_data['frames'][0] if holistic_data['frames'] else {}
    holistic_count = (
        len(hol_frame.get('body', [])) +
        len(hol_frame.get('left_hand', [])) +
        len(hol_frame.get('right_hand', []))
    )

    return {
        "pose_landmarks": pose_count,
        "holistic_landmarks": holistic_count,
        "additional_landmarks": holistic_count - pose_count,
        "breakdown": {
            "body": len(hol_frame.get('body', [])),
            "left_hand": len(hol_frame.get('left_hand', [])),
            "right_hand": len(hol_frame.get('right_hand', []))
        },
        "hand_precision_gain": "21 points per hand (fingers tracking)"
    }


def calculate_statistics(skeleton_data: Dict) -> Dict:
    """
    Calculate statistics on extracted skeleton

    Returns:
        {
            "total_frames": int,
            "frames_with_body": int,
            "frames_with_left_hand": int,
            "frames_with_right_hand": int,
            "body_detection_rate": float,
            "left_hand_detection_rate": float,
            "right_hand_detection_rate": float,
            "avg_body_confidence": float,
            "avg_hand_confidence": float
        }
    """
    frames = skeleton_data.get('frames', [])
    total = len(frames)

    if total == 0:
        return {}

    body_count = sum(1 for f in frames if f.get('body'))
    left_hand_count = sum(1 for f in frames if f.get('left_hand'))
    right_hand_count = sum(1 for f in frames if f.get('right_hand'))

    # Average confidences
    body_confidences = []
    for frame in frames:
        for lm in frame.get('body', []):
            body_confidences.append(lm['confidence'])

    avg_body_conf = np.mean(body_confidences) if body_confidences else 0

    return {
        "total_frames": total,
        "frames_with_body": body_count,
        "frames_with_left_hand": left_hand_count,
        "frames_with_right_hand": right_hand_count,
        "body_detection_rate": body_count / total,
        "left_hand_detection_rate": left_hand_count / total,
        "right_hand_detection_rate": right_hand_count / total,
        "avg_body_confidence": float(avg_body_conf),
        "quality_assessment": "excellent" if avg_body_conf > 0.8 else "good" if avg_body_conf > 0.6 else "fair"
    }


# ==================== STANDALONE EXECUTION ====================

def main():
    """Example usage"""
    import argparse

    parser = argparse.ArgumentParser(description="Extract 75 landmarks with MediaPipe Holistic")
    parser.add_argument('video', help='Input video file')
    parser.add_argument('-o', '--output', help='Output JSON file (default: input_holistic.json)')
    parser.add_argument('--complexity', type=int, default=1, choices=[0, 1, 2],
                       help='Model complexity: 0=lite, 1=full, 2=heavy (default: 1)')
    parser.add_argument('--visualize', action='store_true',
                       help='Show visualization window')

    args = parser.parse_args()

    # Output path
    if args.output:
        output_path = args.output
    else:
        output_path = Path(args.video).stem + "_holistic.json"

    # Extract
    extractor = SkeletonExtractorHolistic(model_complexity=args.complexity)

    def progress(frame_idx, total):
        if frame_idx % 30 == 0:  # Print every 30 frames
            print(f"Processing: {frame_idx}/{total} ({(frame_idx/total)*100:.1f}%)")

    result = extractor.extract_from_video(args.video, progress_callback=progress)

    # Save
    extractor.save_json(result, output_path)

    # Statistics
    stats = calculate_statistics(result)
    print("\n=== EXTRACTION STATISTICS ===")
    for key, value in stats.items():
        print(f"{key}: {value}")

    print(f"\nSkeleton saved to: {output_path}")


if __name__ == '__main__':
    main()

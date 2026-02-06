"""
Simple Skeleton Viewer - Desktop Application
Visualize 75-landmark skeleton overlay on video with frame-by-frame navigation
"""

import cv2
import json
import numpy as np
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SkeletonViewerSimple:
    """
    Simple desktop viewer for 75-landmark skeleton overlay

    Features:
    - Video playback with skeleton overlay
    - Frame-by-frame navigation
    - Color-coded landmarks (body, left hand, right hand)
    - Quality info display
    - Keyboard controls
    """

    # Color scheme (BGR format for OpenCV)
    COLOR_BODY = (255, 100, 100)      # Light blue
    COLOR_LEFT_HAND = (100, 255, 100) # Light green
    COLOR_RIGHT_HAND = (100, 100, 255) # Light red
    COLOR_TEXT = (255, 255, 255)      # White
    COLOR_BG = (40, 40, 40)           # Dark gray

    # MediaPipe Pose connections (33 landmarks)
    POSE_CONNECTIONS = [
        # Face
        (0, 1), (1, 2), (2, 3), (3, 7),  # Right eye
        (0, 4), (4, 5), (5, 6), (6, 8),  # Left eye
        (9, 10),  # Mouth
        # Torso
        (11, 12), (11, 13), (13, 15), (15, 17), (15, 19), (15, 21),  # Left arm
        (12, 14), (14, 16), (16, 18), (16, 20), (16, 22),  # Right arm
        (11, 23), (12, 24), (23, 24),  # Torso
        # Legs
        (23, 25), (25, 27), (27, 29), (27, 31),  # Left leg
        (24, 26), (26, 28), (28, 30), (28, 32),  # Right leg
    ]

    # Hand connections (21 landmarks each)
    HAND_CONNECTIONS = [
        # Thumb
        (0, 1), (1, 2), (2, 3), (3, 4),
        # Index
        (0, 5), (5, 6), (6, 7), (7, 8),
        # Middle
        (0, 9), (9, 10), (10, 11), (11, 12),
        # Ring
        (0, 13), (13, 14), (14, 15), (15, 16),
        # Pinky
        (0, 17), (17, 18), (18, 19), (19, 20),
        # Palm
        (5, 9), (9, 13), (13, 17),
    ]

    def __init__(self, video_path: str, skeleton_path: str):
        """
        Initialize viewer

        Args:
            video_path: Path to video file
            skeleton_path: Path to skeleton JSON file
        """
        self.video_path = Path(video_path)
        self.skeleton_path = Path(skeleton_path)

        # Validate files
        if not self.video_path.exists():
            raise FileNotFoundError(f"Video not found: {video_path}")
        if not self.skeleton_path.exists():
            raise FileNotFoundError(f"Skeleton JSON not found: {skeleton_path}")

        # Load skeleton data
        logger.info(f"Loading skeleton data from {self.skeleton_path.name}")
        with open(self.skeleton_path, 'r') as f:
            self.skeleton_data = json.load(f)

        # Load video
        logger.info(f"Loading video from {self.video_path.name}")
        self.cap = cv2.VideoCapture(str(self.video_path))

        if not self.cap.isOpened():
            raise RuntimeError(f"Could not open video: {video_path}")

        # Video properties
        self.width = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        self.height = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        self.fps = self.cap.get(cv2.CAP_PROP_FPS)
        self.total_frames = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT))

        # Viewer state
        self.current_frame_idx = 0
        self.playing = False
        self.show_skeleton = True
        self.show_body = True
        self.show_hands = True
        self.show_info = True

        logger.info(f"Video: {self.width}x{self.height} @ {self.fps:.2f}fps, {self.total_frames} frames")
        logger.info(f"Skeleton: {len(self.skeleton_data['frames'])} frames, {self.skeleton_data['total_landmarks']} landmarks")

    def get_frame_skeleton(self, frame_idx: int) -> Optional[Dict]:
        """Get skeleton data for specific frame"""
        frames = self.skeleton_data.get('frames', [])
        if 0 <= frame_idx < len(frames):
            return frames[frame_idx]
        return None

    def draw_landmarks(
        self,
        frame: np.ndarray,
        landmarks: List[Dict],
        connections: List[Tuple[int, int]],
        color: Tuple[int, int, int],
        radius: int = 3,
        thickness: int = 2
    ):
        """Draw landmarks and connections on frame"""
        h, w = frame.shape[:2]

        # Draw connections
        for conn in connections:
            idx1, idx2 = conn
            if idx1 < len(landmarks) and idx2 < len(landmarks):
                lm1 = landmarks[idx1]
                lm2 = landmarks[idx2]

                # Convert normalized coordinates to pixel coordinates
                x1 = int(lm1['x'] * w)
                y1 = int(lm1['y'] * h)
                x2 = int(lm2['x'] * w)
                y2 = int(lm2['y'] * h)

                # Draw line
                cv2.line(frame, (x1, y1), (x2, y2), color, thickness)

        # Draw landmarks
        for lm in landmarks:
            x = int(lm['x'] * w)
            y = int(lm['y'] * h)
            cv2.circle(frame, (x, y), radius, color, -1)

    def draw_skeleton_overlay(self, frame: np.ndarray, frame_idx: int) -> np.ndarray:
        """Draw skeleton overlay on frame"""
        if not self.show_skeleton:
            return frame

        skeleton = self.get_frame_skeleton(frame_idx)
        if not skeleton:
            return frame

        # Draw body (33 landmarks)
        if self.show_body and skeleton.get('body'):
            self.draw_landmarks(
                frame,
                skeleton['body'],
                self.POSE_CONNECTIONS,
                self.COLOR_BODY,
                radius=4,
                thickness=2
            )

        # Draw left hand (21 landmarks)
        if self.show_hands and skeleton.get('left_hand'):
            self.draw_landmarks(
                frame,
                skeleton['left_hand'],
                self.HAND_CONNECTIONS,
                self.COLOR_LEFT_HAND,
                radius=3,
                thickness=2
            )

        # Draw right hand (21 landmarks)
        if self.show_hands and skeleton.get('right_hand'):
            self.draw_landmarks(
                frame,
                skeleton['right_hand'],
                self.HAND_CONNECTIONS,
                self.COLOR_RIGHT_HAND,
                radius=3,
                thickness=2
            )

        return frame

    def draw_info_panel(self, frame: np.ndarray, frame_idx: int):
        """Draw info panel on frame"""
        if not self.show_info:
            return

        h, w = frame.shape[:2]
        panel_height = 120
        panel_width = 300
        margin = 10

        # Create semi-transparent panel
        overlay = frame.copy()
        cv2.rectangle(
            overlay,
            (margin, margin),
            (margin + panel_width, margin + panel_height),
            self.COLOR_BG,
            -1
        )
        cv2.addWeighted(overlay, 0.7, frame, 0.3, 0, frame)

        # Draw border
        cv2.rectangle(
            frame,
            (margin, margin),
            (margin + panel_width, margin + panel_height),
            self.COLOR_TEXT,
            1
        )

        # Text info
        skeleton = self.get_frame_skeleton(frame_idx)

        y_offset = margin + 25
        line_height = 20

        # Frame info
        cv2.putText(
            frame,
            f"Frame: {frame_idx}/{self.total_frames}",
            (margin + 10, y_offset),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            self.COLOR_TEXT,
            1
        )
        y_offset += line_height

        # Time
        timestamp = frame_idx / self.fps if self.fps > 0 else 0
        cv2.putText(
            frame,
            f"Time: {timestamp:.2f}s",
            (margin + 10, y_offset),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            self.COLOR_TEXT,
            1
        )
        y_offset += line_height

        # Detection status
        if skeleton:
            body_count = len(skeleton.get('body', []))
            left_hand_count = len(skeleton.get('left_hand', []))
            right_hand_count = len(skeleton.get('right_hand', []))

            cv2.putText(
                frame,
                f"Body: {body_count}/33",
                (margin + 10, y_offset),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                self.COLOR_BODY,
                1
            )
            y_offset += line_height

            cv2.putText(
                frame,
                f"L.Hand: {left_hand_count}/21",
                (margin + 10, y_offset),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                self.COLOR_LEFT_HAND,
                1
            )
            y_offset += line_height

            cv2.putText(
                frame,
                f"R.Hand: {right_hand_count}/21",
                (margin + 10, y_offset),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.5,
                self.COLOR_RIGHT_HAND,
                1
            )

    def draw_controls_help(self, frame: np.ndarray):
        """Draw keyboard controls help"""
        h, w = frame.shape[:2]
        y_start = h - 150
        x_start = 10

        controls = [
            "CONTROLS:",
            "SPACE - Play/Pause",
            "LEFT/RIGHT - Prev/Next frame",
            "S - Toggle skeleton",
            "B - Toggle body",
            "H - Toggle hands",
            "I - Toggle info",
            "Q/ESC - Quit"
        ]

        for i, text in enumerate(controls):
            cv2.putText(
                frame,
                text,
                (x_start, y_start + i * 18),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.4,
                self.COLOR_TEXT,
                1
            )

    def get_frame(self, frame_idx: int) -> Optional[np.ndarray]:
        """Get specific frame from video"""
        self.cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
        ret, frame = self.cap.read()
        return frame if ret else None

    def run(self):
        """Run viewer main loop"""
        window_name = f"Skeleton Viewer - {self.video_path.name}"
        cv2.namedWindow(window_name, cv2.WINDOW_NORMAL)
        cv2.resizeWindow(window_name, 1280, 720)

        logger.info("Starting viewer...")
        logger.info("Press 'Q' or ESC to quit")

        while True:
            # Get current frame
            frame = self.get_frame(self.current_frame_idx)

            if frame is None:
                logger.warning(f"Could not read frame {self.current_frame_idx}")
                break

            # Draw skeleton overlay
            frame = self.draw_skeleton_overlay(frame, self.current_frame_idx)

            # Draw info panel
            self.draw_info_panel(frame, self.current_frame_idx)

            # Draw controls help
            self.draw_controls_help(frame)

            # Show frame
            cv2.imshow(window_name, frame)

            # Handle keyboard input
            wait_time = int(1000 / self.fps) if self.playing else 0
            key = cv2.waitKey(wait_time) & 0xFF

            if key == ord('q') or key == 27:  # Q or ESC
                break
            elif key == ord(' '):  # SPACE - play/pause
                self.playing = not self.playing
            elif key == 81 or key == 2:  # LEFT arrow
                self.current_frame_idx = max(0, self.current_frame_idx - 1)
            elif key == 83 or key == 3:  # RIGHT arrow
                self.current_frame_idx = min(self.total_frames - 1, self.current_frame_idx + 1)
            elif key == ord('s'):  # S - toggle skeleton
                self.show_skeleton = not self.show_skeleton
            elif key == ord('b'):  # B - toggle body
                self.show_body = not self.show_body
            elif key == ord('h'):  # H - toggle hands
                self.show_hands = not self.show_hands
            elif key == ord('i'):  # I - toggle info
                self.show_info = not self.show_info

            # Auto-advance if playing
            if self.playing:
                self.current_frame_idx += 1
                if self.current_frame_idx >= self.total_frames:
                    self.current_frame_idx = 0  # Loop

        # Cleanup
        self.cap.release()
        cv2.destroyAllWindows()
        logger.info("Viewer closed")


def main():
    """Command-line interface"""
    import argparse

    parser = argparse.ArgumentParser(description="Simple skeleton viewer with frame-by-frame navigation")
    parser.add_argument('video', help='Video file')
    parser.add_argument('skeleton', help='Skeleton JSON file')

    args = parser.parse_args()

    try:
        viewer = SkeletonViewerSimple(args.video, args.skeleton)
        viewer.run()
    except Exception as e:
        logger.error(f"Error: {e}")
        return False

    return True


if __name__ == '__main__':
    import sys
    success = main()
    sys.exit(0 if success else 1)

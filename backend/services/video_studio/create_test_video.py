"""
Create a simple test video with a moving stick figure
for testing skeleton extraction
"""

import cv2
import numpy as np
from pathlib import Path


def create_simple_test_video(
    output_path: str = "test_video.mp4",
    width: int = 640,
    height: int = 480,
    fps: float = 30.0,
    duration: float = 3.0,
    codec: str = "mp4v"
):
    """
    Create a simple test video with a moving stick figure

    Args:
        output_path: Output video file path
        width: Video width
        height: Video height
        fps: Frames per second
        duration: Video duration in seconds
        codec: Video codec (mp4v, avc1, etc.)
    """

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Calculate total frames
    total_frames = int(fps * duration)

    # Initialize video writer
    fourcc = cv2.VideoWriter_fourcc(*codec)
    writer = cv2.VideoWriter(str(output_path), fourcc, fps, (width, height))

    if not writer.isOpened():
        raise RuntimeError(f"Could not open video writer for {output_path}")

    print(f"Creating test video: {width}x{height} @ {fps}fps, {duration}s ({total_frames} frames)")

    # Draw frames
    for frame_idx in range(total_frames):
        # Create black background
        frame = np.zeros((height, width, 3), dtype=np.uint8)

        # Calculate animation progress (0.0 to 1.0)
        progress = frame_idx / total_frames

        # Draw a moving stick figure
        center_x = int(width * 0.3 + (width * 0.4) * progress)
        center_y = height // 2

        # Head
        cv2.circle(frame, (center_x, center_y - 60), 20, (255, 255, 255), 2)

        # Body
        cv2.line(frame, (center_x, center_y - 40), (center_x, center_y + 40), (255, 255, 255), 2)

        # Arms (animate)
        arm_angle = progress * np.pi * 2  # Full rotation
        left_arm_x = center_x - int(30 * np.cos(arm_angle))
        left_arm_y = center_y - 20 + int(30 * np.sin(arm_angle))
        right_arm_x = center_x + int(30 * np.cos(arm_angle))
        right_arm_y = center_y - 20 - int(30 * np.sin(arm_angle))

        cv2.line(frame, (center_x, center_y - 20), (left_arm_x, left_arm_y), (255, 255, 255), 2)
        cv2.line(frame, (center_x, center_y - 20), (right_arm_x, right_arm_y), (255, 255, 255), 2)

        # Legs (animate)
        leg_angle = progress * np.pi * 4  # 2 full cycles
        left_leg_x = center_x - 20
        left_leg_y = center_y + 40 + int(40 * np.sin(leg_angle))
        right_leg_x = center_x + 20
        right_leg_y = center_y + 40 - int(40 * np.sin(leg_angle))

        cv2.line(frame, (center_x, center_y + 40), (left_leg_x, left_leg_y), (255, 255, 255), 2)
        cv2.line(frame, (center_x, center_y + 40), (right_leg_x, right_leg_y), (255, 255, 255), 2)

        # Add frame counter
        cv2.putText(
            frame,
            f"Frame {frame_idx}/{total_frames}",
            (10, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (255, 255, 255),
            2
        )

        # Write frame
        writer.write(frame)

        # Progress
        if frame_idx % 30 == 0:
            print(f"Progress: {frame_idx}/{total_frames} ({(frame_idx/total_frames)*100:.1f}%)")

    # Release
    writer.release()

    # Verify file
    if not output_path.exists():
        raise RuntimeError(f"Video file not created: {output_path}")

    file_size = output_path.stat().st_size / 1024  # KB
    print(f"\nTest video created successfully!")
    print(f"Path: {output_path}")
    print(f"Size: {file_size:.1f} KB")
    print(f"Frames: {total_frames}")
    print(f"Duration: {duration:.1f}s")

    return str(output_path)


def main():
    """Create test video"""
    import argparse

    parser = argparse.ArgumentParser(description="Create test video for skeleton extraction")
    parser.add_argument('-o', '--output', default='test_video.mp4', help='Output video path')
    parser.add_argument('-w', '--width', type=int, default=640, help='Video width')
    parser.add_argument('-H', '--height', type=int, default=480, help='Video height')
    parser.add_argument('-f', '--fps', type=float, default=30.0, help='Frames per second')
    parser.add_argument('-d', '--duration', type=float, default=3.0, help='Duration in seconds')

    args = parser.parse_args()

    try:
        video_path = create_simple_test_video(
            output_path=args.output,
            width=args.width,
            height=args.height,
            fps=args.fps,
            duration=args.duration
        )

        print(f"\nYou can now test skeleton extraction with:")
        print(f"python skeleton_extraction_holistic.py {video_path} -o output.json")

    except Exception as e:
        print(f"ERROR: {e}")
        return False

    return True


if __name__ == '__main__':
    import sys
    success = main()
    sys.exit(0 if success else 1)

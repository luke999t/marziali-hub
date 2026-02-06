"""
Test script for skeleton viewer
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from skeleton_viewer_simple import SkeletonViewerSimple


def test_viewer_initialization():
    """Test viewer initialization"""
    print("Testing SkeletonViewerSimple initialization...")

    try:
        viewer = SkeletonViewerSimple("test_video.mp4", "test_skeleton.json")

        print(f"[PASS] Viewer initialized successfully")
        print(f"  - Video: {viewer.width}x{viewer.height} @ {viewer.fps:.2f}fps")
        print(f"  - Total frames: {viewer.total_frames}")
        print(f"  - Skeleton frames: {len(viewer.skeleton_data['frames'])}")
        print(f"  - Total landmarks: {viewer.skeleton_data['total_landmarks']}")

        # Test getting a frame
        frame = viewer.get_frame(0)
        if frame is not None:
            print(f"[PASS] Successfully read frame 0")
            print(f"  - Frame shape: {frame.shape}")
        else:
            print(f"[FAIL] Could not read frame 0")
            return False

        # Test getting skeleton for frame
        skeleton = viewer.get_frame_skeleton(0)
        if skeleton is not None:
            print(f"[PASS] Successfully got skeleton for frame 0")
            print(f"  - Body landmarks: {len(skeleton.get('body', []))}")
            print(f"  - Left hand landmarks: {len(skeleton.get('left_hand', []))}")
            print(f"  - Right hand landmarks: {len(skeleton.get('right_hand', []))}")
        else:
            print(f"[FAIL] Could not get skeleton for frame 0")
            return False

        # Cleanup
        viewer.cap.release()

        print("\n[SUCCESS] All viewer tests passed!")
        print("\nTo run the viewer GUI, use:")
        print("python skeleton_viewer_simple.py test_video.mp4 test_skeleton.json")

        return True

    except Exception as e:
        print(f"[FAIL] Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    success = test_viewer_initialization()
    sys.exit(0 if success else 1)

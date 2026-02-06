"""
Manual test script for skeleton_extraction_holistic.py
Bypasses pytest to avoid web3 dependency conflicts
"""

import sys
from pathlib import Path
import json
import tempfile

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from skeleton_extraction_holistic import (
    SkeletonExtractorHolistic,
    Landmark3D,
    FrameData,
    VideoMetadata,
    calculate_statistics,
    compare_pose_vs_holistic
)


class TestRunner:
    """Simple test runner"""

    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def test(self, name, condition, error_msg=""):
        """Run a single test"""
        if condition:
            print(f"[PASS] {name}")
            self.passed += 1
            self.tests.append((name, True, ""))
        else:
            print(f"[FAIL] {name}: {error_msg}")
            self.failed += 1
            self.tests.append((name, False, error_msg))

    def summary(self):
        """Print test summary"""
        total = self.passed + self.failed
        print(f"\n{'='*60}")
        print(f"TEST SUMMARY: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"\nFailed tests:")
            for name, success, error in self.tests:
                if not success:
                    print(f"  - {name}: {error}")
        print(f"{'='*60}")
        return self.failed == 0


def main():
    """Run all manual tests"""
    runner = TestRunner()

    print("="*60)
    print("MANUAL TEST: skeleton_extraction_holistic.py")
    print("="*60)

    # TEST 1: Module Import
    print("\n[TEST 1] Module Import")
    try:
        from skeleton_extraction_holistic import SkeletonExtractorHolistic
        runner.test("Module import successful", True)
    except Exception as e:
        runner.test("Module import successful", False, str(e))
        return False

    # TEST 2: Landmark3D Creation
    print("\n[TEST 2] Landmark3D Dataclass")
    try:
        lm = Landmark3D(id=0, x=0.5, y=0.5, z=0.0, confidence=0.95)
        runner.test("Landmark3D creation", True)
        runner.test("Landmark3D id", lm.id == 0)
        runner.test("Landmark3D x", lm.x == 0.5)
        runner.test("Landmark3D y", lm.y == 0.5)
        runner.test("Landmark3D z", lm.z == 0.0)
        runner.test("Landmark3D confidence", lm.confidence == 0.95)
    except Exception as e:
        runner.test("Landmark3D creation", False, str(e))

    # TEST 3: FrameData Creation
    print("\n[TEST 3] FrameData Dataclass")
    try:
        frame = FrameData(index=0, timestamp=0.0)
        runner.test("FrameData creation", True)
        runner.test("FrameData empty body", len(frame.body) == 0)
        runner.test("FrameData empty left_hand", len(frame.left_hand) == 0)
        runner.test("FrameData empty right_hand", len(frame.right_hand) == 0)

        # Add landmarks
        for i in range(33):
            frame.body.append(Landmark3D(i, 0.5, 0.5, 0.0, 0.9))
        for i in range(21):
            frame.left_hand.append(Landmark3D(i, 0.3, 0.5, 0.0, 1.0))
            frame.right_hand.append(Landmark3D(i, 0.7, 0.5, 0.0, 1.0))

        runner.test("FrameData body count", len(frame.body) == 33)
        runner.test("FrameData left_hand count", len(frame.left_hand) == 21)
        runner.test("FrameData right_hand count", len(frame.right_hand) == 21)

        total = len(frame.body) + len(frame.left_hand) + len(frame.right_hand)
        runner.test("FrameData total landmarks = 75", total == 75)
    except Exception as e:
        runner.test("FrameData creation", False, str(e))

    # TEST 4: VideoMetadata Creation
    print("\n[TEST 4] VideoMetadata Dataclass")
    try:
        meta = VideoMetadata(
            filename="test.mp4",
            width=1920,
            height=1080,
            fps=30.0,
            total_frames=900,
            duration=30.0
        )
        runner.test("VideoMetadata creation", True)
        runner.test("VideoMetadata filename", meta.filename == "test.mp4")
        runner.test("VideoMetadata width", meta.width == 1920)
        runner.test("VideoMetadata height", meta.height == 1080)
        runner.test("VideoMetadata fps", meta.fps == 30.0)
        runner.test("VideoMetadata total_frames", meta.total_frames == 900)
        runner.test("VideoMetadata duration", meta.duration == 30.0)
    except Exception as e:
        runner.test("VideoMetadata creation", False, str(e))

    # TEST 5: SkeletonExtractorHolistic Initialization
    print("\n[TEST 5] SkeletonExtractorHolistic Initialization")
    try:
        # Default initialization
        extractor = SkeletonExtractorHolistic()
        runner.test("Extractor default init", True)
        runner.test("Default min_detection_confidence", extractor.min_detection_confidence == 0.5)
        runner.test("Default min_tracking_confidence", extractor.min_tracking_confidence == 0.5)
        runner.test("Default model_complexity", extractor.model_complexity == 1)
        runner.test("Default enable_segmentation", extractor.enable_segmentation == False)

        # Custom initialization
        extractor2 = SkeletonExtractorHolistic(
            min_detection_confidence=0.7,
            min_tracking_confidence=0.8,
            model_complexity=2,
            enable_segmentation=True
        )
        runner.test("Extractor custom init", True)
        runner.test("Custom min_detection_confidence", extractor2.min_detection_confidence == 0.7)
        runner.test("Custom min_tracking_confidence", extractor2.min_tracking_confidence == 0.8)
        runner.test("Custom model_complexity", extractor2.model_complexity == 2)
        runner.test("Custom enable_segmentation", extractor2.enable_segmentation == True)
    except Exception as e:
        runner.test("Extractor initialization", False, str(e))

    # TEST 6: Statistics Calculation
    print("\n[TEST 6] Statistics Calculation")
    try:
        # Empty data
        data_empty = {"frames": []}
        stats_empty = calculate_statistics(data_empty)
        runner.test("Statistics on empty data", stats_empty == {})

        # Full detection data
        frames = []
        for i in range(10):
            frame = {
                "index": i,
                "timestamp": i/30.0,
                "body": [{"id": j, "x": 0.5, "y": 0.5, "z": 0.0, "confidence": 0.95} for j in range(33)],
                "left_hand": [{"id": j, "x": 0.3, "y": 0.5, "z": 0.0, "confidence": 1.0} for j in range(21)],
                "right_hand": [{"id": j, "x": 0.7, "y": 0.5, "z": 0.0, "confidence": 1.0} for j in range(21)]
            }
            frames.append(frame)

        data_full = {"frames": frames}
        stats = calculate_statistics(data_full)

        runner.test("Statistics total_frames", stats.get("total_frames") == 10)
        runner.test("Statistics frames_with_body", stats.get("frames_with_body") == 10)
        runner.test("Statistics body_detection_rate", stats.get("body_detection_rate") == 1.0)
        runner.test("Statistics left_hand_detection_rate", stats.get("left_hand_detection_rate") == 1.0)
        runner.test("Statistics right_hand_detection_rate", stats.get("right_hand_detection_rate") == 1.0)
        runner.test("Statistics quality_assessment", stats.get("quality_assessment") == "excellent")

        # Check avg_body_confidence is close to 0.95
        avg_conf = stats.get("avg_body_confidence", 0)
        runner.test("Statistics avg_body_confidence", 0.94 <= avg_conf <= 0.96, f"Expected ~0.95, got {avg_conf}")
    except Exception as e:
        runner.test("Statistics calculation", False, str(e))

    # TEST 7: JSON Save/Load
    print("\n[TEST 7] JSON Save/Load")
    try:
        extractor = SkeletonExtractorHolistic()

        # Create test data
        test_data = {
            "version": "2.0",
            "source": "MediaPipe Holistic",
            "total_landmarks": 75,
            "frames": []
        }

        # Save to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name

        extractor.save_json(test_data, temp_path, pretty=True)
        runner.test("JSON save successful", Path(temp_path).exists())

        # Load and verify
        with open(temp_path, 'r') as f:
            loaded = json.load(f)

        runner.test("JSON load successful", True)
        runner.test("JSON version", loaded["version"] == "2.0")
        runner.test("JSON source", loaded["source"] == "MediaPipe Holistic")
        runner.test("JSON total_landmarks", loaded["total_landmarks"] == 75)

        # Clean up
        Path(temp_path).unlink()

    except Exception as e:
        runner.test("JSON save/load", False, str(e))

    # TEST 8: Compare Pose vs Holistic
    print("\n[TEST 8] Compare Pose vs Holistic")
    try:
        # Create mock pose data (33 landmarks)
        pose_data = {
            "frames": [{
                "landmarks": [{"id": i, "x": 0.5, "y": 0.5, "z": 0.0} for i in range(33)]
            }]
        }

        # Create mock holistic data (75 landmarks)
        holistic_data = {
            "frames": [{
                "body": [{"id": i, "x": 0.5, "y": 0.5, "z": 0.0, "confidence": 0.9} for i in range(33)],
                "left_hand": [{"id": i, "x": 0.3, "y": 0.5, "z": 0.0, "confidence": 1.0} for i in range(21)],
                "right_hand": [{"id": i, "x": 0.7, "y": 0.5, "z": 0.0, "confidence": 1.0} for i in range(21)]
            }]
        }

        # Save to temp files
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            pose_path = f.name
            json.dump(pose_data, f)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            holistic_path = f.name
            json.dump(holistic_data, f)

        # Compare
        comparison = compare_pose_vs_holistic(pose_path, holistic_path)

        runner.test("Comparison pose_landmarks", comparison["pose_landmarks"] == 33)
        runner.test("Comparison holistic_landmarks", comparison["holistic_landmarks"] == 75)
        runner.test("Comparison additional_landmarks", comparison["additional_landmarks"] == 42)
        runner.test("Comparison body breakdown", comparison["breakdown"]["body"] == 33)
        runner.test("Comparison left_hand breakdown", comparison["breakdown"]["left_hand"] == 21)
        runner.test("Comparison right_hand breakdown", comparison["breakdown"]["right_hand"] == 21)

        # Clean up
        Path(pose_path).unlink()
        Path(holistic_path).unlink()

    except Exception as e:
        runner.test("Compare pose vs holistic", False, str(e))

    # TEST 9: Error Handling
    print("\n[TEST 9] Error Handling")
    try:
        extractor = SkeletonExtractorHolistic()

        # Test video not found
        error_raised = False
        try:
            extractor.extract_from_video("nonexistent_video.mp4")
        except FileNotFoundError:
            error_raised = True

        runner.test("FileNotFoundError raised for nonexistent video", error_raised)

    except Exception as e:
        runner.test("Error handling", False, str(e))

    # Print summary
    success = runner.summary()

    if success:
        print("\n[SUCCESS] ALL TESTS PASSED!")
        print("\nModule is ready for integration testing with real videos.")
        return True
    else:
        print("\n[ERROR] SOME TESTS FAILED")
        return False


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)

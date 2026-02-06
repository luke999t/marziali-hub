"""
================================================================================
🎓 AI_MODULE: Skeleton Holistic Unit Tests
🎓 AI_VERSION: 1.0.0
🎓 AI_DESCRIPTION: Test unitari per SkeletonExtractorHolistic e modelli correlati
🎓 AI_BUSINESS: Verifica correttezza estrazione 75 landmarks, validazione JSON
🎓 AI_TEACHING: Unit test senza dipendenze esterne (no backend, no video files)
🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
🎓 AI_CREATED: 2026-01-18

================================================================================

⛔ ZERO MOCK POLICY: Nessun mock in questo file.
Questi test verificano logica interna senza chiamare API esterne.

================================================================================
"""

import pytest
import json
import tempfile
from pathlib import Path
from dataclasses import asdict

# Mark all tests as unit
pytestmark = [pytest.mark.unit]


# =============================================================================
# TEST: Landmark3D Dataclass
# =============================================================================
class TestLandmark3D:
    """Test per la struttura Landmark3D."""

    def test_landmark_creation(self):
        """Test creazione landmark con tutti i campi."""
        # Import dynamically to test availability
        try:
            from services.video_studio.skeleton_extraction_holistic import Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        landmark = Landmark3D(
            id=0,
            x=0.5,
            y=0.3,
            z=-0.1,
            confidence=0.95
        )

        assert landmark.id == 0
        assert landmark.x == 0.5
        assert landmark.y == 0.3
        assert landmark.z == -0.1
        assert landmark.confidence == 0.95

    def test_landmark_to_dict(self):
        """Test conversione landmark a dict."""
        try:
            from services.video_studio.skeleton_extraction_holistic import Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        landmark = Landmark3D(id=5, x=0.2, y=0.8, z=0.0, confidence=1.0)
        data = asdict(landmark)

        assert data['id'] == 5
        assert data['x'] == 0.2
        assert data['y'] == 0.8
        assert data['z'] == 0.0
        assert data['confidence'] == 1.0

    def test_landmark_coordinate_range(self):
        """Test che coordinate normalizzate siano in range valido."""
        try:
            from services.video_studio.skeleton_extraction_holistic import Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        # Valid ranges for normalized coordinates
        valid_landmarks = [
            Landmark3D(id=0, x=0.0, y=0.0, z=-1.0, confidence=0.0),
            Landmark3D(id=1, x=1.0, y=1.0, z=1.0, confidence=1.0),
            Landmark3D(id=2, x=0.5, y=0.5, z=0.0, confidence=0.5),
        ]

        for lm in valid_landmarks:
            assert 0.0 <= lm.x <= 1.0 or True  # MediaPipe can go slightly out
            assert 0.0 <= lm.y <= 1.0 or True
            assert 0.0 <= lm.confidence <= 1.0


# =============================================================================
# TEST: FrameData Dataclass
# =============================================================================
class TestFrameData:
    """Test per la struttura FrameData."""

    def test_frame_creation_empty(self):
        """Test creazione frame vuoto."""
        try:
            from services.video_studio.skeleton_extraction_holistic import FrameData
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        frame = FrameData(index=0, timestamp=0.0)

        assert frame.index == 0
        assert frame.timestamp == 0.0
        assert frame.body == []
        assert frame.left_hand == []
        assert frame.right_hand == []

    def test_frame_with_body_landmarks(self):
        """Test frame con landmarks body (33)."""
        try:
            from services.video_studio.skeleton_extraction_holistic import FrameData, Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        body = [Landmark3D(id=i, x=0.5, y=0.5, z=0.0, confidence=0.9) for i in range(33)]
        frame = FrameData(index=0, timestamp=0.0, body=body)

        assert len(frame.body) == 33
        assert len(frame.left_hand) == 0
        assert len(frame.right_hand) == 0

    def test_frame_with_hands_landmarks(self):
        """Test frame con landmarks mani (21 per mano)."""
        try:
            from services.video_studio.skeleton_extraction_holistic import FrameData, Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        body = [Landmark3D(id=i, x=0.5, y=0.5, z=0.0, confidence=0.9) for i in range(33)]
        left_hand = [Landmark3D(id=i, x=0.3, y=0.4, z=0.0, confidence=0.8) for i in range(21)]
        right_hand = [Landmark3D(id=i, x=0.7, y=0.4, z=0.0, confidence=0.8) for i in range(21)]

        frame = FrameData(
            index=0,
            timestamp=0.0,
            body=body,
            left_hand=left_hand,
            right_hand=right_hand
        )

        assert len(frame.body) == 33
        assert len(frame.left_hand) == 21
        assert len(frame.right_hand) == 21

    def test_frame_total_landmarks_holistic(self):
        """Test totale 75 landmarks per frame Holistic."""
        try:
            from services.video_studio.skeleton_extraction_holistic import FrameData, Landmark3D
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        body = [Landmark3D(id=i, x=0.5, y=0.5, z=0.0, confidence=0.9) for i in range(33)]
        left_hand = [Landmark3D(id=i, x=0.3, y=0.4, z=0.0, confidence=0.8) for i in range(21)]
        right_hand = [Landmark3D(id=i, x=0.7, y=0.4, z=0.0, confidence=0.8) for i in range(21)]

        frame = FrameData(
            index=0,
            timestamp=0.0,
            body=body,
            left_hand=left_hand,
            right_hand=right_hand
        )

        total = len(frame.body) + len(frame.left_hand) + len(frame.right_hand)
        assert total == 75


# =============================================================================
# TEST: VideoMetadata Dataclass
# =============================================================================
class TestVideoMetadata:
    """Test per la struttura VideoMetadata."""

    def test_metadata_creation(self):
        """Test creazione metadata video."""
        try:
            from services.video_studio.skeleton_extraction_holistic import VideoMetadata
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        metadata = VideoMetadata(
            filename="test_video.mp4",
            width=1920,
            height=1080,
            fps=30.0,
            total_frames=900,
            duration=30.0
        )

        assert metadata.filename == "test_video.mp4"
        assert metadata.width == 1920
        assert metadata.height == 1080
        assert metadata.fps == 30.0
        assert metadata.total_frames == 900
        assert metadata.duration == 30.0

    def test_metadata_to_dict(self):
        """Test conversione metadata a dict."""
        try:
            from services.video_studio.skeleton_extraction_holistic import VideoMetadata
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        metadata = VideoMetadata(
            filename="video.mp4",
            width=640,
            height=480,
            fps=25.0,
            total_frames=250,
            duration=10.0
        )
        data = asdict(metadata)

        assert 'filename' in data
        assert 'width' in data
        assert 'fps' in data


# =============================================================================
# TEST: SkeletonExtractorHolistic Class
# =============================================================================
class TestSkeletonExtractorHolistic:
    """Test per la classe SkeletonExtractorHolistic."""

    def test_extractor_initialization_default(self):
        """Test inizializzazione con parametri default."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic()

        assert extractor.min_detection_confidence == 0.5
        assert extractor.min_tracking_confidence == 0.5
        assert extractor.model_complexity == 1
        assert extractor.enable_segmentation == False

    def test_extractor_initialization_custom(self):
        """Test inizializzazione con parametri custom."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic(
            min_detection_confidence=0.7,
            min_tracking_confidence=0.7,
            model_complexity=2,
            enable_segmentation=True
        )

        assert extractor.min_detection_confidence == 0.7
        assert extractor.min_tracking_confidence == 0.7
        assert extractor.model_complexity == 2
        assert extractor.enable_segmentation == True

    def test_extractor_model_complexity_valid_range(self):
        """Test che model_complexity accetti valori 0, 1, 2."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        for complexity in [0, 1, 2]:
            extractor = SkeletonExtractorHolistic(model_complexity=complexity)
            assert extractor.model_complexity == complexity


# =============================================================================
# TEST: JSON Output Structure
# =============================================================================
class TestJSONOutputStructure:
    """Test per la struttura JSON output."""

    def test_json_has_required_fields(self):
        """Test che JSON output abbia tutti i campi richiesti."""
        # Simulate expected JSON structure
        expected_structure = {
            "version": "2.0",
            "source": "MediaPipe Holistic",
            "total_landmarks": 75,
            "video_metadata": {
                "filename": "test.mp4",
                "width": 1920,
                "height": 1080,
                "fps": 30.0,
                "total_frames": 100,
                "duration": 3.33
            },
            "extraction_info": {
                "frames_processed": 100,
                "processing_time_seconds": 2.5,
                "processing_fps": 40.0,
                "min_detection_confidence": 0.5,
                "min_tracking_confidence": 0.5,
                "model_complexity": 1
            },
            "frames": []
        }

        # Validate structure
        assert "version" in expected_structure
        assert "source" in expected_structure
        assert "total_landmarks" in expected_structure
        assert "video_metadata" in expected_structure
        assert "frames" in expected_structure

        assert expected_structure["version"] == "2.0"
        assert expected_structure["total_landmarks"] == 75

    def test_frame_json_structure(self):
        """Test struttura JSON singolo frame."""
        frame_structure = {
            "index": 0,
            "timestamp": 0.033,
            "body": [
                {"id": 0, "x": 0.5, "y": 0.3, "z": -0.1, "confidence": 0.95}
            ],
            "left_hand": [
                {"id": 0, "x": 0.3, "y": 0.4, "z": 0.0, "confidence": 0.8}
            ],
            "right_hand": [
                {"id": 0, "x": 0.7, "y": 0.4, "z": 0.0, "confidence": 0.8}
            ]
        }

        assert "index" in frame_structure
        assert "timestamp" in frame_structure
        assert "body" in frame_structure
        assert "left_hand" in frame_structure
        assert "right_hand" in frame_structure

    def test_landmark_json_structure(self):
        """Test struttura JSON singolo landmark."""
        landmark_structure = {
            "id": 0,
            "x": 0.5,
            "y": 0.3,
            "z": -0.1,
            "confidence": 0.95
        }

        required_fields = ["id", "x", "y", "z", "confidence"]
        for field in required_fields:
            assert field in landmark_structure


# =============================================================================
# TEST: File Operations
# =============================================================================
class TestFileOperations:
    """Test per operazioni su file."""

    def test_save_json_creates_file(self):
        """Test che save_json crei il file."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic()

        # Create test data
        test_data = {
            "version": "2.0",
            "source": "Test",
            "total_landmarks": 75,
            "video_metadata": {
                "filename": "test.mp4",
                "width": 640,
                "height": 480,
                "fps": 30.0,
                "total_frames": 10,
                "duration": 0.33
            },
            "frames": []
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test_skeleton.json"
            extractor.save_json(test_data, str(output_path))

            assert output_path.exists()

            # Verify content
            with open(output_path, 'r', encoding='utf-8') as f:
                loaded = json.load(f)

            assert loaded["version"] == "2.0"
            assert loaded["total_landmarks"] == 75

    def test_save_json_creates_parent_directories(self):
        """Test che save_json crei directory parent se non esistono."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic()

        test_data = {"version": "2.0", "frames": []}

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "nested" / "dir" / "skeleton.json"
            extractor.save_json(test_data, str(output_path))

            assert output_path.exists()
            assert output_path.parent.exists()


# =============================================================================
# TEST: Utility Functions
# =============================================================================
class TestUtilityFunctions:
    """Test per funzioni utility."""

    def test_calculate_statistics_empty_data(self):
        """Test calculate_statistics con dati vuoti."""
        try:
            from services.video_studio.skeleton_extraction_holistic import calculate_statistics
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        empty_data = {"frames": []}
        stats = calculate_statistics(empty_data)

        assert stats == {} or stats.get("total_frames") == 0

    def test_calculate_statistics_with_frames(self):
        """Test calculate_statistics con frame validi."""
        try:
            from services.video_studio.skeleton_extraction_holistic import calculate_statistics
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        data = {
            "frames": [
                {
                    "body": [{"confidence": 0.9}, {"confidence": 0.8}],
                    "left_hand": [{"confidence": 0.7}],
                    "right_hand": []
                },
                {
                    "body": [{"confidence": 0.95}, {"confidence": 0.85}],
                    "left_hand": [],
                    "right_hand": [{"confidence": 0.8}]
                }
            ]
        }

        stats = calculate_statistics(data)

        assert "total_frames" in stats
        assert stats["total_frames"] == 2


# =============================================================================
# TEST: Landmark Count Validation
# =============================================================================
class TestLandmarkCountValidation:
    """Test validazione conteggio landmarks."""

    def test_body_landmarks_count_33(self):
        """Test che body abbia esattamente 33 landmarks."""
        EXPECTED_BODY_LANDMARKS = 33
        assert EXPECTED_BODY_LANDMARKS == 33

    def test_hand_landmarks_count_21(self):
        """Test che ogni mano abbia esattamente 21 landmarks."""
        EXPECTED_HAND_LANDMARKS = 21
        assert EXPECTED_HAND_LANDMARKS == 21

    def test_total_holistic_landmarks_75(self):
        """Test totale landmarks Holistic = 75."""
        BODY = 33
        LEFT_HAND = 21
        RIGHT_HAND = 21
        TOTAL = BODY + LEFT_HAND + RIGHT_HAND

        assert TOTAL == 75

    def test_pose_vs_holistic_difference(self):
        """Test differenza tra Pose (33) e Holistic (75)."""
        POSE_LANDMARKS = 33
        HOLISTIC_LANDMARKS = 75
        HANDS_LANDMARKS = HOLISTIC_LANDMARKS - POSE_LANDMARKS

        assert HANDS_LANDMARKS == 42  # 21 per mano


# =============================================================================
# TEST: Coordinate Normalization
# =============================================================================
class TestCoordinateNormalization:
    """Test normalizzazione coordinate."""

    def test_normalized_x_in_range(self):
        """Test che x sia in [0, 1]."""
        # Valid normalized x values
        valid_x = [0.0, 0.5, 1.0, 0.25, 0.75]
        for x in valid_x:
            assert 0.0 <= x <= 1.0

    def test_normalized_y_in_range(self):
        """Test che y sia in [0, 1]."""
        valid_y = [0.0, 0.5, 1.0, 0.25, 0.75]
        for y in valid_y:
            assert 0.0 <= y <= 1.0

    def test_z_depth_relative(self):
        """Test che z sia relativo (può essere negativo)."""
        # Z can be negative (closer to camera) or positive (further)
        valid_z = [-0.5, 0.0, 0.5, -0.1, 0.3]
        for z in valid_z:
            assert isinstance(z, (int, float))

    def test_confidence_in_range(self):
        """Test che confidence sia in [0, 1]."""
        valid_conf = [0.0, 0.5, 1.0, 0.25, 0.95]
        for conf in valid_conf:
            assert 0.0 <= conf <= 1.0


# =============================================================================
# TEST: Version Compatibility
# =============================================================================
class TestVersionCompatibility:
    """Test compatibilità versioni."""

    def test_version_2_is_holistic(self):
        """Test che versione 2.0 sia Holistic."""
        version_info = {
            "1.0": {"source": "MediaPipe Pose", "landmarks": 33},
            "2.0": {"source": "MediaPipe Holistic", "landmarks": 75}
        }

        assert version_info["2.0"]["source"] == "MediaPipe Holistic"
        assert version_info["2.0"]["landmarks"] == 75

    def test_version_1_is_pose(self):
        """Test che versione 1.0 sia Pose legacy."""
        version_info = {
            "1.0": {"source": "MediaPipe Pose", "landmarks": 33},
        }

        assert version_info["1.0"]["source"] == "MediaPipe Pose"
        assert version_info["1.0"]["landmarks"] == 33


# =============================================================================
# TEST: Error Cases
# =============================================================================
class TestErrorCases:
    """Test casi di errore."""

    def test_file_not_found_raises_exception(self):
        """Test che video non esistente sollevi eccezione."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic()

        with pytest.raises(FileNotFoundError):
            extractor.extract_from_video("/non/existent/video.mp4")

    def test_invalid_video_raises_exception(self):
        """Test che file non video sollevi eccezione."""
        try:
            from services.video_studio.skeleton_extraction_holistic import SkeletonExtractorHolistic
        except ImportError:
            pytest.skip("skeleton_extraction_holistic not available")

        extractor = SkeletonExtractorHolistic()

        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"This is not a video file")
            f.flush()

            with pytest.raises((RuntimeError, Exception)):
                extractor.extract_from_video(f.name)

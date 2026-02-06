"""
Multi-Video Fusion - Create Perfect Avatar from Multiple Technique Executions

AI_MODULE: multi_video_fusion
AI_DESCRIPTION: Fuse N videos of same technique to create consensus "perfect" avatar
AI_BUSINESS: Teaching tool - show ideal technique by averaging expert executions
AI_TEACHING: DTW alignment + weighted averaging + outlier detection + video generation

ALTERNATIVE_VALUTATE:
- Single master video: Subjective, misses variations
- Manual selection: Time-consuming, not scalable
- Simple averaging: Ignores timing differences

PERCHE_QUESTA_SOLUZIONE:
- DTW aligns different execution speeds
- Weighted average considers confidence and smoothness
- Outlier detection removes anomalous executions
- Result: Consensus skeleton representing ideal form

DEPENDENCIES:
- fastdtw: Dynamic Time Warping for sequence alignment
- numpy: Array operations
- scipy: Statistical functions, signal processing
- opencv-python: Video generation

LIMITAZIONI_NOTE:
- Requires consistent skeleton detection across videos
- Minimum 3 videos recommended for meaningful consensus
- Very different styles may not fuse well

METRICHE_SUCCESSO:
- Alignment accuracy: >95% frame correspondence
- Smoothness: Jitter reduction >50% vs individual videos
- Outlier detection: Identify >90% of anomalous executions
"""

import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
import logging
import json
import cv2
from collections import defaultdict

# Try fastdtw for dynamic time warping
try:
    from fastdtw import fastdtw
    FASTDTW_AVAILABLE = True
except ImportError:
    FASTDTW_AVAILABLE = False
    logging.warning("fastdtw not available. Install with: pip install fastdtw")

# Try scipy for signal processing and statistics
try:
    from scipy import stats
    from scipy.signal import savgol_filter
    from scipy.spatial.distance import euclidean
    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    logging.warning("scipy not available. Install with: pip install scipy")

logger = logging.getLogger(__name__)


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class SkeletonSequence:
    """
    Represents a sequence of skeleton frames from a video.

    Attributes:
        video_id: Unique identifier for source video
        frames: List of frame data, each containing joint positions
        frame_count: Number of frames
        fps: Original video FPS
        metadata: Additional info (style, performer, etc.)
    """
    video_id: str
    frames: List[Dict[str, Dict[str, float]]]  # List of {joint: {x, y, confidence}}
    frame_count: int
    fps: float = 30.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FusionResult:
    """
    Result of multi-video fusion.

    Attributes:
        consensus_skeleton: The fused "perfect" skeleton sequence
        outlier_indices: Indices of videos flagged as outliers
        similarity_matrix: Pairwise similarity between input videos
        confidence_per_frame: Fusion confidence at each frame
        report: Detailed fusion statistics
    """
    consensus_skeleton: SkeletonSequence
    outlier_indices: List[int]
    similarity_matrix: np.ndarray
    confidence_per_frame: List[float]
    report: Dict[str, Any]


@dataclass
class AlignmentResult:
    """
    Result of temporal alignment.

    Attributes:
        aligned_sequences: List of aligned skeleton sequences
        warping_paths: DTW warping paths for each sequence
        reference_index: Index of the reference sequence used
    """
    aligned_sequences: List[SkeletonSequence]
    warping_paths: List[List[Tuple[int, int]]]
    reference_index: int


# =============================================================================
# MAIN CLASS
# =============================================================================

class MultiVideoFusion:
    """
    Fuse multiple videos of the same technique into a consensus "perfect" avatar.

    WORKFLOW:
    1. Load skeleton sequences from N videos
    2. Align temporally using DTW (Dynamic Time Warping)
    3. For each frame, calculate weighted consensus position
    4. Detect and exclude outlier executions
    5. Generate smooth avatar video

    BUSINESS VALUE:
    - Creates ideal technique reference from multiple masters
    - Removes individual quirks, reveals essential form
    - Objective, data-driven teaching standard
    """

    # Joints used for fusion (MediaPipe format)
    FUSION_JOINTS = [
        "nose", "left_shoulder", "right_shoulder",
        "left_elbow", "right_elbow", "left_wrist", "right_wrist",
        "left_hip", "right_hip", "left_knee", "right_knee",
        "left_ankle", "right_ankle"
    ]

    def __init__(
        self,
        output_dir: Optional[Path] = None,
        smoothing_window: int = 5,
        outlier_threshold: float = 2.0
    ):
        """
        Initialize multi-video fusion system.

        Args:
            output_dir: Directory for output files
            smoothing_window: Window size for Savitzky-Golay smoothing
            outlier_threshold: Z-score threshold for outlier detection
        """
        self.output_dir = output_dir or Path("output/fusion")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.smoothing_window = smoothing_window
        self.outlier_threshold = outlier_threshold

        if not FASTDTW_AVAILABLE:
            logger.warning("fastdtw not available - using simple alignment")
        if not SCIPY_AVAILABLE:
            logger.warning("scipy not available - using basic statistics")

        logger.info(f"MultiVideoFusion initialized. Output: {self.output_dir}")

    # =========================================================================
    # TEMPORAL ALIGNMENT
    # =========================================================================

    def align_multiple_videos(
        self,
        video_skeletons: List[SkeletonSequence],
        reference_index: Optional[int] = None
    ) -> AlignmentResult:
        """
        Align multiple skeleton sequences temporally using DTW.

        Uses Dynamic Time Warping to synchronize sequences that may have
        different speeds/timing. All sequences are warped to match a
        reference sequence (typically the median length).

        Args:
            video_skeletons: List of SkeletonSequence objects
            reference_index: Index of reference sequence (auto-selects if None)

        Returns:
            AlignmentResult with aligned sequences and warping paths

        Example:
            >>> sequences = [load_skeleton(v) for v in videos]
            >>> aligned = fusion.align_multiple_videos(sequences)
            >>> len(aligned.aligned_sequences[0].frames) == len(aligned.aligned_sequences[1].frames)
            True
        """
        if len(video_skeletons) < 2:
            raise ValueError("Need at least 2 sequences for alignment")

        # Select reference (median length if not specified)
        if reference_index is None:
            lengths = [s.frame_count for s in video_skeletons]
            median_length = np.median(lengths)
            reference_index = int(np.argmin([abs(l - median_length) for l in lengths]))

        reference = video_skeletons[reference_index]
        logger.info(f"Using sequence {reference_index} as reference (frames: {reference.frame_count})")

        aligned_sequences = []
        warping_paths = []

        for i, sequence in enumerate(video_skeletons):
            if i == reference_index:
                # Reference sequence stays unchanged
                aligned_sequences.append(sequence)
                warping_paths.append([(j, j) for j in range(reference.frame_count)])
                continue

            # Align this sequence to reference using DTW
            aligned, path = self._align_sequence_to_reference(sequence, reference)
            aligned_sequences.append(aligned)
            warping_paths.append(path)

            logger.info(f"Aligned sequence {i}: {sequence.frame_count} -> {aligned.frame_count} frames")

        return AlignmentResult(
            aligned_sequences=aligned_sequences,
            warping_paths=warping_paths,
            reference_index=reference_index
        )

    def _align_sequence_to_reference(
        self,
        sequence: SkeletonSequence,
        reference: SkeletonSequence
    ) -> Tuple[SkeletonSequence, List[Tuple[int, int]]]:
        """
        Align a single sequence to a reference using DTW.

        Returns the aligned sequence (resampled to match reference length)
        and the warping path.
        """
        # Convert frames to feature vectors for DTW
        seq_features = self._frames_to_feature_matrix(sequence.frames)
        ref_features = self._frames_to_feature_matrix(reference.frames)

        # Run DTW
        if FASTDTW_AVAILABLE:
            distance, path = fastdtw(seq_features, ref_features, dist=euclidean if SCIPY_AVAILABLE else self._simple_distance)
        else:
            # Simple linear interpolation fallback
            path = self._simple_alignment_path(len(sequence.frames), len(reference.frames))

        # Resample sequence to match reference using warping path
        aligned_frames = self._resample_with_path(sequence.frames, reference.frame_count, path)

        aligned_sequence = SkeletonSequence(
            video_id=sequence.video_id,
            frames=aligned_frames,
            frame_count=len(aligned_frames),
            fps=reference.fps,
            metadata={**sequence.metadata, "aligned": True, "original_frames": sequence.frame_count}
        )

        return aligned_sequence, path

    def _frames_to_feature_matrix(self, frames: List[Dict]) -> np.ndarray:
        """
        Convert skeleton frames to feature matrix for DTW.

        Each row is a frame, columns are flattened joint coordinates.
        """
        feature_list = []

        for frame in frames:
            features = []
            for joint in self.FUSION_JOINTS:
                if joint in frame:
                    features.extend([frame[joint].get("x", 0), frame[joint].get("y", 0)])
                else:
                    features.extend([0, 0])  # Missing joint
            feature_list.append(features)

        return np.array(feature_list)

    def _simple_distance(self, a: np.ndarray, b: np.ndarray) -> float:
        """Simple Euclidean distance fallback."""
        return np.sqrt(np.sum((a - b) ** 2))

    def _simple_alignment_path(self, len_a: int, len_b: int) -> List[Tuple[int, int]]:
        """
        Simple linear interpolation path when DTW not available.
        """
        path = []
        for i in range(len_b):
            j = int(i * (len_a - 1) / (len_b - 1)) if len_b > 1 else 0
            path.append((j, i))
        return path

    def _resample_with_path(
        self,
        frames: List[Dict],
        target_length: int,
        path: List[Tuple[int, int]]
    ) -> List[Dict]:
        """
        Resample frames to target length using warping path.
        """
        if not path:
            return frames[:target_length]

        # Group path by target index
        target_to_source = defaultdict(list)
        for source_idx, target_idx in path:
            target_to_source[target_idx].append(source_idx)

        # For each target frame, average the mapped source frames
        resampled = []
        for t in range(target_length):
            source_indices = target_to_source.get(t, [t if t < len(frames) else len(frames) - 1])

            # Average the source frames
            if len(source_indices) == 1:
                resampled.append(frames[source_indices[0]])
            else:
                averaged_frame = self._average_frames([frames[i] for i in source_indices])
                resampled.append(averaged_frame)

        return resampled

    def _average_frames(self, frames: List[Dict]) -> Dict:
        """Average multiple skeleton frames."""
        if len(frames) == 1:
            return frames[0]

        averaged = {}
        for joint in self.FUSION_JOINTS:
            x_vals = [f[joint]["x"] for f in frames if joint in f]
            y_vals = [f[joint]["y"] for f in frames if joint in f]
            conf_vals = [f[joint].get("confidence", 1.0) for f in frames if joint in f]

            if x_vals:
                averaged[joint] = {
                    "x": np.mean(x_vals),
                    "y": np.mean(y_vals),
                    "confidence": np.mean(conf_vals)
                }

        return averaged

    # =========================================================================
    # CONSENSUS CALCULATION
    # =========================================================================

    def calculate_consensus_skeleton(
        self,
        aligned_skeletons: List[SkeletonSequence],
        weights: Optional[List[float]] = None
    ) -> SkeletonSequence:
        """
        Calculate consensus skeleton from aligned sequences.

        For each frame and joint, calculates weighted average position
        across all sequences. Weights can be based on confidence,
        smoothness, or manual assignment.

        Args:
            aligned_skeletons: List of aligned SkeletonSequence objects
            weights: Optional weights for each sequence (default: equal)

        Returns:
            SkeletonSequence representing the consensus "perfect" skeleton

        Example:
            >>> consensus = fusion.calculate_consensus_skeleton(aligned_sequences)
            >>> consensus.video_id
            "consensus_fusion"
        """
        if not aligned_skeletons:
            raise ValueError("No skeletons provided for consensus calculation")

        # Use equal weights if not specified
        if weights is None:
            weights = [1.0] * len(aligned_skeletons)

        # Normalize weights
        total_weight = sum(weights)
        weights = [w / total_weight for w in weights]

        # Find target frame count (should be same for aligned sequences)
        frame_counts = [s.frame_count for s in aligned_skeletons]
        target_frames = min(frame_counts)  # Use minimum to be safe

        consensus_frames = []
        confidence_per_frame = []

        for frame_idx in range(target_frames):
            frame_data = {}
            frame_confidence = []

            for joint in self.FUSION_JOINTS:
                # Collect values from all sequences
                x_vals = []
                y_vals = []
                joint_weights = []
                confidences = []

                for seq_idx, skeleton in enumerate(aligned_skeletons):
                    if frame_idx < len(skeleton.frames):
                        frame = skeleton.frames[frame_idx]
                        if joint in frame:
                            x_vals.append(frame[joint]["x"])
                            y_vals.append(frame[joint]["y"])
                            conf = frame[joint].get("confidence", 1.0)
                            confidences.append(conf)
                            # Weight by sequence weight * joint confidence
                            joint_weights.append(weights[seq_idx] * conf)

                if x_vals:
                    # Weighted average
                    total_w = sum(joint_weights)
                    if total_w > 0:
                        avg_x = sum(x * w for x, w in zip(x_vals, joint_weights)) / total_w
                        avg_y = sum(y * w for y, w in zip(y_vals, joint_weights)) / total_w
                        avg_conf = np.mean(confidences)

                        frame_data[joint] = {
                            "x": avg_x,
                            "y": avg_y,
                            "confidence": avg_conf
                        }
                        frame_confidence.append(avg_conf)

            consensus_frames.append(frame_data)
            confidence_per_frame.append(np.mean(frame_confidence) if frame_confidence else 0)

        # Apply smoothing to reduce jitter
        smoothed_frames = self._smooth_skeleton_sequence(consensus_frames)

        return SkeletonSequence(
            video_id="consensus_fusion",
            frames=smoothed_frames,
            frame_count=len(smoothed_frames),
            fps=aligned_skeletons[0].fps if aligned_skeletons else 30.0,
            metadata={
                "source_count": len(aligned_skeletons),
                "fusion_method": "weighted_average",
                "confidence_per_frame": confidence_per_frame
            }
        )

    def _smooth_skeleton_sequence(self, frames: List[Dict]) -> List[Dict]:
        """
        Apply Savitzky-Golay smoothing to skeleton sequence.

        Reduces jitter while preserving important motion features.
        """
        if len(frames) < self.smoothing_window:
            return frames  # Too short to smooth

        if not SCIPY_AVAILABLE:
            return frames  # Can't smooth without scipy

        smoothed = []

        # Collect time series for each joint coordinate
        joint_series = {joint: {"x": [], "y": []} for joint in self.FUSION_JOINTS}

        for frame in frames:
            for joint in self.FUSION_JOINTS:
                if joint in frame:
                    joint_series[joint]["x"].append(frame[joint]["x"])
                    joint_series[joint]["y"].append(frame[joint]["y"])
                else:
                    # Use previous value or 0
                    prev_x = joint_series[joint]["x"][-1] if joint_series[joint]["x"] else 0
                    prev_y = joint_series[joint]["y"][-1] if joint_series[joint]["y"] else 0
                    joint_series[joint]["x"].append(prev_x)
                    joint_series[joint]["y"].append(prev_y)

        # Apply smoothing
        smoothed_series = {}
        window = min(self.smoothing_window, len(frames) - 2)
        if window % 2 == 0:
            window -= 1  # Must be odd
        if window < 3:
            window = 3

        for joint in self.FUSION_JOINTS:
            try:
                smoothed_series[joint] = {
                    "x": savgol_filter(joint_series[joint]["x"], window, 2).tolist(),
                    "y": savgol_filter(joint_series[joint]["y"], window, 2).tolist()
                }
            except:
                smoothed_series[joint] = joint_series[joint]

        # Reconstruct frames
        for i in range(len(frames)):
            frame_data = {}
            for joint in self.FUSION_JOINTS:
                if joint in frames[i]:
                    frame_data[joint] = {
                        "x": smoothed_series[joint]["x"][i],
                        "y": smoothed_series[joint]["y"][i],
                        "confidence": frames[i][joint].get("confidence", 1.0)
                    }
            smoothed.append(frame_data)

        return smoothed

    # =========================================================================
    # OUTLIER DETECTION
    # =========================================================================

    def detect_outliers(
        self,
        skeletons: List[SkeletonSequence],
        threshold: Optional[float] = None
    ) -> List[int]:
        """
        Identify videos with executions too different from consensus.

        Uses z-score or IQR to detect sequences that deviate significantly
        from the group average.

        Args:
            skeletons: List of SkeletonSequence objects
            threshold: Z-score threshold (default: 2.0)

        Returns:
            List of indices of outlier sequences

        Example:
            >>> outliers = fusion.detect_outliers(sequences)
            >>> print(f"Outliers: {outliers}")
            Outliers: [3, 7]  # Videos 3 and 7 are anomalous
        """
        if len(skeletons) < 3:
            logger.warning("Need at least 3 sequences for meaningful outlier detection")
            return []

        threshold = threshold or self.outlier_threshold

        # Calculate average distance from each sequence to all others
        distances = []

        for i, seq_i in enumerate(skeletons):
            seq_distances = []
            for j, seq_j in enumerate(skeletons):
                if i != j:
                    dist = self._sequence_distance(seq_i, seq_j)
                    seq_distances.append(dist)
            distances.append(np.mean(seq_distances))

        distances = np.array(distances)

        # Z-score outlier detection
        if SCIPY_AVAILABLE:
            z_scores = np.abs(stats.zscore(distances))
            outliers = np.where(z_scores > threshold)[0].tolist()
        else:
            # Simple IQR fallback
            q1 = np.percentile(distances, 25)
            q3 = np.percentile(distances, 75)
            iqr = q3 - q1
            lower = q1 - 1.5 * iqr
            upper = q3 + 1.5 * iqr
            outliers = [i for i, d in enumerate(distances) if d < lower or d > upper]

        logger.info(f"Outlier detection: {len(outliers)} outliers from {len(skeletons)} sequences")
        return outliers

    def _sequence_distance(
        self,
        seq_a: SkeletonSequence,
        seq_b: SkeletonSequence
    ) -> float:
        """
        Calculate distance between two skeleton sequences.

        Uses average per-frame Euclidean distance.
        """
        min_frames = min(seq_a.frame_count, seq_b.frame_count)
        if min_frames == 0:
            return float('inf')

        total_distance = 0

        for i in range(min_frames):
            frame_a = seq_a.frames[i]
            frame_b = seq_b.frames[i]

            frame_dist = 0
            joint_count = 0

            for joint in self.FUSION_JOINTS:
                if joint in frame_a and joint in frame_b:
                    dx = frame_a[joint]["x"] - frame_b[joint]["x"]
                    dy = frame_a[joint]["y"] - frame_b[joint]["y"]
                    frame_dist += np.sqrt(dx**2 + dy**2)
                    joint_count += 1

            if joint_count > 0:
                total_distance += frame_dist / joint_count

        return total_distance / min_frames

    # =========================================================================
    # VIDEO GENERATION
    # =========================================================================

    def generate_avatar_video(
        self,
        consensus_skeleton: SkeletonSequence,
        output_path: Optional[Path] = None,
        style: str = "wireframe",
        resolution: Tuple[int, int] = (640, 480),
        background_color: Tuple[int, int, int] = (30, 30, 30)
    ) -> str:
        """
        Generate video of the consensus avatar skeleton.

        Renders the fused skeleton as an animated video showing
        the ideal technique execution.

        Args:
            consensus_skeleton: The fused SkeletonSequence
            output_path: Where to save the video
            style: Rendering style:
                - "wireframe": Simple lines and circles
                - "silhouette": Filled body shape
                - "3d_model": (Future) 3D character model
            resolution: Video resolution (width, height)
            background_color: BGR background color

        Returns:
            Path to generated video file

        Example:
            >>> video_path = fusion.generate_avatar_video(consensus, style="wireframe")
            >>> print(video_path)
            "output/fusion/avatar_consensus.mp4"
        """
        if output_path is None:
            output_path = self.output_dir / f"avatar_{consensus_skeleton.video_id}.mp4"
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Create video writer
        fourcc = cv2.VideoWriter_fourcc(*'mp4v')
        fps = consensus_skeleton.fps or 30.0
        out = cv2.VideoWriter(str(output_path), fourcc, fps, resolution)

        # Render each frame
        for frame_idx, frame_data in enumerate(consensus_skeleton.frames):
            img = self._render_skeleton_frame(
                frame_data, resolution, style, background_color
            )
            out.write(img)

        out.release()

        logger.info(f"Generated avatar video: {output_path} ({len(consensus_skeleton.frames)} frames)")
        return str(output_path)

    def _render_skeleton_frame(
        self,
        frame_data: Dict,
        resolution: Tuple[int, int],
        style: str,
        bg_color: Tuple[int, int, int]
    ) -> np.ndarray:
        """
        Render a single skeleton frame to image.
        """
        w, h = resolution
        img = np.full((h, w, 3), bg_color, dtype=np.uint8)

        # Define skeleton connections (bone structure)
        connections = [
            ("nose", "left_shoulder"), ("nose", "right_shoulder"),
            ("left_shoulder", "right_shoulder"),
            ("left_shoulder", "left_elbow"), ("left_elbow", "left_wrist"),
            ("right_shoulder", "right_elbow"), ("right_elbow", "right_wrist"),
            ("left_shoulder", "left_hip"), ("right_shoulder", "right_hip"),
            ("left_hip", "right_hip"),
            ("left_hip", "left_knee"), ("left_knee", "left_ankle"),
            ("right_hip", "right_knee"), ("right_knee", "right_ankle"),
        ]

        # Color scheme
        joint_color = (200, 200, 200)  # Light gray
        bone_color = (150, 150, 150)  # Medium gray
        joint_radius = 6 if style == "detailed" else 4

        # Draw bones (lines)
        for joint_a, joint_b in connections:
            if joint_a in frame_data and joint_b in frame_data:
                x1 = int(frame_data[joint_a]["x"] * w)
                y1 = int(frame_data[joint_a]["y"] * h)
                x2 = int(frame_data[joint_b]["x"] * w)
                y2 = int(frame_data[joint_b]["y"] * h)

                thickness = 3 if style == "wireframe" else 5
                cv2.line(img, (x1, y1), (x2, y2), bone_color, thickness)

        # Draw joints (circles)
        for joint, data in frame_data.items():
            x = int(data["x"] * w)
            y = int(data["y"] * h)

            # Confidence affects opacity (simplified: affects size)
            conf = data.get("confidence", 1.0)
            radius = int(joint_radius * conf)

            cv2.circle(img, (x, y), radius, joint_color, -1)

        return img

    # =========================================================================
    # FUSION REPORT
    # =========================================================================

    def fusion_report(
        self,
        input_videos: List[SkeletonSequence],
        consensus: SkeletonSequence,
        outliers: List[int]
    ) -> Dict[str, Any]:
        """
        Generate detailed report of the fusion process.

        Includes statistics, similarity matrix, outlier analysis,
        and confidence metrics.

        Args:
            input_videos: Original skeleton sequences
            consensus: The fused consensus skeleton
            outliers: List of outlier indices

        Returns:
            Dictionary with:
            - input_summary: Stats about input videos
            - similarity_matrix: Pairwise video similarities
            - outlier_analysis: Details on why videos were flagged
            - consensus_quality: Quality metrics for the fusion
            - recommendations: Suggestions for improvement
        """
        n_videos = len(input_videos)

        # Build similarity matrix
        similarity_matrix = np.zeros((n_videos, n_videos))
        for i in range(n_videos):
            for j in range(n_videos):
                if i != j:
                    dist = self._sequence_distance(input_videos[i], input_videos[j])
                    # Convert distance to similarity (inverse)
                    similarity_matrix[i, j] = 1.0 / (1.0 + dist)
                else:
                    similarity_matrix[i, j] = 1.0

        # Calculate frame counts and duration
        frame_counts = [s.frame_count for s in input_videos]
        durations = [s.frame_count / s.fps for s in input_videos]

        # Outlier analysis
        outlier_details = []
        for idx in outliers:
            if idx < len(input_videos):
                avg_similarity = np.mean([similarity_matrix[idx, j] for j in range(n_videos) if j != idx])
                outlier_details.append({
                    "video_index": idx,
                    "video_id": input_videos[idx].video_id,
                    "average_similarity": float(avg_similarity),
                    "frame_count": input_videos[idx].frame_count,
                    "reason": "Low similarity to other executions"
                })

        # Consensus quality metrics
        consensus_confidence = consensus.metadata.get("confidence_per_frame", [])
        avg_confidence = np.mean(consensus_confidence) if consensus_confidence else 0

        report = {
            "input_summary": {
                "video_count": n_videos,
                "total_frames_processed": sum(frame_counts),
                "frame_count_range": [min(frame_counts), max(frame_counts)],
                "duration_range_seconds": [min(durations), max(durations)],
                "average_fps": np.mean([s.fps for s in input_videos])
            },
            "similarity_matrix": similarity_matrix.tolist(),
            "average_pairwise_similarity": float(np.mean(similarity_matrix[np.triu_indices(n_videos, k=1)])),
            "outlier_analysis": {
                "outlier_count": len(outliers),
                "outlier_indices": outliers,
                "outlier_details": outlier_details
            },
            "consensus_quality": {
                "frame_count": consensus.frame_count,
                "average_confidence": float(avg_confidence),
                "smoothing_applied": True,
                "joints_included": len(self.FUSION_JOINTS)
            },
            "recommendations": self._generate_recommendations(
                n_videos, outliers, avg_confidence, similarity_matrix
            )
        }

        return report

    def _generate_recommendations(
        self,
        n_videos: int,
        outliers: List[int],
        avg_confidence: float,
        similarity_matrix: np.ndarray
    ) -> List[str]:
        """
        Generate recommendations based on fusion analysis.
        """
        recommendations = []

        if n_videos < 5:
            recommendations.append("Add more video samples (recommended: 10+) for better consensus")

        if len(outliers) > n_videos * 0.3:
            recommendations.append("High outlier ratio detected - verify videos show same technique")

        if avg_confidence < 0.7:
            recommendations.append("Low confidence in skeleton detection - ensure good video quality")

        avg_similarity = np.mean(similarity_matrix[np.triu_indices(n_videos, k=1)])
        if avg_similarity < 0.5:
            recommendations.append("Low overall similarity - videos may show different techniques or styles")

        if not recommendations:
            recommendations.append("Fusion quality is good - no issues detected")

        return recommendations


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def load_skeleton_from_json(json_path: Path) -> SkeletonSequence:
    """
    Load skeleton sequence from JSON file.

    Expected format:
    {
        "video_id": "technique_001",
        "fps": 30,
        "frames": [
            {"nose": {"x": 0.5, "y": 0.2, "confidence": 0.9}, ...},
            ...
        ]
    }
    """
    with open(json_path, 'r') as f:
        data = json.load(f)

    return SkeletonSequence(
        video_id=data.get("video_id", json_path.stem),
        frames=data.get("frames", []),
        frame_count=len(data.get("frames", [])),
        fps=data.get("fps", 30.0),
        metadata=data.get("metadata", {})
    )


def save_skeleton_to_json(skeleton: SkeletonSequence, output_path: Path):
    """
    Save skeleton sequence to JSON file.
    """
    data = {
        "video_id": skeleton.video_id,
        "fps": skeleton.fps,
        "frame_count": skeleton.frame_count,
        "frames": skeleton.frames,
        "metadata": skeleton.metadata
    }

    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)


# =============================================================================
# MAIN - QUICK TEST
# =============================================================================

def main():
    """Quick test of MultiVideoFusion."""
    print("=" * 60)
    print("MultiVideoFusion - Quick Test")
    print("=" * 60)

    # Create synthetic test data
    print("\n1. Creating synthetic skeleton sequences...")

    def create_test_sequence(video_id: str, offset: float = 0) -> SkeletonSequence:
        """Create a synthetic skeleton sequence (simulating a punch)."""
        frames = []
        for i in range(30):  # 1 second at 30fps
            t = i / 30.0
            # Simulate punch motion: right wrist moves forward
            frames.append({
                "nose": {"x": 0.5, "y": 0.2, "confidence": 0.95},
                "left_shoulder": {"x": 0.4, "y": 0.3, "confidence": 0.9},
                "right_shoulder": {"x": 0.6, "y": 0.3, "confidence": 0.9},
                "left_elbow": {"x": 0.35, "y": 0.4, "confidence": 0.85},
                "right_elbow": {"x": 0.65 + t * 0.1 + offset * 0.05, "y": 0.35, "confidence": 0.85},
                "left_wrist": {"x": 0.3, "y": 0.45, "confidence": 0.8},
                "right_wrist": {"x": 0.7 + t * 0.2 + offset * 0.05, "y": 0.3, "confidence": 0.8},
                "left_hip": {"x": 0.45, "y": 0.55, "confidence": 0.9},
                "right_hip": {"x": 0.55, "y": 0.55, "confidence": 0.9},
                "left_knee": {"x": 0.4, "y": 0.75, "confidence": 0.85},
                "right_knee": {"x": 0.6, "y": 0.75, "confidence": 0.85},
                "left_ankle": {"x": 0.38, "y": 0.95, "confidence": 0.8},
                "right_ankle": {"x": 0.62, "y": 0.95, "confidence": 0.8},
            })
        return SkeletonSequence(
            video_id=video_id,
            frames=frames,
            frame_count=len(frames),
            fps=30.0
        )

    # Create test sequences with slight variations
    sequences = [
        create_test_sequence("video_001", offset=0),
        create_test_sequence("video_002", offset=0.1),
        create_test_sequence("video_003", offset=-0.1),
        create_test_sequence("video_004", offset=0.05),
        create_test_sequence("video_005", offset=0.5),  # Outlier
    ]

    print(f"   Created {len(sequences)} test sequences")

    # Test fusion
    print("\n2. Running fusion...")
    fusion = MultiVideoFusion(output_dir=Path("test_output/fusion"))

    # Align
    aligned = fusion.align_multiple_videos(sequences)
    print(f"   Aligned {len(aligned.aligned_sequences)} sequences")

    # Detect outliers
    outliers = fusion.detect_outliers(aligned.aligned_sequences)
    print(f"   Outliers detected: {outliers}")

    # Calculate consensus (excluding outliers)
    clean_sequences = [s for i, s in enumerate(aligned.aligned_sequences) if i not in outliers]
    consensus = fusion.calculate_consensus_skeleton(clean_sequences)
    print(f"   Consensus: {consensus.frame_count} frames")

    # Generate video
    video_path = fusion.generate_avatar_video(consensus, style="wireframe")
    print(f"   Generated video: {video_path}")

    # Generate report
    report = fusion.fusion_report(sequences, consensus, outliers)
    print(f"\n3. Fusion Report:")
    print(f"   Input videos: {report['input_summary']['video_count']}")
    print(f"   Outliers: {report['outlier_analysis']['outlier_count']}")
    print(f"   Consensus quality: {report['consensus_quality']['average_confidence']:.2%}")
    print(f"   Recommendations: {report['recommendations']}")

    print("\n" + "=" * 60)
    print("Test complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()

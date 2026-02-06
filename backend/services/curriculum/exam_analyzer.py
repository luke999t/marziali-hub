"""
================================================================================
    EXAM ANALYZER - AI-Powered Exam Video Analysis
================================================================================

AI_MODULE: ExamAnalyzer Service
AI_DESCRIPTION: Analyzes student exam videos using AI and comparison engine
AI_BUSINESS: Core value proposition - automated fair grading with detailed feedback
AI_TEACHING: Integration with comparison_engine.py and realtime_pose_corrector.py

ALGORITHM:
    1. Download/stream exam video from URL
    2. Extract skeleton data using MediaPipe (via realtime_pose_corrector)
    3. Load reference videos for the level
    4. Compare using comparison_engine (DTW-based)
    5. Identify corrections using pose deviation analyzer
    6. Generate structured feedback + score

OUTPUTS:
    {
        "analysis": {
            "skeleton_data": {...},
            "comparison_results": {...},
            "pose_corrections": [...],
            "strengths": [...],
            "improvements": [...]
        },
        "score": 85.5,
        "feedback": "Human readable feedback text"
    }

SETTINGS (from curriculum):
    ai_feedback_enabled: bool
    ai_weight: float (0-1) - weight in final score calculation

================================================================================
"""

import cv2
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import logging
import json
import tempfile
import os
import asyncio
from pathlib import Path
import httpx

logger = logging.getLogger(__name__)


@dataclass
class ExamAnalysisResult:
    """Result of exam analysis."""
    overall_score: float
    timing_score: float
    form_score: float
    power_score: float
    technique_scores: Dict[str, float]
    pose_corrections: List[Dict]
    strengths: List[str]
    improvements: List[str]
    detailed_feedback: str
    analyzed_at: str


@dataclass
class PoseCorrection:
    """A single pose correction."""
    timestamp: float
    body_part: str
    issue: str
    suggestion: str
    severity: str  # 'low', 'medium', 'high', 'critical'


class ExamAnalyzer:
    """
    AI-powered exam video analyzer.

    Integrates with:
    - comparison_engine.py for technique comparison
    - realtime_pose_corrector.py for skeleton extraction and deviation analysis

    USAGE:
        analyzer = ExamAnalyzer()
        result = await analyzer.analyze_submission(video_url, reference_video_ids)
    """

    def __init__(
        self,
        knowledge_base_path: Optional[str] = None,
        min_confidence: float = 0.5,
        sample_rate: int = 5  # Analyze every N frames
    ):
        """
        Initialize ExamAnalyzer.

        Args:
            knowledge_base_path: Path to knowledge base for reference poses
            min_confidence: Minimum pose detection confidence
            sample_rate: Frame sampling rate for analysis
        """
        self.knowledge_base_path = knowledge_base_path
        self.min_confidence = min_confidence
        self.sample_rate = sample_rate

        # Lazy load heavy dependencies
        self._pose_detector = None
        self._comparison_engine = None
        self._deviation_analyzer = None
        self._feedback_generator = None

        # Analysis settings (can be overridden per-analysis)
        self.settings = {
            'timing_weight': 0.2,
            'form_weight': 0.5,
            'power_weight': 0.3,
            'min_frames_required': 30,
            'max_video_duration': 300,  # 5 minutes max
            'deviation_threshold': 0.15
        }

        logger.info("ExamAnalyzer initialized")

    def _init_pose_detector(self):
        """Lazy initialize pose detector."""
        if self._pose_detector is None:
            try:
                import mediapipe as mp
                self._mp_pose = mp.solutions.pose
                self._pose_detector = self._mp_pose.Pose(
                    static_image_mode=False,
                    model_complexity=2,  # Higher accuracy for exams
                    enable_segmentation=False,
                    min_detection_confidence=self.min_confidence,
                    min_tracking_confidence=self.min_confidence
                )
                logger.info("MediaPipe Pose initialized")
            except ImportError:
                logger.error("MediaPipe not installed")
                raise RuntimeError("MediaPipe required for exam analysis")

    def _init_comparison_engine(self):
        """Lazy initialize comparison engine."""
        if self._comparison_engine is None:
            try:
                from services.video_studio.comparison_engine import ComparisonEngine
                self._comparison_engine = ComparisonEngine(
                    knowledge_base_path=self.knowledge_base_path or "knowledge_base"
                )
                logger.info("ComparisonEngine initialized")
            except ImportError as e:
                logger.warning(f"ComparisonEngine not available: {e}")
                self._comparison_engine = None

    def _init_deviation_analyzer(self):
        """Lazy initialize deviation analyzer."""
        if self._deviation_analyzer is None:
            try:
                from services.video_studio.realtime_pose_corrector import (
                    PoseDeviationAnalyzer,
                    FeedbackGenerator
                )
                self._deviation_analyzer = PoseDeviationAnalyzer()
                self._feedback_generator = FeedbackGenerator()
                logger.info("PoseDeviationAnalyzer initialized")
            except ImportError as e:
                logger.warning(f"PoseDeviationAnalyzer not available: {e}")
                self._deviation_analyzer = None

    async def analyze_submission(
        self,
        video_url: str,
        reference_video_ids: List[str],
        settings_override: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Analyze an exam submission video.

        Args:
            video_url: URL to student's exam video
            reference_video_ids: List of reference video IDs for comparison
            settings_override: Optional settings to override defaults

        Returns:
            Dict with analysis results, score, and feedback
        """
        logger.info(f"Starting analysis for video: {video_url}")

        if settings_override:
            analysis_settings = {**self.settings, **settings_override}
        else:
            analysis_settings = self.settings

        try:
            # Step 1: Download/stream video and extract frames
            video_path = await self._download_video(video_url)

            # Step 2: Extract skeleton data
            skeleton_sequence = await self._extract_skeleton_sequence(video_path)

            if len(skeleton_sequence) < analysis_settings['min_frames_required']:
                logger.warning(f"Insufficient frames: {len(skeleton_sequence)}")
                return self._create_insufficient_data_result()

            # Step 3: Load reference data
            reference_data = await self._load_reference_data(reference_video_ids)

            # Step 4: Compare with references
            comparison_results = await self._compare_with_references(
                skeleton_sequence,
                reference_data
            )

            # Step 5: Analyze pose deviations
            pose_corrections = await self._analyze_deviations(
                skeleton_sequence,
                reference_data
            )

            # Step 6: Calculate scores
            scores = self._calculate_scores(comparison_results, analysis_settings)

            # Step 7: Generate feedback
            analysis_result = self._generate_analysis_result(
                scores,
                comparison_results,
                pose_corrections
            )

            # Cleanup
            if video_path and os.path.exists(video_path):
                os.unlink(video_path)

            logger.info(f"Analysis complete. Score: {analysis_result.overall_score}")

            return {
                'analysis': {
                    'skeleton_data': self._summarize_skeleton(skeleton_sequence),
                    'comparison_results': {
                        'overall_score': scores['overall'],
                        'timing_score': scores['timing'],
                        'form_score': scores['form'],
                        'technique_scores': scores.get('technique_scores', {})
                    },
                    'pose_corrections': [asdict(c) if hasattr(c, '__dict__') else c for c in pose_corrections],
                    'strengths': analysis_result.strengths,
                    'improvements': analysis_result.improvements
                },
                'score': analysis_result.overall_score,
                'feedback': analysis_result.detailed_feedback
            }

        except Exception as e:
            logger.error(f"Analysis failed: {e}", exc_info=True)
            return self._create_error_result(str(e))

    async def _download_video(self, video_url: str) -> str:
        """
        Download video to temporary file.

        Args:
            video_url: URL to video

        Returns:
            Path to downloaded video file
        """
        logger.info(f"Downloading video from: {video_url}")

        # Create temp file
        temp_file = tempfile.NamedTemporaryFile(
            suffix='.mp4',
            delete=False
        )
        temp_path = temp_file.name
        temp_file.close()

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(video_url, timeout=60.0)
                response.raise_for_status()

                with open(temp_path, 'wb') as f:
                    f.write(response.content)

            logger.info(f"Video downloaded to: {temp_path}")
            return temp_path

        except Exception as e:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise RuntimeError(f"Failed to download video: {e}")

    async def _extract_skeleton_sequence(self, video_path: str) -> List[Dict]:
        """
        Extract skeleton sequence from video.

        Args:
            video_path: Path to video file

        Returns:
            List of skeleton frames (each frame is dict of landmark positions)
        """
        self._init_pose_detector()

        skeleton_sequence = []
        cap = cv2.VideoCapture(video_path)

        if not cap.isOpened():
            raise RuntimeError(f"Failed to open video: {video_path}")

        frame_count = 0
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS) or 30

        logger.info(f"Processing video: {total_frames} frames at {fps} fps")

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

        try:
            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                frame_count += 1

                # Sample every N frames
                if frame_count % self.sample_rate != 0:
                    continue

                # Convert BGR to RGB
                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

                # Process with MediaPipe
                results = self._pose_detector.process(frame_rgb)

                if results.pose_landmarks:
                    # Extract landmark positions
                    landmarks = {}
                    for idx, name in landmark_names.items():
                        lm = results.pose_landmarks.landmark[idx]
                        if lm.visibility >= self.min_confidence:
                            landmarks[name] = (lm.x, lm.y, lm.z)

                    skeleton_sequence.append({
                        'frame': frame_count,
                        'timestamp': frame_count / fps,
                        'landmarks': landmarks
                    })

        finally:
            cap.release()

        logger.info(f"Extracted {len(skeleton_sequence)} skeleton frames")
        return skeleton_sequence

    async def _load_reference_data(self, reference_video_ids: List[str]) -> List[Dict]:
        """
        Load reference video data.

        Args:
            reference_video_ids: List of video IDs

        Returns:
            List of reference data dicts
        """
        reference_data = []

        # Try to load from knowledge base
        if self.knowledge_base_path:
            kb_path = Path(self.knowledge_base_path)
            for video_id in reference_video_ids:
                ref_file = kb_path / f"reference_{video_id}.json"
                if ref_file.exists():
                    with open(ref_file, 'r', encoding='utf-8') as f:
                        reference_data.append(json.load(f))
                    logger.info(f"Loaded reference: {video_id}")

        # If no references found, use built-in templates
        if not reference_data:
            logger.warning("No reference videos found, using default templates")
            reference_data = self._get_default_reference_data()

        return reference_data

    def _get_default_reference_data(self) -> List[Dict]:
        """Get default reference data for basic techniques."""
        return [
            {
                'name': 'default_reference',
                'duration': 5.0,
                'skeleton_data': [],
                'key_poses': [
                    {
                        'left_shoulder': (0.4, 0.4, 0.0),
                        'right_shoulder': (0.6, 0.4, 0.0),
                        'left_hip': (0.4, 0.6, 0.0),
                        'right_hip': (0.6, 0.6, 0.0),
                    }
                ],
                'motion_signature': 'default'
            }
        ]

    async def _compare_with_references(
        self,
        skeleton_sequence: List[Dict],
        reference_data: List[Dict]
    ) -> Dict:
        """
        Compare skeleton sequence with reference data.

        Args:
            skeleton_sequence: Extracted skeleton frames
            reference_data: Reference video data

        Returns:
            Comparison results dict
        """
        self._init_comparison_engine()

        if not self._comparison_engine or not reference_data:
            return self._basic_comparison(skeleton_sequence)

        # Prepare student data for comparison engine
        student_data = {
            'name': 'exam_submission',
            'duration': skeleton_sequence[-1]['timestamp'] if skeleton_sequence else 0,
            'skeleton_data': [f['landmarks'] for f in skeleton_sequence if f.get('landmarks')],
            'motion_signature': self._calculate_motion_signature(skeleton_sequence)
        }

        # Compare with each reference
        comparisons = []
        for ref in reference_data:
            try:
                result = self._comparison_engine.compare_techniques(
                    student_data,
                    ref,
                    comparison_mode='detailed'
                )
                comparisons.append(result)
            except Exception as e:
                logger.warning(f"Comparison failed for reference: {e}")

        if not comparisons:
            return self._basic_comparison(skeleton_sequence)

        # Aggregate results
        avg_overall = np.mean([c.overall_similarity for c in comparisons])
        avg_timing = np.mean([c.timing_similarity for c in comparisons])
        avg_form = np.mean([c.form_similarity for c in comparisons])
        avg_power = np.mean([c.power_similarity for c in comparisons])

        # Collect all key differences
        all_differences = []
        for c in comparisons:
            all_differences.extend(c.key_differences)

        # Collect recommendations
        all_recommendations = []
        for c in comparisons:
            all_recommendations.extend(c.recommendations)

        return {
            'overall_similarity': avg_overall,
            'timing_similarity': avg_timing,
            'form_similarity': avg_form,
            'power_similarity': avg_power,
            'key_differences': all_differences,
            'recommendations': list(set(all_recommendations))[:5]
        }

    def _basic_comparison(self, skeleton_sequence: List[Dict]) -> Dict:
        """
        Basic comparison when comparison engine unavailable.

        Analyzes consistency and smoothness of movement.
        """
        if not skeleton_sequence:
            return {
                'overall_similarity': 0.5,
                'timing_similarity': 0.5,
                'form_similarity': 0.5,
                'power_similarity': 0.5,
                'key_differences': [],
                'recommendations': ['Unable to perform detailed comparison']
            }

        # Analyze movement consistency
        consistency_scores = []

        for i in range(1, len(skeleton_sequence)):
            prev = skeleton_sequence[i - 1].get('landmarks', {})
            curr = skeleton_sequence[i].get('landmarks', {})

            if prev and curr:
                # Calculate smoothness (lower change = higher consistency)
                changes = []
                for key in prev:
                    if key in curr:
                        prev_pos = np.array(prev[key])
                        curr_pos = np.array(curr[key])
                        change = np.linalg.norm(curr_pos - prev_pos)
                        changes.append(change)

                if changes:
                    avg_change = np.mean(changes)
                    # Convert to score (smaller change = higher score)
                    consistency = max(0, 1 - avg_change * 5)
                    consistency_scores.append(consistency)

        avg_consistency = np.mean(consistency_scores) if consistency_scores else 0.5

        return {
            'overall_similarity': avg_consistency * 0.8 + 0.1,  # Scale to 0.1-0.9
            'timing_similarity': 0.7,  # Default
            'form_similarity': avg_consistency,
            'power_similarity': 0.7,  # Default
            'key_differences': [],
            'recommendations': [
                'Maintain smooth, controlled movements',
                'Practice consistency in technique execution'
            ]
        }

    async def _analyze_deviations(
        self,
        skeleton_sequence: List[Dict],
        reference_data: List[Dict]
    ) -> List[PoseCorrection]:
        """
        Analyze pose deviations and generate corrections.

        Args:
            skeleton_sequence: Student skeleton frames
            reference_data: Reference data

        Returns:
            List of pose corrections
        """
        self._init_deviation_analyzer()

        corrections = []

        if not self._deviation_analyzer or not reference_data:
            return self._basic_deviation_analysis(skeleton_sequence)

        # Get ideal landmarks from first reference
        if reference_data[0].get('key_poses'):
            ideal_landmarks = reference_data[0]['key_poses'][0]
        else:
            return self._basic_deviation_analysis(skeleton_sequence)

        # Analyze key frames (beginning, middle, end)
        key_frame_indices = [
            0,
            len(skeleton_sequence) // 4,
            len(skeleton_sequence) // 2,
            3 * len(skeleton_sequence) // 4,
            len(skeleton_sequence) - 1
        ]

        for idx in key_frame_indices:
            if idx >= len(skeleton_sequence):
                continue

            frame = skeleton_sequence[idx]
            current_landmarks = frame.get('landmarks', {})

            if not current_landmarks:
                continue

            # Calculate deviations
            deviations = self._deviation_analyzer.calculate_deviations(
                current_landmarks,
                ideal_landmarks
            )

            # Convert to PoseCorrections
            for dev in deviations[:3]:  # Top 3 per frame
                if dev.severity in ['high', 'critical']:
                    corrections.append(PoseCorrection(
                        timestamp=frame.get('timestamp', idx / 30),
                        body_part=dev.landmark_name,
                        issue=f"{dev.landmark_name} deviation: {dev.deviation_degrees:.1f}°",
                        suggestion=dev.correction_text,
                        severity=dev.severity
                    ))

        # Deduplicate similar corrections
        unique_corrections = self._deduplicate_corrections(corrections)

        return unique_corrections[:10]  # Limit to 10 most important

    def _basic_deviation_analysis(self, skeleton_sequence: List[Dict]) -> List[PoseCorrection]:
        """Basic deviation analysis when analyzer unavailable."""
        corrections = []

        if not skeleton_sequence:
            return corrections

        # Analyze for common issues
        issues_detected = set()

        for i, frame in enumerate(skeleton_sequence):
            landmarks = frame.get('landmarks', {})

            if not landmarks:
                continue

            # Check shoulder alignment
            if 'left_shoulder' in landmarks and 'right_shoulder' in landmarks:
                ls = landmarks['left_shoulder']
                rs = landmarks['right_shoulder']
                shoulder_diff = abs(ls[1] - rs[1])

                if shoulder_diff > 0.1 and 'shoulders' not in issues_detected:
                    corrections.append(PoseCorrection(
                        timestamp=frame.get('timestamp', i / 30),
                        body_part='shoulders',
                        issue='Shoulders not level',
                        suggestion='Keep shoulders aligned and level',
                        severity='medium'
                    ))
                    issues_detected.add('shoulders')

            # Check hip alignment
            if 'left_hip' in landmarks and 'right_hip' in landmarks:
                lh = landmarks['left_hip']
                rh = landmarks['right_hip']
                hip_diff = abs(lh[1] - rh[1])

                if hip_diff > 0.1 and 'hips' not in issues_detected:
                    corrections.append(PoseCorrection(
                        timestamp=frame.get('timestamp', i / 30),
                        body_part='hips',
                        issue='Hips not level',
                        suggestion='Maintain stable hip position',
                        severity='medium'
                    ))
                    issues_detected.add('hips')

        return corrections

    def _deduplicate_corrections(self, corrections: List[PoseCorrection]) -> List[PoseCorrection]:
        """Remove duplicate corrections based on body part."""
        seen_parts = set()
        unique = []

        for corr in corrections:
            if corr.body_part not in seen_parts:
                unique.append(corr)
                seen_parts.add(corr.body_part)

        return unique

    def _calculate_scores(
        self,
        comparison_results: Dict,
        settings: Dict
    ) -> Dict[str, float]:
        """
        Calculate final scores from comparison results.

        Args:
            comparison_results: Results from comparison
            settings: Analysis settings

        Returns:
            Dict of scores
        """
        timing = comparison_results.get('timing_similarity', 0.5) * 100
        form = comparison_results.get('form_similarity', 0.5) * 100
        power = comparison_results.get('power_similarity', 0.5) * 100

        # Weighted overall score
        overall = (
            timing * settings['timing_weight'] +
            form * settings['form_weight'] +
            power * settings['power_weight']
        )

        return {
            'overall': round(overall, 1),
            'timing': round(timing, 1),
            'form': round(form, 1),
            'power': round(power, 1),
            'technique_scores': {}
        }

    def _generate_analysis_result(
        self,
        scores: Dict[str, float],
        comparison_results: Dict,
        pose_corrections: List[PoseCorrection]
    ) -> ExamAnalysisResult:
        """
        Generate final analysis result with feedback.

        Args:
            scores: Calculated scores
            comparison_results: Comparison results
            pose_corrections: Pose corrections

        Returns:
            ExamAnalysisResult
        """
        # Identify strengths
        strengths = []
        if scores['timing'] >= 80:
            strengths.append("Excellent timing and rhythm")
        elif scores['timing'] >= 70:
            strengths.append("Good timing control")

        if scores['form'] >= 80:
            strengths.append("Very accurate form and technique")
        elif scores['form'] >= 70:
            strengths.append("Good form execution")

        if scores['power'] >= 80:
            strengths.append("Strong power and energy expression")
        elif scores['power'] >= 70:
            strengths.append("Good power generation")

        if not strengths:
            strengths.append("Showing effort and commitment to practice")

        # Identify improvements
        improvements = []
        if scores['timing'] < 70:
            improvements.append("Work on timing and rhythm consistency")
        if scores['form'] < 70:
            improvements.append("Focus on proper technique form")
        if scores['power'] < 70:
            improvements.append("Develop more power in movements")

        # Add specific improvements from corrections
        for corr in pose_corrections[:3]:
            improvements.append(corr.suggestion)

        # Add recommendations from comparison
        recommendations = comparison_results.get('recommendations', [])
        improvements.extend([r for r in recommendations if r not in improvements][:2])

        # Generate detailed feedback
        feedback = self._generate_feedback_text(scores, strengths, improvements)

        return ExamAnalysisResult(
            overall_score=scores['overall'],
            timing_score=scores['timing'],
            form_score=scores['form'],
            power_score=scores['power'],
            technique_scores=scores.get('technique_scores', {}),
            pose_corrections=[asdict(c) if hasattr(c, '__dict__') else c for c in pose_corrections],
            strengths=strengths,
            improvements=improvements[:5],
            detailed_feedback=feedback,
            analyzed_at=datetime.utcnow().isoformat()
        )

    def _generate_feedback_text(
        self,
        scores: Dict[str, float],
        strengths: List[str],
        improvements: List[str]
    ) -> str:
        """Generate human-readable feedback text."""
        overall = scores['overall']

        # Opening
        if overall >= 90:
            opening = "Excellent performance! You demonstrate mastery of this technique."
        elif overall >= 80:
            opening = "Very good execution. You show strong understanding of the technique."
        elif overall >= 70:
            opening = "Good effort. Your technique shows promise with some areas to refine."
        elif overall >= 60:
            opening = "Decent attempt. Continue practicing to improve your execution."
        else:
            opening = "Keep practicing. Focus on the fundamentals to build a strong foundation."

        # Build feedback
        feedback_parts = [opening]

        if strengths:
            feedback_parts.append(f"\nStrengths: {', '.join(strengths[:3])}")

        if improvements:
            feedback_parts.append(f"\nAreas to improve: {', '.join(improvements[:3])}")

        # Closing
        if overall >= 70:
            feedback_parts.append("\nGreat work! Keep up the practice.")
        else:
            feedback_parts.append("\nDon't give up! Consistent practice will lead to improvement.")

        return ' '.join(feedback_parts)

    def _calculate_motion_signature(self, skeleton_sequence: List[Dict]) -> str:
        """Calculate motion signature for comparison."""
        if not skeleton_sequence:
            return ""

        # Simple signature based on key movements
        signature_parts = []

        for i in range(0, len(skeleton_sequence), 5):
            frame = skeleton_sequence[i]
            landmarks = frame.get('landmarks', {})

            if 'right_wrist' in landmarks:
                wrist = landmarks['right_wrist']
                # Encode position as character
                char = chr(int(wrist[0] * 26) + 65)  # A-Z based on x position
                signature_parts.append(char)

        return ''.join(signature_parts[:20])

    def _summarize_skeleton(self, skeleton_sequence: List[Dict]) -> Dict:
        """Create summary of skeleton data for storage."""
        if not skeleton_sequence:
            return {'frames': 0}

        return {
            'frames': len(skeleton_sequence),
            'duration': skeleton_sequence[-1].get('timestamp', 0) if skeleton_sequence else 0,
            'landmarks_per_frame': len(skeleton_sequence[0].get('landmarks', {})) if skeleton_sequence else 0,
            'sample_rate': self.sample_rate
        }

    def _create_insufficient_data_result(self) -> Dict:
        """Create result for insufficient video data."""
        return {
            'analysis': {
                'skeleton_data': {},
                'comparison_results': {'overall_score': 0},
                'pose_corrections': [],
                'strengths': [],
                'improvements': ['Video too short or no person detected']
            },
            'score': 0,
            'feedback': "Unable to analyze video. Please ensure the video clearly shows the full technique execution."
        }

    def _create_error_result(self, error_message: str) -> Dict:
        """Create result for analysis error."""
        return {
            'analysis': {
                'skeleton_data': {},
                'comparison_results': {'overall_score': 0},
                'pose_corrections': [],
                'strengths': [],
                'improvements': ['Analysis error - please try again']
            },
            'score': 0,
            'feedback': f"Analysis error: {error_message}. Please try submitting again."
        }

    def cleanup(self):
        """Cleanup resources."""
        if self._pose_detector:
            self._pose_detector.close()
            self._pose_detector = None
        logger.info("ExamAnalyzer cleaned up")


# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

async def analyze_exam_video(video_url: str, reference_ids: List[str]) -> Dict:
    """
    Convenience function to analyze an exam video.

    Args:
        video_url: URL to exam video
        reference_ids: List of reference video IDs

    Returns:
        Analysis results
    """
    analyzer = ExamAnalyzer()
    try:
        return await analyzer.analyze_submission(video_url, reference_ids)
    finally:
        analyzer.cleanup()

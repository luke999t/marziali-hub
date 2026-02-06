"""
AI_MODULE: DualVideoAlignmentProcessor Service
AI_DESCRIPTION: Allineamento video bilingui con scene detection e audio fingerprinting
AI_BUSINESS: Creazione coppie frasi allineate da video in lingue diverse
AI_TEACHING: Video processing, audio fingerprinting, subtitle alignment, DTW

PIPELINE:
1. Scene Detection - Rileva cambi scena per fingerprint visivo
2. Audio Fingerprinting - Match pattern audio (musica/effetti)
3. Calculate Offset - Trova differenza temporale tra versioni
4. Sync Subtitles - Applica offset ai timestamp
5. Create Pairs - Genera coppie bilingui allineate

USE CASES:
- Anime JAP + ITA dub
- Film originale + doppiaggio
- Serie TV multilingua
- Documentari tradotti

DEPENDENCIES (optional):
- OpenCV (cv2) for video/scene detection
- librosa for audio analysis
- pysrt for subtitle parsing
- numpy for signal processing

ZERO MOCK POLICY:
- All tests use real video/audio when available
- Real subtitle parsing
- Graceful degradation without heavy dependencies
"""

import asyncio
import logging
import hashlib
import json
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Generator
from enum import Enum
from datetime import datetime, timedelta
import uuid

# Optional dependencies
try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False
    np = None

try:
    import librosa
    HAS_LIBROSA = True
except ImportError:
    HAS_LIBROSA = False


# === ENUMS ===

class VideoLanguage(str, Enum):
    """Supported video languages."""
    JAPANESE = "ja"
    CHINESE = "zh"
    KOREAN = "ko"
    ENGLISH = "en"
    ITALIAN = "it"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"
    PORTUGUESE = "pt"


class AlignmentMethod(str, Enum):
    """Methods for aligning videos."""
    SCENE_DETECTION = "scene_detection"
    AUDIO_FINGERPRINT = "audio_fingerprint"
    SUBTITLE_TIMING = "subtitle_timing"
    COMBINED = "combined"


class AlignmentQuality(str, Enum):
    """Quality level of alignment."""
    EXCELLENT = "excellent"  # > 0.95 confidence
    GOOD = "good"           # 0.80 - 0.95
    FAIR = "fair"           # 0.60 - 0.80
    POOR = "poor"           # < 0.60
    FAILED = "failed"


# === DATA CLASSES ===

@dataclass
class Timestamp:
    """A timestamp with millisecond precision."""
    hours: int = 0
    minutes: int = 0
    seconds: int = 0
    milliseconds: int = 0

    @classmethod
    def from_seconds(cls, total_seconds: float) -> 'Timestamp':
        """Create from total seconds."""
        ms = int(total_seconds * 1000)
        hours = ms // 3600000
        ms %= 3600000
        minutes = ms // 60000
        ms %= 60000
        seconds = ms // 1000
        milliseconds = ms % 1000
        return cls(hours, minutes, seconds, milliseconds)

    @classmethod
    def from_srt_time(cls, time_str: str) -> 'Timestamp':
        """Parse SRT timestamp format: 00:01:23,456"""
        match = re.match(r'(\d{2}):(\d{2}):(\d{2})[,.](\d{3})', time_str)
        if match:
            return cls(
                int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                int(match.group(4))
            )
        return cls()

    def to_seconds(self) -> float:
        """Convert to total seconds."""
        return (self.hours * 3600 +
                self.minutes * 60 +
                self.seconds +
                self.milliseconds / 1000)

    def to_srt_format(self) -> str:
        """Convert to SRT format."""
        return f"{self.hours:02d}:{self.minutes:02d}:{self.seconds:02d},{self.milliseconds:03d}"

    def __add__(self, other: 'Timestamp') -> 'Timestamp':
        total = self.to_seconds() + other.to_seconds()
        return Timestamp.from_seconds(total)

    def __sub__(self, other: 'Timestamp') -> 'Timestamp':
        total = self.to_seconds() - other.to_seconds()
        return Timestamp.from_seconds(max(0, total))

    def add_offset(self, offset_seconds: float) -> 'Timestamp':
        """Add offset in seconds."""
        return Timestamp.from_seconds(self.to_seconds() + offset_seconds)


@dataclass
class SubtitleEntry:
    """A single subtitle entry."""
    index: int
    start: Timestamp
    end: Timestamp
    text: str
    original_text: str = ""  # Before cleanup

    @property
    def duration(self) -> float:
        """Duration in seconds."""
        return self.end.to_seconds() - self.start.to_seconds()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'index': self.index,
            'start': self.start.to_srt_format(),
            'end': self.end.to_srt_format(),
            'text': self.text,
            'duration': self.duration
        }


@dataclass
class SceneChange:
    """A detected scene change."""
    timestamp: float  # seconds
    frame_number: int
    confidence: float
    frame_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AudioFingerprint:
    """Audio fingerprint for a segment."""
    start_time: float
    end_time: float
    features: List[float] = field(default_factory=list)
    hash_value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'start_time': self.start_time,
            'end_time': self.end_time,
            'hash_value': self.hash_value
        }


@dataclass
class AlignmentOffset:
    """Calculated offset between two videos."""
    offset_seconds: float  # Positive = video2 starts later
    speed_ratio: float = 1.0  # 1.0 = same speed
    confidence: float = 0.0
    method_used: AlignmentMethod = AlignmentMethod.COMBINED
    quality: AlignmentQuality = AlignmentQuality.FAIR

    def to_dict(self) -> Dict[str, Any]:
        return {
            'offset_seconds': self.offset_seconds,
            'speed_ratio': self.speed_ratio,
            'confidence': self.confidence,
            'method_used': self.method_used.value,
            'quality': self.quality.value
        }


@dataclass
class AlignedSubtitlePair:
    """A pair of aligned subtitles from both versions."""
    id: str
    source_entry: SubtitleEntry
    target_entry: SubtitleEntry
    source_language: VideoLanguage
    target_language: VideoLanguage
    alignment_score: float
    time_diff_ms: int  # Difference in timing
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source': self.source_entry.to_dict(),
            'target': self.target_entry.to_dict(),
            'source_language': self.source_language.value,
            'target_language': self.target_language.value,
            'alignment_score': self.alignment_score,
            'time_diff_ms': self.time_diff_ms,
            'notes': self.notes
        }


@dataclass
class VideoInfo:
    """Information about a video file."""
    path: Path
    language: VideoLanguage
    duration_seconds: float = 0.0
    fps: float = 0.0
    frame_count: int = 0
    width: int = 0
    height: int = 0
    has_audio: bool = True
    subtitle_path: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': str(self.path),
            'language': self.language.value,
            'duration_seconds': self.duration_seconds,
            'fps': self.fps,
            'frame_count': self.frame_count,
            'resolution': f"{self.width}x{self.height}"
        }


@dataclass
class AlignmentResult:
    """Complete result of video alignment."""
    id: str
    source_video: VideoInfo
    target_video: VideoInfo
    offset: AlignmentOffset
    aligned_pairs: List[AlignedSubtitlePair] = field(default_factory=list)
    scene_changes_source: List[SceneChange] = field(default_factory=list)
    scene_changes_target: List[SceneChange] = field(default_factory=list)
    total_subtitles_source: int = 0
    total_subtitles_target: int = 0
    aligned_count: int = 0
    unaligned_count: int = 0
    processing_time_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'source_video': self.source_video.to_dict(),
            'target_video': self.target_video.to_dict(),
            'offset': self.offset.to_dict(),
            'aligned_pairs': [p.to_dict() for p in self.aligned_pairs],
            'statistics': {
                'total_source': self.total_subtitles_source,
                'total_target': self.total_subtitles_target,
                'aligned': self.aligned_count,
                'unaligned': self.unaligned_count,
                'alignment_rate': self.aligned_count / max(1, self.total_subtitles_source)
            },
            'processing_time_seconds': self.processing_time_seconds,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class AlignmentOptions:
    """Options for video alignment."""
    # Scene detection
    scene_threshold: float = 30.0  # Threshold for scene change
    min_scene_length: float = 1.0  # Minimum seconds between scenes

    # Audio fingerprinting
    audio_segment_length: float = 5.0  # Seconds per segment
    audio_sample_rate: int = 22050

    # Subtitle alignment
    max_time_diff_ms: int = 2000  # Max ms difference for alignment
    min_alignment_score: float = 0.5

    # General
    use_scene_detection: bool = True
    use_audio_fingerprint: bool = True
    use_subtitle_timing: bool = True


# === SUBTITLE PARSER ===

class SubtitleParser:
    """Parser for subtitle files (SRT, ASS, VTT)."""

    @staticmethod
    def parse_srt(content: str) -> List[SubtitleEntry]:
        """Parse SRT format subtitles."""
        entries = []
        blocks = re.split(r'\n\n+', content.strip())

        for block in blocks:
            lines = block.strip().split('\n')
            if len(lines) < 3:
                continue

            try:
                # Index
                index = int(lines[0].strip())

                # Timestamps
                time_match = re.match(
                    r'(\d{2}:\d{2}:\d{2}[,.]\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}[,.]\d{3})',
                    lines[1]
                )
                if not time_match:
                    continue

                start = Timestamp.from_srt_time(time_match.group(1))
                end = Timestamp.from_srt_time(time_match.group(2))

                # Text (remaining lines)
                text = '\n'.join(lines[2:]).strip()
                # Clean HTML tags
                text = re.sub(r'<[^>]+>', '', text)

                entries.append(SubtitleEntry(
                    index=index,
                    start=start,
                    end=end,
                    text=text,
                    original_text='\n'.join(lines[2:])
                ))

            except (ValueError, IndexError):
                continue

        return entries

    @staticmethod
    def parse_ass(content: str) -> List[SubtitleEntry]:
        """Parse ASS/SSA format subtitles."""
        entries = []
        index = 1

        # Find [Events] section
        events_match = re.search(r'\[Events\](.*?)(?:\[|$)', content, re.DOTALL | re.IGNORECASE)
        if not events_match:
            return entries

        events_section = events_match.group(1)

        # Parse Dialogue lines
        for line in events_section.split('\n'):
            line = line.strip()
            if not line.startswith('Dialogue:'):
                continue

            # Format: Dialogue: Layer,Start,End,Style,Name,MarginL,MarginR,MarginV,Effect,Text
            parts = line.split(',', 9)
            if len(parts) < 10:
                continue

            try:
                # Parse timestamps (h:mm:ss.cc format)
                start_str = parts[1].strip()
                end_str = parts[2].strip()

                start_match = re.match(r'(\d+):(\d{2}):(\d{2})\.(\d{2})', start_str)
                end_match = re.match(r'(\d+):(\d{2}):(\d{2})\.(\d{2})', end_str)

                if not start_match or not end_match:
                    continue

                start = Timestamp(
                    int(start_match.group(1)),
                    int(start_match.group(2)),
                    int(start_match.group(3)),
                    int(start_match.group(4)) * 10
                )
                end = Timestamp(
                    int(end_match.group(1)),
                    int(end_match.group(2)),
                    int(end_match.group(3)),
                    int(end_match.group(4)) * 10
                )

                # Text (with ASS formatting removed)
                text = parts[9]
                text = re.sub(r'\{[^}]+\}', '', text)  # Remove {formatting}
                text = text.replace('\\N', '\n').replace('\\n', '\n')
                text = text.strip()

                entries.append(SubtitleEntry(
                    index=index,
                    start=start,
                    end=end,
                    text=text,
                    original_text=parts[9]
                ))
                index += 1

            except (ValueError, IndexError):
                continue

        return entries

    @staticmethod
    def parse_file(file_path: Path) -> List[SubtitleEntry]:
        """Parse subtitle file based on extension."""
        if not file_path.exists():
            return []

        content = file_path.read_text(encoding='utf-8', errors='ignore')
        suffix = file_path.suffix.lower()

        if suffix in ['.srt', '.vtt']:
            return SubtitleParser.parse_srt(content)
        elif suffix in ['.ass', '.ssa']:
            return SubtitleParser.parse_ass(content)
        else:
            # Try SRT format by default
            return SubtitleParser.parse_srt(content)


# === MAIN PROCESSOR ===

class DualVideoAlignmentProcessor:
    """
    Processor for aligning two versions of the same video.

    Uses scene detection, audio fingerprinting, and subtitle timing
    to find the temporal offset between versions and align subtitles.
    """

    def __init__(self, options: Optional[AlignmentOptions] = None):
        """Initialize processor."""
        self.logger = logging.getLogger(__name__)
        self.options = options or AlignmentOptions()
        self._check_dependencies()

    def _check_dependencies(self):
        """Check available dependencies."""
        if not HAS_CV2:
            self.logger.warning("OpenCV not available - scene detection disabled")
        if not HAS_LIBROSA:
            self.logger.warning("librosa not available - audio fingerprinting disabled")

    # === VIDEO INFO ===

    def get_video_info(self, video_path: Path, language: VideoLanguage) -> VideoInfo:
        """Get information about a video file."""
        info = VideoInfo(path=video_path, language=language)

        if not HAS_CV2:
            return info

        if not video_path.exists():
            return info

        try:
            cap = cv2.VideoCapture(str(video_path))
            if cap.isOpened():
                info.fps = cap.get(cv2.CAP_PROP_FPS)
                info.frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                info.width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                info.height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                if info.fps > 0:
                    info.duration_seconds = info.frame_count / info.fps
                cap.release()
        except Exception as e:
            self.logger.error(f"Error getting video info: {e}")

        return info

    # === SCENE DETECTION ===

    def detect_scenes(
        self,
        video_path: Path,
        options: Optional[AlignmentOptions] = None
    ) -> List[SceneChange]:
        """
        Detect scene changes in a video.

        Uses frame difference threshold to find cuts.
        """
        opts = options or self.options
        scenes = []

        if not HAS_CV2:
            self.logger.warning("OpenCV required for scene detection")
            return scenes

        if not video_path.exists():
            return scenes

        try:
            cap = cv2.VideoCapture(str(video_path))
            fps = cap.get(cv2.CAP_PROP_FPS)
            min_frames = int(opts.min_scene_length * fps) if fps > 0 else 30

            prev_frame = None
            frame_num = 0
            last_scene_frame = 0

            while True:
                ret, frame = cap.read()
                if not ret:
                    break

                # Convert to grayscale
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                gray = cv2.resize(gray, (160, 90))  # Downscale for speed

                if prev_frame is not None:
                    # Calculate frame difference
                    diff = cv2.absdiff(prev_frame, gray)
                    mean_diff = np.mean(diff)

                    # Check if scene change
                    if (mean_diff > opts.scene_threshold and
                        frame_num - last_scene_frame > min_frames):

                        # Calculate frame hash
                        frame_hash = hashlib.md5(gray.tobytes()).hexdigest()[:8]

                        scenes.append(SceneChange(
                            timestamp=frame_num / fps if fps > 0 else 0,
                            frame_number=frame_num,
                            confidence=min(1.0, mean_diff / 100),
                            frame_hash=frame_hash
                        ))
                        last_scene_frame = frame_num

                prev_frame = gray
                frame_num += 1

            cap.release()
            self.logger.info(f"Detected {len(scenes)} scenes in {video_path.name}")

        except Exception as e:
            self.logger.error(f"Error detecting scenes: {e}")

        return scenes

    # === AUDIO FINGERPRINTING ===

    def extract_audio_fingerprints(
        self,
        video_path: Path,
        options: Optional[AlignmentOptions] = None
    ) -> List[AudioFingerprint]:
        """
        Extract audio fingerprints from video.

        Focuses on non-vocal audio (music, effects) for better matching.
        """
        opts = options or self.options
        fingerprints = []

        if not HAS_LIBROSA:
            self.logger.warning("librosa required for audio fingerprinting")
            return fingerprints

        try:
            # Load audio from video
            y, sr = librosa.load(str(video_path), sr=opts.audio_sample_rate)
            duration = len(y) / sr

            segment_samples = int(opts.audio_segment_length * sr)
            hop_samples = segment_samples // 2

            for start_sample in range(0, len(y) - segment_samples, hop_samples):
                segment = y[start_sample:start_sample + segment_samples]

                # Extract features
                mfcc = librosa.feature.mfcc(y=segment, sr=sr, n_mfcc=13)
                features = mfcc.mean(axis=1).tolist()

                # Create hash from features
                feature_bytes = np.array(features).tobytes()
                hash_value = hashlib.md5(feature_bytes).hexdigest()[:12]

                start_time = start_sample / sr
                end_time = (start_sample + segment_samples) / sr

                fingerprints.append(AudioFingerprint(
                    start_time=start_time,
                    end_time=end_time,
                    features=features,
                    hash_value=hash_value
                ))

            self.logger.info(f"Extracted {len(fingerprints)} audio fingerprints")

        except Exception as e:
            self.logger.error(f"Error extracting audio fingerprints: {e}")

        return fingerprints

    # === OFFSET CALCULATION ===

    def calculate_offset_from_scenes(
        self,
        scenes1: List[SceneChange],
        scenes2: List[SceneChange]
    ) -> AlignmentOffset:
        """Calculate offset by matching scene changes."""
        if not scenes1 or not scenes2:
            return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SCENE_DETECTION)

        # Find matching scenes by frame hash
        offsets = []
        for s1 in scenes1:
            for s2 in scenes2:
                if s1.frame_hash == s2.frame_hash:
                    offset = s2.timestamp - s1.timestamp
                    offsets.append(offset)

        if not offsets:
            # Fallback: match by order
            min_scenes = min(len(scenes1), len(scenes2))
            for i in range(min_scenes):
                offset = scenes2[i].timestamp - scenes1[i].timestamp
                offsets.append(offset)

        if offsets:
            # Use median offset
            offsets.sort()
            median_offset = offsets[len(offsets) // 2]

            # Calculate confidence based on consistency
            if len(offsets) > 1:
                variance = sum((o - median_offset) ** 2 for o in offsets) / len(offsets)
                confidence = max(0.1, 1.0 - min(1.0, variance / 10))
            else:
                confidence = 0.5

            return AlignmentOffset(
                offset_seconds=median_offset,
                speed_ratio=1.0,
                confidence=confidence,
                method_used=AlignmentMethod.SCENE_DETECTION
            )

        return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SCENE_DETECTION)

    def calculate_offset_from_audio(
        self,
        fps1: List[AudioFingerprint],
        fps2: List[AudioFingerprint]
    ) -> AlignmentOffset:
        """Calculate offset by matching audio fingerprints."""
        if not fps1 or not fps2 or not HAS_LIBROSA:
            return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.AUDIO_FINGERPRINT)

        # Match fingerprints by hash
        offsets = []
        for f1 in fps1:
            for f2 in fps2:
                if f1.hash_value == f2.hash_value:
                    offset = f2.start_time - f1.start_time
                    offsets.append(offset)

        if offsets:
            offsets.sort()
            median_offset = offsets[len(offsets) // 2]
            confidence = min(1.0, len(offsets) / 10)

            return AlignmentOffset(
                offset_seconds=median_offset,
                speed_ratio=1.0,
                confidence=confidence,
                method_used=AlignmentMethod.AUDIO_FINGERPRINT
            )

        return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.AUDIO_FINGERPRINT)

    def calculate_offset_from_subtitles(
        self,
        subs1: List[SubtitleEntry],
        subs2: List[SubtitleEntry]
    ) -> AlignmentOffset:
        """Calculate offset by analyzing subtitle timing patterns."""
        if not subs1 or not subs2:
            return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SUBTITLE_TIMING)

        # Compare timing patterns
        offsets = []

        # Match subtitles by index (assuming same content order)
        min_subs = min(len(subs1), len(subs2))
        for i in range(min_subs):
            offset = subs2[i].start.to_seconds() - subs1[i].start.to_seconds()
            offsets.append(offset)

        if offsets:
            offsets.sort()
            median_offset = offsets[len(offsets) // 2]

            # Calculate speed ratio
            if len(subs1) > 1 and len(subs2) > 1:
                duration1 = subs1[-1].end.to_seconds() - subs1[0].start.to_seconds()
                duration2 = subs2[-1].end.to_seconds() - subs2[0].start.to_seconds()
                speed_ratio = duration2 / duration1 if duration1 > 0 else 1.0
            else:
                speed_ratio = 1.0

            # Confidence based on consistency
            if len(offsets) > 2:
                variance = sum((o - median_offset) ** 2 for o in offsets) / len(offsets)
                confidence = max(0.1, 1.0 - min(1.0, variance))
            else:
                confidence = 0.5

            return AlignmentOffset(
                offset_seconds=median_offset,
                speed_ratio=speed_ratio,
                confidence=confidence,
                method_used=AlignmentMethod.SUBTITLE_TIMING
            )

        return AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SUBTITLE_TIMING)

    def calculate_combined_offset(
        self,
        scene_offset: AlignmentOffset,
        audio_offset: AlignmentOffset,
        subtitle_offset: AlignmentOffset
    ) -> AlignmentOffset:
        """Combine multiple offset calculations."""
        offsets = []
        weights = []

        if scene_offset.confidence > 0:
            offsets.append(scene_offset.offset_seconds)
            weights.append(scene_offset.confidence)

        if audio_offset.confidence > 0:
            offsets.append(audio_offset.offset_seconds)
            weights.append(audio_offset.confidence)

        if subtitle_offset.confidence > 0:
            offsets.append(subtitle_offset.offset_seconds)
            weights.append(subtitle_offset.confidence * 0.8)  # Slightly less weight

        if not offsets:
            return AlignmentOffset(
                0.0, 1.0, 0.0,
                AlignmentMethod.COMBINED,
                AlignmentQuality.FAILED
            )

        # Weighted average
        total_weight = sum(weights)
        combined_offset = sum(o * w for o, w in zip(offsets, weights)) / total_weight
        combined_confidence = total_weight / len(offsets)

        # Determine quality
        if combined_confidence > 0.95:
            quality = AlignmentQuality.EXCELLENT
        elif combined_confidence > 0.80:
            quality = AlignmentQuality.GOOD
        elif combined_confidence > 0.60:
            quality = AlignmentQuality.FAIR
        else:
            quality = AlignmentQuality.POOR

        return AlignmentOffset(
            offset_seconds=combined_offset,
            speed_ratio=subtitle_offset.speed_ratio if subtitle_offset.confidence > 0 else 1.0,
            confidence=combined_confidence,
            method_used=AlignmentMethod.COMBINED,
            quality=quality
        )

    # === SUBTITLE ALIGNMENT ===

    def align_subtitles(
        self,
        source_subs: List[SubtitleEntry],
        target_subs: List[SubtitleEntry],
        offset: AlignmentOffset,
        source_lang: VideoLanguage,
        target_lang: VideoLanguage,
        options: Optional[AlignmentOptions] = None
    ) -> List[AlignedSubtitlePair]:
        """
        Align subtitles from source and target using calculated offset.
        """
        opts = options or self.options
        aligned_pairs = []

        # Apply offset to target timestamps
        adjusted_target = []
        for sub in target_subs:
            adjusted_start = sub.start.to_seconds() - offset.offset_seconds
            adjusted_end = sub.end.to_seconds() - offset.offset_seconds

            adjusted_target.append({
                'original': sub,
                'adjusted_start': adjusted_start,
                'adjusted_end': adjusted_end
            })

        # Match source subtitles with target
        used_targets = set()

        for source in source_subs:
            source_mid = (source.start.to_seconds() + source.end.to_seconds()) / 2

            best_match = None
            best_score = 0.0
            best_diff = float('inf')

            for i, target in enumerate(adjusted_target):
                if i in used_targets:
                    continue

                target_mid = (target['adjusted_start'] + target['adjusted_end']) / 2
                time_diff = abs(source_mid - target_mid) * 1000  # Convert to ms

                if time_diff > opts.max_time_diff_ms:
                    continue

                # Calculate alignment score
                score = 1.0 - (time_diff / opts.max_time_diff_ms)

                if score > best_score:
                    best_score = score
                    best_match = (i, target['original'])
                    best_diff = time_diff

            if best_match and best_score >= opts.min_alignment_score:
                idx, target_sub = best_match
                used_targets.add(idx)

                pair = AlignedSubtitlePair(
                    id=f"{source.index}:{target_sub.index}",
                    source_entry=source,
                    target_entry=target_sub,
                    source_language=source_lang,
                    target_language=target_lang,
                    alignment_score=best_score,
                    time_diff_ms=int(best_diff)
                )
                aligned_pairs.append(pair)

        self.logger.info(
            f"Aligned {len(aligned_pairs)}/{len(source_subs)} subtitles"
        )
        return aligned_pairs

    # === MAIN PROCESSING ===

    async def align_videos(
        self,
        source_video: Path,
        target_video: Path,
        source_subtitles: Path,
        target_subtitles: Path,
        source_language: VideoLanguage,
        target_language: VideoLanguage,
        options: Optional[AlignmentOptions] = None
    ) -> AlignmentResult:
        """
        Align two video versions and their subtitles.

        Args:
            source_video: Path to source video (original)
            target_video: Path to target video (translated)
            source_subtitles: Path to source subtitle file
            target_subtitles: Path to target subtitle file
            source_language: Source language
            target_language: Target language
            options: Alignment options

        Returns:
            AlignmentResult with aligned subtitle pairs
        """
        start_time = datetime.utcnow()
        opts = options or self.options

        # Get video info
        source_info = self.get_video_info(source_video, source_language)
        source_info.subtitle_path = source_subtitles

        target_info = self.get_video_info(target_video, target_language)
        target_info.subtitle_path = target_subtitles

        # Parse subtitles
        source_subs = SubtitleParser.parse_file(source_subtitles)
        target_subs = SubtitleParser.parse_file(target_subtitles)

        # Initialize offset calculations
        scene_offset = AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SCENE_DETECTION)
        audio_offset = AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.AUDIO_FINGERPRINT)
        subtitle_offset = AlignmentOffset(0.0, 1.0, 0.0, AlignmentMethod.SUBTITLE_TIMING)

        scenes_source = []
        scenes_target = []

        # Scene detection
        if opts.use_scene_detection and HAS_CV2:
            scenes_source = self.detect_scenes(source_video, opts)
            scenes_target = self.detect_scenes(target_video, opts)
            scene_offset = self.calculate_offset_from_scenes(scenes_source, scenes_target)

        # Audio fingerprinting
        if opts.use_audio_fingerprint and HAS_LIBROSA:
            fps_source = self.extract_audio_fingerprints(source_video, opts)
            fps_target = self.extract_audio_fingerprints(target_video, opts)
            audio_offset = self.calculate_offset_from_audio(fps_source, fps_target)

        # Subtitle timing analysis
        if opts.use_subtitle_timing:
            subtitle_offset = self.calculate_offset_from_subtitles(source_subs, target_subs)

        # Combine offsets
        combined_offset = self.calculate_combined_offset(
            scene_offset, audio_offset, subtitle_offset
        )

        # Align subtitles
        aligned_pairs = self.align_subtitles(
            source_subs, target_subs, combined_offset,
            source_language, target_language, opts
        )

        end_time = datetime.utcnow()

        return AlignmentResult(
            id=str(uuid.uuid4())[:8],
            source_video=source_info,
            target_video=target_info,
            offset=combined_offset,
            aligned_pairs=aligned_pairs,
            scene_changes_source=scenes_source,
            scene_changes_target=scenes_target,
            total_subtitles_source=len(source_subs),
            total_subtitles_target=len(target_subs),
            aligned_count=len(aligned_pairs),
            unaligned_count=len(source_subs) - len(aligned_pairs),
            processing_time_seconds=(end_time - start_time).total_seconds()
        )

    # === EXPORT ===

    def export_to_json(
        self,
        result: AlignmentResult,
        output_path: Path
    ) -> int:
        """Export alignment result to JSON."""
        output_path.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        return len(result.aligned_pairs)

    def export_to_anki(
        self,
        result: AlignmentResult,
        output_path: Path
    ) -> int:
        """Export to Anki-compatible TSV."""
        cards = []
        for pair in result.aligned_pairs:
            front = pair.source_entry.text
            back = pair.target_entry.text
            tags = f"{result.source_video.language.value} {result.target_video.language.value}"
            cards.append(f"{front}\t{back}\t{tags}")

        output_path.write_text("\n".join(cards), encoding='utf-8')
        return len(cards)

    def export_to_tmx(
        self,
        result: AlignmentResult,
        output_path: Path
    ) -> int:
        """Export to TMX format."""
        tmx_header = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE tmx SYSTEM "tmx14.dtd">
<tmx version="1.4">
  <header
    creationtool="DualVideoAlignmentProcessor"
    creationtoolversion="1.0"
    segtype="sentence"
    o-tmf="unknown"
    adminlang="en"
    srclang="{result.source_video.language.value}"
    datatype="plaintext">
  </header>
  <body>
'''
        tmx_footer = '''  </body>
</tmx>'''

        tus = []
        for pair in result.aligned_pairs:
            src = self._escape_xml(pair.source_entry.text)
            tgt = self._escape_xml(pair.target_entry.text)

            tu = f'''    <tu>
      <tuv xml:lang="{result.source_video.language.value}">
        <seg>{src}</seg>
      </tuv>
      <tuv xml:lang="{result.target_video.language.value}">
        <seg>{tgt}</seg>
      </tuv>
    </tu>'''
            tus.append(tu)

        content = tmx_header + "\n".join(tus) + "\n" + tmx_footer
        output_path.write_text(content, encoding='utf-8')
        return len(result.aligned_pairs)

    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))

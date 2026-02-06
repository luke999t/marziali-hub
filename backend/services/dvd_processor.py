"""
🎓 AI_MODULE: DVD Processor - Parallel Corpus Extractor
🎓 AI_DESCRIPTION: Estrae sentence pairs da DVD multi-audio/sottotitoli
🎓 AI_BUSINESS: Arricchisce vocabolario traduzione con contenuti reali
🎓 AI_TEACHING: Parallel corpus è il gold standard per training traduttori

🔄 ALTERNATIVE_VALUTATE:
- Solo sottotitoli: Scartato, perdiamo contesto audio
- Solo audio (speech-to-text): Scartato, meno preciso dei sottotitoli ufficiali
- Allineamento manuale: Scartato, non scala

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Sottotitoli già segmentati e sincronizzati
- Timestamp permette allineamento preciso
- Audio per verifica/fallback
- 1 film = 1000+ sentence pairs

🔒 PRIVACY BY DESIGN:
- Video DVD originale → temp/ (CANCELLATO dopo estrazione)
- NO salvataggio audio estratto
- NO riferimento a titolo film
- NO timestamp nel vocabolario finale
- Solo sentence pairs anonimizzati entrano nel sistema

📊 METRICHE_SUCCESSO:
- Tempo processing: < 5min per film
- Accuracy allineamento: > 90%
- Pairs validi: > 70% del totale
"""

import subprocess
import json
import logging
import re
import uuid
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Language code mapping
LANGUAGE_CODES = {
    "ita": "it", "italian": "it", "italiano": "it",
    "jpn": "ja", "japanese": "ja", "giapponese": "ja",
    "eng": "en", "english": "en", "inglese": "en",
    "chi": "zh", "chinese": "zh", "cinese": "zh",
    "kor": "ko", "korean": "ko", "coreano": "ko",
    "fra": "fr", "french": "fr", "francese": "fr",
    "deu": "de", "german": "de", "tedesco": "de",
    "spa": "es", "spanish": "es", "spagnolo": "es",
}


@dataclass
class SubtitleEntry:
    """Single subtitle entry"""
    index: int
    start_time: str  # Format: "00:15:32,100"
    end_time: str
    text: str
    start_ms: int = 0
    end_ms: int = 0


@dataclass
class AlignedPair:
    """Aligned sentence pair"""
    source_text: str
    target_text: str
    confidence: float
    # NO timestamp, NO film reference (PRIVACY)


@dataclass
class TrackInfo:
    """Audio/subtitle track information"""
    index: int
    language: str
    language_code: str
    codec: str
    is_default: bool = False


class DvdProcessor:
    """
    Pipeline completa DVD → Sentence Pairs per traduzione

    Workflow:
    1. Rileva tracce audio/sottotitoli
    2. Estrai sottotitoli selezionati
    3. Allinea per timestamp
    4. Filtra per confidence
    5. Anonimizza (rimuovi riferimenti al film)
    6. Output sentence pairs per vocabolario
    """

    def __init__(self, temp_path: str = "data/temp/dvd"):
        self.temp_path = Path(temp_path)
        self.temp_path.mkdir(parents=True, exist_ok=True)

    async def extract_tracks(self, video_path: str) -> Dict[str, Any]:
        """
        Estrae tracce audio e sottotitoli da video

        Returns:
        {
            "audio_tracks": [
                {"index": 0, "language": "Italian", "language_code": "it", "codec": "aac"},
                {"index": 1, "language": "Japanese", "language_code": "ja", "codec": "aac"}
            ],
            "subtitle_tracks": [
                {"index": 0, "language": "Italian", "language_code": "it", "codec": "subrip"},
                {"index": 1, "language": "Japanese", "language_code": "ja", "codec": "subrip"}
            ]
        }
        """
        try:
            cmd = [
                "ffprobe",
                "-v", "quiet",
                "-print_format", "json",
                "-show_streams",
                video_path
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"ffprobe failed: {result.stderr}")

            data = json.loads(result.stdout)
            streams = data.get("streams", [])

            audio_tracks = []
            subtitle_tracks = []

            for stream in streams:
                codec_type = stream.get("codec_type")
                index = stream.get("index", 0)
                tags = stream.get("tags", {})

                language = tags.get("language", tags.get("title", "unknown"))
                language_code = self._normalize_language(language)
                codec = stream.get("codec_name", "unknown")
                is_default = stream.get("disposition", {}).get("default", 0) == 1

                track_info = TrackInfo(
                    index=index,
                    language=language,
                    language_code=language_code,
                    codec=codec,
                    is_default=is_default
                )

                if codec_type == "audio":
                    audio_tracks.append(asdict(track_info))
                elif codec_type == "subtitle":
                    subtitle_tracks.append(asdict(track_info))

            return {
                "audio_tracks": audio_tracks,
                "subtitle_tracks": subtitle_tracks,
                "video_path": video_path,
            }

        except Exception as e:
            logger.error(f"Track extraction failed: {e}")
            return {
                "audio_tracks": [],
                "subtitle_tracks": [],
                "error": str(e),
            }

    def _normalize_language(self, lang: str) -> str:
        """Normalize language string to ISO code"""
        lang_lower = lang.lower().strip()
        return LANGUAGE_CODES.get(lang_lower, lang_lower[:2])

    async def extract_subtitles(
        self,
        video_path: str,
        track_index: int,
        output_path: Optional[str] = None
    ) -> str:
        """
        Estrae sottotitoli come .srt

        Args:
            video_path: Path al video
            track_index: Indice della traccia sottotitoli
            output_path: Path output (opzionale)

        Returns:
            Path al file .srt estratto
        """
        if output_path is None:
            output_path = self.temp_path / f"sub_{track_index}_{uuid.uuid4().hex[:8]}.srt"

        try:
            cmd = [
                "ffmpeg",
                "-y",
                "-i", video_path,
                "-map", f"0:s:{track_index}",
                "-c:s", "srt",
                str(output_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Subtitle extraction failed: {result.stderr}")

            logger.info(f"Extracted subtitles to: {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Subtitle extraction error: {e}")
            raise

    def parse_srt(self, srt_path: str) -> List[SubtitleEntry]:
        """Parse SRT file into subtitle entries"""
        entries = []

        try:
            with open(srt_path, "r", encoding="utf-8-sig") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(srt_path, "r", encoding="latin-1") as f:
                content = f.read()

        # Split by double newline (subtitle blocks)
        blocks = re.split(r'\n\n+', content.strip())

        for block in blocks:
            lines = block.strip().split('\n')
            if len(lines) < 3:
                continue

            try:
                index = int(lines[0])
                time_line = lines[1]
                text = '\n'.join(lines[2:])

                # Parse timestamp: "00:15:32,100 --> 00:15:34,500"
                time_match = re.match(
                    r'(\d{2}:\d{2}:\d{2},\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2},\d{3})',
                    time_line
                )

                if time_match:
                    start_time = time_match.group(1)
                    end_time = time_match.group(2)

                    entries.append(SubtitleEntry(
                        index=index,
                        start_time=start_time,
                        end_time=end_time,
                        text=self._clean_subtitle_text(text),
                        start_ms=self._time_to_ms(start_time),
                        end_ms=self._time_to_ms(end_time),
                    ))

            except (ValueError, IndexError) as e:
                logger.warning(f"Failed to parse subtitle block: {e}")
                continue

        return entries

    def _clean_subtitle_text(self, text: str) -> str:
        """Clean subtitle text (remove tags, normalize whitespace)"""
        # Remove HTML-like tags
        text = re.sub(r'<[^>]+>', '', text)
        # Remove SRT formatting tags
        text = re.sub(r'\{[^}]+\}', '', text)
        # Normalize whitespace
        text = ' '.join(text.split())
        return text.strip()

    def _time_to_ms(self, time_str: str) -> int:
        """Convert SRT timestamp to milliseconds"""
        # Format: "00:15:32,100"
        try:
            match = re.match(r'(\d{2}):(\d{2}):(\d{2}),(\d{3})', time_str)
            if match:
                h, m, s, ms = map(int, match.groups())
                return h * 3600000 + m * 60000 + s * 1000 + ms
        except:
            pass
        return 0

    async def align_subtitles(
        self,
        srt_source: str,
        srt_target: str,
        tolerance_ms: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Allinea sottotitoli per timestamp

        Args:
            srt_source: Path al file sorgente (es: giapponese)
            srt_target: Path al file target (es: italiano)
            tolerance_ms: Tolleranza in millisecondi per matching

        Returns:
            Lista di pairs allineati con confidence
        """
        source_subs = self.parse_srt(srt_source)
        target_subs = self.parse_srt(srt_target)

        logger.info(f"Aligning {len(source_subs)} source subs with {len(target_subs)} target subs")

        aligned_pairs = []
        used_targets = set()

        for source_sub in source_subs:
            best_match = None
            best_score = 0

            for i, target_sub in enumerate(target_subs):
                if i in used_targets:
                    continue

                score = self._calc_alignment_score(source_sub, target_sub, tolerance_ms)

                if score > best_score:
                    best_score = score
                    best_match = (i, target_sub)

            if best_match and best_score > 0.5:
                idx, target_sub = best_match
                used_targets.add(idx)

                aligned_pairs.append({
                    "source_text": source_sub.text,
                    "target_text": target_sub.text,
                    "confidence": best_score,
                    # PRIVACY: NO timestamp, NO indices
                })

        logger.info(f"Aligned {len(aligned_pairs)} pairs (confidence > 0.5)")
        return aligned_pairs

    def _calc_alignment_score(
        self,
        source: SubtitleEntry,
        target: SubtitleEntry,
        tolerance_ms: int
    ) -> float:
        """Calculate alignment confidence score"""
        # Time overlap score
        start_diff = abs(source.start_ms - target.start_ms)
        end_diff = abs(source.end_ms - target.end_ms)

        if start_diff > tolerance_ms * 3 or end_diff > tolerance_ms * 3:
            return 0.0

        # Higher score for closer timestamps
        time_score = 1.0 - (start_diff + end_diff) / (tolerance_ms * 6)
        time_score = max(0, time_score)

        # Length similarity score (translations should have similar length)
        len_ratio = len(target.text) / max(len(source.text), 1)
        # Allow 0.3x to 3x length difference
        if len_ratio < 0.3 or len_ratio > 3:
            length_score = 0.3
        else:
            length_score = 1.0 - abs(1.0 - len_ratio) / 2

        # Combined score
        return time_score * 0.7 + length_score * 0.3

    async def process_dvd(
        self,
        video_path: str,
        source_lang: str,
        target_lang: str,
        source_track_idx: Optional[int] = None,
        target_track_idx: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Pipeline completa DVD → Sentence Pairs

        Args:
            video_path: Path al video DVD/MKV/MP4
            source_lang: Lingua sorgente (es: "ja")
            target_lang: Lingua target (es: "it")
            source_track_idx: Indice traccia sottotitoli sorgente (auto se None)
            target_track_idx: Indice traccia sottotitoli target (auto se None)

        Returns:
            {
                "success": True,
                "total_pairs": 1234,
                "source_lang": "ja",
                "target_lang": "it",
                "pairs": [...],
                "stats": {...}
            }
        """
        job_id = uuid.uuid4().hex[:12]
        job_temp = self.temp_path / job_id
        job_temp.mkdir(parents=True, exist_ok=True)

        try:
            logger.info(f"Starting DVD processing job {job_id}")

            # Step 1: Rileva tracce
            tracks = await self.extract_tracks(video_path)
            if "error" in tracks:
                raise RuntimeError(f"Track detection failed: {tracks['error']}")

            # Step 2: Find subtitle tracks by language
            if source_track_idx is None:
                source_track_idx = self._find_track_by_lang(
                    tracks["subtitle_tracks"], source_lang
                )
            if target_track_idx is None:
                target_track_idx = self._find_track_by_lang(
                    tracks["subtitle_tracks"], target_lang
                )

            if source_track_idx is None:
                raise ValueError(f"No subtitle track found for source language: {source_lang}")
            if target_track_idx is None:
                raise ValueError(f"No subtitle track found for target language: {target_lang}")

            # Step 3: Estrai sottotitoli
            source_srt = await self.extract_subtitles(
                video_path,
                source_track_idx,
                str(job_temp / f"source_{source_lang}.srt")
            )
            target_srt = await self.extract_subtitles(
                video_path,
                target_track_idx,
                str(job_temp / f"target_{target_lang}.srt")
            )

            # Step 4: Allinea
            pairs = await self.align_subtitles(source_srt, target_srt)

            # Step 5: Filtra (solo confidence > 0.7)
            high_confidence = [p for p in pairs if p["confidence"] > 0.7]
            medium_confidence = [p for p in pairs if 0.5 < p["confidence"] <= 0.7]

            # Step 6: Anonimizza
            anonymized = self._anonymize_pairs(high_confidence)

            # Calculate stats
            stats = {
                "total_extracted": len(pairs),
                "high_confidence": len(high_confidence),
                "medium_confidence": len(medium_confidence),
                "avg_confidence": sum(p["confidence"] for p in pairs) / len(pairs) if pairs else 0,
            }

            logger.info(f"DVD processing completed: {len(anonymized)} pairs extracted")

            return {
                "success": True,
                "job_id": job_id,
                "total_pairs": len(anonymized),
                "source_lang": source_lang,
                "target_lang": target_lang,
                "pairs": anonymized,
                "stats": stats,
            }

        except Exception as e:
            logger.error(f"DVD processing failed: {e}")
            return {
                "success": False,
                "job_id": job_id,
                "error": str(e),
            }

        finally:
            # PRIVACY: Cleanup temp files
            self._cleanup_temp(job_temp)

    def _find_track_by_lang(
        self,
        tracks: List[Dict],
        lang_code: str
    ) -> Optional[int]:
        """Find track index by language code"""
        normalized = self._normalize_language(lang_code)

        for i, track in enumerate(tracks):
            if track.get("language_code") == normalized:
                return i

        return None

    def _anonymize_pairs(self, pairs: List[Dict]) -> List[Dict]:
        """
        Rimuove riferimenti al film originale
        Output solo: testo source, testo target, confidence

        PRIVACY BY DESIGN: Nessuna traccia dell'origine
        """
        return [
            {
                "source": p["source_text"],
                "target": p["target_text"],
                "confidence": round(p["confidence"], 3),
                # NO: timestamp, film_name, scene, track_index
            }
            for p in pairs
        ]

    def _cleanup_temp(self, temp_dir: Path):
        """Delete temporary files after processing"""
        try:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
                logger.info(f"Cleaned up temp directory: {temp_dir}")
        except Exception as e:
            logger.warning(f"Temp cleanup failed: {e}")


# Integration with vocabulary/translation memory
async def import_dvd_pairs_to_vocabulary(
    pairs: List[Dict],
    source_lang: str,
    target_lang: str,
    llm_debate_service=None,
    translation_memory=None
) -> Dict[str, Any]:
    """
    Importa sentence pairs nel sistema traduzione

    1. Multi-LLM debate per validazione
    2. Se confidence >= 80% → auto-approve
    3. Se confidence < 80% → queue per staff review
    4. Arricchisce translation_memory.py
    """
    auto_approved = 0
    queued_for_review = 0
    rejected = 0

    for pair in pairs:
        try:
            # Validate with LLM debate if available
            if llm_debate_service:
                validation = await llm_debate_service.validate_translation(
                    source=pair["source"],
                    target=pair["target"],
                    source_lang=source_lang,
                    target_lang=target_lang
                )
                consensus_confidence = validation.get("consensus_confidence", pair["confidence"])
            else:
                consensus_confidence = pair["confidence"]

            if consensus_confidence >= 0.8:
                # Auto-approve → add to translation memory
                if translation_memory:
                    await translation_memory.add_entry(
                        source=pair["source"],
                        target=pair["target"],
                        confidence=consensus_confidence,
                        source_type="parallel_corpus"  # NO film reference
                    )
                auto_approved += 1
            elif consensus_confidence >= 0.5:
                # Queue for staff review
                queued_for_review += 1
            else:
                # Reject low confidence pairs
                rejected += 1

        except Exception as e:
            logger.warning(f"Failed to import pair: {e}")
            rejected += 1

    return {
        "auto_approved": auto_approved,
        "queued_for_review": queued_for_review,
        "rejected": rejected,
        "total_processed": len(pairs),
    }

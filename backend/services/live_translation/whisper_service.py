"""
🎤 Whisper Speech-to-Text Service
OpenAI Whisper - Open source, self-hosted speech recognition
Fine-tuned for martial arts terminology
"""

import os
import asyncio
from typing import Optional, AsyncGenerator, List, Dict
import logging
import torch
import numpy as np
from faster_whisper import WhisperModel
import io
import wave

logger = logging.getLogger(__name__)


class WhisperService:
    """
    Whisper speech-to-text service

    Open source, self-hosted alternative to Google Cloud Speech-to-Text
    Fine-tuned for martial arts terminology
    """

    def __init__(
        self,
        model_size: str = "large-v3",
        model_path: Optional[str] = None,
        device: str = "auto",
        compute_type: str = "float16"
    ):
        """
        Initialize Whisper service

        Args:
            model_size: Model size (tiny, base, small, medium, large, large-v2, large-v3)
            model_path: Path to custom fine-tuned model (if None, uses default)
            device: Device to use (cuda, cpu, auto)
            compute_type: Compute type (float16, int8, int8_float16)
        """
        self.model_size = model_size
        self.model_path = model_path or os.getenv("WHISPER_MODEL_PATH")

        # Auto-detect device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"

        self.device = device
        self.compute_type = compute_type if device == "cuda" else "int8"

        # Load model
        try:
            if self.model_path and os.path.exists(self.model_path):
                # Load fine-tuned model
                logger.info(f"Loading fine-tuned Whisper model from {self.model_path}")
                self.model = WhisperModel(
                    self.model_path,
                    device=self.device,
                    compute_type=self.compute_type
                )
            else:
                # Load default model
                logger.info(f"Loading Whisper {model_size} model on {device}")
                self.model = WhisperModel(
                    model_size,
                    device=self.device,
                    compute_type=self.compute_type
                )

            logger.info(f"✅ Whisper model loaded successfully ({device}, {self.compute_type})")

        except Exception as e:
            logger.error(f"Failed to load Whisper model: {e}")
            self.model = None

        # Audio buffer for streaming
        self.sample_rate = 16000
        self.chunk_duration = 3  # seconds

        # Martial arts terminology boost (words to prioritize)
        self.martial_arts_vocabulary = [
            # Italian
            "kata", "kumite", "kihon", "dojo", "sensei", "karate", "judo",
            "taekwondo", "kung fu", "aikido", "kendo", "jiu-jitsu", "muay thai",
            "posizione", "guardia", "pugno", "calcio", "blocco", "parata",
            "mae geri", "yoko geri", "mawashi geri", "gyaku zuki", "oi zuki",
            "gedan barai", "age uke", "soto uke", "uchi uke", "shuto uke",
            # Commands
            "hajime", "yame", "rei", "mokuso", "kiritsu", "kamae",
            # Common terms
            "cintura", "gi", "kimono", "hakama", "obi", "tatami"
        ]

    async def transcribe_stream(
        self,
        audio_generator: AsyncGenerator[bytes, None],
        language_code: str = "it-IT",
        enable_automatic_punctuation: bool = True,
        enable_word_time_offsets: bool = False
    ) -> AsyncGenerator[dict, None]:
        """
        Transcribe audio stream in real-time

        Args:
            audio_generator: Async generator yielding audio chunks (bytes)
            language_code: Language code (e.g., "it-IT", "en-US")
            enable_automatic_punctuation: Add punctuation automatically (always true for Whisper)
            enable_word_time_offsets: Include word-level timestamps

        Yields:
            Dictionary with transcription results
        """
        if not self.model:
            logger.error("Whisper model not loaded")
            yield {
                "error": "Whisper model not available",
                "text": "",
                "is_final": False,
                "confidence": 0.0,
                "language": language_code
            }
            return

        # Convert language code (it-IT -> it)
        language = language_code.split("-")[0]

        # Buffer for accumulating audio
        audio_buffer = bytearray()
        chunk_size = self.sample_rate * self.chunk_duration * 2  # 16-bit PCM = 2 bytes per sample

        try:
            async for audio_chunk in audio_generator:
                audio_buffer.extend(audio_chunk)

                # Process when buffer is large enough
                if len(audio_buffer) >= chunk_size:
                    # Extract chunk
                    chunk_bytes = bytes(audio_buffer[:chunk_size])
                    audio_buffer = audio_buffer[chunk_size:]

                    # Convert bytes to numpy array
                    audio_array = np.frombuffer(chunk_bytes, dtype=np.int16).astype(np.float32) / 32768.0

                    # Transcribe
                    result = await self._transcribe_chunk(
                        audio_array,
                        language=language,
                        word_timestamps=enable_word_time_offsets
                    )

                    if result and result.get("text"):
                        yield {
                            "text": result["text"],
                            "is_final": True,
                            "confidence": result.get("confidence", 0.0),
                            "language": language_code,
                            "words": result.get("words") if enable_word_time_offsets else None
                        }

        except Exception as e:
            logger.error(f"Error in Whisper streaming: {e}")
            yield {
                "error": str(e),
                "text": "",
                "is_final": False,
                "confidence": 0.0,
                "language": language_code
            }

    async def _transcribe_chunk(
        self,
        audio_array: np.ndarray,
        language: str = "it",
        word_timestamps: bool = False
    ) -> dict:
        """
        Transcribe a single audio chunk

        Args:
            audio_array: Audio data as numpy array
            language: Language code
            word_timestamps: Include word-level timestamps

        Returns:
            Dictionary with transcription
        """
        try:
            # Run in thread pool (Whisper is synchronous)
            loop = asyncio.get_event_loop()
            segments, info = await loop.run_in_executor(
                None,
                lambda: self.model.transcribe(
                    audio_array,
                    language=language,
                    beam_size=5,
                    word_timestamps=word_timestamps,
                    vad_filter=True,  # Voice activity detection
                    initial_prompt=" ".join(self.martial_arts_vocabulary)  # Boost martial arts terms
                )
            )

            # Collect segments
            text_parts = []
            words = []
            total_confidence = 0
            segment_count = 0

            for segment in segments:
                text_parts.append(segment.text.strip())
                total_confidence += segment.avg_logprob
                segment_count += 1

                if word_timestamps and hasattr(segment, 'words'):
                    for word in segment.words:
                        words.append({
                            "word": word.word,
                            "start": word.start,
                            "end": word.end,
                            "probability": word.probability
                        })

            if not text_parts:
                return {"text": "", "confidence": 0.0}

            # Calculate average confidence (convert log prob to probability)
            avg_confidence = min(1.0, max(0.0, (total_confidence / segment_count + 5) / 5))

            return {
                "text": " ".join(text_parts),
                "confidence": avg_confidence,
                "language": info.language,
                "words": words if word_timestamps else None
            }

        except Exception as e:
            logger.error(f"Error transcribing chunk: {e}")
            return {"text": "", "confidence": 0.0, "error": str(e)}

    async def transcribe_single(
        self,
        audio_content: bytes,
        language_code: str = "it-IT"
    ) -> dict:
        """
        Transcribe a single audio file (not streaming)

        Args:
            audio_content: Audio data as bytes (WAV format)
            language_code: Language code

        Returns:
            Dictionary with transcription result
        """
        if not self.model:
            logger.error("Whisper model not loaded")
            return {
                "error": "Whisper model not available",
                "text": "",
                "confidence": 0.0,
                "language": language_code
            }

        language = language_code.split("-")[0]

        try:
            # Convert bytes to numpy array
            with io.BytesIO(audio_content) as audio_file:
                with wave.open(audio_file, 'rb') as wav:
                    frames = wav.readframes(wav.getnframes())
                    audio_array = np.frombuffer(frames, dtype=np.int16).astype(np.float32) / 32768.0

            # Transcribe
            result = await self._transcribe_chunk(audio_array, language=language)

            return {
                "text": result.get("text", ""),
                "confidence": result.get("confidence", 0.0),
                "language": language_code
            }

        except Exception as e:
            logger.error(f"Error in single transcription: {e}")
            return {
                "error": str(e),
                "text": "",
                "confidence": 0.0,
                "language": language_code
            }

    def get_supported_languages(self) -> List[dict]:
        """
        Get list of supported languages

        Returns:
            List of dicts with language info
        """
        return [
            {"code": "it-IT", "name": "Italiano", "region": "Italia"},
            {"code": "en-US", "name": "English", "region": "United States"},
            {"code": "en-GB", "name": "English", "region": "United Kingdom"},
            {"code": "es-ES", "name": "Español", "region": "España"},
            {"code": "fr-FR", "name": "Français", "region": "France"},
            {"code": "de-DE", "name": "Deutsch", "region": "Deutschland"},
            {"code": "pt-BR", "name": "Português", "region": "Brasil"},
            {"code": "ja-JP", "name": "日本語", "region": "日本"},
            {"code": "zh-CN", "name": "中文", "region": "中国"},
            {"code": "ko-KR", "name": "한국어", "region": "대한민국"},
        ]


# Global instance (lazy initialization)
_whisper_service: Optional[WhisperService] = None


def get_whisper_service() -> WhisperService:
    """Get global Whisper service instance"""
    global _whisper_service
    if _whisper_service is None:
        _whisper_service = WhisperService()
    return _whisper_service

"""
🎤 Speech-to-Text Service
Google Cloud Speech-to-Text integration for real-time transcription
"""

import os
from typing import Optional, AsyncGenerator
import asyncio
import logging
from google.cloud import speech_v1p1beta1 as speech
from google.oauth2 import service_account

logger = logging.getLogger(__name__)


class SpeechToTextService:
    """Google Cloud Speech-to-Text service for live transcription"""

    def __init__(self, credentials_path: Optional[str] = None):
        """
        Initialize Speech-to-Text service

        Args:
            credentials_path: Path to Google Cloud service account JSON file
        """
        self.credentials_path = credentials_path or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

        if self.credentials_path and os.path.exists(self.credentials_path):
            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path
            )
            self.client = speech.SpeechClient(credentials=credentials)
        else:
            # Will use default credentials if available
            try:
                self.client = speech.SpeechClient()
            except Exception as e:
                logger.warning(f"Failed to initialize Speech client: {e}")
                self.client = None

        self.encoding = speech.RecognitionConfig.AudioEncoding.LINEAR16
        self.sample_rate = 16000  # 16kHz
        self.language_code = "it-IT"  # Default to Italian

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
            enable_automatic_punctuation: Add punctuation automatically
            enable_word_time_offsets: Include word-level timestamps

        Yields:
            Dictionary with transcription results:
            {
                "text": str,
                "is_final": bool,
                "confidence": float,
                "language": str
            }
        """
        if not self.client:
            logger.error("Speech-to-Text client not initialized")
            yield {
                "error": "Speech-to-Text service not available",
                "text": "",
                "is_final": False,
                "confidence": 0.0,
                "language": language_code
            }
            return

        # Configure recognition
        config = speech.RecognitionConfig(
            encoding=self.encoding,
            sample_rate_hertz=self.sample_rate,
            language_code=language_code,
            enable_automatic_punctuation=enable_automatic_punctuation,
            enable_word_time_offsets=enable_word_time_offsets,
            model="latest_long",  # Best for live streaming
            use_enhanced=True,  # Use enhanced model
        )

        streaming_config = speech.StreamingRecognitionConfig(
            config=config,
            interim_results=True  # Get partial results
        )

        try:
            # Create request generator
            async def request_generator():
                # First request with config
                yield speech.StreamingRecognizeRequest(
                    streaming_config=streaming_config
                )

                # Then audio chunks
                async for chunk in audio_generator:
                    yield speech.StreamingRecognizeRequest(audio_content=chunk)

            # Perform streaming recognition
            responses = self.client.streaming_recognize(request_generator())

            for response in responses:
                if not response.results:
                    continue

                # Get the first result (most recent)
                result = response.results[0]

                if not result.alternatives:
                    continue

                # Get the top alternative
                alternative = result.alternatives[0]

                yield {
                    "text": alternative.transcript,
                    "is_final": result.is_final,
                    "confidence": alternative.confidence if result.is_final else None,
                    "language": language_code,
                    "stability": result.stability if not result.is_final else None
                }

        except Exception as e:
            logger.error(f"Error in speech recognition: {e}")
            yield {
                "error": str(e),
                "text": "",
                "is_final": False,
                "confidence": 0.0,
                "language": language_code
            }

    async def transcribe_single(
        self,
        audio_content: bytes,
        language_code: str = "it-IT"
    ) -> dict:
        """
        Transcribe a single audio chunk (not streaming)

        Args:
            audio_content: Audio data as bytes
            language_code: Language code

        Returns:
            Dictionary with transcription result
        """
        if not self.client:
            logger.error("Speech-to-Text client not initialized")
            return {
                "error": "Speech-to-Text service not available",
                "text": "",
                "confidence": 0.0,
                "language": language_code
            }

        config = speech.RecognitionConfig(
            encoding=self.encoding,
            sample_rate_hertz=self.sample_rate,
            language_code=language_code,
            enable_automatic_punctuation=True,
        )

        audio = speech.RecognitionAudio(content=audio_content)

        try:
            response = self.client.recognize(config=config, audio=audio)

            if not response.results:
                return {
                    "text": "",
                    "confidence": 0.0,
                    "language": language_code
                }

            result = response.results[0]
            alternative = result.alternatives[0]

            return {
                "text": alternative.transcript,
                "confidence": alternative.confidence,
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

    def get_supported_languages(self) -> list[dict]:
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
_speech_service: Optional[SpeechToTextService] = None


def get_speech_service() -> SpeechToTextService:
    """Get global Speech-to-Text service instance"""
    global _speech_service
    if _speech_service is None:
        _speech_service = SpeechToTextService()
    return _speech_service

"""
🔌 Service Protocols (Interfaces)
Define interfaces for pluggable speech-to-text and translation services
"""

from typing import Protocol, AsyncGenerator, List, Dict, Optional


class SpeechToTextService(Protocol):
    """
    Protocol for speech-to-text services

    Implementations:
    - WhisperService (open source, self-hosted)
    - GoogleSpeechService (Google Cloud)
    """

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
        ...

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
        ...

    def get_supported_languages(self) -> List[dict]:
        """
        Get list of supported languages

        Returns:
            List of dicts with language info
        """
        ...


class TranslationService(Protocol):
    """
    Protocol for translation services

    Implementations:
    - NLLBTranslationService (open source, self-hosted, fine-tuned for martial arts)
    - GoogleTranslationService (Google Cloud Translation API)
    """

    async def translate_text(
        self,
        text: str,
        target_language: str,
        source_language: str = "it"
    ) -> dict:
        """
        Translate text to target language

        Args:
            text: Text to translate
            target_language: Target language code (e.g., "en", "es")
            source_language: Source language code (default: "it")

        Returns:
            Dictionary with translation result:
            {
                "translated_text": str,
                "source_language": str,
                "target_language": str,
                "confidence": float (optional)
            }
        """
        ...

    async def translate_to_multiple(
        self,
        text: str,
        target_languages: List[str],
        source_language: str = "it"
    ) -> Dict[str, dict]:
        """
        Translate text to multiple languages

        Args:
            text: Text to translate
            target_languages: List of target language codes
            source_language: Source language code

        Returns:
            Dictionary mapping language code to translation result
        """
        ...

    def detect_language(self, text: str) -> dict:
        """
        Detect language of text

        Args:
            text: Text to analyze

        Returns:
            Dictionary with detection result:
            {
                "language": str,
                "confidence": float
            }
        """
        ...

    def get_supported_languages(self) -> List[Dict[str, str]]:
        """
        Get list of supported languages

        Returns:
            List of dictionaries with language info
        """
        ...

    def clear_cache(self):
        """Clear translation cache"""
        ...

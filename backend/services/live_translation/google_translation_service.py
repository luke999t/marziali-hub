"""
🌍 Translation Service
Google Cloud Translation API integration for real-time subtitle translation
"""

import os
from typing import Optional, List, Dict
import logging
from google.cloud import translate_v2 as translate
from google.oauth2 import service_account

logger = logging.getLogger(__name__)


class TranslationService:
    """Google Cloud Translation service for subtitle translation"""

    def __init__(self, credentials_path: Optional[str] = None):
        """
        Initialize Translation service

        Args:
            credentials_path: Path to Google Cloud service account JSON file
        """
        self.credentials_path = credentials_path or os.getenv("GOOGLE_APPLICATION_CREDENTIALS")

        if self.credentials_path and os.path.exists(self.credentials_path):
            credentials = service_account.Credentials.from_service_account_file(
                self.credentials_path
            )
            self.client = translate.Client(credentials=credentials)
        else:
            # Will use default credentials if available
            try:
                self.client = translate.Client()
            except Exception as e:
                logger.warning(f"Failed to initialize Translation client: {e}")
                self.client = None

        # Cache for translations to avoid re-translating same text
        self.translation_cache: Dict[tuple, str] = {}
        self.cache_max_size = 1000

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
                "confidence": float
            }
        """
        if not self.client:
            logger.error("Translation client not initialized")
            return {
                "translated_text": text,  # Return original if translation fails
                "source_language": source_language,
                "target_language": target_language,
                "error": "Translation service not available"
            }

        # Check cache
        cache_key = (text.lower(), source_language, target_language)
        if cache_key in self.translation_cache:
            return {
                "translated_text": self.translation_cache[cache_key],
                "source_language": source_language,
                "target_language": target_language,
                "cached": True
            }

        try:
            # Perform translation
            result = self.client.translate(
                text,
                target_language=target_language,
                source_language=source_language,
                format_="text"
            )

            translated_text = result["translatedText"]

            # Cache the result
            if len(self.translation_cache) < self.cache_max_size:
                self.translation_cache[cache_key] = translated_text
            else:
                # Clear cache if it gets too large
                self.translation_cache.clear()

            return {
                "translated_text": translated_text,
                "source_language": source_language,
                "target_language": target_language,
                "detected_source": result.get("detectedSourceLanguage"),
                "cached": False
            }

        except Exception as e:
            logger.error(f"Error translating text: {e}")
            return {
                "translated_text": text,  # Return original on error
                "source_language": source_language,
                "target_language": target_language,
                "error": str(e)
            }

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
        results = {}

        for lang in target_languages:
            if lang == source_language:
                # Don't translate to same language
                results[lang] = {
                    "translated_text": text,
                    "source_language": source_language,
                    "target_language": lang,
                    "same_language": True
                }
            else:
                results[lang] = await self.translate_text(
                    text, lang, source_language
                )

        return results

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
        if not self.client:
            logger.error("Translation client not initialized")
            return {
                "language": "unknown",
                "confidence": 0.0,
                "error": "Translation service not available"
            }

        try:
            result = self.client.detect_language(text)

            return {
                "language": result["language"],
                "confidence": result["confidence"]
            }

        except Exception as e:
            logger.error(f"Error detecting language: {e}")
            return {
                "language": "unknown",
                "confidence": 0.0,
                "error": str(e)
            }

    def get_supported_languages(self) -> List[Dict[str, str]]:
        """
        Get list of supported languages

        Returns:
            List of dictionaries with language info
        """
        if not self.client:
            return self._get_default_languages()

        try:
            results = self.client.get_languages()

            return [
                {
                    "code": lang["language"],
                    "name": lang.get("name", lang["language"])
                }
                for lang in results
            ]

        except Exception as e:
            logger.error(f"Error getting supported languages: {e}")
            return self._get_default_languages()

    def _get_default_languages(self) -> List[Dict[str, str]]:
        """Get default list of common languages"""
        return [
            {"code": "it", "name": "Italiano"},
            {"code": "en", "name": "English"},
            {"code": "es", "name": "Español"},
            {"code": "fr", "name": "Français"},
            {"code": "de", "name": "Deutsch"},
            {"code": "pt", "name": "Português"},
            {"code": "ja", "name": "日本語"},
            {"code": "zh-CN", "name": "中文 (简体)"},
            {"code": "ko", "name": "한국어"},
            {"code": "ar", "name": "العربية"},
        ]

    def clear_cache(self):
        """Clear translation cache"""
        self.translation_cache.clear()
        logger.info("Translation cache cleared")


# Global instance (lazy initialization)
_translation_service: Optional[TranslationService] = None


def get_translation_service() -> TranslationService:
    """Get global Translation service instance"""
    global _translation_service
    if _translation_service is None:
        _translation_service = TranslationService()
    return _translation_service

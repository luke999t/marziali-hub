"""
🏭 Service Factory
Factory pattern for creating speech and translation services based on configuration

IMPORTANT: Uses LAZY IMPORTS to make torch optional
- WhisperService and NLLBService are imported INSIDE functions
- This allows using Google Cloud without installing torch (395MB)
"""

import os
from typing import Union
import logging

from .protocols import SpeechToTextService, TranslationService

logger = logging.getLogger(__name__)


def get_speech_service() -> SpeechToTextService:
    """
    Get speech-to-text service based on configuration

    Environment variable: SPEECH_PROVIDER
    - "whisper" (default) - Open source Whisper (self-hosted, requires torch)
    - "google" - Google Cloud Speech-to-Text (no torch needed)

    Returns:
        SpeechToTextService implementation
    """
    provider = os.getenv("SPEECH_PROVIDER", "whisper").lower()

    logger.info(f"🎤 Initializing speech service: {provider}")

    if provider == "whisper":
        # LAZY IMPORT - only load torch if using Whisper
        try:
            from .whisper_service import get_whisper_service
            return get_whisper_service()
        except ImportError as e:
            logger.error(f"Failed to load Whisper service (torch not installed?): {e}")
            logger.warning("Falling back to Google Speech service")
            # Try Google as fallback
            try:
                from .google_speech_service import get_speech_service as get_google_speech
                return get_google_speech()
            except ImportError:
                raise RuntimeError(
                    "Neither Whisper nor Google Speech service available. "
                    "Install torch for Whisper or configure Google Cloud credentials."
                )
    elif provider == "google":
        # Lazy import to avoid dependency if not used
        try:
            from .google_speech_service import get_speech_service as get_google_speech
            return get_google_speech()
        except ImportError as e:
            logger.error(f"Failed to load Google Speech service: {e}")
            logger.warning("Falling back to Whisper service")
            try:
                from .whisper_service import get_whisper_service
                return get_whisper_service()
            except ImportError:
                raise RuntimeError(
                    "Neither Google Speech nor Whisper service available. "
                    "Configure Google Cloud credentials or install torch."
                )
    else:
        logger.warning(f"Unknown speech provider '{provider}', using Whisper as default")
        try:
            from .whisper_service import get_whisper_service
            return get_whisper_service()
        except ImportError as e:
            raise RuntimeError(f"Whisper service not available: {e}. Install torch or use SPEECH_PROVIDER=google")


def get_translation_service() -> TranslationService:
    """
    Get translation service based on configuration

    Environment variable: TRANSLATION_PROVIDER
    - "nllb" (default) - Open source NLLB-200 (self-hosted, fine-tuned for martial arts, requires torch)
    - "google" - Google Cloud Translation API (no torch needed)

    Returns:
        TranslationService implementation
    """
    provider = os.getenv("TRANSLATION_PROVIDER", "nllb").lower()

    logger.info(f"🌍 Initializing translation service: {provider}")

    if provider == "nllb":
        # LAZY IMPORT - only load torch if using NLLB
        try:
            from .nllb_service import get_nllb_service
            return get_nllb_service()
        except ImportError as e:
            logger.error(f"Failed to load NLLB service (torch not installed?): {e}")
            logger.warning("Falling back to Google Translation service")
            # Try Google as fallback
            try:
                from .google_translation_service import get_translation_service as get_google_translation
                return get_google_translation()
            except ImportError:
                raise RuntimeError(
                    "Neither NLLB nor Google Translation service available. "
                    "Install torch for NLLB or configure Google Cloud credentials."
                )
    elif provider == "google":
        # Lazy import to avoid dependency if not used
        try:
            from .google_translation_service import get_translation_service as get_google_translation
            return get_google_translation()
        except ImportError as e:
            logger.error(f"Failed to load Google Translation service: {e}")
            logger.warning("Falling back to NLLB service")
            try:
                from .nllb_service import get_nllb_service
                return get_nllb_service()
            except ImportError:
                raise RuntimeError(
                    "Neither Google Translation nor NLLB service available. "
                    "Configure Google Cloud credentials or install torch."
                )
    else:
        logger.warning(f"Unknown translation provider '{provider}', using NLLB as default")
        try:
            from .nllb_service import get_nllb_service
            return get_nllb_service()
        except ImportError as e:
            raise RuntimeError(f"NLLB service not available: {e}. Install torch or use TRANSLATION_PROVIDER=google")


def get_provider_info() -> dict:
    """
    Get information about current providers

    Returns:
        Dictionary with provider information
    """
    speech_provider = os.getenv("SPEECH_PROVIDER", "whisper").lower()
    translation_provider = os.getenv("TRANSLATION_PROVIDER", "nllb").lower()

    provider_descriptions = {
        "whisper": {
            "name": "OpenAI Whisper",
            "type": "open source",
            "cost": "self-hosted (no API costs)",
            "latency": "~200-300ms",
            "accuracy": "~95%",
            "features": [
                "Fine-tuned for martial arts terminology",
                "Runs on local GPU",
                "No internet required",
                "Privacy-friendly (data stays local)"
            ]
        },
        "google": {
            "name": "Google Cloud Speech-to-Text",
            "type": "cloud API",
            "cost": "~$1.44/hour",
            "latency": "~100-300ms",
            "accuracy": "~95-98%",
            "features": [
                "No infrastructure required",
                "Highly accurate",
                "Multiple models available",
                "Automatic updates"
            ]
        },
        "nllb": {
            "name": "Meta NLLB-200",
            "type": "open source",
            "cost": "self-hosted (no API costs)",
            "latency": "~50-150ms",
            "accuracy": "~90-95%",
            "features": [
                "Fine-tuned for martial arts terminology",
                "Learning from user corrections",
                "Terminology database",
                "Runs on local GPU",
                "No internet required",
                "Privacy-friendly (data stays local)"
            ]
        }
    }

    # Add Google translation description
    provider_descriptions["google_translation"] = {
        "name": "Google Cloud Translation",
        "type": "cloud API",
        "cost": "~$20 per 1M characters",
        "latency": "~50-150ms",
        "accuracy": "~98%",
        "features": [
            "No infrastructure required",
            "100+ languages",
            "Highly accurate",
            "Automatic updates"
        ]
    }

    return {
        "speech": {
            "provider": speech_provider,
            "info": provider_descriptions.get(speech_provider, {})
        },
        "translation": {
            "provider": translation_provider,
            "info": provider_descriptions.get(translation_provider, provider_descriptions.get("google_translation", {}))
        }
    }


def switch_provider(service_type: str, provider: str):
    """
    Switch provider for a service type

    Args:
        service_type: "speech" or "translation"
        provider: Provider name (e.g., "whisper", "google", "nllb")

    Note:
        This only updates environment variable for current session.
        For persistent change, update .env file.
    """
    if service_type == "speech":
        os.environ["SPEECH_PROVIDER"] = provider
        logger.info(f"✅ Switched speech provider to: {provider}")
        logger.warning("Restart application for changes to take full effect")
    elif service_type == "translation":
        os.environ["TRANSLATION_PROVIDER"] = provider
        logger.info(f"✅ Switched translation provider to: {provider}")
        logger.warning("Restart application for changes to take full effect")
    else:
        raise ValueError(f"Unknown service type: {service_type}")

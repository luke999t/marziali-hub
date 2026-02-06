"""
🌍 NLLB Translation Service
Meta NLLB-200 - Open source, self-hosted translation
Fine-tuned for martial arts terminology with learning system
"""

import os
from typing import Optional, List, Dict
import logging
import torch
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import asyncio
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class NLLBTranslationService:
    """
    NLLB-200 translation service

    Open source, self-hosted alternative to Google Cloud Translation
    Fine-tuned for martial arts terminology
    Includes learning system from user feedback
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        device: str = "auto",
        terminology_db_path: Optional[str] = None
    ):
        """
        Initialize NLLB translation service

        Args:
            model_path: Path to fine-tuned model (if None, uses default)
            device: Device to use (cuda, cpu, auto)
            terminology_db_path: Path to martial arts terminology database
        """
        self.model_path = model_path or os.getenv("NLLB_MODEL_PATH", "facebook/nllb-200-distilled-600M")

        # Auto-detect device
        if device == "auto":
            device = "cuda" if torch.cuda.is_available() else "cpu"

        self.device = device

        # Load model and tokenizer
        try:
            logger.info(f"Loading NLLB model from {self.model_path}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_path).to(self.device)
            logger.info(f"✅ NLLB model loaded successfully ({device})")
        except Exception as e:
            logger.error(f"Failed to load NLLB model: {e}")
            self.model = None
            self.tokenizer = None

        # Translation cache
        self.translation_cache: Dict[tuple, str] = {}
        self.cache_max_size = 10000

        # Martial arts terminology database
        self.terminology_db_path = terminology_db_path or os.getenv(
            "TERMINOLOGY_DB_PATH",
            "/data/martial_arts_terminology.json"
        )
        self.terminology_db = self._load_terminology_db()

        # Learning database (user corrections)
        self.learning_db_path = os.getenv("LEARNING_DB_PATH", "/data/translation_corrections.json")
        self.learning_db = self._load_learning_db()

        # Language code mapping (NLLB uses special codes)
        self.lang_code_map = {
            "it": "ita_Latn",
            "en": "eng_Latn",
            "es": "spa_Latn",
            "fr": "fra_Latn",
            "de": "deu_Latn",
            "pt": "por_Latn",
            "ja": "jpn_Jpan",
            "zh": "zho_Hans",
            "ko": "kor_Hang",
            "ar": "arb_Arab",
        }

    def _load_terminology_db(self) -> Dict[str, Dict[str, str]]:
        """Load martial arts terminology database"""
        if os.path.exists(self.terminology_db_path):
            try:
                with open(self.terminology_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load terminology DB: {e}")

        # Default terminology database
        return {
            # Italian -> Other languages
            "kata": {
                "it": "kata",
                "en": "kata",
                "es": "kata",
                "fr": "kata",
                "de": "Kata"
            },
            "kumite": {
                "it": "kumite",
                "en": "kumite",
                "es": "kumite",
                "fr": "kumite",
                "de": "Kumite"
            },
            "kihon": {
                "it": "kihon",
                "en": "kihon",
                "es": "kihon",
                "fr": "kihon",
                "de": "Kihon"
            },
            "dojo": {
                "it": "dojo",
                "en": "dojo",
                "es": "dojo",
                "fr": "dojo",
                "de": "Dojo"
            },
            "sensei": {
                "it": "sensei",
                "en": "sensei",
                "es": "sensei",
                "fr": "sensei",
                "de": "Sensei"
            },
            "guardia": {
                "it": "guardia",
                "en": "guard position",
                "es": "guardia",
                "fr": "garde",
                "de": "Stellung"
            },
            "pugno": {
                "it": "pugno",
                "en": "punch",
                "es": "puño",
                "fr": "coup de poing",
                "de": "Fauststoß"
            },
            "calcio": {
                "it": "calcio",
                "en": "kick",
                "es": "patada",
                "fr": "coup de pied",
                "de": "Tritt"
            },
            "blocco": {
                "it": "blocco",
                "en": "block",
                "es": "bloqueo",
                "fr": "blocage",
                "de": "Block"
            },
            "cintura nera": {
                "it": "cintura nera",
                "en": "black belt",
                "es": "cinturón negro",
                "fr": "ceinture noire",
                "de": "schwarzer Gürtel"
            },
        }

    def _load_learning_db(self) -> List[dict]:
        """Load user corrections/feedback database"""
        if os.path.exists(self.learning_db_path):
            try:
                with open(self.learning_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load learning DB: {e}")
        return []

    def _save_learning_db(self):
        """Save user corrections to file"""
        try:
            os.makedirs(os.path.dirname(self.learning_db_path), exist_ok=True)
            with open(self.learning_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.learning_db, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to save learning DB: {e}")

    def _check_terminology(self, text: str, target_lang: str) -> Optional[str]:
        """Check if text is in terminology database"""
        text_lower = text.lower().strip()
        if text_lower in self.terminology_db:
            return self.terminology_db[text_lower].get(target_lang)
        return None

    def _apply_corrections(self, text: str, source_lang: str, target_lang: str) -> str:
        """Apply learned corrections from user feedback"""
        # Check if we have a correction for this exact text
        for correction in self.learning_db:
            if (
                correction["source_text"].lower() == text.lower() and
                correction["source_lang"] == source_lang and
                correction["target_lang"] == target_lang
            ):
                logger.info(f"Applied correction: '{text}' -> '{correction['corrected_text']}'")
                return correction["corrected_text"]
        return text

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
            target_language: Target language code
            source_language: Source language code

        Returns:
            Dictionary with translation result
        """
        if not self.model or not self.tokenizer:
            logger.error("NLLB model not loaded")
            return {
                "translated_text": text,
                "source_language": source_language,
                "target_language": target_language,
                "error": "NLLB model not available"
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

        # Check terminology database
        terminology_match = self._check_terminology(text, target_language)
        if terminology_match:
            self.translation_cache[cache_key] = terminology_match
            return {
                "translated_text": terminology_match,
                "source_language": source_language,
                "target_language": target_language,
                "terminology": True
            }

        try:
            # Convert language codes
            src_lang = self.lang_code_map.get(source_language, "ita_Latn")
            tgt_lang = self.lang_code_map.get(target_language, "eng_Latn")

            # Run translation in thread pool
            loop = asyncio.get_event_loop()
            translated_text = await loop.run_in_executor(
                None,
                self._translate_sync,
                text,
                src_lang,
                tgt_lang
            )

            # Apply learned corrections
            translated_text = self._apply_corrections(translated_text, source_language, target_language)

            # Cache result
            if len(self.translation_cache) < self.cache_max_size:
                self.translation_cache[cache_key] = translated_text
            else:
                # Clear cache if too large
                self.translation_cache.clear()

            return {
                "translated_text": translated_text,
                "source_language": source_language,
                "target_language": target_language,
                "cached": False
            }

        except Exception as e:
            logger.error(f"Error translating text: {e}")
            return {
                "translated_text": text,
                "source_language": source_language,
                "target_language": target_language,
                "error": str(e)
            }

    def _translate_sync(self, text: str, src_lang: str, tgt_lang: str) -> str:
        """Synchronous translation (runs in thread pool)"""
        # Tokenize
        self.tokenizer.src_lang = src_lang
        inputs = self.tokenizer(text, return_tensors="pt").to(self.device)

        # Generate translation
        translated_tokens = self.model.generate(
            **inputs,
            forced_bos_token_id=self.tokenizer.lang_code_to_id[tgt_lang],
            max_length=512,
            num_beams=5,
            early_stopping=True
        )

        # Decode
        translated_text = self.tokenizer.batch_decode(translated_tokens, skip_special_tokens=True)[0]
        return translated_text

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

        # Translate in parallel
        tasks = []
        for lang in target_languages:
            if lang == source_language:
                results[lang] = {
                    "translated_text": text,
                    "source_language": source_language,
                    "target_language": lang,
                    "same_language": True
                }
            else:
                tasks.append((lang, self.translate_text(text, lang, source_language)))

        # Wait for all translations
        for lang, task in tasks:
            results[lang] = await task

        return results

    def add_correction(
        self,
        source_text: str,
        source_lang: str,
        target_lang: str,
        wrong_translation: str,
        corrected_text: str,
        corrected_by: Optional[str] = None
    ):
        """
        Add user correction to learning database

        This allows the system to learn from mistakes

        Args:
            source_text: Original source text
            source_lang: Source language
            target_lang: Target language
            wrong_translation: Incorrect translation produced by model
            corrected_text: Correct translation (from user/instructor)
            corrected_by: User ID who made the correction
        """
        correction = {
            "source_text": source_text,
            "source_lang": source_lang,
            "target_lang": target_lang,
            "wrong_translation": wrong_translation,
            "corrected_text": corrected_text,
            "corrected_by": corrected_by,
            "timestamp": datetime.utcnow().isoformat()
        }

        self.learning_db.append(correction)
        self._save_learning_db()

        logger.info(f"Added correction: '{source_text}' ({source_lang}) -> '{corrected_text}' ({target_lang})")

    def detect_language(self, text: str) -> dict:
        """
        Detect language (basic heuristic for NLLB)

        For full language detection, use a separate library
        """
        # Simple heuristic based on character sets
        # For production, use langdetect or similar

        return {
            "language": "it",  # Default to Italian
            "confidence": 0.5,
            "note": "Language detection not fully implemented in NLLB service"
        }

    def get_supported_languages(self) -> List[Dict[str, str]]:
        """Get list of supported languages"""
        return [
            {"code": "it", "name": "Italiano"},
            {"code": "en", "name": "English"},
            {"code": "es", "name": "Español"},
            {"code": "fr", "name": "Français"},
            {"code": "de", "name": "Deutsch"},
            {"code": "pt", "name": "Português"},
            {"code": "ja", "name": "日本語"},
            {"code": "zh", "name": "中文"},
            {"code": "ko", "name": "한국어"},
            {"code": "ar", "name": "العربية"},
        ]

    def clear_cache(self):
        """Clear translation cache"""
        self.translation_cache.clear()
        logger.info("Translation cache cleared")

    def get_learning_stats(self) -> dict:
        """Get statistics about learned corrections"""
        return {
            "total_corrections": len(self.learning_db),
            "by_language": self._count_by_language(),
            "recent_corrections": self.learning_db[-10:]  # Last 10
        }

    def _count_by_language(self) -> Dict[str, int]:
        """Count corrections by target language"""
        counts = {}
        for correction in self.learning_db:
            lang = correction["target_lang"]
            counts[lang] = counts.get(lang, 0) + 1
        return counts


# Global instance
_nllb_service: Optional[NLLBTranslationService] = None


def get_nllb_service() -> NLLBTranslationService:
    """Get global NLLB service instance"""
    global _nllb_service
    if _nllb_service is None:
        _nllb_service = NLLBTranslationService()
    return _nllb_service

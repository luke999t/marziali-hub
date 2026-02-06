# translation_manager.py
"""
AI_MODULE: Translation Manager (Multilingual Support)
AI_DESCRIPTION: Gestisce traduzioni per 5 lingue (IT, EN, ES, FR, DE)
AI_BUSINESS: Internazionalizzazione per mercato globale
AI_TEACHING: i18n per supporto multi-lingua

ALTERNATIVE_VALUTATE:
- Gettext (.po files): Scartato, JSON più flessibile per web
- Database translations: Scartato, file system più veloce
- Runtime translation API: Scartato, troppo lento e costoso

PERCHÉ_QUESTA_SOLUZIONE:
- JSON files: Facili da editare, versionabili, veloci da leggere
- 5 lingue target: IT, EN, ES, FR, DE (mercati principali)
- Fallback intelligente: EN come default se chiave mancante
- Cache in memoria: Performance ottimali
"""

from typing import Dict, Any, Optional, List
from pathlib import Path
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# Supported languages
SUPPORTED_LANGUAGES = ['it', 'en', 'es', 'fr', 'de']
DEFAULT_LANGUAGE = 'en'


@dataclass
class LanguageInfo:
    """Informazioni lingua"""
    code: str
    name: str
    native: str


class TranslationManager:
    """
    Gestisce traduzioni multi-lingua per l'applicazione

    Features:
    - Caricamento JSON translations
    - 5 lingue supportate: IT, EN, ES, FR, DE
    - Fallback intelligente a EN
    - Cache in memoria
    - Nested key access (e.g., "video.controls.play")
    """

    def __init__(self, locales_dir: Optional[str] = None):
        """
        Inizializza TranslationManager

        Args:
            locales_dir: Path alla directory locales (default: src/locales)
        """
        if locales_dir is None:
            # Default to src/locales relative to this file
            locales_dir = Path(__file__).parent / "locales"

        self.locales_dir = Path(locales_dir)
        self.current_language = DEFAULT_LANGUAGE
        self.translations: Dict[str, Dict[str, Any]] = {}
        self.language_info: Dict[str, LanguageInfo] = {}

        # Load all translations
        self._load_all_translations()

        logger.info(f"TranslationManager initialized with {len(self.translations)} languages")

    def _load_all_translations(self):
        """Carica tutte le traduzioni disponibili"""
        for lang_code in SUPPORTED_LANGUAGES:
            try:
                self._load_language(lang_code)
                logger.info(f"Loaded translations for '{lang_code}'")
            except Exception as e:
                logger.error(f"Failed to load translations for '{lang_code}': {e}")

    def _load_language(self, lang_code: str):
        """
        Carica traduzioni per una specifica lingua

        Args:
            lang_code: Codice lingua (it, en, es, fr, de)
        """
        lang_file = self.locales_dir / f"{lang_code}.json"

        if not lang_file.exists():
            raise FileNotFoundError(f"Translation file not found: {lang_file}")

        with open(lang_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.translations[lang_code] = data

        # Store language info
        if 'language' in data:
            self.language_info[lang_code] = LanguageInfo(
                code=data['language'].get('code', lang_code),
                name=data['language'].get('name', lang_code.upper()),
                native=data['language'].get('native', lang_code.upper())
            )

    def set_language(self, lang_code: str) -> bool:
        """
        Imposta la lingua corrente

        Args:
            lang_code: Codice lingua (it, en, es, fr, de)

        Returns:
            True se lingua impostata con successo, False altrimenti
        """
        if lang_code not in SUPPORTED_LANGUAGES:
            logger.warning(f"Unsupported language: {lang_code}. Using default: {DEFAULT_LANGUAGE}")
            return False

        if lang_code not in self.translations:
            logger.warning(f"Translations not loaded for: {lang_code}")
            return False

        self.current_language = lang_code
        logger.info(f"Language set to: {lang_code}")
        return True

    def get_current_language(self) -> str:
        """Ottieni la lingua corrente"""
        return self.current_language

    def get_supported_languages(self) -> List[Dict[str, str]]:
        """
        Ottieni lista lingue supportate

        Returns:
            Lista di dict con info lingua (code, name, native)
        """
        return [
            {
                'code': info.code,
                'name': info.name,
                'native': info.native
            }
            for lang_code, info in self.language_info.items()
        ]

    def translate(
        self,
        key: str,
        lang: Optional[str] = None,
        fallback: Optional[str] = None
    ) -> str:
        """
        Traduci una chiave

        Args:
            key: Chiave traduzione (supporta nested: "video.controls.play")
            lang: Lingua target (default: lingua corrente)
            fallback: Testo di fallback se chiave non trovata

        Returns:
            Traduzione o fallback

        Examples:
            >>> manager.translate("common.play")  # "Play" (if EN)
            >>> manager.translate("video.controls.speed", lang="it")  # "Velocità"
            >>> manager.translate("unknown.key", fallback="N/A")  # "N/A"
        """
        if lang is None:
            lang = self.current_language

        # Get translation data for language
        translations = self.translations.get(lang)

        if not translations:
            # Try fallback to English
            if lang != DEFAULT_LANGUAGE:
                logger.warning(f"Language '{lang}' not found, falling back to '{DEFAULT_LANGUAGE}'")
                return self.translate(key, lang=DEFAULT_LANGUAGE, fallback=fallback)

            # No translations at all
            return fallback if fallback else key

        # Navigate nested keys (e.g., "video.controls.play")
        keys = key.split('.')
        value = translations

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                # Key not found in this language, try fallback to English
                if lang != DEFAULT_LANGUAGE:
                    logger.debug(f"Key '{key}' not found in '{lang}', trying '{DEFAULT_LANGUAGE}'")
                    return self.translate(key, lang=DEFAULT_LANGUAGE, fallback=fallback)

                # Not found in English either
                logger.debug(f"Key '{key}' not found in translations")
                return fallback if fallback else key

        return str(value)

    def t(self, key: str, **kwargs) -> str:
        """
        Shortcut per translate()

        Args:
            key: Chiave traduzione
            **kwargs: Parametri per translate() (lang, fallback)

        Returns:
            Traduzione

        Examples:
            >>> manager.t("common.play")
            >>> manager.t("video.speed", lang="it")
        """
        return self.translate(key, **kwargs)

    def get_section(
        self,
        section: str,
        lang: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ottieni un'intera sezione di traduzioni

        Args:
            section: Nome sezione (e.g., "common", "video", "annotations")
            lang: Lingua target (default: lingua corrente)

        Returns:
            Dictionary con tutte le traduzioni della sezione

        Examples:
            >>> manager.get_section("common")
            {'play': 'Play', 'pause': 'Pause', ...}
        """
        if lang is None:
            lang = self.current_language

        translations = self.translations.get(lang, {})
        return translations.get(section, {})

    def get_all_translations(self, lang: Optional[str] = None) -> Dict[str, Any]:
        """
        Ottieni tutte le traduzioni per una lingua

        Args:
            lang: Lingua target (default: lingua corrente)

        Returns:
            Dictionary completo traduzioni
        """
        if lang is None:
            lang = self.current_language

        return self.translations.get(lang, {})

    def has_key(self, key: str, lang: Optional[str] = None) -> bool:
        """
        Verifica se una chiave esiste

        Args:
            key: Chiave da verificare
            lang: Lingua target (default: lingua corrente)

        Returns:
            True se la chiave esiste, False altrimenti
        """
        if lang is None:
            lang = self.current_language

        translations = self.translations.get(lang, {})
        keys = key.split('.')
        value = translations

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return False

        return True

    def reload_translations(self):
        """Ricarica tutte le traduzioni (utile per hot-reload)"""
        self.translations.clear()
        self.language_info.clear()
        self._load_all_translations()
        logger.info("All translations reloaded")

    def get_missing_keys(
        self,
        reference_lang: str = 'en'
    ) -> Dict[str, List[str]]:
        """
        Trova chiavi mancanti in altre lingue rispetto a una di riferimento

        Args:
            reference_lang: Lingua di riferimento (default: en)

        Returns:
            Dict con lingua -> lista chiavi mancanti
        """
        if reference_lang not in self.translations:
            return {}

        reference = self.translations[reference_lang]
        missing = {}

        def get_all_keys(d: Dict, prefix: str = '') -> List[str]:
            """Recursive key extraction"""
            keys = []
            for k, v in d.items():
                full_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, dict):
                    keys.extend(get_all_keys(v, full_key))
                else:
                    keys.append(full_key)
            return keys

        reference_keys = set(get_all_keys(reference))

        for lang_code, translations in self.translations.items():
            if lang_code == reference_lang:
                continue

            lang_keys = set(get_all_keys(translations))
            missing_keys = reference_keys - lang_keys

            if missing_keys:
                missing[lang_code] = sorted(list(missing_keys))

        return missing


# Singleton instance
_translation_manager_instance: Optional[TranslationManager] = None


def get_translation_manager(locales_dir: Optional[str] = None) -> TranslationManager:
    """
    Ottieni singleton TranslationManager

    Args:
        locales_dir: Path alla directory locales (solo per init)

    Returns:
        TranslationManager instance
    """
    global _translation_manager_instance

    if _translation_manager_instance is None:
        _translation_manager_instance = TranslationManager(locales_dir)

    return _translation_manager_instance


# Convenience functions
def t(key: str, **kwargs) -> str:
    """
    Global translate function

    Args:
        key: Translation key
        **kwargs: Parameters for translate()

    Returns:
        Translation
    """
    manager = get_translation_manager()
    return manager.translate(key, **kwargs)


def set_language(lang_code: str) -> bool:
    """
    Global set language function

    Args:
        lang_code: Language code

    Returns:
        True if successful
    """
    manager = get_translation_manager()
    return manager.set_language(lang_code)


def get_current_language() -> str:
    """Get current language"""
    manager = get_translation_manager()
    return manager.get_current_language()

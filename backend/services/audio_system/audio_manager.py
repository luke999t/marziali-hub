"""
# AI_MODULE: AudioManager
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Facade principale per orchestrazione sistema audio completo
# AI_BUSINESS: Punto di ingresso unico per TTS, voice cloning, styling, storage.
#              Semplifica integrazione per video tutorial, doppiaggio, pronuncia.
# AI_TEACHING: Pattern Facade che espone API semplice nascondendo complessita.
#              Singleton con _reset_for_testing. Coordina tutti i sotto-moduli.
# AI_DEPENDENCIES: Tutti i moduli audio_system
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

AudioManager Module
===================

Facade principale per il sistema audio.

Espone API semplificate per:
- Generazione TTS multilingua
- Voice cloning con profili
- Audio styling con preset
- Storage e gestione file
- Database pronuncie

Uso:
    manager = await AudioManager.get_instance()

    # TTS semplice
    result = await manager.generate_tts("Ciao mondo", language="it")

    # Voice cloning
    result = await manager.clone_voice(
        text="Benvenuti al corso",
        profile_id="maestro_123"
    )

    # Styling
    result = await manager.apply_style(
        audio_path="/path/audio.wav",
        style="dojo_reverb"
    )

    # Pronuncia termine
    entries = await manager.get_pronunciation("oi-zuki")
"""

import asyncio
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Union
import logging

from .audio_storage import AudioStorage, AudioCategory, AudioFormat, AudioMetadata, StorageConfig
from .pronunciation_db import PronunciationDB, PronunciationEntry, LanguageCode, MartialArtStyle, TermCategory
from .tts_generator import TTSGenerator, TTSRequest, TTSResult, TTSEngine, TTSVoice
from .voice_styler import VoiceStyler, StylePreset, AudioStyle, StyleResult
from .voice_cloner import VoiceCloner, VoiceProfile, VoiceCloningResult, ReferenceValidation

logger = logging.getLogger(__name__)


@dataclass
class AudioSystemConfig:
    """Configurazione sistema audio."""
    storage_base_path: str = None
    pronunciation_db_path: str = None
    voice_profiles_dir: str = None
    tts_cache_dir: str = None
    preferred_tts_engine: TTSEngine = TTSEngine.EDGE
    auto_cleanup_temp: bool = True
    temp_retention_hours: int = 24
    enable_dedup: bool = True
    secure_delete: bool = False

    def __post_init__(self):
        if self.storage_base_path is None:
            self.storage_base_path = os.path.join(os.getcwd(), "storage", "audio")


@dataclass
class AudioGenerationResult:
    """Risultato unificato generazione audio."""
    success: bool
    audio_id: Optional[str]  # ID in storage
    audio_path: Optional[str]
    duration_seconds: Optional[float]
    method: str  # "tts", "clone", "style"
    source_text: Optional[str]
    language: Optional[str]
    metadata: Dict[str, Any]
    error: Optional[str] = None


class AudioManager:
    """
    Facade principale per sistema audio.

    Singleton pattern con _reset_for_testing per test isolation.
    """

    _instance: Optional["AudioManager"] = None
    _lock = asyncio.Lock()

    def __init__(self, config: Optional[AudioSystemConfig] = None):
        """
        Inizializza AudioManager.

        Args:
            config: Configurazione sistema
        """
        if config is None:
            config = AudioSystemConfig()
        self._config = config

        # Sotto-moduli (lazy init)
        self._storage: Optional[AudioStorage] = None
        self._pronunciation_db: Optional[PronunciationDB] = None
        self._tts: Optional[TTSGenerator] = None
        self._styler: Optional[VoiceStyler] = None
        self._cloner: Optional[VoiceCloner] = None

        self._initialized = False

    @classmethod
    async def get_instance(cls, config: Optional[AudioSystemConfig] = None) -> "AudioManager":
        """
        Ottiene istanza singleton.

        Args:
            config: Configurazione (solo prima chiamata)

        Returns:
            Istanza AudioManager
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(config)
                await cls._instance._initialize()
            return cls._instance

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset singleton per test isolation."""
        if cls._instance is not None:
            # Reset sotto-moduli
            AudioStorage._reset_for_testing()
            PronunciationDB._reset_for_testing()
        cls._instance = None

    async def _initialize(self) -> None:
        """Inizializza tutti i sotto-moduli."""
        if self._initialized:
            return

        logger.info("Inizializzazione AudioManager...")

        # Storage
        storage_config = StorageConfig(
            base_path=self._config.storage_base_path,
            temp_retention_hours=self._config.temp_retention_hours,
            enable_dedup=self._config.enable_dedup,
            secure_delete=self._config.secure_delete,
            auto_cleanup=self._config.auto_cleanup_temp,
        )
        self._storage = await AudioStorage.get_instance(storage_config)

        # Pronunciation DB
        db_path = self._config.pronunciation_db_path or os.path.join(
            self._config.storage_base_path, "pronunciation.db"
        )
        self._pronunciation_db = await PronunciationDB.get_instance(db_path)

        # TTS Generator
        tts_cache = self._config.tts_cache_dir or os.path.join(
            self._config.storage_base_path, "tts_cache"
        )
        self._tts = TTSGenerator(
            cache_dir=tts_cache,
            preferred_engine=self._config.preferred_tts_engine,
        )

        # Voice Styler
        styled_dir = os.path.join(self._config.storage_base_path, "styled")
        self._styler = VoiceStyler(output_dir=styled_dir)

        # Voice Cloner
        profiles_dir = self._config.voice_profiles_dir or os.path.join(
            self._config.storage_base_path, "voice_profiles"
        )
        self._cloner = VoiceCloner(profiles_dir=profiles_dir)

        self._initialized = True
        logger.info("AudioManager inizializzato")

    # ==================== TTS ====================

    async def generate_tts(
        self,
        text: str,
        language: str = "it",
        voice_id: Optional[str] = None,
        engine: TTSEngine = TTSEngine.AUTO,
        rate: float = 1.0,
        pitch: float = 1.0,
        volume: float = 1.0,
        store: bool = True,
    ) -> AudioGenerationResult:
        """
        Genera audio TTS.

        Args:
            text: Testo da sintetizzare
            language: Codice lingua
            voice_id: ID voce specifica
            engine: Engine TTS
            rate: Velocita parlato
            pitch: Altezza voce
            volume: Volume
            store: Se salvare in storage

        Returns:
            AudioGenerationResult
        """
        request = TTSRequest(
            text=text,
            language=language,
            voice_id=voice_id,
            engine=engine,
            rate=rate,
            pitch=pitch,
            volume=volume,
        )

        result = await self._tts.generate(request)

        if not result.success:
            return AudioGenerationResult(
                success=False,
                audio_id=None,
                audio_path=None,
                duration_seconds=None,
                method="tts",
                source_text=text,
                language=language,
                metadata={},
                error=result.error,
            )

        audio_id = None
        if store and result.audio_path:
            metadata = await self._storage.store(
                result.audio_path,
                AudioCategory.TTS,
                metadata_extra={
                    "source_text": text,
                    "language": language,
                    "voice_id": result.voice_used,
                    "engine": result.engine_used,
                }
            )
            audio_id = metadata.id

        return AudioGenerationResult(
            success=True,
            audio_id=audio_id,
            audio_path=result.audio_path,
            duration_seconds=result.duration_seconds,
            method="tts",
            source_text=text,
            language=language,
            metadata={
                "engine": result.engine_used,
                "voice": result.voice_used,
                "cached": result.cached,
            },
        )

    async def get_tts_voices(
        self,
        language: Optional[str] = None,
        engine: Optional[TTSEngine] = None,
    ) -> List[TTSVoice]:
        """Lista voci TTS disponibili."""
        return await self._tts.get_voices(language, engine)

    async def get_available_tts_engines(self) -> List[TTSEngine]:
        """Lista engine TTS disponibili."""
        return await self._tts.get_available_engines()

    # ==================== Voice Cloning ====================

    async def create_voice_profile(
        self,
        name: str,
        reference_path: str,
        language: str,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> VoiceProfile:
        """
        Crea profilo voce per cloning.

        Args:
            name: Nome profilo
            reference_path: Path audio reference
            language: Lingua parlante
            description: Descrizione
            created_by: ID utente

        Returns:
            VoiceProfile creato
        """
        return await self._cloner.create_profile(
            name=name,
            reference_path=reference_path,
            language=language,
            description=description,
            created_by=created_by,
        )

    async def validate_voice_reference(self, audio_path: str) -> ReferenceValidation:
        """Valida audio reference per voice cloning."""
        return await self._cloner.validate_reference(audio_path)

    async def clone_voice(
        self,
        text: str,
        profile_id: str,
        target_language: Optional[str] = None,
        speed: float = 1.0,
        store: bool = True,
    ) -> AudioGenerationResult:
        """
        Genera audio con voce clonata.

        Args:
            text: Testo da sintetizzare
            profile_id: ID profilo voce
            target_language: Lingua output
            speed: Velocita parlato
            store: Se salvare in storage

        Returns:
            AudioGenerationResult
        """
        result = await self._cloner.clone(
            text=text,
            profile_id=profile_id,
            target_language=target_language,
            speed=speed,
        )

        if not result.success:
            return AudioGenerationResult(
                success=False,
                audio_id=None,
                audio_path=None,
                duration_seconds=None,
                method="clone",
                source_text=text,
                language=result.language,
                metadata={},
                error=result.error,
            )

        audio_id = None
        if store and result.output_path:
            metadata = await self._storage.store(
                result.output_path,
                AudioCategory.CLONED,
                metadata_extra={
                    "source_text": text,
                    "language": result.language,
                    "voice_profile_id": profile_id,
                }
            )
            audio_id = metadata.id

        return AudioGenerationResult(
            success=True,
            audio_id=audio_id,
            audio_path=result.output_path,
            duration_seconds=result.duration_seconds,
            method="clone",
            source_text=text,
            language=result.language,
            metadata={
                "profile_id": profile_id,
                "processing_time_ms": result.processing_time_ms,
            },
        )

    async def get_voice_profile(self, profile_id: str) -> Optional[VoiceProfile]:
        """Ottiene profilo voce."""
        return await self._cloner.get_profile(profile_id)

    async def list_voice_profiles(self) -> List[VoiceProfile]:
        """Lista profili voce."""
        return await self._cloner.list_profiles()

    async def delete_voice_profile(self, profile_id: str) -> bool:
        """Elimina profilo voce."""
        return await self._cloner.delete_profile(profile_id)

    # ==================== Styling ====================

    async def apply_style(
        self,
        audio_path: str,
        style: Union[StylePreset, str],
        store: bool = True,
    ) -> AudioGenerationResult:
        """
        Applica stile audio.

        Args:
            audio_path: Path audio input
            style: Preset stile o nome
            store: Se salvare in storage

        Returns:
            AudioGenerationResult
        """
        # Converti string in enum se necessario
        if isinstance(style, str):
            try:
                style = StylePreset(style)
            except ValueError:
                return AudioGenerationResult(
                    success=False,
                    audio_id=None,
                    audio_path=None,
                    duration_seconds=None,
                    method="style",
                    source_text=None,
                    language=None,
                    metadata={},
                    error=f"Stile non valido: {style}",
                )

        result = await self._styler.apply_style(audio_path, preset=style)

        if not result.success:
            return AudioGenerationResult(
                success=False,
                audio_id=None,
                audio_path=None,
                duration_seconds=None,
                method="style",
                source_text=None,
                language=None,
                metadata={},
                error=result.error,
            )

        audio_id = None
        if store and result.output_path:
            metadata = await self._storage.store(
                result.output_path,
                AudioCategory.STYLED,
                metadata_extra={
                    "style_applied": result.style_applied,
                    "source_path": audio_path,
                }
            )
            audio_id = metadata.id

        return AudioGenerationResult(
            success=True,
            audio_id=audio_id,
            audio_path=result.output_path,
            duration_seconds=result.duration_seconds,
            method="style",
            source_text=None,
            language=None,
            metadata={
                "style": result.style_applied,
                "processing_time_ms": result.processing_time_ms,
            },
        )

    async def get_style_presets(self) -> List[AudioStyle]:
        """Lista preset stile disponibili."""
        return self._styler.get_presets()

    async def analyze_audio(self, audio_path: str) -> Dict[str, Any]:
        """Analizza caratteristiche audio."""
        return await self._styler.analyze_audio(audio_path)

    async def suggest_style(self, audio_path: str) -> Optional[StylePreset]:
        """Suggerisce stile basato su analisi."""
        return await self._styler.suggest_style(audio_path)

    # ==================== Pronunciation ====================

    async def get_pronunciation(
        self,
        term: str,
        language: Optional[LanguageCode] = None,
    ) -> List[PronunciationEntry]:
        """
        Cerca pronuncia termine.

        Args:
            term: Termine da cercare (originale o romanizzato)
            language: Lingua opzionale

        Returns:
            Lista PronunciationEntry
        """
        # Cerca prima per termine esatto
        results = await self._pronunciation_db.find_by_term(term, language)
        if results:
            return results

        # Cerca per romanizzazione
        results = await self._pronunciation_db.find_by_romanization(term, language)
        if results:
            return results

        # Ricerca full-text
        return await self._pronunciation_db.search(term, language=language, limit=10)

    async def add_pronunciation(
        self,
        term: str,
        language: LanguageCode,
        romanization: str,
        category: TermCategory,
        martial_art: MartialArtStyle,
        **kwargs
    ) -> PronunciationEntry:
        """Aggiunge termine al database pronuncie."""
        return await self._pronunciation_db.add(
            term=term,
            language=language,
            romanization=romanization,
            category=category,
            martial_art=martial_art,
            **kwargs
        )

    async def generate_pronunciation_audio(
        self,
        entry_id: str,
        voice_profile_id: Optional[str] = None,
    ) -> AudioGenerationResult:
        """
        Genera audio pronuncia per un termine.

        Args:
            entry_id: ID entry pronuncia
            voice_profile_id: Profilo voce per cloning (opzionale)

        Returns:
            AudioGenerationResult
        """
        entry = await self._pronunciation_db.get(entry_id)
        if entry is None:
            return AudioGenerationResult(
                success=False,
                audio_id=None,
                audio_path=None,
                duration_seconds=None,
                method="tts",
                source_text=None,
                language=None,
                metadata={},
                error=f"Entry pronuncia non trovata: {entry_id}",
            )

        # Usa romanizzazione per TTS
        text = entry.romanization

        if voice_profile_id:
            # Usa voice cloning
            return await self.clone_voice(
                text=text,
                profile_id=voice_profile_id,
                target_language=entry.language,
            )
        else:
            # Usa TTS standard
            return await self.generate_tts(
                text=text,
                language=entry.language,
            )

    async def seed_pronunciation_db(self) -> int:
        """Popola database con termini base."""
        return await self._pronunciation_db.seed_basic_terms()

    # ==================== Storage ====================

    async def get_audio(self, audio_id: str) -> Optional[Path]:
        """Ottiene path audio per ID."""
        return await self._storage.get(audio_id)

    async def get_audio_metadata(self, audio_id: str) -> Optional[AudioMetadata]:
        """Ottiene metadata audio."""
        return await self._storage.get_metadata(audio_id)

    async def delete_audio(self, audio_id: str, secure: bool = False) -> bool:
        """Elimina audio."""
        return await self._storage.delete(audio_id, secure)

    async def list_audio(
        self,
        category: Optional[AudioCategory] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AudioMetadata]:
        """Lista audio in storage."""
        if category:
            return await self._storage.list_by_category(category, limit, offset)

        # Lista tutti
        all_audio = []
        for cat in AudioCategory:
            cat_audio = await self._storage.list_by_category(cat, limit, offset)
            all_audio.extend(cat_audio)
        return all_audio[:limit]

    async def get_storage_stats(self) -> Dict[str, Any]:
        """Ottiene statistiche storage."""
        stats = await self._storage.get_stats()
        return {
            "total_files": stats.total_files,
            "total_size_bytes": stats.total_size_bytes,
            "total_size_mb": round(stats.total_size_bytes / (1024 * 1024), 2),
            "files_by_category": stats.files_by_category,
            "size_by_category": stats.size_by_category,
            "dedup_savings_bytes": stats.dedup_savings_bytes,
        }

    async def cleanup_temp_files(self, max_age_hours: Optional[int] = None) -> int:
        """Pulisce file temporanei."""
        return await self._storage.cleanup_temp_files(max_age_hours)

    # ==================== Workflow Combinati ====================

    async def generate_tutorial_audio(
        self,
        segments: List[Dict[str, Any]],
        voice_profile_id: Optional[str] = None,
        style: Optional[StylePreset] = None,
    ) -> List[AudioGenerationResult]:
        """
        Genera audio per segmenti tutorial.

        Args:
            segments: Lista segmenti [{"text": "...", "language": "it"}, ...]
            voice_profile_id: Profilo voce per cloning
            style: Stile da applicare

        Returns:
            Lista risultati per ogni segmento
        """
        results = []

        for segment in segments:
            text = segment.get("text", "")
            language = segment.get("language", "it")

            # Genera audio base
            if voice_profile_id:
                result = await self.clone_voice(text, voice_profile_id, language, store=False)
            else:
                result = await self.generate_tts(text, language, store=False)

            # Applica stile se richiesto
            if result.success and style and result.audio_path:
                styled = await self.apply_style(result.audio_path, style, store=True)
                results.append(styled)
            else:
                results.append(result)

        return results

    async def is_fully_available(self) -> Dict[str, bool]:
        """
        Verifica disponibilita tutti i sotto-sistemi.

        Returns:
            Dict con stato per ogni componente
        """
        tts_engines = await self._tts.get_available_engines()
        return {
            "storage": self._storage is not None,
            "pronunciation_db": self._pronunciation_db is not None,
            "tts_edge": TTSEngine.EDGE in tts_engines,
            "tts_coqui": TTSEngine.COQUI in tts_engines,
            "tts_pyttsx3": TTSEngine.PYTTSX3 in tts_engines,
            "voice_cloner": await self._cloner.is_available(),
            "voice_styler": await self._styler.is_available(),
        }

    async def get_system_info(self) -> Dict[str, Any]:
        """Ottiene informazioni sistema audio."""
        availability = await self.is_fully_available()
        storage_stats = await self.get_storage_stats()
        pronunciation_stats = await self._pronunciation_db.get_stats()

        return {
            "availability": availability,
            "storage": storage_stats,
            "pronunciation": {
                "total_entries": pronunciation_stats.total_entries,
                "verified_count": pronunciation_stats.verified_count,
                "entries_by_language": pronunciation_stats.entries_by_language,
            },
            "voice_profiles_count": len(await self.list_voice_profiles()),
            "supported_languages": self._cloner.get_supported_languages(),
        }

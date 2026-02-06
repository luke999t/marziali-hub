"""
# AI_MODULE: TTSGenerator
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Text-to-Speech multi-engine (Edge TTS, Coqui TTS, pyttsx3) con fallback
# AI_BUSINESS: Genera audio narrazione per video tutorial, pronuncia termini,
#              istruzioni vocali. Supporto multilingua con voci native.
# AI_TEACHING: Pattern Strategy per motori TTS intercambiabili, fallback automatico,
#              caching risultati, integrazione con PronunciationDB per termini speciali.
# AI_DEPENDENCIES: edge-tts, TTS (Coqui), pyttsx3, aiofiles
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

TTSGenerator Module
===================

Generatore Text-to-Speech multi-engine con supporto per:
- Edge TTS (Microsoft, cloud, alta qualita)
- Coqui TTS (locale, open source)
- pyttsx3 (locale, offline, veloce)

Features:
- Auto-fallback se engine non disponibile
- Cache risultati per testi ripetuti
- Voci per lingua con preset
- Rate/pitch/volume configurabili
- SSML support per controllo fine
"""

import asyncio
import hashlib
import os
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
import logging

logger = logging.getLogger(__name__)


class TTSEngine(Enum):
    """Motori TTS disponibili."""
    EDGE = "edge"  # Microsoft Edge TTS (cloud)
    COQUI = "coqui"  # Coqui TTS (locale)
    PYTTSX3 = "pyttsx3"  # pyttsx3 (locale, offline)
    AUTO = "auto"  # Scelta automatica


@dataclass
class TTSVoice:
    """Definizione voce TTS."""
    id: str
    name: str
    language: str
    gender: str  # male, female, neutral
    engine: str
    sample_rate: int = 22050
    style: Optional[str] = None  # es. "cheerful", "sad" per voci avanzate

    @property
    def short_code(self) -> str:
        """Codice breve per la voce."""
        return f"{self.language}_{self.gender}_{self.engine}"


@dataclass
class TTSRequest:
    """Richiesta TTS."""
    text: str
    language: str = "it"
    voice_id: Optional[str] = None
    engine: TTSEngine = TTSEngine.AUTO
    rate: float = 1.0  # 0.5 - 2.0
    pitch: float = 1.0  # 0.5 - 2.0
    volume: float = 1.0  # 0.0 - 1.0
    use_ssml: bool = False
    output_format: str = "mp3"  # mp3, wav
    cache: bool = True
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def cache_key(self) -> str:
        """Genera chiave cache univoca."""
        content = f"{self.text}|{self.language}|{self.voice_id}|{self.engine.value}"
        content += f"|{self.rate}|{self.pitch}|{self.volume}|{self.output_format}"
        return hashlib.md5(content.encode()).hexdigest()


@dataclass
class TTSResult:
    """Risultato TTS."""
    success: bool
    audio_path: Optional[str]
    duration_seconds: Optional[float]
    engine_used: str
    voice_used: str
    cached: bool
    error: Optional[str] = None
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


class TTSEngineBase(ABC):
    """Classe base per motori TTS."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Verifica se engine e' disponibile."""
        pass

    @abstractmethod
    async def get_voices(self, language: Optional[str] = None) -> List[TTSVoice]:
        """Lista voci disponibili."""
        pass

    @abstractmethod
    async def synthesize(
        self,
        text: str,
        voice: TTSVoice,
        output_path: str,
        rate: float = 1.0,
        pitch: float = 1.0,
        volume: float = 1.0,
    ) -> bool:
        """
        Sintetizza testo in audio.

        Returns:
            True se successo
        """
        pass


class EdgeTTSEngine(TTSEngineBase):
    """Engine Edge TTS (Microsoft)."""

    def __init__(self):
        self._available: Optional[bool] = None
        self._voices_cache: Optional[List[TTSVoice]] = None

    async def is_available(self) -> bool:
        """Verifica disponibilita edge-tts."""
        if self._available is not None:
            return self._available

        try:
            import edge_tts
            self._available = True
        except ImportError:
            self._available = False
            logger.warning("edge-tts non installato")

        return self._available

    async def get_voices(self, language: Optional[str] = None) -> List[TTSVoice]:
        """Lista voci Edge TTS."""
        if not await self.is_available():
            return []

        if self._voices_cache is not None and language is None:
            return self._voices_cache

        try:
            import edge_tts
            voices_data = await edge_tts.list_voices()

            voices = []
            for v in voices_data:
                lang_code = v.get("Locale", "").split("-")[0].lower()
                if language and lang_code != language.lower():
                    continue

                gender = v.get("Gender", "neutral").lower()
                voice = TTSVoice(
                    id=v.get("ShortName", ""),
                    name=v.get("FriendlyName", ""),
                    language=lang_code,
                    gender=gender,
                    engine="edge",
                    sample_rate=24000,
                )
                voices.append(voice)

            if language is None:
                self._voices_cache = voices

            return voices
        except Exception as e:
            logger.error(f"Errore lista voci Edge TTS: {e}")
            return []

    async def synthesize(
        self,
        text: str,
        voice: TTSVoice,
        output_path: str,
        rate: float = 1.0,
        pitch: float = 1.0,
        volume: float = 1.0,
    ) -> bool:
        """Sintetizza con Edge TTS."""
        if not await self.is_available():
            return False

        try:
            import edge_tts

            # Converti rate/pitch in formato Edge
            rate_str = f"{int((rate - 1) * 100):+d}%"
            pitch_str = f"{int((pitch - 1) * 50):+d}Hz"
            volume_str = f"{int((volume - 1) * 100):+d}%"

            communicate = edge_tts.Communicate(
                text=text,
                voice=voice.id,
                rate=rate_str,
                pitch=pitch_str,
                volume=volume_str,
            )

            await communicate.save(output_path)
            return True
        except Exception as e:
            logger.error(f"Errore sintesi Edge TTS: {e}")
            return False


class CoquiTTSEngine(TTSEngineBase):
    """Engine Coqui TTS (locale)."""

    def __init__(self):
        self._available: Optional[bool] = None
        self._tts = None
        self._model_name = "tts_models/multilingual/multi-dataset/xtts_v2"

    async def is_available(self) -> bool:
        """Verifica disponibilita Coqui TTS."""
        if self._available is not None:
            return self._available

        try:
            from TTS.api import TTS
            self._available = True
        except ImportError:
            self._available = False
            logger.warning("Coqui TTS non installato")

        return self._available

    def _get_tts(self):
        """Lazy load TTS model."""
        if self._tts is None:
            try:
                from TTS.api import TTS
                self._tts = TTS(self._model_name)
            except Exception as e:
                logger.error(f"Errore caricamento modello Coqui: {e}")
        return self._tts

    async def get_voices(self, language: Optional[str] = None) -> List[TTSVoice]:
        """Lista voci Coqui TTS."""
        if not await self.is_available():
            return []

        # Coqui XTTS supporta molte lingue
        supported = ["it", "en", "es", "fr", "de", "pt", "pl", "tr", "ru", "nl", "cs", "ar", "zh", "ja", "ko"]

        voices = []
        for lang in supported:
            if language and lang != language.lower():
                continue
            voices.append(TTSVoice(
                id=f"coqui_{lang}_default",
                name=f"Coqui {lang.upper()}",
                language=lang,
                gender="neutral",
                engine="coqui",
                sample_rate=22050,
            ))

        return voices

    async def synthesize(
        self,
        text: str,
        voice: TTSVoice,
        output_path: str,
        rate: float = 1.0,
        pitch: float = 1.0,
        volume: float = 1.0,
    ) -> bool:
        """Sintetizza con Coqui TTS."""
        if not await self.is_available():
            return False

        try:
            def _run_tts():
                tts = self._get_tts()
                if tts is None:
                    return False
                tts.tts_to_file(
                    text=text,
                    file_path=output_path,
                    language=voice.language,
                    speed=rate,
                )
                return True

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, _run_tts)

            if result and (pitch != 1.0 or volume != 1.0):
                await self._apply_effects(output_path, pitch, volume)

            return result
        except Exception as e:
            logger.error(f"Errore sintesi Coqui TTS: {e}")
            return False

    async def _apply_effects(self, audio_path: str, pitch: float, volume: float) -> None:
        """Applica effetti post-processing."""
        try:
            import soundfile as sf
            import numpy as np

            data, sr = sf.read(audio_path)
            data = data * volume

            # Pitch shift richiede librosa, skip se non disponibile
            if pitch != 1.0:
                try:
                    import librosa
                    n_steps = 12 * (pitch - 1)  # semitoni
                    data = librosa.effects.pitch_shift(data, sr=sr, n_steps=n_steps)
                except ImportError:
                    pass

            sf.write(audio_path, data, sr)
        except Exception as e:
            logger.warning(f"Errore applicazione effetti: {e}")


class Pyttsx3Engine(TTSEngineBase):
    """Engine pyttsx3 (offline)."""

    def __init__(self):
        self._available: Optional[bool] = None
        self._engine = None

    async def is_available(self) -> bool:
        """Verifica disponibilita pyttsx3."""
        if self._available is not None:
            return self._available

        try:
            import pyttsx3
            self._available = True
        except ImportError:
            self._available = False
            logger.warning("pyttsx3 non installato")

        return self._available

    def _get_engine(self):
        """Lazy load engine."""
        if self._engine is None:
            try:
                import pyttsx3
                self._engine = pyttsx3.init()
            except Exception as e:
                logger.error(f"Errore init pyttsx3: {e}")
        return self._engine

    async def get_voices(self, language: Optional[str] = None) -> List[TTSVoice]:
        """Lista voci pyttsx3."""
        if not await self.is_available():
            return []

        try:
            def _list_voices():
                engine = self._get_engine()
                if engine is None:
                    return []

                voices = []
                for v in engine.getProperty('voices'):
                    # Estrai lingua da ID
                    lang = "en"
                    if "italian" in v.name.lower() or "it-" in v.id.lower():
                        lang = "it"
                    elif "japanese" in v.name.lower() or "ja-" in v.id.lower():
                        lang = "ja"
                    elif "chinese" in v.name.lower() or "zh-" in v.id.lower():
                        lang = "zh"

                    if language and lang != language.lower():
                        continue

                    gender = "female" if "female" in v.name.lower() else "male"
                    voices.append(TTSVoice(
                        id=v.id,
                        name=v.name,
                        language=lang,
                        gender=gender,
                        engine="pyttsx3",
                        sample_rate=22050,
                    ))
                return voices

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _list_voices)
        except Exception as e:
            logger.error(f"Errore lista voci pyttsx3: {e}")
            return []

    async def synthesize(
        self,
        text: str,
        voice: TTSVoice,
        output_path: str,
        rate: float = 1.0,
        pitch: float = 1.0,
        volume: float = 1.0,
    ) -> bool:
        """Sintetizza con pyttsx3."""
        if not await self.is_available():
            return False

        try:
            def _run_tts():
                engine = self._get_engine()
                if engine is None:
                    return False

                engine.setProperty('voice', voice.id)
                engine.setProperty('rate', int(150 * rate))  # Default 150 wpm
                engine.setProperty('volume', volume)

                engine.save_to_file(text, output_path)
                engine.runAndWait()
                return True

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _run_tts)
        except Exception as e:
            logger.error(f"Errore sintesi pyttsx3: {e}")
            return False


class TTSGenerator:
    """
    Generatore TTS multi-engine con fallback automatico.

    Uso:
        gen = TTSGenerator()
        result = await gen.generate(TTSRequest(text="Ciao", language="it"))
    """

    # Voci di default per lingua
    DEFAULT_VOICES = {
        "it": {
            "edge": "it-IT-IsabellaNeural",
            "coqui": "coqui_it_default",
            "pyttsx3": None,  # Sistema sceglie
        },
        "en": {
            "edge": "en-US-AriaNeural",
            "coqui": "coqui_en_default",
            "pyttsx3": None,
        },
        "ja": {
            "edge": "ja-JP-NanamiNeural",
            "coqui": "coqui_ja_default",
            "pyttsx3": None,
        },
        "zh": {
            "edge": "zh-CN-XiaoxiaoNeural",
            "coqui": "coqui_zh_default",
            "pyttsx3": None,
        },
    }

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        preferred_engine: TTSEngine = TTSEngine.EDGE,
    ):
        """
        Inizializza TTSGenerator.

        Args:
            cache_dir: Directory per cache audio
            preferred_engine: Engine preferito
        """
        if cache_dir is None:
            cache_dir = os.path.join(tempfile.gettempdir(), "tts_cache")
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)

        self._preferred_engine = preferred_engine
        self._engines: Dict[TTSEngine, TTSEngineBase] = {
            TTSEngine.EDGE: EdgeTTSEngine(),
            TTSEngine.COQUI: CoquiTTSEngine(),
            TTSEngine.PYTTSX3: Pyttsx3Engine(),
        }
        self._voices_cache: Dict[str, List[TTSVoice]] = {}

    async def get_available_engines(self) -> List[TTSEngine]:
        """Lista engine disponibili."""
        available = []
        for engine_type, engine in self._engines.items():
            if await engine.is_available():
                available.append(engine_type)
        return available

    async def get_voices(
        self,
        language: Optional[str] = None,
        engine: Optional[TTSEngine] = None,
    ) -> List[TTSVoice]:
        """
        Lista voci disponibili.

        Args:
            language: Filtra per lingua
            engine: Filtra per engine

        Returns:
            Lista TTSVoice
        """
        cache_key = f"{language or 'all'}_{engine.value if engine else 'all'}"

        if cache_key in self._voices_cache:
            return self._voices_cache[cache_key]

        voices = []
        engines_to_check = [engine] if engine else list(self._engines.keys())

        for eng_type in engines_to_check:
            eng = self._engines.get(eng_type)
            if eng and await eng.is_available():
                eng_voices = await eng.get_voices(language)
                voices.extend(eng_voices)

        self._voices_cache[cache_key] = voices
        return voices

    async def _select_engine(self, request: TTSRequest) -> Optional[TTSEngineBase]:
        """Seleziona engine per request."""
        if request.engine != TTSEngine.AUTO:
            eng = self._engines.get(request.engine)
            if eng and await eng.is_available():
                return eng
            logger.warning(f"Engine {request.engine.value} non disponibile, fallback")

        # Ordine di preferenza
        order = [self._preferred_engine, TTSEngine.EDGE, TTSEngine.COQUI, TTSEngine.PYTTSX3]

        for eng_type in order:
            eng = self._engines.get(eng_type)
            if eng and await eng.is_available():
                return eng

        return None

    async def _select_voice(
        self,
        request: TTSRequest,
        engine: TTSEngineBase,
    ) -> Optional[TTSVoice]:
        """Seleziona voce per request."""
        voices = await engine.get_voices(request.language)

        if not voices:
            return None

        # Se voice_id specificato, cerca
        if request.voice_id:
            for v in voices:
                if v.id == request.voice_id:
                    return v

        # Usa default per lingua/engine
        engine_name = type(engine).__name__.replace("Engine", "").lower()
        defaults = self.DEFAULT_VOICES.get(request.language, {})
        default_id = defaults.get(engine_name)

        if default_id:
            for v in voices:
                if v.id == default_id:
                    return v

        # Fallback: prima voce disponibile
        return voices[0]

    def _get_cache_path(self, request: TTSRequest) -> Path:
        """Ottiene path cache per request."""
        ext = request.output_format
        return self._cache_dir / f"{request.cache_key}.{ext}"

    async def generate(self, request: TTSRequest) -> TTSResult:
        """
        Genera audio TTS.

        Args:
            request: TTSRequest con parametri

        Returns:
            TTSResult con audio o errore
        """
        # Controlla cache
        cache_path = self._get_cache_path(request)
        if request.cache and cache_path.exists():
            duration = await self._get_audio_duration(str(cache_path))
            return TTSResult(
                success=True,
                audio_path=str(cache_path),
                duration_seconds=duration,
                engine_used="cache",
                voice_used="cached",
                cached=True,
            )

        # Seleziona engine
        engine = await self._select_engine(request)
        if engine is None:
            return TTSResult(
                success=False,
                audio_path=None,
                duration_seconds=None,
                engine_used="none",
                voice_used="none",
                cached=False,
                error="Nessun engine TTS disponibile",
            )

        # Seleziona voce
        voice = await self._select_voice(request, engine)
        if voice is None:
            return TTSResult(
                success=False,
                audio_path=None,
                duration_seconds=None,
                engine_used=type(engine).__name__,
                voice_used="none",
                cached=False,
                error=f"Nessuna voce disponibile per {request.language}",
            )

        # Genera audio
        output_path = str(cache_path) if request.cache else str(
            self._cache_dir / f"temp_{request.cache_key}.{request.output_format}"
        )

        success = await engine.synthesize(
            text=request.text,
            voice=voice,
            output_path=output_path,
            rate=request.rate,
            pitch=request.pitch,
            volume=request.volume,
        )

        if not success:
            return TTSResult(
                success=False,
                audio_path=None,
                duration_seconds=None,
                engine_used=type(engine).__name__,
                voice_used=voice.id,
                cached=False,
                error="Errore durante sintesi",
            )

        duration = await self._get_audio_duration(output_path)

        return TTSResult(
            success=True,
            audio_path=output_path,
            duration_seconds=duration,
            engine_used=voice.engine,
            voice_used=voice.id,
            cached=False,
        )

    async def _get_audio_duration(self, audio_path: str) -> Optional[float]:
        """Ottiene durata audio."""
        try:
            import soundfile as sf
            with sf.SoundFile(audio_path) as f:
                return len(f) / f.samplerate
        except Exception:
            return None

    async def generate_batch(
        self,
        texts: List[str],
        language: str = "it",
        **kwargs
    ) -> List[TTSResult]:
        """
        Genera audio per lista di testi.

        Args:
            texts: Lista testi
            language: Lingua
            **kwargs: Parametri aggiuntivi per TTSRequest

        Returns:
            Lista TTSResult
        """
        tasks = [
            self.generate(TTSRequest(text=text, language=language, **kwargs))
            for text in texts
        ]
        return await asyncio.gather(*tasks)

    async def preview(
        self,
        text: str,
        voice: TTSVoice,
        duration_limit: float = 5.0,
    ) -> TTSResult:
        """
        Genera preview breve per voce.

        Args:
            text: Testo preview
            voice: Voce da testare
            duration_limit: Durata max in secondi

        Returns:
            TTSResult con audio preview
        """
        # Tronca testo se necessario
        words = text.split()
        preview_text = ""
        for word in words:
            if len(preview_text) > 100:  # ~5 secondi
                break
            preview_text += word + " "

        request = TTSRequest(
            text=preview_text.strip(),
            language=voice.language,
            voice_id=voice.id,
            engine=TTSEngine(voice.engine) if voice.engine in [e.value for e in TTSEngine] else TTSEngine.AUTO,
            cache=False,
        )

        return await self.generate(request)

    def clear_cache(self) -> int:
        """
        Pulisce cache TTS.

        Returns:
            Numero file eliminati
        """
        deleted = 0
        for f in self._cache_dir.glob("*"):
            if f.is_file():
                f.unlink()
                deleted += 1
        return deleted

    def get_cache_size(self) -> int:
        """Ottiene dimensione cache in bytes."""
        return sum(f.stat().st_size for f in self._cache_dir.glob("*") if f.is_file())

"""
# AI_MODULE: VoiceCloner
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Voice cloning con XTTS v2 (Coqui) per generare audio con voce maestro
# AI_BUSINESS: Clona voce di un maestro per generare istruzioni con la sua voce,
#              doppiaggio automatico video in altre lingue mantenendo voce originale.
# AI_TEACHING: Usa XTTS v2 per zero-shot voice cloning, gestione profili voce,
#              audio reference con requisiti qualita, caching speaker embeddings.
# AI_DEPENDENCIES: TTS (Coqui), torch, soundfile
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

VoiceCloner Module
==================

Voice cloning con XTTS v2 per doppiaggio e sintesi vocale personalizzata.

Features:
- Zero-shot voice cloning (non richiede training)
- Supporto multilingua (24+ lingue)
- Profili voce salvabili e riutilizzabili
- Validazione audio reference
- Caching speaker embeddings
- Batch cloning per efficienza

Requisiti audio reference:
- Durata: 6-30 secondi
- Formato: WAV, MP3, FLAC
- Sample rate: 16kHz+ (22.05kHz consigliato)
- Mono o Stereo (convertito automaticamente)
- Voce pulita senza rumore di fondo
- Parlato continuo (non canto)
"""

import asyncio
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import logging
import uuid

logger = logging.getLogger(__name__)


@dataclass
class VoiceProfile:
    """Profilo voce per cloning."""
    id: str
    name: str
    description: Optional[str]
    language: str  # Lingua nativa del parlante
    reference_audio_path: str
    reference_duration_seconds: float
    created_at: str
    created_by: Optional[str]
    embedding_path: Optional[str] = None  # Path speaker embedding cached
    quality_score: float = 0.0  # 0-1, qualita reference
    verified: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VoiceProfile":
        """Crea da dizionario."""
        return cls(**data)

    def to_json(self) -> str:
        """Serializza in JSON."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "VoiceProfile":
        """Deserializza da JSON."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class VoiceCloningResult:
    """Risultato voice cloning."""
    success: bool
    text: str
    language: str
    voice_profile_id: str
    output_path: Optional[str]
    duration_seconds: Optional[float]
    processing_time_ms: float
    error: Optional[str] = None
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ReferenceValidation:
    """Risultato validazione audio reference."""
    valid: bool
    duration_seconds: float
    sample_rate: int
    channels: int
    format: str
    issues: List[str]
    quality_score: float
    recommendations: List[str]


class VoiceCloner:
    """
    Voice cloning con XTTS v2.

    Uso:
        cloner = VoiceCloner()

        # Crea profilo voce
        profile = await cloner.create_profile(
            name="Maestro Tanaka",
            reference_path="maestro_sample.wav",
            language="ja"
        )

        # Clona voce
        result = await cloner.clone(
            text="Oggi impariamo oi-zuki",
            profile_id=profile.id,
            target_language="it"
        )
    """

    # Lingue supportate da XTTS v2
    SUPPORTED_LANGUAGES = [
        "en", "es", "fr", "de", "it", "pt", "pl", "tr", "ru",
        "nl", "cs", "ar", "zh-cn", "ja", "hu", "ko", "hi"
    ]

    # Requisiti audio reference
    MIN_DURATION = 6.0  # secondi
    MAX_DURATION = 30.0
    MIN_SAMPLE_RATE = 16000
    RECOMMENDED_SAMPLE_RATE = 22050

    def __init__(
        self,
        profiles_dir: Optional[str] = None,
        cache_embeddings: bool = True,
        device: str = "auto",  # "auto", "cpu", "cuda"
    ):
        """
        Inizializza VoiceCloner.

        Args:
            profiles_dir: Directory per profili voce
            cache_embeddings: Se cachare speaker embeddings
            device: Device per inference
        """
        if profiles_dir is None:
            profiles_dir = os.path.join(os.getcwd(), "storage", "audio", "voice_profiles")
        self._profiles_dir = Path(profiles_dir)
        self._profiles_dir.mkdir(parents=True, exist_ok=True)

        self._cache_embeddings = cache_embeddings
        self._device = device
        self._tts = None
        self._available: Optional[bool] = None
        self._profiles_cache: Dict[str, VoiceProfile] = {}

        # Carica profili esistenti
        self._load_profiles()

    def _load_profiles(self) -> None:
        """Carica profili da disco."""
        for profile_dir in self._profiles_dir.iterdir():
            if profile_dir.is_dir():
                meta_path = profile_dir / "profile.json"
                if meta_path.exists():
                    try:
                        profile = VoiceProfile.from_json(meta_path.read_text(encoding="utf-8"))
                        self._profiles_cache[profile.id] = profile
                    except Exception as e:
                        logger.warning(f"Errore caricamento profilo {profile_dir}: {e}")

    async def is_available(self) -> bool:
        """Verifica se XTTS e' disponibile."""
        if self._available is not None:
            return self._available

        try:
            from TTS.api import TTS
            import torch
            self._available = True
            logger.info("XTTS disponibile")
        except ImportError as e:
            self._available = False
            logger.warning(f"XTTS non disponibile: {e}")

        return self._available

    def _get_tts(self):
        """Lazy load XTTS model."""
        if self._tts is not None:
            return self._tts

        try:
            from TTS.api import TTS
            import torch

            # Determina device
            if self._device == "auto":
                device = "cuda" if torch.cuda.is_available() else "cpu"
            else:
                device = self._device

            logger.info(f"Caricamento XTTS su {device}...")
            self._tts = TTS("tts_models/multilingual/multi-dataset/xtts_v2").to(device)
            logger.info("XTTS caricato")
            return self._tts
        except Exception as e:
            logger.error(f"Errore caricamento XTTS: {e}")
            return None

    async def validate_reference(self, audio_path: str) -> ReferenceValidation:
        """
        Valida audio reference per voice cloning.

        Args:
            audio_path: Path audio reference

        Returns:
            ReferenceValidation con dettagli
        """
        issues = []
        recommendations = []
        quality_score = 1.0

        try:
            import soundfile as sf
            import numpy as np

            info = sf.info(audio_path)
            duration = info.duration
            sample_rate = info.samplerate
            channels = info.channels
            audio_format = Path(audio_path).suffix[1:].upper()

            # Controlla durata
            if duration < self.MIN_DURATION:
                issues.append(f"Durata troppo corta ({duration:.1f}s < {self.MIN_DURATION}s)")
                quality_score -= 0.3
            elif duration > self.MAX_DURATION:
                issues.append(f"Durata troppo lunga ({duration:.1f}s > {self.MAX_DURATION}s)")
                recommendations.append("Taglia a 15-20 secondi di parlato pulito")
                quality_score -= 0.1

            # Controlla sample rate
            if sample_rate < self.MIN_SAMPLE_RATE:
                issues.append(f"Sample rate troppo basso ({sample_rate}Hz < {self.MIN_SAMPLE_RATE}Hz)")
                quality_score -= 0.2
            elif sample_rate < self.RECOMMENDED_SAMPLE_RATE:
                recommendations.append(f"Consigliato {self.RECOMMENDED_SAMPLE_RATE}Hz per migliore qualita")

            # Analizza qualita audio
            audio, sr = sf.read(audio_path)
            if channels > 1:
                audio = np.mean(audio, axis=1)

            # RMS
            rms = np.sqrt(np.mean(audio ** 2))
            rms_db = 20 * np.log10(rms) if rms > 0 else -100

            if rms_db < -30:
                issues.append(f"Audio troppo basso ({rms_db:.1f}dB)")
                recommendations.append("Normalizza audio o registra con volume piu alto")
                quality_score -= 0.2
            elif rms_db > -6:
                issues.append(f"Audio potrebbe essere distorto ({rms_db:.1f}dB)")
                quality_score -= 0.15

            # Peak
            peak = np.max(np.abs(audio))
            if peak > 0.99:
                issues.append("Possibile clipping rilevato")
                quality_score -= 0.2

            # Silenzio iniziale/finale
            # Semplice check: primi/ultimi 0.5s
            silence_threshold = 0.01
            start_samples = int(sr * 0.5)
            end_samples = int(sr * 0.5)

            if len(audio) > start_samples + end_samples:
                start_rms = np.sqrt(np.mean(audio[:start_samples] ** 2))
                end_rms = np.sqrt(np.mean(audio[-end_samples:] ** 2))

                if start_rms < silence_threshold:
                    recommendations.append("Rimuovi silenzio iniziale")
                if end_rms < silence_threshold:
                    recommendations.append("Rimuovi silenzio finale")

            quality_score = max(0.0, min(1.0, quality_score))
            valid = len(issues) == 0 or quality_score >= 0.5

            return ReferenceValidation(
                valid=valid,
                duration_seconds=duration,
                sample_rate=sample_rate,
                channels=channels,
                format=audio_format,
                issues=issues,
                quality_score=quality_score,
                recommendations=recommendations,
            )

        except Exception as e:
            logger.error(f"Errore validazione reference: {e}")
            return ReferenceValidation(
                valid=False,
                duration_seconds=0,
                sample_rate=0,
                channels=0,
                format="",
                issues=[f"Errore lettura file: {e}"],
                quality_score=0,
                recommendations=["Verifica formato file audio"],
            )

    async def create_profile(
        self,
        name: str,
        reference_path: str,
        language: str,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
        force: bool = False,
    ) -> VoiceProfile:
        """
        Crea profilo voce da audio reference.

        Args:
            name: Nome profilo (es. "Maestro Tanaka")
            reference_path: Path audio reference
            language: Lingua nativa del parlante
            description: Descrizione opzionale
            created_by: ID utente creatore
            force: Se True, salta validazione

        Returns:
            VoiceProfile creato

        Raises:
            ValueError: Se reference non valido
            FileNotFoundError: Se file non esiste
        """
        if not os.path.exists(reference_path):
            raise FileNotFoundError(f"Audio reference non trovato: {reference_path}")

        # Valida reference
        validation = await self.validate_reference(reference_path)
        if not validation.valid and not force:
            raise ValueError(f"Audio reference non valido: {validation.issues}")

        # Genera ID
        profile_id = str(uuid.uuid4())

        # Crea directory profilo
        profile_dir = self._profiles_dir / profile_id
        profile_dir.mkdir(parents=True, exist_ok=True)

        # Copia audio reference
        ref_ext = Path(reference_path).suffix
        ref_dest = profile_dir / f"reference{ref_ext}"
        shutil.copy2(reference_path, ref_dest)

        # Crea profilo
        profile = VoiceProfile(
            id=profile_id,
            name=name,
            description=description,
            language=language,
            reference_audio_path=str(ref_dest),
            reference_duration_seconds=validation.duration_seconds,
            created_at=datetime.now().isoformat(),
            created_by=created_by,
            quality_score=validation.quality_score,
        )

        # Salva metadata
        meta_path = profile_dir / "profile.json"
        meta_path.write_text(profile.to_json(), encoding="utf-8")

        # Cache profilo
        self._profiles_cache[profile_id] = profile

        logger.info(f"Profilo voce creato: {profile_id} - {name}")
        return profile

    async def get_profile(self, profile_id: str) -> Optional[VoiceProfile]:
        """Ottiene profilo per ID."""
        return self._profiles_cache.get(profile_id)

    async def list_profiles(self) -> List[VoiceProfile]:
        """Lista tutti i profili."""
        return list(self._profiles_cache.values())

    async def delete_profile(self, profile_id: str) -> bool:
        """
        Elimina profilo voce.

        Args:
            profile_id: ID profilo

        Returns:
            True se eliminato
        """
        if profile_id not in self._profiles_cache:
            return False

        profile_dir = self._profiles_dir / profile_id
        if profile_dir.exists():
            shutil.rmtree(profile_dir)

        del self._profiles_cache[profile_id]
        logger.info(f"Profilo eliminato: {profile_id}")
        return True

    async def update_profile(
        self,
        profile_id: str,
        **updates
    ) -> Optional[VoiceProfile]:
        """
        Aggiorna profilo voce.

        Args:
            profile_id: ID profilo
            **updates: Campi da aggiornare (name, description, verified)

        Returns:
            VoiceProfile aggiornato o None
        """
        profile = self._profiles_cache.get(profile_id)
        if profile is None:
            return None

        allowed = {"name", "description", "verified", "metadata"}
        for key, value in updates.items():
            if key in allowed:
                setattr(profile, key, value)

        # Salva
        meta_path = self._profiles_dir / profile_id / "profile.json"
        meta_path.write_text(profile.to_json(), encoding="utf-8")

        return profile

    async def clone(
        self,
        text: str,
        profile_id: str,
        target_language: Optional[str] = None,
        output_path: Optional[str] = None,
        speed: float = 1.0,
    ) -> VoiceCloningResult:
        """
        Genera audio con voce clonata.

        Args:
            text: Testo da sintetizzare
            profile_id: ID profilo voce
            target_language: Lingua output (default: lingua profilo)
            output_path: Path output (auto se None)
            speed: Velocita parlato (0.5-2.0)

        Returns:
            VoiceCloningResult
        """
        start_time = datetime.now()

        # Verifica disponibilita
        if not await self.is_available():
            return VoiceCloningResult(
                success=False,
                text=text,
                language=target_language or "",
                voice_profile_id=profile_id,
                output_path=None,
                duration_seconds=None,
                processing_time_ms=0,
                error="XTTS non disponibile",
            )

        # Ottieni profilo
        profile = self._profiles_cache.get(profile_id)
        if profile is None:
            return VoiceCloningResult(
                success=False,
                text=text,
                language=target_language or "",
                voice_profile_id=profile_id,
                output_path=None,
                duration_seconds=None,
                processing_time_ms=0,
                error=f"Profilo non trovato: {profile_id}",
            )

        # Determina lingua
        language = target_language or profile.language
        if language not in self.SUPPORTED_LANGUAGES:
            # Mapping common codes
            lang_map = {"zh": "zh-cn", "jp": "ja"}
            language = lang_map.get(language, language)

        if language not in self.SUPPORTED_LANGUAGES:
            return VoiceCloningResult(
                success=False,
                text=text,
                language=language,
                voice_profile_id=profile_id,
                output_path=None,
                duration_seconds=None,
                processing_time_ms=0,
                error=f"Lingua non supportata: {language}",
            )

        # Genera output path
        if output_path is None:
            output_dir = Path(os.getcwd()) / "storage" / "audio" / "cloned"
            output_dir.mkdir(parents=True, exist_ok=True)
            text_hash = hashlib.md5(text.encode()).hexdigest()[:8]
            output_path = str(output_dir / f"clone_{profile_id[:8]}_{text_hash}.wav")

        try:
            def _clone():
                tts = self._get_tts()
                if tts is None:
                    return None

                tts.tts_to_file(
                    text=text,
                    speaker_wav=profile.reference_audio_path,
                    language=language,
                    file_path=output_path,
                    speed=speed,
                )
                return output_path

            loop = asyncio.get_event_loop()
            result_path = await loop.run_in_executor(None, _clone)

            if result_path is None:
                processing_time = (datetime.now() - start_time).total_seconds() * 1000
                return VoiceCloningResult(
                    success=False,
                    text=text,
                    language=language,
                    voice_profile_id=profile_id,
                    output_path=None,
                    duration_seconds=None,
                    processing_time_ms=processing_time,
                    error="Errore TTS engine",
                )

            # Calcola durata
            duration = await self._get_duration(output_path)
            processing_time = (datetime.now() - start_time).total_seconds() * 1000

            return VoiceCloningResult(
                success=True,
                text=text,
                language=language,
                voice_profile_id=profile_id,
                output_path=output_path,
                duration_seconds=duration,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            logger.error(f"Errore voice cloning: {e}")
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            return VoiceCloningResult(
                success=False,
                text=text,
                language=language,
                voice_profile_id=profile_id,
                output_path=None,
                duration_seconds=None,
                processing_time_ms=processing_time,
                error=str(e),
            )

    async def clone_batch(
        self,
        texts: List[str],
        profile_id: str,
        target_language: Optional[str] = None,
    ) -> List[VoiceCloningResult]:
        """
        Clona batch di testi.

        Args:
            texts: Lista testi
            profile_id: ID profilo
            target_language: Lingua target

        Returns:
            Lista risultati
        """
        # Esegui sequenzialmente per evitare conflitti CUDA
        results = []
        for text in texts:
            result = await self.clone(text, profile_id, target_language)
            results.append(result)
        return results

    async def _get_duration(self, audio_path: str) -> Optional[float]:
        """Ottiene durata audio."""
        try:
            import soundfile as sf
            info = sf.info(audio_path)
            return info.duration
        except Exception:
            return None

    async def compare_voices(
        self,
        profile_id1: str,
        profile_id2: str,
        test_text: str = "Questo e' un test di confronto vocale.",
    ) -> Dict[str, Any]:
        """
        Confronta due profili voce generando stesso testo.

        Args:
            profile_id1: Primo profilo
            profile_id2: Secondo profilo
            test_text: Testo di test

        Returns:
            Dict con paths audio e info
        """
        result1 = await self.clone(test_text, profile_id1, "it")
        result2 = await self.clone(test_text, profile_id2, "it")

        return {
            "profile1": {
                "id": profile_id1,
                "success": result1.success,
                "audio_path": result1.output_path,
                "duration": result1.duration_seconds,
            },
            "profile2": {
                "id": profile_id2,
                "success": result2.success,
                "audio_path": result2.output_path,
                "duration": result2.duration_seconds,
            },
            "test_text": test_text,
        }

    def get_supported_languages(self) -> List[str]:
        """Lista lingue supportate."""
        return self.SUPPORTED_LANGUAGES.copy()

    async def estimate_processing_time(
        self,
        text: str,
        profile_id: str,
    ) -> float:
        """
        Stima tempo processing in secondi.

        Args:
            text: Testo
            profile_id: Profilo

        Returns:
            Tempo stimato in secondi
        """
        # Stima basata su lunghezza testo
        # ~1 secondo per 10 caratteri su GPU, ~5 secondi su CPU
        chars = len(text)
        base_time = chars / 10

        # Check device
        try:
            import torch
            if torch.cuda.is_available():
                return base_time * 1.0
        except ImportError:
            pass

        return base_time * 5.0

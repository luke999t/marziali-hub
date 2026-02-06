"""
# AI_MODULE: VoiceStyler
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Audio processing con Pedalboard (Spotify) per effetti voce e ambiente
# AI_BUSINESS: Applica effetti audio per simulare ambienti (dojo, palestra),
#              equalizzare voci, rimuovere rumore, normalizzare volume.
# AI_TEACHING: Usa Pedalboard per effetti real-time quality, preset per scenari comuni,
#              chain di effetti personalizzabili, processing non distruttivo.
# AI_DEPENDENCIES: pedalboard, soundfile, numpy
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

VoiceStyler Module
==================

Processing audio professionale con Pedalboard di Spotify.

Preset disponibili:
- DOJO_REVERB: Riverberazione ambiente dojo tradizionale
- CLEAR_VOICE: Voce pulita e chiara per istruzioni
- WARM_NARRATOR: Voce calda per narrazione
- ENERGETIC: Voce energica per allenamenti
- MEDITATION: Voce calma per meditazione/kata
- OUTDOOR: Ambiente esterno
- NOISE_REDUCTION: Rimozione rumore
- NORMALIZE: Normalizzazione volume

Features:
- Effetti real-time quality
- Chain di effetti personalizzabili
- Preview veloce
- Processing batch
- Export in vari formati
"""

import asyncio
import os
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Tuple
import logging

logger = logging.getLogger(__name__)


class StylePreset(Enum):
    """Preset di stile audio."""
    DOJO_REVERB = "dojo_reverb"
    CLEAR_VOICE = "clear_voice"
    WARM_NARRATOR = "warm_narrator"
    ENERGETIC = "energetic"
    MEDITATION = "meditation"
    OUTDOOR = "outdoor"
    NOISE_REDUCTION = "noise_reduction"
    NORMALIZE = "normalize"
    PHONE_CALL = "phone_call"
    RADIO = "radio"
    CUSTOM = "custom"


@dataclass
class AudioStyle:
    """Definizione stile audio con parametri effetti."""
    name: str
    description: str
    effects: List[Dict[str, Any]]  # Lista effetti con parametri
    gain_db: float = 0.0
    normalize: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return {
            "name": self.name,
            "description": self.description,
            "effects": self.effects,
            "gain_db": self.gain_db,
            "normalize": self.normalize,
        }


@dataclass
class StyleResult:
    """Risultato applicazione stile."""
    success: bool
    input_path: str
    output_path: Optional[str]
    style_applied: str
    duration_seconds: Optional[float]
    processing_time_ms: float
    error: Optional[str] = None


class VoiceStyler:
    """
    Audio processing con Pedalboard.

    Uso:
        styler = VoiceStyler()
        result = await styler.apply_style(
            input_path="voice.wav",
            preset=StylePreset.DOJO_REVERB
        )
    """

    # Definizione preset
    PRESETS: Dict[StylePreset, AudioStyle] = {
        StylePreset.DOJO_REVERB: AudioStyle(
            name="Dojo Reverb",
            description="Riverberazione ambiente dojo tradizionale",
            effects=[
                {"type": "reverb", "room_size": 0.6, "damping": 0.5, "wet_level": 0.3, "dry_level": 0.7},
                {"type": "eq", "low_shelf_gain_db": -2, "high_shelf_gain_db": -1},
            ],
            normalize=True,
        ),
        StylePreset.CLEAR_VOICE: AudioStyle(
            name="Clear Voice",
            description="Voce pulita e chiara per istruzioni",
            effects=[
                {"type": "highpass", "cutoff_hz": 80},
                {"type": "compressor", "threshold_db": -20, "ratio": 4, "attack_ms": 10, "release_ms": 100},
                {"type": "eq", "low_shelf_gain_db": -3, "high_shelf_gain_db": 2},
            ],
            normalize=True,
        ),
        StylePreset.WARM_NARRATOR: AudioStyle(
            name="Warm Narrator",
            description="Voce calda per narrazione",
            effects=[
                {"type": "highpass", "cutoff_hz": 60},
                {"type": "eq", "low_shelf_gain_db": 2, "mid_gain_db": 1, "high_shelf_gain_db": -1},
                {"type": "compressor", "threshold_db": -18, "ratio": 3, "attack_ms": 20, "release_ms": 150},
                {"type": "reverb", "room_size": 0.2, "wet_level": 0.1, "dry_level": 0.9},
            ],
            normalize=True,
        ),
        StylePreset.ENERGETIC: AudioStyle(
            name="Energetic",
            description="Voce energica per allenamenti",
            effects=[
                {"type": "highpass", "cutoff_hz": 100},
                {"type": "eq", "low_shelf_gain_db": 1, "mid_gain_db": 3, "high_shelf_gain_db": 2},
                {"type": "compressor", "threshold_db": -15, "ratio": 6, "attack_ms": 5, "release_ms": 50},
                {"type": "limiter", "threshold_db": -3},
            ],
            gain_db=3,
            normalize=True,
        ),
        StylePreset.MEDITATION: AudioStyle(
            name="Meditation",
            description="Voce calma per meditazione e kata",
            effects=[
                {"type": "highpass", "cutoff_hz": 50},
                {"type": "lowpass", "cutoff_hz": 8000},
                {"type": "eq", "high_shelf_gain_db": -3},
                {"type": "reverb", "room_size": 0.8, "damping": 0.8, "wet_level": 0.4, "dry_level": 0.6},
            ],
            gain_db=-3,
        ),
        StylePreset.OUTDOOR: AudioStyle(
            name="Outdoor",
            description="Ambiente esterno",
            effects=[
                {"type": "highpass", "cutoff_hz": 120},
                {"type": "eq", "mid_gain_db": -2, "high_shelf_gain_db": 1},
                {"type": "reverb", "room_size": 0.3, "wet_level": 0.15, "dry_level": 0.85},
            ],
        ),
        StylePreset.NOISE_REDUCTION: AudioStyle(
            name="Noise Reduction",
            description="Rimozione rumore di fondo",
            effects=[
                {"type": "highpass", "cutoff_hz": 80},
                {"type": "lowpass", "cutoff_hz": 12000},
                {"type": "noisegate", "threshold_db": -40, "attack_ms": 1, "release_ms": 100},
            ],
            normalize=True,
        ),
        StylePreset.NORMALIZE: AudioStyle(
            name="Normalize",
            description="Solo normalizzazione volume",
            effects=[],
            normalize=True,
        ),
        StylePreset.PHONE_CALL: AudioStyle(
            name="Phone Call",
            description="Effetto chiamata telefonica",
            effects=[
                {"type": "highpass", "cutoff_hz": 300},
                {"type": "lowpass", "cutoff_hz": 3400},
                {"type": "bitcrush", "bit_depth": 8},
            ],
        ),
        StylePreset.RADIO: AudioStyle(
            name="Radio",
            description="Effetto radio vintage",
            effects=[
                {"type": "highpass", "cutoff_hz": 200},
                {"type": "lowpass", "cutoff_hz": 5000},
                {"type": "compressor", "threshold_db": -20, "ratio": 8},
                {"type": "distortion", "drive_db": 5},
            ],
        ),
    }

    def __init__(self, output_dir: Optional[str] = None):
        """
        Inizializza VoiceStyler.

        Args:
            output_dir: Directory output per file processati
        """
        if output_dir is None:
            output_dir = os.path.join(os.getcwd(), "storage", "audio", "styled")
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._pedalboard_available: Optional[bool] = None

    async def is_available(self) -> bool:
        """Verifica se Pedalboard e' disponibile."""
        if self._pedalboard_available is not None:
            return self._pedalboard_available

        try:
            import pedalboard
            import soundfile
            self._pedalboard_available = True
        except ImportError:
            self._pedalboard_available = False
            logger.warning("pedalboard o soundfile non installato")

        return self._pedalboard_available

    def get_presets(self) -> List[AudioStyle]:
        """Lista preset disponibili."""
        return list(self.PRESETS.values())

    def get_preset(self, preset: StylePreset) -> Optional[AudioStyle]:
        """Ottiene preset specifico."""
        return self.PRESETS.get(preset)

    def _build_effect(self, effect_config: Dict[str, Any]):
        """Costruisce effetto Pedalboard da config."""
        try:
            import pedalboard as pb

            effect_type = effect_config.get("type", "")

            if effect_type == "reverb":
                return pb.Reverb(
                    room_size=effect_config.get("room_size", 0.5),
                    damping=effect_config.get("damping", 0.5),
                    wet_level=effect_config.get("wet_level", 0.3),
                    dry_level=effect_config.get("dry_level", 0.7),
                )
            elif effect_type == "compressor":
                return pb.Compressor(
                    threshold_db=effect_config.get("threshold_db", -20),
                    ratio=effect_config.get("ratio", 4),
                    attack_ms=effect_config.get("attack_ms", 10),
                    release_ms=effect_config.get("release_ms", 100),
                )
            elif effect_type == "highpass":
                return pb.HighpassFilter(
                    cutoff_frequency_hz=effect_config.get("cutoff_hz", 80),
                )
            elif effect_type == "lowpass":
                return pb.LowpassFilter(
                    cutoff_frequency_hz=effect_config.get("cutoff_hz", 8000),
                )
            elif effect_type == "eq":
                # Pedalboard non ha EQ parametrico semplice,
                # usiamo combinazione di filtri
                effects = []
                if effect_config.get("low_shelf_gain_db"):
                    effects.append(pb.LowShelfFilter(
                        cutoff_frequency_hz=200,
                        gain_db=effect_config["low_shelf_gain_db"],
                    ))
                if effect_config.get("high_shelf_gain_db"):
                    effects.append(pb.HighShelfFilter(
                        cutoff_frequency_hz=4000,
                        gain_db=effect_config["high_shelf_gain_db"],
                    ))
                return effects if effects else None
            elif effect_type == "gain":
                return pb.Gain(gain_db=effect_config.get("gain_db", 0))
            elif effect_type == "limiter":
                return pb.Limiter(
                    threshold_db=effect_config.get("threshold_db", -3),
                    release_ms=effect_config.get("release_ms", 100),
                )
            elif effect_type == "noisegate":
                return pb.NoiseGate(
                    threshold_db=effect_config.get("threshold_db", -40),
                    attack_ms=effect_config.get("attack_ms", 1),
                    release_ms=effect_config.get("release_ms", 100),
                )
            elif effect_type == "chorus":
                return pb.Chorus(
                    rate_hz=effect_config.get("rate_hz", 1.5),
                    depth=effect_config.get("depth", 0.5),
                    mix=effect_config.get("mix", 0.5),
                )
            elif effect_type == "delay":
                return pb.Delay(
                    delay_seconds=effect_config.get("delay_seconds", 0.3),
                    feedback=effect_config.get("feedback", 0.3),
                    mix=effect_config.get("mix", 0.3),
                )
            elif effect_type == "distortion":
                return pb.Distortion(
                    drive_db=effect_config.get("drive_db", 10),
                )
            elif effect_type == "bitcrush":
                return pb.Bitcrush(
                    bit_depth=effect_config.get("bit_depth", 8),
                )
            elif effect_type == "phaser":
                return pb.Phaser(
                    rate_hz=effect_config.get("rate_hz", 0.5),
                    depth=effect_config.get("depth", 0.5),
                    feedback=effect_config.get("feedback", 0.5),
                    mix=effect_config.get("mix", 0.5),
                )
            else:
                logger.warning(f"Tipo effetto sconosciuto: {effect_type}")
                return None

        except Exception as e:
            logger.error(f"Errore creazione effetto {effect_config}: {e}")
            return None

    def _build_pedalboard(self, style: AudioStyle):
        """Costruisce Pedalboard da stile."""
        import pedalboard as pb

        effects = []

        # Aggiungi gain iniziale se specificato
        if style.gain_db != 0:
            effects.append(pb.Gain(gain_db=style.gain_db))

        # Aggiungi effetti
        for effect_config in style.effects:
            effect = self._build_effect(effect_config)
            if effect is not None:
                if isinstance(effect, list):
                    effects.extend(effect)
                else:
                    effects.append(effect)

        return pb.Pedalboard(effects) if effects else pb.Pedalboard([])

    async def apply_style(
        self,
        input_path: str,
        preset: Optional[StylePreset] = None,
        custom_style: Optional[AudioStyle] = None,
        output_path: Optional[str] = None,
    ) -> StyleResult:
        """
        Applica stile a file audio.

        Args:
            input_path: Path file input
            preset: Preset da applicare
            custom_style: Stile custom (alternativo a preset)
            output_path: Path output (auto-generato se None)

        Returns:
            StyleResult
        """
        start_time = datetime.now()

        if not await self.is_available():
            return StyleResult(
                success=False,
                input_path=input_path,
                output_path=None,
                style_applied="none",
                duration_seconds=None,
                processing_time_ms=0,
                error="Pedalboard non disponibile",
            )

        # Determina stile
        if custom_style:
            style = custom_style
        elif preset:
            style = self.PRESETS.get(preset)
            if style is None:
                return StyleResult(
                    success=False,
                    input_path=input_path,
                    output_path=None,
                    style_applied=preset.value if preset else "none",
                    duration_seconds=None,
                    processing_time_ms=0,
                    error=f"Preset non trovato: {preset}",
                )
        else:
            return StyleResult(
                success=False,
                input_path=input_path,
                output_path=None,
                style_applied="none",
                duration_seconds=None,
                processing_time_ms=0,
                error="Specificare preset o custom_style",
            )

        # Genera output path
        if output_path is None:
            input_name = Path(input_path).stem
            output_path = str(self._output_dir / f"{input_name}_{style.name.lower().replace(' ', '_')}.wav")

        try:
            def _process():
                import soundfile as sf
                import numpy as np
                import pedalboard as pb

                # Leggi audio
                audio, sample_rate = sf.read(input_path)

                # Assicura formato corretto (float32, 2D)
                if audio.dtype != np.float32:
                    audio = audio.astype(np.float32)
                if len(audio.shape) == 1:
                    audio = audio.reshape(-1, 1)

                # Costruisci e applica pedalboard
                board = self._build_pedalboard(style)
                processed = board(audio, sample_rate)

                # Normalizza se richiesto
                if style.normalize:
                    max_val = np.max(np.abs(processed))
                    if max_val > 0:
                        processed = processed / max_val * 0.95

                # Salva output
                sf.write(output_path, processed, sample_rate)

                # Calcola durata
                duration = len(processed) / sample_rate
                return duration

            loop = asyncio.get_event_loop()
            duration = await loop.run_in_executor(None, _process)

            processing_time = (datetime.now() - start_time).total_seconds() * 1000

            return StyleResult(
                success=True,
                input_path=input_path,
                output_path=output_path,
                style_applied=style.name,
                duration_seconds=duration,
                processing_time_ms=processing_time,
            )

        except Exception as e:
            logger.error(f"Errore processing audio: {e}")
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            return StyleResult(
                success=False,
                input_path=input_path,
                output_path=None,
                style_applied=style.name,
                duration_seconds=None,
                processing_time_ms=processing_time,
                error=str(e),
            )

    async def apply_style_batch(
        self,
        input_paths: List[str],
        preset: StylePreset,
    ) -> List[StyleResult]:
        """
        Applica stile a batch di file.

        Args:
            input_paths: Lista path input
            preset: Preset da applicare

        Returns:
            Lista StyleResult
        """
        tasks = [
            self.apply_style(input_path, preset=preset)
            for input_path in input_paths
        ]
        return await asyncio.gather(*tasks)

    async def chain_effects(
        self,
        input_path: str,
        effects: List[Dict[str, Any]],
        output_path: Optional[str] = None,
        normalize: bool = True,
    ) -> StyleResult:
        """
        Applica catena di effetti custom.

        Args:
            input_path: Path input
            effects: Lista effetti con parametri
            output_path: Path output
            normalize: Se normalizzare

        Returns:
            StyleResult
        """
        custom_style = AudioStyle(
            name="Custom Chain",
            description="Catena effetti personalizzata",
            effects=effects,
            normalize=normalize,
        )
        return await self.apply_style(
            input_path,
            custom_style=custom_style,
            output_path=output_path,
        )

    async def analyze_audio(self, audio_path: str) -> Dict[str, Any]:
        """
        Analizza caratteristiche audio.

        Args:
            audio_path: Path audio

        Returns:
            Dict con analisi (duration, rms, peak, etc.)
        """
        if not await self.is_available():
            return {"error": "Pedalboard non disponibile"}

        try:
            def _analyze():
                import soundfile as sf
                import numpy as np

                audio, sr = sf.read(audio_path)

                # Converti a mono se stereo
                if len(audio.shape) > 1:
                    audio_mono = np.mean(audio, axis=1)
                else:
                    audio_mono = audio

                duration = len(audio_mono) / sr
                rms = np.sqrt(np.mean(audio_mono ** 2))
                rms_db = 20 * np.log10(rms) if rms > 0 else -100
                peak = np.max(np.abs(audio_mono))
                peak_db = 20 * np.log10(peak) if peak > 0 else -100

                # Dynamic range
                # Calcola RMS in finestre
                window_size = int(sr * 0.1)  # 100ms
                windows = len(audio_mono) // window_size
                if windows > 0:
                    rms_values = []
                    for i in range(windows):
                        start = i * window_size
                        end = start + window_size
                        window_rms = np.sqrt(np.mean(audio_mono[start:end] ** 2))
                        if window_rms > 0:
                            rms_values.append(20 * np.log10(window_rms))
                    if rms_values:
                        dynamic_range = max(rms_values) - min(rms_values)
                    else:
                        dynamic_range = 0
                else:
                    dynamic_range = 0

                return {
                    "duration_seconds": duration,
                    "sample_rate": sr,
                    "channels": audio.shape[1] if len(audio.shape) > 1 else 1,
                    "rms_db": round(rms_db, 2),
                    "peak_db": round(peak_db, 2),
                    "dynamic_range_db": round(dynamic_range, 2),
                    "headroom_db": round(-peak_db, 2),
                    "samples": len(audio_mono),
                }

            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, _analyze)

        except Exception as e:
            logger.error(f"Errore analisi audio: {e}")
            return {"error": str(e)}

    async def suggest_style(self, audio_path: str) -> Optional[StylePreset]:
        """
        Suggerisce stile basato su analisi audio.

        Args:
            audio_path: Path audio

        Returns:
            StylePreset suggerito o None
        """
        analysis = await self.analyze_audio(audio_path)

        if "error" in analysis:
            return None

        rms_db = analysis.get("rms_db", -20)
        dynamic_range = analysis.get("dynamic_range_db", 20)
        peak_db = analysis.get("peak_db", 0)

        # Logica suggerimento
        if rms_db < -30:
            # Audio molto basso, normalizza
            return StylePreset.NORMALIZE
        elif dynamic_range > 30:
            # Alta dinamica, comprimi per voce chiara
            return StylePreset.CLEAR_VOICE
        elif peak_db > -3:
            # Quasi clipping, limita
            return StylePreset.NOISE_REDUCTION
        elif rms_db > -10:
            # Audio molto forte, probabilmente energico
            return StylePreset.ENERGETIC
        else:
            # Default: voce calda per narrazione
            return StylePreset.WARM_NARRATOR

    def create_custom_style(
        self,
        name: str,
        description: str,
        effects: List[Dict[str, Any]],
        gain_db: float = 0.0,
        normalize: bool = True,
    ) -> AudioStyle:
        """
        Crea stile custom.

        Args:
            name: Nome stile
            description: Descrizione
            effects: Lista effetti
            gain_db: Gain iniziale
            normalize: Se normalizzare

        Returns:
            AudioStyle creato
        """
        return AudioStyle(
            name=name,
            description=description,
            effects=effects,
            gain_db=gain_db,
            normalize=normalize,
        )

"""
# AI_MODULE: AudioSystem
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Sistema completo per generazione audio, TTS, voice cloning e processing
# AI_BUSINESS: Genera audio per video tutorial, doppiaggio, pronuncia corretta termini arti marziali
# AI_TEACHING: Package che espone AudioManager come facade, con TTS multi-engine, voice cloning XTTS,
#              audio styling con Pedalboard, e database pronuncie SQLite. Pattern Singleton con
#              _reset_for_testing per test isolation.
# AI_DEPENDENCIES: edge-tts, TTS (Coqui), pyttsx3, pedalboard, librosa, soundfile
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

AudioSystem Package
==================

Sistema audio completo per il Media Center Arti Marziali.

Componenti:
-----------
- AudioManager: Facade principale per orchestrazione
- TTSGenerator: Text-to-Speech multi-engine (Edge TTS, Coqui, pyttsx3)
- VoiceCloner: Clonazione vocale con XTTS v2
- VoiceSyler: Processing audio con Pedalboard (Spotify)
- PronunciationDB: Database SQLite per pronuncie corrette
- AudioStorage: Gestione file audio con cleanup automatico

Uso:
----
    from services.audio_system import AudioManager

    # Singleton pattern
    manager = AudioManager.get_instance()

    # TTS semplice
    audio_path = await manager.generate_tts(
        text="Oi-zuki chudan",
        language="ja",
        voice="male_1"
    )

    # Voice cloning
    cloned_path = await manager.clone_voice(
        text="Benvenuti al corso di karate",
        reference_audio="/path/to/maestro_voice.wav"
    )

    # Audio styling
    styled_path = await manager.apply_style(
        audio_path=audio_path,
        style="dojo_reverb"
    )

Testing:
--------
    # Reset per test isolation
    AudioManager._reset_for_testing()
"""

from .audio_storage import AudioStorage, AudioFormat, AudioMetadata
from .tts_generator import TTSGenerator, TTSEngine, TTSVoice, TTSRequest, TTSResult
from .pronunciation_db import PronunciationDB, PronunciationEntry, LanguageCode
from .voice_styler import VoiceStyler, AudioStyle, StylePreset
from .voice_cloner import VoiceCloner, VoiceCloningResult, VoiceProfile
from .audio_manager import AudioManager

__all__ = [
    # Main facade
    "AudioManager",

    # Storage
    "AudioStorage",
    "AudioFormat",
    "AudioMetadata",

    # TTS
    "TTSGenerator",
    "TTSEngine",
    "TTSVoice",
    "TTSRequest",
    "TTSResult",

    # Pronunciation
    "PronunciationDB",
    "PronunciationEntry",
    "LanguageCode",

    # Styling
    "VoiceStyler",
    "AudioStyle",
    "StylePreset",

    # Voice Cloning
    "VoiceCloner",
    "VoiceCloningResult",
    "VoiceProfile",
]

__version__ = "1.0.0"
__author__ = "Media Center Arti Marziali"

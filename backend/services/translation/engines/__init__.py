"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Engines Package
================================================================================
"""

from .ollama_engine import (
    OllamaEngine,
    BaseTranslationEngine,
    TranslationResult,
    CritiqueResult,
    DebateRound,
    get_ollama_engine
)

__all__ = [
    "OllamaEngine",
    "BaseTranslationEngine",
    "TranslationResult",
    "CritiqueResult",
    "DebateRound",
    "get_ollama_engine"
]

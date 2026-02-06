"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Services Package
================================================================================

    AI_MODULE: Translation Package
    AI_DESCRIPTION: Sistema traduzione multi-LLM con debate
    AI_BUSINESS: Traduzione terminologia arti marziali
================================================================================
"""

from .translation_debate import (
    TranslationDebateService,
    DebateConfig,
    DebateResult,
    DebateStrategy,
    get_debate_service,
    get_glossary_context,
    MARTIAL_ARTS_GLOSSARY
)

from .llm_config import (
    LLMConfigManager,
    LLMProvider,
    LanguageFamily,
    ProviderConfig,
    get_llm_config
)

from .engines.ollama_engine import (
    OllamaEngine,
    TranslationResult,
    CritiqueResult,
    DebateRound,
    get_ollama_engine
)

__all__ = [
    # Debate Service
    "TranslationDebateService",
    "DebateConfig",
    "DebateResult",
    "DebateStrategy",
    "get_debate_service",
    "get_glossary_context",
    "MARTIAL_ARTS_GLOSSARY",

    # LLM Config
    "LLMConfigManager",
    "LLMProvider",
    "LanguageFamily",
    "ProviderConfig",
    "get_llm_config",

    # Engines
    "OllamaEngine",
    "TranslationResult",
    "CritiqueResult",
    "DebateRound",
    "get_ollama_engine",
]

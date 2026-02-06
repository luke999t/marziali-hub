"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Video Studio Services
================================================================================

    AI_FIRST: Video Studio Package for Martial Arts Content Processing
    AI_DESCRIPTION: AI-powered video processing, translation, and analysis

================================================================================
"""

# Translation Engine and LLM Configuration
from .translation_engine import (
    TranslationEngine,
    TranslationResult,
    TranslationProvider,
    BaseTranslationEngine,
    ClaudeEngine,
    OpenAIEngine,
    DeepLEngine,
    OllamaEngine,
    EnsembleTranslator,
)

from .llm_config import (
    LLMConfigManager,
    llm_config,
    LLMProvider,
    ProviderConfig,
    EnsembleConfig,
    RoutingConfig,
)

from .translation_memory import (
    TranslationMemory,
    translation_memory,
    MemoryEntry,
    GlossaryTerm,
    MemorySearchResult,
)

from .glossary_service import (
    GlossaryService,
    glossary_service,
    GlossaryEntry,
    GlossaryCategory,
    ContentGenre,
    ContentMedium,
    GlossaryFilter,
)

__all__ = [
    # Translation Engine
    "TranslationEngine",
    "TranslationResult",
    "TranslationProvider",
    "BaseTranslationEngine",
    "ClaudeEngine",
    "OpenAIEngine",
    "DeepLEngine",
    "OllamaEngine",
    "EnsembleTranslator",
    # LLM Config
    "LLMConfigManager",
    "llm_config",
    "LLMProvider",
    "ProviderConfig",
    "EnsembleConfig",
    "RoutingConfig",
    # Translation Memory
    "TranslationMemory",
    "translation_memory",
    "MemoryEntry",
    "GlossaryTerm",
    "MemorySearchResult",
    # Glossary Service
    "GlossaryService",
    "glossary_service",
    "GlossaryEntry",
    "GlossaryCategory",
    "ContentGenre",
    "ContentMedium",
    "GlossaryFilter",
]

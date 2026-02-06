"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Multi-LLM Configuration System
================================================================================

    AI_FIRST: LLM Configuration & Routing for Martial Arts Translation
    AI_MODULE: LLM Configuration & Routing
    AI_DESCRIPTION: Sistema configurabile per gestire multipli LLM con routing
                    basato su lingua e confidence, supporto ensemble
    AI_BUSINESS: Massimizza qualità traduzione usando LLM ottimali per lingua
    AI_TEACHING: Strategy pattern, ensemble methods, configuration management

    Adapted from: SOFTWARE A - SISTEMA TRADUZIONE MANGAANIME AI-POWERED

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

# ==============================================================================
# LOGGING
# ==============================================================================
logger = structlog.get_logger(__name__)


# ==============================================================================
# ENVIRONMENT CONFIG (replaces app.core.config)
# ==============================================================================
class LLMSettings:
    """Configuration from environment variables"""

    CLAUDE_API_KEY: str = os.getenv("CLAUDE_API_KEY", "")
    CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    CLAUDE_MAX_TOKENS: int = int(os.getenv("CLAUDE_MAX_TOKENS", "4096"))

    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_MAX_TOKENS: int = int(os.getenv("OPENAI_MAX_TOKENS", "4096"))

    DEEPL_API_KEY: str = os.getenv("DEEPL_API_KEY", "")


settings = LLMSettings()


# ==============================================================================
# PROVIDER TYPES
# ==============================================================================
class LLMProvider(str, Enum):
    """Available LLM providers"""
    # Commercial providers
    CLAUDE = "claude"
    OPENAI = "openai"
    DEEPL = "deepl"
    GEMINI = "gemini"

    # Open source / Self-hosted
    OLLAMA = "ollama"
    LLAMA_CPP = "llama_cpp"
    VLLM = "vllm"
    TEXT_GEN = "text_gen"
    HUGGINGFACE = "huggingface"


class LanguageFamily(str, Enum):
    """Language families for routing"""
    EASTERN = "eastern"
    WESTERN = "western"
    MIXED = "mixed"


# ==============================================================================
# CONFIGURATION MODELS
# ==============================================================================
@dataclass
class ProviderConfig:
    """Configuration for a single LLM provider"""
    provider: LLMProvider
    enabled: bool = True
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None

    # Performance settings
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout_seconds: int = 60
    max_retries: int = 3

    # Language confidence scores (0-1)
    language_confidence: Dict[str, float] = field(default_factory=dict)

    # Cost per 1K tokens (for optimization)
    cost_per_1k_tokens: float = 0.0

    # Priority (lower = higher priority)
    priority: int = 10

    def get_confidence_for_languages(self, source: str, target: str) -> float:
        """Get confidence score for a language pair"""
        key = f"{source}->{target}"
        if key in self.language_confidence:
            return self.language_confidence[key]

        source_family = self._get_language_family(source)
        target_family = self._get_language_family(target)

        if source_family == target_family:
            family_key = f"{source_family.value}_same"
        else:
            family_key = f"{source_family.value}_to_{target_family.value}"

        return self.language_confidence.get(family_key, 0.7)

    def _get_language_family(self, lang: str) -> LanguageFamily:
        """Determine language family"""
        eastern = ["ja", "zh", "ko", "th", "vi"]
        if lang in eastern:
            return LanguageFamily.EASTERN
        return LanguageFamily.WESTERN


@dataclass
class EnsembleConfig:
    """Configuration for ensemble translation"""
    enabled: bool = False
    num_providers: int = 2
    strategy: str = "confidence"
    confidence_threshold: float = 0.1
    provider_weights: Dict[str, float] = field(default_factory=dict)
    run_all: bool = True


@dataclass
class RoutingConfig:
    """Configuration for language-based routing"""
    enabled: bool = True
    language_routes: Dict[str, List[str]] = field(default_factory=dict)
    eastern_providers: List[str] = field(default_factory=lambda: ["claude", "openai"])
    western_providers: List[str] = field(default_factory=lambda: ["deepl", "openai"])
    mixed_providers: List[str] = field(default_factory=lambda: ["claude", "openai"])


# ==============================================================================
# MAIN CONFIGURATION CLASS
# ==============================================================================
class LLMConfigManager:
    """
    AI_MODULE: LLM Configuration Manager
    AI_DESCRIPTION: Gestisce configurazione multi-LLM con routing intelligente
    AI_BUSINESS: Ottimizza qualità/costo usando LLM giusto per ogni traduzione
    AI_TEACHING: Singleton pattern, dynamic configuration, provider factory
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self.providers: Dict[str, ProviderConfig] = {}
        self.ensemble: EnsembleConfig = EnsembleConfig()
        self.routing: RoutingConfig = RoutingConfig()

        self._load_default_config()
        self._initialized = True

    def _load_default_config(self):
        """Load default configuration"""
        # Claude - Best for Japanese/context-aware
        self.providers["claude"] = ProviderConfig(
            provider=LLMProvider.CLAUDE,
            api_key=settings.CLAUDE_API_KEY,
            model_name=settings.CLAUDE_MODEL,
            max_tokens=settings.CLAUDE_MAX_TOKENS,
            language_confidence={
                "ja->it": 0.95,
                "ja->en": 0.95,
                "ja->es": 0.90,
                "zh->en": 0.90,
                "ko->en": 0.88,
                "eastern_same": 0.85,
                "eastern_to_western": 0.92,
                "western_to_eastern": 0.80,
            },
            cost_per_1k_tokens=0.003,
            priority=1
        )

        # OpenAI - Good all-around
        self.providers["openai"] = ProviderConfig(
            provider=LLMProvider.OPENAI,
            api_key=settings.OPENAI_API_KEY,
            model_name=settings.OPENAI_MODEL,
            max_tokens=settings.OPENAI_MAX_TOKENS,
            language_confidence={
                "ja->en": 0.90,
                "en->es": 0.92,
                "en->it": 0.90,
                "en->fr": 0.92,
                "eastern_to_western": 0.88,
                "western_same": 0.90,
            },
            cost_per_1k_tokens=0.002,
            priority=2
        )

        # DeepL - Best for European languages
        self.providers["deepl"] = ProviderConfig(
            provider=LLMProvider.DEEPL,
            api_key=settings.DEEPL_API_KEY,
            language_confidence={
                "en->de": 0.98,
                "en->fr": 0.97,
                "en->it": 0.96,
                "en->es": 0.96,
                "de->en": 0.97,
                "western_same": 0.95,
                "eastern_to_western": 0.75,
            },
            cost_per_1k_tokens=0.00002,
            priority=3
        )

        # Ollama - Local open source models
        self.providers["ollama"] = ProviderConfig(
            provider=LLMProvider.OLLAMA,
            enabled=False,
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model_name=os.getenv("OLLAMA_MODEL", "llama3.1:8b"),
            language_confidence={
                "en->es": 0.85,
                "en->fr": 0.85,
                "western_same": 0.82,
                "eastern_to_western": 0.70,
            },
            cost_per_1k_tokens=0.0,
            priority=5
        )

        # Gemini
        self.providers["gemini"] = ProviderConfig(
            provider=LLMProvider.GEMINI,
            enabled=False,
            language_confidence={
                "ja->en": 0.88,
                "en->es": 0.90,
                "western_same": 0.88,
            },
            cost_per_1k_tokens=0.00025,
            priority=4
        )

        # Default ensemble config
        self.ensemble = EnsembleConfig(
            enabled=False,
            num_providers=2,
            strategy="confidence"
        )

        # Default routing
        self.routing = RoutingConfig(
            enabled=True,
            language_routes={
                "ja->it": ["claude", "openai"],
                "ja->en": ["claude", "openai"],
                "en->it": ["deepl", "openai"],
                "en->es": ["deepl", "openai"],
                "zh->en": ["claude", "openai"],
            }
        )

    # ==========================================================================
    # PROVIDER MANAGEMENT
    # ==========================================================================
    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        """Get provider configuration by name"""
        return self.providers.get(name)

    def enable_provider(self, name: str, enabled: bool = True):
        """Enable or disable a provider"""
        if name in self.providers:
            self.providers[name].enabled = enabled
            logger.info("provider_status_changed", provider=name, enabled=enabled)

    def update_provider(self, name: str, config: Dict[str, Any]):
        """Update provider configuration"""
        if name not in self.providers:
            raise ValueError(f"Unknown provider: {name}")

        provider = self.providers[name]
        for key, value in config.items():
            if hasattr(provider, key):
                setattr(provider, key, value)

        logger.info("provider_updated", provider=name, updates=list(config.keys()))

    def add_custom_provider(
        self,
        name: str,
        provider_type: LLMProvider,
        **kwargs
    ):
        """Add a custom provider configuration"""
        self.providers[name] = ProviderConfig(
            provider=provider_type,
            **kwargs
        )
        logger.info("custom_provider_added", name=name, type=provider_type.value)

    def list_enabled_providers(self) -> List[str]:
        """List all enabled providers"""
        return [
            name for name, config in self.providers.items()
            if config.enabled and self._has_credentials(config)
        ]

    def _has_credentials(self, config: ProviderConfig) -> bool:
        """Check if provider has required credentials"""
        if config.provider in [LLMProvider.OLLAMA, LLMProvider.LLAMA_CPP,
                               LLMProvider.VLLM, LLMProvider.TEXT_GEN]:
            return config.base_url is not None
        return config.api_key is not None

    # ==========================================================================
    # ROUTING LOGIC
    # ==========================================================================
    def get_providers_for_translation(
        self,
        source_lang: str,
        target_lang: str,
        num_providers: Optional[int] = None
    ) -> List[str]:
        """
        Get optimal providers for a translation task
        """
        if not self.routing.enabled:
            return self.list_enabled_providers()

        route_key = f"{source_lang}->{target_lang}"
        if route_key in self.routing.language_routes:
            providers = self.routing.language_routes[route_key]
            providers = [p for p in providers if p in self.providers
                        and self.providers[p].enabled]
        else:
            providers = self._get_family_providers(source_lang, target_lang)

        providers = sorted(
            providers,
            key=lambda p: self.providers[p].get_confidence_for_languages(
                source_lang, target_lang
            ),
            reverse=True
        )

        if num_providers:
            providers = providers[:num_providers]

        return providers

    def _get_family_providers(
        self,
        source_lang: str,
        target_lang: str
    ) -> List[str]:
        """Get providers based on language families"""
        eastern = ["ja", "zh", "ko", "th", "vi"]

        source_eastern = source_lang in eastern
        target_eastern = target_lang in eastern

        if source_eastern and target_eastern:
            providers = self.routing.eastern_providers
        elif not source_eastern and not target_eastern:
            providers = self.routing.western_providers
        else:
            providers = self.routing.mixed_providers

        return [p for p in providers if p in self.providers
                and self.providers[p].enabled]

    # ==========================================================================
    # ENSEMBLE CONFIGURATION
    # ==========================================================================
    def configure_ensemble(
        self,
        enabled: bool,
        num_providers: int = 2,
        strategy: str = "confidence",
        **kwargs
    ):
        """Configure ensemble translation"""
        self.ensemble.enabled = enabled
        self.ensemble.num_providers = num_providers
        self.ensemble.strategy = strategy

        for key, value in kwargs.items():
            if hasattr(self.ensemble, key):
                setattr(self.ensemble, key, value)

        logger.info(
            "ensemble_configured",
            enabled=enabled,
            num_providers=num_providers,
            strategy=strategy
        )

    def should_use_ensemble(self) -> bool:
        """Check if ensemble translation should be used"""
        return self.ensemble.enabled and len(self.list_enabled_providers()) >= 2

    # ==========================================================================
    # EXPORT/IMPORT CONFIGURATION
    # ==========================================================================
    def export_config(self) -> Dict[str, Any]:
        """Export full configuration as dict"""
        return {
            "providers": {
                name: {
                    "provider": config.provider.value,
                    "enabled": config.enabled,
                    "model_name": config.model_name,
                    "base_url": config.base_url,
                    "max_tokens": config.max_tokens,
                    "temperature": config.temperature,
                    "language_confidence": config.language_confidence,
                    "cost_per_1k_tokens": config.cost_per_1k_tokens,
                    "priority": config.priority,
                }
                for name, config in self.providers.items()
            },
            "ensemble": {
                "enabled": self.ensemble.enabled,
                "num_providers": self.ensemble.num_providers,
                "strategy": self.ensemble.strategy,
                "confidence_threshold": self.ensemble.confidence_threshold,
                "run_all": self.ensemble.run_all,
            },
            "routing": {
                "enabled": self.routing.enabled,
                "language_routes": self.routing.language_routes,
                "eastern_providers": self.routing.eastern_providers,
                "western_providers": self.routing.western_providers,
                "mixed_providers": self.routing.mixed_providers,
            }
        }

    def import_config(self, config: Dict[str, Any]):
        """Import configuration from dict"""
        if "providers" in config:
            for name, pconfig in config["providers"].items():
                if name in self.providers:
                    self.update_provider(name, pconfig)

        if "ensemble" in config:
            for key, value in config["ensemble"].items():
                if hasattr(self.ensemble, key):
                    setattr(self.ensemble, key, value)

        if "routing" in config:
            for key, value in config["routing"].items():
                if hasattr(self.routing, key):
                    setattr(self.routing, key, value)

        logger.info("config_imported")


# ==============================================================================
# GLOBAL INSTANCE
# ==============================================================================
llm_config = LLMConfigManager()

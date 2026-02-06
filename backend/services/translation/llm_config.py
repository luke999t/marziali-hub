"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Multi-LLM Configuration
================================================================================

    AI_MODULE: LLM Configuration & Routing
    AI_DESCRIPTION: Configurazione multi-LLM con routing per lingua
    AI_BUSINESS: Usa LLM ottimale per ogni coppia linguistica
    AI_TEACHING: Strategy pattern, language routing, provider factory

    ALTERNATIVE_VALUTATE:
    - Singolo provider: Scartato perche non ottimale per tutte le lingue
    - Config statica: Scartata perche non adattabile
    - Config dinamica: Scelta per flessibilita

    PERCHE_QUESTA_SOLUZIONE:
    - Vantaggio tecnico: Routing intelligente per lingua
    - Vantaggio business: Qualita ottimale per ogni traduzione
    - Trade-off: Complessita configurazione

================================================================================
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import os
import logging

logger = logging.getLogger(__name__)


# ==============================================================================
# PROVIDER TYPES
# ==============================================================================
class LLMProvider(str, Enum):
    """Provider LLM disponibili"""
    # Locale (Ollama)
    OLLAMA = "ollama"

    # Cloud (futuri)
    CLAUDE = "claude"
    OPENAI = "openai"
    DEEPL = "deepl"


class LanguageFamily(str, Enum):
    """Famiglie linguistiche per routing"""
    EASTERN = "eastern"    # Giapponese, Cinese, Coreano
    WESTERN = "western"    # Italiano, Inglese, Spagnolo, etc.
    MIXED = "mixed"        # Traduzioni cross-family


# ==============================================================================
# PROVIDER CONFIG
# ==============================================================================
@dataclass
class ProviderConfig:
    """
    AI_MODULE: Provider Configuration
    AI_DESCRIPTION: Configurazione singolo provider LLM

    PARAMETRI:
    - provider: Tipo provider (ollama, claude, etc.)
    - enabled: Se attivo
    - model_name: Nome modello specifico
    - language_confidence: Punteggio per coppie linguistiche
    """
    provider: LLMProvider
    enabled: bool = True
    base_url: Optional[str] = None
    model_name: Optional[str] = None
    api_key: Optional[str] = None

    # Performance
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout_seconds: int = 120
    max_retries: int = 3

    # Language confidence (0-1): quanto e bravo per questa coppia
    language_confidence: Dict[str, float] = field(default_factory=dict)

    # Costo per 1K tokens (0 per locale)
    cost_per_1k_tokens: float = 0.0

    # Priorita (1 = massima)
    priority: int = 10

    def get_confidence_for_languages(self, source: str, target: str) -> float:
        """Ottiene confidence per coppia linguistica"""
        key = f"{source}->{target}"
        if key in self.language_confidence:
            return self.language_confidence[key]

        # Fallback per famiglia
        source_family = self._get_language_family(source)
        target_family = self._get_language_family(target)

        if source_family == target_family:
            return self.language_confidence.get(f"{source_family.value}_same", 0.7)
        else:
            return self.language_confidence.get(
                f"{source_family.value}_to_{target_family.value}", 0.7
            )

    def _get_language_family(self, lang: str) -> LanguageFamily:
        eastern = ["ja", "zh", "ko", "th", "vi"]
        return LanguageFamily.EASTERN if lang in eastern else LanguageFamily.WESTERN


# ==============================================================================
# ROUTING CONFIG
# ==============================================================================
@dataclass
class RoutingConfig:
    """
    AI_MODULE: Language Routing Configuration
    AI_DESCRIPTION: Regole per routing traduzioni a provider ottimali

    ESEMPIO:
    language_routes["ja->it"] = ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"]
    """
    enabled: bool = True

    # Route esplicite: "ja->it" -> ["provider1", "provider2"]
    language_routes: Dict[str, List[str]] = field(default_factory=dict)

    # Provider di default per famiglia
    eastern_providers: List[str] = field(
        default_factory=lambda: ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"]
    )
    western_providers: List[str] = field(
        default_factory=lambda: ["ollama:llama3.1:8b"]
    )
    mixed_providers: List[str] = field(
        default_factory=lambda: ["ollama:llama3.1:8b"]
    )


# ==============================================================================
# MAIN CONFIG MANAGER
# ==============================================================================
class LLMConfigManager:
    """
    AI_MODULE: LLM Configuration Manager
    AI_DESCRIPTION: Gestisce configurazione multi-LLM
    AI_BUSINESS: Ottimizza provider per ogni traduzione

    SINGLETON: Una sola istanza globale

    USAGE:
        config = get_llm_config()
        providers = config.get_providers_for_translation("ja", "it")
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
        self.routing: RoutingConfig = RoutingConfig()

        self._load_default_config()
        self._initialized = True

    def _load_default_config(self):
        """Carica configurazione default per Media Center"""

        # Ollama Llama 3.1 - Buon bilanciamento generale
        self.providers["ollama:llama3.1:8b"] = ProviderConfig(
            provider=LLMProvider.OLLAMA,
            enabled=True,
            base_url="http://localhost:11434",
            model_name="llama3.1:8b",
            language_confidence={
                "ja->it": 0.80,
                "ja->en": 0.85,
                "zh->en": 0.80,
                "en->it": 0.85,
                "en->es": 0.85,
                "eastern_to_western": 0.80,
                "western_same": 0.85,
            },
            cost_per_1k_tokens=0.0,
            priority=2
        )

        # Ollama Qwen - Ottimo per cinese/giapponese
        self.providers["ollama:qwen2.5:7b"] = ProviderConfig(
            provider=LLMProvider.OLLAMA,
            enabled=True,  # Abilitare dopo download
            base_url="http://localhost:11434",
            model_name="qwen2.5:7b",
            language_confidence={
                "ja->it": 0.90,
                "ja->en": 0.92,
                "zh->it": 0.92,
                "zh->en": 0.95,
                "ko->en": 0.88,
                "eastern_to_western": 0.90,
                "eastern_same": 0.85,
            },
            cost_per_1k_tokens=0.0,
            priority=1
        )

        # Ollama Mistral - Buono per critica (reasoning)
        self.providers["ollama:mistral:7b"] = ProviderConfig(
            provider=LLMProvider.OLLAMA,
            enabled=False,  # Abilitare dopo download
            base_url="http://localhost:11434",
            model_name="mistral:7b",
            language_confidence={
                "en->it": 0.88,
                "en->es": 0.88,
                "en->fr": 0.90,
                "western_same": 0.88,
                "eastern_to_western": 0.75,
            },
            cost_per_1k_tokens=0.0,
            priority=3
        )

        # Routing di default
        self.routing = RoutingConfig(
            enabled=True,
            language_routes={
                "ja->it": ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
                "ja->en": ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
                "zh->it": ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
                "zh->en": ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
                "en->it": ["ollama:llama3.1:8b"],
                "ko->it": ["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
            },
            eastern_providers=["ollama:qwen2.5:7b", "ollama:llama3.1:8b"],
            western_providers=["ollama:llama3.1:8b"],
            mixed_providers=["ollama:llama3.1:8b"]
        )

        logger.info(f"LLM Config caricata: {len(self.providers)} providers")

    # ==========================================================================
    # PROVIDER MANAGEMENT
    # ==========================================================================
    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        """Ottiene configurazione provider per nome"""
        return self.providers.get(name)

    def enable_provider(self, name: str, enabled: bool = True):
        """Abilita/disabilita provider"""
        if name in self.providers:
            self.providers[name].enabled = enabled
            logger.info(f"Provider {name} enabled={enabled}")

    def list_enabled_providers(self) -> List[str]:
        """Lista provider abilitati"""
        return [
            name for name, config in self.providers.items()
            if config.enabled
        ]

    # ==========================================================================
    # ROUTING
    # ==========================================================================
    def get_providers_for_translation(
        self,
        source_lang: str,
        target_lang: str,
        num_providers: int = None
    ) -> List[str]:
        """
        Ottiene provider ottimali per coppia linguistica.

        Args:
            source_lang: Lingua sorgente (ja, zh, en, etc.)
            target_lang: Lingua target (it, en, es, etc.)
            num_providers: Numero max provider da ritornare

        Returns:
            Lista nomi provider ordinati per confidence
        """
        if not self.routing.enabled:
            return self.list_enabled_providers()

        # Cerca route esplicita
        route_key = f"{source_lang}->{target_lang}"
        if route_key in self.routing.language_routes:
            providers = self.routing.language_routes[route_key]
            # Filtra solo abilitati
            providers = [p for p in providers if p in self.providers
                        and self.providers[p].enabled]
        else:
            # Usa routing per famiglia
            providers = self._get_family_providers(source_lang, target_lang)

        # Ordina per confidence
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

    def _get_family_providers(self, source: str, target: str) -> List[str]:
        """Ottiene provider per famiglia linguistica"""
        eastern = ["ja", "zh", "ko", "th", "vi"]

        source_eastern = source in eastern
        target_eastern = target in eastern

        if source_eastern and target_eastern:
            providers = self.routing.eastern_providers
        elif not source_eastern and not target_eastern:
            providers = self.routing.western_providers
        else:
            providers = self.routing.mixed_providers

        return [p for p in providers if p in self.providers
                and self.providers[p].enabled]

    def get_optimal_translator_and_critic(
        self,
        source_lang: str,
        target_lang: str
    ) -> tuple:
        """
        Ottiene coppia ottimale translator/critic per debate.

        STRATEGIA:
        - Translator: Migliore per questa coppia linguistica
        - Critic: Secondo migliore (per diversita), o stesso se unico

        Returns:
            (translator_model, critic_model)
        """
        providers = self.get_providers_for_translation(source_lang, target_lang)

        if not providers:
            # Fallback a llama
            return ("llama3.1:8b", "llama3.1:8b")

        # Estrai nome modello da provider name (es: "ollama:llama3.1:8b" -> "llama3.1:8b")
        def extract_model(provider_name: str) -> str:
            if ":" in provider_name:
                parts = provider_name.split(":")
                if len(parts) >= 2:
                    return ":".join(parts[1:])
            return provider_name

        translator = extract_model(providers[0])

        if len(providers) > 1:
            critic = extract_model(providers[1])
        else:
            # Stesso modello
            critic = translator

        return (translator, critic)

    # ==========================================================================
    # EXPORT/STATUS
    # ==========================================================================
    def get_status(self) -> Dict[str, Any]:
        """Ritorna status configurazione"""
        return {
            "providers": {
                name: {
                    "enabled": config.enabled,
                    "model": config.model_name,
                    "priority": config.priority,
                }
                for name, config in self.providers.items()
            },
            "routing_enabled": self.routing.enabled,
            "enabled_providers": self.list_enabled_providers()
        }


# ==============================================================================
# SINGLETON INSTANCE
# ==============================================================================
_llm_config: Optional[LLMConfigManager] = None


def get_llm_config() -> LLMConfigManager:
    """
    Ottiene istanza singleton LLMConfigManager.

    USAGE:
        config = get_llm_config()
        providers = config.get_providers_for_translation("ja", "it")
    """
    global _llm_config

    if _llm_config is None:
        _llm_config = LLMConfigManager()

    return _llm_config

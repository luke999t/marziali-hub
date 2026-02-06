"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - LLM Config Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di logica pura (dataclass, enum, singleton pattern).

================================================================================
"""

import pytest


# ==============================================================================
# TEST: LLMProvider Enum - Pure Logic
# ==============================================================================
class TestLLMProvider:
    """Test LLMProvider enum - logica pura."""

    def test_provider_values(self):
        """Test all provider values."""
        from services.video_studio.llm_config import LLMProvider

        assert LLMProvider.CLAUDE.value == "claude"
        assert LLMProvider.OPENAI.value == "openai"
        assert LLMProvider.DEEPL.value == "deepl"
        assert LLMProvider.GEMINI.value == "gemini"
        assert LLMProvider.OLLAMA.value == "ollama"
        assert LLMProvider.LLAMA_CPP.value == "llama_cpp"
        assert LLMProvider.VLLM.value == "vllm"

    def test_provider_from_string(self):
        """Test creating provider from string."""
        from services.video_studio.llm_config import LLMProvider

        provider = LLMProvider("claude")
        assert provider == LLMProvider.CLAUDE


# ==============================================================================
# TEST: LanguageFamily Enum - Pure Logic
# ==============================================================================
class TestLanguageFamily:
    """Test LanguageFamily enum - logica pura."""

    def test_language_family_values(self):
        """Test language family values."""
        from services.video_studio.llm_config import LanguageFamily

        assert LanguageFamily.EASTERN.value == "eastern"
        assert LanguageFamily.WESTERN.value == "western"
        assert LanguageFamily.MIXED.value == "mixed"


# ==============================================================================
# TEST: ProviderConfig - Pure Logic
# ==============================================================================
class TestProviderConfig:
    """Test ProviderConfig dataclass - logica pura."""

    def test_provider_config_creation(self):
        """Test creating a ProviderConfig."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider

        config = ProviderConfig(
            provider=LLMProvider.CLAUDE,
            enabled=True,
            api_key="test-key",
            model_name="claude-sonnet-4-20250514",
            max_tokens=4096,
            temperature=0.3,
            priority=1
        )

        assert config.provider == LLMProvider.CLAUDE
        assert config.enabled is True
        assert config.api_key == "test-key"
        assert config.model_name == "claude-sonnet-4-20250514"
        assert config.max_tokens == 4096
        assert config.priority == 1

    def test_provider_config_defaults(self):
        """Test ProviderConfig default values."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider

        config = ProviderConfig(provider=LLMProvider.OPENAI)

        assert config.enabled is True
        assert config.api_key is None
        assert config.base_url is None
        assert config.max_tokens == 4096
        assert config.temperature == 0.3
        assert config.timeout_seconds == 60
        assert config.max_retries == 3
        assert config.cost_per_1k_tokens == 0.0
        assert config.priority == 10

    def test_get_confidence_for_languages_exact_match(self):
        """Test confidence lookup for exact language pair."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider

        config = ProviderConfig(
            provider=LLMProvider.CLAUDE,
            language_confidence={
                "ja->it": 0.95,
                "ja->en": 0.92
            }
        )

        confidence = config.get_confidence_for_languages("ja", "it")
        assert confidence == 0.95

        confidence = config.get_confidence_for_languages("ja", "en")
        assert confidence == 0.92

    def test_get_confidence_for_languages_family_fallback(self):
        """Test confidence lookup with family fallback."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider

        config = ProviderConfig(
            provider=LLMProvider.CLAUDE,
            language_confidence={
                "eastern_to_western": 0.88,
                "western_same": 0.90
            }
        )

        # Japanese to Italian (eastern to western)
        confidence = config.get_confidence_for_languages("ja", "it")
        assert confidence == 0.88

        # English to Spanish (western same)
        confidence = config.get_confidence_for_languages("en", "es")
        assert confidence == 0.90

    def test_get_language_family_eastern(self):
        """Test eastern language detection."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider, LanguageFamily

        config = ProviderConfig(provider=LLMProvider.CLAUDE)

        assert config._get_language_family("ja") == LanguageFamily.EASTERN
        assert config._get_language_family("zh") == LanguageFamily.EASTERN
        assert config._get_language_family("ko") == LanguageFamily.EASTERN
        assert config._get_language_family("th") == LanguageFamily.EASTERN
        assert config._get_language_family("vi") == LanguageFamily.EASTERN

    def test_get_language_family_western(self):
        """Test western language detection."""
        from services.video_studio.llm_config import ProviderConfig, LLMProvider, LanguageFamily

        config = ProviderConfig(provider=LLMProvider.CLAUDE)

        assert config._get_language_family("en") == LanguageFamily.WESTERN
        assert config._get_language_family("it") == LanguageFamily.WESTERN
        assert config._get_language_family("es") == LanguageFamily.WESTERN
        assert config._get_language_family("fr") == LanguageFamily.WESTERN
        assert config._get_language_family("de") == LanguageFamily.WESTERN


# ==============================================================================
# TEST: EnsembleConfig - Pure Logic
# ==============================================================================
class TestEnsembleConfig:
    """Test EnsembleConfig dataclass - logica pura."""

    def test_ensemble_config_creation(self):
        """Test creating an EnsembleConfig."""
        from services.video_studio.llm_config import EnsembleConfig

        config = EnsembleConfig(
            enabled=True,
            num_providers=3,
            strategy="voting",
            confidence_threshold=0.15
        )

        assert config.enabled is True
        assert config.num_providers == 3
        assert config.strategy == "voting"
        assert config.confidence_threshold == 0.15

    def test_ensemble_config_defaults(self):
        """Test EnsembleConfig default values."""
        from services.video_studio.llm_config import EnsembleConfig

        config = EnsembleConfig()

        assert config.enabled is False
        assert config.num_providers == 2
        assert config.strategy == "confidence"
        assert config.confidence_threshold == 0.1
        assert config.run_all is True


# ==============================================================================
# TEST: RoutingConfig - Pure Logic
# ==============================================================================
class TestRoutingConfig:
    """Test RoutingConfig dataclass - logica pura."""

    def test_routing_config_creation(self):
        """Test creating a RoutingConfig."""
        from services.video_studio.llm_config import RoutingConfig

        config = RoutingConfig(
            enabled=True,
            language_routes={"ja->it": ["claude", "openai"]}
        )

        assert config.enabled is True
        assert config.language_routes["ja->it"] == ["claude", "openai"]

    def test_routing_config_defaults(self):
        """Test RoutingConfig default values."""
        from services.video_studio.llm_config import RoutingConfig

        config = RoutingConfig()

        assert config.enabled is True
        assert "claude" in config.eastern_providers
        assert "openai" in config.eastern_providers
        assert "deepl" in config.western_providers
        assert "claude" in config.mixed_providers


# ==============================================================================
# TEST: LLMConfigManager Singleton - Pure Logic
# ==============================================================================
class TestLLMConfigManagerSingleton:
    """Test LLMConfigManager singleton pattern - logica pura."""

    def test_singleton_pattern(self):
        """Test that LLMConfigManager is a singleton."""
        from services.video_studio.llm_config import LLMConfigManager

        # Reset singleton for test
        LLMConfigManager._instance = None

        config1 = LLMConfigManager()
        config2 = LLMConfigManager()

        assert config1 is config2

    def test_singleton_initialization(self):
        """Test singleton initializes only once."""
        from services.video_studio.llm_config import LLMConfigManager

        # Reset singleton for test
        LLMConfigManager._instance = None

        config = LLMConfigManager()

        assert config._initialized is True
        assert len(config.providers) > 0


# ==============================================================================
# TEST: LLMConfigManager Provider Management - Pure Logic
# ==============================================================================
class TestLLMConfigManagerProviders:
    """Test provider management - logica pura."""

    @pytest.fixture
    def llm_config(self):
        """Get fresh LLMConfigManager instance."""
        from services.video_studio.llm_config import LLMConfigManager
        LLMConfigManager._instance = None
        return LLMConfigManager()

    def test_get_provider(self, llm_config):
        """Test getting a provider."""
        config = llm_config.get_provider("claude")

        assert config is not None
        assert config.provider.value == "claude"

    def test_get_provider_not_found(self, llm_config):
        """Test getting non-existent provider."""
        config = llm_config.get_provider("non_existent")

        assert config is None

    def test_enable_provider(self, llm_config):
        """Test enabling/disabling a provider."""
        llm_config.enable_provider("deepl", enabled=False)
        assert llm_config.providers["deepl"].enabled is False

        llm_config.enable_provider("deepl", enabled=True)
        assert llm_config.providers["deepl"].enabled is True

    def test_update_provider(self, llm_config):
        """Test updating provider config."""
        llm_config.update_provider("claude", {
            "max_tokens": 8192,
            "temperature": 0.5
        })

        config = llm_config.get_provider("claude")
        assert config.max_tokens == 8192
        assert config.temperature == 0.5

    def test_update_provider_unknown(self, llm_config):
        """Test updating unknown provider raises error."""
        with pytest.raises(ValueError, match="Unknown provider"):
            llm_config.update_provider("unknown", {"max_tokens": 1000})


# ==============================================================================
# TEST: Default Configuration - Pure Logic
# ==============================================================================
class TestDefaultConfiguration:
    """Test default configuration values - logica pura."""

    @pytest.fixture
    def llm_config(self):
        """Get fresh LLMConfigManager instance."""
        from services.video_studio.llm_config import LLMConfigManager
        LLMConfigManager._instance = None
        return LLMConfigManager()

    def test_default_providers_exist(self, llm_config):
        """Test that default providers are configured."""
        assert "claude" in llm_config.providers
        assert "openai" in llm_config.providers
        assert "deepl" in llm_config.providers
        assert "ollama" in llm_config.providers
        assert "gemini" in llm_config.providers

    def test_claude_default_confidence(self, llm_config):
        """Test Claude default language confidence."""
        claude = llm_config.providers["claude"]

        assert claude.language_confidence.get("ja->it", 0) >= 0.9
        assert claude.language_confidence.get("ja->en", 0) >= 0.9

    def test_deepl_default_confidence(self, llm_config):
        """Test DeepL default language confidence."""
        deepl = llm_config.providers["deepl"]

        assert deepl.language_confidence.get("en->de", 0) >= 0.95
        assert deepl.language_confidence.get("western_same", 0) >= 0.9

    def test_ollama_disabled_by_default(self, llm_config):
        """Test Ollama is disabled by default."""
        ollama = llm_config.providers["ollama"]

        assert ollama.enabled is False

    def test_default_routing_routes(self, llm_config):
        """Test default routing routes."""
        assert "ja->it" in llm_config.routing.language_routes
        assert "ja->en" in llm_config.routing.language_routes
        assert "en->it" in llm_config.routing.language_routes


# ==============================================================================
# TEST: Global Instance - Pure Logic
# ==============================================================================
class TestGlobalInstance:
    """Test global llm_config instance - logica pura."""

    def test_global_instance_exists(self):
        """Test that global instance is available."""
        from services.video_studio.llm_config import llm_config

        assert llm_config is not None
        assert isinstance(llm_config, type(llm_config))

    def test_global_instance_is_singleton(self):
        """Test global instance is the same as new instance.

        FIX_2025_01_21: Restore singleton state before test.
        Other tests reset _instance=None, so we must restore it to llm_config
        to verify the singleton pattern works correctly with the global instance.
        """
        from services.video_studio.llm_config import llm_config, LLMConfigManager

        # Restore singleton to point to the global instance
        # (other tests may have reset _instance to None)
        LLMConfigManager._instance = llm_config

        new_instance = LLMConfigManager()
        assert new_instance is llm_config

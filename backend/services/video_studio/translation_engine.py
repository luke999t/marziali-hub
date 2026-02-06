"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Engine
================================================================================

    AI_FIRST: Multi-Provider Translation Engine for Martial Arts Content
    AI_MODULE: Translation Engine Core
    AI_DESCRIPTION: Multi-provider translation con Claude, OpenAI, DeepL
    AI_BUSINESS: Traduzione AI context-aware con 85%+ accuracy
    AI_TEACHING: Strategy pattern, async API calls, retry logic

    Adapted from: SOFTWARE A - SISTEMA TRADUZIONE MANGAANIME AI-POWERED

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================
import asyncio
import json
import os
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

# ==============================================================================
# LOGGING
# ==============================================================================
logger = structlog.get_logger(__name__)


# ==============================================================================
# ENVIRONMENT CONFIG (replaces app.core.config)
# ==============================================================================
class TranslationSettings:
    """Configuration from environment variables"""

    CLAUDE_API_KEY: str = os.getenv("CLAUDE_API_KEY", "")
    CLAUDE_MODEL: str = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
    CLAUDE_MAX_TOKENS: int = int(os.getenv("CLAUDE_MAX_TOKENS", "4096"))

    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    OPENAI_MAX_TOKENS: int = int(os.getenv("OPENAI_MAX_TOKENS", "4096"))

    DEEPL_API_KEY: str = os.getenv("DEEPL_API_KEY", "")

    TRANSLATION_PRIMARY_PROVIDER: str = os.getenv("TRANSLATION_PRIMARY_PROVIDER", "claude")
    TRANSLATION_FALLBACK_PROVIDER: str = os.getenv("TRANSLATION_FALLBACK_PROVIDER", "openai")
    TRANSLATION_CONFIDENCE_THRESHOLD: float = float(os.getenv("TRANSLATION_CONFIDENCE_THRESHOLD", "0.7"))


settings = TranslationSettings()


# ==============================================================================
# DATA CLASSES
# ==============================================================================
@dataclass
class TranslationResult:
    """
    AI_MODULE: Translation Result
    AI_DESCRIPTION: Risultato traduzione con metadata
    """
    text: str
    confidence: float = 0.0
    alternatives: List[str] = field(default_factory=list)
    cultural_note: Optional[str] = None
    translator_note: Optional[str] = None
    provider: str = ""
    processing_time_ms: float = 0.0
    tokens_used: int = 0

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "confidence": self.confidence,
            "alternatives": self.alternatives,
            "cultural_note": self.cultural_note,
            "translator_note": self.translator_note,
            "provider": self.provider,
            "processing_time_ms": self.processing_time_ms,
            "tokens_used": self.tokens_used
        }


# ==============================================================================
# PROVIDER TYPES
# ==============================================================================
class TranslationProvider(str, Enum):
    """Provider di traduzione disponibili"""
    CLAUDE = "claude"
    OPENAI = "openai"
    DEEPL = "deepl"


# ==============================================================================
# ABSTRACT BASE ENGINE
# ==============================================================================
class BaseTranslationEngine(ABC):
    """
    AI_MODULE: Base Translation Engine
    AI_DESCRIPTION: Interfaccia astratta per provider traduzione
    AI_BUSINESS: Strategy pattern per provider pluggabili
    """

    def __init__(self):
        self.is_initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the translation engine"""
        pass

    @abstractmethod
    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """Translate text"""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Return provider identifier"""
        pass

    async def complete(self, prompt: str) -> str:
        """
        Complete a prompt (for critiques, analysis, etc.)
        Default implementation uses translate infrastructure
        """
        return ""


# ==============================================================================
# CLAUDE ENGINE
# ==============================================================================
class ClaudeEngine(BaseTranslationEngine):
    """
    AI_MODULE: Claude Translation Engine
    AI_DESCRIPTION: Engine basato su Anthropic Claude
    AI_BUSINESS: Best per context-aware translation, character voice
    AI_TEACHING: Anthropic SDK, system prompts, JSON mode
    """

    def __init__(self):
        super().__init__()
        self.client = None

    async def initialize(self) -> None:
        if self.is_initialized:
            return

        try:
            from anthropic import AsyncAnthropic

            if not settings.CLAUDE_API_KEY:
                raise ValueError("CLAUDE_API_KEY not configured")

            self.client = AsyncAnthropic(api_key=settings.CLAUDE_API_KEY)
            self.is_initialized = True
            logger.info("claude_engine_initialized")

        except Exception as e:
            logger.error("claude_init_failed", error=str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """
        AI_MODULE: Claude Translation
        AI_DESCRIPTION: Traduzione con Claude e context awareness
        """
        start_time = time.time()

        if not self.is_initialized:
            await self.initialize()

        system_prompt = self._build_system_prompt(
            source_lang, target_lang, context
        )
        user_message = self._build_user_message(text, context)

        try:
            response = await self.client.messages.create(
                model=settings.CLAUDE_MODEL,
                max_tokens=settings.CLAUDE_MAX_TOKENS,
                system=system_prompt,
                messages=[{"role": "user", "content": user_message}]
            )

            result_text = response.content[0].text
            result = self._parse_response(result_text)

            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=result.get("translation", result_text),
                confidence=result.get("confidence", 0.85),
                alternatives=result.get("alternatives", []),
                cultural_note=result.get("cultural_note"),
                translator_note=result.get("translator_note"),
                provider=self.get_provider_name(),
                processing_time_ms=processing_time,
                tokens_used=response.usage.input_tokens + response.usage.output_tokens
            )

        except Exception as e:
            logger.error("claude_translation_failed", error=str(e), text=text[:50])
            raise

    def _build_system_prompt(
        self,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build system prompt for translation"""
        lang_names = {
            "ja": "Japanese", "en": "English", "it": "Italian",
            "es": "Spanish", "fr": "French", "de": "German",
            "zh": "Chinese", "ko": "Korean", "pt": "Portuguese"
        }

        source_name = lang_names.get(source_lang, source_lang)
        target_name = lang_names.get(target_lang, target_lang)

        prompt = f"""You are a professional martial arts content translator specializing in {source_name} to {target_name} translation.

RULES:
1. Preserve technical martial arts terminology accurately
2. Maintain natural flow in {target_name}
3. Use cultural adaptation where needed
4. Keep honorifics when culturally significant
5. Provide alternatives for ambiguous text

OUTPUT FORMAT (JSON):
{{
  "translation": "translated text",
  "confidence": 0.0-1.0,
  "alternatives": ["alt1", "alt2"],
  "cultural_note": "optional note",
  "translator_note": "optional note"
}}"""

        if context:
            if context.get("character"):
                prompt += f"\n\nCHARACTER: {context['character']}"
            if context.get("glossary"):
                prompt += f"\n\nGLOSSARY: {json.dumps(context['glossary'])}"
            if context.get("previous_dialogue"):
                prompt += f"\n\nPREVIOUS DIALOGUE: {context['previous_dialogue']}"

        return prompt

    def _build_user_message(
        self,
        text: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build user message"""
        return f"Translate this text:\n\n{text}"

    def _parse_response(self, response_text: str) -> dict:
        """Parse JSON response from Claude"""
        try:
            if "{" in response_text:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                json_str = response_text[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError):
            pass
        return {"translation": response_text, "confidence": 0.7}

    def get_provider_name(self) -> str:
        return "claude"

    async def complete(self, prompt: str) -> str:
        """Complete a prompt using Claude"""
        if not self.is_initialized:
            await self.initialize()

        try:
            response = await self.client.messages.create(
                model=settings.CLAUDE_MODEL,
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.content[0].text
        except Exception as e:
            logger.error("claude_complete_failed", error=str(e))
            return ""


# ==============================================================================
# OPENAI ENGINE
# ==============================================================================
class OpenAIEngine(BaseTranslationEngine):
    """
    AI_MODULE: OpenAI Translation Engine
    AI_DESCRIPTION: Engine basato su OpenAI GPT
    AI_BUSINESS: Fallback provider, good for general translation
    AI_TEACHING: OpenAI SDK, function calling, JSON mode
    """

    def __init__(self):
        super().__init__()
        self.client = None

    async def initialize(self) -> None:
        if self.is_initialized:
            return

        try:
            from openai import AsyncOpenAI

            if not settings.OPENAI_API_KEY:
                raise ValueError("OPENAI_API_KEY not configured")

            self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
            self.is_initialized = True
            logger.info("openai_engine_initialized")

        except Exception as e:
            logger.error("openai_init_failed", error=str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """Translate with OpenAI"""
        start_time = time.time()

        if not self.is_initialized:
            await self.initialize()

        system_prompt = self._build_prompt(source_lang, target_lang, context)

        try:
            response = await self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                max_tokens=settings.OPENAI_MAX_TOKENS,
                temperature=0.3,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": text}
                ]
            )

            result_text = response.choices[0].message.content
            result = json.loads(result_text)

            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=result.get("translation", result_text),
                confidence=result.get("confidence", 0.85),
                alternatives=result.get("alternatives", []),
                cultural_note=result.get("cultural_note"),
                translator_note=result.get("translator_note"),
                provider=self.get_provider_name(),
                processing_time_ms=processing_time,
                tokens_used=response.usage.total_tokens
            )

        except Exception as e:
            logger.error("openai_translation_failed", error=str(e))
            raise

    def _build_prompt(
        self,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build translation prompt"""
        return f"""Translate from {source_lang} to {target_lang} for martial arts content.
Return JSON: {{"translation": "...", "confidence": 0.0-1.0, "alternatives": [], "cultural_note": null, "translator_note": null}}"""

    def get_provider_name(self) -> str:
        return "openai"

    async def complete(self, prompt: str) -> str:
        """Complete a prompt using OpenAI"""
        if not self.is_initialized:
            await self.initialize()

        try:
            response = await self.client.chat.completions.create(
                model=settings.OPENAI_MODEL,
                max_tokens=2048,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error("openai_complete_failed", error=str(e))
            return ""


# ==============================================================================
# DEEPL ENGINE
# ==============================================================================
class DeepLEngine(BaseTranslationEngine):
    """
    AI_MODULE: DeepL Translation Engine
    AI_DESCRIPTION: Engine basato su DeepL API
    AI_BUSINESS: Fallback for quick translations
    AI_TEACHING: REST API client, simple integration
    """

    def __init__(self):
        super().__init__()
        self.translator = None

    async def initialize(self) -> None:
        if self.is_initialized:
            return

        try:
            import deepl

            if not settings.DEEPL_API_KEY:
                raise ValueError("DEEPL_API_KEY not configured")

            self.translator = deepl.Translator(settings.DEEPL_API_KEY)
            self.is_initialized = True
            logger.info("deepl_engine_initialized")

        except Exception as e:
            logger.error("deepl_init_failed", error=str(e))
            raise

    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """Translate with DeepL"""
        start_time = time.time()

        if not self.is_initialized:
            await self.initialize()

        lang_map = {
            "ja": "JA", "en": "EN-US", "it": "IT",
            "es": "ES", "fr": "FR", "de": "DE",
            "zh": "ZH", "pt": "PT-BR"
        }

        try:
            result = self.translator.translate_text(
                text,
                source_lang=lang_map.get(source_lang, source_lang.upper()),
                target_lang=lang_map.get(target_lang, target_lang.upper())
            )

            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=result.text,
                confidence=0.8,
                alternatives=[],
                provider=self.get_provider_name(),
                processing_time_ms=processing_time
            )

        except Exception as e:
            logger.error("deepl_translation_failed", error=str(e))
            raise

    def get_provider_name(self) -> str:
        return "deepl"


# ==============================================================================
# OLLAMA ENGINE (Open Source Local Models)
# ==============================================================================
class OllamaEngine(BaseTranslationEngine):
    """
    AI_MODULE: Ollama Translation Engine
    AI_DESCRIPTION: Engine per modelli open source locali via Ollama
    AI_BUSINESS: Traduzione gratuita, privacy-preserving, customizable
    AI_TEACHING: REST API client, local LLM inference

    Supports: LLama 3.1, Mistral, Mixtral, Qwen, etc.
    """

    def __init__(self, base_url: str = None, model: str = None):
        super().__init__()
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        self.client = None

    async def initialize(self) -> None:
        if self.is_initialized:
            return

        try:
            import httpx

            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=120.0
            )

            response = await self.client.get("/api/tags")
            if response.status_code != 200:
                raise ValueError("Ollama server not responding")

            self.is_initialized = True
            logger.info("ollama_engine_initialized", model=self.model)

        except Exception as e:
            logger.error("ollama_init_failed", error=str(e))
            raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """Translate with Ollama local model"""
        start_time = time.time()

        if not self.is_initialized:
            await self.initialize()

        prompt = self._build_prompt(text, source_lang, target_lang, context)

        try:
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2048
                    }
                }
            )

            result = response.json()
            result_text = result.get("response", "")

            parsed = self._parse_response(result_text)
            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=parsed.get("translation", result_text),
                confidence=parsed.get("confidence", 0.75),
                alternatives=parsed.get("alternatives", []),
                cultural_note=parsed.get("cultural_note"),
                translator_note=parsed.get("translator_note"),
                provider=self.get_provider_name(),
                processing_time_ms=processing_time,
                tokens_used=result.get("eval_count", 0)
            )

        except Exception as e:
            logger.error("ollama_translation_failed", error=str(e))
            raise

    def _build_prompt(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for Ollama model"""
        lang_names = {
            "ja": "Japanese", "en": "English", "it": "Italian",
            "es": "Spanish", "fr": "French", "de": "German",
            "zh": "Chinese", "ko": "Korean"
        }

        source_name = lang_names.get(source_lang, source_lang)
        target_name = lang_names.get(target_lang, target_lang)

        prompt = f"""You are a professional martial arts translator. Translate the following text from {source_name} to {target_name}.

Rules:
- Preserve technical terminology accurately
- Use natural {target_name} expressions
- Provide alternatives for ambiguous text

Respond ONLY with JSON:
{{"translation": "translated text", "confidence": 0.0-1.0, "alternatives": [], "cultural_note": null}}

Text to translate:
{text}

JSON response:"""

        return prompt

    def _parse_response(self, response_text: str) -> dict:
        """Parse JSON from Ollama response"""
        try:
            if "{" in response_text:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                return json.loads(response_text[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
        return {"translation": response_text.strip(), "confidence": 0.7}

    def get_provider_name(self) -> str:
        return f"ollama:{self.model}"

    async def complete(self, prompt: str) -> str:
        """Complete a prompt using Ollama"""
        if not self.is_initialized:
            await self.initialize()

        try:
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,
                        "num_predict": 2048
                    }
                }
            )
            result = response.json()
            return result.get("response", "")
        except Exception as e:
            logger.error("ollama_complete_failed", error=str(e))
            return ""


# ==============================================================================
# ENSEMBLE TRANSLATOR
# ==============================================================================
class EnsembleTranslator:
    """
    AI_MODULE: Ensemble Translation
    AI_DESCRIPTION: Chiama multipli LLM in parallelo e combina risultati
    AI_BUSINESS: Massima qualità tramite consensus/voting
    AI_TEACHING: Async parallelism, voting algorithms, confidence aggregation
    """

    @staticmethod
    async def translate_ensemble(
        text: str,
        source_lang: str,
        target_lang: str,
        providers: List[str],
        context: Optional[Dict[str, Any]] = None,
        strategy: str = "confidence"
    ) -> TranslationResult:
        """
        Translate using multiple providers in parallel
        """
        from .llm_config import llm_config

        tasks = []
        provider_names = []

        for provider_name in providers:
            config = llm_config.get_provider(provider_name)
            if not config or not config.enabled:
                continue

            try:
                engine = await TranslationEngine.get_engine_by_name(provider_name)
                task = engine.translate(text, source_lang, target_lang, context)
                tasks.append(task)
                provider_names.append(provider_name)
            except Exception as e:
                logger.warning(
                    "ensemble_provider_skip",
                    provider=provider_name,
                    error=str(e)
                )

        if not tasks:
            raise Exception("No providers available for ensemble translation")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(
                    "ensemble_provider_failed",
                    provider=provider_names[i],
                    error=str(result)
                )
            else:
                result.provider = provider_names[i]
                successful_results.append(result)

        if not successful_results:
            raise Exception("All ensemble providers failed")

        if strategy == "confidence":
            return EnsembleTranslator._select_by_confidence(successful_results)
        elif strategy == "voting":
            return EnsembleTranslator._select_by_voting(successful_results)
        elif strategy == "weighted":
            return EnsembleTranslator._select_by_weighted(
                successful_results, source_lang, target_lang
            )
        else:
            return successful_results[0]

    @staticmethod
    def _select_by_confidence(results: List[TranslationResult]) -> TranslationResult:
        """Select result with highest confidence"""
        return max(results, key=lambda r: r.confidence)

    @staticmethod
    def _select_by_voting(results: List[TranslationResult]) -> TranslationResult:
        """Select result by majority voting on text similarity"""
        if len(results) == 1:
            return results[0]

        texts = [r.text.lower().strip() for r in results]

        from collections import Counter
        text_counts = Counter(texts)
        most_common_text, count = text_counts.most_common(1)[0]

        for result in results:
            if result.text.lower().strip() == most_common_text:
                agreement_ratio = count / len(results)
                result.confidence = min(1.0, result.confidence + (agreement_ratio * 0.1))
                result.translator_note = f"Ensemble consensus ({count}/{len(results)} providers agreed)"
                return result

        return results[0]

    @staticmethod
    def _select_by_weighted(
        results: List[TranslationResult],
        source_lang: str,
        target_lang: str
    ) -> TranslationResult:
        """Select result using weighted confidence based on language expertise"""
        from .llm_config import llm_config

        best_result = None
        best_score = -1

        for result in results:
            config = llm_config.get_provider(result.provider)
            if config:
                lang_confidence = config.get_confidence_for_languages(
                    source_lang, target_lang
                )
                score = result.confidence * lang_confidence
            else:
                score = result.confidence

            if score > best_score:
                best_score = score
                best_result = result

        return best_result


# ==============================================================================
# TRANSLATION ENGINE FACTORY
# ==============================================================================
class TranslationEngine:
    """
    AI_MODULE: Translation Engine Factory
    AI_DESCRIPTION: Factory per creare engine traduzione con multi-LLM support
    AI_BUSINESS: Selezione automatica, ensemble, routing per lingua
    AI_TEACHING: Factory pattern, caching, warm-up, configurability
    """

    _engines: dict = {}
    _standby_engines: dict = {}

    @classmethod
    async def get_engine(
        cls,
        provider: TranslationProvider = None
    ) -> BaseTranslationEngine:
        """Get or create translation engine"""
        if provider is None:
            provider = TranslationProvider(settings.TRANSLATION_PRIMARY_PROVIDER)

        return await cls.get_engine_by_name(provider.value)

    @classmethod
    async def get_engine_by_name(cls, name: str) -> BaseTranslationEngine:
        """Get or create translation engine by name"""
        from .llm_config import llm_config

        if name in cls._engines:
            return cls._engines[name]

        if name in cls._standby_engines:
            engine = cls._standby_engines.pop(name)
            cls._engines[name] = engine
            logger.info("engine_promoted_from_standby", provider=name)
            return engine

        config = llm_config.get_provider(name)

        if name == "claude" or (config and config.provider.value == "claude"):
            engine = ClaudeEngine()
        elif name == "openai" or (config and config.provider.value == "openai"):
            engine = OpenAIEngine()
        elif name == "deepl" or (config and config.provider.value == "deepl"):
            engine = DeepLEngine()
        elif name == "ollama" or (config and config.provider.value == "ollama"):
            base_url = config.base_url if config else None
            model = config.model_name if config else None
            engine = OllamaEngine(base_url=base_url, model=model)
        elif name.startswith("ollama:"):
            model = name.split(":", 1)[1]
            base_url = config.base_url if config else None
            engine = OllamaEngine(base_url=base_url, model=model)
        else:
            raise ValueError(f"Unknown provider: {name}")

        await engine.initialize()
        cls._engines[name] = engine

        return engine

    @classmethod
    async def warm_up_engine(cls, name: str) -> bool:
        """Pre-initialize engine in standby mode"""
        try:
            if name in cls._engines or name in cls._standby_engines:
                return True

            engine = await cls.get_engine_by_name(name)
            if name in cls._engines:
                cls._standby_engines[name] = cls._engines.pop(name)

            logger.info("engine_warmed_up", provider=name)
            return True

        except Exception as e:
            logger.error("engine_warmup_failed", provider=name, error=str(e))
            return False

    @classmethod
    async def warm_up_all(cls, providers: List[str] = None):
        """Warm up multiple engines in parallel"""
        from .llm_config import llm_config

        if providers is None:
            providers = llm_config.list_enabled_providers()

        tasks = [cls.warm_up_engine(name) for name in providers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = sum(1 for r in results if r is True)
        logger.info(
            "engines_warmed_up",
            total=len(providers),
            successful=successful
        )

    @classmethod
    def shutdown_engine(cls, name: str):
        """Shutdown and remove an engine"""
        if name in cls._engines:
            del cls._engines[name]
            logger.info("engine_shutdown", provider=name)
        if name in cls._standby_engines:
            del cls._standby_engines[name]

    @classmethod
    def get_engine_status(cls) -> Dict[str, Any]:
        """Get status of all engines"""
        return {
            "active": list(cls._engines.keys()),
            "standby": list(cls._standby_engines.keys()),
            "total_initialized": len(cls._engines) + len(cls._standby_engines)
        }

    @classmethod
    async def translate(
        cls,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None,
        provider: TranslationProvider = None
    ) -> TranslationResult:
        """Translate with specified provider"""
        engine = await cls.get_engine(provider)
        return await engine.translate(text, source_lang, target_lang, context)

    @classmethod
    async def translate_with_fallback(
        cls,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None,
        confidence_threshold: float = None
    ) -> TranslationResult:
        """Translate with automatic fallback"""
        if confidence_threshold is None:
            confidence_threshold = settings.TRANSLATION_CONFIDENCE_THRESHOLD

        primary = TranslationProvider(settings.TRANSLATION_PRIMARY_PROVIDER)
        try:
            result = await cls.translate(
                text, source_lang, target_lang, context, primary
            )

            if result.confidence >= confidence_threshold:
                return result

        except Exception as e:
            logger.warning("primary_translation_failed", error=str(e))
            result = None

        fallback = TranslationProvider(settings.TRANSLATION_FALLBACK_PROVIDER)
        if fallback != primary:
            try:
                fallback_result = await cls.translate(
                    text, source_lang, target_lang, context, fallback
                )

                if result is None or fallback_result.confidence > result.confidence:
                    logger.info(
                        "fallback_translation_used",
                        provider=fallback.value
                    )
                    return fallback_result

            except Exception as e:
                logger.warning("fallback_translation_failed", error=str(e))

        if result:
            return result

        raise Exception("All translation providers failed")

    @classmethod
    async def translate_smart(
        cls,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None,
        verify: bool = False
    ) -> TranslationResult:
        """
        Smart translation with automatic provider routing and optional verification
        """
        from .llm_config import llm_config

        providers = llm_config.get_providers_for_translation(
            source_lang, target_lang
        )

        if not providers:
            raise Exception("No providers available for this language pair")

        if llm_config.should_use_ensemble():
            num_providers = llm_config.ensemble.num_providers
            selected_providers = providers[:num_providers]

            result = await EnsembleTranslator.translate_ensemble(
                text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                providers=selected_providers,
                context=context,
                strategy=llm_config.ensemble.strategy
            )

            logger.info(
                "smart_translation_ensemble",
                providers=selected_providers,
                confidence=result.confidence
            )

            return result

        primary_provider = providers[0]
        result = await cls.translate(
            text=text,
            source_lang=source_lang,
            target_lang=target_lang,
            context=context,
            provider=TranslationProvider(primary_provider) if primary_provider in [p.value for p in TranslationProvider] else None
        )

        if verify and len(providers) > 1 and result.confidence < 0.9:
            secondary_provider = providers[1]

            try:
                verify_result = await cls.translate(
                    text=text,
                    source_lang=source_lang,
                    target_lang=target_lang,
                    context=context,
                    provider=TranslationProvider(secondary_provider) if secondary_provider in [p.value for p in TranslationProvider] else None
                )

                if verify_result.confidence > result.confidence:
                    result = verify_result
                    result.translator_note = f"Verified by {secondary_provider}"
                elif verify_result.text.lower().strip() == result.text.lower().strip():
                    result.confidence = min(1.0, result.confidence + 0.1)
                    result.translator_note = f"Confirmed by {secondary_provider}"

                logger.info(
                    "translation_verified",
                    primary=primary_provider,
                    secondary=secondary_provider,
                    final_confidence=result.confidence
                )

            except Exception as e:
                logger.warning("verification_failed", error=str(e))

        return result

    @classmethod
    async def translate_with_providers(
        cls,
        text: str,
        source_lang: str,
        target_lang: str,
        providers: List[str],
        context: Optional[Dict[str, Any]] = None,
        parallel: bool = True
    ) -> TranslationResult:
        """
        Translate with specific providers (configurable)
        """
        if not providers:
            raise ValueError("At least one provider required")

        if len(providers) == 1:
            engine = await cls.get_engine_by_name(providers[0])
            return await engine.translate(text, source_lang, target_lang, context)

        if parallel:
            return await EnsembleTranslator.translate_ensemble(
                text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                providers=providers,
                context=context,
                strategy="confidence"
            )
        else:
            best_result = None

            for provider_name in providers:
                try:
                    engine = await cls.get_engine_by_name(provider_name)
                    result = await engine.translate(
                        text, source_lang, target_lang, context
                    )

                    if best_result is None or result.confidence > best_result.confidence:
                        best_result = result

                    if result.confidence >= 0.95:
                        break

                except Exception as e:
                    logger.warning(
                        "provider_failed",
                        provider=provider_name,
                        error=str(e)
                    )

            if best_result is None:
                raise Exception("All providers failed")

            return best_result

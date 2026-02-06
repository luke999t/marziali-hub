"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Ollama Translation Engine
================================================================================

    AI_MODULE: Ollama Translation Engine
    AI_DESCRIPTION: Engine per modelli locali Ollama con supporto debate
    AI_BUSINESS: Traduzione gratuita, privacy-preserving, customizable
    AI_TEACHING: REST API client, local LLM inference, debate pattern

    ALTERNATIVE_VALUTATE:
    - OpenAI API: Scartato perche richiede internet e costi
    - HuggingFace local: Scartato perche setup complesso
    - Ollama: Scelto perche semplice, gratuito, supporta molti modelli

    PERCHE_QUESTA_SOLUZIONE:
    - Vantaggio tecnico: Modelli locali, nessuna latenza rete esterna
    - Vantaggio business: Costo zero, dati rimangono locali
    - Trade-off: Richiede GPU per performance ottimali

    INTEGRATION_DEPENDENCIES:
    - Upstream: Ollama server (localhost:11434)
    - Downstream: translation_debate.py, llm_config.py

================================================================================
"""

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
import asyncio

import httpx

# Logging semplificato per evitare dipendenze esterne
import logging
logger = logging.getLogger(__name__)


# ==============================================================================
# DATA CLASSES
# ==============================================================================
@dataclass
class TranslationResult:
    """
    AI_MODULE: Translation Result
    AI_DESCRIPTION: Risultato traduzione con metadata e confidence

    Usato sia per traduzione singola che per risultati debate.
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


@dataclass
class CritiqueResult:
    """
    AI_MODULE: Critique Result
    AI_DESCRIPTION: Risultato critica di una traduzione

    Usato nel debate per valutare traduzioni.
    """
    is_acceptable: bool
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    confidence_adjustment: float = 0.0
    reasoning: str = ""

    def to_dict(self) -> dict:
        return {
            "is_acceptable": self.is_acceptable,
            "issues": self.issues,
            "suggestions": self.suggestions,
            "confidence_adjustment": self.confidence_adjustment,
            "reasoning": self.reasoning
        }


@dataclass
class DebateRound:
    """
    AI_MODULE: Debate Round
    AI_DESCRIPTION: Singolo round di debate tra translator e critic

    Tiene traccia di traduzione, critica e risposta.
    """
    round_number: int
    translation: TranslationResult
    critique: Optional[CritiqueResult] = None
    response: Optional[str] = None
    consensus_reached: bool = False


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

    async def critique(
        self,
        original_text: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> CritiqueResult:
        """
        Critique a translation (for debate system).
        Default implementation - subclasses should override.
        """
        return CritiqueResult(
            is_acceptable=True,
            issues=[],
            suggestions=[],
            confidence_adjustment=0.0,
            reasoning="No critique available"
        )

    async def respond_to_critique(
        self,
        original_text: str,
        translation: str,
        critique: CritiqueResult,
        source_lang: str,
        target_lang: str
    ) -> TranslationResult:
        """
        Respond to critique with improved translation.
        Default implementation - subclasses should override.
        """
        return TranslationResult(
            text=translation,
            confidence=0.7,
            provider=self.get_provider_name()
        )


# ==============================================================================
# OLLAMA ENGINE
# ==============================================================================
class OllamaEngine(BaseTranslationEngine):
    """
    AI_MODULE: Ollama Translation Engine
    AI_DESCRIPTION: Engine per modelli open source locali via Ollama
    AI_BUSINESS: Traduzione gratuita, privacy-preserving, customizable
    AI_TEACHING: REST API client, local LLM inference, debate support

    Supports: LLama 3.1, Mistral, Mixtral, Qwen, etc.

    METODI PRINCIPALI:
    - translate(): Traduzione base
    - critique(): Critica una traduzione (per debate)
    - respond_to_critique(): Risponde a critica con traduzione migliorata
    """

    def __init__(
        self,
        base_url: str = None,
        model: str = None,
        critic_model: str = None
    ):
        """
        Args:
            base_url: URL server Ollama (default: localhost:11434)
            model: Modello per traduzione (default: llama3.1:8b)
            critic_model: Modello per critica (default: stesso di model)

        PERCHE DUE MODELLI:
        Nel debate, e utile avere modelli diversi per traduzione e critica.
        Es: Qwen per tradurre cinese/giapponese, Mistral per criticare.
        """
        super().__init__()
        self.base_url = base_url or "http://localhost:11434"
        self.model = model or "llama3.1:8b"
        self.critic_model = critic_model or self.model
        self.client: Optional[httpx.AsyncClient] = None

    async def initialize(self) -> None:
        """
        Inizializza connessione a Ollama.

        Verifica che:
        1. Server Ollama sia attivo
        2. Modello richiesto sia disponibile
        """
        if self.is_initialized:
            return

        try:
            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=120.0  # Modelli locali possono essere lenti
            )

            # Verifica server attivo
            response = await self.client.get("/api/tags")
            if response.status_code != 200:
                raise ValueError(f"Ollama server non risponde: {response.status_code}")

            # Verifica modello disponibile
            models_data = response.json()
            available_models = [m["name"] for m in models_data.get("models", [])]

            if self.model not in available_models and not any(
                self.model in m for m in available_models
            ):
                logger.warning(
                    f"Modello {self.model} non trovato. Disponibili: {available_models}"
                )
                # Non fallisce, potrebbe essere scaricato on-demand

            self.is_initialized = True
            logger.info(f"OllamaEngine inizializzato: model={self.model}")

        except httpx.ConnectError as e:
            raise ValueError(
                f"Impossibile connettersi a Ollama su {self.base_url}. "
                f"Assicurati che Ollama sia attivo. Errore: {e}"
            )
        except Exception as e:
            logger.error(f"Errore inizializzazione Ollama: {e}")
            raise

    async def translate(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationResult:
        """
        Traduce testo usando modello Ollama locale.

        AI_TEACHING: Il prompt e strutturato per:
        1. Definire ruolo (traduttore professionale arti marziali)
        2. Fornire regole specifiche per il dominio
        3. Richiedere output JSON strutturato
        """
        start_time = time.time()

        if not self.is_initialized:
            await self.initialize()

        prompt = self._build_translation_prompt(text, source_lang, target_lang, context)

        try:
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.3,  # Bassa per traduzioni consistenti
                        "num_predict": 2048
                    }
                }
            )

            result = response.json()
            result_text = result.get("response", "")

            # Parse JSON response
            parsed = self._parse_json_response(result_text)
            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=parsed.get("translation", result_text.strip()),
                confidence=parsed.get("confidence", 0.75),
                alternatives=parsed.get("alternatives", []),
                cultural_note=parsed.get("cultural_note"),
                translator_note=parsed.get("translator_note"),
                provider=self.get_provider_name(),
                processing_time_ms=processing_time,
                tokens_used=result.get("eval_count", 0)
            )

        except Exception as e:
            logger.error(f"Errore traduzione Ollama: {e}")
            raise

    async def critique(
        self,
        original_text: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> CritiqueResult:
        """
        Critica una traduzione (usato nel debate).

        AI_TEACHING: Il critico deve:
        1. Identificare errori semantici
        2. Verificare terminologia tecnica (arti marziali)
        3. Valutare naturalezza nella lingua target
        4. Suggerire miglioramenti specifici
        """
        if not self.is_initialized:
            await self.initialize()

        prompt = self._build_critique_prompt(
            original_text, translation, source_lang, target_lang, context
        )

        try:
            response = await self.client.post(
                "/api/generate",
                json={
                    "model": self.critic_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.4,  # Leggermente piu alta per varieta
                        "num_predict": 1024
                    }
                }
            )

            result = response.json()
            result_text = result.get("response", "")

            parsed = self._parse_json_response(result_text)

            return CritiqueResult(
                is_acceptable=parsed.get("is_acceptable", True),
                issues=parsed.get("issues", []),
                suggestions=parsed.get("suggestions", []),
                confidence_adjustment=parsed.get("confidence_adjustment", 0.0),
                reasoning=parsed.get("reasoning", "")
            )

        except Exception as e:
            logger.error(f"Errore critica Ollama: {e}")
            # Fallback: accetta la traduzione
            return CritiqueResult(
                is_acceptable=True,
                issues=[],
                suggestions=[],
                reasoning=f"Critica non disponibile: {e}"
            )

    async def respond_to_critique(
        self,
        original_text: str,
        translation: str,
        critique: CritiqueResult,
        source_lang: str,
        target_lang: str
    ) -> TranslationResult:
        """
        Risponde a critica con traduzione migliorata.

        AI_TEACHING: Il traduttore deve:
        1. Considerare i problemi identificati
        2. Applicare i suggerimenti dove appropriato
        3. Giustificare scelte che non cambia
        """
        if not self.is_initialized:
            await self.initialize()

        start_time = time.time()
        prompt = self._build_response_prompt(
            original_text, translation, critique, source_lang, target_lang
        )

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

            parsed = self._parse_json_response(result_text)
            processing_time = (time.time() - start_time) * 1000

            return TranslationResult(
                text=parsed.get("translation", result_text.strip()),
                confidence=parsed.get("confidence", 0.8),
                alternatives=parsed.get("alternatives", []),
                translator_note=parsed.get("reasoning", ""),
                provider=self.get_provider_name(),
                processing_time_ms=processing_time,
                tokens_used=result.get("eval_count", 0)
            )

        except Exception as e:
            logger.error(f"Errore risposta critica Ollama: {e}")
            # Fallback: ritorna traduzione originale
            return TranslationResult(
                text=translation,
                confidence=0.6,
                provider=self.get_provider_name()
            )

    def get_provider_name(self) -> str:
        return f"ollama:{self.model}"

    # ==========================================================================
    # PROMPT BUILDERS
    # ==========================================================================
    def _build_translation_prompt(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """
        Costruisce prompt per traduzione.

        PERCHE QUESTO FORMATO:
        - Ruolo specifico (arti marziali) per terminologia corretta
        - Regole esplicite per consistenza
        - Output JSON per parsing affidabile
        """
        lang_names = {
            "ja": "Japanese", "en": "English", "it": "Italian",
            "es": "Spanish", "fr": "French", "de": "German",
            "zh": "Chinese", "ko": "Korean", "pt": "Portuguese"
        }

        source_name = lang_names.get(source_lang, source_lang)
        target_name = lang_names.get(target_lang, target_lang)

        prompt = f"""You are a professional martial arts translator specializing in {source_name} to {target_name} translation.

DOMAIN: Martial arts techniques, training methods, philosophy.

RULES:
1. Preserve technical terminology accuracy (kicks, punches, stances, etc.)
2. Keep Japanese/Chinese terms when commonly used (kata, chi, sensei)
3. Maintain natural flow in {target_name}
4. Provide alternatives for ambiguous terms

"""
        # Aggiungi context se presente
        if context:
            if context.get("glossary"):
                prompt += f"GLOSSARY (use these terms):\n{json.dumps(context['glossary'], indent=2)}\n\n"
            if context.get("style"):
                prompt += f"MARTIAL ART STYLE: {context['style']}\n\n"

        prompt += f"""TEXT TO TRANSLATE:
{text}

RESPOND ONLY WITH JSON:
{{"translation": "translated text", "confidence": 0.0-1.0, "alternatives": [], "cultural_note": null, "translator_note": null}}

JSON:"""

        return prompt

    def _build_critique_prompt(
        self,
        original_text: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]]
    ) -> str:
        """
        Costruisce prompt per critica.

        PERCHE QUESTO FORMATO:
        - Chiede analisi specifica degli errori
        - Richiede suggerimenti concreti
        - Output strutturato per facile parsing
        """
        lang_names = {
            "ja": "Japanese", "en": "English", "it": "Italian",
            "es": "Spanish", "fr": "French", "de": "German",
            "zh": "Chinese", "ko": "Korean"
        }

        source_name = lang_names.get(source_lang, source_lang)
        target_name = lang_names.get(target_lang, target_lang)

        prompt = f"""You are a senior translation reviewer for martial arts content.

TASK: Critique this {source_name} to {target_name} translation.

ORIGINAL TEXT ({source_name}):
{original_text}

TRANSLATION ({target_name}):
{translation}

EVALUATE:
1. Semantic accuracy (meaning preserved?)
2. Technical terminology (martial arts terms correct?)
3. Naturalness in {target_name}
4. Any cultural nuances lost?

RESPOND ONLY WITH JSON:
{{
  "is_acceptable": true/false,
  "issues": ["issue1", "issue2"],
  "suggestions": ["suggestion1", "suggestion2"],
  "confidence_adjustment": -0.2 to +0.2,
  "reasoning": "brief explanation"
}}

JSON:"""

        return prompt

    def _build_response_prompt(
        self,
        original_text: str,
        translation: str,
        critique: CritiqueResult,
        source_lang: str,
        target_lang: str
    ) -> str:
        """
        Costruisce prompt per risposta a critica.

        PERCHE QUESTO FORMATO:
        - Mostra critica ricevuta
        - Chiede di affrontare ogni problema
        - Permette di difendere scelte valide
        """
        issues_str = "\n".join(f"- {issue}" for issue in critique.issues)
        suggestions_str = "\n".join(f"- {s}" for s in critique.suggestions)

        prompt = f"""You are a professional martial arts translator.

A reviewer has critiqued your translation. Address the feedback.

ORIGINAL TEXT:
{original_text}

YOUR TRANSLATION:
{translation}

REVIEWER FEEDBACK:
Issues:
{issues_str}

Suggestions:
{suggestions_str}

Reasoning: {critique.reasoning}

TASK:
1. Consider each issue
2. Apply valid suggestions
3. Explain any suggestions you disagree with
4. Provide improved translation

RESPOND ONLY WITH JSON:
{{"translation": "improved text", "confidence": 0.0-1.0, "alternatives": [], "reasoning": "why you made these changes"}}

JSON:"""

        return prompt

    def _parse_json_response(self, response_text: str) -> dict:
        """
        Parse JSON da risposta LLM.

        PERCHE QUESTO METODO:
        LLM a volte aggiungono testo prima/dopo JSON.
        Questo metodo estrae solo la parte JSON valida.
        """
        try:
            if "{" in response_text:
                start = response_text.index("{")
                end = response_text.rindex("}") + 1
                json_str = response_text[start:end]
                return json.loads(json_str)
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"JSON parse fallito: {e}")

        # Fallback: ritorna testo grezzo come translation
        return {"translation": response_text.strip(), "confidence": 0.7}


# ==============================================================================
# FACTORY FUNCTION
# ==============================================================================
def get_ollama_engine(
    model: str = "llama3.1:8b",
    critic_model: str = None,
    base_url: str = "http://localhost:11434"
) -> OllamaEngine:
    """
    Factory function per creare OllamaEngine.

    Args:
        model: Modello per traduzione
        critic_model: Modello per critica (default: stesso di model)
        base_url: URL server Ollama

    Returns:
        OllamaEngine configurato

    USAGE:
        engine = get_ollama_engine(model="qwen2.5:7b")
        await engine.initialize()
        result = await engine.translate("text", "ja", "it")
    """
    return OllamaEngine(
        base_url=base_url,
        model=model,
        critic_model=critic_model or model
    )

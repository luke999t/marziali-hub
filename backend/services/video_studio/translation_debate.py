"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Debate System
================================================================================

    AI_FIRST: Multi-LLM Debate Translation System
    AI_DESCRIPTION: Uses multiple LLMs to debate and refine translations
                   through structured argumentation rounds

    STATUS: Placeholder for Ollama integration

================================================================================
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from abc import ABC, abstractmethod

import httpx

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMS AND DATA CLASSES
# ==============================================================================

class DebateRole(Enum):
    """Roles in the translation debate"""
    PRIMARY = "primary"          # Main translator
    CRITIC = "critic"            # Reviews and critiques translation
    ARBITER = "arbiter"          # Final decision maker (optional)


class DebatePhase(Enum):
    """Phases of the debate process"""
    INITIAL_TRANSLATION = "initial_translation"
    CRITIQUE = "critique"
    DEFENSE = "defense"
    REFINEMENT = "refinement"
    CONSENSUS = "consensus"


@dataclass
class DebateArgument:
    """Single argument in the debate"""
    role: DebateRole
    phase: DebatePhase
    content: str
    confidence: float
    reasoning: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TranslationCandidate:
    """A translation candidate with metadata"""
    text: str
    source_text: str
    source_lang: str
    target_lang: str
    confidence: float
    provider: str
    arguments_for: List[str] = field(default_factory=list)
    arguments_against: List[str] = field(default_factory=list)
    refinements: List[str] = field(default_factory=list)


@dataclass
class DebateResult:
    """Result of a translation debate"""
    final_translation: str
    confidence: float
    consensus_reached: bool
    rounds_completed: int
    debate_history: List[DebateArgument]
    candidates: List[TranslationCandidate]
    duration_ms: float
    winner_role: Optional[DebateRole] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "final_translation": self.final_translation,
            "confidence": self.confidence,
            "consensus_reached": self.consensus_reached,
            "rounds_completed": self.rounds_completed,
            "duration_ms": self.duration_ms,
            "winner_role": self.winner_role.value if self.winner_role else None,
            "debate_summary": {
                "total_arguments": len(self.debate_history),
                "candidates_considered": len(self.candidates)
            }
        }


@dataclass
class DebateConfig:
    """Configuration for the debate system"""
    max_rounds: int = 3
    min_confidence_threshold: float = 0.85
    consensus_threshold: float = 0.90
    timeout_seconds: float = 60.0
    require_reasoning: bool = True
    enable_arbiter: bool = False


# ==============================================================================
# ABSTRACT LLM INTERFACE
# ==============================================================================

class DebateLLM(ABC):
    """Abstract base class for LLMs participating in debates"""

    def __init__(self, role: DebateRole, model_name: str):
        self.role = role
        self.model_name = model_name
        self._initialized = False

    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the LLM connection"""
        pass

    @abstractmethod
    async def generate_translation(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationCandidate:
        """Generate initial translation"""
        pass

    @abstractmethod
    async def critique_translation(
        self,
        original: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> DebateArgument:
        """Critique a translation"""
        pass

    @abstractmethod
    async def defend_translation(
        self,
        original: str,
        translation: str,
        critique: DebateArgument,
        context: Optional[Dict[str, Any]] = None
    ) -> DebateArgument:
        """Defend a translation against critique"""
        pass

    @abstractmethod
    async def refine_translation(
        self,
        original: str,
        translation: str,
        arguments: List[DebateArgument],
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationCandidate:
        """Refine translation based on debate"""
        pass


# ==============================================================================
# OLLAMA LLM IMPLEMENTATION
# ==============================================================================

class OllamaDebateLLM(DebateLLM):
    """
    Ollama-based LLM for translation debates.

    Requires Ollama server running locally (default: http://localhost:11434).
    Supports models like:
    - llama3.2
    - mistral
    - qwen2.5
    - phi3
    """

    # Language name mappings for natural prompts
    LANGUAGE_NAMES = {
        "ja": "Japanese",
        "zh": "Chinese",
        "ko": "Korean",
        "vi": "Vietnamese",
        "th": "Thai",
        "it": "Italian",
        "en": "English",
        "es": "Spanish",
        "fr": "French",
        "de": "German",
        "pt": "Portuguese",
    }

    def __init__(
        self,
        role: DebateRole,
        model_name: str = "llama3.2",
        base_url: str = "http://localhost:11434",
        timeout: float = 60.0
    ):
        super().__init__(role, model_name)
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
        self._available_models: List[str] = []

    def _get_language_name(self, code: str) -> str:
        """Get full language name from code."""
        return self.LANGUAGE_NAMES.get(code, code)

    async def initialize(self) -> bool:
        """
        Initialize Ollama client and verify connection.

        Returns:
            True if Ollama is available and model exists
        """
        logger.info(f"Initializing Ollama LLM: {self.model_name} at {self.base_url}")

        try:
            self._client = httpx.AsyncClient(timeout=self.timeout)

            # Check if Ollama is running
            response = await self._client.get(f"{self.base_url}/api/tags")
            if response.status_code != 200:
                logger.error(f"Ollama server returned {response.status_code}")
                return False

            # Parse available models
            data = response.json()
            self._available_models = [m.get("name", "") for m in data.get("models", [])]

            # Check if requested model is available
            model_available = any(
                self.model_name in model_name
                for model_name in self._available_models
            )

            if not model_available:
                logger.warning(
                    f"Model {self.model_name} not found. "
                    f"Available: {self._available_models}. "
                    f"Will attempt to use anyway (Ollama may pull it)."
                )

            self._initialized = True
            logger.info(f"Ollama LLM initialized successfully: {self.model_name}")
            return True

        except httpx.ConnectError:
            logger.error(f"Cannot connect to Ollama at {self.base_url}. Is Ollama running?")
            return False
        except Exception as e:
            logger.error(f"Failed to initialize Ollama: {e}")
            return False

    async def _generate(self, prompt: str, system: Optional[str] = None) -> str:
        """
        Call Ollama generate API.

        Args:
            prompt: User prompt
            system: Optional system prompt

        Returns:
            Generated text response
        """
        if not self._client:
            raise RuntimeError("Ollama client not initialized")

        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.7,
                "top_p": 0.9,
            }
        }

        if system:
            payload["system"] = system

        try:
            response = await self._client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout
            )

            if response.status_code != 200:
                logger.error(f"Ollama API error: {response.status_code} - {response.text}")
                raise RuntimeError(f"Ollama API error: {response.status_code}")

            data = response.json()
            return data.get("response", "")

        except httpx.TimeoutException:
            logger.error(f"Ollama request timed out after {self.timeout}s")
            raise
        except Exception as e:
            logger.error(f"Ollama generate error: {e}")
            raise

    def _parse_confidence(self, text: str) -> float:
        """Extract confidence score from LLM response."""
        import re

        # Look for patterns like "confidence: 0.85" or "confidence score: 85%"
        patterns = [
            r"confidence[:\s]+(\d+\.?\d*)%?",
            r"(\d+\.?\d*)\s*(?:out of 1|/1)",
            r"score[:\s]+(\d+\.?\d*)%?",
        ]

        for pattern in patterns:
            match = re.search(pattern, text.lower())
            if match:
                value = float(match.group(1))
                # Convert percentage to decimal if needed
                if value > 1:
                    value = value / 100
                return min(max(value, 0.0), 1.0)

        # Default confidence if not found
        return 0.75

    def _extract_translation(self, text: str) -> str:
        """Extract translation from LLM response."""
        import re

        # Look for patterns like "Translation:" or numbered items
        patterns = [
            r"(?:translation|traduzione)[:\s]*[\"']?([^\"'\n]+)[\"']?",
            r"(?:1\.|•)\s*[\"']?([^\"'\n]+)[\"']?",
            r"^[\"']([^\"']+)[\"']$",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()

        # If no pattern matches, return first non-empty line
        for line in text.split("\n"):
            line = line.strip()
            if line and not line.startswith(("#", "-", "*", "•")):
                return line

        return text.strip()

    async def generate_translation(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationCandidate:
        """
        Generate translation using Ollama.
        """
        logger.info(f"Generating translation with {self.model_name}: {source_lang} -> {target_lang}")

        source_name = self._get_language_name(source_lang)
        target_name = self._get_language_name(target_lang)

        context_str = ""
        if context:
            context_str = f"\nContext: {json.dumps(context, ensure_ascii=False)}"

        system_prompt = """You are an expert translator specializing in martial arts content.
You have deep knowledge of martial arts terminology in multiple languages.
Always preserve the technical accuracy of martial arts terms."""

        user_prompt = f"""Translate the following text from {source_name} to {target_name}.
{context_str}

Text to translate:
{text}

Respond in this exact format:
Translation: [your translation here]
Confidence: [0.0-1.0]
Reasoning: [brief explanation of translation choices]"""

        try:
            response = await self._generate(user_prompt, system_prompt)
            translation = self._extract_translation(response)
            confidence = self._parse_confidence(response)

            return TranslationCandidate(
                text=translation,
                source_text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                confidence=confidence,
                provider=f"ollama/{self.model_name}",
                arguments_for=[response]
            )

        except Exception as e:
            logger.error(f"Translation generation failed: {e}")
            # Return fallback with low confidence
            return TranslationCandidate(
                text=f"[ERROR] {text}",
                source_text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                confidence=0.0,
                provider=f"ollama/{self.model_name}",
                arguments_against=[str(e)]
            )

    async def critique_translation(
        self,
        original: str,
        translation: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None
    ) -> DebateArgument:
        """
        Critique a translation using Ollama.
        """
        logger.info(f"Critiquing translation with {self.model_name}")

        source_name = self._get_language_name(source_lang)
        target_name = self._get_language_name(target_lang)

        system_prompt = """You are a strict translation critic specializing in martial arts terminology.
Your job is to find issues, inaccuracies, and areas for improvement in translations.
Be thorough but fair in your critique."""

        user_prompt = f"""Review this translation critically:

Original ({source_name}): {original}
Translation ({target_name}): {translation}

Evaluate:
1. Accuracy - Does it convey the same meaning?
2. Terminology - Are martial arts terms translated correctly?
3. Naturalness - Does it sound natural in {target_name}?
4. Issues - List any specific problems found

Respond in this format:
Critique: [your detailed critique]
Issues: [list specific issues, or "None found"]
Confidence: [0.0-1.0 in your critique]"""

        try:
            response = await self._generate(user_prompt, system_prompt)
            confidence = self._parse_confidence(response)

            return DebateArgument(
                role=self.role,
                phase=DebatePhase.CRITIQUE,
                content=response,
                confidence=confidence,
                reasoning=f"Critique by {self.model_name}"
            )

        except Exception as e:
            logger.error(f"Critique failed: {e}")
            return DebateArgument(
                role=self.role,
                phase=DebatePhase.CRITIQUE,
                content=f"[ERROR] Failed to critique: {e}",
                confidence=0.0,
                reasoning=str(e)
            )

    async def defend_translation(
        self,
        original: str,
        translation: str,
        critique: DebateArgument,
        context: Optional[Dict[str, Any]] = None
    ) -> DebateArgument:
        """
        Defend translation against critique using Ollama.
        """
        logger.info(f"Defending translation with {self.model_name}")

        system_prompt = """You are defending a translation you created.
Address the critique points fairly - accept valid criticisms but defend correct choices.
Be constructive and suggest improvements where appropriate."""

        user_prompt = f"""Your translation is being critiqued. Respond to defend or accept the critique:

Original text: {original}
Your translation: {translation}

Critique received:
{critique.content}

Respond in this format:
Defense: [your response to the critique]
Accepted issues: [list any valid points you accept]
Defended choices: [explain choices you stand by]
Confidence: [0.0-1.0 in your defense]"""

        try:
            response = await self._generate(user_prompt, system_prompt)
            confidence = self._parse_confidence(response)

            return DebateArgument(
                role=self.role,
                phase=DebatePhase.DEFENSE,
                content=response,
                confidence=confidence,
                reasoning=f"Defense by {self.model_name}"
            )

        except Exception as e:
            logger.error(f"Defense failed: {e}")
            return DebateArgument(
                role=self.role,
                phase=DebatePhase.DEFENSE,
                content=f"[ERROR] Failed to defend: {e}",
                confidence=0.0,
                reasoning=str(e)
            )

    async def refine_translation(
        self,
        original: str,
        translation: str,
        arguments: List[DebateArgument],
        context: Optional[Dict[str, Any]] = None
    ) -> TranslationCandidate:
        """
        Refine translation based on debate arguments using Ollama.
        """
        logger.info(f"Refining translation with {self.model_name}")

        # Build argument summary
        argument_summary = "\n".join([
            f"- [{arg.role.value.upper()}] {arg.phase.value}: {arg.content[:500]}"
            for arg in arguments
        ])

        system_prompt = """You are refining a translation based on debate feedback.
Incorporate valid criticisms while preserving correct choices.
Produce the best possible translation considering all feedback."""

        user_prompt = f"""Refine this translation based on the debate:

Original text: {original}
Current translation: {translation}

Debate arguments:
{argument_summary}

Produce an improved translation that addresses valid critiques.

Respond in this format:
Refined translation: [your improved translation]
Changes made: [list what you changed and why]
Confidence: [0.0-1.0]"""

        try:
            response = await self._generate(user_prompt, system_prompt)
            refined_text = self._extract_translation(response)
            confidence = self._parse_confidence(response)

            return TranslationCandidate(
                text=refined_text,
                source_text=original,
                source_lang="",  # Will be filled by caller
                target_lang="",
                confidence=confidence,
                provider=f"ollama/{self.model_name}",
                refinements=[f"Refined based on {len(arguments)} arguments"]
            )

        except Exception as e:
            logger.error(f"Refinement failed: {e}")
            return TranslationCandidate(
                text=translation,  # Return original if refinement fails
                source_text=original,
                source_lang="",
                target_lang="",
                confidence=0.5,
                provider=f"ollama/{self.model_name}",
                arguments_against=[str(e)]
            )

    async def close(self):
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None


# ==============================================================================
# TRANSLATION DEBATE SYSTEM
# ==============================================================================

class TranslationDebateSystem:
    """
    Multi-LLM translation debate system.

    Uses two or more LLMs to debate and refine translations through
    structured argumentation rounds to achieve higher quality.

    Architecture:
    1. Primary LLM generates initial translation
    2. Critic LLM reviews and critiques
    3. Primary defends or accepts critique
    4. Refinement based on debate
    5. Repeat until consensus or max rounds
    """

    def __init__(self, config: Optional[DebateConfig] = None):
        self.config = config or DebateConfig()
        self._primary: Optional[DebateLLM] = None
        self._critic: Optional[DebateLLM] = None
        self._arbiter: Optional[DebateLLM] = None
        self._initialized = False

    async def initialize(
        self,
        primary_model: str = "llama3.2",
        critic_model: str = "mistral",
        arbiter_model: Optional[str] = None
    ) -> bool:
        """
        Initialize the debate system with LLMs.

        Args:
            primary_model: Model for primary translator
            critic_model: Model for critic
            arbiter_model: Optional model for final arbitration
        """
        logger.info("Initializing Translation Debate System")

        # Initialize primary LLM
        self._primary = OllamaDebateLLM(
            role=DebateRole.PRIMARY,
            model_name=primary_model
        )
        await self._primary.initialize()

        # Initialize critic LLM
        self._critic = OllamaDebateLLM(
            role=DebateRole.CRITIC,
            model_name=critic_model
        )
        await self._critic.initialize()

        # Optional arbiter
        if arbiter_model and self.config.enable_arbiter:
            self._arbiter = OllamaDebateLLM(
                role=DebateRole.ARBITER,
                model_name=arbiter_model
            )
            await self._arbiter.initialize()

        self._initialized = True
        return True

    async def debate_translation(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        context: Optional[Dict[str, Any]] = None,
        debate_rounds: int = 2
    ) -> DebateResult:
        """
        Perform translation through multi-LLM debate.

        Args:
            text: Text to translate
            source_lang: Source language code
            target_lang: Target language code
            context: Optional context (glossary, style, etc.)
            debate_rounds: Number of debate rounds (default 2)

        Returns:
            DebateResult with final translation and debate history
        """
        start_time = datetime.now()
        debate_history: List[DebateArgument] = []
        candidates: List[TranslationCandidate] = []

        # Use provided rounds or config default
        max_rounds = min(debate_rounds, self.config.max_rounds)

        logger.info(f"Starting translation debate: {source_lang} -> {target_lang}")
        logger.info(f"Max rounds: {max_rounds}")

        try:
            # Phase 1: Initial translation from primary
            logger.info("Phase 1: Initial Translation")
            initial_translation = await self._primary.generate_translation(
                text=text,
                source_lang=source_lang,
                target_lang=target_lang,
                context=context
            )
            candidates.append(initial_translation)

            debate_history.append(DebateArgument(
                role=DebateRole.PRIMARY,
                phase=DebatePhase.INITIAL_TRANSLATION,
                content=initial_translation.text,
                confidence=initial_translation.confidence,
                reasoning="Initial translation generated"
            ))

            current_translation = initial_translation

            # Debate rounds
            for round_num in range(max_rounds):
                logger.info(f"Debate Round {round_num + 1}/{max_rounds}")

                # Phase 2: Critique from critic
                critique = await self._critic.critique_translation(
                    original=text,
                    translation=current_translation.text,
                    source_lang=source_lang,
                    target_lang=target_lang,
                    context=context
                )
                debate_history.append(critique)

                # Check if high confidence - early consensus
                if critique.confidence >= self.config.consensus_threshold:
                    logger.info("High confidence critique - early consensus")
                    break

                # Phase 3: Defense from primary
                defense = await self._primary.defend_translation(
                    original=text,
                    translation=current_translation.text,
                    critique=critique,
                    context=context
                )
                debate_history.append(defense)

                # Phase 4: Refinement
                refined = await self._primary.refine_translation(
                    original=text,
                    translation=current_translation.text,
                    arguments=[critique, defense],
                    context=context
                )
                candidates.append(refined)

                debate_history.append(DebateArgument(
                    role=DebateRole.PRIMARY,
                    phase=DebatePhase.REFINEMENT,
                    content=refined.text,
                    confidence=refined.confidence,
                    reasoning=f"Refinement after round {round_num + 1}"
                ))

                current_translation = refined

                # Check for consensus
                if refined.confidence >= self.config.min_confidence_threshold:
                    logger.info(f"Confidence threshold met at round {round_num + 1}")
                    break

            # Calculate final result
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000

            # Determine best translation
            best_candidate = max(candidates, key=lambda c: c.confidence)
            consensus_reached = best_candidate.confidence >= self.config.consensus_threshold

            return DebateResult(
                final_translation=best_candidate.text,
                confidence=best_candidate.confidence,
                consensus_reached=consensus_reached,
                rounds_completed=min(round_num + 1, max_rounds),
                debate_history=debate_history,
                candidates=candidates,
                duration_ms=duration_ms,
                winner_role=DebateRole.PRIMARY if consensus_reached else None,
                metadata={
                    "source_lang": source_lang,
                    "target_lang": target_lang,
                    "primary_model": self._primary.model_name if self._primary else None,
                    "critic_model": self._critic.model_name if self._critic else None
                }
            )

        except asyncio.TimeoutError:
            logger.error("Debate timed out")
            duration_ms = (datetime.now() - start_time).total_seconds() * 1000

            # Return best available
            if candidates:
                best = max(candidates, key=lambda c: c.confidence)
                return DebateResult(
                    final_translation=best.text,
                    confidence=best.confidence * 0.9,  # Penalize for timeout
                    consensus_reached=False,
                    rounds_completed=len(candidates),
                    debate_history=debate_history,
                    candidates=candidates,
                    duration_ms=duration_ms,
                    metadata={"error": "timeout"}
                )
            else:
                return DebateResult(
                    final_translation="",
                    confidence=0.0,
                    consensus_reached=False,
                    rounds_completed=0,
                    debate_history=[],
                    candidates=[],
                    duration_ms=duration_ms,
                    metadata={"error": "timeout_no_candidates"}
                )

        except Exception as e:
            logger.error(f"Debate error: {e}")
            raise

    def get_debate_summary(self, result: DebateResult) -> str:
        """Generate human-readable debate summary"""
        summary_lines = [
            "=" * 60,
            "TRANSLATION DEBATE SUMMARY",
            "=" * 60,
            f"Consensus Reached: {'Yes' if result.consensus_reached else 'No'}",
            f"Rounds Completed: {result.rounds_completed}",
            f"Final Confidence: {result.confidence:.2%}",
            f"Duration: {result.duration_ms:.0f}ms",
            "",
            "Final Translation:",
            f"  {result.final_translation}",
            "",
            "Debate History:",
        ]

        for i, arg in enumerate(result.debate_history):
            summary_lines.append(
                f"  {i+1}. [{arg.role.value}] {arg.phase.value}: "
                f"{arg.content[:50]}... (conf: {arg.confidence:.2%})"
            )

        summary_lines.append("=" * 60)

        return "\n".join(summary_lines)


# ==============================================================================
# FACTORY FUNCTION
# ==============================================================================

async def create_debate_system(
    primary_model: str = "llama3.2",
    critic_model: str = "mistral",
    config: Optional[DebateConfig] = None
) -> TranslationDebateSystem:
    """
    Factory function to create and initialize a debate system.

    Args:
        primary_model: Ollama model for primary translator
        critic_model: Ollama model for critic
        config: Optional debate configuration

    Returns:
        Initialized TranslationDebateSystem
    """
    system = TranslationDebateSystem(config=config)
    await system.initialize(
        primary_model=primary_model,
        critic_model=critic_model
    )
    return system


# ==============================================================================
# EXAMPLE USAGE
# ==============================================================================

async def _example_usage():
    """Example usage of the debate system"""

    # Create system
    config = DebateConfig(
        max_rounds=3,
        min_confidence_threshold=0.85,
        consensus_threshold=0.90
    )

    system = await create_debate_system(
        primary_model="llama3.2",
        critic_model="mistral",
        config=config
    )

    # Perform debate translation
    result = await system.debate_translation(
        text="Seiken-zuki wa karate no kihon waza desu.",
        source_lang="ja",
        target_lang="it",
        context={"genre": "martial_arts", "style": "karate"},
        debate_rounds=2
    )

    # Print summary
    print(system.get_debate_summary(result))

    return result


if __name__ == "__main__":
    asyncio.run(_example_usage())

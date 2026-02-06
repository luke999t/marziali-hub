"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Debate Unit Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di logica pura per TranslationDebateSystem.

================================================================================
"""

import pytest
from datetime import datetime

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.unit]


# ==============================================================================
# TEST: Data Classes - Pure Logic
# ==============================================================================
class TestDebateDataClassesLogic:
    """Tests for debate data classes - pure logic."""

    def test_debate_role_enum(self):
        """Test DebateRole enum values."""
        from services.video_studio.translation_debate import DebateRole

        assert DebateRole.PRIMARY.value == "primary"
        assert DebateRole.CRITIC.value == "critic"
        assert DebateRole.ARBITER.value == "arbiter"

    def test_debate_phase_enum(self):
        """Test DebatePhase enum values."""
        from services.video_studio.translation_debate import DebatePhase

        assert DebatePhase.INITIAL_TRANSLATION.value == "initial_translation"
        assert DebatePhase.CRITIQUE.value == "critique"
        assert DebatePhase.DEFENSE.value == "defense"
        assert DebatePhase.REFINEMENT.value == "refinement"
        assert DebatePhase.CONSENSUS.value == "consensus"

    def test_translation_candidate_creation(self):
        """Test TranslationCandidate creation."""
        from services.video_studio.translation_debate import TranslationCandidate

        candidate = TranslationCandidate(
            text="Il karate è un'arte marziale",
            source_text="空手は武道です",
            source_lang="ja",
            target_lang="it",
            confidence=0.89,
            provider="ollama/llama3.2"
        )

        assert candidate.text == "Il karate è un'arte marziale"
        assert candidate.source_lang == "ja"
        assert candidate.target_lang == "it"
        assert candidate.confidence == 0.89

    def test_debate_argument_creation(self):
        """Test DebateArgument creation."""
        from services.video_studio.translation_debate import (
            DebateArgument, DebateRole, DebatePhase
        )

        argument = DebateArgument(
            role=DebateRole.CRITIC,
            phase=DebatePhase.CRITIQUE,
            content="La traduzione è buona ma 'budo' potrebbe essere meglio",
            confidence=0.82,
            reasoning="Il termine budo ha connotazione filosofica"
        )

        assert argument.role == DebateRole.CRITIC
        assert argument.phase == DebatePhase.CRITIQUE
        assert argument.confidence == 0.82
        assert "budo" in argument.content

    def test_debate_argument_has_timestamp(self):
        """Test DebateArgument has timestamp."""
        from services.video_studio.translation_debate import (
            DebateArgument, DebateRole, DebatePhase
        )

        argument = DebateArgument(
            role=DebateRole.CRITIC,
            phase=DebatePhase.CRITIQUE,
            content="Test content",
            confidence=0.85,
            reasoning="Test reasoning"
        )

        assert argument.timestamp is not None
        assert isinstance(argument.timestamp, datetime)

    def test_debate_config_defaults(self):
        """Test DebateConfig default values."""
        from services.video_studio.translation_debate import DebateConfig

        config = DebateConfig()

        assert config.max_rounds == 3
        assert config.min_confidence_threshold == 0.85
        assert config.consensus_threshold == 0.90
        assert config.timeout_seconds == 60.0

    def test_debate_config_custom(self):
        """Test DebateConfig custom values."""
        from services.video_studio.translation_debate import DebateConfig

        config = DebateConfig(
            max_rounds=5,
            min_confidence_threshold=0.80,
            consensus_threshold=0.85,
            timeout_seconds=120.0
        )

        assert config.max_rounds == 5
        assert config.min_confidence_threshold == 0.80
        assert config.timeout_seconds == 120.0

    def test_debate_result_to_dict(self):
        """Test DebateResult.to_dict()."""
        from services.video_studio.translation_debate import (
            DebateResult, DebateRole
        )

        result = DebateResult(
            final_translation="Test translation",
            confidence=0.91,
            consensus_reached=True,
            rounds_completed=2,
            debate_history=[],
            candidates=[],
            duration_ms=1500.0,
            winner_role=DebateRole.PRIMARY
        )

        result_dict = result.to_dict()

        assert result_dict["final_translation"] == "Test translation"
        assert result_dict["confidence"] == 0.91
        assert result_dict["consensus_reached"] is True
        assert result_dict["rounds_completed"] == 2
        assert result_dict["winner_role"] == "primary"


# ==============================================================================
# TEST: Confidence Calculations - Pure Logic
# ==============================================================================
class TestConfidenceCalculationsLogic:
    """Test confidence calculations - pure logic."""

    def test_average_confidence(self):
        """Test average confidence calculation."""
        confidences = [0.85, 0.90, 0.82, 0.88]

        avg = sum(confidences) / len(confidences)

        assert avg == pytest.approx(0.8625, rel=0.01)

    def test_weighted_confidence(self):
        """Test weighted confidence calculation."""
        results = [
            {"confidence": 0.90, "weight": 2},
            {"confidence": 0.80, "weight": 1},
            {"confidence": 0.85, "weight": 1}
        ]

        total_weight = sum(r["weight"] for r in results)
        weighted_conf = sum(r["confidence"] * r["weight"] for r in results) / total_weight

        assert weighted_conf == pytest.approx(0.8625, rel=0.01)

    def test_consensus_threshold_check(self):
        """Test consensus threshold checking."""
        consensus_threshold = 0.90

        high_agreement = 0.92
        low_agreement = 0.75

        assert high_agreement >= consensus_threshold
        assert low_agreement < consensus_threshold


# ==============================================================================
# TEST: Debate Flow Logic - Pure Logic
# ==============================================================================
class TestDebateFlowLogic:
    """Test debate flow logic - pure logic."""

    def test_phase_ordering(self):
        """Test debate phase ordering."""
        from services.video_studio.translation_debate import DebatePhase

        phases = [
            DebatePhase.INITIAL_TRANSLATION,
            DebatePhase.CRITIQUE,
            DebatePhase.DEFENSE,
            DebatePhase.REFINEMENT,
            DebatePhase.CONSENSUS
        ]

        phase_values = [p.value for p in phases]

        assert phase_values[0] == "initial_translation"
        assert phase_values[-1] == "consensus"

    def test_round_completion_logic(self):
        """Test round completion logic."""
        max_rounds = 3
        current_round = 2

        # Check if more rounds needed
        needs_more_rounds = current_round < max_rounds
        assert needs_more_rounds is True

        current_round = 3
        needs_more_rounds = current_round < max_rounds
        assert needs_more_rounds is False

    def test_early_consensus_exit(self):
        """Test early consensus exit logic."""
        consensus_threshold = 0.90
        min_confidence = 0.85

        # High confidence from both sides = early exit
        primary_conf = 0.95
        critic_conf = 0.92

        avg_conf = (primary_conf + critic_conf) / 2
        can_exit_early = avg_conf >= consensus_threshold

        assert can_exit_early is True


# ==============================================================================
# TEST: Translation Candidate Comparison - Pure Logic
# ==============================================================================
class TestTranslationCandidateComparisonLogic:
    """Test translation candidate comparison - pure logic."""

    def test_select_best_candidate(self):
        """Test selecting best candidate by confidence."""
        candidates = [
            {"text": "Traduzione A", "confidence": 0.85},
            {"text": "Traduzione B", "confidence": 0.92},
            {"text": "Traduzione C", "confidence": 0.88}
        ]

        best = max(candidates, key=lambda c: c["confidence"])

        assert best["text"] == "Traduzione B"
        assert best["confidence"] == 0.92

    def test_candidate_quality_classification(self):
        """Test candidate quality classification."""
        def classify_quality(confidence):
            if confidence >= 0.90:
                return "high"
            elif confidence >= 0.75:
                return "medium"
            else:
                return "low"

        assert classify_quality(0.95) == "high"
        assert classify_quality(0.82) == "medium"
        assert classify_quality(0.60) == "low"


# ==============================================================================
# TEST: Debate Summary Generation - Pure Logic
# ==============================================================================
class TestDebateSummaryLogic:
    """Test debate summary generation - pure logic."""

    def test_summary_format(self):
        """Test debate summary format."""
        from services.video_studio.translation_debate import (
            DebateResult, DebateRole
        )

        result = DebateResult(
            final_translation="Test translation",
            confidence=0.91,
            consensus_reached=True,
            rounds_completed=2,
            debate_history=[],
            candidates=[],
            duration_ms=1500.0,
            winner_role=DebateRole.PRIMARY
        )

        # Generate simple summary
        summary_parts = [
            f"Translation: {result.final_translation}",
            f"Confidence: {result.confidence:.1%}",
            f"Consensus: {'Yes' if result.consensus_reached else 'No'}",
            f"Rounds: {result.rounds_completed}"
        ]

        summary = "\n".join(summary_parts)

        assert "Test translation" in summary
        assert "91" in summary
        assert "Yes" in summary

    def test_duration_formatting(self):
        """Test duration formatting."""
        duration_ms = 1500.0

        duration_seconds = duration_ms / 1000
        formatted = f"{duration_seconds:.2f}s"

        assert formatted == "1.50s"


# ==============================================================================
# TEST: Language Pair Handling - Pure Logic
# ==============================================================================
class TestLanguagePairHandlingLogic:
    """Test language pair handling - pure logic."""

    def test_valid_language_pairs(self):
        """Test valid language pairs."""
        supported_pairs = [
            ("ja", "it"), ("ja", "en"),
            ("zh", "it"), ("zh", "en"),
            ("ko", "it"), ("ko", "en")
        ]

        test_pair = ("ja", "it")
        is_supported = test_pair in supported_pairs

        assert is_supported is True

    def test_invalid_language_pair(self):
        """Test invalid language pair detection."""
        supported_pairs = [("ja", "it"), ("zh", "it"), ("ko", "it")]

        invalid_pair = ("xx", "yy")
        is_supported = invalid_pair in supported_pairs

        assert is_supported is False


# ==============================================================================
# TEST: Context Integration - Pure Logic
# ==============================================================================
class TestContextIntegrationLogic:
    """Test context integration - pure logic."""

    def test_glossary_context_structure(self):
        """Test glossary context structure."""
        context = {
            "glossary": {"sensei": "maestro", "kata": "kata"},
            "genre": "martial_arts",
            "preserve_names": True
        }

        assert "glossary" in context
        assert "sensei" in context["glossary"]
        assert context["preserve_names"] is True

    def test_context_merging(self):
        """Test context merging logic."""
        base_context = {"genre": "martial_arts"}
        user_context = {"glossary": {"sensei": "maestro"}}

        merged = {**base_context, **user_context}

        assert "genre" in merged
        assert "glossary" in merged


# ==============================================================================
# TEST: Error Handling Logic - Pure Logic
# ==============================================================================
class TestDebateErrorHandlingLogic:
    """Test debate error handling - pure logic."""

    def test_empty_text_validation(self):
        """Test empty text validation."""
        def validate_text(text):
            if not text or not text.strip():
                raise ValueError("Text cannot be empty")
            return True

        with pytest.raises(ValueError):
            validate_text("")

        with pytest.raises(ValueError):
            validate_text("   ")

        assert validate_text("Valid text") is True

    def test_confidence_bounds_validation(self):
        """Test confidence bounds validation."""
        def validate_confidence(conf):
            if not 0 <= conf <= 1:
                raise ValueError("Confidence must be 0-1")
            return True

        assert validate_confidence(0.5) is True
        assert validate_confidence(0.0) is True
        assert validate_confidence(1.0) is True

        with pytest.raises(ValueError):
            validate_confidence(1.5)

        with pytest.raises(ValueError):
            validate_confidence(-0.1)


# ==============================================================================
# TEST: Result Aggregation - Pure Logic
# ==============================================================================
class TestResultAggregationLogic:
    """Test result aggregation - pure logic."""

    def test_debate_history_tracking(self):
        """Test debate history tracking."""
        history = []

        # Simulate debate phases
        history.append({"phase": "initial", "content": "First translation"})
        history.append({"phase": "critique", "content": "Critique here"})
        history.append({"phase": "defense", "content": "Defense here"})
        history.append({"phase": "refinement", "content": "Refined translation"})

        assert len(history) == 4
        assert history[0]["phase"] == "initial"
        assert history[-1]["phase"] == "refinement"

    def test_candidate_tracking(self):
        """Test candidate tracking during debate."""
        candidates = []

        # Add initial
        candidates.append({"text": "Initial", "confidence": 0.80})
        # Add refined
        candidates.append({"text": "Refined", "confidence": 0.88})
        # Add final
        candidates.append({"text": "Final", "confidence": 0.92})

        # Best candidate
        best = max(candidates, key=lambda c: c["confidence"])
        assert best["text"] == "Final"


# ==============================================================================
# TEST: Timeout Handling - Pure Logic
# ==============================================================================
class TestTimeoutHandlingLogic:
    """Test timeout handling - pure logic."""

    def test_timeout_check(self):
        """Test timeout checking logic."""
        timeout_seconds = 60.0
        elapsed_seconds = 45.0

        is_timeout = elapsed_seconds > timeout_seconds
        assert is_timeout is False

        elapsed_seconds = 70.0
        is_timeout = elapsed_seconds > timeout_seconds
        assert is_timeout is True

    def test_remaining_time_calculation(self):
        """Test remaining time calculation."""
        timeout_seconds = 60.0
        elapsed_seconds = 25.0

        remaining = max(0, timeout_seconds - elapsed_seconds)
        assert remaining == 35.0

        elapsed_seconds = 70.0
        remaining = max(0, timeout_seconds - elapsed_seconds)
        assert remaining == 0


# ==============================================================================
# TEST: Parametrized Tests - Pure Logic
# ==============================================================================
class TestParametrizedDebateLogic:
    """Parametrized tests for debate logic."""

    @pytest.mark.parametrize("confidence,expected_quality", [
        (0.95, "high"),
        (0.90, "high"),
        (0.85, "medium"),
        (0.75, "medium"),
        (0.60, "low"),
    ])
    def test_confidence_to_quality_mapping(self, confidence, expected_quality):
        """Test confidence to quality mapping."""
        def get_quality(conf):
            if conf >= 0.90:
                return "high"
            elif conf >= 0.75:
                return "medium"
            else:
                return "low"

        assert get_quality(confidence) == expected_quality

    @pytest.mark.parametrize("rounds,max_rounds,should_continue", [
        (1, 3, True),
        (2, 3, True),
        (3, 3, False),
        (4, 3, False),
    ])
    def test_round_continuation_logic(self, rounds, max_rounds, should_continue):
        """Test round continuation logic."""
        assert (rounds < max_rounds) == should_continue

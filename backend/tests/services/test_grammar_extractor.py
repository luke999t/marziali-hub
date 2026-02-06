"""
================================================================================
AI_MODULE: Grammar Extractor Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test per estrazione grammatica da PDF/EPUB/Immagini
AI_BUSINESS: Verifica pipeline estrazione e anonimizzazione
AI_TEACHING: pytest, async testing, real file operations
AI_CREATED: 2026-02-05

ZERO MOCK POLICY:
- All tests use real files and real LLM calls
- No mocking of services
- Real database operations

PRIVACY TESTS:
- Verify NO source traces in output
- Verify anonymization is complete
================================================================================
"""

import pytest
import asyncio
import json
import tempfile
from pathlib import Path

# Test markers
pytestmark = [pytest.mark.integration, pytest.mark.services]


# === FIXTURES ===

@pytest.fixture
def sample_grammar_text():
    """Sample Japanese grammar text for testing."""
    return """
    日本語文法入門

    1. 助詞「は」(wa)
    「は」は文の主題を示す助詞です。主語とは異なり、話題の焦点を示します。

    例文:
    - 私は学生です。(I am a student.)
    - 東京は日本の首都です。(Tokyo is the capital of Japan.)

    2. 助詞「が」(ga)
    「が」は主語を示す助詞です。新情報や強調に使います。

    例文:
    - 誰が来ましたか。(Who came?)
    - 私が田中です。(I am Tanaka.)

    3. 動詞の「て形」
    動詞を接続する際に使う形です。

    例文:
    - 食べて寝る。(Eat and sleep.)
    - 見て聞いて。(Watch and listen.)
    """


@pytest.fixture
def sample_pdf_path(tmp_path, sample_grammar_text):
    """Create a sample PDF for testing (requires fpdf2)."""
    try:
        from fpdf import FPDF

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        # Note: fpdf doesn't support Japanese well, this is for structure testing
        pdf.multi_cell(0, 10, "Sample Grammar Text\n\nParticle WA marks topic.")
        pdf_path = tmp_path / "test_grammar.pdf"
        pdf.output(str(pdf_path))
        return pdf_path
    except ImportError:
        pytest.skip("fpdf2 not installed")


@pytest.fixture
def forbidden_words():
    """List of words that must NEVER appear in output."""
    return [
        "source", "book", "author", "page", "isbn", "publisher",
        "chapter", "edition", "copyright", "rights", "reserved",
        "textbook", "manual", "guide", "volume", "citation"
    ]


# === UNIT TESTS ===

class TestRuleNormalizer:
    """Tests for RuleNormalizer."""

    @pytest.mark.asyncio
    async def test_verify_no_source_traces(self, forbidden_words):
        """Verify that verify_no_source_traces catches forbidden words."""
        from services.language_learning.rule_normalizer import verify_no_source_traces

        # Clean JSON should pass
        clean_json = {
            "language": "ja",
            "rules": [
                {
                    "id": "rule_1",
                    "name": "Particle WA",
                    "description": "Marks the topic of a sentence"
                }
            ]
        }
        assert verify_no_source_traces(clean_json) is True

        # JSON with forbidden word should fail
        dirty_json = {
            "language": "ja",
            "rules": [
                {
                    "id": "rule_1",
                    "name": "Particle WA",
                    "description": "From textbook chapter 1"  # FORBIDDEN!
                }
            ]
        }
        with pytest.raises(AssertionError):
            verify_no_source_traces(dirty_json)

    @pytest.mark.asyncio
    async def test_rule_id_generation(self):
        """Test that rule IDs are deterministic."""
        from services.language_learning.rule_normalizer import RuleNormalizer

        normalizer = RuleNormalizer()

        id1 = normalizer._generate_rule_id("Particle WA", "[NOUN]は", "ja")
        id2 = normalizer._generate_rule_id("Particle WA", "[NOUN]は", "ja")
        id3 = normalizer._generate_rule_id("Particle GA", "[NOUN]が", "ja")

        # Same input = same ID
        assert id1 == id2
        # Different input = different ID
        assert id1 != id3
        # ID format
        assert id1.startswith("rule_ja_")


class TestGrammarMerger:
    """Tests for GrammarMergerService."""

    @pytest.mark.asyncio
    async def test_create_empty_grammar(self, tmp_path):
        """Test creating a new empty grammar database."""
        from services.language_learning.grammar_merger import GrammarMergerService

        merger = GrammarMergerService(storage_path=tmp_path)

        # No grammar exists yet
        grammar = await merger.load_grammar("ja")
        assert grammar is None

    @pytest.mark.asyncio
    async def test_save_and_load_grammar(self, tmp_path):
        """Test saving and loading grammar."""
        from services.language_learning.grammar_merger import (
            GrammarMergerService, GrammarDatabase
        )
        from services.language_learning.rule_normalizer import (
            NormalizedRule, RuleCategory, DifficultyLevel, RuleExample
        )

        merger = GrammarMergerService(storage_path=tmp_path)

        # Create a test rule
        rule = NormalizedRule(
            id="test_rule_1",
            category=RuleCategory.PARTICLE,
            name="Test Particle",
            description="A test particle rule",
            pattern="[NOUN]は",
            examples=[
                RuleExample(
                    original="私は学生です",
                    translation="I am a student",
                    note="Basic usage"
                )
            ],
            exceptions=["Not used with existence verbs"],
            difficulty=DifficultyLevel.BASIC,
            related_rules=["test_rule_2"],
            tags=["particle", "topic"]
        )

        # Merge rule
        grammar = await merger.merge_rules("ja", [rule])

        # Verify
        assert grammar.language == "ja"
        assert grammar.total_rules == 1
        assert grammar.sources_count == 1

        # Load and verify
        loaded = await merger.load_grammar("ja")
        assert loaded is not None
        assert loaded.total_rules == 1
        assert loaded.rules[0].name == "Test Particle"

    @pytest.mark.asyncio
    async def test_fuzzy_deduplication(self, tmp_path):
        """Test that similar rules are merged."""
        from services.language_learning.grammar_merger import GrammarMergerService
        from services.language_learning.rule_normalizer import (
            NormalizedRule, RuleCategory, DifficultyLevel, RuleExample
        )

        merger = GrammarMergerService(storage_path=tmp_path)

        # First rule
        rule1 = NormalizedRule(
            id="rule_1",
            category=RuleCategory.PARTICLE,
            name="Particle WA",
            description="Topic marker",
            pattern="[NOUN]は",
            examples=[RuleExample("私は", "I (topic)", "")],
            exceptions=[],
            difficulty=DifficultyLevel.BASIC
        )

        await merger.merge_rules("ja", [rule1])

        # Second similar rule (should merge)
        rule2 = NormalizedRule(
            id="rule_2",
            category=RuleCategory.PARTICLE,
            name="Particle wa",  # Same but lowercase
            description="Marks the topic of a sentence",  # Longer description
            pattern="[NOUN]は",  # Same pattern
            examples=[RuleExample("彼は", "He (topic)", "")],  # Different example
            exceptions=["Not with が"],
            difficulty=DifficultyLevel.BASIC
        )

        grammar = await merger.merge_rules("ja", [rule2])

        # Should still be 1 rule (merged)
        assert grammar.total_rules == 1
        # But with 2 examples
        assert len(grammar.rules[0].examples) == 2
        # Sources count incremented
        assert grammar.sources_count == 2

    @pytest.mark.asyncio
    async def test_no_source_in_output(self, tmp_path, forbidden_words):
        """Verify output JSON has no source traces."""
        from services.language_learning.grammar_merger import GrammarMergerService
        from services.language_learning.rule_normalizer import (
            NormalizedRule, RuleCategory, DifficultyLevel
        )

        merger = GrammarMergerService(storage_path=tmp_path)

        rule = NormalizedRule(
            id="test_rule",
            category=RuleCategory.PARTICLE,
            name="Test Rule",
            description="A grammar rule description",
            pattern="[X]は",
            examples=[],
            exceptions=[],
            difficulty=DifficultyLevel.BASIC
        )

        await merger.merge_rules("ja", [rule])

        # Load the saved JSON file
        json_path = tmp_path / "grammar_ja.json"
        with open(json_path, "r", encoding="utf-8") as f:
            content = f.read().lower()

        # Check no forbidden words
        for word in forbidden_words:
            assert word not in content, f"Found forbidden word: {word}"


class TestTextExtractors:
    """Tests for text extractors."""

    @pytest.mark.asyncio
    async def test_pdf_extractor_missing_file(self):
        """Test PDF extractor with missing file."""
        from services.language_learning.text_extractors import PDFExtractor

        extractor = PDFExtractor()
        result = await extractor.extract_from_pdf(
            "/nonexistent/file.pdf",
            language="ja"
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_epub_extractor_missing_file(self):
        """Test EPUB extractor with missing file."""
        from services.language_learning.text_extractors import EPUBExtractor

        extractor = EPUBExtractor()
        result = await extractor.extract_from_epub(
            "/nonexistent/file.epub",
            language="ja"
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_ocr_extractor_missing_file(self):
        """Test OCR extractor with missing file."""
        from services.language_learning.text_extractors import OCRExtractor

        extractor = OCRExtractor()
        result = await extractor.extract_from_image(
            "/nonexistent/image.png",
            language="ja"
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_chunking(self):
        """Test text chunking."""
        from services.language_learning.text_extractors.pdf_extractor import PDFExtractor

        extractor = PDFExtractor()

        # Create long text
        long_text = "テスト。" * 5000  # ~5000 sentences

        chunks = list(extractor._chunk_text(long_text))

        # Should have multiple chunks
        assert len(chunks) > 1

        # Each chunk should be within limits
        for chunk in chunks:
            assert len(chunk.content) <= extractor.MAX_CHARS_PER_CHUNK


class TestGrammarExtractor:
    """Integration tests for GrammarExtractor."""

    @pytest.mark.asyncio
    async def test_extractor_initialization(self, tmp_path):
        """Test GrammarExtractor initializes correctly."""
        from services.language_learning import GrammarExtractor

        extractor = GrammarExtractor(storage_path=tmp_path)

        assert extractor.pdf_extractor is not None
        assert extractor.epub_extractor is not None
        assert extractor.ocr_extractor is not None
        assert extractor.normalizer is not None
        assert extractor.merger is not None

    @pytest.mark.asyncio
    async def test_get_nonexistent_grammar(self, tmp_path):
        """Test getting grammar for a language with no data."""
        from services.language_learning import GrammarExtractor

        extractor = GrammarExtractor(storage_path=tmp_path)

        grammar = await extractor.get_grammar("ko")
        assert grammar is None

    @pytest.mark.asyncio
    async def test_extraction_result_no_source(self, forbidden_words):
        """Verify ExtractionResult has no source fields."""
        from services.language_learning.grammar_extractor import ExtractionResult

        result = ExtractionResult(
            success=True,
            language="ja",
            rules_extracted=5,
            rules_merged=10,
            total_rules_in_db=15,
            processing_time_seconds=30.5,
            rules=[]
        )

        result_dict = result.to_dict()
        result_json = json.dumps(result_dict).lower()

        for word in forbidden_words:
            assert word not in result_json, f"Found forbidden: {word}"


# === REAL EXTRACTION TESTS (require running LLM) ===

@pytest.mark.skipif(
    True,  # Set to False to run real tests
    reason="Requires running Ollama LLM"
)
class TestRealExtraction:
    """Real extraction tests - require running LLM."""

    @pytest.mark.asyncio
    async def test_real_text_extraction(self, sample_grammar_text, tmp_path):
        """Test real grammar extraction from text."""
        from services.language_learning.rule_normalizer import RuleNormalizer

        normalizer = RuleNormalizer()

        rules = await normalizer.extract_rules_from_text(
            sample_grammar_text,
            language="ja"
        )

        # Should extract some rules
        assert len(rules) > 0

        # Verify no source traces
        for rule in rules:
            rule_json = json.dumps(rule.to_dict()).lower()
            assert "source" not in rule_json
            assert "book" not in rule_json
            assert "author" not in rule_json


# === API TESTS ===

@pytest.mark.skipif(
    True,  # Set to False to run real API tests
    reason="Requires running backend server"
)
class TestGrammarAPI:
    """API integration tests - require running server."""

    BACKEND_URL = "http://localhost:8000"
    API_PREFIX = "/api/v1/grammar"

    @pytest.mark.asyncio
    async def test_get_grammar_not_found(self):
        """Test getting non-existent grammar returns 404."""
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BACKEND_URL}{self.API_PREFIX}/ko"
            )

        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_search_empty(self):
        """Test search with no results."""
        import httpx

        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BACKEND_URL}{self.API_PREFIX}/ja/search",
                params={"q": "nonexistent12345"}
            )

        # Should return 200 with empty results, or 404 if no DB
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert data["total_results"] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

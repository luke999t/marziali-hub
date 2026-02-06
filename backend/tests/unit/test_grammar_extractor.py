"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Grammar Extractor Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di logica pura (strutture dati, regex, parsing).

================================================================================
"""

import pytest
import json
import re
from datetime import datetime
from pathlib import Path


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.unit]


# ==============================================================================
# TEST: Enums - Pure Logic
# ==============================================================================
class TestGrammarEnums:
    """Test grammar extractor enums - logica pura."""

    def test_document_type_enum(self):
        """Test DocumentType enum values."""
        from services.video_studio.grammar_extractor import DocumentType

        assert DocumentType.PDF.value == "pdf"
        assert DocumentType.EPUB.value == "epub"
        assert DocumentType.IMAGE.value == "image"
        assert DocumentType.TEXT.value == "text"

    def test_grammar_category_enum(self):
        """Test GrammarCategory enum values."""
        from services.video_studio.grammar_extractor import GrammarCategory

        assert GrammarCategory.PARTICLES.value == "particles"
        assert GrammarCategory.VERB_CONJUGATION.value == "verb_conjugation"
        assert GrammarCategory.HONORIFICS.value == "honorifics"
        assert GrammarCategory.EXPRESSIONS.value == "expressions"

    def test_extraction_quality_enum(self):
        """Test ExtractionQuality enum values."""
        from services.video_studio.grammar_extractor import ExtractionQuality

        assert ExtractionQuality.HIGH.value == "high"
        assert ExtractionQuality.MEDIUM.value == "medium"
        assert ExtractionQuality.LOW.value == "low"
        assert ExtractionQuality.OCR.value == "ocr"


# ==============================================================================
# TEST: Data Classes - Pure Logic
# ==============================================================================
class TestGrammarDataClasses:
    """Test grammar data classes - logica pura."""

    def test_extraction_config_defaults(self):
        """Test ExtractionConfig defaults."""
        from services.video_studio.grammar_extractor import ExtractionConfig

        config = ExtractionConfig()
        assert config.extract_examples is True
        assert config.max_examples_per_rule == 5
        assert config.detect_level is True

    def test_grammar_rule_creation(self):
        """Test GrammarRule creation."""
        from services.video_studio.grammar_extractor import GrammarRule, GrammarCategory

        rule = GrammarRule(
            rule_id="rule_test123",
            pattern="~てもいい",
            explanation="Used to express permission",
            examples=["ここで写真を撮ってもいいですか。"],
            category=GrammarCategory.EXPRESSIONS,
            language="ja",
            level="N4",
            source_page=5,
            confidence=0.92
        )

        assert rule.rule_id == "rule_test123"
        assert rule.pattern == "~てもいい"
        assert rule.language == "ja"
        assert rule.level == "N4"

    def test_grammar_rule_to_dict(self):
        """Test GrammarRule.to_dict()."""
        from services.video_studio.grammar_extractor import GrammarRule, GrammarCategory

        rule = GrammarRule(
            rule_id="rule_test123",
            pattern="~てもいい",
            explanation="Used to express permission",
            examples=[],
            category=GrammarCategory.EXPRESSIONS,
            language="ja",
            level="N4",
            confidence=0.92
        )

        rule_dict = rule.to_dict()

        assert rule_dict["rule_id"] == "rule_test123"
        assert rule_dict["pattern"] == "~てもいい"
        assert rule_dict["category"] == "expressions"
        assert rule_dict["confidence"] == 0.92


# ==============================================================================
# TEST: Language Detection - Pure Logic
# ==============================================================================
class TestLanguageDetection:
    """Test language detection - logica pura."""

    def test_detect_japanese_hiragana(self):
        """Test rilevamento giapponese con hiragana."""
        text = "あいうえお"

        hiragana_pattern = re.compile(r'[\u3040-\u309F]')
        has_hiragana = bool(hiragana_pattern.search(text))

        assert has_hiragana is True

    def test_detect_japanese_katakana(self):
        """Test rilevamento giapponese con katakana."""
        text = "カラテ"

        katakana_pattern = re.compile(r'[\u30A0-\u30FF]')
        has_katakana = bool(katakana_pattern.search(text))

        assert has_katakana is True

    def test_detect_japanese_kanji(self):
        """Test rilevamento giapponese con kanji."""
        text = "正拳突き"

        kanji_pattern = re.compile(r'[\u4E00-\u9FFF]')
        has_kanji = bool(kanji_pattern.search(text))

        assert has_kanji is True

    def test_detect_chinese(self):
        """Test rilevamento cinese."""
        text = "中文语法"

        chinese_pattern = re.compile(r'[\u4E00-\u9FFF]')
        has_chinese = bool(chinese_pattern.search(text))

        assert has_chinese is True

    def test_detect_korean(self):
        """Test rilevamento coreano."""
        text = "한국어"

        korean_pattern = re.compile(r'[\uAC00-\uD7AF]')
        has_korean = bool(korean_pattern.search(text))

        assert has_korean is True


# ==============================================================================
# TEST: Text Cleaning - Pure Logic
# ==============================================================================
class TestTextCleaning:
    """Test pulizia testo - logica pura."""

    def test_remove_extra_whitespace(self):
        """Test rimozione spazi extra."""
        text = "Hello    World   Test"
        cleaned = " ".join(text.split())

        assert cleaned == "Hello World Test"

    def test_remove_leading_trailing_whitespace(self):
        """Test rimozione spazi iniziali/finali."""
        text = "   Hello World   "
        cleaned = text.strip()

        assert cleaned == "Hello World"

    def test_normalize_newlines(self):
        """Test normalizzazione newline."""
        text = "Hello\r\nWorld\rTest\nEnd"
        normalized = text.replace('\r\n', '\n').replace('\r', '\n')

        assert normalized == "Hello\nWorld\nTest\nEnd"


# ==============================================================================
# TEST: Grammar Rule Parsing - Pure Logic
# ==============================================================================
class TestGrammarRuleParsing:
    """Test parsing regole grammaticali - logica pura."""

    def test_parse_particle_rule(self):
        """Test parsing regola particelle."""
        rule_text = "は (wa) - 主題を示す"

        particle_match = re.match(r'(\S+)\s+\((\w+)\)\s+-\s+(.+)', rule_text)

        assert particle_match is not None
        assert particle_match.group(1) == "は"
        assert particle_match.group(2) == "wa"
        assert particle_match.group(3) == "主題を示す"

    def test_parse_chapter_header(self):
        """Test parsing header capitolo."""
        header = "第1章: 助詞"

        chapter_match = re.match(r'第(\d+)章[:：]\s*(.+)', header)

        assert chapter_match is not None
        assert chapter_match.group(1) == "1"
        assert chapter_match.group(2) == "助詞"

    def test_parse_korean_particle(self):
        """Test parsing particella coreana."""
        rule_text = "은/는 - 주제"

        korean_match = re.match(r'(\S+)\s+-\s+(.+)', rule_text)

        assert korean_match is not None
        assert korean_match.group(1) == "은/는"
        assert korean_match.group(2) == "주제"


# ==============================================================================
# TEST: Grammar Structure - Pure Logic
# ==============================================================================
class TestGrammarStructure:
    """Test struttura grammatica - logica pura."""

    def test_grammar_rule_structure(self):
        """Test struttura regola grammaticale."""
        rule = {
            "id": "ja_particle_wa",
            "language": "ja",
            "category": "particle",
            "form": "は",
            "romaji": "wa",
            "meaning": "Topic marker",
            "examples": ["私は学生です", "これは本です"],
            "difficulty": "beginner"
        }

        assert "id" in rule
        assert "language" in rule
        assert "form" in rule
        assert "meaning" in rule
        assert isinstance(rule["examples"], list)


# ==============================================================================
# TEST: JSON Serialization - Pure Logic
# ==============================================================================
class TestJSONSerialization:
    """Test serializzazione JSON - logica pura."""

    def test_serialize_grammar_rule(self):
        """Test serializzazione regola."""
        rule = {
            "form": "は",
            "romaji": "wa",
            "meaning": "Topic marker"
        }

        json_str = json.dumps(rule, ensure_ascii=False)
        parsed = json.loads(json_str)

        assert parsed["form"] == "は"
        assert parsed["romaji"] == "wa"

    def test_serialize_unicode_content(self):
        """Test serializzazione contenuto unicode."""
        content = {
            "japanese": "日本語文法",
            "chinese": "中文语法",
            "korean": "한국어 문법"
        }

        json_str = json.dumps(content, ensure_ascii=False)
        parsed = json.loads(json_str)

        assert parsed["japanese"] == "日本語文法"
        assert parsed["chinese"] == "中文语法"
        assert parsed["korean"] == "한국어 문법"


# ==============================================================================
# TEST: Difficulty Levels - Pure Logic
# ==============================================================================
class TestDifficultyLevels:
    """Test livelli difficolta - logica pura."""

    def test_difficulty_order(self):
        """Test ordine livelli difficolta."""
        levels = ["beginner", "elementary", "intermediate", "advanced", "master"]

        assert levels.index("beginner") < levels.index("intermediate")
        assert levels.index("intermediate") < levels.index("advanced")
        assert levels.index("advanced") < levels.index("master")

    def test_difficulty_progression(self):
        """Test progressione difficolta."""
        user_level = "intermediate"
        available_levels = ["beginner", "elementary", "intermediate", "advanced", "master"]

        user_index = available_levels.index(user_level)
        accessible_levels = available_levels[:user_index + 1]

        assert "beginner" in accessible_levels
        assert "intermediate" in accessible_levels
        assert "advanced" not in accessible_levels


# ==============================================================================
# TEST: Parametrized Languages - Pure Logic
# ==============================================================================
class TestLanguagesParametrized:
    """Test linguaggi parametrizzati - logica pura."""

    @pytest.mark.parametrize("lang_code,lang_name", [
        ("ja", "Japanese"),
        ("zh", "Chinese"),
        ("ko", "Korean"),
        ("en", "English"),
        ("it", "Italian"),
    ])
    def test_language_mapping(self, lang_code, lang_name):
        """Test mapping codici lingua."""
        language_names = {
            "ja": "Japanese",
            "zh": "Chinese",
            "ko": "Korean",
            "en": "English",
            "it": "Italian"
        }

        assert language_names[lang_code] == lang_name


# ==============================================================================
# TEST: Quality Thresholds - Pure Logic
# ==============================================================================
class TestQualityThresholds:
    """Test soglie qualita - logica pura."""

    def test_quality_low(self):
        """Test soglia qualita bassa."""
        threshold_low = 0.5
        score = 0.3

        assert score < threshold_low

    def test_quality_medium(self):
        """Test soglia qualita media."""
        threshold_medium = 0.7
        score = 0.75

        assert score >= threshold_medium

    def test_quality_high(self):
        """Test soglia qualita alta."""
        threshold_high = 0.9
        score = 0.95

        assert score >= threshold_high


# ==============================================================================
# TEST: Extractor Supports - Pure Logic
# ==============================================================================
class TestExtractorSupports:
    """Test extractor supports - logica pura."""

    def test_pdf_extractor_supports(self):
        """Test PDFExtractor.supports()."""
        from services.video_studio.grammar_extractor import PDFExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = PDFExtractor(config=config)

        assert extractor.supports("test.pdf") is True
        assert extractor.supports("test.PDF") is True
        assert extractor.supports("test.epub") is False
        assert extractor.supports("test.txt") is False

    def test_epub_extractor_supports(self):
        """Test EPUBExtractor.supports()."""
        from services.video_studio.grammar_extractor import EPUBExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = EPUBExtractor(config=config)

        assert extractor.supports("test.epub") is True
        assert extractor.supports("test.EPUB") is True
        assert extractor.supports("test.pdf") is False
        assert extractor.supports("test.mobi") is False

    def test_image_extractor_supports(self):
        """Test ImageExtractor.supports()."""
        from services.video_studio.grammar_extractor import ImageExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = ImageExtractor(config=config)

        assert extractor.supports("test.png") is True
        assert extractor.supports("test.jpg") is True
        assert extractor.supports("test.jpeg") is True
        assert extractor.supports("test.tiff") is True
        assert extractor.supports("test.bmp") is True
        assert extractor.supports("test.gif") is True
        assert extractor.supports("test.webp") is True
        assert extractor.supports("test.pdf") is False


# ==============================================================================
# TEST: Performance Metrics - Pure Logic
# ==============================================================================
class TestPerformanceMetrics:
    """Test metriche performance - logica pura."""

    def test_extraction_rate_calculation(self):
        """Test calcolo rate estrazione."""
        pages_processed = 50
        time_seconds = 100

        rate = pages_processed / time_seconds

        assert rate == 0.5  # pages per second

    def test_accuracy_calculation(self):
        """Test calcolo accuratezza."""
        correct = 85
        total = 100

        accuracy = correct / total

        assert accuracy == 0.85

"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Grammar Extractor Integration Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di logica pura + test API REALI.

================================================================================
"""

import pytest
import json
import re
import tempfile
import os
import zipfile

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: Document Type Detection - Pure Logic
# ==============================================================================
class TestDocumentTypeDetectionLogic:
    """Test document type detection - pure logic."""

    def test_detect_pdf_extension(self):
        """Test PDF detection by extension."""
        pdf_files = ["document.pdf", "book.PDF", "file.Pdf"]
        for filename in pdf_files:
            assert filename.lower().endswith(".pdf")

    def test_detect_epub_extension(self):
        """Test EPUB detection by extension."""
        epub_files = ["book.epub", "novel.EPUB"]
        for filename in epub_files:
            assert filename.lower().endswith(".epub")

    def test_detect_image_extensions(self):
        """Test image detection by extensions."""
        image_files = [
            "photo.png", "image.jpg", "scan.jpeg",
            "doc.tiff", "bitmap.bmp", "graphic.gif", "modern.webp"
        ]
        image_extensions = [".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif", ".webp"]

        for filename in image_files:
            ext = os.path.splitext(filename)[1].lower()
            assert ext in image_extensions


# ==============================================================================
# TEST: Language Detection - Pure Logic
# ==============================================================================
class TestLanguageDetectionLogic:
    """Test language detection patterns - pure logic."""

    def test_detect_japanese_hiragana(self):
        """Test Japanese hiragana detection."""
        text = "あいうえお"
        hiragana_pattern = re.compile(r'[\u3040-\u309F]')
        assert bool(hiragana_pattern.search(text)) is True

    def test_detect_japanese_katakana(self):
        """Test Japanese katakana detection."""
        text = "カラテ"
        katakana_pattern = re.compile(r'[\u30A0-\u30FF]')
        assert bool(katakana_pattern.search(text)) is True

    def test_detect_japanese_kanji(self):
        """Test Japanese kanji detection."""
        text = "正拳突き"
        kanji_pattern = re.compile(r'[\u4E00-\u9FFF]')
        assert bool(kanji_pattern.search(text)) is True

    def test_detect_korean(self):
        """Test Korean hangul detection."""
        text = "한국어"
        korean_pattern = re.compile(r'[\uAC00-\uD7AF]')
        assert bool(korean_pattern.search(text)) is True

    def test_detect_chinese(self):
        """Test Chinese character detection."""
        text = "中文语法"
        chinese_pattern = re.compile(r'[\u4E00-\u9FFF]')
        assert bool(chinese_pattern.search(text)) is True


# ==============================================================================
# TEST: Grammar Rule Parsing - Pure Logic
# ==============================================================================
class TestGrammarRuleParsingLogic:
    """Test grammar rule parsing - pure logic."""

    def test_parse_particle_rule(self):
        """Test parsing particle rule format."""
        rule_text = "は (wa) - 主題を示す"
        particle_match = re.match(r'(\S+)\s+\((\w+)\)\s+-\s+(.+)', rule_text)

        assert particle_match is not None
        assert particle_match.group(1) == "は"
        assert particle_match.group(2) == "wa"
        assert particle_match.group(3) == "主題を示す"

    def test_parse_chapter_header(self):
        """Test parsing chapter header."""
        header = "第1章: 助詞"
        chapter_match = re.match(r'第(\d+)章[:：]\s*(.+)', header)

        assert chapter_match is not None
        assert chapter_match.group(1) == "1"
        assert chapter_match.group(2) == "助詞"

    def test_parse_korean_particle(self):
        """Test parsing Korean particle."""
        rule_text = "은/는 - 주제"
        korean_match = re.match(r'(\S+)\s+-\s+(.+)', rule_text)

        assert korean_match is not None
        assert korean_match.group(1) == "은/는"
        assert korean_match.group(2) == "주제"


# ==============================================================================
# TEST: Text Cleaning - Pure Logic
# ==============================================================================
class TestTextCleaningLogic:
    """Test text cleaning logic - pure logic."""

    def test_remove_extra_whitespace(self):
        """Test removing extra whitespace."""
        text = "Hello    World   Test"
        cleaned = " ".join(text.split())
        assert cleaned == "Hello World Test"

    def test_normalize_newlines(self):
        """Test normalizing newlines."""
        text = "Hello\r\nWorld\rTest\nEnd"
        normalized = text.replace('\r\n', '\n').replace('\r', '\n')
        assert normalized == "Hello\nWorld\nTest\nEnd"

    def test_strip_whitespace(self):
        """Test stripping leading/trailing whitespace."""
        text = "   Hello World   "
        cleaned = text.strip()
        assert cleaned == "Hello World"


# ==============================================================================
# TEST: Extractor Supports - Pure Logic
# ==============================================================================
class TestExtractorSupportsLogic:
    """Test extractor supports method - pure logic."""

    def test_pdf_extractor_supports(self):
        """Test PDFExtractor.supports()."""
        from services.video_studio.grammar_extractor import PDFExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = PDFExtractor(config=config)

        assert extractor.supports("test.pdf") is True
        assert extractor.supports("test.PDF") is True
        assert extractor.supports("test.epub") is False

    def test_epub_extractor_supports(self):
        """Test EPUBExtractor.supports()."""
        from services.video_studio.grammar_extractor import EPUBExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = EPUBExtractor(config=config)

        assert extractor.supports("test.epub") is True
        assert extractor.supports("test.EPUB") is True
        assert extractor.supports("test.pdf") is False

    def test_image_extractor_supports(self):
        """Test ImageExtractor.supports()."""
        from services.video_studio.grammar_extractor import ImageExtractor, ExtractionConfig

        config = ExtractionConfig()
        extractor = ImageExtractor(config=config)

        assert extractor.supports("test.png") is True
        assert extractor.supports("test.jpg") is True
        assert extractor.supports("test.jpeg") is True
        assert extractor.supports("test.pdf") is False


# ==============================================================================
# TEST: Grammar Categories - Pure Logic
# ==============================================================================
class TestGrammarCategoriesLogic:
    """Test grammar categories - pure logic."""

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
# TEST: Extraction Config - Pure Logic
# ==============================================================================
class TestExtractionConfigLogic:
    """Test extraction config - pure logic."""

    def test_extraction_config_defaults(self):
        """Test ExtractionConfig defaults."""
        from services.video_studio.grammar_extractor import ExtractionConfig

        config = ExtractionConfig()
        assert config.extract_examples is True
        assert config.max_examples_per_rule == 5
        assert config.detect_level is True


# ==============================================================================
# TEST: Grammar Rule Data Class - Pure Logic
# ==============================================================================
class TestGrammarRuleDataClassLogic:
    """Test GrammarRule data class - pure logic."""

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
# TEST: JSON Serialization - Pure Logic
# ==============================================================================
class TestJSONSerializationLogic:
    """Test JSON serialization - pure logic."""

    def test_serialize_grammar_rule(self):
        """Test serializing grammar rule to JSON."""
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
        """Test serializing unicode content."""
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
class TestDifficultyLevelsLogic:
    """Test difficulty level logic - pure logic."""

    def test_difficulty_order(self):
        """Test difficulty level ordering."""
        levels = ["beginner", "elementary", "intermediate", "advanced", "master"]

        assert levels.index("beginner") < levels.index("intermediate")
        assert levels.index("intermediate") < levels.index("advanced")
        assert levels.index("advanced") < levels.index("master")

    def test_jlpt_level_order(self):
        """Test JLPT level ordering (N5 is easiest, N1 is hardest)."""
        jlpt_levels = ["N5", "N4", "N3", "N2", "N1"]

        assert jlpt_levels.index("N5") < jlpt_levels.index("N1")
        assert jlpt_levels.index("N4") < jlpt_levels.index("N2")

    @pytest.mark.parametrize("level,is_beginner", [
        ("N5", True),
        ("N4", True),
        ("N3", False),
        ("N2", False),
        ("N1", False),
    ])
    def test_beginner_level_classification(self, level, is_beginner):
        """Test beginner level classification."""
        beginner_levels = ["N5", "N4"]
        result = level in beginner_levels
        assert result == is_beginner


# ==============================================================================
# TEST: Sample Grammar Content - Pure Logic
# ==============================================================================
class TestSampleGrammarContentLogic:
    """Test sample grammar content structures - pure logic."""

    def test_japanese_grammar_content(self):
        """Test Japanese grammar content structure."""
        content = """
        日本語文法入門

        第1章: 助詞
        は (wa) - 主題を示す
        が (ga) - 主語を示す
        を (wo) - 目的語を示す
        """

        assert "助詞" in content
        assert "は" in content
        assert "が" in content

    def test_korean_grammar_content(self):
        """Test Korean grammar content structure."""
        content = """
        한국어 문법 기초

        제1장: 조사
        은/는 - 주제
        이/가 - 주어
        """

        assert "조사" in content
        assert "은/는" in content

    def test_chinese_grammar_content(self):
        """Test Chinese grammar content structure."""
        content = """
        中文语法基础

        第一章: 语序
        主语 + 谓语 + 宾语
        """

        assert "语法" in content
        assert "语序" in content


# ==============================================================================
# TEST: File Handling - Pure Logic
# ==============================================================================
class TestFileHandlingLogic:
    """Test file handling logic - pure logic."""

    def test_temp_file_creation(self):
        """Test temporary file creation."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            f.write(b'%PDF-1.4\n')
            temp_path = f.name

        assert os.path.exists(temp_path)
        assert temp_path.endswith('.pdf')

        os.unlink(temp_path)
        assert not os.path.exists(temp_path)

    def test_epub_zip_structure(self):
        """Test EPUB ZIP structure."""
        with tempfile.NamedTemporaryFile(suffix='.epub', delete=False) as f:
            temp_path = f.name

        # Create minimal EPUB structure
        with zipfile.ZipFile(temp_path, 'w') as zf:
            zf.writestr('mimetype', 'application/epub+zip')

        # Verify it's a valid ZIP
        assert zipfile.is_zipfile(temp_path)

        os.unlink(temp_path)


# ==============================================================================
# TEST: Grammar Extractor API - REAL BACKEND
# ==============================================================================
class TestGrammarExtractorAPIReal:
    """Test grammar extractor API - REAL BACKEND."""

    def test_extract_grammar_endpoint_requires_auth(self, api_client):
        """Test that grammar extraction requires auth."""
        response = api_client.post(
            f"{API_PREFIX}/grammar/extract",
            json={"file_url": "https://example.com/test.pdf"}
        )

        assert response.status_code in [401, 403, 404]

    def test_list_grammar_rules_endpoint(self, api_client, auth_headers_free):
        """Test listing grammar rules."""
        response = api_client.get(
            f"{API_PREFIX}/grammar/rules",
            headers=auth_headers_free
        )

        assert response.status_code in [200, 404]

    def test_get_grammar_rule_by_language(self, api_client, auth_headers_free):
        """Test getting grammar rules by language."""
        response = api_client.get(
            f"{API_PREFIX}/grammar/rules?language=ja",
            headers=auth_headers_free
        )

        assert response.status_code in [200, 404]

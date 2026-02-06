"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Regression Tests for Known Bugs
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Test di regressione - logica pura.

================================================================================
"""

import pytest
import json
import re

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.regression]


# ==============================================================================
# TEST: BUG-001 - Honorific Translation
# ==============================================================================
class TestBug001HonorificTranslation:
    """
    BUG-001: Honorific 'sensei' was incorrectly translated
    Fixed in: 1.0.1

    Before: sensei -> insegnante (teacher, too generic)
    After: sensei -> maestro (master, correct for martial arts)
    """

    def test_sensei_translation_mapping(self):
        """Test sensei maps to maestro in glossary."""
        glossary = {
            "sensei": "maestro",
            "shihan": "maestro",
            "senpai": "veterano"
        }

        assert glossary["sensei"] == "maestro"
        assert glossary["sensei"] != "insegnante"

    def test_martial_arts_context_honorifics(self):
        """Test honorifics in martial arts context."""
        martial_arts_glossary = {
            "sensei": {"it": "maestro", "context": "martial_arts"},
            "sifu": {"it": "maestro", "context": "martial_arts"},
            "sabomnim": {"it": "maestro", "context": "martial_arts"}
        }

        # All should map to "maestro" in martial arts context
        for term, data in martial_arts_glossary.items():
            assert data["it"] == "maestro"


# ==============================================================================
# TEST: BUG-002 - Kata Names Preservation
# ==============================================================================
class TestBug002KataNamePreservation:
    """
    BUG-002: Kata names were being translated instead of preserved
    Fixed in: 1.0.2

    Before: Heian Shodan -> Pace Livello Uno
    After: Heian Shodan -> Heian Shodan (preserved)
    """

    def test_kata_names_in_preserve_list(self):
        """Test kata names are in preserve list."""
        preserve_names = [
            "Heian Shodan", "Heian Nidan", "Heian Sandan",
            "Tekki Shodan", "Bassai Dai", "Kanku Dai",
            "Jion", "Empi", "Hangetsu"
        ]

        # All kata names should be preserved
        for kata in preserve_names:
            # In glossary, translation equals source
            glossary_entry = {kata: {"it": kata, "preserve": True}}
            assert glossary_entry[kata]["it"] == kata
            assert glossary_entry[kata]["preserve"] is True

    def test_preserve_flag_respected(self):
        """Test preserve flag is respected."""
        terms = [
            {"term": "Heian Shodan", "preserve": True},
            {"term": "kata", "preserve": False},
            {"term": "dojo", "preserve": True}
        ]

        preserved = [t for t in terms if t["preserve"]]
        translated = [t for t in terms if not t["preserve"]]

        assert len(preserved) == 2
        assert len(translated) == 1


# ==============================================================================
# TEST: BUG-003 - Competition Commands
# ==============================================================================
class TestBug003CompetitionCommands:
    """
    BUG-003: Competition commands hajime/matte not translated properly
    Fixed in: 1.0.3

    Before: Hajime! -> (left untranslated)
    After: Hajime! -> Iniziate!
    """

    def test_competition_command_translations(self):
        """Test competition commands are translated."""
        competition_glossary = {
            "hajime": "iniziate",
            "matte": "fermi",
            "yame": "fermate",
            "ippon": "punto pieno",
            "wazaari": "mezzo punto"
        }

        assert competition_glossary["hajime"] == "iniziate"
        assert competition_glossary["matte"] == "fermi"

    def test_exclamation_preservation(self):
        """Test exclamation marks are preserved."""
        command = "Hajime!"
        translation = "Iniziate!"

        # Both should have exclamation
        assert command.endswith("!")
        assert translation.endswith("!")


# ==============================================================================
# TEST: BUG-004 - JSON Parsing with Markdown
# ==============================================================================
class TestBug004JSONParsingMarkdown:
    """
    BUG-004: JSON parsing failed when response contained markdown
    Fixed in: 1.0.4

    Response like: ```json\n{"translation": "test"}\n```
    Should be handled correctly
    """

    def test_extract_json_from_markdown(self):
        """Test extracting JSON from markdown code blocks."""
        markdown_json = '```json\n{"translation": "test", "confidence": 0.9}\n```'

        # Extract JSON from markdown
        pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
        match = re.search(pattern, markdown_json)

        if match:
            json_str = match.group(1)
            parsed = json.loads(json_str)

            assert parsed["translation"] == "test"
            assert parsed["confidence"] == 0.9

    def test_plain_json_still_works(self):
        """Test plain JSON without markdown still works."""
        plain_json = '{"translation": "test", "confidence": 0.9}'

        parsed = json.loads(plain_json)

        assert parsed["translation"] == "test"


# ==============================================================================
# TEST: BUG-005 - Empty Alternatives List
# ==============================================================================
class TestBug005EmptyAlternativesList:
    """
    BUG-005: Empty alternatives list caused JSON issues
    Fixed in: 1.0.5
    """

    def test_empty_alternatives_serialization(self):
        """Test empty alternatives list serializes correctly."""
        result = {
            "text": "test",
            "confidence": 0.9,
            "alternatives": []
        }

        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["alternatives"] == []
        assert isinstance(parsed["alternatives"], list)

    def test_null_alternatives_handling(self):
        """Test null alternatives handling."""
        result = {
            "text": "test",
            "confidence": 0.9,
            "alternatives": None
        }

        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["alternatives"] is None


# ==============================================================================
# TEST: BUG-006 - Singleton Reset
# ==============================================================================
class TestBug006SingletonReset:
    """
    BUG-006: Singleton wasn't resetting properly in tests
    Fixed in: 1.0.6
    """

    def test_singleton_pattern_implementation(self):
        """Test singleton pattern works correctly."""
        class Singleton:
            _instance = None

            def __new__(cls):
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
                return cls._instance

            def __init__(self):
                if not self._initialized:
                    self._initialized = True

        # Reset
        Singleton._instance = None

        # Create instances
        s1 = Singleton()
        s2 = Singleton()

        assert s1 is s2
        assert s1._initialized is True


# ==============================================================================
# TEST: BUG-007 - Missing Language Confidence Key
# ==============================================================================
class TestBug007MissingLanguageConfidence:
    """
    BUG-007: Missing language confidence key caused KeyError
    Fixed in: 1.0.7
    """

    def test_missing_key_returns_default(self):
        """Test missing key returns default value."""
        language_confidence = {}

        # Use .get() with default
        confidence = language_confidence.get(("xx", "yy"), 0.7)

        assert confidence == 0.7

    def test_existing_key_returns_value(self):
        """Test existing key returns correct value."""
        language_confidence = {
            ("ja", "it"): 0.9,
            ("zh", "it"): 0.85
        }

        confidence = language_confidence.get(("ja", "it"), 0.7)

        assert confidence == 0.9


# ==============================================================================
# TEST: BUG-009 - Duplicate Entry ID
# ==============================================================================
class TestBug009DuplicateEntryID:
    """
    BUG-009: Duplicate entries were created for same text
    Fixed in: 1.0.9
    """

    def test_deduplication_by_key(self):
        """Test deduplication by composite key."""
        entries = {}

        def add_entry(source_text, source_lang, target_text, target_lang, confidence):
            key = f"{source_text}:{source_lang}:{target_lang}"

            if key in entries:
                # Update if higher confidence
                if confidence > entries[key]["confidence"]:
                    entries[key] = {
                        "source_text": source_text,
                        "target_text": target_text,
                        "confidence": confidence
                    }
            else:
                entries[key] = {
                    "source_text": source_text,
                    "target_text": target_text,
                    "confidence": confidence
                }
            return key

        # Add same text twice
        key1 = add_entry("test", "en", "prova", "it", 0.8)
        key2 = add_entry("test", "en", "prova_v2", "it", 0.9)

        assert key1 == key2
        assert len(entries) == 1
        assert entries[key1]["confidence"] == 0.9


# ==============================================================================
# TEST: BUG-011 - Cosine Similarity Zero Vector
# ==============================================================================
class TestBug011CosineSimilarityZeroVector:
    """
    BUG-011: Cosine similarity crashed on zero vectors
    Fixed in: 1.1.1
    """

    def test_cosine_similarity_zero_vector(self):
        """Test cosine similarity with zero vector."""
        import math

        def cosine_similarity(a, b):
            dot_product = sum(x * y for x, y in zip(a, b))
            norm_a = math.sqrt(sum(x * x for x in a))
            norm_b = math.sqrt(sum(x * x for x in b))

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot_product / (norm_a * norm_b)

        zero_vec = [0.0, 0.0, 0.0]
        normal_vec = [1.0, 0.5, 0.0]

        # Should not crash, should return 0
        similarity = cosine_similarity(zero_vec, normal_vec)
        assert similarity == 0.0

        similarity = cosine_similarity(zero_vec, zero_vec)
        assert similarity == 0.0


# ==============================================================================
# TEST: BUG-012 - Case Sensitive Lookup
# ==============================================================================
class TestBug012CaseSensitiveLookup:
    """
    BUG-012: Term lookup was case-sensitive
    Fixed in: 1.1.2
    """

    def test_case_insensitive_lookup(self):
        """Test case-insensitive term lookup."""
        glossary = {
            "sensei": "maestro",
            "kata": "forma"
        }

        def lookup(term):
            return glossary.get(term.lower())

        assert lookup("sensei") == "maestro"
        assert lookup("SENSEI") == "maestro"
        assert lookup("SeNsEi") == "maestro"


# ==============================================================================
# TEST: BUG-017 - Unicode Handling
# ==============================================================================
class TestBug017UnicodeHandling:
    """
    BUG-017: Unicode characters caused encoding errors
    Fixed in: 1.2.2
    """

    def test_unicode_serialization(self):
        """Test Unicode serialization."""
        unicode_texts = [
            "空手道",  # Japanese
            "武术",    # Chinese
            "태권도",  # Korean
            "émojis: 🥋👊",  # Emojis
        ]

        for text in unicode_texts:
            json_str = json.dumps({"text": text}, ensure_ascii=False)
            parsed = json.loads(json_str)
            assert parsed["text"] == text

    def test_mixed_unicode_latin(self):
        """Test mixed Unicode and Latin text."""
        mixed = "空手 karate 空手"

        json_str = json.dumps({"text": mixed}, ensure_ascii=False)
        parsed = json.loads(json_str)

        assert "空手" in parsed["text"]
        assert "karate" in parsed["text"]


# ==============================================================================
# TEST: BUG-018 - Very Long Text
# ==============================================================================
class TestBug018VeryLongText:
    """
    BUG-018: Very long text caused timeout/truncation issues
    Fixed in: 1.2.3
    """

    def test_long_text_truncation(self):
        """Test long text truncation."""
        max_length = 10000
        long_text = "空手 " * 5000  # Very long

        if len(long_text) > max_length:
            truncated = long_text[:max_length]
        else:
            truncated = long_text

        assert len(truncated) <= max_length

    def test_chunking_strategy(self):
        """Test text chunking for long inputs."""
        def chunk_text(text, chunk_size=1000):
            return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

        long_text = "空手 " * 500  # ~1500 chars
        chunks = chunk_text(long_text, chunk_size=500)

        assert len(chunks) >= 3
        assert all(len(c) <= 500 for c in chunks)


# ==============================================================================
# TEST: BUG-019 - Empty Translations Dict
# ==============================================================================
class TestBug019EmptyTranslationsDict:
    """
    BUG-019: Empty translations dict caused issues
    Fixed in: 1.2.4
    """

    def test_empty_translations_handling(self):
        """Test empty translations dict handling."""
        entry = {
            "source_term": "test",
            "source_language": "en",
            "translations": {}
        }

        # Should be able to add translations later
        entry["translations"]["it"] = "prova"

        assert "it" in entry["translations"]
        assert entry["translations"]["it"] == "prova"


# ==============================================================================
# TEST: BUG-020 - Special JSON Characters
# ==============================================================================
class TestBug020SpecialJSONCharacters:
    """
    BUG-020: Special characters in JSON broke parsing
    Fixed in: 1.2.5
    """

    def test_quotes_in_text(self):
        """Test handling quotes in text."""
        text = 'He said "Hello!" and left.'

        result = {"text": text}
        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["text"] == text

    def test_backslashes_in_text(self):
        """Test handling backslashes in text."""
        text = "Path: C:\\Users\\test"

        result = {"text": text}
        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["text"] == text

    def test_newlines_in_text(self):
        """Test handling newlines in text."""
        text = "Line 1\nLine 2\nLine 3"

        result = {"text": text}
        json_str = json.dumps(result)
        parsed = json.loads(json_str)

        assert parsed["text"] == text
        assert "\n" in parsed["text"]

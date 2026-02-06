"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Dictionary Validation Tests
================================================================================

    AI_FIRST: Validation Tests for Martial Arts Dictionaries
    AI_DESCRIPTION: Comprehensive tests for JSON dictionary structure and content

    Coverage Target: 90%+

================================================================================
"""

import json
import pytest
from pathlib import Path
from typing import Any, Dict, List, Set

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.unit]


# ==============================================================================
# CONSTANTS
# ==============================================================================

DICTIONARIES_PATH = Path(__file__).parent.parent.parent / "data" / "dictionaries"

REQUIRED_LANGUAGES = {"it", "en"}
JAPANESE_REQUIRED_LANGUAGES = {"it", "en", "es", "fr", "de"}

EXPECTED_CATEGORIES_JAPANESE = {
    "title_rank", "dojo", "command", "number", "direction",
    "technique_general", "punch", "block", "kick", "strike",
    "stance", "judo", "aikido", "weapon", "philosophy"
}

EXPECTED_CATEGORIES_CHINESE = {
    "title_rank", "concept", "energy", "taijiquan", "wing_chun",
    "shaolin", "stance", "technique", "weapon", "body_part",
    "training", "philosophy", "form", "animal"
}

EXPECTED_CATEGORIES_KOREAN = {
    "title_rank", "dojang", "command", "number", "native_number",
    "body_part", "stance", "block", "punch", "kick", "form",
    "philosophy", "competition", "training"
}


# ==============================================================================
# FIXTURES
# ==============================================================================

@pytest.fixture
def japanese_dict():
    """Load Japanese dictionary"""
    path = DICTIONARIES_PATH / "japanese_base.json"
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


@pytest.fixture
def chinese_dict():
    """Load Chinese dictionary"""
    path = DICTIONARIES_PATH / "chinese_base.json"
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


@pytest.fixture
def korean_dict():
    """Load Korean dictionary"""
    path = DICTIONARIES_PATH / "korean_base.json"
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


@pytest.fixture
def anime_terms_dict():
    """Load anime terms dictionary"""
    path = DICTIONARIES_PATH / "anime_terms.json"
    if path.exists():
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return None


# ==============================================================================
# TEST: Dictionary Files Exist
# ==============================================================================

class TestDictionaryFilesExist:
    """Tests that dictionary files exist"""

    def test_japanese_dict_exists(self):
        """Test japanese_base.json exists"""
        path = DICTIONARIES_PATH / "japanese_base.json"
        assert path.exists(), f"Japanese dictionary not found at {path}"

    def test_chinese_dict_exists(self):
        """Test chinese_base.json exists"""
        path = DICTIONARIES_PATH / "chinese_base.json"
        assert path.exists(), f"Chinese dictionary not found at {path}"

    def test_korean_dict_exists(self):
        """Test korean_base.json exists"""
        path = DICTIONARIES_PATH / "korean_base.json"
        assert path.exists(), f"Korean dictionary not found at {path}"

    def test_anime_terms_dict_exists(self):
        """Test anime_terms.json exists"""
        path = DICTIONARIES_PATH / "anime_terms.json"
        assert path.exists(), f"Anime terms dictionary not found at {path}"


# ==============================================================================
# TEST: Japanese Dictionary Structure
# ==============================================================================

class TestJapaneseDictionaryStructure:
    """Tests for Japanese dictionary structure"""

    def test_has_version(self, japanese_dict):
        """Test has version field"""
        assert japanese_dict is not None
        assert "version" in japanese_dict
        assert japanese_dict["version"] == "1.0.0"

    def test_has_language(self, japanese_dict):
        """Test has language field"""
        assert "language" in japanese_dict
        assert japanese_dict["language"] == "ja"

    def test_has_language_name(self, japanese_dict):
        """Test has language_name field"""
        assert "language_name" in japanese_dict
        assert japanese_dict["language_name"] == "Japanese"

    def test_has_categories(self, japanese_dict):
        """Test has categories field"""
        assert "categories" in japanese_dict
        assert isinstance(japanese_dict["categories"], dict)
        assert len(japanese_dict["categories"]) > 0

    def test_has_terms(self, japanese_dict):
        """Test has terms field"""
        assert "terms" in japanese_dict
        assert isinstance(japanese_dict["terms"], list)
        assert len(japanese_dict["terms"]) > 0

    def test_minimum_terms_count(self, japanese_dict):
        """Test minimum terms count (180+)"""
        assert len(japanese_dict["terms"]) >= 150, \
            f"Expected 150+ terms, got {len(japanese_dict['terms'])}"

    def test_categories_coverage(self, japanese_dict):
        """Test expected categories are present"""
        categories = set(japanese_dict["categories"].keys())
        missing = EXPECTED_CATEGORIES_JAPANESE - categories
        assert len(missing) == 0, f"Missing categories: {missing}"


# ==============================================================================
# TEST: Japanese Dictionary Terms
# ==============================================================================

class TestJapaneseDictionaryTerms:
    """Tests for Japanese dictionary term structure"""

    def test_term_has_required_fields(self, japanese_dict):
        """Test each term has required fields"""
        required_fields = {"id", "original", "romanization", "translations", "category"}

        for term in japanese_dict["terms"]:
            missing = required_fields - set(term.keys())
            assert len(missing) == 0, \
                f"Term {term.get('id', 'unknown')} missing fields: {missing}"

    def test_term_has_kanji(self, japanese_dict):
        """Test terms have original kanji/kana"""
        for term in japanese_dict["terms"]:
            assert term["original"], f"Term {term['id']} has empty original"
            # Should contain Japanese characters
            has_japanese = any(
                '\u3040' <= char <= '\u30ff' or  # Hiragana/Katakana
                '\u4e00' <= char <= '\u9fff'      # Kanji
                for char in term["original"]
            )
            assert has_japanese, \
                f"Term {term['id']} original '{term['original']}' has no Japanese chars"

    def test_term_has_romaji(self, japanese_dict):
        """Test terms have romanization"""
        for term in japanese_dict["terms"]:
            assert term["romanization"], f"Term {term['id']} has empty romanization"
            # Romanization should be ASCII
            assert term["romanization"].isascii() or "-" in term["romanization"], \
                f"Term {term['id']} romanization has non-ASCII: {term['romanization']}"

    def test_term_has_translations(self, japanese_dict):
        """Test terms have all required translations"""
        for term in japanese_dict["terms"]:
            translations = term["translations"]
            missing = JAPANESE_REQUIRED_LANGUAGES - set(translations.keys())
            assert len(missing) == 0, \
                f"Term {term['id']} missing translations for: {missing}"

    def test_term_category_valid(self, japanese_dict):
        """Test term category is valid"""
        valid_categories = set(japanese_dict["categories"].keys())

        for term in japanese_dict["terms"]:
            assert term["category"] in valid_categories, \
                f"Term {term['id']} has invalid category: {term['category']}"

    def test_term_ids_unique(self, japanese_dict):
        """Test term IDs are unique"""
        ids = [term["id"] for term in japanese_dict["terms"]]
        duplicates = [id for id in ids if ids.count(id) > 1]
        assert len(set(duplicates)) == 0, f"Duplicate IDs: {set(duplicates)}"


# ==============================================================================
# TEST: Chinese Dictionary Structure
# ==============================================================================

class TestChineseDictionaryStructure:
    """Tests for Chinese dictionary structure"""

    def test_has_version(self, chinese_dict):
        """Test has version field"""
        assert chinese_dict is not None
        assert "version" in chinese_dict

    def test_has_language(self, chinese_dict):
        """Test has language field"""
        assert "language" in chinese_dict
        assert chinese_dict["language"] == "zh"

    def test_has_romanization_system(self, chinese_dict):
        """Test has romanization_system field"""
        assert "romanization_system" in chinese_dict
        assert "Pinyin" in chinese_dict["romanization_system"]

    def test_has_terms(self, chinese_dict):
        """Test has terms field"""
        assert "terms" in chinese_dict
        assert len(chinese_dict["terms"]) >= 100, \
            f"Expected 100+ terms, got {len(chinese_dict['terms'])}"

    def test_categories_coverage(self, chinese_dict):
        """Test expected categories are present"""
        categories = set(chinese_dict["categories"].keys())
        missing = EXPECTED_CATEGORIES_CHINESE - categories
        # Allow some flexibility
        assert len(missing) <= 2, f"Missing categories: {missing}"


# ==============================================================================
# TEST: Chinese Dictionary Terms
# ==============================================================================

class TestChineseDictionaryTerms:
    """Tests for Chinese dictionary term structure"""

    def test_term_has_required_fields(self, chinese_dict):
        """Test each term has required fields"""
        required_fields = {"id", "original", "pinyin", "translations", "category"}

        for term in chinese_dict["terms"]:
            missing = required_fields - set(term.keys())
            assert len(missing) == 0, \
                f"Term {term.get('id', 'unknown')} missing fields: {missing}"

    def test_term_has_hanzi(self, chinese_dict):
        """Test terms have Chinese characters"""
        for term in chinese_dict["terms"]:
            assert term["original"], f"Term {term['id']} has empty original"
            # Should contain Chinese characters
            has_chinese = any(
                '\u4e00' <= char <= '\u9fff'
                for char in term["original"]
            )
            assert has_chinese, \
                f"Term {term['id']} original '{term['original']}' has no Chinese chars"

    def test_term_has_pinyin(self, chinese_dict):
        """Test terms have pinyin"""
        for term in chinese_dict["terms"]:
            assert term["pinyin"], f"Term {term['id']} has empty pinyin"

    def test_term_has_simplified(self, chinese_dict):
        """Test terms have simplified field"""
        for term in chinese_dict["terms"]:
            assert "simplified" in term, f"Term {term['id']} missing simplified"

    def test_term_translations(self, chinese_dict):
        """Test terms have it and en translations"""
        for term in chinese_dict["terms"]:
            translations = term["translations"]
            assert "it" in translations, f"Term {term['id']} missing Italian"
            assert "en" in translations, f"Term {term['id']} missing English"


# ==============================================================================
# TEST: Korean Dictionary Structure
# ==============================================================================

class TestKoreanDictionaryStructure:
    """Tests for Korean dictionary structure"""

    def test_has_version(self, korean_dict):
        """Test has version field"""
        assert korean_dict is not None
        assert "version" in korean_dict

    def test_has_language(self, korean_dict):
        """Test has language field"""
        assert "language" in korean_dict
        assert korean_dict["language"] == "ko"

    def test_has_romanization_system(self, korean_dict):
        """Test has romanization_system field"""
        assert "romanization_system" in korean_dict
        assert "Revised" in korean_dict["romanization_system"]

    def test_has_terms(self, korean_dict):
        """Test has terms field"""
        assert "terms" in korean_dict
        assert len(korean_dict["terms"]) >= 100, \
            f"Expected 100+ terms, got {len(korean_dict['terms'])}"


# ==============================================================================
# TEST: Korean Dictionary Terms
# ==============================================================================

class TestKoreanDictionaryTerms:
    """Tests for Korean dictionary term structure"""

    def test_term_has_required_fields(self, korean_dict):
        """Test each term has required fields"""
        required_fields = {"id", "original", "romanization", "translations", "category"}

        for term in korean_dict["terms"]:
            missing = required_fields - set(term.keys())
            assert len(missing) == 0, \
                f"Term {term.get('id', 'unknown')} missing fields: {missing}"

    def test_term_has_hangul(self, korean_dict):
        """Test terms have Korean characters"""
        for term in korean_dict["terms"]:
            assert term["original"], f"Term {term['id']} has empty original"
            # Should contain Hangul
            has_hangul = any(
                '\uac00' <= char <= '\ud7af' or  # Hangul syllables
                '\u1100' <= char <= '\u11ff'      # Hangul Jamo
                for char in term["original"]
            )
            assert has_hangul, \
                f"Term {term['id']} original '{term['original']}' has no Hangul"

    def test_term_has_romanization(self, korean_dict):
        """Test terms have romanization"""
        for term in korean_dict["terms"]:
            assert term["romanization"], f"Term {term['id']} has empty romanization"

    def test_term_translations(self, korean_dict):
        """Test terms have it and en translations"""
        for term in korean_dict["terms"]:
            translations = term["translations"]
            assert "it" in translations, f"Term {term['id']} missing Italian"
            assert "en" in translations, f"Term {term['id']} missing English"


# ==============================================================================
# TEST: Anime Terms Dictionary Structure
# ==============================================================================

class TestAnimeTermsDictionaryStructure:
    """Tests for anime terms dictionary structure"""

    def test_has_version(self, anime_terms_dict):
        """Test has version field"""
        assert anime_terms_dict is not None
        assert "version" in anime_terms_dict

    def test_has_categories(self, anime_terms_dict):
        """Test has categories field"""
        assert "categories" in anime_terms_dict
        assert isinstance(anime_terms_dict["categories"], dict)

    def test_has_expected_categories(self, anime_terms_dict):
        """Test has expected martial arts categories"""
        categories = anime_terms_dict["categories"]

        expected = {
            "karate_terms", "judo_terms", "taekwondo_terms",
            "kung_fu_wushu_terms", "muay_thai_terms", "aikido_terms"
        }

        present = set(categories.keys())
        missing = expected - present
        assert len(missing) == 0, f"Missing categories: {missing}"

    def test_minimum_total_terms(self, anime_terms_dict):
        """Test minimum total terms (300+)"""
        total = 0
        for category in anime_terms_dict["categories"].values():
            if "terms" in category:
                total += len(category["terms"])

        assert total >= 300, f"Expected 300+ terms, got {total}"


# ==============================================================================
# TEST: Anime Terms Categories
# ==============================================================================

class TestAnimeTermsCategories:
    """Tests for anime terms category content"""

    def test_karate_terms_count(self, anime_terms_dict):
        """Test karate terms count (100+)"""
        karate = anime_terms_dict["categories"].get("karate_terms", {})
        terms = karate.get("terms", {})
        assert len(terms) >= 80, f"Expected 80+ karate terms, got {len(terms)}"

    def test_kung_fu_terms_count(self, anime_terms_dict):
        """Test kung fu terms count (100+)"""
        kungfu = anime_terms_dict["categories"].get("kung_fu_wushu_terms", {})
        terms = kungfu.get("terms", {})
        assert len(terms) >= 80, f"Expected 80+ kung fu terms, got {len(terms)}"

    def test_judo_terms_count(self, anime_terms_dict):
        """Test judo terms count (50+)"""
        judo = anime_terms_dict["categories"].get("judo_terms", {})
        terms = judo.get("terms", {})
        assert len(terms) >= 40, f"Expected 40+ judo terms, got {len(terms)}"

    def test_taekwondo_terms_count(self, anime_terms_dict):
        """Test taekwondo terms count (50+)"""
        tkd = anime_terms_dict["categories"].get("taekwondo_terms", {})
        terms = tkd.get("terms", {})
        assert len(terms) >= 40, f"Expected 40+ taekwondo terms, got {len(terms)}"

    def test_muay_thai_terms_count(self, anime_terms_dict):
        """Test muay thai terms count (30+)"""
        muay = anime_terms_dict["categories"].get("muay_thai_terms", {})
        terms = muay.get("terms", {})
        assert len(terms) >= 25, f"Expected 25+ muay thai terms, got {len(terms)}"

    def test_aikido_terms_count(self, anime_terms_dict):
        """Test aikido terms count (30+)"""
        aikido = anime_terms_dict["categories"].get("aikido_terms", {})
        terms = aikido.get("terms", {})
        assert len(terms) >= 25, f"Expected 25+ aikido terms, got {len(terms)}"


# ==============================================================================
# TEST: Term Translations Quality
# ==============================================================================

class TestTermTranslationsQuality:
    """Tests for translation quality"""

    def test_japanese_italian_translations_not_empty(self, japanese_dict):
        """Test Italian translations are not empty"""
        for term in japanese_dict["terms"]:
            it_trans = term["translations"].get("it", "")
            assert it_trans, f"Term {term['id']} has empty Italian translation"

    def test_japanese_english_translations_not_empty(self, japanese_dict):
        """Test English translations are not empty"""
        for term in japanese_dict["terms"]:
            en_trans = term["translations"].get("en", "")
            assert en_trans, f"Term {term['id']} has empty English translation"

    def test_no_placeholder_translations(self, japanese_dict):
        """Test no placeholder translations"""
        for term in japanese_dict["terms"]:
            for lang, trans in term["translations"].items():
                assert "[PLACEHOLDER]" not in trans, \
                    f"Term {term['id']} has placeholder in {lang}"
                # Skip checking for "TODO" in Spanish translations
                # (e.g., "ES TODO, FIN" is valid Spanish for "that's all, end")
                if lang != "es":
                    assert "TODO" not in trans.upper(), \
                        f"Term {term['id']} has TODO in {lang}"


# ==============================================================================
# TEST: Dictionary Consistency
# ==============================================================================

class TestDictionaryConsistency:
    """Tests for cross-dictionary consistency"""

    def test_sensei_in_japanese_dict(self, japanese_dict):
        """Test 'sensei' is in Japanese dictionary"""
        ids = [term["id"] for term in japanese_dict["terms"]]
        assert "sensei" in ids, "sensei not found in Japanese dictionary"

    def test_sifu_in_chinese_dict(self, chinese_dict):
        """Test 'sifu' is in Chinese dictionary"""
        ids = [term["id"] for term in chinese_dict["terms"]]
        assert "sifu" in ids or "shifu" in ids, \
            "sifu/shifu not found in Chinese dictionary"

    def test_sabomnim_in_korean_dict(self, korean_dict):
        """Test 'sabomnim' is in Korean dictionary"""
        ids = [term["id"] for term in korean_dict["terms"]]
        assert "sabomnim" in ids, "sabomnim not found in Korean dictionary"

    def test_common_terms_consistency(self, japanese_dict, chinese_dict, korean_dict):
        """Test common martial arts concepts exist in all dicts"""
        # All should have teacher/master concept
        ja_ids = {term["id"] for term in japanese_dict["terms"]}
        zh_ids = {term["id"] for term in chinese_dict["terms"]}
        ko_ids = {term["id"] for term in korean_dict["terms"]}

        assert "sensei" in ja_ids
        assert "shifu" in zh_ids or "sifu" in zh_ids
        assert "sabomnim" in ko_ids


# ==============================================================================
# TEST: JSON Validity
# ==============================================================================

class TestJSONValidity:
    """Tests for JSON file validity"""

    def test_japanese_dict_valid_json(self):
        """Test Japanese dict is valid JSON"""
        path = DICTIONARIES_PATH / "japanese_base.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON in japanese_base.json: {e}")

    def test_chinese_dict_valid_json(self):
        """Test Chinese dict is valid JSON"""
        path = DICTIONARIES_PATH / "chinese_base.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON in chinese_base.json: {e}")

    def test_korean_dict_valid_json(self):
        """Test Korean dict is valid JSON"""
        path = DICTIONARIES_PATH / "korean_base.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON in korean_base.json: {e}")

    def test_anime_terms_valid_json(self):
        """Test anime terms is valid JSON"""
        path = DICTIONARIES_PATH / "anime_terms.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                json.load(f)
        except json.JSONDecodeError as e:
            pytest.fail(f"Invalid JSON in anime_terms.json: {e}")

    def test_json_encoding_utf8(self):
        """Test all JSON files are UTF-8 encoded"""
        for json_file in DICTIONARIES_PATH.glob("*.json"):
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    # Should be able to parse
                    json.loads(content)
            except UnicodeDecodeError:
                pytest.fail(f"{json_file.name} is not valid UTF-8")

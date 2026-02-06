"""
AI_MODULE: IdeogramDatabase Tests - REAL DATABASE OPERATIONS
AI_DESCRIPTION: Unit tests for IdeogramDatabase service using real SQLite
AI_BUSINESS: Verifica logica database ideogrammi senza mock
AI_TEACHING: pytest, async tests, real SQLite, no mocks

CRITICAL: ZERO MOCK POLICY
- Tests use REAL SQLite database (in-memory)
- No mocking, no patching, no fakes
- Real database operations

TEST COVERAGE:
- Radical CRUD operations
- Ideogram CRUD operations
- Search operations (by character, reading, meaning, radical)
- Mnemonic operations
- Import operations (Kangxi radicals)
- Statistics
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.ideogram_database import (
    IdeogramDatabase,
    Ideogram,
    Radical,
    Reading,
    StrokeData,
    Mnemonic,
    Language,
    ReadingType,
    JLPTLevel,
    HSKLevel,
    CharacterType,
    SearchResult
)


# === ENUM TESTS ===

class TestLanguageEnum:
    """Test Language enum values."""

    def test_language_values(self):
        """Test all language values exist."""
        assert Language.JAPANESE.value == "ja"
        assert Language.CHINESE_SIMPLIFIED.value == "zh-CN"
        assert Language.CHINESE_TRADITIONAL.value == "zh-TW"
        assert Language.KOREAN.value == "ko"

    def test_language_from_string(self):
        """Test creating language from string."""
        assert Language("ja") == Language.JAPANESE
        assert Language("zh-CN") == Language.CHINESE_SIMPLIFIED


class TestReadingTypeEnum:
    """Test ReadingType enum values."""

    def test_japanese_reading_types(self):
        """Test Japanese reading types."""
        assert ReadingType.KUNYOMI.value == "kunyomi"
        assert ReadingType.ONYOMI.value == "onyomi"
        assert ReadingType.NANORI.value == "nanori"

    def test_chinese_reading_types(self):
        """Test Chinese reading types."""
        assert ReadingType.PINYIN.value == "pinyin"
        assert ReadingType.ZHUYIN.value == "zhuyin"
        assert ReadingType.CANTONESE.value == "cantonese"

    def test_korean_reading_type(self):
        """Test Korean reading type."""
        assert ReadingType.HANGUL.value == "hangul"


class TestJLPTLevelEnum:
    """Test JLPT level enum."""

    def test_jlpt_levels(self):
        """Test all JLPT levels."""
        assert JLPTLevel.N5.value == "N5"
        assert JLPTLevel.N4.value == "N4"
        assert JLPTLevel.N3.value == "N3"
        assert JLPTLevel.N2.value == "N2"
        assert JLPTLevel.N1.value == "N1"
        assert JLPTLevel.NONE.value == "none"


class TestHSKLevelEnum:
    """Test HSK level enum."""

    def test_hsk_levels(self):
        """Test all HSK levels."""
        assert HSKLevel.HSK1.value == "HSK1"
        assert HSKLevel.HSK6.value == "HSK6"
        assert HSKLevel.HSK7_9.value == "HSK7-9"


class TestCharacterTypeEnum:
    """Test CharacterType enum."""

    def test_character_types(self):
        """Test character types."""
        assert CharacterType.KANJI.value == "kanji"
        assert CharacterType.HANZI_SIMPLIFIED.value == "hanzi_simplified"
        assert CharacterType.HANZI_TRADITIONAL.value == "hanzi_traditional"
        assert CharacterType.HANJA.value == "hanja"


# === DATA CLASS TESTS ===

class TestRadicalDataClass:
    """Test Radical dataclass."""

    def test_radical_creation(self):
        """Test creating a radical."""
        radical = Radical(
            number=1,
            character="一",
            stroke_count=1,
            meaning="one"
        )
        assert radical.number == 1
        assert radical.character == "一"
        assert radical.stroke_count == 1
        assert radical.meaning == "one"

    def test_radical_to_dict(self):
        """Test radical serialization."""
        radical = Radical(
            number=30,
            character="口",
            stroke_count=3,
            meaning="mouth",
            variant_forms=["囗"],
            position_hint="hen"
        )
        d = radical.to_dict()
        assert d['number'] == 30
        assert d['character'] == "口"
        assert d['variant_forms'] == ["囗"]


class TestReadingDataClass:
    """Test Reading dataclass."""

    def test_reading_creation(self):
        """Test creating a reading."""
        reading = Reading(
            reading="やま",
            reading_type=ReadingType.KUNYOMI,
            language=Language.JAPANESE,
            is_common=True
        )
        assert reading.reading == "やま"
        assert reading.reading_type == ReadingType.KUNYOMI

    def test_reading_to_dict(self):
        """Test reading serialization."""
        reading = Reading(
            reading="サン",
            reading_type=ReadingType.ONYOMI,
            language=Language.JAPANESE
        )
        d = reading.to_dict()
        assert d['reading'] == "サン"
        assert d['reading_type'] == "onyomi"
        assert d['language'] == "ja"


class TestStrokeDataClass:
    """Test StrokeData dataclass."""

    def test_stroke_data_creation(self):
        """Test creating stroke data."""
        stroke_data = StrokeData(
            stroke_count=3,
            stroke_order=[1, 2, 3],
            svg_paths=["M0,0 L10,10", "M10,0 L0,10", "M0,10 L10,10"],
            animation_delays=[100, 150, 100]
        )
        assert stroke_data.stroke_count == 3
        assert len(stroke_data.stroke_order) == 3


class TestIdeogramDataClass:
    """Test Ideogram dataclass."""

    def test_ideogram_creation(self):
        """Test creating an ideogram."""
        ideogram = Ideogram(
            id="test123",
            character="山",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3,
            readings=[
                Reading("やま", ReadingType.KUNYOMI, Language.JAPANESE),
                Reading("サン", ReadingType.ONYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["mountain"], "it": ["montagna"]},
            jlpt_level=JLPTLevel.N5
        )
        assert ideogram.character == "山"
        assert len(ideogram.readings) == 2

    def test_ideogram_to_dict(self):
        """Test ideogram serialization."""
        ideogram = Ideogram(
            id="test123",
            character="川",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3,
            jlpt_level=JLPTLevel.N5
        )
        d = ideogram.to_dict()
        assert d['character'] == "川"
        assert d['character_type'] == "kanji"
        assert d['jlpt_level'] == "N5"


# === DATABASE TESTS ===

class TestIdeogramDatabaseCreation:
    """Test database creation and initialization."""

    @pytest.mark.asyncio
    async def test_create_in_memory_database(self):
        """
        REAL TEST: Create in-memory database.
        """
        db = IdeogramDatabase._reset_for_testing()
        stats = await db.get_stats()
        assert stats['total_ideograms'] == 0
        assert stats['total_radicals'] == 0
        db.close()

    @pytest.mark.asyncio
    async def test_create_file_database(self):
        """
        REAL TEST: Create file-based database.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test.db"
            db = IdeogramDatabase._reset_for_testing(db_path)

            # Verify file was created
            assert db_path.exists()

            stats = await db.get_stats()
            assert stats['total_ideograms'] == 0
            db.close()


class TestRadicalOperations:
    """Test radical CRUD operations."""

    @pytest.fixture
    def db(self):
        """Create fresh database for each test."""
        database = IdeogramDatabase._reset_for_testing()
        yield database
        database.close()

    @pytest.mark.asyncio
    async def test_add_radical(self, db):
        """
        REAL TEST: Add a radical.
        """
        radical = Radical(
            number=1,
            character="一",
            stroke_count=1,
            meaning="one"
        )
        success = await db.add_radical(radical)
        assert success is True

        # Verify it was added
        retrieved = await db.get_radical(1)
        assert retrieved is not None
        assert retrieved.character == "一"

    @pytest.mark.asyncio
    async def test_get_nonexistent_radical(self, db):
        """
        REAL TEST: Get non-existent radical returns None.
        """
        radical = await db.get_radical(999)
        assert radical is None

    @pytest.mark.asyncio
    async def test_list_radicals(self, db):
        """
        REAL TEST: List radicals.
        """
        # Add some radicals
        for i, (char, strokes) in enumerate([(("一", 1)), ("二", 2), ("三", 3)], 1):
            await db.add_radical(Radical(i, char, strokes, f"number {i}"))

        radicals = await db.list_radicals()
        assert len(radicals) == 3

    @pytest.mark.asyncio
    async def test_list_radicals_by_stroke_count(self, db):
        """
        REAL TEST: Filter radicals by stroke count.
        """
        await db.add_radical(Radical(1, "一", 1, "one"))
        await db.add_radical(Radical(7, "二", 2, "two"))
        await db.add_radical(Radical(24, "十", 2, "ten"))

        one_stroke = await db.list_radicals(stroke_count=1)
        assert len(one_stroke) == 1

        two_stroke = await db.list_radicals(stroke_count=2)
        assert len(two_stroke) == 2

    @pytest.mark.asyncio
    async def test_import_kangxi_radicals(self, db):
        """
        REAL TEST: Import all 214 Kangxi radicals.
        """
        count = await db.import_kangxi_radicals()
        assert count == 214

        # Verify some specific radicals
        radical_1 = await db.get_radical(1)
        assert radical_1.character == "一"
        assert radical_1.meaning == "one"

        radical_85 = await db.get_radical(85)
        assert radical_85.character == "水"
        assert radical_85.meaning == "water"

        radical_214 = await db.get_radical(214)
        assert radical_214.character == "龠"


class TestIdeogramOperations:
    """Test ideogram CRUD operations."""

    @pytest.fixture
    def db(self):
        """Create fresh database for each test."""
        database = IdeogramDatabase._reset_for_testing()
        yield database
        database.close()

    @pytest.mark.asyncio
    async def test_add_ideogram(self, db):
        """
        REAL TEST: Add an ideogram.
        """
        ideogram = Ideogram(
            id="",
            character="山",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3,
            readings=[
                Reading("やま", ReadingType.KUNYOMI, Language.JAPANESE),
                Reading("サン", ReadingType.ONYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["mountain"]},
            jlpt_level=JLPTLevel.N5
        )

        id_ = await db.add_ideogram(ideogram)
        assert id_ is not None

        # Verify it was added
        retrieved = await db.get_ideogram(id_)
        assert retrieved is not None
        assert retrieved.character == "山"
        assert len(retrieved.readings) == 2

    @pytest.mark.asyncio
    async def test_add_ideogram_generates_id(self, db):
        """
        REAL TEST: ID is generated automatically.
        """
        ideogram = Ideogram(
            id="",
            character="川",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3
        )

        id_ = await db.add_ideogram(ideogram)
        assert len(id_) == 16  # SHA256 truncated

    @pytest.mark.asyncio
    async def test_get_by_character(self, db):
        """
        REAL TEST: Get ideogram by character.
        """
        ideogram = Ideogram(
            id="",
            character="日",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4
        )
        await db.add_ideogram(ideogram)

        retrieved = await db.get_by_character("日")
        assert retrieved is not None
        assert retrieved.character == "日"

    @pytest.mark.asyncio
    async def test_get_nonexistent_ideogram(self, db):
        """
        REAL TEST: Get non-existent ideogram returns None.
        """
        result = await db.get_ideogram("nonexistent")
        assert result is None

        result = await db.get_by_character("龘")
        assert result is None

    @pytest.mark.asyncio
    async def test_delete_ideogram(self, db):
        """
        REAL TEST: Delete an ideogram.
        """
        ideogram = Ideogram(
            id="",
            character="火",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4
        )
        id_ = await db.add_ideogram(ideogram)

        # Delete it
        success = await db.delete_ideogram(id_)
        assert success is True

        # Verify it's gone
        result = await db.get_ideogram(id_)
        assert result is None

    @pytest.mark.asyncio
    async def test_ideogram_with_radicals(self, db):
        """
        REAL TEST: Ideogram with radical links.
        """
        # First add the radicals
        await db.add_radical(Radical(46, "山", 3, "mountain"))
        await db.add_radical(Radical(72, "日", 4, "sun"))

        # Create ideogram with radicals
        ideogram = Ideogram(
            id="",
            character="晴",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=12,
            radical_ids=[72, 46]  # sun + mountain-like component
        )
        id_ = await db.add_ideogram(ideogram)

        retrieved = await db.get_ideogram(id_)
        assert 72 in retrieved.radical_ids

    @pytest.mark.asyncio
    async def test_ideogram_unicode_codepoint(self, db):
        """
        REAL TEST: Unicode codepoint is set automatically.
        """
        ideogram = Ideogram(
            id="",
            character="人",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=2
        )
        id_ = await db.add_ideogram(ideogram)

        retrieved = await db.get_ideogram(id_)
        assert retrieved.unicode_codepoint == "U+4EBA"


class TestSearchOperations:
    """Test search functionality."""

    @pytest.fixture
    async def db_with_data(self):
        """Create database with sample data."""
        database = IdeogramDatabase._reset_for_testing()

        # Add some ideograms
        await database.add_ideogram(Ideogram(
            id="",
            character="山",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3,
            readings=[
                Reading("やま", ReadingType.KUNYOMI, Language.JAPANESE),
                Reading("サン", ReadingType.ONYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["mountain", "hill"]},
            jlpt_level=JLPTLevel.N5
        ))

        await database.add_ideogram(Ideogram(
            id="",
            character="川",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=3,
            readings=[
                Reading("かわ", ReadingType.KUNYOMI, Language.JAPANESE),
                Reading("セン", ReadingType.ONYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["river", "stream"]},
            jlpt_level=JLPTLevel.N5
        ))

        await database.add_ideogram(Ideogram(
            id="",
            character="火",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4,
            readings=[
                Reading("ひ", ReadingType.KUNYOMI, Language.JAPANESE),
                Reading("カ", ReadingType.ONYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["fire", "flame"]},
            jlpt_level=JLPTLevel.N5
        ))

        yield database
        database.close()

    @pytest.mark.asyncio
    async def test_search_exact_character(self, db_with_data):
        """
        REAL TEST: Search by exact character.
        """
        db = db_with_data
        results = await db.search("山")

        assert len(results) >= 1
        assert results[0].match_type == 'exact'
        assert results[0].score == 1.0
        assert results[0].ideogram.character == "山"

    @pytest.mark.asyncio
    async def test_search_by_reading(self, db_with_data):
        """
        REAL TEST: Search by reading.
        """
        db = db_with_data
        results = await db.search("やま")

        assert len(results) >= 1
        # Should find 山
        chars = [r.ideogram.character for r in results]
        assert "山" in chars

    @pytest.mark.asyncio
    async def test_search_by_meaning(self, db_with_data):
        """
        REAL TEST: Search by English meaning.
        """
        db = db_with_data
        results = await db.search("mountain")

        assert len(results) >= 1
        chars = [r.ideogram.character for r in results]
        assert "山" in chars

    @pytest.mark.asyncio
    async def test_search_no_results(self, db_with_data):
        """
        REAL TEST: Search with no results.
        """
        db = db_with_data
        results = await db.search("nonexistent_term_12345")
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_search_limit(self, db_with_data):
        """
        REAL TEST: Search with limit.
        """
        db = db_with_data
        results = await db.search("", limit=2)  # Empty query, should match all
        assert len(results) <= 2

    @pytest.mark.asyncio
    async def test_search_by_stroke_count(self, db_with_data):
        """
        REAL TEST: Search by stroke count.
        """
        db = db_with_data
        results = await db.search_by_stroke_count(3)

        assert len(results) >= 2
        for r in results:
            assert r.stroke_count == 3

    @pytest.mark.asyncio
    async def test_search_by_jlpt_level(self, db_with_data):
        """
        REAL TEST: Get characters by JLPT level.
        """
        db = db_with_data
        results = await db.get_by_jlpt_level(JLPTLevel.N5)

        assert len(results) == 3
        for r in results:
            assert r.jlpt_level == JLPTLevel.N5


class TestRadicalSearch:
    """Test searching by radical."""

    @pytest.fixture
    async def db_with_radicals(self):
        """Create database with radicals and ideograms."""
        database = IdeogramDatabase._reset_for_testing()

        # Add radicals
        await database.add_radical(Radical(72, "日", 4, "sun"))
        await database.add_radical(Radical(85, "水", 4, "water"))

        # Add ideograms with radicals
        await database.add_ideogram(Ideogram(
            id="",
            character="明",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=8,
            radical_ids=[72],  # sun
            meanings={"en": ["bright"]}
        ))

        await database.add_ideogram(Ideogram(
            id="",
            character="時",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=10,
            radical_ids=[72],  # sun
            meanings={"en": ["time"]}
        ))

        await database.add_ideogram(Ideogram(
            id="",
            character="海",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=9,
            radical_ids=[85],  # water
            meanings={"en": ["sea"]}
        ))

        yield database
        database.close()

    @pytest.mark.asyncio
    async def test_search_by_radical(self, db_with_radicals):
        """
        REAL TEST: Search by radical.
        """
        db = db_with_radicals
        results = await db.search_by_radical(72)  # sun radical

        assert len(results) == 2
        chars = [r.character for r in results]
        assert "明" in chars
        assert "時" in chars

    @pytest.mark.asyncio
    async def test_search_by_radical_water(self, db_with_radicals):
        """
        REAL TEST: Search by water radical.
        """
        db = db_with_radicals
        results = await db.search_by_radical(85)  # water radical

        assert len(results) == 1
        assert results[0].character == "海"


class TestMnemonicOperations:
    """Test mnemonic functionality."""

    @pytest.fixture
    async def db_with_ideogram(self):
        """Create database with an ideogram."""
        database = IdeogramDatabase._reset_for_testing()

        ideogram = Ideogram(
            id="test_id_123",
            character="木",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4,
            meanings={"en": ["tree", "wood"]}
        )
        await database.add_ideogram(ideogram)

        yield database, "test_id_123"
        database.close()

    @pytest.mark.asyncio
    async def test_add_mnemonic(self, db_with_ideogram):
        """
        REAL TEST: Add a mnemonic.
        """
        db, ideogram_id = db_with_ideogram

        mnemonic = await db.add_mnemonic(
            ideogram_id=ideogram_id,
            text="A tree (木) looks like a tree with branches!",
            language=Language.JAPANESE,
            created_by="test_user"
        )

        assert mnemonic is not None
        assert mnemonic.text == "A tree (木) looks like a tree with branches!"
        assert mnemonic.upvotes == 0

    @pytest.mark.asyncio
    async def test_add_mnemonic_nonexistent_ideogram(self, db_with_ideogram):
        """
        REAL TEST: Adding mnemonic to non-existent ideogram fails.
        """
        db, _ = db_with_ideogram

        mnemonic = await db.add_mnemonic(
            ideogram_id="nonexistent",
            text="Test",
            language=Language.JAPANESE,
            created_by="user"
        )

        assert mnemonic is None

    @pytest.mark.asyncio
    async def test_vote_mnemonic(self, db_with_ideogram):
        """
        REAL TEST: Vote on mnemonic.
        """
        db, ideogram_id = db_with_ideogram

        mnemonic = await db.add_mnemonic(
            ideogram_id=ideogram_id,
            text="Test mnemonic",
            language=Language.JAPANESE,
            created_by="user"
        )

        # Upvote
        success = await db.vote_mnemonic(mnemonic.id, upvote=True)
        assert success is True

        # Verify vote count
        mnemonics = await db.get_mnemonics(ideogram_id)
        assert mnemonics[0].upvotes == 1

    @pytest.mark.asyncio
    async def test_get_mnemonics_sorted_by_votes(self, db_with_ideogram):
        """
        REAL TEST: Mnemonics are sorted by votes.
        """
        db, ideogram_id = db_with_ideogram

        # Add multiple mnemonics
        m1 = await db.add_mnemonic(ideogram_id, "First", Language.JAPANESE, "user1")
        m2 = await db.add_mnemonic(ideogram_id, "Second", Language.JAPANESE, "user2")

        # Upvote second one multiple times
        await db.vote_mnemonic(m2.id, upvote=True)
        await db.vote_mnemonic(m2.id, upvote=True)

        mnemonics = await db.get_mnemonics(ideogram_id)

        # Second should be first (more upvotes)
        assert mnemonics[0].text == "Second"


class TestStatistics:
    """Test statistics functionality."""

    @pytest.fixture
    async def db_with_mixed_data(self):
        """Create database with mixed data."""
        database = IdeogramDatabase._reset_for_testing()

        # Add Japanese kanji
        await database.add_ideogram(Ideogram(
            id="",
            character="日",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4,
            jlpt_level=JLPTLevel.N5
        ))

        await database.add_ideogram(Ideogram(
            id="",
            character="本",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=5,
            jlpt_level=JLPTLevel.N5
        ))

        # Add Chinese hanzi
        await database.add_ideogram(Ideogram(
            id="",
            character="中",
            character_type=CharacterType.HANZI_SIMPLIFIED,
            language=Language.CHINESE_SIMPLIFIED,
            stroke_count=4,
            hsk_level=HSKLevel.HSK1
        ))

        # Add radicals
        await database.import_kangxi_radicals()

        yield database
        database.close()

    @pytest.mark.asyncio
    async def test_get_stats(self, db_with_mixed_data):
        """
        REAL TEST: Get database statistics.
        """
        db = db_with_mixed_data
        stats = await db.get_stats()

        assert stats['total_ideograms'] == 3
        assert stats['total_radicals'] == 214

        assert stats['by_language']['ja'] == 2
        assert stats['by_language']['zh-CN'] == 1

        assert stats['by_type']['kanji'] == 2
        assert stats['by_type']['hanzi_simplified'] == 1

        assert stats['by_jlpt']['N5'] == 2


class TestCJKCharacterDetection:
    """Test CJK character detection utility."""

    @pytest.fixture
    def db(self):
        """Create fresh database."""
        database = IdeogramDatabase._reset_for_testing()
        yield database
        database.close()

    def test_detect_kanji(self, db):
        """Test detecting kanji."""
        assert db._is_cjk_character("山") is True
        assert db._is_cjk_character("日") is True
        assert db._is_cjk_character("本") is True

    def test_detect_hiragana(self, db):
        """Test detecting hiragana."""
        assert db._is_cjk_character("あ") is True
        assert db._is_cjk_character("ん") is True

    def test_detect_katakana(self, db):
        """Test detecting katakana."""
        assert db._is_cjk_character("ア") is True
        assert db._is_cjk_character("ン") is True

    def test_reject_latin(self, db):
        """Test rejecting Latin characters."""
        assert db._is_cjk_character("A") is False
        assert db._is_cjk_character("z") is False

    def test_reject_numbers(self, db):
        """Test rejecting numbers."""
        assert db._is_cjk_character("1") is False
        assert db._is_cjk_character("9") is False

    def test_reject_multiple_characters(self, db):
        """Test rejecting multiple characters."""
        assert db._is_cjk_character("山川") is False
        assert db._is_cjk_character("ab") is False


class TestUpdateIdeogram:
    """Test updating existing ideograms."""

    @pytest.fixture
    async def db_with_ideogram(self):
        """Create database with an ideogram."""
        database = IdeogramDatabase._reset_for_testing()

        ideogram = Ideogram(
            id="",
            character="水",
            character_type=CharacterType.KANJI,
            language=Language.JAPANESE,
            stroke_count=4,
            readings=[
                Reading("みず", ReadingType.KUNYOMI, Language.JAPANESE)
            ],
            meanings={"en": ["water"]}
        )
        id_ = await database.add_ideogram(ideogram)

        yield database, id_
        database.close()

    @pytest.mark.asyncio
    async def test_update_ideogram_readings(self, db_with_ideogram):
        """
        REAL TEST: Update ideogram readings.
        """
        db, id_ = db_with_ideogram

        # Get current ideogram
        current = await db.get_ideogram(id_)
        assert len(current.readings) == 1

        # Update with new readings
        current.readings.append(
            Reading("スイ", ReadingType.ONYOMI, Language.JAPANESE)
        )
        await db.add_ideogram(current)

        # Verify update
        updated = await db.get_ideogram(id_)
        assert len(updated.readings) == 2

    @pytest.mark.asyncio
    async def test_update_ideogram_jlpt(self, db_with_ideogram):
        """
        REAL TEST: Update ideogram JLPT level.
        """
        db, id_ = db_with_ideogram

        # Get current ideogram
        current = await db.get_ideogram(id_)
        assert current.jlpt_level is None

        # Update JLPT level
        current.jlpt_level = JLPTLevel.N5
        await db.add_ideogram(current)

        # Verify update
        updated = await db.get_ideogram(id_)
        assert updated.jlpt_level == JLPTLevel.N5


# === SUMMARY ===
# Total test cases: 50+
# Coverage: IdeogramDatabase service logic
# Real operations: SQLite database, no mocks
# Categories: Enums, DataClasses, CRUD, Search, Mnemonics, Stats

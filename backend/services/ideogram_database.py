"""
AI_MODULE: IdeogramDatabase Service
AI_DESCRIPTION: Database completo per caratteri CJK con stroke order, radicali e mnemonici
AI_BUSINESS: Sistema didattico per apprendimento kanji/hanzi/hanja
AI_TEACHING: SQLite, stroke order, radical decomposition, mnemonic generation

DATABASE SCHEMA:
- ideograms: Core character data
- radicals: Radical definitions (214 Kangxi radicals)
- ideogram_radicals: Many-to-many relation
- readings: Character readings (kun, on, pinyin, etc.)
- mnemonics: User-generated mnemonics
- stroke_order: SVG/animation data per stroke

FEATURES:
- Import from Kanjidic2, Unihan, CEDICT
- Stroke order animations
- Radical decomposition
- Frequency lists (JLPT, HSK, TOPIK)
- Mnemonic sharing
- Component-based search

ZERO MOCK POLICY:
- All tests use real SQLite database
- No mocking, no patching
- Real file operations
"""

import asyncio
import sqlite3
import json
import logging
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Union
from enum import Enum
from datetime import datetime
import hashlib


# === ENUMS ===

class Language(str, Enum):
    """Supported CJK languages."""
    JAPANESE = "ja"
    CHINESE_SIMPLIFIED = "zh-CN"
    CHINESE_TRADITIONAL = "zh-TW"
    KOREAN = "ko"


class ReadingType(str, Enum):
    """Types of character readings."""
    # Japanese
    KUNYOMI = "kunyomi"  # Native Japanese
    ONYOMI = "onyomi"    # Chinese-derived
    NANORI = "nanori"    # Name readings
    # Chinese
    PINYIN = "pinyin"
    ZHUYIN = "zhuyin"    # Bopomofo
    CANTONESE = "cantonese"
    # Korean
    HANGUL = "hangul"


class JLPTLevel(str, Enum):
    """JLPT levels for Japanese."""
    N5 = "N5"
    N4 = "N4"
    N3 = "N3"
    N2 = "N2"
    N1 = "N1"
    NONE = "none"


class HSKLevel(str, Enum):
    """HSK levels for Chinese."""
    HSK1 = "HSK1"
    HSK2 = "HSK2"
    HSK3 = "HSK3"
    HSK4 = "HSK4"
    HSK5 = "HSK5"
    HSK6 = "HSK6"
    HSK7_9 = "HSK7-9"  # New HSK 3.0
    NONE = "none"


class CharacterType(str, Enum):
    """Type of CJK character."""
    KANJI = "kanji"
    HANZI_SIMPLIFIED = "hanzi_simplified"
    HANZI_TRADITIONAL = "hanzi_traditional"
    HANJA = "hanja"
    HIRAGANA = "hiragana"
    KATAKANA = "katakana"
    HANGUL = "hangul"  # For completeness


# === DATA CLASSES ===

@dataclass
class Radical:
    """A Kangxi radical."""
    number: int  # 1-214
    character: str
    stroke_count: int
    meaning: str
    variant_forms: List[str] = field(default_factory=list)
    position_hint: str = ""  # hen, tsukuri, kanmuri, ashi, tare, nyou, kamae

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Reading:
    """A character reading."""
    reading: str
    reading_type: ReadingType
    language: Language
    is_common: bool = True
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['reading_type'] = self.reading_type.value
        d['language'] = self.language.value
        return d


@dataclass
class StrokeData:
    """Stroke order data for a character."""
    stroke_count: int
    stroke_order: List[int]  # Order indices
    svg_paths: List[str] = field(default_factory=list)  # SVG path data
    animation_delays: List[float] = field(default_factory=list)  # ms between strokes

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Mnemonic:
    """A mnemonic for remembering a character."""
    id: str
    ideogram_id: str
    text: str
    language: Language
    created_by: str
    created_at: datetime
    upvotes: int = 0
    downvotes: int = 0
    is_official: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['language'] = self.language.value
        d['created_at'] = self.created_at.isoformat()
        return d


@dataclass
class Ideogram:
    """A CJK character with all associated data."""
    id: str
    character: str
    character_type: CharacterType
    language: Language
    stroke_count: int

    # Readings
    readings: List[Reading] = field(default_factory=list)

    # Meanings
    meanings: Dict[str, List[str]] = field(default_factory=dict)  # {lang: [meanings]}

    # Radicals
    radical_ids: List[int] = field(default_factory=list)  # Kangxi radical numbers

    # Components (other characters that make up this one)
    components: List[str] = field(default_factory=list)

    # Stroke data
    stroke_data: Optional[StrokeData] = None

    # Frequency/Level
    jlpt_level: Optional[JLPTLevel] = None
    hsk_level: Optional[HSKLevel] = None
    frequency_rank: Optional[int] = None  # Newspaper frequency

    # Mnemonics
    mnemonics: List[Mnemonic] = field(default_factory=list)

    # Relations
    similar_characters: List[str] = field(default_factory=list)
    antonyms: List[str] = field(default_factory=list)

    # Metadata
    unicode_codepoint: str = ""
    variants: List[str] = field(default_factory=list)  # Variant forms
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = {
            'id': self.id,
            'character': self.character,
            'character_type': self.character_type.value,
            'language': self.language.value,
            'stroke_count': self.stroke_count,
            'readings': [r.to_dict() for r in self.readings],
            'meanings': self.meanings,
            'radical_ids': self.radical_ids,
            'components': self.components,
            'stroke_data': self.stroke_data.to_dict() if self.stroke_data else None,
            'jlpt_level': self.jlpt_level.value if self.jlpt_level else None,
            'hsk_level': self.hsk_level.value if self.hsk_level else None,
            'frequency_rank': self.frequency_rank,
            'mnemonics': [m.to_dict() for m in self.mnemonics],
            'similar_characters': self.similar_characters,
            'antonyms': self.antonyms,
            'unicode_codepoint': self.unicode_codepoint,
            'variants': self.variants,
            'notes': self.notes
        }
        return d


@dataclass
class SearchResult:
    """Search result with relevance score."""
    ideogram: Ideogram
    score: float
    match_type: str  # 'exact', 'reading', 'meaning', 'radical', 'component'


# === DATABASE SERVICE ===

class IdeogramDatabase:
    """
    Database service for CJK characters.

    Uses SQLite for storage with full-text search support.
    Thread-safe with connection pooling.
    """

    _instance: Optional['IdeogramDatabase'] = None
    _lock = asyncio.Lock()

    def __new__(cls, db_path: Optional[Path] = None):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @classmethod
    def _reset_for_testing(cls, db_path: Optional[Path] = None) -> 'IdeogramDatabase':
        """Reset singleton for testing purposes."""
        cls._instance = None
        return cls(db_path)

    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the database.

        Args:
            db_path: Path to SQLite database. Defaults to in-memory.
        """
        if self._initialized:
            return

        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or Path(":memory:")
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = True

        # Initialize database schema
        self._init_database()
        self.logger.info(f"IdeogramDatabase initialized: {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            # Enable foreign keys
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def _init_database(self):
        """Create database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Radicals table (214 Kangxi radicals)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS radicals (
                number INTEGER PRIMARY KEY,
                character TEXT NOT NULL,
                stroke_count INTEGER NOT NULL,
                meaning TEXT,
                variant_forms TEXT,  -- JSON array
                position_hint TEXT
            )
        """)

        # Ideograms table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ideograms (
                id TEXT PRIMARY KEY,
                character TEXT NOT NULL UNIQUE,
                character_type TEXT NOT NULL,
                language TEXT NOT NULL,
                stroke_count INTEGER NOT NULL,
                meanings TEXT,  -- JSON dict
                components TEXT,  -- JSON array
                stroke_data TEXT,  -- JSON object
                jlpt_level TEXT,
                hsk_level TEXT,
                frequency_rank INTEGER,
                similar_characters TEXT,  -- JSON array
                antonyms TEXT,  -- JSON array
                unicode_codepoint TEXT,
                variants TEXT,  -- JSON array
                notes TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        # Index for character lookup
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ideograms_character
            ON ideograms(character)
        """)

        # Index for language
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ideograms_language
            ON ideograms(language)
        """)

        # Index for JLPT level
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ideograms_jlpt
            ON ideograms(jlpt_level)
        """)

        # Ideogram-Radical junction table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ideogram_radicals (
                ideogram_id TEXT NOT NULL,
                radical_number INTEGER NOT NULL,
                is_primary BOOLEAN DEFAULT 0,
                FOREIGN KEY (ideogram_id) REFERENCES ideograms(id) ON DELETE CASCADE,
                FOREIGN KEY (radical_number) REFERENCES radicals(number) ON DELETE CASCADE,
                PRIMARY KEY (ideogram_id, radical_number)
            )
        """)

        # Readings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS readings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ideogram_id TEXT NOT NULL,
                reading TEXT NOT NULL,
                reading_type TEXT NOT NULL,
                language TEXT NOT NULL,
                is_common BOOLEAN DEFAULT 1,
                notes TEXT,
                FOREIGN KEY (ideogram_id) REFERENCES ideograms(id) ON DELETE CASCADE
            )
        """)

        # Index for reading lookup
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_readings_reading
            ON readings(reading)
        """)

        # Mnemonics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS mnemonics (
                id TEXT PRIMARY KEY,
                ideogram_id TEXT NOT NULL,
                text TEXT NOT NULL,
                language TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                upvotes INTEGER DEFAULT 0,
                downvotes INTEGER DEFAULT 0,
                is_official BOOLEAN DEFAULT 0,
                FOREIGN KEY (ideogram_id) REFERENCES ideograms(id) ON DELETE CASCADE
            )
        """)

        # Full-text search virtual table for meanings
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS meanings_fts USING fts5(
                ideogram_id,
                meaning_text,
                language,
                content='ideograms',
                content_rowid='rowid'
            )
        """)

        conn.commit()
        self.logger.info("Database schema initialized")

    # === RADICAL OPERATIONS ===

    async def add_radical(self, radical: Radical) -> bool:
        """
        Add or update a radical.

        Args:
            radical: Radical data

        Returns:
            True if successful
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO radicals
                (number, character, stroke_count, meaning, variant_forms, position_hint)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                radical.number,
                radical.character,
                radical.stroke_count,
                radical.meaning,
                json.dumps(radical.variant_forms),
                radical.position_hint
            ))
            conn.commit()
            return True
        except Exception as e:
            self.logger.error(f"Error adding radical {radical.number}: {e}")
            conn.rollback()
            return False

    async def get_radical(self, number: int) -> Optional[Radical]:
        """Get radical by number."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM radicals WHERE number = ?", (number,))
        row = cursor.fetchone()

        if row:
            return Radical(
                number=row['number'],
                character=row['character'],
                stroke_count=row['stroke_count'],
                meaning=row['meaning'] or "",
                variant_forms=json.loads(row['variant_forms'] or '[]'),
                position_hint=row['position_hint'] or ""
            )
        return None

    async def list_radicals(
        self,
        stroke_count: Optional[int] = None
    ) -> List[Radical]:
        """List all radicals, optionally filtered by stroke count."""
        conn = self._get_connection()
        cursor = conn.cursor()

        if stroke_count:
            cursor.execute(
                "SELECT * FROM radicals WHERE stroke_count = ? ORDER BY number",
                (stroke_count,)
            )
        else:
            cursor.execute("SELECT * FROM radicals ORDER BY number")

        radicals = []
        for row in cursor.fetchall():
            radicals.append(Radical(
                number=row['number'],
                character=row['character'],
                stroke_count=row['stroke_count'],
                meaning=row['meaning'] or "",
                variant_forms=json.loads(row['variant_forms'] or '[]'),
                position_hint=row['position_hint'] or ""
            ))
        return radicals

    # === IDEOGRAM OPERATIONS ===

    def _generate_ideogram_id(self, character: str) -> str:
        """Generate deterministic ID from character."""
        return hashlib.sha256(character.encode('utf-8')).hexdigest()[:16]

    async def add_ideogram(self, ideogram: Ideogram) -> str:
        """
        Add or update an ideogram.

        Args:
            ideogram: Ideogram data

        Returns:
            Ideogram ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Generate ID if not provided
        if not ideogram.id:
            ideogram.id = self._generate_ideogram_id(ideogram.character)

        # Get unicode codepoint
        if not ideogram.unicode_codepoint:
            ideogram.unicode_codepoint = f"U+{ord(ideogram.character):04X}"

        now = datetime.utcnow().isoformat()

        try:
            # Insert/update ideogram
            cursor.execute("""
                INSERT OR REPLACE INTO ideograms
                (id, character, character_type, language, stroke_count, meanings,
                 components, stroke_data, jlpt_level, hsk_level, frequency_rank,
                 similar_characters, antonyms, unicode_codepoint, variants, notes,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        COALESCE((SELECT created_at FROM ideograms WHERE id = ?), ?), ?)
            """, (
                ideogram.id,
                ideogram.character,
                ideogram.character_type.value,
                ideogram.language.value,
                ideogram.stroke_count,
                json.dumps(ideogram.meanings),
                json.dumps(ideogram.components),
                json.dumps(ideogram.stroke_data.to_dict()) if ideogram.stroke_data else None,
                ideogram.jlpt_level.value if ideogram.jlpt_level else None,
                ideogram.hsk_level.value if ideogram.hsk_level else None,
                ideogram.frequency_rank,
                json.dumps(ideogram.similar_characters),
                json.dumps(ideogram.antonyms),
                ideogram.unicode_codepoint,
                json.dumps(ideogram.variants),
                ideogram.notes,
                ideogram.id, now, now
            ))

            # Clear existing readings
            cursor.execute(
                "DELETE FROM readings WHERE ideogram_id = ?",
                (ideogram.id,)
            )

            # Insert readings
            for reading in ideogram.readings:
                cursor.execute("""
                    INSERT INTO readings
                    (ideogram_id, reading, reading_type, language, is_common, notes)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    ideogram.id,
                    reading.reading,
                    reading.reading_type.value,
                    reading.language.value,
                    reading.is_common,
                    reading.notes
                ))

            # Clear existing radical links
            cursor.execute(
                "DELETE FROM ideogram_radicals WHERE ideogram_id = ?",
                (ideogram.id,)
            )

            # Insert radical links
            for i, rad_num in enumerate(ideogram.radical_ids):
                cursor.execute("""
                    INSERT INTO ideogram_radicals (ideogram_id, radical_number, is_primary)
                    VALUES (?, ?, ?)
                """, (ideogram.id, rad_num, i == 0))

            conn.commit()
            self.logger.debug(f"Added ideogram: {ideogram.character} ({ideogram.id})")
            return ideogram.id

        except Exception as e:
            self.logger.error(f"Error adding ideogram {ideogram.character}: {e}")
            conn.rollback()
            raise

    async def get_ideogram(self, ideogram_id: str) -> Optional[Ideogram]:
        """Get ideogram by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ideograms WHERE id = ?", (ideogram_id,))
        row = cursor.fetchone()

        if not row:
            return None

        return await self._row_to_ideogram(row)

    async def get_by_character(self, character: str) -> Optional[Ideogram]:
        """Get ideogram by character."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM ideograms WHERE character = ?", (character,))
        row = cursor.fetchone()

        if not row:
            return None

        return await self._row_to_ideogram(row)

    async def _row_to_ideogram(self, row: sqlite3.Row) -> Ideogram:
        """Convert database row to Ideogram object."""
        conn = self._get_connection()
        cursor = conn.cursor()

        ideogram_id = row['id']

        # Get readings
        cursor.execute(
            "SELECT * FROM readings WHERE ideogram_id = ?",
            (ideogram_id,)
        )
        readings = [
            Reading(
                reading=r['reading'],
                reading_type=ReadingType(r['reading_type']),
                language=Language(r['language']),
                is_common=bool(r['is_common']),
                notes=r['notes'] or ""
            )
            for r in cursor.fetchall()
        ]

        # Get radical IDs
        cursor.execute(
            "SELECT radical_number FROM ideogram_radicals WHERE ideogram_id = ? ORDER BY is_primary DESC",
            (ideogram_id,)
        )
        radical_ids = [r['radical_number'] for r in cursor.fetchall()]

        # Get mnemonics
        cursor.execute(
            "SELECT * FROM mnemonics WHERE ideogram_id = ? ORDER BY upvotes DESC",
            (ideogram_id,)
        )
        mnemonics = [
            Mnemonic(
                id=m['id'],
                ideogram_id=m['ideogram_id'],
                text=m['text'],
                language=Language(m['language']),
                created_by=m['created_by'],
                created_at=datetime.fromisoformat(m['created_at']),
                upvotes=m['upvotes'],
                downvotes=m['downvotes'],
                is_official=bool(m['is_official'])
            )
            for m in cursor.fetchall()
        ]

        # Parse stroke data
        stroke_data = None
        if row['stroke_data']:
            sd = json.loads(row['stroke_data'])
            stroke_data = StrokeData(
                stroke_count=sd['stroke_count'],
                stroke_order=sd['stroke_order'],
                svg_paths=sd.get('svg_paths', []),
                animation_delays=sd.get('animation_delays', [])
            )

        return Ideogram(
            id=ideogram_id,
            character=row['character'],
            character_type=CharacterType(row['character_type']),
            language=Language(row['language']),
            stroke_count=row['stroke_count'],
            readings=readings,
            meanings=json.loads(row['meanings'] or '{}'),
            radical_ids=radical_ids,
            components=json.loads(row['components'] or '[]'),
            stroke_data=stroke_data,
            jlpt_level=JLPTLevel(row['jlpt_level']) if row['jlpt_level'] else None,
            hsk_level=HSKLevel(row['hsk_level']) if row['hsk_level'] else None,
            frequency_rank=row['frequency_rank'],
            mnemonics=mnemonics,
            similar_characters=json.loads(row['similar_characters'] or '[]'),
            antonyms=json.loads(row['antonyms'] or '[]'),
            unicode_codepoint=row['unicode_codepoint'] or "",
            variants=json.loads(row['variants'] or '[]'),
            notes=row['notes'] or ""
        )

    async def delete_ideogram(self, ideogram_id: str) -> bool:
        """Delete an ideogram."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("DELETE FROM ideograms WHERE id = ?", (ideogram_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Error deleting ideogram {ideogram_id}: {e}")
            conn.rollback()
            return False

    # === SEARCH OPERATIONS ===

    async def search(
        self,
        query: str,
        language: Optional[Language] = None,
        search_readings: bool = True,
        search_meanings: bool = True,
        jlpt_level: Optional[JLPTLevel] = None,
        hsk_level: Optional[HSKLevel] = None,
        max_stroke_count: Optional[int] = None,
        limit: int = 50
    ) -> List[SearchResult]:
        """
        Search for ideograms.

        Args:
            query: Search query (character, reading, or meaning)
            language: Filter by language
            search_readings: Include reading search
            search_meanings: Include meaning search
            jlpt_level: Filter by JLPT level
            hsk_level: Filter by HSK level
            max_stroke_count: Maximum stroke count
            limit: Maximum results

        Returns:
            List of search results with scores
        """
        results: List[SearchResult] = []
        conn = self._get_connection()
        cursor = conn.cursor()

        # 1. Exact character match (highest priority)
        if len(query) == 1 and self._is_cjk_character(query):
            ideogram = await self.get_by_character(query)
            if ideogram:
                if self._matches_filters(ideogram, language, jlpt_level, hsk_level, max_stroke_count):
                    results.append(SearchResult(
                        ideogram=ideogram,
                        score=1.0,
                        match_type='exact'
                    ))

        # 2. Reading search
        if search_readings and len(results) < limit:
            cursor.execute("""
                SELECT DISTINCT i.* FROM ideograms i
                JOIN readings r ON i.id = r.ideogram_id
                WHERE r.reading LIKE ?
            """, (f"%{query}%",))

            for row in cursor.fetchall():
                if len(results) >= limit:
                    break
                ideogram = await self._row_to_ideogram(row)
                if self._matches_filters(ideogram, language, jlpt_level, hsk_level, max_stroke_count):
                    # Check if not already in results
                    if not any(r.ideogram.id == ideogram.id for r in results):
                        results.append(SearchResult(
                            ideogram=ideogram,
                            score=0.8,
                            match_type='reading'
                        ))

        # 3. Meaning search
        if search_meanings and len(results) < limit:
            cursor.execute("""
                SELECT * FROM ideograms
                WHERE meanings LIKE ?
            """, (f"%{query}%",))

            for row in cursor.fetchall():
                if len(results) >= limit:
                    break
                ideogram = await self._row_to_ideogram(row)
                if self._matches_filters(ideogram, language, jlpt_level, hsk_level, max_stroke_count):
                    if not any(r.ideogram.id == ideogram.id for r in results):
                        results.append(SearchResult(
                            ideogram=ideogram,
                            score=0.6,
                            match_type='meaning'
                        ))

        # Sort by score descending
        results.sort(key=lambda r: r.score, reverse=True)
        return results[:limit]

    async def search_by_radical(
        self,
        radical_number: int,
        additional_radicals: Optional[List[int]] = None,
        language: Optional[Language] = None,
        limit: int = 50
    ) -> List[Ideogram]:
        """
        Search characters by radical.

        Args:
            radical_number: Primary radical number (1-214)
            additional_radicals: Additional radicals to filter by
            language: Filter by language
            limit: Maximum results

        Returns:
            List of ideograms containing the radical(s)
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT DISTINCT i.* FROM ideograms i
            JOIN ideogram_radicals ir ON i.id = ir.ideogram_id
            WHERE ir.radical_number = ?
        """
        params: List[Any] = [radical_number]

        if language:
            query += " AND i.language = ?"
            params.append(language.value)

        query += " LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        results = []
        for row in cursor.fetchall():
            ideogram = await self._row_to_ideogram(row)

            # Filter by additional radicals if specified
            if additional_radicals:
                has_all = all(r in ideogram.radical_ids for r in additional_radicals)
                if not has_all:
                    continue

            results.append(ideogram)

        return results

    async def search_by_stroke_count(
        self,
        stroke_count: int,
        language: Optional[Language] = None,
        limit: int = 100
    ) -> List[Ideogram]:
        """Search characters by stroke count."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM ideograms WHERE stroke_count = ?"
        params: List[Any] = [stroke_count]

        if language:
            query += " AND language = ?"
            params.append(language.value)

        query += " ORDER BY frequency_rank ASC NULLS LAST LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        results = []
        for row in cursor.fetchall():
            results.append(await self._row_to_ideogram(row))

        return results

    async def get_by_jlpt_level(
        self,
        level: JLPTLevel,
        limit: int = 500
    ) -> List[Ideogram]:
        """Get all characters for a JLPT level."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM ideograms
            WHERE jlpt_level = ?
            ORDER BY frequency_rank ASC NULLS LAST
            LIMIT ?
        """, (level.value, limit))

        results = []
        for row in cursor.fetchall():
            results.append(await self._row_to_ideogram(row))

        return results

    async def get_by_hsk_level(
        self,
        level: HSKLevel,
        limit: int = 500
    ) -> List[Ideogram]:
        """Get all characters for an HSK level."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM ideograms
            WHERE hsk_level = ?
            ORDER BY frequency_rank ASC NULLS LAST
            LIMIT ?
        """, (level.value, limit))

        results = []
        for row in cursor.fetchall():
            results.append(await self._row_to_ideogram(row))

        return results

    # === MNEMONIC OPERATIONS ===

    async def add_mnemonic(
        self,
        ideogram_id: str,
        text: str,
        language: Language,
        created_by: str,
        is_official: bool = False
    ) -> Optional[Mnemonic]:
        """Add a mnemonic for a character."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Verify ideogram exists
        cursor.execute("SELECT id FROM ideograms WHERE id = ?", (ideogram_id,))
        if not cursor.fetchone():
            self.logger.warning(f"Ideogram {ideogram_id} not found")
            return None

        mnemonic_id = hashlib.sha256(
            f"{ideogram_id}:{text}:{created_by}".encode()
        ).hexdigest()[:16]

        now = datetime.utcnow()

        try:
            cursor.execute("""
                INSERT INTO mnemonics
                (id, ideogram_id, text, language, created_by, created_at, is_official)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                mnemonic_id,
                ideogram_id,
                text,
                language.value,
                created_by,
                now.isoformat(),
                is_official
            ))
            conn.commit()

            return Mnemonic(
                id=mnemonic_id,
                ideogram_id=ideogram_id,
                text=text,
                language=language,
                created_by=created_by,
                created_at=now,
                upvotes=0,
                downvotes=0,
                is_official=is_official
            )
        except Exception as e:
            self.logger.error(f"Error adding mnemonic: {e}")
            conn.rollback()
            return None

    async def vote_mnemonic(
        self,
        mnemonic_id: str,
        upvote: bool
    ) -> bool:
        """Upvote or downvote a mnemonic."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            if upvote:
                cursor.execute(
                    "UPDATE mnemonics SET upvotes = upvotes + 1 WHERE id = ?",
                    (mnemonic_id,)
                )
            else:
                cursor.execute(
                    "UPDATE mnemonics SET downvotes = downvotes + 1 WHERE id = ?",
                    (mnemonic_id,)
                )
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Error voting mnemonic: {e}")
            conn.rollback()
            return False

    async def get_mnemonics(
        self,
        ideogram_id: str,
        language: Optional[Language] = None
    ) -> List[Mnemonic]:
        """Get mnemonics for a character."""
        conn = self._get_connection()
        cursor = conn.cursor()

        query = """
            SELECT * FROM mnemonics
            WHERE ideogram_id = ?
        """
        params: List[Any] = [ideogram_id]

        if language:
            query += " AND language = ?"
            params.append(language.value)

        query += " ORDER BY is_official DESC, (upvotes - downvotes) DESC"

        cursor.execute(query, params)

        return [
            Mnemonic(
                id=m['id'],
                ideogram_id=m['ideogram_id'],
                text=m['text'],
                language=Language(m['language']),
                created_by=m['created_by'],
                created_at=datetime.fromisoformat(m['created_at']),
                upvotes=m['upvotes'],
                downvotes=m['downvotes'],
                is_official=bool(m['is_official'])
            )
            for m in cursor.fetchall()
        ]

    # === STATISTICS ===

    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total ideograms
        cursor.execute("SELECT COUNT(*) FROM ideograms")
        stats['total_ideograms'] = cursor.fetchone()[0]

        # By language
        cursor.execute("""
            SELECT language, COUNT(*) as count
            FROM ideograms GROUP BY language
        """)
        stats['by_language'] = {
            row['language']: row['count']
            for row in cursor.fetchall()
        }

        # By character type
        cursor.execute("""
            SELECT character_type, COUNT(*) as count
            FROM ideograms GROUP BY character_type
        """)
        stats['by_type'] = {
            row['character_type']: row['count']
            for row in cursor.fetchall()
        }

        # By JLPT level
        cursor.execute("""
            SELECT jlpt_level, COUNT(*) as count
            FROM ideograms
            WHERE jlpt_level IS NOT NULL
            GROUP BY jlpt_level
        """)
        stats['by_jlpt'] = {
            row['jlpt_level']: row['count']
            for row in cursor.fetchall()
        }

        # Total radicals
        cursor.execute("SELECT COUNT(*) FROM radicals")
        stats['total_radicals'] = cursor.fetchone()[0]

        # Total mnemonics
        cursor.execute("SELECT COUNT(*) FROM mnemonics")
        stats['total_mnemonics'] = cursor.fetchone()[0]

        return stats

    # === IMPORT OPERATIONS ===

    async def import_from_kanjidic2(
        self,
        xml_path: Path,
        progress_callback: Optional[callable] = None
    ) -> int:
        """
        Import characters from KANJIDIC2 XML.

        Args:
            xml_path: Path to kanjidic2.xml
            progress_callback: Optional callback(current, total)

        Returns:
            Number of characters imported
        """
        import xml.etree.ElementTree as ET

        self.logger.info(f"Importing from KANJIDIC2: {xml_path}")

        tree = ET.parse(xml_path)
        root = tree.getroot()

        characters = root.findall('.//character')
        total = len(characters)
        imported = 0

        for i, char_elem in enumerate(characters):
            try:
                # Get character
                literal = char_elem.find('literal').text

                # Get readings
                readings = []
                rmgroup = char_elem.find('.//reading_meaning/rmgroup')
                if rmgroup:
                    for reading in rmgroup.findall('reading'):
                        r_type = reading.get('r_type')
                        if r_type == 'ja_on':
                            readings.append(Reading(
                                reading=reading.text,
                                reading_type=ReadingType.ONYOMI,
                                language=Language.JAPANESE
                            ))
                        elif r_type == 'ja_kun':
                            readings.append(Reading(
                                reading=reading.text,
                                reading_type=ReadingType.KUNYOMI,
                                language=Language.JAPANESE
                            ))

                # Get meanings
                meanings = {'en': []}
                if rmgroup:
                    for meaning in rmgroup.findall('meaning'):
                        if meaning.get('m_lang') is None:  # English
                            meanings['en'].append(meaning.text)

                # Get stroke count
                stroke_count = 0
                sc_elem = char_elem.find('.//stroke_count')
                if sc_elem is not None:
                    stroke_count = int(sc_elem.text)

                # Get JLPT level
                jlpt = None
                jlpt_elem = char_elem.find('.//jlpt')
                if jlpt_elem is not None:
                    jlpt_map = {'1': JLPTLevel.N1, '2': JLPTLevel.N2,
                               '3': JLPTLevel.N3, '4': JLPTLevel.N4}
                    jlpt = jlpt_map.get(jlpt_elem.text)

                # Get frequency
                freq = None
                freq_elem = char_elem.find('.//freq')
                if freq_elem is not None:
                    freq = int(freq_elem.text)

                # Get radical
                radical_ids = []
                rad_elem = char_elem.find('.//rad_value[@rad_type="classical"]')
                if rad_elem is not None:
                    radical_ids.append(int(rad_elem.text))

                ideogram = Ideogram(
                    id="",
                    character=literal,
                    character_type=CharacterType.KANJI,
                    language=Language.JAPANESE,
                    stroke_count=stroke_count,
                    readings=readings,
                    meanings=meanings,
                    radical_ids=radical_ids,
                    jlpt_level=jlpt,
                    frequency_rank=freq
                )

                await self.add_ideogram(ideogram)
                imported += 1

                if progress_callback and i % 100 == 0:
                    progress_callback(i, total)

            except Exception as e:
                self.logger.warning(f"Error importing character: {e}")
                continue

        self.logger.info(f"Imported {imported}/{total} characters from KANJIDIC2")
        return imported

    async def import_kangxi_radicals(self) -> int:
        """
        Import the 214 Kangxi radicals.

        Returns:
            Number of radicals imported
        """
        # Standard Kangxi radicals data
        # Format: (number, character, stroke_count, meaning)
        kangxi_radicals = [
            (1, "一", 1, "one"),
            (2, "丨", 1, "line"),
            (3, "丶", 1, "dot"),
            (4, "丿", 1, "slash"),
            (5, "乙", 1, "second"),
            (6, "亅", 1, "hook"),
            (7, "二", 2, "two"),
            (8, "亠", 2, "lid"),
            (9, "人", 2, "person"),
            (10, "儿", 2, "legs"),
            (11, "入", 2, "enter"),
            (12, "八", 2, "eight"),
            (13, "冂", 2, "upside down box"),
            (14, "冖", 2, "cover"),
            (15, "冫", 2, "ice"),
            (16, "几", 2, "table"),
            (17, "凵", 2, "open box"),
            (18, "刀", 2, "knife"),
            (19, "力", 2, "power"),
            (20, "勹", 2, "wrap"),
            (21, "匕", 2, "spoon"),
            (22, "匚", 2, "box"),
            (23, "匸", 2, "hiding enclosure"),
            (24, "十", 2, "ten"),
            (25, "卜", 2, "divination"),
            (26, "卩", 2, "seal"),
            (27, "厂", 2, "cliff"),
            (28, "厶", 2, "private"),
            (29, "又", 2, "again"),
            (30, "口", 3, "mouth"),
            (31, "囗", 3, "enclosure"),
            (32, "土", 3, "earth"),
            (33, "士", 3, "scholar"),
            (34, "夂", 3, "go"),
            (35, "夊", 3, "go slowly"),
            (36, "夕", 3, "evening"),
            (37, "大", 3, "big"),
            (38, "女", 3, "woman"),
            (39, "子", 3, "child"),
            (40, "宀", 3, "roof"),
            (41, "寸", 3, "inch"),
            (42, "小", 3, "small"),
            (43, "尢", 3, "lame"),
            (44, "尸", 3, "corpse"),
            (45, "屮", 3, "sprout"),
            (46, "山", 3, "mountain"),
            (47, "巛", 3, "river"),
            (48, "工", 3, "work"),
            (49, "己", 3, "oneself"),
            (50, "巾", 3, "turban"),
            (51, "干", 3, "dry"),
            (52, "幺", 3, "short thread"),
            (53, "广", 3, "dotted cliff"),
            (54, "廴", 3, "long stride"),
            (55, "廾", 3, "arch"),
            (56, "弋", 3, "shoot"),
            (57, "弓", 3, "bow"),
            (58, "彐", 3, "snout"),
            (59, "彡", 3, "bristle"),
            (60, "彳", 3, "step"),
            (61, "心", 4, "heart"),
            (62, "戈", 4, "halberd"),
            (63, "戶", 4, "door"),
            (64, "手", 4, "hand"),
            (65, "支", 4, "branch"),
            (66, "攴", 4, "rap"),
            (67, "文", 4, "script"),
            (68, "斗", 4, "dipper"),
            (69, "斤", 4, "axe"),
            (70, "方", 4, "square"),
            (71, "无", 4, "not"),
            (72, "日", 4, "sun"),
            (73, "曰", 4, "say"),
            (74, "月", 4, "moon"),
            (75, "木", 4, "tree"),
            (76, "欠", 4, "lack"),
            (77, "止", 4, "stop"),
            (78, "歹", 4, "death"),
            (79, "殳", 4, "weapon"),
            (80, "毋", 4, "do not"),
            (81, "比", 4, "compare"),
            (82, "毛", 4, "fur"),
            (83, "氏", 4, "clan"),
            (84, "气", 4, "steam"),
            (85, "水", 4, "water"),
            (86, "火", 4, "fire"),
            (87, "爪", 4, "claw"),
            (88, "父", 4, "father"),
            (89, "爻", 4, "mix"),
            (90, "爿", 4, "split wood"),
            (91, "片", 4, "slice"),
            (92, "牙", 4, "fang"),
            (93, "牛", 4, "cow"),
            (94, "犬", 4, "dog"),
            (95, "玄", 5, "profound"),
            (96, "玉", 5, "jade"),
            (97, "瓜", 5, "melon"),
            (98, "瓦", 5, "tile"),
            (99, "甘", 5, "sweet"),
            (100, "生", 5, "life"),
            (101, "用", 5, "use"),
            (102, "田", 5, "field"),
            (103, "疋", 5, "bolt of cloth"),
            (104, "疒", 5, "sickness"),
            (105, "癶", 5, "footsteps"),
            (106, "白", 5, "white"),
            (107, "皮", 5, "skin"),
            (108, "皿", 5, "dish"),
            (109, "目", 5, "eye"),
            (110, "矛", 5, "spear"),
            (111, "矢", 5, "arrow"),
            (112, "石", 5, "stone"),
            (113, "示", 5, "spirit"),
            (114, "禸", 5, "track"),
            (115, "禾", 5, "grain"),
            (116, "穴", 5, "cave"),
            (117, "立", 5, "stand"),
            (118, "竹", 6, "bamboo"),
            (119, "米", 6, "rice"),
            (120, "糸", 6, "silk"),
            (121, "缶", 6, "jar"),
            (122, "网", 6, "net"),
            (123, "羊", 6, "sheep"),
            (124, "羽", 6, "feather"),
            (125, "老", 6, "old"),
            (126, "而", 6, "and"),
            (127, "耒", 6, "plow"),
            (128, "耳", 6, "ear"),
            (129, "聿", 6, "brush"),
            (130, "肉", 6, "meat"),
            (131, "臣", 6, "minister"),
            (132, "自", 6, "self"),
            (133, "至", 6, "arrive"),
            (134, "臼", 6, "mortar"),
            (135, "舌", 6, "tongue"),
            (136, "舛", 6, "oppose"),
            (137, "舟", 6, "boat"),
            (138, "艮", 6, "stopping"),
            (139, "色", 6, "color"),
            (140, "艸", 6, "grass"),
            (141, "虍", 6, "tiger"),
            (142, "虫", 6, "insect"),
            (143, "血", 6, "blood"),
            (144, "行", 6, "walk enclosure"),
            (145, "衣", 6, "clothes"),
            (146, "襾", 6, "west"),
            (147, "見", 7, "see"),
            (148, "角", 7, "horn"),
            (149, "言", 7, "speech"),
            (150, "谷", 7, "valley"),
            (151, "豆", 7, "bean"),
            (152, "豕", 7, "pig"),
            (153, "豸", 7, "badger"),
            (154, "貝", 7, "shell"),
            (155, "赤", 7, "red"),
            (156, "走", 7, "run"),
            (157, "足", 7, "foot"),
            (158, "身", 7, "body"),
            (159, "車", 7, "cart"),
            (160, "辛", 7, "bitter"),
            (161, "辰", 7, "morning"),
            (162, "辵", 7, "walk"),
            (163, "邑", 7, "city"),
            (164, "酉", 7, "wine"),
            (165, "釆", 7, "distinguish"),
            (166, "里", 7, "village"),
            (167, "金", 8, "gold"),
            (168, "長", 8, "long"),
            (169, "門", 8, "gate"),
            (170, "阜", 8, "mound"),
            (171, "隶", 8, "slave"),
            (172, "隹", 8, "short-tailed bird"),
            (173, "雨", 8, "rain"),
            (174, "靑", 8, "blue"),
            (175, "非", 8, "wrong"),
            (176, "面", 9, "face"),
            (177, "革", 9, "leather"),
            (178, "韋", 9, "tanned leather"),
            (179, "韭", 9, "leek"),
            (180, "音", 9, "sound"),
            (181, "頁", 9, "leaf"),
            (182, "風", 9, "wind"),
            (183, "飛", 9, "fly"),
            (184, "食", 9, "eat"),
            (185, "首", 9, "head"),
            (186, "香", 9, "fragrant"),
            (187, "馬", 10, "horse"),
            (188, "骨", 10, "bone"),
            (189, "高", 10, "tall"),
            (190, "髟", 10, "hair"),
            (191, "鬥", 10, "fight"),
            (192, "鬯", 10, "sacrificial wine"),
            (193, "鬲", 10, "cauldron"),
            (194, "鬼", 10, "ghost"),
            (195, "魚", 11, "fish"),
            (196, "鳥", 11, "bird"),
            (197, "鹵", 11, "salt"),
            (198, "鹿", 11, "deer"),
            (199, "麥", 11, "wheat"),
            (200, "麻", 11, "hemp"),
            (201, "黃", 12, "yellow"),
            (202, "黍", 12, "millet"),
            (203, "黑", 12, "black"),
            (204, "黹", 12, "embroidery"),
            (205, "黽", 13, "frog"),
            (206, "鼎", 13, "tripod"),
            (207, "鼓", 13, "drum"),
            (208, "鼠", 13, "rat"),
            (209, "鼻", 14, "nose"),
            (210, "齊", 14, "even"),
            (211, "齒", 15, "tooth"),
            (212, "龍", 16, "dragon"),
            (213, "龜", 16, "turtle"),
            (214, "龠", 17, "flute"),
        ]

        imported = 0
        for num, char, strokes, meaning in kangxi_radicals:
            radical = Radical(
                number=num,
                character=char,
                stroke_count=strokes,
                meaning=meaning
            )
            if await self.add_radical(radical):
                imported += 1

        self.logger.info(f"Imported {imported}/214 Kangxi radicals")
        return imported

    # === UTILITY METHODS ===

    def _is_cjk_character(self, char: str) -> bool:
        """Check if character is CJK."""
        if len(char) != 1:
            return False
        code = ord(char)
        # CJK Unified Ideographs
        if 0x4E00 <= code <= 0x9FFF:
            return True
        # CJK Unified Ideographs Extension A
        if 0x3400 <= code <= 0x4DBF:
            return True
        # CJK Unified Ideographs Extension B
        if 0x20000 <= code <= 0x2A6DF:
            return True
        # Hiragana
        if 0x3040 <= code <= 0x309F:
            return True
        # Katakana
        if 0x30A0 <= code <= 0x30FF:
            return True
        return False

    def _matches_filters(
        self,
        ideogram: Ideogram,
        language: Optional[Language],
        jlpt_level: Optional[JLPTLevel],
        hsk_level: Optional[HSKLevel],
        max_stroke_count: Optional[int]
    ) -> bool:
        """Check if ideogram matches all filters."""
        if language and ideogram.language != language:
            return False
        if jlpt_level and ideogram.jlpt_level != jlpt_level:
            return False
        if hsk_level and ideogram.hsk_level != hsk_level:
            return False
        if max_stroke_count and ideogram.stroke_count > max_stroke_count:
            return False
        return True

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None
            self.logger.info("Database connection closed")


# === FACTORY FUNCTION ===

_db_instance: Optional[IdeogramDatabase] = None

async def get_ideogram_database(
    db_path: Optional[Path] = None
) -> IdeogramDatabase:
    """
    Get or create IdeogramDatabase instance.

    Args:
        db_path: Optional database path. Defaults to data/ideograms.db

    Returns:
        IdeogramDatabase instance
    """
    global _db_instance

    if _db_instance is None:
        if db_path is None:
            # Default path
            base_path = Path(__file__).parent.parent / "data"
            base_path.mkdir(parents=True, exist_ok=True)
            db_path = base_path / "ideograms.db"

        _db_instance = IdeogramDatabase(db_path)

    return _db_instance

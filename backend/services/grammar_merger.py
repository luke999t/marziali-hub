"""
AI_MODULE: GrammarMerger (Omnia) Service
AI_DESCRIPTION: Aggregatore regole grammaticali da fonti multiple con deduplicazione
AI_BUSINESS: Sistema unificato per grammatica CJK multilingua
AI_TEACHING: SQLite FTS, fuzzy matching, version control, rule merging

FEATURES:
- Multi-source aggregation (books, manga, subtitles)
- Fuzzy duplicate detection
- Rule confidence scoring
- Version control for rules
- Export to study formats (Anki, JSON)
- Multi-language support (JA, ZH, KO)

DATABASE SCHEMA:
- grammar_rules: Core rule data
- rule_sources: Source tracking
- rule_versions: Version history
- rule_examples: Example sentences
- rule_relations: Related rules

PRIVACY:
- Source paths anonymized
- Only rule content preserved
- No personal data stored

ZERO MOCK POLICY:
- All tests use real SQLite database
- Real file operations
"""

import asyncio
import sqlite3
import json
import logging
import hashlib
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Set
from enum import Enum
from datetime import datetime
from difflib import SequenceMatcher


# === ENUMS ===

class GrammarLanguage(str, Enum):
    """Supported languages for grammar rules."""
    JAPANESE = "ja"
    CHINESE = "zh"
    KOREAN = "ko"
    MIXED = "mixed"


class GrammarCategory(str, Enum):
    """Categories of grammar rules."""
    PARTICLE = "particle"
    VERB_FORM = "verb_form"
    ADJECTIVE_FORM = "adjective_form"
    SENTENCE_PATTERN = "sentence_pattern"
    HONORIFIC = "honorific"
    CONJUNCTION = "conjunction"
    EXPRESSION = "expression"
    COUNTER = "counter"
    AUXILIARY = "auxiliary"
    CONDITIONAL = "conditional"
    CAUSATIVE = "causative"
    PASSIVE = "passive"
    QUOTATION = "quotation"
    OTHER = "other"


class DifficultyLevel(str, Enum):
    """Difficulty levels for grammar rules."""
    BEGINNER = "beginner"       # JLPT N5-N4 / HSK 1-2
    ELEMENTARY = "elementary"   # JLPT N4-N3 / HSK 3
    INTERMEDIATE = "intermediate"  # JLPT N3-N2 / HSK 4
    UPPER_INTERMEDIATE = "upper_intermediate"  # JLPT N2 / HSK 5
    ADVANCED = "advanced"       # JLPT N1 / HSK 6
    NATIVE = "native"           # Beyond standard tests


class SourceType(str, Enum):
    """Types of grammar rule sources."""
    TEXTBOOK = "textbook"
    MANGA = "manga"
    SUBTITLE = "subtitle"
    BILINGUAL_BOOK = "bilingual_book"
    GRAMMAR_GUIDE = "grammar_guide"
    DICTIONARY = "dictionary"
    USER_CONTRIBUTION = "user_contribution"
    AUTO_EXTRACTED = "auto_extracted"


class RuleStatus(str, Enum):
    """Status of grammar rules."""
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    DEPRECATED = "deprecated"
    MERGED = "merged"


# === DATA CLASSES ===

@dataclass
class GrammarExample:
    """An example sentence for a grammar rule."""
    id: str
    sentence: str
    translation: str
    reading: str = ""  # Furigana/pinyin
    source_id: Optional[str] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RuleSource:
    """Tracking source of a grammar rule."""
    id: str
    source_type: SourceType
    source_hash: str  # Anonymized source identifier
    extraction_date: datetime
    confidence: float = 1.0  # 0.0 - 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['source_type'] = self.source_type.value
        d['extraction_date'] = self.extraction_date.isoformat()
        return d


@dataclass
class RuleVersion:
    """Version history entry for a rule."""
    version: int
    created_at: datetime
    created_by: str
    change_summary: str
    previous_content: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['created_at'] = self.created_at.isoformat()
        return d


@dataclass
class GrammarRule:
    """A grammar rule with all associated data."""
    id: str
    language: GrammarLanguage
    category: GrammarCategory
    difficulty: DifficultyLevel

    # Core content
    pattern: str  # The grammar pattern (e.g., "〜ている", "把〜")
    meaning: str  # Brief explanation
    explanation: str  # Detailed explanation
    structure: str  # Grammatical structure (e.g., "Verb-て + いる")

    # Translations
    translations: Dict[str, str] = field(default_factory=dict)  # {lang: meaning}

    # Usage
    usage_notes: str = ""
    common_mistakes: List[str] = field(default_factory=list)
    related_patterns: List[str] = field(default_factory=list)

    # Examples
    examples: List[GrammarExample] = field(default_factory=list)

    # Sources
    sources: List[RuleSource] = field(default_factory=list)
    source_count: int = 0  # Number of sources confirming this rule

    # Confidence
    confidence: float = 1.0  # Aggregate confidence
    occurrence_count: int = 1  # Times seen in corpus

    # Status
    status: RuleStatus = RuleStatus.DRAFT
    version: int = 1

    # Metadata
    tags: List[str] = field(default_factory=list)
    jlpt_level: Optional[str] = None  # N5-N1
    hsk_level: Optional[str] = None   # HSK1-HSK6
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        d = {
            'id': self.id,
            'language': self.language.value,
            'category': self.category.value,
            'difficulty': self.difficulty.value,
            'pattern': self.pattern,
            'meaning': self.meaning,
            'explanation': self.explanation,
            'structure': self.structure,
            'translations': self.translations,
            'usage_notes': self.usage_notes,
            'common_mistakes': self.common_mistakes,
            'related_patterns': self.related_patterns,
            'examples': [e.to_dict() for e in self.examples],
            'sources': [s.to_dict() for s in self.sources],
            'source_count': self.source_count,
            'confidence': self.confidence,
            'occurrence_count': self.occurrence_count,
            'status': self.status.value,
            'version': self.version,
            'tags': self.tags,
            'jlpt_level': self.jlpt_level,
            'hsk_level': self.hsk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        return d


@dataclass
class MergeResult:
    """Result of merging grammar rules."""
    merged_rule: GrammarRule
    merged_count: int
    source_rules: List[str]  # IDs of merged rules
    similarity_scores: List[float]


# === DATABASE SERVICE ===

class GrammarMerger:
    """
    Grammar rule aggregation and deduplication service.

    The "Omnia" system that unifies grammar knowledge from multiple sources.
    """

    _instance: Optional['GrammarMerger'] = None
    _lock = asyncio.Lock()

    # Similarity threshold for merging (0.0 - 1.0)
    MERGE_THRESHOLD = 0.85

    def __new__(cls, db_path: Optional[Path] = None):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    @classmethod
    def _reset_for_testing(cls, db_path: Optional[Path] = None) -> 'GrammarMerger':
        """Reset singleton for testing purposes."""
        cls._instance = None
        return cls(db_path)

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the merger."""
        if self._initialized:
            return

        self.logger = logging.getLogger(__name__)
        self.db_path = db_path or Path(":memory:")
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = True

        self._init_database()
        self.logger.info(f"GrammarMerger initialized: {self.db_path}")

    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def _init_database(self):
        """Create database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Grammar rules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS grammar_rules (
                id TEXT PRIMARY KEY,
                language TEXT NOT NULL,
                category TEXT NOT NULL,
                difficulty TEXT NOT NULL,
                pattern TEXT NOT NULL,
                meaning TEXT NOT NULL,
                explanation TEXT,
                structure TEXT,
                translations TEXT,
                usage_notes TEXT,
                common_mistakes TEXT,
                related_patterns TEXT,
                source_count INTEGER DEFAULT 1,
                confidence REAL DEFAULT 1.0,
                occurrence_count INTEGER DEFAULT 1,
                status TEXT DEFAULT 'draft',
                version INTEGER DEFAULT 1,
                tags TEXT,
                jlpt_level TEXT,
                hsk_level TEXT,
                created_at TEXT,
                updated_at TEXT
            )
        """)

        # Index for pattern search
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_pattern
            ON grammar_rules(pattern)
        """)

        # Index for language
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_language
            ON grammar_rules(language)
        """)

        # Index for category
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rules_category
            ON grammar_rules(category)
        """)

        # Rule sources table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_sources (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                extraction_date TEXT NOT NULL,
                confidence REAL DEFAULT 1.0,
                metadata TEXT,
                FOREIGN KEY (rule_id) REFERENCES grammar_rules(id) ON DELETE CASCADE
            )
        """)

        # Rule examples table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_examples (
                id TEXT PRIMARY KEY,
                rule_id TEXT NOT NULL,
                sentence TEXT NOT NULL,
                translation TEXT NOT NULL,
                reading TEXT,
                source_id TEXT,
                notes TEXT,
                FOREIGN KEY (rule_id) REFERENCES grammar_rules(id) ON DELETE CASCADE
            )
        """)

        # Rule versions table (history)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                change_summary TEXT,
                previous_content TEXT,
                FOREIGN KEY (rule_id) REFERENCES grammar_rules(id) ON DELETE CASCADE
            )
        """)

        # Rule relations table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS rule_relations (
                rule_id TEXT NOT NULL,
                related_rule_id TEXT NOT NULL,
                relation_type TEXT NOT NULL,
                PRIMARY KEY (rule_id, related_rule_id),
                FOREIGN KEY (rule_id) REFERENCES grammar_rules(id) ON DELETE CASCADE,
                FOREIGN KEY (related_rule_id) REFERENCES grammar_rules(id) ON DELETE CASCADE
            )
        """)

        # Full-text search
        cursor.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING fts5(
                pattern,
                meaning,
                explanation,
                content=grammar_rules,
                content_rowid=rowid
            )
        """)

        conn.commit()
        self.logger.info("Database schema initialized")

    # === RULE CRUD ===

    def _generate_rule_id(self, pattern: str, language: str) -> str:
        """Generate deterministic ID for a rule."""
        content = f"{language}:{pattern}"
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:16]

    async def add_rule(self, rule: GrammarRule) -> str:
        """
        Add a new grammar rule.

        Args:
            rule: Grammar rule to add

        Returns:
            Rule ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Generate ID if not provided
        if not rule.id:
            rule.id = self._generate_rule_id(rule.pattern, rule.language.value)

        now = datetime.utcnow()
        if not rule.created_at:
            rule.created_at = now
        rule.updated_at = now

        try:
            cursor.execute("""
                INSERT OR REPLACE INTO grammar_rules
                (id, language, category, difficulty, pattern, meaning, explanation,
                 structure, translations, usage_notes, common_mistakes, related_patterns,
                 source_count, confidence, occurrence_count, status, version, tags,
                 jlpt_level, hsk_level, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        COALESCE((SELECT created_at FROM grammar_rules WHERE id = ?), ?), ?)
            """, (
                rule.id,
                rule.language.value,
                rule.category.value,
                rule.difficulty.value,
                rule.pattern,
                rule.meaning,
                rule.explanation,
                rule.structure,
                json.dumps(rule.translations),
                rule.usage_notes,
                json.dumps(rule.common_mistakes),
                json.dumps(rule.related_patterns),
                rule.source_count,
                rule.confidence,
                rule.occurrence_count,
                rule.status.value,
                rule.version,
                json.dumps(rule.tags),
                rule.jlpt_level,
                rule.hsk_level,
                rule.id, now.isoformat(), now.isoformat()
            ))

            # Add examples
            cursor.execute("DELETE FROM rule_examples WHERE rule_id = ?", (rule.id,))
            for example in rule.examples:
                if not example.id:
                    example.id = hashlib.sha256(
                        f"{rule.id}:{example.sentence}".encode()
                    ).hexdigest()[:16]
                cursor.execute("""
                    INSERT INTO rule_examples
                    (id, rule_id, sentence, translation, reading, source_id, notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    example.id, rule.id, example.sentence, example.translation,
                    example.reading, example.source_id, example.notes
                ))

            # Add sources
            for source in rule.sources:
                if not source.id:
                    source.id = hashlib.sha256(
                        f"{rule.id}:{source.source_hash}".encode()
                    ).hexdigest()[:16]
                cursor.execute("""
                    INSERT OR REPLACE INTO rule_sources
                    (id, rule_id, source_type, source_hash, extraction_date, confidence, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    source.id, rule.id, source.source_type.value,
                    source.source_hash, source.extraction_date.isoformat(),
                    source.confidence, json.dumps(source.metadata)
                ))

            conn.commit()
            return rule.id

        except Exception as e:
            self.logger.error(f"Error adding rule: {e}")
            conn.rollback()
            raise

    async def get_rule(self, rule_id: str) -> Optional[GrammarRule]:
        """Get a rule by ID."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM grammar_rules WHERE id = ?", (rule_id,))
        row = cursor.fetchone()

        if not row:
            return None

        return await self._row_to_rule(row)

    async def get_rule_by_pattern(
        self,
        pattern: str,
        language: GrammarLanguage
    ) -> Optional[GrammarRule]:
        """Get a rule by pattern and language."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM grammar_rules WHERE pattern = ? AND language = ?",
            (pattern, language.value)
        )
        row = cursor.fetchone()

        if not row:
            return None

        return await self._row_to_rule(row)

    async def _row_to_rule(self, row: sqlite3.Row) -> GrammarRule:
        """Convert database row to GrammarRule object."""
        conn = self._get_connection()
        cursor = conn.cursor()

        rule_id = row['id']

        # Get examples
        cursor.execute(
            "SELECT * FROM rule_examples WHERE rule_id = ?",
            (rule_id,)
        )
        examples = [
            GrammarExample(
                id=e['id'],
                sentence=e['sentence'],
                translation=e['translation'],
                reading=e['reading'] or "",
                source_id=e['source_id'],
                notes=e['notes'] or ""
            )
            for e in cursor.fetchall()
        ]

        # Get sources
        cursor.execute(
            "SELECT * FROM rule_sources WHERE rule_id = ?",
            (rule_id,)
        )
        sources = [
            RuleSource(
                id=s['id'],
                source_type=SourceType(s['source_type']),
                source_hash=s['source_hash'],
                extraction_date=datetime.fromisoformat(s['extraction_date']),
                confidence=s['confidence'],
                metadata=json.loads(s['metadata'] or '{}')
            )
            for s in cursor.fetchall()
        ]

        return GrammarRule(
            id=rule_id,
            language=GrammarLanguage(row['language']),
            category=GrammarCategory(row['category']),
            difficulty=DifficultyLevel(row['difficulty']),
            pattern=row['pattern'],
            meaning=row['meaning'],
            explanation=row['explanation'] or "",
            structure=row['structure'] or "",
            translations=json.loads(row['translations'] or '{}'),
            usage_notes=row['usage_notes'] or "",
            common_mistakes=json.loads(row['common_mistakes'] or '[]'),
            related_patterns=json.loads(row['related_patterns'] or '[]'),
            examples=examples,
            sources=sources,
            source_count=row['source_count'],
            confidence=row['confidence'],
            occurrence_count=row['occurrence_count'],
            status=RuleStatus(row['status']),
            version=row['version'],
            tags=json.loads(row['tags'] or '[]'),
            jlpt_level=row['jlpt_level'],
            hsk_level=row['hsk_level'],
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else None,
            updated_at=datetime.fromisoformat(row['updated_at']) if row['updated_at'] else None
        )

    async def delete_rule(self, rule_id: str) -> bool:
        """Delete a rule."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            cursor.execute("DELETE FROM grammar_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            self.logger.error(f"Error deleting rule: {e}")
            conn.rollback()
            return False

    # === SEARCH ===

    async def search(
        self,
        query: str,
        language: Optional[GrammarLanguage] = None,
        category: Optional[GrammarCategory] = None,
        difficulty: Optional[DifficultyLevel] = None,
        status: Optional[RuleStatus] = None,
        jlpt_level: Optional[str] = None,
        limit: int = 50
    ) -> List[GrammarRule]:
        """
        Search for grammar rules.

        Args:
            query: Search query (pattern or meaning)
            language: Filter by language
            category: Filter by category
            difficulty: Filter by difficulty
            status: Filter by status
            jlpt_level: Filter by JLPT level
            limit: Maximum results

        Returns:
            List of matching rules
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Build query
        conditions = []
        params = []

        if query:
            conditions.append("(pattern LIKE ? OR meaning LIKE ? OR explanation LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

        if language:
            conditions.append("language = ?")
            params.append(language.value)

        if category:
            conditions.append("category = ?")
            params.append(category.value)

        if difficulty:
            conditions.append("difficulty = ?")
            params.append(difficulty.value)

        if status:
            conditions.append("status = ?")
            params.append(status.value)

        if jlpt_level:
            conditions.append("jlpt_level = ?")
            params.append(jlpt_level)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.append(limit)

        cursor.execute(f"""
            SELECT * FROM grammar_rules
            WHERE {where_clause}
            ORDER BY occurrence_count DESC, confidence DESC
            LIMIT ?
        """, params)

        results = []
        for row in cursor.fetchall():
            results.append(await self._row_to_rule(row))

        return results

    async def list_rules(
        self,
        language: Optional[GrammarLanguage] = None,
        category: Optional[GrammarCategory] = None,
        status: Optional[RuleStatus] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[GrammarRule]:
        """List rules with filters and pagination."""
        conn = self._get_connection()
        cursor = conn.cursor()

        conditions = []
        params = []

        if language:
            conditions.append("language = ?")
            params.append(language.value)

        if category:
            conditions.append("category = ?")
            params.append(category.value)

        if status:
            conditions.append("status = ?")
            params.append(status.value)

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        params.extend([limit, offset])

        cursor.execute(f"""
            SELECT * FROM grammar_rules
            WHERE {where_clause}
            ORDER BY pattern
            LIMIT ? OFFSET ?
        """, params)

        results = []
        for row in cursor.fetchall():
            results.append(await self._row_to_rule(row))

        return results

    # === MERGING ===

    def calculate_similarity(self, rule1: GrammarRule, rule2: GrammarRule) -> float:
        """
        Calculate similarity between two grammar rules.

        Uses weighted combination of pattern, meaning, and structure similarity.

        Returns:
            Similarity score (0.0 - 1.0)
        """
        if rule1.language != rule2.language:
            return 0.0

        # Pattern similarity (50% weight)
        pattern_sim = SequenceMatcher(
            None, rule1.pattern, rule2.pattern
        ).ratio()

        # Meaning similarity (30% weight)
        meaning_sim = SequenceMatcher(
            None, rule1.meaning.lower(), rule2.meaning.lower()
        ).ratio()

        # Structure similarity (20% weight)
        structure_sim = 0.0
        if rule1.structure and rule2.structure:
            structure_sim = SequenceMatcher(
                None, rule1.structure, rule2.structure
            ).ratio()
        elif not rule1.structure and not rule2.structure:
            structure_sim = 1.0  # Both empty

        return (pattern_sim * 0.5) + (meaning_sim * 0.3) + (structure_sim * 0.2)

    async def find_similar_rules(
        self,
        rule: GrammarRule,
        threshold: float = 0.7,
        limit: int = 10
    ) -> List[Tuple[GrammarRule, float]]:
        """
        Find rules similar to the given rule.

        Args:
            rule: Rule to compare
            threshold: Minimum similarity score
            limit: Maximum results

        Returns:
            List of (rule, similarity_score) tuples
        """
        # Get all rules in same language
        all_rules = await self.list_rules(language=rule.language, limit=1000)

        similar = []
        for other in all_rules:
            if other.id == rule.id:
                continue

            score = self.calculate_similarity(rule, other)
            if score >= threshold:
                similar.append((other, score))

        # Sort by similarity descending
        similar.sort(key=lambda x: x[1], reverse=True)
        return similar[:limit]

    async def merge_rules(
        self,
        rule_ids: List[str],
        merged_by: str,
        keep_id: Optional[str] = None
    ) -> Optional[MergeResult]:
        """
        Merge multiple rules into one.

        Args:
            rule_ids: IDs of rules to merge
            merged_by: User performing merge
            keep_id: ID of rule to keep (others merged into this)

        Returns:
            MergeResult with merged rule
        """
        if len(rule_ids) < 2:
            self.logger.warning("Need at least 2 rules to merge")
            return None

        # Get all rules
        rules = []
        for rule_id in rule_ids:
            rule = await self.get_rule(rule_id)
            if rule:
                rules.append(rule)

        if len(rules) < 2:
            self.logger.warning("Not enough valid rules found")
            return None

        # Determine primary rule
        if keep_id:
            primary = next((r for r in rules if r.id == keep_id), rules[0])
        else:
            # Use rule with highest source count
            primary = max(rules, key=lambda r: r.source_count)

        # Calculate similarity scores
        similarities = [
            self.calculate_similarity(primary, r)
            for r in rules if r.id != primary.id
        ]

        # Merge content
        merged = GrammarRule(
            id=primary.id,
            language=primary.language,
            category=primary.category,
            difficulty=primary.difficulty,
            pattern=primary.pattern,
            meaning=primary.meaning,
            explanation=self._merge_explanations([r.explanation for r in rules]),
            structure=primary.structure,
            translations=self._merge_dicts([r.translations for r in rules]),
            usage_notes=self._merge_texts([r.usage_notes for r in rules]),
            common_mistakes=self._merge_lists([r.common_mistakes for r in rules]),
            related_patterns=self._merge_lists([r.related_patterns for r in rules]),
            examples=self._merge_examples([r.examples for r in rules]),
            sources=self._merge_sources([r.sources for r in rules]),
            source_count=sum(r.source_count for r in rules),
            confidence=max(r.confidence for r in rules),
            occurrence_count=sum(r.occurrence_count for r in rules),
            status=RuleStatus.APPROVED,
            version=primary.version + 1,
            tags=self._merge_lists([r.tags for r in rules]),
            jlpt_level=primary.jlpt_level,
            hsk_level=primary.hsk_level
        )

        # Save version history
        await self._save_version(
            primary.id,
            primary.version,
            merged_by,
            f"Merged {len(rules)} rules: {', '.join(rule_ids)}",
            json.dumps(primary.to_dict())
        )

        # Update merged rule
        await self.add_rule(merged)

        # Mark other rules as merged
        for rule in rules:
            if rule.id != primary.id:
                rule.status = RuleStatus.MERGED
                rule.related_patterns.append(primary.pattern)
                await self.add_rule(rule)

        return MergeResult(
            merged_rule=merged,
            merged_count=len(rules),
            source_rules=rule_ids,
            similarity_scores=similarities
        )

    def _merge_explanations(self, explanations: List[str]) -> str:
        """Merge multiple explanations, keeping the longest non-empty one."""
        valid = [e for e in explanations if e]
        if not valid:
            return ""
        return max(valid, key=len)

    def _merge_texts(self, texts: List[str]) -> str:
        """Merge multiple text fields."""
        valid = [t for t in texts if t]
        if not valid:
            return ""
        # Deduplicate and join
        unique = list(dict.fromkeys(valid))
        return " ".join(unique)

    def _merge_lists(self, lists: List[List[str]]) -> List[str]:
        """Merge multiple lists, removing duplicates."""
        result: Set[str] = set()
        for lst in lists:
            result.update(lst)
        return list(result)

    def _merge_dicts(self, dicts: List[Dict]) -> Dict:
        """Merge multiple dictionaries."""
        result = {}
        for d in dicts:
            result.update(d)
        return result

    def _merge_examples(
        self,
        example_lists: List[List[GrammarExample]]
    ) -> List[GrammarExample]:
        """Merge examples, removing duplicates by sentence and regenerating IDs."""
        seen_sentences: Set[str] = set()
        result = []
        for examples in example_lists:
            for example in examples:
                if example.sentence not in seen_sentences:
                    seen_sentences.add(example.sentence)
                    # Create new example with fresh ID to avoid conflicts
                    result.append(GrammarExample(
                        id="",  # Will be regenerated on save
                        sentence=example.sentence,
                        translation=example.translation,
                        reading=example.reading,
                        source_id=example.source_id,
                        notes=example.notes
                    ))
        return result

    def _merge_sources(
        self,
        source_lists: List[List[RuleSource]]
    ) -> List[RuleSource]:
        """Merge sources, removing duplicates by hash."""
        seen_hashes: Set[str] = set()
        result = []
        for sources in source_lists:
            for source in sources:
                if source.source_hash not in seen_hashes:
                    seen_hashes.add(source.source_hash)
                    result.append(source)
        return result

    async def _save_version(
        self,
        rule_id: str,
        version: int,
        created_by: str,
        change_summary: str,
        previous_content: str
    ):
        """Save version history entry."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO rule_versions
            (rule_id, version, created_at, created_by, change_summary, previous_content)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            rule_id, version, datetime.utcnow().isoformat(),
            created_by, change_summary, previous_content
        ))
        conn.commit()

    # === AUTO-DEDUPLICATION ===

    async def auto_deduplicate(
        self,
        language: GrammarLanguage,
        threshold: float = 0.85,
        dry_run: bool = True
    ) -> List[MergeResult]:
        """
        Automatically find and merge duplicate rules.

        Args:
            language: Language to process
            threshold: Similarity threshold for merging
            dry_run: If True, only report duplicates without merging

        Returns:
            List of merge results (actual or proposed)
        """
        rules = await self.list_rules(language=language, limit=10000)

        # Find clusters of similar rules
        processed: Set[str] = set()
        merge_results = []

        for rule in rules:
            if rule.id in processed:
                continue

            similar = await self.find_similar_rules(rule, threshold=threshold)
            if not similar:
                continue

            cluster = [rule.id] + [r.id for r, _ in similar]
            processed.update(cluster)

            if dry_run:
                # Create proposed merge result
                merge_results.append(MergeResult(
                    merged_rule=rule,
                    merged_count=len(cluster),
                    source_rules=cluster,
                    similarity_scores=[s for _, s in similar]
                ))
            else:
                # Actually merge
                result = await self.merge_rules(cluster, "auto_dedupe")
                if result:
                    merge_results.append(result)

        return merge_results

    # === STATISTICS ===

    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = self._get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total rules
        cursor.execute("SELECT COUNT(*) FROM grammar_rules")
        stats['total_rules'] = cursor.fetchone()[0]

        # By language
        cursor.execute("""
            SELECT language, COUNT(*) as count
            FROM grammar_rules GROUP BY language
        """)
        stats['by_language'] = {
            row['language']: row['count']
            for row in cursor.fetchall()
        }

        # By category
        cursor.execute("""
            SELECT category, COUNT(*) as count
            FROM grammar_rules GROUP BY category
        """)
        stats['by_category'] = {
            row['category']: row['count']
            for row in cursor.fetchall()
        }

        # By status
        cursor.execute("""
            SELECT status, COUNT(*) as count
            FROM grammar_rules GROUP BY status
        """)
        stats['by_status'] = {
            row['status']: row['count']
            for row in cursor.fetchall()
        }

        # By difficulty
        cursor.execute("""
            SELECT difficulty, COUNT(*) as count
            FROM grammar_rules GROUP BY difficulty
        """)
        stats['by_difficulty'] = {
            row['difficulty']: row['count']
            for row in cursor.fetchall()
        }

        # Total examples
        cursor.execute("SELECT COUNT(*) FROM rule_examples")
        stats['total_examples'] = cursor.fetchone()[0]

        # Total sources
        cursor.execute("SELECT COUNT(*) FROM rule_sources")
        stats['total_sources'] = cursor.fetchone()[0]

        return stats

    # === EXPORT ===

    async def export_to_anki(
        self,
        language: GrammarLanguage,
        output_path: Path,
        include_examples: bool = True
    ) -> int:
        """
        Export rules to Anki-compatible TSV format.

        Args:
            language: Language to export
            output_path: Output file path
            include_examples: Include example sentences

        Returns:
            Number of cards exported
        """
        rules = await self.list_rules(
            language=language,
            status=RuleStatus.APPROVED,
            limit=10000
        )

        cards = []
        for rule in rules:
            front = f"{rule.pattern}"
            # Use <br> for Anki HTML compatibility
            back = f"{rule.meaning}<br><br>{rule.explanation}"

            if include_examples and rule.examples:
                back += "<br><br>例文:<br>"
                for ex in rule.examples[:3]:
                    back += f"• {ex.sentence}<br>  {ex.translation}<br>"

            # Tags
            tags = rule.tags.copy()
            tags.append(rule.category.value)
            if rule.jlpt_level:
                tags.append(rule.jlpt_level)

            cards.append(f"{front}\t{back}\t{' '.join(tags)}")

        output_path.write_text("\n".join(cards), encoding='utf-8')
        return len(cards)

    async def export_to_json(
        self,
        language: GrammarLanguage,
        output_path: Path
    ) -> int:
        """Export rules to JSON format."""
        rules = await self.list_rules(language=language, limit=10000)

        data = {
            'language': language.value,
            'exported_at': datetime.utcnow().isoformat(),
            'rules_count': len(rules),
            'rules': [r.to_dict() for r in rules]
        }

        output_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )
        return len(rules)

    def close(self):
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


# === FACTORY FUNCTION ===

_merger_instance: Optional[GrammarMerger] = None

async def get_grammar_merger(
    db_path: Optional[Path] = None
) -> GrammarMerger:
    """Get or create GrammarMerger instance."""
    global _merger_instance

    if _merger_instance is None:
        if db_path is None:
            base_path = Path(__file__).parent.parent / "data"
            base_path.mkdir(parents=True, exist_ok=True)
            db_path = base_path / "grammar.db"

        _merger_instance = GrammarMerger(db_path)

    return _merger_instance

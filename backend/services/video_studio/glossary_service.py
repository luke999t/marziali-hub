"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Glossary and Terminology Management Service
================================================================================

    AI_FIRST: Martial Arts Glossary with Multi-level Classification
    AI_MODULE: Glossary Service
    AI_DESCRIPTION: Multi-level terminology with usage tracking and RAG search
    AI_BUSINESS: Consistent translations across martial arts styles and techniques
    AI_TEACHING: Terminology management, usage analytics, semantic vectors

    Adapted from: SOFTWARE A - SISTEMA TRADUZIONE MANGAANIME AI-POWERED

================================================================================
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import math
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# Enums and Types
# =============================================================================

class GlossaryCategory(str, Enum):
    """Category of glossary entry"""
    TERM = "term"
    EXPRESSION = "expression"
    ONOMATOPOEIA = "onomatopoeia"
    HONORIFIC = "honorific"
    CULTURAL = "cultural"
    TECHNICAL = "technical"
    NAME = "name"
    SLANG = "slang"
    CATCHPHRASE = "catchphrase"
    # Martial arts specific
    TECHNIQUE = "technique"
    STANCE = "stance"
    WEAPON = "weapon"
    FORM = "form"
    PHILOSOPHY = "philosophy"


class ContentGenre(str, Enum):
    """Genre of content"""
    ACTION = "action"
    ADVENTURE = "adventure"
    COMEDY = "comedy"
    DRAMA = "drama"
    FANTASY = "fantasy"
    HORROR = "horror"
    MYSTERY = "mystery"
    ROMANCE = "romance"
    SCI_FI = "sci_fi"
    SLICE_OF_LIFE = "slice_of_life"
    SPORTS = "sports"
    SUPERNATURAL = "supernatural"
    THRILLER = "thriller"
    MECHA = "mecha"
    ISEKAI = "isekai"
    SHOUNEN = "shounen"
    SHOUJO = "shoujo"
    SEINEN = "seinen"
    JOSEI = "josei"
    # Martial arts specific
    MARTIAL_ARTS = "martial_arts"
    WUXIA = "wuxia"
    XIANXIA = "xianxia"


class ContentMedium(str, Enum):
    """Type of media"""
    MANGA = "manga"
    ANIME = "anime"
    LIGHT_NOVEL = "light_novel"
    VISUAL_NOVEL = "visual_novel"
    GAME = "game"
    WEBTOON = "webtoon"
    # Martial arts specific
    INSTRUCTIONAL = "instructional"
    DOCUMENTARY = "documentary"
    DEMONSTRATION = "demonstration"
    COMPETITION = "competition"


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class UsageRecord:
    """Record of term usage"""
    usage_id: str
    entry_id: str

    # Context
    author_id: Optional[str] = None
    author_name: Optional[str] = None
    work_id: Optional[str] = None
    work_title: Optional[str] = None
    genre: Optional[ContentGenre] = None
    medium: Optional[ContentMedium] = None

    # Usage details
    context: str = ""
    translation_used: str = ""
    position: Optional[str] = None

    # Metadata
    used_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    user_id: Optional[str] = None


@dataclass
class GlossaryEntry:
    """A glossary/terminology entry"""
    entry_id: str

    # Source term
    source_term: str
    source_language: str
    reading: Optional[str] = None

    # Category and classification
    category: GlossaryCategory = GlossaryCategory.TERM
    tags: List[str] = field(default_factory=list)

    # Translations
    translations: Dict[str, List[str]] = field(default_factory=dict)

    # Preferred translation per context
    preferred_translations: Dict[str, str] = field(default_factory=dict)

    # Author-specific translations
    author_translations: Dict[str, Dict[str, str]] = field(default_factory=dict)

    # Notes and context
    definition: str = ""
    usage_notes: str = ""
    cultural_notes: str = ""

    # Usage statistics
    total_usage_count: int = 0
    usage_by_author: Dict[str, int] = field(default_factory=dict)
    usage_by_genre: Dict[str, int] = field(default_factory=dict)
    usage_by_medium: Dict[str, int] = field(default_factory=dict)

    # RAG/Vector search
    embedding: Optional[List[float]] = None
    semantic_tags: List[str] = field(default_factory=list)

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    created_by: Optional[str] = None
    is_verified: bool = False

    # Related entries
    synonyms: List[str] = field(default_factory=list)
    antonyms: List[str] = field(default_factory=list)
    related_terms: List[str] = field(default_factory=list)


@dataclass
class GlossaryFilter:
    """Filter criteria for glossary queries"""
    source_language: Optional[str] = None
    target_language: Optional[str] = None
    category: Optional[GlossaryCategory] = None
    genres: Optional[List[ContentGenre]] = None
    mediums: Optional[List[ContentMedium]] = None
    author_id: Optional[str] = None
    tags: Optional[List[str]] = None
    min_usage: Optional[int] = None
    is_verified: Optional[bool] = None
    search_text: Optional[str] = None


@dataclass
class UsageStatistics:
    """Statistics about term usage"""
    entry_id: str
    source_term: str
    total_count: int

    by_author: List[Tuple[str, str, int]]
    by_genre: List[Tuple[str, int]]
    by_medium: List[Tuple[str, int]]

    top_translations: List[Tuple[str, str, int]]
    recent_usage: int


# =============================================================================
# Glossary Service
# =============================================================================

class GlossaryService:
    """
    Service for managing glossaries and terminology.

    Features:
    - Multi-level classification (author, genre, medium)
    - Usage tracking with detailed statistics
    - RAG-ready semantic tagging
    - Author-specific translations
    - Preferred translations per context
    """

    def __init__(self):
        self._entries: Dict[str, GlossaryEntry] = {}
        self._usage_records: Dict[str, UsageRecord] = {}

        # Indexes for fast lookup
        self._by_source_term: Dict[str, List[str]] = {}
        self._by_author: Dict[str, Set[str]] = {}
        self._by_genre: Dict[str, Set[str]] = {}
        self._by_medium: Dict[str, Set[str]] = {}
        self._by_tag: Dict[str, Set[str]] = {}

    # =========================================================================
    # Entry Management
    # =========================================================================

    def create_entry(
        self,
        source_term: str,
        source_language: str,
        translations: Dict[str, List[str]],
        category: GlossaryCategory = GlossaryCategory.TERM,
        definition: str = "",
        tags: Optional[List[str]] = None,
        reading: Optional[str] = None,
        usage_notes: str = "",
        cultural_notes: str = "",
        created_by: Optional[str] = None,
        semantic_tags: Optional[List[str]] = None
    ) -> GlossaryEntry:
        """Create a new glossary entry."""
        entry_id = str(uuid.uuid4())

        entry = GlossaryEntry(
            entry_id=entry_id,
            source_term=source_term,
            source_language=source_language,
            reading=reading,
            category=category,
            tags=tags or [],
            translations=translations,
            definition=definition,
            usage_notes=usage_notes,
            cultural_notes=cultural_notes,
            created_by=created_by,
            semantic_tags=semantic_tags or []
        )

        self._entries[entry_id] = entry
        self._index_entry(entry)

        logger.info(
            "Glossary entry created",
            entry_id=entry_id,
            term=source_term,
            category=category.value
        )

        return entry

    def _index_entry(self, entry: GlossaryEntry) -> None:
        """Index entry for fast lookup"""
        term_lower = entry.source_term.lower()
        if term_lower not in self._by_source_term:
            self._by_source_term[term_lower] = []
        self._by_source_term[term_lower].append(entry.entry_id)

        for tag in entry.tags:
            if tag not in self._by_tag:
                self._by_tag[tag] = set()
            self._by_tag[tag].add(entry.entry_id)

    def get_entry(self, entry_id: str) -> Optional[GlossaryEntry]:
        """Get entry by ID"""
        return self._entries.get(entry_id)

    def find_by_term(
        self,
        term: str,
        source_language: Optional[str] = None
    ) -> List[GlossaryEntry]:
        """Find entries by source term"""
        term_lower = term.lower()
        entry_ids = self._by_source_term.get(term_lower, [])

        entries = []
        for eid in entry_ids:
            entry = self._entries.get(eid)
            if entry:
                if source_language and entry.source_language != source_language:
                    continue
                entries.append(entry)

        return entries

    def update_entry(
        self,
        entry_id: str,
        translations: Optional[Dict[str, List[str]]] = None,
        definition: Optional[str] = None,
        tags: Optional[List[str]] = None,
        usage_notes: Optional[str] = None,
        cultural_notes: Optional[str] = None,
        is_verified: Optional[bool] = None
    ) -> Optional[GlossaryEntry]:
        """Update an existing entry"""
        entry = self._entries.get(entry_id)
        if not entry:
            return None

        if translations is not None:
            entry.translations = translations
        if definition is not None:
            entry.definition = definition
        if tags is not None:
            for old_tag in entry.tags:
                if old_tag in self._by_tag:
                    self._by_tag[old_tag].discard(entry_id)
            entry.tags = tags
            for tag in tags:
                if tag not in self._by_tag:
                    self._by_tag[tag] = set()
                self._by_tag[tag].add(entry_id)
        if usage_notes is not None:
            entry.usage_notes = usage_notes
        if cultural_notes is not None:
            entry.cultural_notes = cultural_notes
        if is_verified is not None:
            entry.is_verified = is_verified

        entry.updated_at = datetime.utcnow().isoformat()

        return entry

    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry"""
        if entry_id not in self._entries:
            return False

        entry = self._entries[entry_id]

        term_lower = entry.source_term.lower()
        if term_lower in self._by_source_term:
            self._by_source_term[term_lower] = [
                eid for eid in self._by_source_term[term_lower]
                if eid != entry_id
            ]

        for tag in entry.tags:
            if tag in self._by_tag:
                self._by_tag[tag].discard(entry_id)

        del self._entries[entry_id]

        return True

    # =========================================================================
    # Translation Management
    # =========================================================================

    def add_translation(
        self,
        entry_id: str,
        language: str,
        translation: str
    ) -> bool:
        """Add a translation to an entry"""
        entry = self._entries.get(entry_id)
        if not entry:
            return False

        if language not in entry.translations:
            entry.translations[language] = []

        if translation not in entry.translations[language]:
            entry.translations[language].append(translation)

        entry.updated_at = datetime.utcnow().isoformat()
        return True

    def set_author_translation(
        self,
        entry_id: str,
        author_id: str,
        language: str,
        translation: str
    ) -> bool:
        """Set author-specific translation."""
        entry = self._entries.get(entry_id)
        if not entry:
            return False

        if author_id not in entry.author_translations:
            entry.author_translations[author_id] = {}

        entry.author_translations[author_id][language] = translation
        entry.updated_at = datetime.utcnow().isoformat()

        return True

    def set_preferred_translation(
        self,
        entry_id: str,
        context: str,
        translation: str
    ) -> bool:
        """Set preferred translation for a context."""
        entry = self._entries.get(entry_id)
        if not entry:
            return False

        entry.preferred_translations[context] = translation
        entry.updated_at = datetime.utcnow().isoformat()

        return True

    def get_best_translation(
        self,
        entry_id: str,
        target_language: str,
        author_id: Optional[str] = None,
        genre: Optional[ContentGenre] = None
    ) -> Optional[str]:
        """Get the best translation based on context."""
        entry = self._entries.get(entry_id)
        if not entry:
            return None

        if author_id and author_id in entry.author_translations:
            if target_language in entry.author_translations[author_id]:
                return entry.author_translations[author_id][target_language]

        if genre and genre.value in entry.preferred_translations:
            return entry.preferred_translations[genre.value]

        if target_language in entry.translations:
            translations = entry.translations[target_language]
            if translations:
                return translations[0]

        return None

    # =========================================================================
    # Usage Tracking
    # =========================================================================

    def record_usage(
        self,
        entry_id: str,
        translation_used: str,
        context: str = "",
        author_id: Optional[str] = None,
        author_name: Optional[str] = None,
        work_id: Optional[str] = None,
        work_title: Optional[str] = None,
        genre: Optional[ContentGenre] = None,
        medium: Optional[ContentMedium] = None,
        position: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Optional[UsageRecord]:
        """Record usage of a glossary term."""
        entry = self._entries.get(entry_id)
        if not entry:
            return None

        usage_id = str(uuid.uuid4())

        record = UsageRecord(
            usage_id=usage_id,
            entry_id=entry_id,
            author_id=author_id,
            author_name=author_name,
            work_id=work_id,
            work_title=work_title,
            genre=genre,
            medium=medium,
            context=context,
            translation_used=translation_used,
            position=position,
            user_id=user_id
        )

        self._usage_records[usage_id] = record

        entry.total_usage_count += 1

        if author_id:
            entry.usage_by_author[author_id] = entry.usage_by_author.get(author_id, 0) + 1
            if author_id not in self._by_author:
                self._by_author[author_id] = set()
            self._by_author[author_id].add(entry_id)

        if genre:
            entry.usage_by_genre[genre.value] = entry.usage_by_genre.get(genre.value, 0) + 1
            if genre.value not in self._by_genre:
                self._by_genre[genre.value] = set()
            self._by_genre[genre.value].add(entry_id)

        if medium:
            entry.usage_by_medium[medium.value] = entry.usage_by_medium.get(medium.value, 0) + 1
            if medium.value not in self._by_medium:
                self._by_medium[medium.value] = set()
            self._by_medium[medium.value].add(entry_id)

        entry.updated_at = datetime.utcnow().isoformat()

        return record

    def get_usage_statistics(self, entry_id: str) -> Optional[UsageStatistics]:
        """Get detailed usage statistics for an entry"""
        entry = self._entries.get(entry_id)
        if not entry:
            return None

        records = [
            r for r in self._usage_records.values()
            if r.entry_id == entry_id
        ]

        author_counts: Dict[str, Tuple[str, int]] = {}
        for r in records:
            if r.author_id:
                if r.author_id not in author_counts:
                    author_counts[r.author_id] = (r.author_name or r.author_id, 0)
                name, count = author_counts[r.author_id]
                author_counts[r.author_id] = (name, count + 1)

        by_author = [
            (aid, name, count)
            for aid, (name, count) in sorted(
                author_counts.items(),
                key=lambda x: x[1][1],
                reverse=True
            )
        ]

        by_genre = sorted(
            [(g, c) for g, c in entry.usage_by_genre.items()],
            key=lambda x: x[1],
            reverse=True
        )

        by_medium = sorted(
            [(m, c) for m, c in entry.usage_by_medium.items()],
            key=lambda x: x[1],
            reverse=True
        )

        translation_counts: Dict[Tuple[str, str], int] = {}
        for r in records:
            if r.translation_used:
                for lang, trans_list in entry.translations.items():
                    if r.translation_used in trans_list:
                        key = (lang, r.translation_used)
                        translation_counts[key] = translation_counts.get(key, 0) + 1
                        break

        top_translations = [
            (lang, trans, count)
            for (lang, trans), count in sorted(
                translation_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        ]

        recent_usage = min(entry.total_usage_count, len(records))

        return UsageStatistics(
            entry_id=entry_id,
            source_term=entry.source_term,
            total_count=entry.total_usage_count,
            by_author=by_author,
            by_genre=by_genre,
            by_medium=by_medium,
            top_translations=top_translations,
            recent_usage=recent_usage
        )

    def get_author_terms(
        self,
        author_id: str,
        min_usage: int = 1
    ) -> List[Tuple[GlossaryEntry, int]]:
        """Get terms used by a specific author."""
        entry_ids = self._by_author.get(author_id, set())

        results = []
        for eid in entry_ids:
            entry = self._entries.get(eid)
            if entry:
                count = entry.usage_by_author.get(author_id, 0)
                if count >= min_usage:
                    results.append((entry, count))

        return sorted(results, key=lambda x: x[1], reverse=True)

    def get_genre_terms(
        self,
        genre: ContentGenre,
        min_usage: int = 1
    ) -> List[Tuple[GlossaryEntry, int]]:
        """Get terms commonly used in a genre"""
        entry_ids = self._by_genre.get(genre.value, set())

        results = []
        for eid in entry_ids:
            entry = self._entries.get(eid)
            if entry:
                count = entry.usage_by_genre.get(genre.value, 0)
                if count >= min_usage:
                    results.append((entry, count))

        return sorted(results, key=lambda x: x[1], reverse=True)

    # =========================================================================
    # Search and Query
    # =========================================================================

    def search(
        self,
        filter_criteria: GlossaryFilter,
        limit: int = 50,
        offset: int = 0
    ) -> List[GlossaryEntry]:
        """Search glossary entries with filters."""
        results = []

        for entry in self._entries.values():
            if filter_criteria.source_language:
                if entry.source_language != filter_criteria.source_language:
                    continue

            if filter_criteria.target_language:
                if filter_criteria.target_language not in entry.translations:
                    continue

            if filter_criteria.category:
                if entry.category != filter_criteria.category:
                    continue

            if filter_criteria.tags:
                if not any(tag in entry.tags for tag in filter_criteria.tags):
                    continue

            if filter_criteria.genres:
                genre_values = [g.value for g in filter_criteria.genres]
                if not any(g in entry.usage_by_genre for g in genre_values):
                    continue

            if filter_criteria.mediums:
                medium_values = [m.value for m in filter_criteria.mediums]
                if not any(m in entry.usage_by_medium for m in medium_values):
                    continue

            if filter_criteria.author_id:
                if filter_criteria.author_id not in entry.usage_by_author:
                    continue

            if filter_criteria.min_usage:
                if entry.total_usage_count < filter_criteria.min_usage:
                    continue

            if filter_criteria.is_verified is not None:
                if entry.is_verified != filter_criteria.is_verified:
                    continue

            if filter_criteria.search_text:
                search_lower = filter_criteria.search_text.lower()
                found = False
                if search_lower in entry.source_term.lower():
                    found = True
                elif search_lower in entry.definition.lower():
                    found = True
                else:
                    for trans_list in entry.translations.values():
                        if any(search_lower in t.lower() for t in trans_list):
                            found = True
                            break
                if not found:
                    continue

            results.append(entry)

        results.sort(key=lambda e: e.total_usage_count, reverse=True)

        return results[offset:offset + limit]

    def suggest_translations(
        self,
        term: str,
        target_language: str,
        author_id: Optional[str] = None,
        genre: Optional[ContentGenre] = None,
        medium: Optional[ContentMedium] = None,
        limit: int = 5
    ) -> List[Tuple[str, float, str]]:
        """Suggest translations for a term based on usage patterns."""
        entries = self.find_by_term(term)
        if not entries:
            return []

        suggestions = []

        for entry in entries:
            if target_language not in entry.translations:
                continue

            for translation in entry.translations[target_language]:
                confidence = 0.5
                reasons = []

                if author_id and author_id in entry.author_translations:
                    if entry.author_translations[author_id].get(target_language) == translation:
                        confidence += 0.3
                        author_count = entry.usage_by_author.get(author_id, 0)
                        reasons.append(f"Used {author_count}x by this author")

                if genre and genre.value in entry.usage_by_genre:
                    genre_count = entry.usage_by_genre[genre.value]
                    confidence += min(0.2, genre_count * 0.02)
                    reasons.append(f"Used {genre_count}x in {genre.value}")

                if medium and medium.value in entry.usage_by_medium:
                    medium_count = entry.usage_by_medium[medium.value]
                    confidence += min(0.1, medium_count * 0.01)
                    reasons.append(f"Used {medium_count}x in {medium.value}")

                if entry.total_usage_count > 10:
                    confidence += min(0.1, entry.total_usage_count * 0.005)
                    reasons.append(f"Total usage: {entry.total_usage_count}")

                if entry.is_verified:
                    confidence += 0.1
                    reasons.append("Verified entry")

                confidence = min(1.0, confidence)
                reason = "; ".join(reasons) if reasons else "Standard translation"

                suggestions.append((translation, confidence, reason))

        suggestions.sort(key=lambda x: x[1], reverse=True)

        seen = set()
        unique = []
        for trans, conf, reason in suggestions:
            if trans not in seen:
                seen.add(trans)
                unique.append((trans, conf, reason))

        return unique[:limit]

    # =========================================================================
    # RAG/Semantic Search
    # =========================================================================

    def set_embedding(
        self,
        entry_id: str,
        embedding: List[float]
    ) -> bool:
        """Set vector embedding for RAG search"""
        entry = self._entries.get(entry_id)
        if not entry:
            return False

        entry.embedding = embedding
        entry.updated_at = datetime.utcnow().isoformat()
        return True

    def add_semantic_tags(
        self,
        entry_id: str,
        tags: List[str]
    ) -> bool:
        """Add semantic tags for improved RAG retrieval"""
        entry = self._entries.get(entry_id)
        if not entry:
            return False

        for tag in tags:
            if tag not in entry.semantic_tags:
                entry.semantic_tags.append(tag)

        entry.updated_at = datetime.utcnow().isoformat()
        return True

    def semantic_search(
        self,
        query_embedding: List[float],
        limit: int = 10,
        min_similarity: float = 0.7
    ) -> List[Tuple[GlossaryEntry, float]]:
        """Search entries by vector similarity (for RAG)."""
        results = []

        for entry in self._entries.values():
            if not entry.embedding:
                continue

            similarity = self._cosine_similarity(query_embedding, entry.embedding)

            if similarity >= min_similarity:
                results.append((entry, similarity))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:limit]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        if len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot_product / (norm1 * norm2)

    # =========================================================================
    # Import/Export
    # =========================================================================

    def export_glossary(
        self,
        filter_criteria: Optional[GlossaryFilter] = None
    ) -> List[Dict[str, Any]]:
        """Export glossary entries as dictionaries"""
        if filter_criteria:
            entries = self.search(filter_criteria, limit=10000)
        else:
            entries = list(self._entries.values())

        return [
            {
                "entry_id": e.entry_id,
                "source_term": e.source_term,
                "source_language": e.source_language,
                "reading": e.reading,
                "category": e.category.value,
                "tags": e.tags,
                "translations": e.translations,
                "definition": e.definition,
                "usage_notes": e.usage_notes,
                "cultural_notes": e.cultural_notes,
                "total_usage_count": e.total_usage_count,
                "is_verified": e.is_verified
            }
            for e in entries
        ]

    def import_entries(
        self,
        entries_data: List[Dict[str, Any]],
        created_by: Optional[str] = None
    ) -> int:
        """Import glossary entries from dictionaries"""
        count = 0

        for data in entries_data:
            try:
                category = GlossaryCategory(data.get("category", "term"))

                self.create_entry(
                    source_term=data["source_term"],
                    source_language=data["source_language"],
                    translations=data.get("translations", {}),
                    category=category,
                    definition=data.get("definition", ""),
                    tags=data.get("tags", []),
                    reading=data.get("reading"),
                    usage_notes=data.get("usage_notes", ""),
                    cultural_notes=data.get("cultural_notes", ""),
                    created_by=created_by
                )
                count += 1
            except Exception as e:
                logger.warning(
                    "Failed to import entry",
                    term=data.get("source_term"),
                    error=str(e)
                )

        return count

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall glossary statistics"""
        total_entries = len(self._entries)
        total_usage = sum(e.total_usage_count for e in self._entries.values())

        by_category = {}
        for entry in self._entries.values():
            cat = entry.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

        by_language = {}
        for entry in self._entries.values():
            lang = entry.source_language
            by_language[lang] = by_language.get(lang, 0) + 1

        author_totals: Dict[str, int] = {}
        for entry in self._entries.values():
            for author_id, count in entry.usage_by_author.items():
                author_totals[author_id] = author_totals.get(author_id, 0) + count

        top_authors = sorted(
            author_totals.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "total_entries": total_entries,
            "total_usage_records": total_usage,
            "verified_entries": sum(1 for e in self._entries.values() if e.is_verified),
            "by_category": by_category,
            "by_source_language": by_language,
            "unique_authors": len(self._by_author),
            "unique_genres": len(self._by_genre),
            "top_authors": top_authors
        }


# ==============================================================================
# GLOBAL INSTANCE
# ==============================================================================
glossary_service = GlossaryService()

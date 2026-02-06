"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Memory with RAG
================================================================================

    AI_FIRST: Translation Memory & RAG System for Martial Arts Content
    AI_MODULE: Translation Memory & RAG System
    AI_DESCRIPTION: Sistema di memoria traduzione con RAG per apprendimento
    AI_BUSINESS: Migliora traduzioni nel tempo imparando da traduzioni precedenti
    AI_TEACHING: RAG, vector embeddings, semantic search, incremental learning

    Adapted from: SOFTWARE A - SISTEMA TRADUZIONE MANGAANIME AI-POWERED

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog

try:
    import numpy as np
except ImportError:
    np = None

try:
    from sqlalchemy.ext.asyncio import AsyncSession
except ImportError:
    AsyncSession = None

# ==============================================================================
# LOGGING
# ==============================================================================
logger = structlog.get_logger(__name__)


# ==============================================================================
# DATA MODELS
# ==============================================================================
@dataclass
class MemoryEntry:
    """Single entry in translation memory"""
    id: str
    source_text: str
    source_lang: str
    target_text: str
    target_lang: str
    confidence: float
    usage_count: int = 0
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Metadata
    context_tags: List[str] = field(default_factory=list)
    provider_source: str = ""
    refinement_count: int = 0
    cross_validated: bool = False

    # Vector embedding for semantic search
    embedding: Optional[List[float]] = None


@dataclass
class GlossaryTerm:
    """Specialized term in glossary"""
    id: str
    term: str
    language: str
    translations: Dict[str, str]
    domain: str
    examples: List[Dict[str, str]] = field(default_factory=list)
    notes: str = ""
    usage_count: int = 0


@dataclass
class MemorySearchResult:
    """Result from memory search"""
    entry: MemoryEntry
    similarity_score: float
    match_type: str


# ==============================================================================
# TRANSLATION MEMORY
# ==============================================================================
class TranslationMemory:
    """
    AI_MODULE: Translation Memory with RAG
    AI_DESCRIPTION: Memorizza e recupera traduzioni per migliorare qualità
    AI_BUSINESS: Apprendimento continuo, consistenza terminologica
    AI_TEACHING: RAG implementation, vector similarity, caching

    Features:
    - Semantic search with embeddings
    - Exact match for known phrases
    - Glossary management
    - Usage tracking for quality
    - Cross-language validation storage
    """

    def __init__(self, db_session: Optional[Any] = None):
        self.db_session = db_session

        # In-memory caches (not persistent)
        self._entry_cache: Dict[str, MemoryEntry] = {}
        self._glossary_cache: Dict[str, GlossaryTerm] = {}
        self._embedding_cache: Dict[str, List[float]] = {}

        self._embedding_model = None
        self._max_cache_size = 10000

    async def initialize(self):
        """Initialize translation memory"""
        if self.db_session:
            await self._load_frequent_entries()

        logger.info("translation_memory_initialized")

    # ==========================================================================
    # CORE OPERATIONS
    # ==========================================================================

    async def add_translation(
        self,
        source_text: str,
        source_lang: str,
        target_text: str,
        target_lang: str,
        confidence: float,
        context_tags: Optional[List[str]] = None,
        provider: str = "",
        cross_validated: bool = False
    ) -> str:
        """
        Add a translation to memory

        Returns entry ID
        """
        entry_id = self._generate_entry_id(source_text, source_lang, target_lang)

        existing = await self.get_entry(entry_id)

        if existing:
            existing.target_text = target_text
            existing.confidence = max(existing.confidence, confidence)
            existing.refinement_count += 1
            existing.updated_at = datetime.utcnow()
            existing.cross_validated = existing.cross_validated or cross_validated

            if context_tags:
                existing.context_tags = list(set(existing.context_tags + context_tags))

            await self._persist_entry(existing)

            logger.debug(
                "translation_memory_updated",
                entry_id=entry_id,
                refinements=existing.refinement_count
            )
        else:
            entry = MemoryEntry(
                id=entry_id,
                source_text=source_text,
                source_lang=source_lang,
                target_text=target_text,
                target_lang=target_lang,
                confidence=confidence,
                context_tags=context_tags or [],
                provider_source=provider,
                cross_validated=cross_validated
            )

            entry.embedding = await self._generate_embedding(source_text)

            await self._persist_entry(entry)
            self._entry_cache[entry_id] = entry

            logger.debug(
                "translation_memory_added",
                entry_id=entry_id,
                confidence=confidence
            )

        return entry_id

    async def get_relevant_context(
        self,
        text: str,
        source_lang: str,
        target_lang: str,
        max_results: int = 5
    ) -> Dict[str, Any]:
        """
        Get relevant context from translation memory for RAG

        Returns suggestions and glossary terms
        """
        context = {
            "suggestions": [],
            "glossary_terms": [],
            "similar_translations": []
        }

        # 1. Exact match check
        entry_id = self._generate_entry_id(text, source_lang, target_lang)
        exact_match = await self.get_entry(entry_id)

        if exact_match:
            context["suggestions"].append({
                "text": exact_match.target_text,
                "confidence": exact_match.confidence,
                "match_type": "exact",
                "usage_count": exact_match.usage_count
            })

            exact_match.usage_count += 1
            await self._persist_entry(exact_match)

        # 2. Semantic search for similar translations
        similar = await self._semantic_search(
            text, source_lang, target_lang, max_results
        )

        for result in similar:
            if result.entry.id != entry_id:
                context["similar_translations"].append({
                    "source": result.entry.source_text,
                    "translation": result.entry.target_text,
                    "similarity": result.similarity_score,
                    "confidence": result.entry.confidence
                })

        # 3. Glossary terms
        glossary_terms = await self._find_glossary_terms(
            text, source_lang, target_lang
        )
        context["glossary_terms"] = glossary_terms

        return context

    async def search(
        self,
        query: str,
        source_lang: str,
        target_lang: str,
        max_results: int = 10,
        min_confidence: float = 0.0
    ) -> List[MemorySearchResult]:
        """Search translation memory"""
        results = []

        semantic_results = await self._semantic_search(
            query, source_lang, target_lang, max_results * 2
        )

        for result in semantic_results:
            if result.entry.confidence >= min_confidence:
                results.append(result)

                if len(results) >= max_results:
                    break

        return results

    # ==========================================================================
    # GLOSSARY MANAGEMENT
    # ==========================================================================

    async def add_glossary_term(
        self,
        term: str,
        language: str,
        translations: Dict[str, str],
        domain: str = "general",
        examples: Optional[List[Dict[str, str]]] = None,
        notes: str = ""
    ) -> str:
        """Add term to glossary"""
        term_id = hashlib.md5(f"{term}:{language}".encode()).hexdigest()

        glossary_term = GlossaryTerm(
            id=term_id,
            term=term,
            language=language,
            translations=translations,
            domain=domain,
            examples=examples or [],
            notes=notes
        )

        self._glossary_cache[term_id] = glossary_term

        if self.db_session:
            await self._persist_glossary_term(glossary_term)

        logger.info(
            "glossary_term_added",
            term=term,
            language=language,
            translations=list(translations.keys())
        )

        return term_id

    async def get_glossary_term(
        self,
        term: str,
        language: str,
        target_lang: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Get glossary term with translation"""
        term_id = hashlib.md5(f"{term}:{language}".encode()).hexdigest()

        glossary_term = self._glossary_cache.get(term_id)

        if not glossary_term and self.db_session:
            glossary_term = await self._load_glossary_term(term_id)

        if not glossary_term:
            return None

        result = {
            "term": glossary_term.term,
            "language": glossary_term.language,
            "domain": glossary_term.domain,
            "notes": glossary_term.notes
        }

        if target_lang and target_lang in glossary_term.translations:
            result["translation"] = glossary_term.translations[target_lang]
        else:
            result["translations"] = glossary_term.translations

        return result

    async def _find_glossary_terms(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> List[Dict[str, Any]]:
        """Find glossary terms in text"""
        found_terms = []
        text_lower = text.lower()

        for term in self._glossary_cache.values():
            if term.language == source_lang and term.term.lower() in text_lower:
                translation = term.translations.get(target_lang)
                if translation:
                    found_terms.append({
                        "term": term.term,
                        "translation": translation,
                        "domain": term.domain
                    })

        return found_terms

    # ==========================================================================
    # LEARNING FROM COLLABORATIVE TRANSLATION
    # ==========================================================================

    async def learn_from_collaborative(
        self,
        source_text: str,
        source_lang: str,
        target_lang: str,
        final_translation: str,
        confidence: float,
        learnings: Dict[str, Any]
    ):
        """
        Store learnings from collaborative translation
        """
        await self.add_translation(
            source_text, source_lang,
            final_translation, target_lang,
            confidence,
            context_tags=["collaborative", "refined"],
            cross_validated=learnings.get("cross_ref_agreement", 0) > 0.5
        )

        if "stable_vocabulary" in learnings:
            for word in learnings["stable_vocabulary"]:
                pass

        logger.info(
            "collaborative_learnings_stored",
            source_hash=learnings.get("source_text_hash"),
            refinements=learnings.get("refinement_count", 0)
        )

    # ==========================================================================
    # INTERNAL METHODS
    # ==========================================================================

    def _generate_entry_id(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> str:
        """Generate unique entry ID"""
        key = f"{source_lang}:{target_lang}:{text}"
        return hashlib.md5(key.encode()).hexdigest()

    async def _generate_embedding(self, text: str) -> List[float]:
        """Generate embedding for text"""
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self._embedding_cache:
            return self._embedding_cache[cache_key]

        # Simple character-based embedding placeholder
        # In production, use sentence-transformers
        embedding = [0.0] * 384
        for i, char in enumerate(text[:384]):
            embedding[i] = ord(char) / 65535.0

        self._embedding_cache[cache_key] = embedding
        return embedding

    async def _semantic_search(
        self,
        query: str,
        source_lang: str,
        target_lang: str,
        max_results: int
    ) -> List[MemorySearchResult]:
        """Perform semantic search using embeddings"""
        query_embedding = await self._generate_embedding(query)

        results = []

        for entry in self._entry_cache.values():
            if entry.source_lang != source_lang or entry.target_lang != target_lang:
                continue

            if entry.embedding:
                similarity = self._cosine_similarity(query_embedding, entry.embedding)

                if similarity > 0.3:
                    results.append(MemorySearchResult(
                        entry=entry,
                        similarity_score=similarity,
                        match_type="semantic"
                    ))

        results.sort(key=lambda x: x.similarity_score, reverse=True)

        return results[:max_results]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between vectors"""
        if not vec1 or not vec2:
            return 0.0

        if np is not None:
            a = np.array(vec1)
            b = np.array(vec2)

            dot_product = np.dot(a, b)
            norm_a = np.linalg.norm(a)
            norm_b = np.linalg.norm(b)

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot_product / (norm_a * norm_b)
        else:
            # Fallback without numpy
            dot_product = sum(a * b for a, b in zip(vec1, vec2))
            norm_a = sum(a * a for a in vec1) ** 0.5
            norm_b = sum(b * b for b in vec2) ** 0.5

            if norm_a == 0 or norm_b == 0:
                return 0.0

            return dot_product / (norm_a * norm_b)

    async def get_entry(self, entry_id: str) -> Optional[MemoryEntry]:
        """Get entry by ID"""
        if entry_id in self._entry_cache:
            return self._entry_cache[entry_id]

        if self.db_session:
            return await self._load_entry(entry_id)

        return None

    async def _persist_entry(self, entry: MemoryEntry):
        """Persist entry to database"""
        if not self.db_session:
            self._entry_cache[entry.id] = entry

            if len(self._entry_cache) > self._max_cache_size:
                sorted_entries = sorted(
                    self._entry_cache.items(),
                    key=lambda x: x[1].usage_count
                )

                for entry_id, _ in sorted_entries[:100]:
                    del self._entry_cache[entry_id]
            return

        self._entry_cache[entry.id] = entry

    async def _load_entry(self, entry_id: str) -> Optional[MemoryEntry]:
        """Load entry from database"""
        return None

    async def _load_frequent_entries(self):
        """Load frequently used entries into cache"""
        pass

    async def _persist_glossary_term(self, term: GlossaryTerm):
        """Persist glossary term to database"""
        pass

    async def _load_glossary_term(self, term_id: str) -> Optional[GlossaryTerm]:
        """Load glossary term from database"""
        return None

    # ==========================================================================
    # STATISTICS
    # ==========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """Get translation memory statistics"""
        total_entries = len(self._entry_cache)
        total_glossary = len(self._glossary_cache)

        lang_pairs = {}
        for entry in self._entry_cache.values():
            pair = f"{entry.source_lang}->{entry.target_lang}"
            lang_pairs[pair] = lang_pairs.get(pair, 0) + 1

        if total_entries > 0:
            avg_confidence = sum(
                e.confidence for e in self._entry_cache.values()
            ) / total_entries
        else:
            avg_confidence = 0.0

        return {
            "total_entries": total_entries,
            "total_glossary_terms": total_glossary,
            "language_pairs": lang_pairs,
            "average_confidence": avg_confidence,
            "cache_size_bytes": len(str(self._entry_cache))
        }


# ==============================================================================
# GLOBAL INSTANCE
# ==============================================================================
translation_memory = TranslationMemory()

"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Translation Memory with RAG
================================================================================

    AI_MODULE: Translation Memory & RAG System
    AI_DESCRIPTION: Sistema di memoria traduzione con RAG per arti marziali
    AI_BUSINESS: Migliora traduzioni live imparando da traduzioni precedenti
    AI_TEACHING: RAG, vector embeddings, semantic search, glossary termini tecnici

    ADATTATO DA: SOFTWARE A - SISTEMA TRADUZIONE MANGAANIME AI-POWERED
    DATA: 19 Novembre 2025

================================================================================
"""

# ==============================================================================
# IMPORTS
# ==============================================================================
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
import numpy as np
import structlog

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

    # Vector embedding for semantic search
    embedding: Optional[List[float]] = None


@dataclass
class GlossaryTerm:
    """
    Specialized term in martial arts glossary

    Examples:
    - "kata" → {"it": "forma", "en": "form", "es": "forma"}
    - "kumite" → {"it": "combattimento", "en": "sparring"}
    - "kiai" → {"it": "grido", "en": "shout"}
    """
    id: str
    term: str
    language: str
    translations: Dict[str, str]  # {target_lang: translation}
    domain: str  # "karate", "judo", "aikido", "taekwondo", "general"
    examples: List[Dict[str, str]] = field(default_factory=list)
    notes: str = ""
    usage_count: int = 0


@dataclass
class MemorySearchResult:
    """Result from memory search"""
    entry: MemoryEntry
    similarity_score: float
    match_type: str  # "exact", "semantic", "fuzzy"


# ==============================================================================
# MARTIAL ARTS GLOSSARY - PRE-LOADED TERMS
# ==============================================================================
MARTIAL_ARTS_GLOSSARY = {
    # Karate terms
    "kata": {"ja": "型", "it": "forma", "en": "form", "es": "forma"},
    "kumite": {"ja": "組手", "it": "combattimento", "en": "sparring", "es": "combate"},
    "kiai": {"ja": "気合", "it": "grido", "en": "shout", "es": "grito"},
    "dojo": {"ja": "道場", "it": "palestra", "en": "training hall", "es": "gimnasio"},
    "sensei": {"ja": "先生", "it": "maestro", "en": "teacher", "es": "maestro"},
    "obi": {"ja": "帯", "it": "cintura", "en": "belt", "es": "cinturón"},
    "gi": {"ja": "着", "it": "divisa", "en": "uniform", "es": "uniforme"},

    # Judo terms
    "randori": {"ja": "乱取り", "it": "pratica libera", "en": "free practice"},
    "ippon": {"ja": "一本", "it": "punto pieno", "en": "full point"},
    "waza-ari": {"ja": "技あり", "it": "mezzo punto", "en": "half point"},

    # Common techniques
    "tsuki": {"ja": "突き", "it": "pugno", "en": "punch", "es": "puñetazo"},
    "geri": {"ja": "蹴り", "it": "calcio", "en": "kick", "es": "patada"},
    "uke": {"ja": "受け", "it": "parata", "en": "block", "es": "bloqueo"},

    # Positions
    "kamae": {"ja": "構え", "it": "guardia", "en": "stance", "es": "posición"},
    "seiza": {"ja": "正座", "it": "seduta formale", "en": "formal sitting"},
}


# ==============================================================================
# TRANSLATION MEMORY
# ==============================================================================
class TranslationMemory:
    """
    AI_MODULE: Translation Memory with RAG for Martial Arts
    AI_DESCRIPTION: Memorizza e recupera traduzioni per migliorare live translation
    AI_BUSINESS: Consistenza terminologica arti marziali, apprendimento continuo
    AI_TEACHING: RAG implementation, vector similarity, glossary management

    Features:
    - Semantic search with embeddings
    - Martial arts glossary pre-loaded
    - Exact match for known phrases
    - Usage tracking for quality
    """

    def __init__(self):
        # In-memory caches
        self._entry_cache: Dict[str, MemoryEntry] = {}
        self._glossary_cache: Dict[str, GlossaryTerm] = {}
        self._embedding_cache: Dict[str, List[float]] = {}

        # Max entries to keep in memory
        self._max_cache_size = 10000

        # Load martial arts glossary
        self._load_martial_arts_glossary()

    def _load_martial_arts_glossary(self):
        """Load pre-defined martial arts terms"""
        for term, translations in MARTIAL_ARTS_GLOSSARY.items():
            term_id = hashlib.md5(f"{term}:ja".encode()).hexdigest()

            self._glossary_cache[term_id] = GlossaryTerm(
                id=term_id,
                term=term,
                language="ja",  # Most martial arts terms are Japanese
                translations=translations,
                domain="martial_arts"
            )

        logger.info(
            "martial_arts_glossary_loaded",
            terms_count=len(MARTIAL_ARTS_GLOSSARY)
        )

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
        provider: str = ""
    ) -> str:
        """
        Add a translation to memory
        Returns entry ID
        """
        entry_id = self._generate_entry_id(source_text, source_lang, target_lang)

        # Check if exists
        existing = self._entry_cache.get(entry_id)

        if existing:
            # Update with refinement
            existing.target_text = target_text
            existing.confidence = max(existing.confidence, confidence)
            existing.refinement_count += 1
            existing.updated_at = datetime.utcnow()

            if context_tags:
                existing.context_tags = list(set(existing.context_tags + context_tags))

            logger.debug(
                "translation_memory_updated",
                entry_id=entry_id,
                refinements=existing.refinement_count
            )
        else:
            # Create new entry
            entry = MemoryEntry(
                id=entry_id,
                source_text=source_text,
                source_lang=source_lang,
                target_text=target_text,
                target_lang=target_lang,
                confidence=confidence,
                context_tags=context_tags or [],
                provider_source=provider
            )

            # Generate embedding for semantic search
            entry.embedding = self._generate_embedding(source_text)
            self._entry_cache[entry_id] = entry

            logger.debug(
                "translation_memory_added",
                entry_id=entry_id,
                confidence=confidence
            )

            # Cache size management
            if len(self._entry_cache) > self._max_cache_size:
                self._evict_least_used()

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

        Returns suggestions and glossary terms for improving translation
        """
        context = {
            "suggestions": [],
            "glossary_terms": [],
            "similar_translations": []
        }

        # 1. Exact match check
        entry_id = self._generate_entry_id(text, source_lang, target_lang)
        exact_match = self._entry_cache.get(entry_id)

        if exact_match:
            context["suggestions"].append({
                "text": exact_match.target_text,
                "confidence": exact_match.confidence,
                "match_type": "exact",
                "usage_count": exact_match.usage_count
            })
            exact_match.usage_count += 1

        # 2. Semantic search for similar translations
        similar = self._semantic_search(text, source_lang, target_lang, max_results)

        for result in similar:
            if result.entry.id != entry_id:
                context["similar_translations"].append({
                    "source": result.entry.source_text,
                    "translation": result.entry.target_text,
                    "similarity": result.similarity_score,
                    "confidence": result.entry.confidence
                })

        # 3. Find glossary terms in text
        glossary_terms = self._find_glossary_terms(text, source_lang, target_lang)
        context["glossary_terms"] = glossary_terms

        return context

    # ==========================================================================
    # GLOSSARY METHODS
    # ==========================================================================

    def _find_glossary_terms(
        self,
        text: str,
        source_lang: str,
        target_lang: str
    ) -> List[Dict[str, Any]]:
        """Find martial arts glossary terms in text"""
        found_terms = []
        text_lower = text.lower()

        for term in self._glossary_cache.values():
            if term.term.lower() in text_lower:
                translation = term.translations.get(target_lang)
                if translation:
                    found_terms.append({
                        "term": term.term,
                        "translation": translation,
                        "domain": term.domain
                    })
                    term.usage_count += 1

        return found_terms

    def add_glossary_term(
        self,
        term: str,
        language: str,
        translations: Dict[str, str],
        domain: str = "martial_arts"
    ) -> str:
        """Add custom term to glossary"""
        term_id = hashlib.md5(f"{term}:{language}".encode()).hexdigest()

        self._glossary_cache[term_id] = GlossaryTerm(
            id=term_id,
            term=term,
            language=language,
            translations=translations,
            domain=domain
        )

        logger.info(
            "glossary_term_added",
            term=term,
            translations=list(translations.keys())
        )

        return term_id

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

    def _generate_embedding(self, text: str) -> List[float]:
        """
        Generate embedding for text

        NOTE: In production, use sentence-transformers:
        from sentence_transformers import SentenceTransformer
        model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
        """
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self._embedding_cache:
            return self._embedding_cache[cache_key]

        # Simple character-based embedding (placeholder)
        embedding = [0.0] * 384
        for i, char in enumerate(text[:384]):
            embedding[i] = ord(char) / 65535.0

        self._embedding_cache[cache_key] = embedding
        return embedding

    def _semantic_search(
        self,
        query: str,
        source_lang: str,
        target_lang: str,
        max_results: int
    ) -> List[MemorySearchResult]:
        """Perform semantic search using embeddings"""
        query_embedding = self._generate_embedding(query)
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

        a = np.array(vec1)
        b = np.array(vec2)

        dot_product = np.dot(a, b)
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)

        if norm_a == 0 or norm_b == 0:
            return 0.0

        return float(dot_product / (norm_a * norm_b))

    def _evict_least_used(self):
        """Remove least used entries when cache is full"""
        sorted_entries = sorted(
            self._entry_cache.items(),
            key=lambda x: x[1].usage_count
        )

        for entry_id, _ in sorted_entries[:100]:
            del self._entry_cache[entry_id]

        logger.debug("cache_eviction", removed=100)

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

        avg_confidence = 0.0
        if total_entries > 0:
            avg_confidence = sum(
                e.confidence for e in self._entry_cache.values()
            ) / total_entries

        return {
            "total_entries": total_entries,
            "total_glossary_terms": total_glossary,
            "language_pairs": lang_pairs,
            "average_confidence": avg_confidence,
            "martial_arts_terms": len(MARTIAL_ARTS_GLOSSARY)
        }


# ==============================================================================
# GLOBAL INSTANCE
# ==============================================================================
translation_memory = TranslationMemory()

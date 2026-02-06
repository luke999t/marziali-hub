"""
🎓 AI_MODULE: ChromaDB Semantic Retriever
🎓 AI_DESCRIPTION: Semantic search using vector embeddings for knowledge retrieval
🎓 AI_BUSINESS: Improve AI agent accuracy with semantic understanding vs keyword matching
🎓 AI_TEACHING: Vector embeddings + cosine similarity + ChromaDB persistent storage

📄 ALTERNATIVE_VALUTATE:
- Keyword matching only: Fast but misses semantic meaning
- Elasticsearch: Too heavy for our use case
- Pinecone: Cloud-only, costs for production

💡 PERCHÉ_QUESTA_SOLUZIONE:
- ChromaDB: Open source, embeds in Python, persistent local storage
- Sentence transformers: State-of-art embeddings for semantic search
- Hybrid search: Combine semantic + keyword for best results

🔧 DEPENDENCIES:
- chromadb==0.4.18: Vector database
- sentence-transformers: Embedding models

⚠️ LIMITAZIONI_NOTE:
- First query slow (~2-3s) due to model loading
- Embedding cache needed for performance
- Max 8192 tokens per document

🎯 METRICHE_SUCCESSO:
- Retrieval accuracy: >85% relevant results
- Query time: <500ms (after warm-up)
- Storage: <500MB for 10k documents

📊 PERFORMANCE:
- Embedding generation: ~100ms per document
- Query time: ~200-300ms
- Memory: ~2GB RAM (model loaded)

🧪 TEST_COVERAGE:
- test_chroma_retriever.py
  - test_semantic_search()
  - test_hybrid_search()
  - test_relevance_ranking()
"""

import logging
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
import json
import hashlib

try:
    import chromadb
    # Note: chromadb.config.Settings is deprecated in 0.4.x
    # Use chromadb.PersistentClient or chromadb.Client directly
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logging.warning("ChromaDB not available. Install with: pip install chromadb")

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDINGS_AVAILABLE = True
except ImportError:
    EMBEDDINGS_AVAILABLE = False
    logging.warning("Sentence transformers not available. Install with: pip install sentence-transformers")

logger = logging.getLogger(__name__)


@dataclass
class SemanticResult:
    """Result from semantic search"""
    content: Dict[str, Any]
    relevance_score: float  # 0-1, higher is more relevant
    source_type: str  # "form", "sequence", "pattern"
    document_id: str
    metadata: Dict[str, Any]


class ChromaRetriever:
    """
    Semantic retrieval using ChromaDB + embeddings

    FEATURES:
    - Vector embeddings for semantic understanding
    - Persistent storage (survives restarts)
    - Hybrid search (semantic + keyword)
    - Fast similarity search
    """

    def __init__(
        self,
        collection_name: str = "martial_arts_knowledge",
        persist_directory: Optional[Path] = None,
        embedding_model: str = "all-MiniLM-L6-v2",  # Fast, good quality
        in_memory: bool = False  # Use in-memory client for testing
    ):
        """
        Initialize ChromaDB retriever with semantic search capabilities.

        Args:
            collection_name: Name for ChromaDB collection
            persist_directory: Where to store ChromaDB data (ignored if in_memory=True)
            embedding_model: Sentence transformer model name
            in_memory: If True, use in-memory client (useful for testing)

        🎓 AI_TEACHING: ChromaDB 0.4.x API changes:
        - OLD: chromadb.Client(Settings(chroma_db_impl="duckdb+parquet", ...))
        - NEW: chromadb.PersistentClient(path=...) for persistent storage
        - NEW: chromadb.Client() for in-memory (ephemeral) storage
        """
        if not CHROMADB_AVAILABLE:
            raise ImportError("ChromaDB not installed. Run: pip install chromadb")

        if not EMBEDDINGS_AVAILABLE:
            raise ImportError("Sentence transformers not installed. Run: pip install sentence-transformers")

        self.collection_name = collection_name
        self.in_memory = in_memory
        self.persist_directory = persist_directory or Path("data/chroma_db")

        # Initialize ChromaDB client based on mode
        # ChromaDB 0.4.x uses PersistentClient for disk storage, Client for in-memory
        if in_memory:
            # In-memory client for testing - no disk persistence
            self.client = chromadb.Client()
            logger.info("ChromaDB initialized in-memory mode (ephemeral)")
        else:
            # Persistent client - survives restarts
            self.persist_directory.mkdir(parents=True, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(self.persist_directory))
            logger.info(f"ChromaDB initialized with persistence at: {self.persist_directory}")

        # Get or create collection using get_or_create_collection (idempotent)
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            metadata={"description": "Martial arts knowledge base"}
        )
        logger.info(f"Collection ready: {collection_name} (count: {self.collection.count()})")

        # Load embedding model
        logger.info(f"Loading embedding model: {embedding_model}")
        self.embedding_model = SentenceTransformer(embedding_model)
        logger.info("Embedding model loaded successfully")

        # Cache for embeddings
        self.embedding_cache: Dict[str, List[float]] = {}

    def add_documents(
        self,
        documents: List[Dict[str, Any]],
        source_type: str,
        batch_size: int = 100
    ) -> int:
        """
        Add documents to ChromaDB

        Args:
            documents: List of knowledge items
            source_type: "form", "sequence", "pattern"
            batch_size: Batch size for embedding generation

        Returns:
            Number of documents added
        """
        if not documents:
            return 0

        logger.info(f"Adding {len(documents)} documents of type '{source_type}'")

        ids = []
        embeddings = []
        metadatas = []
        documents_text = []

        for i, doc in enumerate(documents):
            # Generate unique ID
            doc_id = self._generate_document_id(doc, source_type)
            ids.append(doc_id)

            # Convert doc to searchable text
            text = self._document_to_text(doc, source_type)
            documents_text.append(text)

            # Generate embedding
            embedding = self._get_embedding(text)
            embeddings.append(embedding)

            # Metadata
            metadata = {
                "source_type": source_type,
                "name": doc.get("name", "unknown"),
                "style": doc.get("style", "generic")
            }
            metadatas.append(metadata)

        # Add to collection in batches
        for i in range(0, len(ids), batch_size):
            batch_ids = ids[i:i+batch_size]
            batch_embeddings = embeddings[i:i+batch_size]
            batch_metadatas = metadatas[i:i+batch_size]
            batch_documents = documents_text[i:i+batch_size]

            self.collection.add(
                ids=batch_ids,
                embeddings=batch_embeddings,
                metadatas=batch_metadatas,
                documents=batch_documents
            )

        # Note: PersistentClient auto-persists, no need for client.persist()
        logger.info(f"Successfully added {len(documents)} documents")
        return len(documents)

    def semantic_search(
        self,
        query: str,
        top_k: int = 5,
        min_relevance: float = 0.5,
        source_type_filter: Optional[str] = None
    ) -> List[SemanticResult]:
        """
        Semantic search using vector similarity

        Args:
            query: User question
            top_k: Number of results
            min_relevance: Minimum relevance score (0-1)
            source_type_filter: Filter by source type ("form", "sequence", etc)

        Returns:
            List of semantic results sorted by relevance
        """
        # Generate query embedding
        query_embedding = self._get_embedding(query)

        # Build where filter
        where_filter = None
        if source_type_filter:
            where_filter = {"source_type": source_type_filter}

        # Query ChromaDB
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k * 2,  # Get more, filter later
            where=where_filter,
            include=["embeddings", "metadatas", "documents", "distances"]
        )

        # Parse results
        semantic_results = []

        if results['ids'] and len(results['ids']) > 0:
            for i, doc_id in enumerate(results['ids'][0]):
                # Distance to relevance score (closer distance = higher relevance)
                distance = results['distances'][0][i]
                relevance = 1 / (1 + distance)  # Convert distance to 0-1 score

                if relevance < min_relevance:
                    continue

                metadata = results['metadatas'][0][i]
                document = results['documents'][0][i]

                # Parse document back to dict (stored as JSON string)
                try:
                    content = json.loads(document) if document.startswith('{') else {"text": document}
                except:
                    content = {"text": document}

                result = SemanticResult(
                    content=content,
                    relevance_score=relevance,
                    source_type=metadata.get("source_type", "unknown"),
                    document_id=doc_id,
                    metadata=metadata
                )

                semantic_results.append(result)

        # Sort by relevance
        semantic_results.sort(key=lambda x: x.relevance_score, reverse=True)

        # Return top-k
        return semantic_results[:top_k]

    def hybrid_search(
        self,
        query: str,
        top_k: int = 5,
        semantic_weight: float = 0.7,
        keyword_weight: float = 0.3
    ) -> List[SemanticResult]:
        """
        Hybrid search combining semantic + keyword matching

        Args:
            query: User question
            top_k: Number of results
            semantic_weight: Weight for semantic score (0-1)
            keyword_weight: Weight for keyword score (0-1)

        Returns:
            Combined results
        """
        # Semantic search
        semantic_results = self.semantic_search(query, top_k=top_k * 2, min_relevance=0.3)

        # Simple keyword boost
        query_keywords = set(query.lower().split())

        for result in semantic_results:
            # Check if keywords appear in document
            doc_text = json.dumps(result.content).lower()
            keyword_matches = sum(1 for kw in query_keywords if kw in doc_text)
            keyword_score = keyword_matches / len(query_keywords) if query_keywords else 0

            # Combine scores
            result.relevance_score = (
                semantic_weight * result.relevance_score +
                keyword_weight * keyword_score
            )

        # Re-sort and return top-k
        semantic_results.sort(key=lambda x: x.relevance_score, reverse=True)
        return semantic_results[:top_k]

    def clear_collection(self):
        """
        Clear all documents from collection.

        Deletes and recreates the collection to remove all documents.
        With PersistentClient, changes are automatically persisted.
        """
        self.client.delete_collection(name=self.collection_name)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"description": "Martial arts knowledge base"}
        )
        # Note: PersistentClient auto-persists, no need for client.persist()
        logger.info("Collection cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get collection statistics"""
        count = self.collection.count()
        return {
            "collection_name": self.collection_name,
            "document_count": count,
            "persist_directory": str(self.persist_directory),
            "embedding_model": self.embedding_model.get_sentence_embedding_dimension()
        }

    def _document_to_text(self, doc: Dict[str, Any], source_type: str) -> str:
        """Convert document dict to searchable text"""
        parts = []

        # Name
        if "name" in doc:
            parts.append(f"Name: {doc['name']}")

        # Style
        if "style" in doc:
            parts.append(f"Style: {doc['style']}")

        # Techniques
        if "techniques" in doc:
            techniques_str = ", ".join(doc["techniques"])
            parts.append(f"Techniques: {techniques_str}")

        # Description
        if "description" in doc:
            parts.append(f"Description: {doc['description']}")

        # Keywords
        if "keywords" in doc:
            keywords_str = ", ".join(doc["keywords"])
            parts.append(f"Keywords: {keywords_str}")

        text = " | ".join(parts)

        # Store full document as JSON for retrieval
        full_json = json.dumps(doc, ensure_ascii=False)

        return full_json

    def _generate_document_id(self, doc: Dict[str, Any], source_type: str) -> str:
        """Generate unique ID for document"""
        # Use content hash
        doc_str = json.dumps(doc, sort_keys=True)
        content_hash = hashlib.md5(doc_str.encode()).hexdigest()
        return f"{source_type}_{content_hash}"

    def _get_embedding(self, text: str) -> List[float]:
        """
        Get embedding for text (with caching)

        Args:
            text: Text to embed

        Returns:
            Embedding vector
        """
        # Check cache
        cache_key = hashlib.md5(text.encode()).hexdigest()
        if cache_key in self.embedding_cache:
            return self.embedding_cache[cache_key]

        # Generate embedding
        embedding = self.embedding_model.encode(text, convert_to_numpy=True)
        embedding_list = embedding.tolist()

        # Cache
        if len(self.embedding_cache) < 1000:  # Max cache size
            self.embedding_cache[cache_key] = embedding_list

        return embedding_list


# Fallback if ChromaDB not available
class SimpleKeywordRetriever:
    """Fallback retriever using keyword matching only"""

    def __init__(self, *args, **kwargs):
        logger.warning("Using fallback keyword retriever (ChromaDB not available)")
        self.documents: List[Tuple[Dict, str]] = []

    def add_documents(self, documents: List[Dict], source_type: str, **kwargs) -> int:
        for doc in documents:
            self.documents.append((doc, source_type))
        return len(documents)

    def semantic_search(self, query: str, top_k: int = 5, **kwargs) -> List[SemanticResult]:
        query_keywords = set(query.lower().split())
        results = []

        for doc, source_type in self.documents:
            doc_text = json.dumps(doc).lower()
            matches = sum(1 for kw in query_keywords if kw in doc_text)
            score = matches / len(query_keywords) if query_keywords else 0

            if score > 0:
                results.append(SemanticResult(
                    content=doc,
                    relevance_score=score,
                    source_type=source_type,
                    document_id=str(hash(json.dumps(doc))),
                    metadata={}
                ))

        results.sort(key=lambda x: x.relevance_score, reverse=True)
        return results[:top_k]

    def hybrid_search(self, *args, **kwargs):
        return self.semantic_search(*args, **kwargs)

    def get_stats(self):
        return {"document_count": len(self.documents), "mode": "fallback"}


# Auto-select best retriever
def get_retriever(*args, **kwargs):
    """Get best available retriever"""
    if CHROMADB_AVAILABLE and EMBEDDINGS_AVAILABLE:
        return ChromaRetriever(*args, **kwargs)
    else:
        return SimpleKeywordRetriever(*args, **kwargs)

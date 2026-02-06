"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Unit Tests for Glossary Service
================================================================================

    AI_FIRST: Unit Tests for Glossary and Terminology Management
    AI_DESCRIPTION: Comprehensive tests for terminology, usage tracking, and RAG

================================================================================
"""

import pytest
from datetime import datetime

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.unit]


# ==============================================================================
# TEST: Enums
# ==============================================================================
class TestEnums:
    """Tests for enum types"""

    def test_glossary_category_values(self):
        """Test GlossaryCategory enum values"""
        from services.video_studio.glossary_service import GlossaryCategory

        assert GlossaryCategory.TERM.value == "term"
        assert GlossaryCategory.TECHNIQUE.value == "technique"
        assert GlossaryCategory.HONORIFIC.value == "honorific"
        assert GlossaryCategory.STANCE.value == "stance"
        assert GlossaryCategory.WEAPON.value == "weapon"
        assert GlossaryCategory.PHILOSOPHY.value == "philosophy"

    def test_content_genre_values(self):
        """Test ContentGenre enum values"""
        from services.video_studio.glossary_service import ContentGenre

        assert ContentGenre.MARTIAL_ARTS.value == "martial_arts"
        assert ContentGenre.WUXIA.value == "wuxia"
        assert ContentGenre.XIANXIA.value == "xianxia"
        assert ContentGenre.ACTION.value == "action"
        assert ContentGenre.SHOUNEN.value == "shounen"

    def test_content_medium_values(self):
        """Test ContentMedium enum values"""
        from services.video_studio.glossary_service import ContentMedium

        assert ContentMedium.INSTRUCTIONAL.value == "instructional"
        assert ContentMedium.DOCUMENTARY.value == "documentary"
        assert ContentMedium.DEMONSTRATION.value == "demonstration"
        assert ContentMedium.COMPETITION.value == "competition"
        assert ContentMedium.ANIME.value == "anime"


# ==============================================================================
# TEST: Data Classes
# ==============================================================================
class TestDataClasses:
    """Tests for data classes"""

    def test_usage_record_creation(self):
        """Test UsageRecord dataclass"""
        from services.video_studio.glossary_service import UsageRecord, ContentGenre

        record = UsageRecord(
            usage_id="usage-001",
            entry_id="entry-001",
            author_id="author-001",
            author_name="Test Author",
            genre=ContentGenre.MARTIAL_ARTS,
            context="Training session",
            translation_used="pugno"
        )

        assert record.usage_id == "usage-001"
        assert record.author_id == "author-001"
        assert record.genre == ContentGenre.MARTIAL_ARTS

    def test_glossary_entry_creation(self):
        """Test GlossaryEntry dataclass"""
        from services.video_studio.glossary_service import GlossaryEntry, GlossaryCategory

        entry = GlossaryEntry(
            entry_id="entry-001",
            source_term="sensei",
            source_language="ja",
            category=GlossaryCategory.HONORIFIC,
            translations={"it": ["maestro"], "en": ["teacher"]},
            definition="Honorific for teacher"
        )

        assert entry.source_term == "sensei"
        assert entry.category == GlossaryCategory.HONORIFIC
        assert "maestro" in entry.translations["it"]

    def test_glossary_entry_defaults(self):
        """Test GlossaryEntry default values"""
        from services.video_studio.glossary_service import GlossaryEntry, GlossaryCategory

        entry = GlossaryEntry(
            entry_id="entry-001",
            source_term="test",
            source_language="en"
        )

        assert entry.category == GlossaryCategory.TERM
        assert entry.tags == []
        assert entry.translations == {}
        assert entry.total_usage_count == 0
        assert entry.is_verified is False

    def test_glossary_filter_creation(self):
        """Test GlossaryFilter dataclass"""
        from services.video_studio.glossary_service import GlossaryFilter, GlossaryCategory, ContentGenre

        filter_obj = GlossaryFilter(
            source_language="ja",
            target_language="it",
            category=GlossaryCategory.TECHNIQUE,
            genres=[ContentGenre.MARTIAL_ARTS],
            min_usage=5
        )

        assert filter_obj.source_language == "ja"
        assert filter_obj.category == GlossaryCategory.TECHNIQUE


# ==============================================================================
# TEST: GlossaryService Entry Management
# ==============================================================================
class TestGlossaryServiceEntryManagement:
    """Tests for entry management"""

    def test_create_entry(self, glossary_service):
        """Test creating a glossary entry"""
        from services.video_studio.glossary_service import GlossaryCategory

        entry = glossary_service.create_entry(
            source_term="kata",
            source_language="ja",
            translations={"it": ["forma"], "en": ["form", "pattern"]},
            category=GlossaryCategory.FORM,
            definition="Sequence of movements",
            tags=["karate", "traditional"]
        )

        assert entry is not None
        assert entry.source_term == "kata"
        assert entry.category == GlossaryCategory.FORM
        assert "forma" in entry.translations["it"]

    def test_get_entry(self, glossary_service):
        """Test getting an entry by ID"""
        entry = glossary_service.create_entry(
            source_term="dojo",
            source_language="ja",
            translations={"it": ["palestra"]}
        )

        retrieved = glossary_service.get_entry(entry.entry_id)

        assert retrieved is not None
        assert retrieved.source_term == "dojo"

    def test_get_entry_not_found(self, glossary_service):
        """Test getting non-existent entry"""
        result = glossary_service.get_entry("non-existent-id")
        assert result is None

    def test_find_by_term(self, glossary_service):
        """Test finding entries by term"""
        glossary_service.create_entry(
            source_term="kumite",
            source_language="ja",
            translations={"it": ["combattimento"]}
        )

        entries = glossary_service.find_by_term("kumite")

        assert len(entries) >= 1
        assert entries[0].source_term == "kumite"

    def test_find_by_term_case_insensitive(self, glossary_service):
        """Test case-insensitive term search"""
        glossary_service.create_entry(
            source_term="Sensei",
            source_language="ja",
            translations={"it": ["maestro"]}
        )

        entries = glossary_service.find_by_term("sensei")
        assert len(entries) >= 1

        entries = glossary_service.find_by_term("SENSEI")
        assert len(entries) >= 1

    def test_find_by_term_with_language_filter(self, glossary_service):
        """Test finding by term with language filter"""
        glossary_service.create_entry(
            source_term="master",
            source_language="en",
            translations={"it": ["maestro"]}
        )
        glossary_service.create_entry(
            source_term="master",
            source_language="zh",
            translations={"it": ["maestro"]}
        )

        entries = glossary_service.find_by_term("master", source_language="en")
        assert len(entries) == 1
        assert entries[0].source_language == "en"

    def test_update_entry(self, glossary_service):
        """Test updating an entry"""
        entry = glossary_service.create_entry(
            source_term="obi",
            source_language="ja",
            translations={"it": ["cintura"]}
        )

        updated = glossary_service.update_entry(
            entry.entry_id,
            translations={"it": ["cintura", "fascia"]},
            definition="Belt worn in martial arts",
            is_verified=True
        )

        assert updated is not None
        assert len(updated.translations["it"]) == 2
        assert updated.is_verified is True

    def test_update_entry_not_found(self, glossary_service):
        """Test updating non-existent entry"""
        result = glossary_service.update_entry("non-existent", definition="test")
        assert result is None

    def test_delete_entry(self, glossary_service):
        """Test deleting an entry"""
        entry = glossary_service.create_entry(
            source_term="to_delete",
            source_language="en",
            translations={"it": ["da_eliminare"]}
        )

        result = glossary_service.delete_entry(entry.entry_id)
        assert result is True

        # Verify deleted
        assert glossary_service.get_entry(entry.entry_id) is None

    def test_delete_entry_not_found(self, glossary_service):
        """Test deleting non-existent entry"""
        result = glossary_service.delete_entry("non-existent")
        assert result is False


# ==============================================================================
# TEST: Translation Management
# ==============================================================================
class TestTranslationManagement:
    """Tests for translation management"""

    def test_add_translation(self, glossary_service):
        """Test adding a translation"""
        entry = glossary_service.create_entry(
            source_term="gi",
            source_language="ja",
            translations={"it": ["divisa"]}
        )

        result = glossary_service.add_translation(
            entry.entry_id, "en", "uniform"
        )

        assert result is True
        updated = glossary_service.get_entry(entry.entry_id)
        assert "uniform" in updated.translations["en"]

    def test_add_translation_no_duplicate(self, glossary_service):
        """Test that duplicate translations are not added"""
        entry = glossary_service.create_entry(
            source_term="test",
            source_language="en",
            translations={"it": ["prova"]}
        )

        glossary_service.add_translation(entry.entry_id, "it", "prova")

        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.translations["it"].count("prova") == 1

    def test_set_author_translation(self, glossary_service):
        """Test setting author-specific translation"""
        entry = glossary_service.create_entry(
            source_term="energy",
            source_language="en",
            translations={"it": ["energia"]}
        )

        result = glossary_service.set_author_translation(
            entry.entry_id, "author-001", "it", "forza vitale"
        )

        assert result is True
        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.author_translations["author-001"]["it"] == "forza vitale"

    def test_set_preferred_translation(self, glossary_service):
        """Test setting preferred translation for context"""
        entry = glossary_service.create_entry(
            source_term="kick",
            source_language="en",
            translations={"it": ["calcio", "pedata"]}
        )

        result = glossary_service.set_preferred_translation(
            entry.entry_id, "martial_arts", "calcio"
        )

        assert result is True
        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.preferred_translations["martial_arts"] == "calcio"

    def test_get_best_translation_author(self, glossary_service):
        """Test getting best translation with author preference"""
        from services.video_studio.glossary_service import ContentGenre

        entry = glossary_service.create_entry(
            source_term="spirit",
            source_language="en",
            translations={"it": ["spirito"]}
        )
        glossary_service.set_author_translation(
            entry.entry_id, "author-001", "it", "anima"
        )

        result = glossary_service.get_best_translation(
            entry.entry_id, "it", author_id="author-001"
        )

        assert result == "anima"

    def test_get_best_translation_genre(self, glossary_service):
        """Test getting best translation with genre preference"""
        from services.video_studio.glossary_service import ContentGenre

        entry = glossary_service.create_entry(
            source_term="power",
            source_language="en",
            translations={"it": ["potere", "forza"]}
        )
        glossary_service.set_preferred_translation(
            entry.entry_id, ContentGenre.MARTIAL_ARTS.value, "forza"
        )

        result = glossary_service.get_best_translation(
            entry.entry_id, "it", genre=ContentGenre.MARTIAL_ARTS
        )

        assert result == "forza"

    def test_get_best_translation_fallback(self, glossary_service):
        """Test getting best translation with fallback"""
        entry = glossary_service.create_entry(
            source_term="test",
            source_language="en",
            translations={"it": ["prova", "test"]}
        )

        result = glossary_service.get_best_translation(entry.entry_id, "it")

        assert result == "prova"  # First translation


# ==============================================================================
# TEST: Usage Tracking
# ==============================================================================
class TestUsageTracking:
    """Tests for usage tracking"""

    def test_record_usage(self, glossary_service):
        """Test recording term usage"""
        from services.video_studio.glossary_service import ContentGenre, ContentMedium

        entry = glossary_service.create_entry(
            source_term="strike",
            source_language="en",
            translations={"it": ["colpo"]}
        )

        record = glossary_service.record_usage(
            entry_id=entry.entry_id,
            translation_used="colpo",
            context="Combat scene",
            author_id="author-001",
            author_name="Test Author",
            genre=ContentGenre.MARTIAL_ARTS,
            medium=ContentMedium.INSTRUCTIONAL
        )

        assert record is not None
        assert record.translation_used == "colpo"

        # Verify usage count updated
        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.total_usage_count == 1

    def test_record_usage_increments_counts(self, glossary_service):
        """Test that usage recording increments various counts"""
        from services.video_studio.glossary_service import ContentGenre

        entry = glossary_service.create_entry(
            source_term="punch",
            source_language="en",
            translations={"it": ["pugno"]}
        )

        # Record multiple usages
        for _ in range(5):
            glossary_service.record_usage(
                entry_id=entry.entry_id,
                translation_used="pugno",
                author_id="author-001",
                genre=ContentGenre.MARTIAL_ARTS
            )

        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.total_usage_count == 5
        assert updated.usage_by_author["author-001"] == 5
        assert updated.usage_by_genre["martial_arts"] == 5

    def test_get_usage_statistics(self, glossary_service):
        """Test getting usage statistics"""
        from services.video_studio.glossary_service import ContentGenre, ContentMedium

        entry = glossary_service.create_entry(
            source_term="block",
            source_language="en",
            translations={"it": ["parata"]}
        )

        glossary_service.record_usage(
            entry_id=entry.entry_id,
            translation_used="parata",
            author_id="author-001",
            author_name="Author One",
            genre=ContentGenre.MARTIAL_ARTS,
            medium=ContentMedium.INSTRUCTIONAL
        )
        glossary_service.record_usage(
            entry_id=entry.entry_id,
            translation_used="parata",
            author_id="author-002",
            author_name="Author Two",
            genre=ContentGenre.ACTION
        )

        stats = glossary_service.get_usage_statistics(entry.entry_id)

        assert stats is not None
        assert stats.total_count == 2
        assert len(stats.by_author) == 2
        assert len(stats.by_genre) == 2

    def test_get_author_terms(self, glossary_service):
        """Test getting terms used by an author"""
        entry1 = glossary_service.create_entry(
            source_term="term1",
            source_language="en",
            translations={"it": ["termine1"]}
        )
        entry2 = glossary_service.create_entry(
            source_term="term2",
            source_language="en",
            translations={"it": ["termine2"]}
        )

        # Record usage for author
        for _ in range(3):
            glossary_service.record_usage(
                entry_id=entry1.entry_id,
                translation_used="termine1",
                author_id="test-author"
            )
        glossary_service.record_usage(
            entry_id=entry2.entry_id,
            translation_used="termine2",
            author_id="test-author"
        )

        results = glossary_service.get_author_terms("test-author")

        assert len(results) == 2
        # Should be sorted by usage count
        assert results[0][1] == 3  # entry1 has 3 usages

    def test_get_genre_terms(self, glossary_service):
        """Test getting terms used in a genre"""
        from services.video_studio.glossary_service import ContentGenre

        entry = glossary_service.create_entry(
            source_term="technique",
            source_language="en",
            translations={"it": ["tecnica"]}
        )

        for _ in range(5):
            glossary_service.record_usage(
                entry_id=entry.entry_id,
                translation_used="tecnica",
                genre=ContentGenre.MARTIAL_ARTS
            )

        results = glossary_service.get_genre_terms(ContentGenre.MARTIAL_ARTS)

        assert len(results) >= 1
        assert results[0][1] == 5


# ==============================================================================
# TEST: Search and Query
# ==============================================================================
class TestSearchAndQuery:
    """Tests for search functionality"""

    def test_search_by_source_language(self, glossary_service):
        """Test search by source language"""
        from services.video_studio.glossary_service import GlossaryFilter

        glossary_service.create_entry(
            source_term="test_ja",
            source_language="ja",
            translations={"it": ["prova"]}
        )
        glossary_service.create_entry(
            source_term="test_en",
            source_language="en",
            translations={"it": ["prova"]}
        )

        filter_obj = GlossaryFilter(source_language="ja")
        results = glossary_service.search(filter_obj)

        assert all(e.source_language == "ja" for e in results)

    def test_search_by_category(self, glossary_service):
        """Test search by category"""
        from services.video_studio.glossary_service import GlossaryFilter, GlossaryCategory

        glossary_service.create_entry(
            source_term="sensei",
            source_language="ja",
            translations={"it": ["maestro"]},
            category=GlossaryCategory.HONORIFIC
        )
        glossary_service.create_entry(
            source_term="mae-geri",
            source_language="ja",
            translations={"it": ["calcio frontale"]},
            category=GlossaryCategory.TECHNIQUE
        )

        filter_obj = GlossaryFilter(category=GlossaryCategory.TECHNIQUE)
        results = glossary_service.search(filter_obj)

        assert all(e.category == GlossaryCategory.TECHNIQUE for e in results)

    def test_search_by_text(self, glossary_service):
        """Test text search"""
        from services.video_studio.glossary_service import GlossaryFilter

        glossary_service.create_entry(
            source_term="karate",
            source_language="ja",
            translations={"it": ["karate"]},
            definition="Empty hand martial art"
        )

        filter_obj = GlossaryFilter(search_text="empty")
        results = glossary_service.search(filter_obj)

        assert len(results) >= 1

    def test_search_by_min_usage(self, glossary_service):
        """Test search by minimum usage"""
        from services.video_studio.glossary_service import GlossaryFilter

        entry = glossary_service.create_entry(
            source_term="popular",
            source_language="en",
            translations={"it": ["popolare"]}
        )

        # Record 10 usages
        for _ in range(10):
            glossary_service.record_usage(
                entry_id=entry.entry_id,
                translation_used="popolare"
            )

        filter_obj = GlossaryFilter(min_usage=5)
        results = glossary_service.search(filter_obj)

        assert all(e.total_usage_count >= 5 for e in results)

    def test_search_pagination(self, glossary_service):
        """Test search pagination"""
        from services.video_studio.glossary_service import GlossaryFilter

        # Create multiple entries
        for i in range(20):
            glossary_service.create_entry(
                source_term=f"term_{i}",
                source_language="en",
                translations={"it": [f"termine_{i}"]}
            )

        filter_obj = GlossaryFilter()
        results = glossary_service.search(filter_obj, limit=5, offset=0)

        assert len(results) == 5

        # Get next page
        results_page2 = glossary_service.search(filter_obj, limit=5, offset=5)
        assert len(results_page2) == 5
        assert results[0].entry_id != results_page2[0].entry_id

    def test_suggest_translations(self, glossary_service):
        """Test translation suggestions"""
        entry = glossary_service.create_entry(
            source_term="kick",
            source_language="en",
            translations={"it": ["calcio", "pedata"]}
        )

        # Add usage to increase confidence
        for _ in range(10):
            glossary_service.record_usage(
                entry_id=entry.entry_id,
                translation_used="calcio"
            )

        suggestions = glossary_service.suggest_translations(
            term="kick",
            target_language="it"
        )

        assert len(suggestions) >= 1
        # Suggestions should include translation, confidence, and reason
        assert len(suggestions[0]) == 3


# ==============================================================================
# TEST: RAG/Semantic Search
# ==============================================================================
class TestSemanticSearch:
    """Tests for RAG/semantic search"""

    def test_set_embedding(self, glossary_service):
        """Test setting embedding for an entry"""
        entry = glossary_service.create_entry(
            source_term="test",
            source_language="en",
            translations={"it": ["prova"]}
        )

        embedding = [0.1] * 384
        result = glossary_service.set_embedding(entry.entry_id, embedding)

        assert result is True
        updated = glossary_service.get_entry(entry.entry_id)
        assert updated.embedding is not None

    def test_add_semantic_tags(self, glossary_service):
        """Test adding semantic tags"""
        entry = glossary_service.create_entry(
            source_term="punch",
            source_language="en",
            translations={"it": ["pugno"]}
        )

        result = glossary_service.add_semantic_tags(
            entry.entry_id,
            ["striking", "combat", "offense"]
        )

        assert result is True
        updated = glossary_service.get_entry(entry.entry_id)
        assert "striking" in updated.semantic_tags

    def test_semantic_search(self, glossary_service):
        """Test semantic search by embedding similarity"""
        # Create entries with embeddings
        entry1 = glossary_service.create_entry(
            source_term="similar1",
            source_language="en",
            translations={"it": ["simile1"]}
        )
        entry2 = glossary_service.create_entry(
            source_term="similar2",
            source_language="en",
            translations={"it": ["simile2"]}
        )

        # Set similar embeddings
        glossary_service.set_embedding(entry1.entry_id, [1.0, 0.5, 0.0])
        glossary_service.set_embedding(entry2.entry_id, [0.9, 0.4, 0.1])

        # Search with similar query
        results = glossary_service.semantic_search(
            query_embedding=[1.0, 0.5, 0.0],
            min_similarity=0.5
        )

        assert len(results) >= 1

    def test_cosine_similarity(self, glossary_service):
        """Test cosine similarity calculation"""
        # Identical vectors
        sim = glossary_service._cosine_similarity([1, 0, 0], [1, 0, 0])
        assert sim == pytest.approx(1.0)

        # Orthogonal vectors
        sim = glossary_service._cosine_similarity([1, 0, 0], [0, 1, 0])
        assert sim == pytest.approx(0.0)

        # Different length vectors
        sim = glossary_service._cosine_similarity([1, 0], [1, 0, 0])
        assert sim == 0.0


# ==============================================================================
# TEST: Import/Export
# ==============================================================================
class TestImportExport:
    """Tests for import/export functionality"""

    def test_export_glossary(self, glossary_service):
        """Test exporting glossary"""
        from services.video_studio.glossary_service import GlossaryCategory

        glossary_service.create_entry(
            source_term="export_test",
            source_language="ja",
            translations={"it": ["test_esportazione"]},
            category=GlossaryCategory.TECHNIQUE
        )

        exported = glossary_service.export_glossary()

        assert len(exported) >= 1
        assert "source_term" in exported[0]
        assert "translations" in exported[0]

    def test_export_with_filter(self, glossary_service):
        """Test exporting with filter"""
        from services.video_studio.glossary_service import GlossaryFilter, GlossaryCategory

        glossary_service.create_entry(
            source_term="filter_test_ja",
            source_language="ja",
            translations={"it": ["prova_filtro"]}
        )
        glossary_service.create_entry(
            source_term="filter_test_en",
            source_language="en",
            translations={"it": ["prova_filtro"]}
        )

        filter_obj = GlossaryFilter(source_language="ja")
        exported = glossary_service.export_glossary(filter_obj)

        assert all(e["source_language"] == "ja" for e in exported)

    def test_import_entries(self, glossary_service):
        """Test importing entries"""
        entries_data = [
            {
                "source_term": "imported1",
                "source_language": "ja",
                "translations": {"it": ["importato1"]},
                "category": "term"
            },
            {
                "source_term": "imported2",
                "source_language": "ja",
                "translations": {"it": ["importato2"]},
                "category": "technique"
            }
        ]

        count = glossary_service.import_entries(entries_data)

        assert count == 2
        assert len(glossary_service.find_by_term("imported1")) == 1
        assert len(glossary_service.find_by_term("imported2")) == 1

    def test_import_with_invalid_data(self, glossary_service):
        """Test importing with invalid data"""
        entries_data = [
            {
                "source_term": "valid",
                "source_language": "ja",
                "translations": {"it": ["valido"]}
            },
            {
                # Missing required fields
                "translations": {}
            }
        ]

        count = glossary_service.import_entries(entries_data)

        # Should import valid entry only
        assert count == 1


# ==============================================================================
# TEST: Statistics
# ==============================================================================
class TestStatistics:
    """Tests for statistics"""

    def test_get_statistics_empty(self, glossary_service):
        """Test statistics on empty glossary"""
        stats = glossary_service.get_statistics()

        assert stats["total_entries"] == 0
        assert stats["total_usage_records"] == 0

    def test_get_statistics_with_data(self, glossary_service):
        """Test statistics with data"""
        from services.video_studio.glossary_service import GlossaryCategory, ContentGenre

        # Create entries
        entry1 = glossary_service.create_entry(
            source_term="stat_term1",
            source_language="ja",
            translations={"it": ["stat_termine1"]},
            category=GlossaryCategory.TECHNIQUE
        )
        entry2 = glossary_service.create_entry(
            source_term="stat_term2",
            source_language="en",
            translations={"it": ["stat_termine2"]},
            category=GlossaryCategory.TERM
        )

        # Verify entry
        glossary_service.update_entry(entry1.entry_id, is_verified=True)

        # Record usage
        glossary_service.record_usage(
            entry_id=entry1.entry_id,
            translation_used="stat_termine1",
            author_id="author-001",
            genre=ContentGenre.MARTIAL_ARTS
        )

        stats = glossary_service.get_statistics()

        assert stats["total_entries"] == 2
        assert stats["verified_entries"] == 1
        assert "technique" in stats["by_category"]
        assert "ja" in stats["by_source_language"]


# ==============================================================================
# TEST: Global Instance
# ==============================================================================
class TestGlobalInstance:
    """Tests for global glossary_service instance"""

    def test_global_instance_exists(self):
        """Test that global instance is available"""
        from services.video_studio.glossary_service import glossary_service

        assert glossary_service is not None

    def test_global_instance_functional(self):
        """Test that global instance works"""
        from services.video_studio.glossary_service import glossary_service

        entry = glossary_service.create_entry(
            source_term="global_test_term",
            source_language="en",
            translations={"it": ["termine_test_globale"]}
        )

        assert entry is not None

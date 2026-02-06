"""
Unit Tests - Video Moderation Validation
Test metadata validation logic in isolation
"""

import pytest
from modules.video_moderation.validation import VideoMetadataValidator, validate_video_metadata
from models.video import Video, VideoCategory, Difficulty


@pytest.mark.unit
class TestVideoMetadataValidator:
    """Test VideoMetadataValidator class"""

    @pytest.fixture
    def validator(self):
        """Create validator instance"""
        return VideoMetadataValidator()

    @pytest.fixture
    def valid_video(self):
        """Create a valid video object"""
        video = Video(
            title="Introduzione al Tai Chi per Principianti",
            description="Questo video copre le basi fondamentali del Tai Chi, ideale per chi inizia. Imparerai le posizioni di base e i primi movimenti.",
            tags=["tai chi", "principianti", "basi"],
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="https://example.com/thumbnail.jpg",
            duration=600,  # 10 minutes
            tier_required="FREE"
        )
        return video

    # === TITLE VALIDATION ===

    def test_validate_title_missing(self, validator):
        """Test title missing is blocking issue"""
        video = Video(title=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Title mancante" in issue for issue in result["issues"])

    def test_validate_title_too_short(self, validator):
        """Test title too short is blocking issue"""
        video = Video(title="Short")
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("troppo corto" in issue for issue in result["issues"])

    def test_validate_title_too_long(self, validator):
        """Test title too long is blocking issue"""
        video = Video(title="A" * 300)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("troppo lungo" in issue for issue in result["issues"])

    def test_warn_title_very_long(self, validator):
        """Test title warning for length > 100 chars"""
        video = Video(
            title="This is a very long title that exceeds 100 characters and should generate a warning but not an error since its under 255 chars",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert result["valid"] == True  # No blocking issues
        assert any("molto lungo" in warn for warn in result["warnings"])

    def test_warn_title_no_capital(self, validator):
        """Test title warning for missing capital letter"""
        video = Video(
            title="introduzione al tai chi senza maiuscola iniziale ok",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("maiuscola" in warn for warn in result["warnings"])

    def test_warn_title_excessive_caps(self, validator):
        """Test title warning for too many capitals"""
        video = Video(
            title="TUTTO IN MAIUSCOLO È CONSIDERATO URLARE ONLINE",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("maiuscole" in warn for warn in result["warnings"])

    # === DESCRIPTION VALIDATION ===

    def test_validate_description_missing(self, validator):
        """Test description missing is blocking issue"""
        video = Video(description=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Descrizione mancante" in issue for issue in result["issues"])

    def test_validate_description_too_short(self, validator):
        """Test description too short is blocking issue"""
        video = Video(description="Short")
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("troppo corta" in issue for issue in result["issues"])

    def test_validate_description_too_long(self, validator):
        """Test description over 5000 chars is blocking issue"""
        video = Video(description="A" * 6000)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("troppo lunga" in issue for issue in result["issues"])

    def test_warn_description_very_long(self, validator):
        """Test description warning for > 2000 chars"""
        video = Video(
            title="Valid Title Here",
            description="A" * 2500,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("molto lunga" in warn for warn in result["warnings"])

    # === TAGS VALIDATION ===

    def test_warn_tags_missing(self, validator):
        """Test missing tags generates warning"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            tags=None,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("Nessun tag" in warn for warn in result["warnings"])

    def test_warn_tags_too_few(self, validator):
        """Test < 3 tags generates warning"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            tags=["tag1", "tag2"],
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("Pochi tag" in warn for warn in result["warnings"])

    def test_warn_tags_too_many(self, validator):
        """Test > 10 tags generates warning"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            tags=[f"tag{i}" for i in range(15)],
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("Troppi tag" in warn for warn in result["warnings"])

    def test_warn_tags_duplicates(self, validator):
        """Test duplicate tags generate warning"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            tags=["tai chi", "tai chi", "principianti"],
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert any("duplicati" in warn for warn in result["warnings"])

    # === CATEGORY VALIDATION ===

    def test_validate_category_missing(self, validator):
        """Test category missing is blocking issue"""
        video = Video(category=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Categoria mancante" in issue for issue in result["issues"])

    def test_validate_category_other_not_allowed(self, validator):
        """Test OTHER category is not allowed"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            category=VideoCategory.OTHER,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("OTHER non permessa" in issue for issue in result["issues"])

    # === DIFFICULTY VALIDATION ===

    def test_validate_difficulty_missing(self, validator):
        """Test difficulty missing is blocking issue"""
        video = Video(difficulty=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Difficoltà mancante" in issue for issue in result["issues"])

    # === THUMBNAIL VALIDATION ===

    def test_validate_thumbnail_missing(self, validator):
        """Test thumbnail missing is blocking issue"""
        video = Video(thumbnail_url=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Thumbnail mancante" in issue for issue in result["issues"])

    # === DURATION VALIDATION ===

    def test_warn_duration_very_short(self, validator):
        """Test warning for video < 1 minute"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE",
            duration=30  # 30 seconds
        )
        result = validator.validate(video)

        assert any("molto corto" in warn for warn in result["warnings"])

    def test_warn_duration_very_long(self, validator):
        """Test warning for video > 2 hours"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE",
            duration=8000  # > 2 hours
        )
        result = validator.validate(video)

        assert any("molto lungo" in warn for warn in result["warnings"])

    # === TIER VALIDATION ===

    def test_validate_tier_missing(self, validator):
        """Test tier missing is blocking issue"""
        video = Video(tier_required=None)
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Tier richiesto mancante" in issue for issue in result["issues"])

    def test_validate_tier_invalid(self, validator):
        """Test invalid tier is blocking issue"""
        video = Video(
            title="Valid Title Here",
            description="A" * 60,
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="INVALID_TIER"
        )
        result = validator.validate(video)

        assert result["valid"] == False
        assert any("Tier non valido" in issue for issue in result["issues"])

    # === SCORE CALCULATION ===

    def test_score_perfect(self, validator, valid_video):
        """Test perfect video gets score 100"""
        result = validator.validate(valid_video)

        assert result["valid"] == True
        assert result["score"] == 100
        assert len(result["issues"]) == 0

    def test_score_with_warnings(self, validator):
        """Test score calculation with warnings only"""
        video = Video(
            title="Valid Title Here But Very Long Over 100 Characters Which Should Generate A Warning Not An Error For Length",
            description="A" * 60,
            tags=["tag1"],  # Too few tags
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE",
            duration=30  # Too short
        )
        result = validator.validate(video)

        assert result["valid"] == True  # No blocking issues
        assert result["score"] < 100
        assert result["score"] >= 80  # 3-4 warnings = -15 to -20
        assert len(result["warnings"]) >= 3

    def test_score_with_issues(self, validator):
        """Test score calculation with blocking issues"""
        video = Video(
            title="Short",  # Too short - blocking
            description="Also short",  # Too short - blocking
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url="test.jpg",
            tier_required="FREE"
        )
        result = validator.validate(video)

        assert result["valid"] == False
        assert result["score"] <= 60  # 2 issues = -40
        assert len(result["issues"]) == 2

    def test_score_minimum_zero(self, validator):
        """Test score cannot go below 0"""
        video = Video(
            title=None,  # -20
            description=None,  # -20
            category=None,  # -20
            difficulty=None,  # -20
            thumbnail_url=None,  # -20
            tier_required=None  # -20
        )
        result = validator.validate(video)

        assert result["score"] == 0
        assert result["valid"] == False
        assert len(result["issues"]) >= 6

    # === HELPER FUNCTION ===

    def test_validate_video_metadata_helper(self, valid_video):
        """Test convenience helper function"""
        result = validate_video_metadata(valid_video)

        assert "valid" in result
        assert "score" in result
        assert "issues" in result
        assert "warnings" in result
        assert result["valid"] == True
        assert result["score"] == 100

    # === COMPLETE VALIDATION SCENARIOS ===

    def test_complete_validation_all_valid(self, validator, valid_video):
        """Test complete validation with all fields valid"""
        result = validator.validate(valid_video)

        assert result == {
            "valid": True,
            "score": 100,
            "issues": [],
            "warnings": []
        }

    def test_complete_validation_multiple_issues(self, validator):
        """Test complete validation with multiple issues"""
        video = Video(
            title="Bad",  # Too short
            description="Bad",  # Too short
            category=VideoCategory.OTHER,  # Not allowed
            difficulty=Difficulty.BEGINNER,
            thumbnail_url=None,  # Missing
            tier_required="INVALID"  # Invalid
        )
        result = validator.validate(video)

        assert result["valid"] == False
        assert len(result["issues"]) == 5
        assert result["score"] == 0

    def test_complete_validation_mixed_issues_warnings(self, validator):
        """Test validation with both issues and warnings"""
        video = Video(
            title="Valid Title For Video",
            description="A" * 2500,  # Warning: very long
            tags=["tag1"],  # Warning: too few
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            thumbnail_url=None,  # Issue: missing
            tier_required="FREE",
            duration=30  # Warning: very short
        )
        result = validator.validate(video)

        assert result["valid"] == False  # Has blocking issues
        assert len(result["issues"]) == 1  # Missing thumbnail
        assert len(result["warnings"]) >= 3  # Long description, few tags, short duration
        assert result["score"] == 65  # 100 - 20 (1 issue) - 15 (3 warnings)

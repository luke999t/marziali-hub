"""
================================================================================
AI_MODULE: TestValidators
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test unitari per validazione Pydantic schemas - ZERO MOCK
AI_BUSINESS: Previene dati invalidi nel sistema (security + data quality)
AI_TEACHING: Pydantic validators, field constraints, regex validation

ZERO_MOCK_POLICY:
- Test unitari puri su Pydantic schemas
- Nessuna dipendenza esterna, solo validazione

COVERAGE_TARGET: 100% su validators in schemas.py
================================================================================
"""

import pytest
from pydantic import ValidationError
from uuid import uuid4
from datetime import datetime

# Import schemas
from api.v1.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    VideoCreateRequest,
    VideoUpdateRequest,
    VideoCategory,
    Difficulty,
    VideoProgressUpdate,
    RefreshTokenRequest,
    MessageResponse,
    ErrorResponse,
)


# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.unit]


# ==============================================================================
# TEST: Email Validation
# ==============================================================================
class TestEmailValidation:
    """Test email validation in auth schemas."""

    VALID_EMAILS = [
        "test@example.com",
        "user.name@domain.org",
        "user+tag@example.co.uk",
        "test123@subdomain.domain.com",
        "a@b.co",
    ]

    INVALID_EMAILS = [
        "not-an-email",
        "@nodomain.com",
        "no@",
        "spaces in@email.com",
        "double@@email.com",
        "",
    ]

    @pytest.mark.parametrize("email", VALID_EMAILS)
    def test_valid_emails_accepted_register(self, email):
        """Email valide sono accettate in registrazione."""
        user = UserRegisterRequest(
            email=email,
            username="validuser123",
            password="ValidPass123!",
            full_name="Test User"
        )
        assert user.email == email

    @pytest.mark.parametrize("email", INVALID_EMAILS)
    def test_invalid_emails_rejected_register(self, email):
        """Email invalide sollevano ValidationError in registrazione."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email=email,
                username="validuser123",
                password="ValidPass123!",
                full_name="Test User"
            )
        # Verify it's an email validation error
        assert "email" in str(exc_info.value).lower() or "value" in str(exc_info.value).lower()

    @pytest.mark.parametrize("email", VALID_EMAILS)
    def test_valid_emails_accepted_login(self, email):
        """Email valide sono accettate in login."""
        login = UserLoginRequest(email=email, password="anypassword")
        assert login.email == email

    @pytest.mark.parametrize("email", INVALID_EMAILS)
    def test_invalid_emails_rejected_login(self, email):
        """Email invalide sollevano ValidationError in login."""
        with pytest.raises(ValidationError):
            UserLoginRequest(email=email, password="anypassword")


# ==============================================================================
# TEST: Password Validation
# ==============================================================================
class TestPasswordValidation:
    """Test password strength validation."""

    VALID_PASSWORDS = [
        "ValidPass123!",
        "MyP4ssword",
        "Str0ngP@ss",
        "Test1234",
        "aB3defgh",
    ]

    INVALID_PASSWORDS_NO_UPPER = [
        "nouppercase123",
        "all_lowercase1",
        "12345678a",
    ]

    INVALID_PASSWORDS_NO_LOWER = [
        "NOLOWERCASE123",
        "ALL_UPPERCASE1",
        "12345678A",
    ]

    INVALID_PASSWORDS_NO_DIGIT = [
        "NoDigitsHere",
        "Password!@#",
        "abcdefgH",
    ]

    INVALID_PASSWORDS_TOO_SHORT = [
        "Short1",
        "Ab1",
        "1234567",
    ]

    @pytest.mark.parametrize("password", VALID_PASSWORDS)
    def test_valid_passwords_accepted(self, password):
        """Password valide sono accettate."""
        user = UserRegisterRequest(
            email="test@example.com",
            username="validuser123",
            password=password,
            full_name="Test User"
        )
        assert user.password == password

    @pytest.mark.parametrize("password", INVALID_PASSWORDS_NO_UPPER)
    def test_password_requires_uppercase(self, password):
        """Password senza maiuscole solleva errore."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email="test@example.com",
                username="validuser123",
                password=password,
                full_name="Test User"
            )
        assert "uppercase" in str(exc_info.value).lower()

    @pytest.mark.parametrize("password", INVALID_PASSWORDS_NO_LOWER)
    def test_password_requires_lowercase(self, password):
        """Password senza minuscole solleva errore."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email="test@example.com",
                username="validuser123",
                password=password,
                full_name="Test User"
            )
        assert "lowercase" in str(exc_info.value).lower()

    @pytest.mark.parametrize("password", INVALID_PASSWORDS_NO_DIGIT)
    def test_password_requires_digit(self, password):
        """Password senza numeri solleva errore."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email="test@example.com",
                username="validuser123",
                password=password,
                full_name="Test User"
            )
        assert "digit" in str(exc_info.value).lower()

    @pytest.mark.parametrize("password", INVALID_PASSWORDS_TOO_SHORT)
    def test_password_minimum_length(self, password):
        """Password troppo corte sollevano errore."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email="test@example.com",
                username="validuser123",
                password=password,
                full_name="Test User"
            )
        # Should fail either on length or password strength
        error_str = str(exc_info.value).lower()
        assert "length" in error_str or "character" in error_str or "digit" in error_str or "uppercase" in error_str


# ==============================================================================
# TEST: Username Validation
# ==============================================================================
class TestUsernameValidation:
    """Test username format validation."""

    VALID_USERNAMES = [
        "validuser",
        "user123",
        "test_user",
        "User_Name_123",
        "abc",
    ]

    INVALID_USERNAMES_FORMAT = [
        "user@name",
        "user name",
        "user-name",
        "user.name",
    ]

    INVALID_USERNAMES_LENGTH = [
        "ab",  # Too short (min 3)
        "a" * 51,  # Too long (max 50)
    ]

    @pytest.mark.parametrize("username", VALID_USERNAMES)
    def test_valid_usernames_accepted(self, username):
        """Username validi sono accettati."""
        user = UserRegisterRequest(
            email="test@example.com",
            username=username,
            password="ValidPass123!",
            full_name="Test User"
        )
        assert user.username == username

    @pytest.mark.parametrize("username", INVALID_USERNAMES_FORMAT)
    def test_invalid_username_format_rejected(self, username):
        """Username con caratteri non validi sollevano errore."""
        with pytest.raises(ValidationError) as exc_info:
            UserRegisterRequest(
                email="test@example.com",
                username=username,
                password="ValidPass123!",
                full_name="Test User"
            )
        error_str = str(exc_info.value).lower()
        assert "username" in error_str or "letters" in error_str or "numbers" in error_str

    @pytest.mark.parametrize("username", INVALID_USERNAMES_LENGTH)
    def test_invalid_username_length_rejected(self, username):
        """Username con lunghezza invalida sollevano errore."""
        with pytest.raises(ValidationError):
            UserRegisterRequest(
                email="test@example.com",
                username=username,
                password="ValidPass123!",
                full_name="Test User"
            )


# ==============================================================================
# TEST: Video Schema Validation
# ==============================================================================
class TestVideoSchemaValidation:
    """Test video create/update schema validation."""

    def test_video_create_valid(self):
        """Video creation con tutti i campi validi."""
        video = VideoCreateRequest(
            title="Test Video Title",
            description="A test video description",
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            style="Karate",
            tags=["karate", "beginner"],
            tier_required="free",
            is_premium=False,
            instructor_name="Sensei Test"
        )
        assert video.title == "Test Video Title"
        assert video.category == VideoCategory.TECHNIQUE
        assert video.difficulty == Difficulty.BEGINNER

    def test_video_create_minimal(self):
        """Video creation con campi minimi richiesti."""
        video = VideoCreateRequest(
            title="Minimal Video",
            category=VideoCategory.KATA,
            difficulty=Difficulty.INTERMEDIATE
        )
        assert video.title == "Minimal Video"
        assert video.tags == []
        assert video.tier_required == "free"

    def test_video_title_required(self):
        """Title è obbligatorio."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                category=VideoCategory.TECHNIQUE,
                difficulty=Difficulty.BEGINNER
            )

    def test_video_title_not_empty(self):
        """Title non può essere vuoto."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                title="",
                category=VideoCategory.TECHNIQUE,
                difficulty=Difficulty.BEGINNER
            )

    def test_video_title_max_length(self):
        """Title ha lunghezza massima."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                title="A" * 256,  # Max is 255
                category=VideoCategory.TECHNIQUE,
                difficulty=Difficulty.BEGINNER
            )

    def test_video_category_enum(self):
        """Category deve essere un valore enum valido."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                title="Test",
                category="invalid_category",
                difficulty=Difficulty.BEGINNER
            )

    def test_video_difficulty_enum(self):
        """Difficulty deve essere un valore enum valido."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                title="Test",
                category=VideoCategory.TECHNIQUE,
                difficulty="invalid_difficulty"
            )

    def test_video_ppv_price_positive(self):
        """PPV price deve essere >= 0."""
        video = VideoCreateRequest(
            title="Premium Video",
            category=VideoCategory.DEMO,
            difficulty=Difficulty.ADVANCED,
            ppv_price=9.99
        )
        assert video.ppv_price == 9.99

    def test_video_ppv_price_not_negative(self):
        """PPV price non può essere negativo."""
        with pytest.raises(ValidationError):
            VideoCreateRequest(
                title="Premium Video",
                category=VideoCategory.DEMO,
                difficulty=Difficulty.ADVANCED,
                ppv_price=-1.00
            )

    @pytest.mark.parametrize("category", list(VideoCategory))
    def test_all_video_categories_valid(self, category):
        """Tutte le categorie video sono valide."""
        video = VideoCreateRequest(
            title="Test",
            category=category,
            difficulty=Difficulty.BEGINNER
        )
        assert video.category == category

    @pytest.mark.parametrize("difficulty", list(Difficulty))
    def test_all_difficulties_valid(self, difficulty):
        """Tutti i livelli difficoltà sono validi."""
        video = VideoCreateRequest(
            title="Test",
            category=VideoCategory.TECHNIQUE,
            difficulty=difficulty
        )
        assert video.difficulty == difficulty


# ==============================================================================
# TEST: Video Progress Schema
# ==============================================================================
class TestVideoProgressValidation:
    """Test video progress update validation."""

    def test_progress_valid(self):
        """Progress update valido."""
        progress = VideoProgressUpdate(
            position_seconds=120,
            quality="1080p"
        )
        assert progress.position_seconds == 120
        assert progress.quality == "1080p"

    def test_progress_position_required(self):
        """Position è obbligatorio."""
        with pytest.raises(ValidationError):
            VideoProgressUpdate(quality="720p")

    def test_progress_position_non_negative(self):
        """Position deve essere >= 0."""
        with pytest.raises(ValidationError):
            VideoProgressUpdate(position_seconds=-1)

    def test_progress_position_zero_valid(self):
        """Position = 0 è valido."""
        progress = VideoProgressUpdate(position_seconds=0)
        assert progress.position_seconds == 0

    def test_progress_quality_optional(self):
        """Quality è opzionale."""
        progress = VideoProgressUpdate(position_seconds=60)
        assert progress.quality is None


# ==============================================================================
# TEST: Token Schema
# ==============================================================================
class TestTokenSchemaValidation:
    """Test token-related schema validation."""

    def test_refresh_token_request_valid(self):
        """Refresh token request valido."""
        request = RefreshTokenRequest(refresh_token="some.jwt.token")
        assert request.refresh_token == "some.jwt.token"

    def test_refresh_token_required(self):
        """Refresh token è obbligatorio."""
        with pytest.raises(ValidationError):
            RefreshTokenRequest()


# ==============================================================================
# TEST: Response Schemas
# ==============================================================================
class TestResponseSchemas:
    """Test response schema validation."""

    def test_message_response(self):
        """MessageResponse schema."""
        response = MessageResponse(message="Operation successful")
        assert response.message == "Operation successful"
        assert response.success is True

    def test_message_response_failure(self):
        """MessageResponse con success=False."""
        response = MessageResponse(message="Operation failed", success=False)
        assert response.success is False

    def test_error_response(self):
        """ErrorResponse schema."""
        response = ErrorResponse(
            error="ValidationError",
            message="Invalid input",
            details={"field": "email", "issue": "invalid format"}
        )
        assert response.error == "ValidationError"
        assert response.details["field"] == "email"

    def test_error_response_no_details(self):
        """ErrorResponse senza details."""
        response = ErrorResponse(
            error="NotFound",
            message="Resource not found"
        )
        assert response.details is None

"""
🔍 Video Metadata Validation
Validazione automatica metadata video prima della moderazione
"""

from typing import Dict, List
from models.video import Video, VideoCategory, Difficulty


class VideoMetadataValidator:
    """
    Validatore metadata video.

    Controlla completezza e correttezza dei metadata prima dell'approvazione.
    Genera score 0-100 basato su issues/warnings.
    """

    def __init__(self):
        self.valid_categories = [c.value for c in VideoCategory]
        self.valid_difficulties = [d.value for d in Difficulty]
        self.valid_tiers = ["FREE", "PREMIUM", "HYBRID_LIGHT", "HYBRID_STANDARD", "BUSINESS"]

    def validate(self, video: Video) -> Dict:
        """
        Valida metadata video.

        Args:
            video: Video object

        Returns:
            Dict con chiavi:
            - valid (bool): True se nessun issue bloccante
            - score (int): 0-100
            - issues (list): Errori bloccanti
            - warnings (list): Suggerimenti non bloccanti
        """
        issues = []
        warnings = []

        # 1. TITLE
        issues.extend(self._validate_title(video.title))
        warnings.extend(self._warn_title(video.title))

        # 2. DESCRIPTION
        issues.extend(self._validate_description(video.description))
        warnings.extend(self._warn_description(video.description))

        # 3. TAGS
        warnings.extend(self._warn_tags(video.tags))

        # 4. CATEGORY
        issues.extend(self._validate_category(video.category))

        # 5. DIFFICULTY
        issues.extend(self._validate_difficulty(video.difficulty))

        # 6. THUMBNAIL
        issues.extend(self._validate_thumbnail(video.thumbnail_url))

        # 7. DURATION
        warnings.extend(self._warn_duration(video.duration))

        # 8. TIER
        issues.extend(self._validate_tier(video.tier_required))

        # Calculate score
        score = self._calculate_score(issues, warnings)

        return {
            "valid": len(issues) == 0,
            "score": score,
            "issues": issues,
            "warnings": warnings
        }

    # === VALIDATION METHODS ===

    def _validate_title(self, title: str) -> List[str]:
        """Validate title (blocking issues)."""
        issues = []

        if not title:
            issues.append("❌ Title mancante")
            return issues

        if len(title) < 10:
            issues.append("❌ Title troppo corto (minimo 10 caratteri)")

        if len(title) > 255:
            issues.append("❌ Title troppo lungo (massimo 255 caratteri)")

        return issues

    def _warn_title(self, title: str) -> List[str]:
        """Warn about title (suggestions)."""
        warnings = []

        if not title:
            return warnings

        if len(title) > 100:
            warnings.append("⚠️ Title molto lungo (considera di accorciare)")

        if not title[0].isupper():
            warnings.append("⚠️ Title dovrebbe iniziare con maiuscola")

        # Check for excessive caps
        if sum(1 for c in title if c.isupper()) > len(title) * 0.5:
            warnings.append("⚠️ Troppe maiuscole nel title")

        return warnings

    def _validate_description(self, description: str) -> List[str]:
        """Validate description."""
        issues = []

        if not description or len(description.strip()) < 50:
            issues.append("❌ Descrizione mancante o troppo corta (minimo 50 caratteri)")

        if description and len(description) > 5000:
            issues.append("❌ Descrizione troppo lunga (massimo 5000 caratteri)")

        return issues

    def _warn_description(self, description: str) -> List[str]:
        """Warn about description."""
        warnings = []

        if description and len(description) > 2000:
            warnings.append("⚠️ Descrizione molto lunga (considera di riassumere)")

        return warnings

    def _warn_tags(self, tags: List[str]) -> List[str]:
        """Warn about tags."""
        warnings = []

        if not tags or len(tags) == 0:
            warnings.append("⚠️ Nessun tag specificato (raccomandati 3-5 tag)")
        elif len(tags) < 3:
            warnings.append("⚠️ Pochi tag (raccomandati almeno 3)")
        elif len(tags) > 10:
            warnings.append("⚠️ Troppi tag (massimo 10 raccomandati)")

        # Check for duplicate tags
        if tags and len(tags) != len(set(tags)):
            warnings.append("⚠️ Tag duplicati presenti")

        return warnings

    def _validate_category(self, category) -> List[str]:
        """Validate category."""
        issues = []

        if not category:
            issues.append("❌ Categoria mancante")
            return issues

        category_value = category.value if hasattr(category, 'value') else str(category)

        if category_value not in self.valid_categories:
            issues.append(f"❌ Categoria non valida: {category_value}")

        if category_value == "other":
            issues.append("❌ Categoria OTHER non permessa (scegli categoria specifica)")

        return issues

    def _validate_difficulty(self, difficulty) -> List[str]:
        """Validate difficulty."""
        issues = []

        if not difficulty:
            issues.append("❌ Difficoltà mancante")
            return issues

        difficulty_value = difficulty.value if hasattr(difficulty, 'value') else str(difficulty)

        if difficulty_value not in self.valid_difficulties:
            issues.append(f"❌ Difficoltà non valida: {difficulty_value}")

        return issues

    def _validate_thumbnail(self, thumbnail_url: str) -> List[str]:
        """Validate thumbnail."""
        issues = []

        if not thumbnail_url:
            issues.append("❌ Thumbnail mancante")

        return issues

    def _warn_duration(self, duration: int) -> List[str]:
        """Warn about duration."""
        warnings = []

        if duration is None:
            return warnings

        if duration < 60:
            warnings.append("⚠️ Video molto corto (< 1 minuto)")
        elif duration > 7200:  # 2 hours
            warnings.append("⚠️ Video molto lungo (> 2 ore)")

        return warnings

    def _validate_tier(self, tier_required: str) -> List[str]:
        """Validate tier."""
        issues = []

        if not tier_required:
            issues.append("❌ Tier richiesto mancante")
            return issues

        tier_upper = tier_required.upper()

        if tier_upper not in self.valid_tiers:
            issues.append(f"❌ Tier non valido: {tier_required}")

        return issues

    def _calculate_score(self, issues: List[str], warnings: List[str]) -> int:
        """
        Calculate validation score 0-100.

        Formula:
        - Start with 100
        - -20 per issue (blocking)
        - -5 per warning (suggestion)
        - Min 0, Max 100
        """
        score = 100
        score -= len(issues) * 20
        score -= len(warnings) * 5
        return max(0, min(100, score))


# === HELPER FUNCTIONS ===

def validate_video_metadata(video: Video) -> Dict:
    """
    Convenience function per validare video.

    Args:
        video: Video object

    Returns:
        Validation result dict
    """
    validator = VideoMetadataValidator()
    return validator.validate(video)

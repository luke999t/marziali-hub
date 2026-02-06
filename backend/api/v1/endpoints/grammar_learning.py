"""
================================================================================
AI_MODULE: Grammar Learning API Endpoints
AI_VERSION: 1.0.0
AI_DESCRIPTION: API per estrazione e gestione regole grammaticali
AI_BUSINESS: Endpoint REST per grammar extraction e querying
AI_TEACHING: FastAPI, file upload, async processing, Pydantic schemas
AI_DEPENDENCIES: fastapi, pydantic
AI_CREATED: 2026-02-05

ENDPOINTS:
- POST /api/v1/grammar/extract - Upload e processa libro
- GET /api/v1/grammar/{language} - Ottieni grammatica
- GET /api/v1/grammar/{language}/stats - Statistiche
- GET /api/v1/grammar/{language}/search - Cerca regole
- POST /api/v1/grammar/{language}/merge - Merge manuale regole
- GET /api/v1/grammar/{language}/export/anki - Export Anki

PRIVACY:
- NO source information in responses
- Only anonymous rules returned
================================================================================
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from enum import Enum

logger = logging.getLogger(__name__)

router = APIRouter()


# === PYDANTIC SCHEMAS ===

class FileTypeEnum(str, Enum):
    """Supported file types for extraction."""
    PDF = "pdf"
    EPUB = "epub"
    IMAGE = "image"
    PDF_SCAN = "pdf_scan"


class LanguageEnum(str, Enum):
    """Supported languages."""
    JAPANESE = "ja"
    CHINESE = "zh"
    KOREAN = "ko"


class RuleCategoryEnum(str, Enum):
    """Grammar rule categories."""
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
    NEGATION = "negation"
    QUESTION = "question"
    OTHER = "other"


class DifficultyEnum(str, Enum):
    """Difficulty levels."""
    BASIC = "basic"
    ELEMENTARY = "elementary"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ExampleSchema(BaseModel):
    """Example sentence schema."""
    original: str
    translation: str
    note: str = ""
    reading: str = ""


class RuleSchema(BaseModel):
    """Grammar rule schema."""
    id: str
    category: str
    name: str
    description: str
    pattern: str
    examples: List[ExampleSchema] = []
    exceptions: List[str] = []
    difficulty: str
    related_rules: List[str] = []
    tags: List[str] = []
    created_at: str = ""


class ExtractionResponse(BaseModel):
    """Response for extraction endpoint."""
    success: bool
    language: str
    rules_extracted: int
    rules_merged: int
    total_rules_in_db: int
    processing_time_seconds: float
    error: Optional[str] = None
    rules: List[RuleSchema] = []


class GrammarResponse(BaseModel):
    """Response for grammar database endpoint."""
    language: str
    last_updated: str
    sources_count: int  # ONLY count, never which sources!
    total_rules: int
    rules: List[RuleSchema]


class StatsResponse(BaseModel):
    """Response for statistics endpoint."""
    language: str
    last_updated: str
    sources_count: int
    total_rules: int
    total_examples: int
    category_distribution: dict
    difficulty_distribution: dict
    avg_examples_per_rule: float


class ManualRuleRequest(BaseModel):
    """Request for manually adding a rule."""
    name: str = Field(..., min_length=1, max_length=200)
    category: RuleCategoryEnum
    description: str = Field(..., min_length=10, max_length=2000)
    pattern: str = Field(..., min_length=1, max_length=200)
    examples: List[ExampleSchema] = Field(default_factory=list, max_items=10)
    exceptions: List[str] = Field(default_factory=list, max_items=20)
    difficulty: DifficultyEnum
    related_rules: List[str] = Field(default_factory=list, max_items=10)
    tags: List[str] = Field(default_factory=list, max_items=10)


class SearchResponse(BaseModel):
    """Response for search endpoint."""
    query: str
    language: str
    total_results: int
    rules: List[RuleSchema]


# === HELPER FUNCTIONS ===

def get_extractor():
    """Get or create GrammarExtractor instance."""
    from services.language_learning import GrammarExtractor
    return GrammarExtractor()


def rule_to_schema(rule) -> RuleSchema:
    """Convert NormalizedRule to RuleSchema."""
    return RuleSchema(
        id=rule.id,
        category=rule.category.value,
        name=rule.name,
        description=rule.description,
        pattern=rule.pattern,
        examples=[
            ExampleSchema(
                original=ex.original,
                translation=ex.translation,
                note=ex.note,
                reading=ex.reading
            )
            for ex in rule.examples
        ],
        exceptions=rule.exceptions,
        difficulty=rule.difficulty.value,
        related_rules=rule.related_rules,
        tags=rule.tags,
        created_at=rule.created_at
    )


# === ENDPOINTS ===

@router.post(
    "/extract",
    response_model=ExtractionResponse,
    summary="Extract grammar from file",
    description="""
    Upload a PDF, EPUB, or image file to extract grammar rules.

    The extraction process:
    1. Extracts text from the file
    2. Analyzes with LLM to find grammar patterns
    3. Reformulates descriptions (no direct quotes)
    4. Generates new examples
    5. Merges with existing rules
    6. DELETES original content

    **PRIVACY**: No source information is stored. Only anonymous rules.
    """
)
async def extract_grammar(
    file: UploadFile = File(..., description="PDF, EPUB, or image file"),
    language: LanguageEnum = Query(
        default=LanguageEnum.JAPANESE,
        description="Target language"
    ),
    file_type: Optional[FileTypeEnum] = Query(
        default=None,
        description="File type (auto-detected if not specified)"
    )
) -> ExtractionResponse:
    """Extract grammar rules from an uploaded file."""
    from services.language_learning import GrammarExtractor
    from services.language_learning.grammar_extractor import FileType

    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Read file content
    try:
        content = await file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    if len(content) > 100 * 1024 * 1024:  # 100MB limit
        raise HTTPException(status_code=400, detail="File too large (max 100MB)")

    # Detect file type
    suffix = file.filename.lower().split(".")[-1] if "." in file.filename else ""

    if file_type is None:
        if suffix == "pdf":
            detected_type = FileType.PDF
        elif suffix == "epub":
            detected_type = FileType.EPUB
        elif suffix in ["png", "jpg", "jpeg", "tiff", "bmp", "gif", "webp"]:
            detected_type = FileType.IMAGE
        else:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type: {suffix}"
            )
    else:
        detected_type = FileType(file_type.value)

    # Process
    extractor = GrammarExtractor()

    try:
        result = await extractor.extract_from_bytes(
            file_bytes=content,
            file_type=detected_type,
            language=language.value
        )
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        raise HTTPException(status_code=500, detail=f"Extraction failed: {e}")
    finally:
        # CRITICAL: Ensure content is deleted
        del content

    if not result.success:
        raise HTTPException(status_code=400, detail=result.error or "Extraction failed")

    return ExtractionResponse(
        success=result.success,
        language=result.language,
        rules_extracted=result.rules_extracted,
        rules_merged=result.rules_merged,
        total_rules_in_db=result.total_rules_in_db,
        processing_time_seconds=result.processing_time_seconds,
        error=result.error,
        rules=[rule_to_schema(r) for r in result.rules]
    )


@router.get(
    "/{language}",
    response_model=GrammarResponse,
    summary="Get grammar database",
    description="Get the complete grammar database for a language."
)
async def get_grammar(
    language: LanguageEnum
) -> GrammarResponse:
    """Get grammar database for a language."""
    extractor = get_extractor()

    grammar = await extractor.get_grammar(language.value)

    if grammar is None:
        raise HTTPException(
            status_code=404,
            detail=f"No grammar database found for {language.value}"
        )

    return GrammarResponse(
        language=grammar.language,
        last_updated=grammar.last_updated,
        sources_count=grammar.sources_count,
        total_rules=grammar.total_rules,
        rules=[rule_to_schema(r) for r in grammar.rules]
    )


@router.get(
    "/{language}/stats",
    response_model=StatsResponse,
    summary="Get grammar statistics",
    description="Get statistics about a grammar database."
)
async def get_statistics(
    language: LanguageEnum
) -> StatsResponse:
    """Get statistics for a grammar database."""
    extractor = get_extractor()

    stats = await extractor.get_statistics(language.value)

    if "error" in stats:
        raise HTTPException(
            status_code=404,
            detail=stats["error"]
        )

    return StatsResponse(**stats)


@router.get(
    "/{language}/search",
    response_model=SearchResponse,
    summary="Search grammar rules",
    description="Search for grammar rules by name, description, or pattern."
)
async def search_rules(
    language: LanguageEnum,
    q: str = Query(..., min_length=1, max_length=100, description="Search query")
) -> SearchResponse:
    """Search for grammar rules."""
    extractor = get_extractor()

    rules = await extractor.search_rules(language.value, q)

    return SearchResponse(
        query=q,
        language=language.value,
        total_results=len(rules),
        rules=[rule_to_schema(r) for r in rules]
    )


@router.post(
    "/{language}/merge",
    response_model=GrammarResponse,
    summary="Manually add rules",
    description="Manually add grammar rules to the database."
)
async def merge_rules(
    language: LanguageEnum,
    rules: List[ManualRuleRequest]
) -> GrammarResponse:
    """Manually add rules to the grammar database."""
    from services.language_learning.rule_normalizer import (
        NormalizedRule, RuleCategory, DifficultyLevel, RuleExample
    )
    from services.language_learning import GrammarMergerService
    import uuid

    merger = GrammarMergerService()

    # Convert to NormalizedRule objects
    normalized_rules = []
    for req in rules:
        rule = NormalizedRule(
            id=f"manual_{uuid.uuid4().hex[:12]}",
            category=RuleCategory(req.category.value),
            name=req.name,
            description=req.description,
            pattern=req.pattern,
            examples=[
                RuleExample(
                    original=ex.original,
                    translation=ex.translation,
                    note=ex.note,
                    reading=ex.reading
                )
                for ex in req.examples
            ],
            exceptions=req.exceptions,
            difficulty=DifficultyLevel(req.difficulty.value),
            related_rules=req.related_rules,
            tags=req.tags
        )
        normalized_rules.append(rule)

    # Merge
    grammar = await merger.merge_rules(language.value, normalized_rules)

    return GrammarResponse(
        language=grammar.language,
        last_updated=grammar.last_updated,
        sources_count=grammar.sources_count,
        total_rules=grammar.total_rules,
        rules=[rule_to_schema(r) for r in grammar.rules]
    )


@router.get(
    "/{language}/export/anki",
    summary="Export to Anki format",
    description="Export grammar rules to Anki-compatible format."
)
async def export_anki(
    language: LanguageEnum
):
    """Export grammar to Anki format."""
    extractor = get_extractor()

    try:
        output_path = await extractor.export_to_anki(language.value)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Export failed: {e}")

    return FileResponse(
        path=str(output_path),
        filename=f"anki_{language.value}.txt",
        media_type="text/plain"
    )


@router.get(
    "/{language}/rules/{category}",
    response_model=SearchResponse,
    summary="Get rules by category",
    description="Get all grammar rules of a specific category."
)
async def get_rules_by_category(
    language: LanguageEnum,
    category: RuleCategoryEnum
) -> SearchResponse:
    """Get rules by category."""
    from services.language_learning.rule_normalizer import RuleCategory
    from services.language_learning import GrammarMergerService

    merger = GrammarMergerService()

    rules = await merger.get_rules_by_category(
        language.value,
        RuleCategory(category.value)
    )

    return SearchResponse(
        query=f"category:{category.value}",
        language=language.value,
        total_results=len(rules),
        rules=[rule_to_schema(r) for r in rules]
    )


@router.get(
    "/{language}/rules/difficulty/{difficulty}",
    response_model=SearchResponse,
    summary="Get rules by difficulty",
    description="Get all grammar rules of a specific difficulty level."
)
async def get_rules_by_difficulty(
    language: LanguageEnum,
    difficulty: DifficultyEnum
) -> SearchResponse:
    """Get rules by difficulty."""
    from services.language_learning.rule_normalizer import DifficultyLevel
    from services.language_learning import GrammarMergerService

    merger = GrammarMergerService()

    rules = await merger.get_rules_by_difficulty(
        language.value,
        DifficultyLevel(difficulty.value)
    )

    return SearchResponse(
        query=f"difficulty:{difficulty.value}",
        language=language.value,
        total_results=len(rules),
        rules=[rule_to_schema(r) for r in rules]
    )

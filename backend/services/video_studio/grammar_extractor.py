"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Grammar Extractor Service
================================================================================

    AI_FIRST: Grammar Rule Extraction from Documents
    AI_DESCRIPTION: Extracts grammar rules from PDF, EPUB, and Images using
                   OCR and document parsing, with anonymization support

    Dependencies:
    - PyMuPDF (fitz) for PDF processing
    - ebooklib for EPUB processing
    - Pillow for image processing
    - pytesseract for OCR (optional)

================================================================================
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from abc import ABC, abstractmethod
import json

logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMS AND DATA CLASSES
# ==============================================================================

class DocumentType(Enum):
    """Supported document types"""
    PDF = "pdf"
    EPUB = "epub"
    IMAGE = "image"
    TEXT = "text"


class GrammarCategory(Enum):
    """Categories of grammar rules"""
    PARTICLES = "particles"           # Japanese/Korean particles
    VERB_CONJUGATION = "verb_conjugation"
    NOUN_DECLENSION = "noun_declension"
    SENTENCE_STRUCTURE = "sentence_structure"
    HONORIFICS = "honorifics"
    COUNTERS = "counters"
    TENSE = "tense"
    ASPECT = "aspect"
    MODALITY = "modality"
    CONJUNCTIONS = "conjunctions"
    EXPRESSIONS = "expressions"
    IDIOMS = "idioms"
    PROVERBS = "proverbs"
    COMPOUND_WORDS = "compound_words"
    PHONETICS = "phonetics"
    OTHER = "other"


class ExtractionQuality(Enum):
    """Quality levels of extraction"""
    HIGH = "high"         # Clean text, well-formatted
    MEDIUM = "medium"     # Some noise, mostly readable
    LOW = "low"           # Significant noise, may need review
    OCR = "ocr"           # OCR extracted, verify manually


@dataclass
class GrammarRule:
    """Single grammar rule extracted from document"""
    rule_id: str
    pattern: str                       # The grammar pattern
    explanation: str                   # Explanation of the rule
    examples: List[str]                # Example sentences
    category: GrammarCategory
    language: str                      # Source language
    level: str                         # JLPT/HSK/TOPIK level if applicable
    source_page: Optional[int] = None
    source_location: Optional[str] = None
    related_rules: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    confidence: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "rule_id": self.rule_id,
            "pattern": self.pattern,
            "explanation": self.explanation,
            "examples": self.examples,
            "category": self.category.value,
            "language": self.language,
            "level": self.level,
            "source_page": self.source_page,
            "related_rules": self.related_rules,
            "tags": self.tags,
            "notes": self.notes,
            "confidence": self.confidence
        }


@dataclass
class ExtractedContent:
    """Content extracted from a document"""
    text: str
    source_type: DocumentType
    source_path: str
    page_count: int
    extraction_quality: ExtractionQuality
    metadata: Dict[str, Any] = field(default_factory=dict)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    images_found: int = 0
    tables_found: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class NormalizedRuleSet:
    """Set of normalized grammar rules"""
    rules: List[GrammarRule]
    language: str
    source_documents: List[str]
    total_rules: int
    categories_covered: Set[GrammarCategory]
    anonymized: bool
    extraction_date: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "rules": [r.to_dict() for r in self.rules],
            "language": self.language,
            "source_documents": self.source_documents if not self.anonymized else ["[ANONYMIZED]"] * len(self.source_documents),
            "total_rules": self.total_rules,
            "categories_covered": [c.value for c in self.categories_covered],
            "anonymized": self.anonymized,
            "extraction_date": self.extraction_date.isoformat()
        }


@dataclass
class ExtractionConfig:
    """Configuration for grammar extraction"""
    extract_examples: bool = True
    max_examples_per_rule: int = 5
    detect_level: bool = True          # Auto-detect JLPT/HSK/TOPIK level
    include_context: bool = True
    ocr_fallback: bool = True          # Use OCR if text extraction fails
    min_confidence: float = 0.6
    supported_languages: List[str] = field(
        default_factory=lambda: ["ja", "zh", "ko", "en", "it"]
    )


# ==============================================================================
# ABSTRACT EXTRACTOR BASE
# ==============================================================================

class DocumentExtractor(ABC):
    """Abstract base class for document extractors"""

    @abstractmethod
    async def extract(self, file_path: Union[str, Path]) -> ExtractedContent:
        """Extract content from document"""
        pass

    @abstractmethod
    def supports(self, file_path: Union[str, Path]) -> bool:
        """Check if this extractor supports the file type"""
        pass


# ==============================================================================
# PDF EXTRACTOR
# ==============================================================================

class PDFExtractor(DocumentExtractor):
    """
    PDF document extractor using PyMuPDF.

    Extracts text, tables, and images from PDF documents.
    """

    SUPPORTED_EXTENSIONS = {".pdf"}

    def __init__(self, config: Optional[ExtractionConfig] = None):
        self.config = config or ExtractionConfig()
        self._fitz_available = False
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if PyMuPDF is available"""
        try:
            import fitz
            self._fitz_available = True
        except ImportError:
            logger.warning("PyMuPDF (fitz) not available. PDF extraction will be limited.")
            self._fitz_available = False

    def supports(self, file_path: Union[str, Path]) -> bool:
        """Check if file is a PDF"""
        path = Path(file_path)
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    async def extract(self, file_path: Union[str, Path]) -> ExtractedContent:
        """
        Extract content from PDF document.

        Args:
            file_path: Path to PDF file

        Returns:
            ExtractedContent with text and metadata
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"PDF file not found: {path}")

        if not self._fitz_available:
            return self._placeholder_extraction(path)

        try:
            import fitz

            doc = fitz.open(str(path))
            text_parts = []
            sections = []
            images_count = 0
            tables_count = 0

            for page_num, page in enumerate(doc):
                # Extract text
                page_text = page.get_text("text")
                text_parts.append(page_text)

                # Track images
                images_count += len(page.get_images())

                # Detect tables (simplified)
                tables = page.find_tables()
                if tables:
                    tables_count += len(tables)

                # Create section
                sections.append({
                    "page": page_num + 1,
                    "text": page_text,
                    "images": len(page.get_images()),
                    "tables": len(tables) if tables else 0
                })

            doc.close()

            full_text = "\n\n".join(text_parts)

            # Determine quality
            quality = ExtractionQuality.HIGH
            if len(full_text.strip()) < 100:
                quality = ExtractionQuality.LOW
            elif images_count > len(doc) * 2:  # Mostly images
                quality = ExtractionQuality.OCR

            return ExtractedContent(
                text=full_text,
                source_type=DocumentType.PDF,
                source_path=str(path),
                page_count=len(doc),
                extraction_quality=quality,
                metadata={
                    "title": doc.metadata.get("title", ""),
                    "author": doc.metadata.get("author", ""),
                    "subject": doc.metadata.get("subject", "")
                },
                sections=sections,
                images_found=images_count,
                tables_found=tables_count
            )

        except Exception as e:
            logger.error(f"PDF extraction error: {e}")
            return self._placeholder_extraction(path)

    def _placeholder_extraction(self, path: Path) -> ExtractedContent:
        """Placeholder when PyMuPDF is not available"""
        return ExtractedContent(
            text=f"[PLACEHOLDER] PDF content from: {path.name}",
            source_type=DocumentType.PDF,
            source_path=str(path),
            page_count=0,
            extraction_quality=ExtractionQuality.LOW,
            metadata={"note": "PyMuPDF not available"}
        )


# ==============================================================================
# EPUB EXTRACTOR
# ==============================================================================

class EPUBExtractor(DocumentExtractor):
    """
    EPUB document extractor using ebooklib.

    Extracts text content from EPUB ebooks.
    """

    SUPPORTED_EXTENSIONS = {".epub"}

    def __init__(self, config: Optional[ExtractionConfig] = None):
        self.config = config or ExtractionConfig()
        self._ebooklib_available = False
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if ebooklib is available"""
        try:
            import ebooklib
            from ebooklib import epub
            self._ebooklib_available = True
        except ImportError:
            logger.warning("ebooklib not available. EPUB extraction will be limited.")
            self._ebooklib_available = False

    def supports(self, file_path: Union[str, Path]) -> bool:
        """Check if file is an EPUB"""
        path = Path(file_path)
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    async def extract(self, file_path: Union[str, Path]) -> ExtractedContent:
        """
        Extract content from EPUB document.

        Args:
            file_path: Path to EPUB file

        Returns:
            ExtractedContent with text and metadata
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"EPUB file not found: {path}")

        if not self._ebooklib_available:
            return self._placeholder_extraction(path)

        try:
            from ebooklib import epub
            from bs4 import BeautifulSoup

            book = epub.read_epub(str(path))
            text_parts = []
            sections = []
            chapter_count = 0

            for item in book.get_items():
                if item.get_type() == epub.ITEM_DOCUMENT:
                    # Parse HTML content
                    soup = BeautifulSoup(item.get_content(), 'html.parser')
                    chapter_text = soup.get_text(separator='\n')
                    text_parts.append(chapter_text)

                    sections.append({
                        "chapter": chapter_count + 1,
                        "title": item.get_name(),
                        "text_length": len(chapter_text)
                    })
                    chapter_count += 1

            full_text = "\n\n".join(text_parts)

            # Get metadata
            title = book.get_metadata('DC', 'title')
            author = book.get_metadata('DC', 'creator')
            language = book.get_metadata('DC', 'language')

            return ExtractedContent(
                text=full_text,
                source_type=DocumentType.EPUB,
                source_path=str(path),
                page_count=chapter_count,
                extraction_quality=ExtractionQuality.HIGH,
                metadata={
                    "title": title[0][0] if title else "",
                    "author": author[0][0] if author else "",
                    "language": language[0][0] if language else ""
                },
                sections=sections
            )

        except Exception as e:
            logger.error(f"EPUB extraction error: {e}")
            return self._placeholder_extraction(path)

    def _placeholder_extraction(self, path: Path) -> ExtractedContent:
        """Placeholder when ebooklib is not available"""
        return ExtractedContent(
            text=f"[PLACEHOLDER] EPUB content from: {path.name}",
            source_type=DocumentType.EPUB,
            source_path=str(path),
            page_count=0,
            extraction_quality=ExtractionQuality.LOW,
            metadata={"note": "ebooklib not available"}
        )


# ==============================================================================
# IMAGE EXTRACTOR (OCR)
# ==============================================================================

class ImageExtractor(DocumentExtractor):
    """
    Image extractor using OCR.

    Extracts text from images using Tesseract OCR (via pytesseract).
    """

    SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif", ".webp"}

    def __init__(self, config: Optional[ExtractionConfig] = None):
        self.config = config or ExtractionConfig()
        self._tesseract_available = False
        self._pillow_available = False
        self._check_dependencies()

    def _check_dependencies(self):
        """Check if OCR dependencies are available"""
        try:
            from PIL import Image
            self._pillow_available = True
        except ImportError:
            logger.warning("Pillow not available. Image processing will be limited.")

        try:
            import pytesseract
            self._tesseract_available = True
        except ImportError:
            logger.warning("pytesseract not available. OCR will not work.")

    def supports(self, file_path: Union[str, Path]) -> bool:
        """Check if file is a supported image"""
        path = Path(file_path)
        return path.suffix.lower() in self.SUPPORTED_EXTENSIONS

    async def extract(self, file_path: Union[str, Path]) -> ExtractedContent:
        """
        Extract text from image using OCR.

        Args:
            file_path: Path to image file

        Returns:
            ExtractedContent with OCR text
        """
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Image file not found: {path}")

        if not self._pillow_available:
            return self._placeholder_extraction(path)

        try:
            from PIL import Image

            img = Image.open(str(path))

            # Get image metadata
            width, height = img.size
            mode = img.mode

            # Extract text using OCR if available
            if self._tesseract_available:
                import pytesseract

                # For Japanese/Chinese/Korean, specify languages
                lang_config = "jpn+chi_sim+chi_tra+kor+eng"

                try:
                    text = pytesseract.image_to_string(
                        img,
                        lang=lang_config,
                        config='--psm 6'  # Assume uniform block of text
                    )
                except Exception as ocr_error:
                    logger.warning(f"OCR failed with multi-lang, trying English: {ocr_error}")
                    text = pytesseract.image_to_string(img)
            else:
                text = f"[PLACEHOLDER] OCR not available for: {path.name}"

            img.close()

            return ExtractedContent(
                text=text,
                source_type=DocumentType.IMAGE,
                source_path=str(path),
                page_count=1,
                extraction_quality=ExtractionQuality.OCR,
                metadata={
                    "width": width,
                    "height": height,
                    "mode": mode,
                    "format": img.format if hasattr(img, 'format') else path.suffix
                },
                images_found=1
            )

        except Exception as e:
            logger.error(f"Image extraction error: {e}")
            return self._placeholder_extraction(path)

    def _placeholder_extraction(self, path: Path) -> ExtractedContent:
        """Placeholder when OCR is not available"""
        return ExtractedContent(
            text=f"[PLACEHOLDER] Image OCR from: {path.name}",
            source_type=DocumentType.IMAGE,
            source_path=str(path),
            page_count=1,
            extraction_quality=ExtractionQuality.LOW,
            metadata={"note": "OCR dependencies not available"}
        )


# ==============================================================================
# GRAMMAR EXTRACTOR MAIN CLASS
# ==============================================================================

class GrammarExtractor:
    """
    Main grammar extraction service.

    Extracts grammar rules from various document formats (PDF, EPUB, Image)
    and normalizes them into a structured format with optional anonymization.
    """

    def __init__(self, config: Optional[ExtractionConfig] = None):
        self.config = config or ExtractionConfig()

        # Initialize extractors
        self._pdf_extractor = PDFExtractor(config)
        self._epub_extractor = EPUBExtractor(config)
        self._image_extractor = ImageExtractor(config)

        # Pattern matchers for different languages
        self._grammar_patterns = self._load_grammar_patterns()

    def _load_grammar_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load regex patterns for grammar rule detection"""
        return {
            "ja": [
                # Japanese grammar patterns
                re.compile(r'([ぁ-ん]+)\s*[：:]\s*(.+)', re.MULTILINE),  # Hiragana pattern
                re.compile(r'〜([ぁ-んァ-ン]+)\s*[\(（](.+?)[\)）]', re.MULTILINE),  # ~form (explanation)
                re.compile(r'文型\s*[：:]\s*(.+)', re.MULTILINE),  # Sentence pattern
                re.compile(r'例文\s*[：:]\s*(.+)', re.MULTILINE),  # Example sentence
            ],
            "zh": [
                # Chinese grammar patterns
                re.compile(r'语法[：:]\s*(.+)', re.MULTILINE),  # Grammar
                re.compile(r'句型[：:]\s*(.+)', re.MULTILINE),  # Sentence pattern
                re.compile(r'例句[：:]\s*(.+)', re.MULTILINE),  # Example
            ],
            "ko": [
                # Korean grammar patterns
                re.compile(r'문법[：:]\s*(.+)', re.MULTILINE),  # Grammar
                re.compile(r'[-(으)ㄴ/는]\s*(.+)', re.MULTILINE),  # Verb endings
                re.compile(r'예문[：:]\s*(.+)', re.MULTILINE),  # Example
            ],
            "general": [
                # General patterns
                re.compile(r'(?:Rule|Grammar|Pattern)\s*[：:]\s*(.+)', re.IGNORECASE | re.MULTILINE),
                re.compile(r'(?:Example|例)\s*[：:]\s*(.+)', re.IGNORECASE | re.MULTILINE),
            ]
        }

    async def extract_from_pdf(
        self,
        file_path: Union[str, Path],
        language: str = "ja"
    ) -> ExtractedContent:
        """
        Extract content from PDF file.

        Args:
            file_path: Path to PDF file
            language: Primary language of the document

        Returns:
            ExtractedContent object
        """
        logger.info(f"Extracting from PDF: {file_path}")
        return await self._pdf_extractor.extract(file_path)

    async def extract_from_epub(
        self,
        file_path: Union[str, Path],
        language: str = "ja"
    ) -> ExtractedContent:
        """
        Extract content from EPUB file.

        Args:
            file_path: Path to EPUB file
            language: Primary language of the document

        Returns:
            ExtractedContent object
        """
        logger.info(f"Extracting from EPUB: {file_path}")
        return await self._epub_extractor.extract(file_path)

    async def extract_from_image(
        self,
        file_path: Union[str, Path],
        language: str = "ja"
    ) -> ExtractedContent:
        """
        Extract text from image using OCR.

        Args:
            file_path: Path to image file
            language: Expected language for OCR

        Returns:
            ExtractedContent object
        """
        logger.info(f"Extracting from image: {file_path}")
        return await self._image_extractor.extract(file_path)

    async def extract_grammar_rules(
        self,
        content: ExtractedContent,
        language: str = "ja"
    ) -> List[GrammarRule]:
        """
        Extract grammar rules from extracted content.

        Args:
            content: Previously extracted document content
            language: Language to search for patterns

        Returns:
            List of GrammarRule objects
        """
        rules = []
        patterns = self._grammar_patterns.get(language, []) + self._grammar_patterns.get("general", [])

        # Split into sections/paragraphs
        paragraphs = content.text.split("\n\n")

        for i, para in enumerate(paragraphs):
            for pattern in patterns:
                matches = pattern.findall(para)
                for match in matches:
                    rule_id = self._generate_rule_id(match if isinstance(match, str) else match[0])

                    rule = GrammarRule(
                        rule_id=rule_id,
                        pattern=match[0] if isinstance(match, tuple) else match,
                        explanation=match[1] if isinstance(match, tuple) and len(match) > 1 else "",
                        examples=[],
                        category=self._categorize_rule(match),
                        language=language,
                        level=self._detect_level(para, language),
                        source_page=self._get_page_number(content, i),
                        confidence=content.extraction_quality.value == "high" and 0.9 or 0.7
                    )

                    # Find examples nearby
                    if self.config.extract_examples:
                        rule.examples = self._find_examples(
                            paragraphs, i, language
                        )[:self.config.max_examples_per_rule]

                    rules.append(rule)

        logger.info(f"Extracted {len(rules)} grammar rules")
        return rules

    def normalize_rules(
        self,
        rules: List[GrammarRule],
        anonymize: bool = True
    ) -> NormalizedRuleSet:
        """
        Normalize and optionally anonymize grammar rules.

        Args:
            rules: List of extracted grammar rules
            anonymize: If True, remove source file information

        Returns:
            NormalizedRuleSet with processed rules
        """
        normalized_rules = []
        sources = set()
        categories = set()

        for rule in rules:
            # Normalize the rule
            normalized = GrammarRule(
                rule_id=rule.rule_id if not anonymize else self._anonymize_id(rule.rule_id),
                pattern=self._normalize_pattern(rule.pattern),
                explanation=self._normalize_text(rule.explanation),
                examples=[self._normalize_text(ex) for ex in rule.examples],
                category=rule.category,
                language=rule.language,
                level=rule.level,
                source_page=None if anonymize else rule.source_page,
                source_location=None if anonymize else rule.source_location,
                related_rules=rule.related_rules,
                tags=rule.tags,
                notes="" if anonymize else rule.notes,
                confidence=rule.confidence
            )

            normalized_rules.append(normalized)
            categories.add(rule.category)

            if rule.source_location:
                sources.add(rule.source_location)

        # Deduplicate rules
        unique_rules = self._deduplicate_rules(normalized_rules)

        return NormalizedRuleSet(
            rules=unique_rules,
            language=rules[0].language if rules else "unknown",
            source_documents=list(sources),
            total_rules=len(unique_rules),
            categories_covered=categories,
            anonymized=anonymize,
            extraction_date=datetime.now(),
            metadata={
                "original_count": len(rules),
                "deduplicated_count": len(unique_rules),
                "anonymization_applied": anonymize
            }
        )

    def _generate_rule_id(self, pattern: str) -> str:
        """Generate unique rule ID from pattern"""
        hash_input = pattern.encode('utf-8')
        return f"rule_{hashlib.md5(hash_input).hexdigest()[:8]}"

    def _anonymize_id(self, rule_id: str) -> str:
        """Anonymize a rule ID"""
        return f"anon_{hashlib.sha256(rule_id.encode()).hexdigest()[:12]}"

    def _categorize_rule(self, match: Union[str, Tuple]) -> GrammarCategory:
        """Categorize a grammar rule based on its pattern"""
        pattern = match[0] if isinstance(match, tuple) else match
        pattern_lower = pattern.lower()

        # Japanese particles
        if re.search(r'[はがをにでへとから]', pattern):
            return GrammarCategory.PARTICLES

        # Verb-related
        if re.search(r'(verb|動詞|ます|です|た形|て形)', pattern_lower):
            return GrammarCategory.VERB_CONJUGATION

        # Honorifics
        if re.search(r'(敬語|honorific|お|ご)', pattern_lower):
            return GrammarCategory.HONORIFICS

        # Counters
        if re.search(r'(counter|助数詞|個|本|枚)', pattern_lower):
            return GrammarCategory.COUNTERS

        # Expressions
        if re.search(r'(expression|表現|phrase)', pattern_lower):
            return GrammarCategory.EXPRESSIONS

        return GrammarCategory.OTHER

    def _detect_level(self, text: str, language: str) -> str:
        """Auto-detect proficiency level"""
        text_lower = text.lower()

        if language == "ja":
            # JLPT levels
            if re.search(r'n1|上級|advanced', text_lower):
                return "N1"
            elif re.search(r'n2|中上級', text_lower):
                return "N2"
            elif re.search(r'n3|中級|intermediate', text_lower):
                return "N3"
            elif re.search(r'n4|初中級', text_lower):
                return "N4"
            elif re.search(r'n5|初級|beginner', text_lower):
                return "N5"

        elif language == "zh":
            # HSK levels
            for level in range(6, 0, -1):
                if re.search(f'hsk\s*{level}', text_lower):
                    return f"HSK{level}"

        elif language == "ko":
            # TOPIK levels
            for level in range(6, 0, -1):
                if re.search(f'topik\s*{level}|급{level}', text_lower):
                    return f"TOPIK{level}"

        return "unknown"

    def _find_examples(
        self,
        paragraphs: List[str],
        current_index: int,
        language: str
    ) -> List[str]:
        """Find example sentences near a grammar pattern"""
        examples = []

        # Look in nearby paragraphs
        start = max(0, current_index - 1)
        end = min(len(paragraphs), current_index + 3)

        example_patterns = [
            re.compile(r'例[：:]\s*(.+)', re.MULTILINE),
            re.compile(r'Example[：:]\s*(.+)', re.IGNORECASE | re.MULTILINE),
            re.compile(r'[「『](.+?)[」』]', re.MULTILINE),  # Japanese quotations
        ]

        for para in paragraphs[start:end]:
            for pattern in example_patterns:
                matches = pattern.findall(para)
                examples.extend(matches)

        return examples[:self.config.max_examples_per_rule]

    def _get_page_number(self, content: ExtractedContent, para_index: int) -> Optional[int]:
        """Estimate page number from paragraph index"""
        if content.sections:
            # Rough estimation
            total_chars = sum(len(s.get('text', '')) for s in content.sections)
            chars_per_page = total_chars / max(content.page_count, 1)

            current_chars = 0
            for i, section in enumerate(content.sections):
                current_chars += len(section.get('text', ''))
                if i >= para_index:
                    return section.get('page', i + 1)

        return None

    def _normalize_pattern(self, pattern: str) -> str:
        """Normalize a grammar pattern"""
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', pattern.strip())

        # Normalize special characters
        normalized = normalized.replace('〜', '~')

        return normalized

    def _normalize_text(self, text: str) -> str:
        """Normalize text content"""
        if not text:
            return ""

        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', text.strip())

        return normalized

    def _deduplicate_rules(self, rules: List[GrammarRule]) -> List[GrammarRule]:
        """Remove duplicate rules based on pattern"""
        seen_patterns = set()
        unique_rules = []

        for rule in rules:
            pattern_key = self._normalize_pattern(rule.pattern).lower()
            if pattern_key not in seen_patterns:
                seen_patterns.add(pattern_key)
                unique_rules.append(rule)

        return unique_rules

    def export_rules(
        self,
        rule_set: NormalizedRuleSet,
        output_path: Union[str, Path],
        format: str = "json"
    ) -> bool:
        """
        Export normalized rules to file.

        Args:
            rule_set: NormalizedRuleSet to export
            output_path: Output file path
            format: Output format (json, csv)

        Returns:
            True if successful
        """
        path = Path(output_path)

        try:
            if format == "json":
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(rule_set.to_dict(), f, ensure_ascii=False, indent=2)

            elif format == "csv":
                import csv
                with open(path, 'w', encoding='utf-8', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=[
                        'rule_id', 'pattern', 'explanation', 'category',
                        'language', 'level', 'confidence'
                    ])
                    writer.writeheader()
                    for rule in rule_set.rules:
                        writer.writerow({
                            'rule_id': rule.rule_id,
                            'pattern': rule.pattern,
                            'explanation': rule.explanation,
                            'category': rule.category.value,
                            'language': rule.language,
                            'level': rule.level,
                            'confidence': rule.confidence
                        })

            logger.info(f"Exported {len(rule_set.rules)} rules to {path}")
            return True

        except Exception as e:
            logger.error(f"Export failed: {e}")
            return False


# ==============================================================================
# FACTORY AND CONVENIENCE FUNCTIONS
# ==============================================================================

def create_grammar_extractor(
    config: Optional[ExtractionConfig] = None
) -> GrammarExtractor:
    """Factory function to create a grammar extractor"""
    return GrammarExtractor(config=config)


async def extract_and_normalize(
    file_path: Union[str, Path],
    language: str = "ja",
    anonymize: bool = True
) -> NormalizedRuleSet:
    """
    Convenience function to extract and normalize grammar rules from a file.

    Args:
        file_path: Path to document
        language: Document language
        anonymize: Whether to anonymize output

    Returns:
        NormalizedRuleSet with extracted rules
    """
    extractor = create_grammar_extractor()
    path = Path(file_path)

    # Determine file type and extract
    if path.suffix.lower() == '.pdf':
        content = await extractor.extract_from_pdf(path, language)
    elif path.suffix.lower() == '.epub':
        content = await extractor.extract_from_epub(path, language)
    elif path.suffix.lower() in {'.png', '.jpg', '.jpeg', '.tiff', '.bmp'}:
        content = await extractor.extract_from_image(path, language)
    else:
        raise ValueError(f"Unsupported file type: {path.suffix}")

    # Extract grammar rules
    rules = await extractor.extract_grammar_rules(content, language)

    # Normalize
    return extractor.normalize_rules(rules, anonymize=anonymize)


# ==============================================================================
# EXAMPLE USAGE
# ==============================================================================

async def _example_usage():
    """Example usage of the grammar extractor"""

    # Create extractor
    config = ExtractionConfig(
        extract_examples=True,
        max_examples_per_rule=3,
        detect_level=True
    )

    extractor = create_grammar_extractor(config)

    # Example: Extract from PDF (placeholder)
    print("Grammar Extractor initialized")
    print(f"Supported formats: PDF, EPUB, Images (PNG, JPG, etc.)")

    # Placeholder demonstration
    from dataclasses import replace

    demo_content = ExtractedContent(
        text="""
        文型：〜てもいい (Permission)
        説明：Used to express permission or ask for permission.
        例文：ここで写真を撮ってもいいですか。

        文型：〜てはいけない (Prohibition)
        説明：Used to express prohibition.
        例文：教室で食べてはいけません。
        """,
        source_type=DocumentType.TEXT,
        source_path="demo.txt",
        page_count=1,
        extraction_quality=ExtractionQuality.HIGH
    )

    rules = await extractor.extract_grammar_rules(demo_content, "ja")
    print(f"\nExtracted {len(rules)} grammar rules")

    for rule in rules:
        print(f"  - {rule.pattern}: {rule.explanation[:50]}...")

    # Normalize with anonymization
    normalized = extractor.normalize_rules(rules, anonymize=True)
    print(f"\nNormalized rule set: {normalized.total_rules} rules")
    print(f"Categories: {[c.value for c in normalized.categories_covered]}")
    print(f"Anonymized: {normalized.anonymized}")


if __name__ == "__main__":
    asyncio.run(_example_usage())

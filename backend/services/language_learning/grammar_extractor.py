"""
================================================================================
AI_MODULE: Grammar Extractor Service
AI_VERSION: 1.0.0
AI_DESCRIPTION: Estrazione completa regole grammaticali da PDF/EPUB/Immagini
AI_BUSINESS: Pipeline AI-first per grammatica da libri con anonimizzazione
AI_TEACHING: Orchestrazione, pipeline pattern, async processing
AI_DEPENDENCIES: PyMuPDF, ebooklib, pytesseract, httpx
AI_CREATED: 2026-02-05

LEGAL PRINCIPLE:
Grammar rules are FACTS, not copyrightable.
Pipeline:
1. Extract text (PDF/EPUB/OCR)
2. Chunk intelligently
3. LLM extracts rules (reformulated)
4. Normalize and anonymize
5. Merge with existing
6. DELETE original text
7. Output: only anonymous rules

FORBIDDEN - NEVER STORED:
- source, book, author, page, isbn, publisher, chapter, edition

================================================================================
"""

import logging
import asyncio
from pathlib import Path
from typing import List, Optional, Union, BinaryIO
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import io

from .text_extractors import PDFExtractor, EPUBExtractor, OCRExtractor
from .rule_normalizer import RuleNormalizer, NormalizedRule
from .grammar_merger import GrammarMergerService, GrammarDatabase

logger = logging.getLogger(__name__)


class FileType(str, Enum):
    """Supported file types for extraction."""
    PDF = "pdf"
    EPUB = "epub"
    IMAGE = "image"
    PDF_SCAN = "pdf_scan"  # Scanned PDF (needs OCR)


@dataclass
class ExtractionProgress:
    """Progress tracking for extraction."""
    stage: str
    current: int
    total: int
    message: str


@dataclass
class ExtractionResult:
    """
    Result of grammar extraction from a file.

    NOTE: No source information is included!
    Only anonymous rules are returned.
    """
    success: bool
    language: str
    rules_extracted: int
    rules_merged: int
    total_rules_in_db: int
    processing_time_seconds: float
    error: Optional[str] = None
    rules: List[NormalizedRule] = field(default_factory=list)

    def to_dict(self):
        return {
            "success": self.success,
            "language": self.language,
            "rules_extracted": self.rules_extracted,
            "rules_merged": self.rules_merged,
            "total_rules_in_db": self.total_rules_in_db,
            "processing_time_seconds": self.processing_time_seconds,
            "error": self.error,
            "rules": [r.to_dict() for r in self.rules]
        }


class GrammarExtractor:
    """
    Main service for extracting grammar rules from books.

    EXTRACTION PIPELINE:
    ┌─────────────────────────────────────────────────────────────┐
    │ INPUT: PDF/EPUB/Image                                        │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [1. Text Extraction]                                         │
    │ - PDF: PyMuPDF (fitz)                                        │
    │ - EPUB: ebooklib                                             │
    │ - Image: Tesseract/PaddleOCR                                 │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [2. Intelligent Chunking]                                    │
    │ - Split by chapters/sections                                 │
    │ - Max 4000 tokens per chunk                                  │
    │ - Preserve sentence boundaries                               │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [3. LLM Rule Extraction]                                     │
    │ - Extract grammar patterns                                   │
    │ - REFORMULATE descriptions                                   │
    │ - Generate NEW examples                                      │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [4. Normalization]                                           │
    │ - Remove ALL source references                               │
    │ - Verify anonymization                                       │
    │ - Generate unique IDs                                        │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [5. Merge with Existing]                                     │
    │ - Load grammar_{language}.json                               │
    │ - Fuzzy deduplicate                                          │
    │ - Merge examples                                             │
    │ - Increment sources_count                                    │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ [6. DELETE Original Text]                                    │
    │ - del text  # Critical!                                      │
    │ - Only rules survive                                         │
    └─────────────────────────────────────────────────────────────┘
                                  ↓
    ┌─────────────────────────────────────────────────────────────┐
    │ OUTPUT: grammar_{language}.json (only anonymous rules)       │
    └─────────────────────────────────────────────────────────────┘
    """

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        llm_base_url: Optional[str] = None
    ):
        """
        Initialize the Grammar Extractor.

        Args:
            storage_path: Where to store grammar files
            llm_base_url: Ollama base URL (default: localhost:11434)
        """
        # Initialize extractors
        self.pdf_extractor = PDFExtractor()
        self.epub_extractor = EPUBExtractor()
        self.ocr_extractor = OCRExtractor()

        # Initialize normalizer and merger
        self.normalizer = RuleNormalizer(llm_base_url=llm_base_url)
        self.merger = GrammarMergerService(storage_path=storage_path)

        # Progress callback
        self._progress_callback = None

    def set_progress_callback(self, callback):
        """Set callback for progress updates."""
        self._progress_callback = callback

    def _report_progress(
        self,
        stage: str,
        current: int,
        total: int,
        message: str
    ):
        """Report progress to callback if set."""
        if self._progress_callback:
            self._progress_callback(ExtractionProgress(
                stage=stage,
                current=current,
                total=total,
                message=message
            ))

    async def extract_from_pdf(
        self,
        file_path: str,
        language: str = "ja"
    ) -> ExtractionResult:
        """
        Extract grammar rules from a PDF file.

        Args:
            file_path: Path to PDF file
            language: Target language (ja, zh, ko)

        Returns:
            ExtractionResult with extracted rules
        """
        start_time = datetime.now()

        self._report_progress("extraction", 0, 4, "Extracting text from PDF...")

        # Step 1: Extract text
        pdf_result = await self.pdf_extractor.extract_from_pdf(file_path, language)

        if not pdf_result.success:
            return ExtractionResult(
                success=False,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=0,
                error=pdf_result.error
            )

        # Process chunks
        result = await self._process_chunks(
            chunks=[c.content for c in pdf_result.chunks],
            language=language,
            start_time=start_time
        )

        # CRITICAL: Delete extracted text
        del pdf_result
        logger.info("Original text deleted after processing")

        return result

    async def extract_from_epub(
        self,
        file_path: str,
        language: str = "ja"
    ) -> ExtractionResult:
        """
        Extract grammar rules from an EPUB file.

        Args:
            file_path: Path to EPUB file
            language: Target language (ja, zh, ko)

        Returns:
            ExtractionResult with extracted rules
        """
        start_time = datetime.now()

        self._report_progress("extraction", 0, 4, "Extracting text from EPUB...")

        # Step 1: Extract text
        epub_result = await self.epub_extractor.extract_from_epub(file_path, language)

        if not epub_result.success:
            return ExtractionResult(
                success=False,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=0,
                error=epub_result.error
            )

        # Process chunks
        result = await self._process_chunks(
            chunks=[c.content for c in epub_result.chunks],
            language=language,
            start_time=start_time
        )

        # CRITICAL: Delete extracted text
        del epub_result
        logger.info("Original text deleted after processing")

        return result

    async def extract_from_image(
        self,
        file_path: str,
        language: str = "ja"
    ) -> ExtractionResult:
        """
        Extract grammar rules from an image file using OCR.

        Args:
            file_path: Path to image file
            language: Target language (ja, zh, ko)

        Returns:
            ExtractionResult with extracted rules
        """
        start_time = datetime.now()

        self._report_progress("extraction", 0, 4, "Extracting text via OCR...")

        # Step 1: OCR extraction
        ocr_result = await self.ocr_extractor.extract_from_image(file_path, language)

        if not ocr_result.success:
            return ExtractionResult(
                success=False,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=0,
                error=ocr_result.error
            )

        # Process chunks
        result = await self._process_chunks(
            chunks=[c.content for c in ocr_result.chunks],
            language=language,
            start_time=start_time
        )

        # CRITICAL: Delete extracted text
        del ocr_result
        logger.info("Original text deleted after processing")

        return result

    async def extract_from_bytes(
        self,
        file_bytes: bytes,
        file_type: FileType,
        language: str = "ja"
    ) -> ExtractionResult:
        """
        Extract grammar rules from file bytes (for uploads).

        Args:
            file_bytes: Raw file content
            file_type: Type of file (pdf, epub, image)
            language: Target language

        Returns:
            ExtractionResult with extracted rules
        """
        start_time = datetime.now()

        self._report_progress("extraction", 0, 4, f"Extracting from {file_type.value}...")

        # Extract based on type
        if file_type == FileType.PDF:
            result = await self.pdf_extractor.extract_from_bytes(file_bytes, language)
        elif file_type == FileType.EPUB:
            result = await self.epub_extractor.extract_from_bytes(file_bytes, language)
        elif file_type == FileType.IMAGE:
            result = await self.ocr_extractor.extract_from_bytes(file_bytes, language)
        elif file_type == FileType.PDF_SCAN:
            # Save to temp file for OCR processing
            import tempfile
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
                f.write(file_bytes)
                temp_path = f.name
            try:
                result = await self.ocr_extractor.extract_from_pdf_images(
                    temp_path, language
                )
            finally:
                Path(temp_path).unlink(missing_ok=True)
        else:
            return ExtractionResult(
                success=False,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=0,
                error=f"Unsupported file type: {file_type}"
            )

        if not result.success:
            return ExtractionResult(
                success=False,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=0,
                error=result.error
            )

        # Process chunks
        extraction_result = await self._process_chunks(
            chunks=[c.content for c in result.chunks],
            language=language,
            start_time=start_time
        )

        # CRITICAL: Delete all traces
        del result
        del file_bytes
        logger.info("Original content deleted after processing")

        return extraction_result

    async def _process_chunks(
        self,
        chunks: List[str],
        language: str,
        start_time: datetime
    ) -> ExtractionResult:
        """
        Process text chunks through the extraction pipeline.

        Args:
            chunks: List of text chunks
            language: Target language
            start_time: When processing started

        Returns:
            ExtractionResult
        """
        total_chunks = len(chunks)
        all_rules: List[NormalizedRule] = []

        # Step 2: Process each chunk with LLM
        self._report_progress(
            "extraction", 1, 4,
            f"Processing {total_chunks} chunks with LLM..."
        )

        for i, chunk in enumerate(chunks):
            self._report_progress(
                "llm", i + 1, total_chunks,
                f"Extracting rules from chunk {i + 1}/{total_chunks}"
            )

            try:
                rules = await self.normalizer.extract_rules_from_text(
                    chunk, language
                )
                all_rules.extend(rules)
            except Exception as e:
                logger.warning(f"Failed to process chunk {i}: {e}")
                continue

            # CRITICAL: Delete chunk after processing
            del chunk

        # CRITICAL: Delete all chunks
        chunks.clear()

        if not all_rules:
            return ExtractionResult(
                success=True,
                language=language,
                rules_extracted=0,
                rules_merged=0,
                total_rules_in_db=0,
                processing_time_seconds=(datetime.now() - start_time).total_seconds(),
                error="No grammar rules found in the text"
            )

        # Step 3: Merge with existing
        self._report_progress(
            "merge", 3, 4,
            f"Merging {len(all_rules)} rules with existing database..."
        )

        grammar_db = await self.merger.merge_rules(language, all_rules)

        # Step 4: Complete
        self._report_progress("complete", 4, 4, "Extraction complete!")

        processing_time = (datetime.now() - start_time).total_seconds()

        return ExtractionResult(
            success=True,
            language=language,
            rules_extracted=len(all_rules),
            rules_merged=grammar_db.total_rules,
            total_rules_in_db=grammar_db.total_rules,
            processing_time_seconds=processing_time,
            rules=all_rules
        )

    async def get_grammar(self, language: str) -> Optional[GrammarDatabase]:
        """
        Get the grammar database for a language.

        Args:
            language: Language code (ja, zh, ko)

        Returns:
            GrammarDatabase or None
        """
        return await self.merger.load_grammar(language)

    async def get_statistics(self, language: str):
        """Get statistics about a grammar database."""
        return await self.merger.get_statistics(language)

    async def search_rules(
        self,
        language: str,
        query: str
    ) -> List[NormalizedRule]:
        """Search for rules matching a query."""
        return await self.merger.search_rules(language, query)

    async def export_to_anki(
        self,
        language: str,
        output_path: Optional[Path] = None
    ) -> Path:
        """Export grammar to Anki format."""
        return await self.merger.export_to_anki(language, output_path)


# Convenience function for testing
async def process_grammar_book(
    file_path: str,
    language: str = "ja",
    file_type: Optional[FileType] = None
) -> ExtractionResult:
    """
    Convenience function to process a grammar book.

    Args:
        file_path: Path to the file
        language: Target language
        file_type: Optional file type (auto-detected if not provided)

    Returns:
        ExtractionResult
    """
    extractor = GrammarExtractor()

    # Auto-detect file type
    path = Path(file_path)
    suffix = path.suffix.lower()

    if file_type is None:
        if suffix == ".pdf":
            file_type = FileType.PDF
        elif suffix == ".epub":
            file_type = FileType.EPUB
        elif suffix in [".png", ".jpg", ".jpeg", ".tiff", ".bmp"]:
            file_type = FileType.IMAGE
        else:
            raise ValueError(f"Unknown file type: {suffix}")

    if file_type == FileType.PDF:
        return await extractor.extract_from_pdf(file_path, language)
    elif file_type == FileType.EPUB:
        return await extractor.extract_from_epub(file_path, language)
    elif file_type == FileType.IMAGE:
        return await extractor.extract_from_image(file_path, language)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")

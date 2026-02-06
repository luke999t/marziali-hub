"""
================================================================================
AI_MODULE: PDF Text Extractor
AI_VERSION: 1.0.0
AI_DESCRIPTION: Estrazione testo da file PDF usando PyMuPDF (fitz)
AI_BUSINESS: Supporto libri grammatica in formato PDF
AI_TEACHING: PyMuPDF, chunking, layout detection
AI_DEPENDENCIES: PyMuPDF (fitz)
AI_CREATED: 2026-02-05

PRIVACY:
- Extracted text is processed for grammar rules ONLY
- Original content is deleted after processing
- NO source metadata is preserved
================================================================================
"""

import logging
from pathlib import Path
from typing import List, Optional, Generator
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class TextChunk:
    """A chunk of extracted text with metadata."""
    content: str
    chunk_index: int
    total_chunks: int
    estimated_tokens: int


@dataclass
class PDFExtractionResult:
    """Result of PDF text extraction."""
    chunks: List[TextChunk]
    total_pages: int
    language_hint: Optional[str]
    success: bool
    error: Optional[str] = None


class PDFExtractor:
    """
    Extracts text from PDF files using PyMuPDF.

    LEGAL: Grammar rules are facts, not copyrightable.
    We extract text temporarily to identify grammar patterns,
    then DELETE the original content. Only rules remain.
    """

    # Max tokens per chunk (approx 4 chars per token for CJK)
    MAX_TOKENS_PER_CHUNK = 4000
    MAX_CHARS_PER_CHUNK = MAX_TOKENS_PER_CHUNK * 4

    def __init__(self):
        self._fitz = None

    def _ensure_fitz(self):
        """Lazy import of PyMuPDF."""
        if self._fitz is None:
            try:
                import fitz
                self._fitz = fitz
            except ImportError:
                raise ImportError(
                    "PyMuPDF not installed. Run: pip install PyMuPDF"
                )
        return self._fitz

    async def extract_from_pdf(
        self,
        file_path: str,
        language: str = "ja"
    ) -> PDFExtractionResult:
        """
        Extract text from PDF file.

        Args:
            file_path: Path to PDF file
            language: Expected language (ja, zh, ko, etc.)

        Returns:
            PDFExtractionResult with chunked text
        """
        fitz = self._ensure_fitz()
        path = Path(file_path)

        if not path.exists():
            return PDFExtractionResult(
                chunks=[],
                total_pages=0,
                language_hint=language,
                success=False,
                error=f"File not found: {file_path}"
            )

        if not path.suffix.lower() == ".pdf":
            return PDFExtractionResult(
                chunks=[],
                total_pages=0,
                language_hint=language,
                success=False,
                error=f"Not a PDF file: {file_path}"
            )

        try:
            doc = fitz.open(str(path))
            total_pages = len(doc)

            # Extract all text
            full_text = []
            for page_num in range(total_pages):
                page = doc[page_num]
                text = page.get_text("text")
                if text.strip():
                    full_text.append(text)

            doc.close()

            # Combine and chunk
            combined_text = "\n\n".join(full_text)
            chunks = list(self._chunk_text(combined_text))

            logger.info(
                f"PDF extraction complete: {total_pages} pages, "
                f"{len(chunks)} chunks"
            )

            return PDFExtractionResult(
                chunks=chunks,
                total_pages=total_pages,
                language_hint=language,
                success=True
            )

        except Exception as e:
            logger.error(f"PDF extraction failed: {e}")
            return PDFExtractionResult(
                chunks=[],
                total_pages=0,
                language_hint=language,
                success=False,
                error=str(e)
            )

    def _chunk_text(self, text: str) -> Generator[TextChunk, None, None]:
        """
        Split text into chunks suitable for LLM processing.

        Tries to split on paragraph boundaries for coherence.
        """
        if not text.strip():
            return

        # Split by double newlines (paragraphs)
        paragraphs = text.split("\n\n")

        current_chunk = []
        current_length = 0
        chunk_index = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue

            para_length = len(para)

            # If single paragraph exceeds limit, split it
            if para_length > self.MAX_CHARS_PER_CHUNK:
                # First yield current chunk if any
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index
                    )
                    chunk_index += 1
                    current_chunk = []
                    current_length = 0

                # Split long paragraph
                for sub_chunk in self._split_long_text(para):
                    yield self._create_chunk(sub_chunk, chunk_index)
                    chunk_index += 1
                continue

            # Check if adding this paragraph would exceed limit
            if current_length + para_length > self.MAX_CHARS_PER_CHUNK:
                # Yield current chunk
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index
                    )
                    chunk_index += 1
                current_chunk = [para]
                current_length = para_length
            else:
                current_chunk.append(para)
                current_length += para_length

        # Yield remaining
        if current_chunk:
            yield self._create_chunk(
                "\n\n".join(current_chunk),
                chunk_index
            )

    def _split_long_text(self, text: str) -> Generator[str, None, None]:
        """Split a long text on sentence boundaries."""
        # Try to split on sentence endings
        sentence_endings = ["。", ".", "！", "!", "？", "?", "」", "\n"]

        current = []
        current_length = 0

        i = 0
        while i < len(text):
            char = text[i]
            current.append(char)
            current_length += 1

            # Check for sentence ending
            is_ending = char in sentence_endings

            if is_ending and current_length >= self.MAX_CHARS_PER_CHUNK * 0.5:
                # Yield if we're past half capacity and hit ending
                yield "".join(current)
                current = []
                current_length = 0
            elif current_length >= self.MAX_CHARS_PER_CHUNK:
                # Force split
                yield "".join(current)
                current = []
                current_length = 0

            i += 1

        if current:
            yield "".join(current)

    def _create_chunk(self, text: str, index: int) -> TextChunk:
        """Create a TextChunk with estimated token count."""
        # Rough estimation: CJK ~1 char = 1 token, others ~4 chars = 1 token
        cjk_count = sum(1 for c in text if ord(c) > 0x3000)
        other_count = len(text) - cjk_count
        estimated_tokens = cjk_count + (other_count // 4)

        return TextChunk(
            content=text,
            chunk_index=index,
            total_chunks=-1,  # Will be set later
            estimated_tokens=estimated_tokens
        )

    async def extract_from_bytes(
        self,
        pdf_bytes: bytes,
        language: str = "ja"
    ) -> PDFExtractionResult:
        """
        Extract text from PDF bytes (for uploaded files).

        Args:
            pdf_bytes: Raw PDF content
            language: Expected language

        Returns:
            PDFExtractionResult with chunked text
        """
        fitz = self._ensure_fitz()

        try:
            doc = fitz.open(stream=pdf_bytes, filetype="pdf")
            total_pages = len(doc)

            full_text = []
            for page_num in range(total_pages):
                page = doc[page_num]
                text = page.get_text("text")
                if text.strip():
                    full_text.append(text)

            doc.close()

            combined_text = "\n\n".join(full_text)
            chunks = list(self._chunk_text(combined_text))

            # Update total_chunks in each chunk
            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            return PDFExtractionResult(
                chunks=chunks,
                total_pages=total_pages,
                language_hint=language,
                success=True
            )

        except Exception as e:
            logger.error(f"PDF bytes extraction failed: {e}")
            return PDFExtractionResult(
                chunks=[],
                total_pages=0,
                language_hint=language,
                success=False,
                error=str(e)
            )

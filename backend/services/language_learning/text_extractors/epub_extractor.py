"""
================================================================================
AI_MODULE: EPUB Text Extractor
AI_VERSION: 1.0.0
AI_DESCRIPTION: Estrazione testo da file EPUB usando ebooklib
AI_BUSINESS: Supporto libri grammatica in formato EPUB
AI_TEACHING: ebooklib, BeautifulSoup, HTML parsing, chunking
AI_DEPENDENCIES: ebooklib, beautifulsoup4, lxml
AI_CREATED: 2026-02-05

PRIVACY:
- Extracted text is processed for grammar rules ONLY
- Original content is deleted after processing
- NO source metadata is preserved (title, author, etc.)
================================================================================
"""

import logging
from pathlib import Path
from typing import List, Optional, Generator
from dataclasses import dataclass
import re

logger = logging.getLogger(__name__)


@dataclass
class TextChunk:
    """A chunk of extracted text with metadata."""
    content: str
    chunk_index: int
    total_chunks: int
    estimated_tokens: int
    chapter_hint: Optional[str] = None


@dataclass
class EPUBExtractionResult:
    """Result of EPUB text extraction."""
    chunks: List[TextChunk]
    total_chapters: int
    language_hint: Optional[str]
    success: bool
    error: Optional[str] = None


class EPUBExtractor:
    """
    Extracts text from EPUB files using ebooklib.

    LEGAL: Grammar rules are facts, not copyrightable.
    We extract text temporarily to identify grammar patterns,
    then DELETE the original content. Only rules remain.

    NOTE: We explicitly DO NOT store:
    - Book title
    - Author name
    - ISBN
    - Publisher
    - Any identifying metadata
    """

    MAX_TOKENS_PER_CHUNK = 4000
    MAX_CHARS_PER_CHUNK = MAX_TOKENS_PER_CHUNK * 4

    def __init__(self):
        self._ebooklib = None
        self._bs4 = None

    def _ensure_deps(self):
        """Lazy import of dependencies."""
        if self._ebooklib is None:
            try:
                import ebooklib
                from ebooklib import epub
                self._ebooklib = ebooklib
                self._epub = epub
            except ImportError:
                raise ImportError(
                    "ebooklib not installed. Run: pip install ebooklib"
                )

        if self._bs4 is None:
            try:
                from bs4 import BeautifulSoup
                self._bs4 = BeautifulSoup
            except ImportError:
                raise ImportError(
                    "beautifulsoup4 not installed. Run: pip install beautifulsoup4 lxml"
                )

    async def extract_from_epub(
        self,
        file_path: str,
        language: str = "ja"
    ) -> EPUBExtractionResult:
        """
        Extract text from EPUB file.

        Args:
            file_path: Path to EPUB file
            language: Expected language (ja, zh, ko, etc.)

        Returns:
            EPUBExtractionResult with chunked text
        """
        self._ensure_deps()
        path = Path(file_path)

        if not path.exists():
            return EPUBExtractionResult(
                chunks=[],
                total_chapters=0,
                language_hint=language,
                success=False,
                error=f"File not found: {file_path}"
            )

        if not path.suffix.lower() == ".epub":
            return EPUBExtractionResult(
                chunks=[],
                total_chapters=0,
                language_hint=language,
                success=False,
                error=f"Not an EPUB file: {file_path}"
            )

        try:
            book = self._epub.read_epub(str(path))

            # Extract chapters
            chapters_text = []
            chapter_count = 0

            for item in book.get_items():
                if item.get_type() == self._ebooklib.ITEM_DOCUMENT:
                    content = item.get_content()
                    soup = self._bs4(content, "lxml")

                    # Remove script and style elements
                    for tag in soup(["script", "style", "nav"]):
                        tag.decompose()

                    text = soup.get_text(separator="\n")
                    text = self._clean_text(text)

                    if text.strip():
                        chapters_text.append(text)
                        chapter_count += 1

            # Combine and chunk
            combined_text = "\n\n---\n\n".join(chapters_text)
            chunks = list(self._chunk_text(combined_text))

            # Update total_chunks
            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            logger.info(
                f"EPUB extraction complete: {chapter_count} chapters, "
                f"{len(chunks)} chunks"
            )

            return EPUBExtractionResult(
                chunks=chunks,
                total_chapters=chapter_count,
                language_hint=language,
                success=True
            )

        except Exception as e:
            logger.error(f"EPUB extraction failed: {e}")
            return EPUBExtractionResult(
                chunks=[],
                total_chapters=0,
                language_hint=language,
                success=False,
                error=str(e)
            )

    def _clean_text(self, text: str) -> str:
        """Clean extracted text."""
        # Remove excessive whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r' {2,}', ' ', text)

        # Remove common EPUB artifacts
        text = re.sub(r'^\s*\d+\s*$', '', text, flags=re.MULTILINE)

        return text.strip()

    def _chunk_text(self, text: str) -> Generator[TextChunk, None, None]:
        """Split text into chunks suitable for LLM processing."""
        if not text.strip():
            return

        # Split by chapter markers or paragraphs
        sections = re.split(r'\n\n---\n\n|\n\n\n+', text)

        current_chunk = []
        current_length = 0
        chunk_index = 0

        for section in sections:
            section = section.strip()
            if not section:
                continue

            section_length = len(section)

            if section_length > self.MAX_CHARS_PER_CHUNK:
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index
                    )
                    chunk_index += 1
                    current_chunk = []
                    current_length = 0

                for sub_chunk in self._split_long_text(section):
                    yield self._create_chunk(sub_chunk, chunk_index)
                    chunk_index += 1
                continue

            if current_length + section_length > self.MAX_CHARS_PER_CHUNK:
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index
                    )
                    chunk_index += 1
                current_chunk = [section]
                current_length = section_length
            else:
                current_chunk.append(section)
                current_length += section_length

        if current_chunk:
            yield self._create_chunk(
                "\n\n".join(current_chunk),
                chunk_index
            )

    def _split_long_text(self, text: str) -> Generator[str, None, None]:
        """Split long text on sentence boundaries."""
        sentence_endings = ["。", ".", "！", "!", "？", "?", "」", "\n"]

        current = []
        current_length = 0

        for char in text:
            current.append(char)
            current_length += 1

            is_ending = char in sentence_endings

            if is_ending and current_length >= self.MAX_CHARS_PER_CHUNK * 0.5:
                yield "".join(current)
                current = []
                current_length = 0
            elif current_length >= self.MAX_CHARS_PER_CHUNK:
                yield "".join(current)
                current = []
                current_length = 0

        if current:
            yield "".join(current)

    def _create_chunk(self, text: str, index: int) -> TextChunk:
        """Create a TextChunk with estimated token count."""
        cjk_count = sum(1 for c in text if ord(c) > 0x3000)
        other_count = len(text) - cjk_count
        estimated_tokens = cjk_count + (other_count // 4)

        return TextChunk(
            content=text,
            chunk_index=index,
            total_chunks=-1,
            estimated_tokens=estimated_tokens
        )

    async def extract_from_bytes(
        self,
        epub_bytes: bytes,
        language: str = "ja"
    ) -> EPUBExtractionResult:
        """
        Extract text from EPUB bytes (for uploaded files).

        Args:
            epub_bytes: Raw EPUB content
            language: Expected language

        Returns:
            EPUBExtractionResult with chunked text
        """
        self._ensure_deps()

        try:
            import io
            book = self._epub.read_epub(io.BytesIO(epub_bytes))

            chapters_text = []
            chapter_count = 0

            for item in book.get_items():
                if item.get_type() == self._ebooklib.ITEM_DOCUMENT:
                    content = item.get_content()
                    soup = self._bs4(content, "lxml")

                    for tag in soup(["script", "style", "nav"]):
                        tag.decompose()

                    text = soup.get_text(separator="\n")
                    text = self._clean_text(text)

                    if text.strip():
                        chapters_text.append(text)
                        chapter_count += 1

            combined_text = "\n\n---\n\n".join(chapters_text)
            chunks = list(self._chunk_text(combined_text))

            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            return EPUBExtractionResult(
                chunks=chunks,
                total_chapters=chapter_count,
                language_hint=language,
                success=True
            )

        except Exception as e:
            logger.error(f"EPUB bytes extraction failed: {e}")
            return EPUBExtractionResult(
                chunks=[],
                total_chapters=0,
                language_hint=language,
                success=False,
                error=str(e)
            )

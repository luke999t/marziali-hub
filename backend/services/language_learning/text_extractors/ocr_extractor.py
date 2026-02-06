"""
================================================================================
AI_MODULE: OCR Text Extractor
AI_VERSION: 1.0.0
AI_DESCRIPTION: Estrazione testo da immagini usando Tesseract/PaddleOCR
AI_BUSINESS: Supporto libri grammatica in formato immagine/scan
AI_TEACHING: Tesseract OCR, PaddleOCR, image preprocessing, PIL
AI_DEPENDENCIES: pytesseract, pillow, opencv-python (optional: paddleocr)
AI_CREATED: 2026-02-05

PRIVACY:
- Extracted text is processed for grammar rules ONLY
- Original images are NOT stored
- NO source metadata is preserved

OCR ENGINES:
1. Tesseract - Good for Western + Japanese/Chinese
2. PaddleOCR - Better for Chinese/Japanese (optional)
================================================================================
"""

import logging
from pathlib import Path
from typing import List, Optional, Generator, Union
from dataclasses import dataclass
import io

logger = logging.getLogger(__name__)


@dataclass
class TextChunk:
    """A chunk of extracted text with metadata."""
    content: str
    chunk_index: int
    total_chunks: int
    estimated_tokens: int
    confidence: float = 0.0


@dataclass
class OCRExtractionResult:
    """Result of OCR text extraction."""
    chunks: List[TextChunk]
    total_images: int
    language_hint: Optional[str]
    ocr_engine: str
    average_confidence: float
    success: bool
    error: Optional[str] = None


class OCRExtractor:
    """
    Extracts text from images using OCR.

    Supports:
    - Tesseract OCR (default)
    - PaddleOCR (better for CJK, optional)

    LEGAL: Grammar rules are facts, not copyrightable.
    We extract text temporarily to identify grammar patterns,
    then DELETE the original content. Only rules remain.
    """

    MAX_TOKENS_PER_CHUNK = 4000
    MAX_CHARS_PER_CHUNK = MAX_TOKENS_PER_CHUNK * 4

    # Tesseract language codes
    TESSERACT_LANGS = {
        "ja": "jpn",
        "zh": "chi_sim+chi_tra",
        "ko": "kor",
        "en": "eng",
    }

    def __init__(self, prefer_paddle: bool = False):
        """
        Initialize OCR extractor.

        Args:
            prefer_paddle: If True, try PaddleOCR first (better for CJK)
        """
        self.prefer_paddle = prefer_paddle
        self._tesseract = None
        self._paddle = None
        self._pil = None
        self._cv2 = None

    def _ensure_pil(self):
        """Lazy import of PIL."""
        if self._pil is None:
            try:
                from PIL import Image, ImageEnhance, ImageFilter
                self._pil = Image
                self._pil_enhance = ImageEnhance
                self._pil_filter = ImageFilter
            except ImportError:
                raise ImportError(
                    "Pillow not installed. Run: pip install pillow"
                )
        return self._pil

    def _ensure_tesseract(self):
        """Lazy import of pytesseract."""
        if self._tesseract is None:
            try:
                import pytesseract
                self._tesseract = pytesseract
            except ImportError:
                raise ImportError(
                    "pytesseract not installed. Run: pip install pytesseract"
                )
        return self._tesseract

    def _try_paddle(self) -> bool:
        """Try to import PaddleOCR."""
        if self._paddle is None:
            try:
                from paddleocr import PaddleOCR
                self._paddle = PaddleOCR(use_angle_cls=True, lang='ch')
                return True
            except ImportError:
                logger.info("PaddleOCR not available, using Tesseract")
                return False
        return True

    def _ensure_cv2(self):
        """Lazy import of OpenCV for preprocessing."""
        if self._cv2 is None:
            try:
                import cv2
                self._cv2 = cv2
            except ImportError:
                logger.warning("OpenCV not available, skipping preprocessing")
                return None
        return self._cv2

    async def extract_from_image(
        self,
        file_path: str,
        language: str = "ja"
    ) -> OCRExtractionResult:
        """
        Extract text from image file.

        Args:
            file_path: Path to image file
            language: Expected language (ja, zh, ko, etc.)

        Returns:
            OCRExtractionResult with extracted text
        """
        Image = self._ensure_pil()
        path = Path(file_path)

        if not path.exists():
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=f"File not found: {file_path}"
            )

        valid_extensions = {".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".gif", ".webp"}
        if path.suffix.lower() not in valid_extensions:
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=f"Unsupported image format: {path.suffix}"
            )

        try:
            image = Image.open(str(path))
            return await self._process_image(image, language)

        except Exception as e:
            logger.error(f"Image extraction failed: {e}")
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=str(e)
            )

    async def extract_from_bytes(
        self,
        image_bytes: bytes,
        language: str = "ja"
    ) -> OCRExtractionResult:
        """
        Extract text from image bytes (for uploaded files).

        Args:
            image_bytes: Raw image content
            language: Expected language

        Returns:
            OCRExtractionResult with extracted text
        """
        Image = self._ensure_pil()

        try:
            image = Image.open(io.BytesIO(image_bytes))
            return await self._process_image(image, language)

        except Exception as e:
            logger.error(f"Image bytes extraction failed: {e}")
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=str(e)
            )

    async def _process_image(
        self,
        image,
        language: str
    ) -> OCRExtractionResult:
        """Process a PIL Image and extract text."""
        # Preprocess image for better OCR
        processed_image = self._preprocess_image(image)

        # Try PaddleOCR first if preferred and available
        if self.prefer_paddle and language in ["zh", "ja"] and self._try_paddle():
            return await self._extract_with_paddle(processed_image, language)

        # Default to Tesseract
        return await self._extract_with_tesseract(processed_image, language)

    def _preprocess_image(self, image):
        """
        Preprocess image for better OCR results.

        - Convert to grayscale
        - Enhance contrast
        - Apply sharpening
        """
        Image = self._ensure_pil()

        # Convert to RGB if necessary
        if image.mode != "RGB":
            image = image.convert("RGB")

        # Convert to grayscale
        image = image.convert("L")

        # Enhance contrast
        enhancer = self._pil_enhance.Contrast(image)
        image = enhancer.enhance(1.5)

        # Sharpen
        image = image.filter(self._pil_filter.SHARPEN)

        # Convert back to RGB for OCR
        image = image.convert("RGB")

        return image

    async def _extract_with_tesseract(
        self,
        image,
        language: str
    ) -> OCRExtractionResult:
        """Extract text using Tesseract OCR."""
        tesseract = self._ensure_tesseract()

        # Get Tesseract language code
        lang_code = self.TESSERACT_LANGS.get(language, "eng")

        try:
            # Get detailed data for confidence
            data = tesseract.image_to_data(
                image,
                lang=lang_code,
                output_type=tesseract.Output.DICT
            )

            # Extract text and calculate confidence
            texts = []
            confidences = []

            for i, text in enumerate(data['text']):
                if text.strip():
                    texts.append(text)
                    conf = data['conf'][i]
                    if conf > 0:
                        confidences.append(conf)

            full_text = " ".join(texts)
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            # Chunk the text
            chunks = list(self._chunk_text(full_text, avg_confidence / 100.0))

            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            logger.info(
                f"Tesseract OCR complete: {len(full_text)} chars, "
                f"confidence: {avg_confidence:.1f}%"
            )

            return OCRExtractionResult(
                chunks=chunks,
                total_images=1,
                language_hint=language,
                ocr_engine="tesseract",
                average_confidence=avg_confidence / 100.0,
                success=True
            )

        except Exception as e:
            logger.error(f"Tesseract OCR failed: {e}")
            return OCRExtractionResult(
                chunks=[],
                total_images=1,
                language_hint=language,
                ocr_engine="tesseract",
                average_confidence=0.0,
                success=False,
                error=str(e)
            )

    async def _extract_with_paddle(
        self,
        image,
        language: str
    ) -> OCRExtractionResult:
        """Extract text using PaddleOCR (better for CJK)."""
        import numpy as np

        try:
            # Convert PIL to numpy array
            img_array = np.array(image)

            # Run PaddleOCR
            result = self._paddle.ocr(img_array, cls=True)

            # Extract text and confidence
            texts = []
            confidences = []

            if result and result[0]:
                for line in result[0]:
                    text = line[1][0]
                    confidence = line[1][1]
                    texts.append(text)
                    confidences.append(confidence)

            full_text = "\n".join(texts)
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0

            # Chunk the text
            chunks = list(self._chunk_text(full_text, avg_confidence))

            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            logger.info(
                f"PaddleOCR complete: {len(full_text)} chars, "
                f"confidence: {avg_confidence:.2%}"
            )

            return OCRExtractionResult(
                chunks=chunks,
                total_images=1,
                language_hint=language,
                ocr_engine="paddleocr",
                average_confidence=avg_confidence,
                success=True
            )

        except Exception as e:
            logger.error(f"PaddleOCR failed, falling back to Tesseract: {e}")
            return await self._extract_with_tesseract(image, language)

    def _chunk_text(
        self,
        text: str,
        confidence: float
    ) -> Generator[TextChunk, None, None]:
        """Split text into chunks."""
        if not text.strip():
            return

        paragraphs = text.split("\n\n")

        current_chunk = []
        current_length = 0
        chunk_index = 0

        for para in paragraphs:
            para = para.strip()
            if not para:
                continue

            para_length = len(para)

            if para_length > self.MAX_CHARS_PER_CHUNK:
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index,
                        confidence
                    )
                    chunk_index += 1
                    current_chunk = []
                    current_length = 0

                for sub_chunk in self._split_long_text(para):
                    yield self._create_chunk(sub_chunk, chunk_index, confidence)
                    chunk_index += 1
                continue

            if current_length + para_length > self.MAX_CHARS_PER_CHUNK:
                if current_chunk:
                    yield self._create_chunk(
                        "\n\n".join(current_chunk),
                        chunk_index,
                        confidence
                    )
                    chunk_index += 1
                current_chunk = [para]
                current_length = para_length
            else:
                current_chunk.append(para)
                current_length += para_length

        if current_chunk:
            yield self._create_chunk(
                "\n\n".join(current_chunk),
                chunk_index,
                confidence
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

    def _create_chunk(
        self,
        text: str,
        index: int,
        confidence: float
    ) -> TextChunk:
        """Create a TextChunk with estimated token count."""
        cjk_count = sum(1 for c in text if ord(c) > 0x3000)
        other_count = len(text) - cjk_count
        estimated_tokens = cjk_count + (other_count // 4)

        return TextChunk(
            content=text,
            chunk_index=index,
            total_chunks=-1,
            estimated_tokens=estimated_tokens,
            confidence=confidence
        )

    async def extract_from_pdf_images(
        self,
        file_path: str,
        language: str = "ja"
    ) -> OCRExtractionResult:
        """
        Extract text from a PDF that contains scanned images.

        Uses PyMuPDF to extract images, then OCR each one.

        Args:
            file_path: Path to PDF file
            language: Expected language

        Returns:
            OCRExtractionResult with extracted text
        """
        Image = self._ensure_pil()

        try:
            import fitz
        except ImportError:
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error="PyMuPDF not installed. Run: pip install PyMuPDF"
            )

        path = Path(file_path)
        if not path.exists():
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=f"File not found: {file_path}"
            )

        try:
            doc = fitz.open(str(path))
            all_text = []
            all_confidences = []
            image_count = 0

            for page_num in range(len(doc)):
                page = doc[page_num]

                # Render page as image
                mat = fitz.Matrix(2, 2)  # 2x zoom for better OCR
                pix = page.get_pixmap(matrix=mat)

                img_data = pix.tobytes("png")
                image = Image.open(io.BytesIO(img_data))

                # OCR the page image
                result = await self._process_image(image, language)

                if result.success and result.chunks:
                    for chunk in result.chunks:
                        all_text.append(chunk.content)
                        all_confidences.append(chunk.confidence)
                    image_count += 1

            doc.close()

            # Combine all text
            full_text = "\n\n".join(all_text)
            avg_confidence = sum(all_confidences) / len(all_confidences) if all_confidences else 0.0

            # Re-chunk the combined text
            chunks = list(self._chunk_text(full_text, avg_confidence))
            for chunk in chunks:
                chunk.total_chunks = len(chunks)

            return OCRExtractionResult(
                chunks=chunks,
                total_images=image_count,
                language_hint=language,
                ocr_engine="tesseract" if not self.prefer_paddle else "paddleocr",
                average_confidence=avg_confidence,
                success=True
            )

        except Exception as e:
            logger.error(f"PDF OCR extraction failed: {e}")
            return OCRExtractionResult(
                chunks=[],
                total_images=0,
                language_hint=language,
                ocr_engine="none",
                average_confidence=0.0,
                success=False,
                error=str(e)
            )

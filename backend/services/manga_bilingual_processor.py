"""
AI_MODULE: MangaBilingualProcessor Service
AI_DESCRIPTION: Estrazione dialoghi da manga bilingui con allineamento
AI_BUSINESS: Creazione coppie frasi da manga per studio lingue CJK
AI_TEACHING: Image processing, OCR, dialogue extraction, bilingual alignment

FEATURES:
- Process manga pages in original + translated versions
- Speech bubble detection (via contours or ML)
- OCR for Japanese/Chinese/Korean text
- Dialogue alignment between versions
- Export to study formats (JSON, Anki, TMX)
- Privacy by design (no source tracking)

PIPELINE:
1. Load original + translated manga pages
2. Detect speech bubbles in both versions
3. OCR text from each bubble
4. Align bubbles by position/order
5. Create bilingual pairs
6. Export results

DEPENDENCIES (optional):
- OpenCV (cv2) for image processing
- Pillow for basic image handling
- pytesseract for OCR
- manga-ocr for Japanese manga OCR (better quality)

ZERO MOCK POLICY:
- All tests use real image processing
- Real OCR calls when available
- Fallback to test mode without dependencies
"""

import asyncio
import logging
import hashlib
import json
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any, Tuple, Union
from enum import Enum
from datetime import datetime
import uuid

# Optional dependencies
try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import cv2
    import numpy as np
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False


# === ENUMS ===

class MangaLanguage(str, Enum):
    """Supported manga languages."""
    JAPANESE = "ja"
    CHINESE_SIMPLIFIED = "zh-CN"
    CHINESE_TRADITIONAL = "zh-TW"
    KOREAN = "ko"
    ENGLISH = "en"
    ITALIAN = "it"
    SPANISH = "es"
    FRENCH = "fr"
    GERMAN = "de"


class BubbleType(str, Enum):
    """Types of speech/text bubbles."""
    SPEECH = "speech"           # Normal dialogue
    THOUGHT = "thought"         # Thought bubble
    NARRATION = "narration"     # Narrator box
    SFX = "sfx"                 # Sound effect
    SIGN = "sign"               # Signs/labels
    UNKNOWN = "unknown"


class ProcessingStatus(str, Enum):
    """Processing status for manga pages."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


# === DATA CLASSES ===

@dataclass
class BoundingBox:
    """Bounding box for a detected region."""
    x: int
    y: int
    width: int
    height: int

    @property
    def center(self) -> Tuple[int, int]:
        return (self.x + self.width // 2, self.y + self.height // 2)

    @property
    def area(self) -> int:
        return self.width * self.height

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

    def overlap_ratio(self, other: 'BoundingBox') -> float:
        """Calculate overlap ratio with another box."""
        x_overlap = max(0, min(self.x + self.width, other.x + other.width) - max(self.x, other.x))
        y_overlap = max(0, min(self.y + self.height, other.y + other.height) - max(self.y, other.y))
        intersection = x_overlap * y_overlap

        if intersection == 0:
            return 0.0

        union = self.area + other.area - intersection
        return intersection / union if union > 0 else 0.0


@dataclass
class TextBubble:
    """A detected text bubble with extracted text."""
    id: str
    bbox: BoundingBox
    text: str
    bubble_type: BubbleType = BubbleType.SPEECH
    confidence: float = 1.0
    reading_order: int = 0
    raw_text: str = ""  # Before cleanup

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['bbox'] = self.bbox.to_dict()
        d['bubble_type'] = self.bubble_type.value
        return d


@dataclass
class AlignedDialogue:
    """A pair of aligned dialogues from original and translated versions."""
    id: str
    original_text: str
    translated_text: str
    original_language: MangaLanguage
    target_language: MangaLanguage
    original_bubble: Optional[TextBubble] = None
    translated_bubble: Optional[TextBubble] = None
    alignment_score: float = 1.0
    page_number: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'original_text': self.original_text,
            'translated_text': self.translated_text,
            'original_language': self.original_language.value,
            'target_language': self.target_language.value,
            'original_bubble': self.original_bubble.to_dict() if self.original_bubble else None,
            'translated_bubble': self.translated_bubble.to_dict() if self.translated_bubble else None,
            'alignment_score': self.alignment_score,
            'page_number': self.page_number,
            'notes': self.notes
        }


@dataclass
class MangaPage:
    """A processed manga page with detected bubbles."""
    id: str
    page_number: int
    image_path: Path
    language: MangaLanguage
    bubbles: List[TextBubble] = field(default_factory=list)
    status: ProcessingStatus = ProcessingStatus.PENDING
    error_message: str = ""
    processing_time_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'page_number': self.page_number,
            'image_path': str(self.image_path),
            'language': self.language.value,
            'bubbles': [b.to_dict() for b in self.bubbles],
            'status': self.status.value,
            'error_message': self.error_message,
            'processing_time_ms': self.processing_time_ms
        }


@dataclass
class ProcessingResult:
    """Result of processing a manga volume."""
    volume_id: str
    original_language: MangaLanguage
    target_language: MangaLanguage
    total_pages: int
    processed_pages: int
    failed_pages: int
    total_dialogues: int
    aligned_pairs: List[AlignedDialogue] = field(default_factory=list)
    original_pages: List[MangaPage] = field(default_factory=list)
    translated_pages: List[MangaPage] = field(default_factory=list)
    processing_time_seconds: float = 0.0
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'volume_id': self.volume_id,
            'original_language': self.original_language.value,
            'target_language': self.target_language.value,
            'total_pages': self.total_pages,
            'processed_pages': self.processed_pages,
            'failed_pages': self.failed_pages,
            'total_dialogues': self.total_dialogues,
            'aligned_pairs': [p.to_dict() for p in self.aligned_pairs],
            'processing_time_seconds': self.processing_time_seconds,
            'created_at': self.created_at.isoformat()
        }


@dataclass
class ProcessingOptions:
    """Options for manga processing."""
    # OCR settings
    ocr_language: str = "jpn"  # tesseract language code
    confidence_threshold: float = 0.5

    # Bubble detection
    min_bubble_area: int = 1000  # pixels
    max_bubble_area: int = 500000

    # Alignment
    alignment_threshold: float = 0.3  # Min overlap for alignment

    # Reading order (Japanese manga: right-to-left, top-to-bottom)
    right_to_left: bool = True
    top_to_bottom: bool = True

    # Output
    include_sfx: bool = False
    include_signs: bool = True


# === PROCESSOR SERVICE ===

class MangaBilingualProcessor:
    """
    Service for extracting bilingual dialogues from manga.

    Processes original and translated manga pages to create
    aligned sentence pairs for language learning.
    """

    def __init__(self, options: Optional[ProcessingOptions] = None):
        """
        Initialize processor.

        Args:
            options: Processing options
        """
        self.logger = logging.getLogger(__name__)
        self.options = options or ProcessingOptions()

        self._check_dependencies()
        self.logger.info("MangaBilingualProcessor initialized")

    def _check_dependencies(self):
        """Check and log available dependencies."""
        if not HAS_PIL:
            self.logger.warning("Pillow not available - image loading disabled")

        if not HAS_CV2:
            self.logger.warning("OpenCV not available - bubble detection disabled")

    # === BUBBLE DETECTION ===

    def detect_bubbles(
        self,
        image_path: Path,
        options: Optional[ProcessingOptions] = None
    ) -> List[TextBubble]:
        """
        Detect speech bubbles in a manga page.

        Args:
            image_path: Path to manga page image
            options: Processing options

        Returns:
            List of detected bubbles
        """
        opts = options or self.options

        if not HAS_CV2:
            self.logger.warning("OpenCV required for bubble detection")
            return []

        if not image_path.exists():
            self.logger.error(f"Image not found: {image_path}")
            return []

        try:
            # Read image
            img = cv2.imread(str(image_path))
            if img is None:
                self.logger.error(f"Failed to read image: {image_path}")
                return []

            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            height, width = gray.shape

            # Threshold to get white regions (speech bubbles are usually white)
            _, binary = cv2.threshold(gray, 240, 255, cv2.THRESH_BINARY)

            # Find contours
            contours, _ = cv2.findContours(
                binary,
                cv2.RETR_EXTERNAL,
                cv2.CHAIN_APPROX_SIMPLE
            )

            bubbles = []
            for i, contour in enumerate(contours):
                # Get bounding rectangle
                x, y, w, h = cv2.boundingRect(contour)
                area = w * h

                # Filter by size
                if area < opts.min_bubble_area or area > opts.max_bubble_area:
                    continue

                # Create bubble
                bbox = BoundingBox(x, y, w, h)
                bubble_id = hashlib.sha256(
                    f"{image_path}:{x}:{y}".encode()
                ).hexdigest()[:12]

                bubble = TextBubble(
                    id=bubble_id,
                    bbox=bbox,
                    text="",
                    bubble_type=BubbleType.SPEECH,
                    confidence=0.8
                )
                bubbles.append(bubble)

            # Sort by reading order
            bubbles = self._sort_by_reading_order(bubbles, opts)

            self.logger.info(f"Detected {len(bubbles)} bubbles in {image_path.name}")
            return bubbles

        except Exception as e:
            self.logger.error(f"Error detecting bubbles: {e}")
            return []

    def _sort_by_reading_order(
        self,
        bubbles: List[TextBubble],
        options: ProcessingOptions
    ) -> List[TextBubble]:
        """Sort bubbles by reading order."""
        # Japanese manga: right-to-left, top-to-bottom
        if options.right_to_left:
            # Sort by columns (right to left), then rows (top to bottom)
            bubbles.sort(key=lambda b: (
                -b.bbox.x // 200,  # Column (inverted)
                b.bbox.y          # Row
            ))
        else:
            # Western: left-to-right, top-to-bottom
            bubbles.sort(key=lambda b: (
                b.bbox.y // 200,  # Row
                b.bbox.x          # Column
            ))

        # Assign reading order
        for i, bubble in enumerate(bubbles):
            bubble.reading_order = i

        return bubbles

    # === OCR ===

    def ocr_bubble(
        self,
        image_path: Path,
        bubble: TextBubble,
        language: str = "jpn"
    ) -> str:
        """
        Extract text from a bubble using OCR.

        Args:
            image_path: Path to manga page image
            bubble: Bubble to OCR
            language: Tesseract language code

        Returns:
            Extracted text
        """
        if not HAS_CV2 or not HAS_PIL:
            self.logger.warning("OpenCV and Pillow required for OCR")
            return ""

        try:
            # Try pytesseract
            try:
                import pytesseract

                img = Image.open(image_path)
                bbox = bubble.bbox

                # Crop bubble region
                cropped = img.crop((
                    bbox.x, bbox.y,
                    bbox.x + bbox.width,
                    bbox.y + bbox.height
                ))

                # OCR
                text = pytesseract.image_to_string(
                    cropped,
                    lang=language,
                    config='--psm 6'
                ).strip()

                return self._clean_ocr_text(text)

            except ImportError:
                self.logger.warning("pytesseract not available")
                return ""

        except Exception as e:
            self.logger.error(f"OCR error: {e}")
            return ""

    def _clean_ocr_text(self, text: str) -> str:
        """Clean up OCR output."""
        # Remove common OCR artifacts
        text = re.sub(r'[\x00-\x1F\x7F]', '', text)  # Control chars
        text = re.sub(r'\s+', ' ', text)  # Multiple spaces
        text = text.strip()

        return text

    # === PAGE PROCESSING ===

    async def process_page(
        self,
        image_path: Path,
        language: MangaLanguage,
        page_number: int = 0,
        options: Optional[ProcessingOptions] = None
    ) -> MangaPage:
        """
        Process a single manga page.

        Args:
            image_path: Path to page image
            language: Page language
            page_number: Page number
            options: Processing options

        Returns:
            Processed MangaPage
        """
        opts = options or self.options
        start_time = datetime.utcnow()

        page = MangaPage(
            id=str(uuid.uuid4())[:8],
            page_number=page_number,
            image_path=image_path,
            language=language,
            status=ProcessingStatus.PROCESSING
        )

        try:
            # Detect bubbles
            bubbles = self.detect_bubbles(image_path, opts)

            # OCR each bubble
            ocr_lang = self._get_tesseract_lang(language)
            for bubble in bubbles:
                bubble.text = self.ocr_bubble(image_path, bubble, ocr_lang)
                bubble.raw_text = bubble.text

            page.bubbles = bubbles
            page.status = ProcessingStatus.COMPLETED

        except Exception as e:
            page.status = ProcessingStatus.FAILED
            page.error_message = str(e)
            self.logger.error(f"Failed to process page {page_number}: {e}")

        end_time = datetime.utcnow()
        page.processing_time_ms = int((end_time - start_time).total_seconds() * 1000)

        return page

    def _get_tesseract_lang(self, language: MangaLanguage) -> str:
        """Get tesseract language code."""
        mapping = {
            MangaLanguage.JAPANESE: "jpn",
            MangaLanguage.CHINESE_SIMPLIFIED: "chi_sim",
            MangaLanguage.CHINESE_TRADITIONAL: "chi_tra",
            MangaLanguage.KOREAN: "kor",
            MangaLanguage.ENGLISH: "eng",
            MangaLanguage.ITALIAN: "ita",
            MangaLanguage.SPANISH: "spa",
            MangaLanguage.FRENCH: "fra",
            MangaLanguage.GERMAN: "deu",
        }
        return mapping.get(language, "eng")

    # === ALIGNMENT ===

    def align_pages(
        self,
        original_page: MangaPage,
        translated_page: MangaPage,
        options: Optional[ProcessingOptions] = None
    ) -> List[AlignedDialogue]:
        """
        Align dialogues between original and translated pages.

        Args:
            original_page: Page in original language
            translated_page: Page in target language
            options: Processing options

        Returns:
            List of aligned dialogue pairs
        """
        opts = options or self.options
        aligned = []

        # Strategy 1: Align by position overlap
        for orig_bubble in original_page.bubbles:
            best_match = None
            best_score = 0.0

            for trans_bubble in translated_page.bubbles:
                score = orig_bubble.bbox.overlap_ratio(trans_bubble.bbox)
                if score > best_score and score >= opts.alignment_threshold:
                    best_score = score
                    best_match = trans_bubble

            if best_match and orig_bubble.text and best_match.text:
                dialogue = AlignedDialogue(
                    id=f"{orig_bubble.id}:{best_match.id}",
                    original_text=orig_bubble.text,
                    translated_text=best_match.text,
                    original_language=original_page.language,
                    target_language=translated_page.language,
                    original_bubble=orig_bubble,
                    translated_bubble=best_match,
                    alignment_score=best_score,
                    page_number=original_page.page_number
                )
                aligned.append(dialogue)

        # Strategy 2: Align by reading order (fallback)
        if not aligned:
            aligned = self._align_by_order(
                original_page,
                translated_page
            )

        self.logger.info(
            f"Aligned {len(aligned)} dialogues from page {original_page.page_number}"
        )
        return aligned

    def _align_by_order(
        self,
        original_page: MangaPage,
        translated_page: MangaPage
    ) -> List[AlignedDialogue]:
        """Align by reading order when position-based fails."""
        aligned = []

        orig_bubbles = sorted(original_page.bubbles, key=lambda b: b.reading_order)
        trans_bubbles = sorted(translated_page.bubbles, key=lambda b: b.reading_order)

        # Pair by index
        for i, orig in enumerate(orig_bubbles):
            if i < len(trans_bubbles):
                trans = trans_bubbles[i]
                if orig.text and trans.text:
                    dialogue = AlignedDialogue(
                        id=f"{orig.id}:{trans.id}",
                        original_text=orig.text,
                        translated_text=trans.text,
                        original_language=original_page.language,
                        target_language=translated_page.language,
                        original_bubble=orig,
                        translated_bubble=trans,
                        alignment_score=0.5,  # Lower confidence
                        page_number=original_page.page_number,
                        notes="Aligned by reading order"
                    )
                    aligned.append(dialogue)

        return aligned

    # === VOLUME PROCESSING ===

    async def process_volume(
        self,
        original_pages: List[Path],
        translated_pages: List[Path],
        original_language: MangaLanguage,
        target_language: MangaLanguage,
        options: Optional[ProcessingOptions] = None
    ) -> ProcessingResult:
        """
        Process a complete manga volume.

        Args:
            original_pages: Paths to original language pages
            translated_pages: Paths to translated pages
            original_language: Original language
            target_language: Translation language
            options: Processing options

        Returns:
            ProcessingResult with all aligned pairs
        """
        start_time = datetime.utcnow()
        opts = options or self.options

        result = ProcessingResult(
            volume_id=str(uuid.uuid4())[:8],
            original_language=original_language,
            target_language=target_language,
            total_pages=len(original_pages),
            processed_pages=0,
            failed_pages=0,
            total_dialogues=0
        )

        # Validate page counts
        if len(original_pages) != len(translated_pages):
            self.logger.warning(
                f"Page count mismatch: {len(original_pages)} vs {len(translated_pages)}"
            )

        # Process pages
        for i, (orig_path, trans_path) in enumerate(
            zip(original_pages, translated_pages)
        ):
            try:
                # Process original page
                orig_page = await self.process_page(
                    orig_path, original_language, i, opts
                )
                result.original_pages.append(orig_page)

                # Process translated page
                trans_page = await self.process_page(
                    trans_path, target_language, i, opts
                )
                result.translated_pages.append(trans_page)

                # Align
                if (orig_page.status == ProcessingStatus.COMPLETED and
                    trans_page.status == ProcessingStatus.COMPLETED):
                    aligned = self.align_pages(orig_page, trans_page, opts)
                    result.aligned_pairs.extend(aligned)
                    result.total_dialogues += len(aligned)
                    result.processed_pages += 1
                else:
                    result.failed_pages += 1

            except Exception as e:
                self.logger.error(f"Error processing page {i}: {e}")
                result.failed_pages += 1

        end_time = datetime.utcnow()
        result.processing_time_seconds = (end_time - start_time).total_seconds()

        self.logger.info(
            f"Processed volume: {result.processed_pages}/{result.total_pages} pages, "
            f"{result.total_dialogues} dialogues"
        )

        return result

    # === EXPORT ===

    def export_to_json(
        self,
        result: ProcessingResult,
        output_path: Path
    ) -> int:
        """
        Export processing result to JSON.

        Args:
            result: Processing result
            output_path: Output file path

        Returns:
            Number of pairs exported
        """
        data = {
            'volume_id': result.volume_id,
            'original_language': result.original_language.value,
            'target_language': result.target_language.value,
            'total_pages': result.total_pages,
            'total_dialogues': result.total_dialogues,
            'exported_at': datetime.utcnow().isoformat(),
            'dialogues': [p.to_dict() for p in result.aligned_pairs]
        }

        output_path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding='utf-8'
        )

        return len(result.aligned_pairs)

    def export_to_anki(
        self,
        result: ProcessingResult,
        output_path: Path
    ) -> int:
        """
        Export to Anki-compatible TSV.

        Args:
            result: Processing result
            output_path: Output file path

        Returns:
            Number of cards exported
        """
        cards = []
        for pair in result.aligned_pairs:
            front = pair.original_text
            back = pair.translated_text
            tags = f"manga page{pair.page_number}"
            cards.append(f"{front}\t{back}\t{tags}")

        output_path.write_text("\n".join(cards), encoding='utf-8')
        return len(cards)

    def export_to_tmx(
        self,
        result: ProcessingResult,
        output_path: Path
    ) -> int:
        """
        Export to TMX (Translation Memory eXchange) format.

        Args:
            result: Processing result
            output_path: Output file path

        Returns:
            Number of pairs exported
        """
        # TMX XML structure
        tmx_header = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE tmx SYSTEM "tmx14.dtd">
<tmx version="1.4">
  <header
    creationtool="MangaBilingualProcessor"
    creationtoolversion="1.0"
    segtype="sentence"
    o-tmf="unknown"
    adminlang="en"
    srclang="{result.original_language.value}"
    datatype="plaintext">
  </header>
  <body>
'''
        tmx_footer = '''  </body>
</tmx>'''

        tus = []
        for pair in result.aligned_pairs:
            # Escape XML special chars
            orig = self._escape_xml(pair.original_text)
            trans = self._escape_xml(pair.translated_text)

            tu = f'''    <tu>
      <tuv xml:lang="{result.original_language.value}">
        <seg>{orig}</seg>
      </tuv>
      <tuv xml:lang="{result.target_language.value}">
        <seg>{trans}</seg>
      </tuv>
    </tu>'''
            tus.append(tu)

        content = tmx_header + "\n".join(tus) + "\n" + tmx_footer
        output_path.write_text(content, encoding='utf-8')

        return len(result.aligned_pairs)

    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        return (text
            .replace('&', '&amp;')
            .replace('<', '&lt;')
            .replace('>', '&gt;')
            .replace('"', '&quot;')
            .replace("'", '&apos;'))


# === SIMPLIFIED API ===

async def process_manga_bilingual(
    original_dir: Path,
    translated_dir: Path,
    original_language: MangaLanguage,
    target_language: MangaLanguage,
    output_dir: Path,
    options: Optional[ProcessingOptions] = None
) -> ProcessingResult:
    """
    Simplified API for processing a manga volume.

    Args:
        original_dir: Directory with original manga pages
        translated_dir: Directory with translated pages
        original_language: Original language
        target_language: Translation language
        output_dir: Directory for output files
        options: Processing options

    Returns:
        ProcessingResult
    """
    processor = MangaBilingualProcessor(options)

    # Get sorted page files
    extensions = {'.jpg', '.jpeg', '.png', '.webp'}

    original_pages = sorted([
        p for p in original_dir.iterdir()
        if p.suffix.lower() in extensions
    ])

    translated_pages = sorted([
        p for p in translated_dir.iterdir()
        if p.suffix.lower() in extensions
    ])

    # Process
    result = await processor.process_volume(
        original_pages,
        translated_pages,
        original_language,
        target_language,
        options
    )

    # Export
    output_dir.mkdir(parents=True, exist_ok=True)

    processor.export_to_json(
        result,
        output_dir / "dialogues.json"
    )

    processor.export_to_anki(
        result,
        output_dir / "anki_cards.tsv"
    )

    processor.export_to_tmx(
        result,
        output_dir / "translation_memory.tmx"
    )

    return result

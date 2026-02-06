"""
🎓 AI_MODULE: PDF Processor Service
🎓 AI_DESCRIPTION: OCR e parsing PDF per estrazione contenuti arti marziali
🎓 AI_BUSINESS: Trasforma libri/documenti PDF in knowledge strutturata
🎓 AI_TEACHING: OCR (EasyOCR/Tesseract), PDF parsing, image extraction

🔄 ALTERNATIVE_VALUTATE:
- PyPDF2 solo testo: Scartato, non gestisce immagini
- Adobe API: Scartato, costo, privacy (cloud)
- Tesseract solo: Scartato, meno accurato per lingue asiatiche
- EasyOCR solo: Scartato, lento su grandi documenti

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Hybrid: EasyOCR per asiatico, Tesseract per europeo
- Local: Tutto processato localmente (privacy)
- Strutturato: Parsing capitoli/sezioni automatico
- Immagini: Estrazione figure tecniche

📊 METRICHE_SUCCESSO:
- OCR accuracy: > 95% (testo stampato)
- Processing speed: < 10s per pagina
- Image extraction: 100% figure rilevate
- Privacy: 100% locale

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: UploadService (file PDF)
- Downstream: Anonymizer, KnowledgeExtractor, MixGenerator
"""

import os
import io
import asyncio
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import logging
import hashlib
import tempfile

logger = logging.getLogger(__name__)


@dataclass
class PDFPage:
    """Singola pagina PDF."""
    page_number: int
    text: str
    images: List[bytes]
    confidence: float
    lang_detected: Optional[str] = None


@dataclass
class PDFDocument:
    """Documento PDF processato."""
    total_pages: int
    pages: List[PDFPage]
    metadata: Dict[str, Any]
    structure: Dict[str, Any]  # chapters, sections
    # 🔒 NO: filename, author, title originali


class PDFProcessor:
    """
    🔒 Servizio per processare PDF con privacy.

    PRIVACY BY DESIGN:
    - Mai salva filename originale
    - Mai espone metadata autore/titolo
    - OCR output anonimizzato
    - Processing completamente locale
    """

    # Lingue supportate per OCR
    SUPPORTED_LANGUAGES = {
        "it": ["it", "italian"],
        "en": ["en", "english"],
        "zh": ["ch_sim", "ch_tra", "chinese_cht"],
        "ja": ["ja", "japanese"],
        "ko": ["ko", "korean"],
        "es": ["es", "spanish"],
        "fr": ["fr", "french"],
        "de": ["de", "german"],
        "pt": ["pt", "portuguese"],
        "ar": ["ar", "arabic"],
        "ru": ["ru", "russian"],
    }

    def __init__(self, ocr_backend: str = "auto"):
        """
        Inizializza il processor.

        Args:
            ocr_backend: "easyocr", "tesseract", o "auto"
        """
        self.ocr_backend = ocr_backend
        self._easyocr_reader = None
        self._pytesseract_available = False
        self._pymupdf_available = False

        # Check disponibilità
        self._check_dependencies()

    def _check_dependencies(self):
        """Verifica dipendenze disponibili."""
        try:
            import pytesseract
            self._pytesseract_available = True
        except ImportError:
            logger.warning("⚠️ pytesseract non disponibile")

        try:
            import fitz  # PyMuPDF
            self._pymupdf_available = True
        except ImportError:
            logger.warning("⚠️ PyMuPDF (fitz) non disponibile")

    # =========================================================================
    # MAIN PROCESSING
    # =========================================================================

    async def process_pdf(
        self,
        file_path: str,
        languages: List[str] = ["it", "en"],
        extract_images: bool = True,
        output_dir: Optional[str] = None
    ) -> PDFDocument:
        """
        🔒 Processa PDF estraendo testo e immagini.

        Args:
            file_path: Path al file PDF
            languages: Lingue per OCR
            extract_images: Se estrarre immagini
            output_dir: Directory per output (temp se None)

        Returns:
            PDFDocument con contenuti estratti (anonimizzato)
        """
        logger.info(f"📄 Processing PDF con OCR ({languages})")

        if not self._pymupdf_available:
            raise ImportError("PyMuPDF (fitz) è richiesto per processare PDF")

        import fitz  # PyMuPDF

        # Apri documento
        doc = fitz.open(file_path)
        total_pages = len(doc)

        pages: List[PDFPage] = []
        all_images: List[Tuple[int, bytes]] = []

        # Setup output directory
        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="pdf_ocr_")

        # Processa ogni pagina
        for page_num in range(total_pages):
            page = doc[page_num]

            # Estrai testo diretto (se disponibile)
            direct_text = page.get_text()

            # Se poco testo, usa OCR
            if len(direct_text.strip()) < 50:
                # Renderizza pagina come immagine per OCR
                pix = page.get_pixmap(dpi=300)
                img_data = pix.tobytes("png")

                # OCR
                ocr_text, confidence, detected_lang = await self._ocr_image(
                    img_data, languages
                )
                text = ocr_text
            else:
                text = direct_text
                confidence = 0.99
                detected_lang = self._detect_primary_language(direct_text, languages)

            # Estrai immagini dalla pagina
            page_images: List[bytes] = []
            if extract_images:
                page_images = self._extract_page_images(page)
                all_images.extend([(page_num + 1, img) for img in page_images])

            pages.append(PDFPage(
                page_number=page_num + 1,
                text=text,
                images=page_images,
                confidence=confidence,
                lang_detected=detected_lang
            ))

        # Estrai struttura (capitoli/sezioni)
        structure = self._extract_structure(pages)

        # 🔒 Metadata anonimizzati (NO titolo, autore, filename)
        metadata = {
            "total_pages": total_pages,
            "total_images": len(all_images),
            "processed_at": datetime.utcnow().isoformat(),
            "languages": languages,
            "avg_confidence": sum(p.confidence for p in pages) / len(pages) if pages else 0,
            # 🔒 MAI: "title", "author", "filename", "creator"
        }

        doc.close()

        return PDFDocument(
            total_pages=total_pages,
            pages=pages,
            metadata=metadata,
            structure=structure
        )

    # =========================================================================
    # OCR
    # =========================================================================

    async def _ocr_image(
        self,
        image_data: bytes,
        languages: List[str]
    ) -> Tuple[str, float, Optional[str]]:
        """
        OCR su immagine.

        Returns:
            (testo, confidenza, lingua_rilevata)
        """
        # Decide backend
        if self.ocr_backend == "auto":
            # EasyOCR per asiatico, Tesseract per europeo
            asian_langs = {"zh", "ja", "ko"}
            if any(lang in asian_langs for lang in languages):
                backend = "easyocr"
            else:
                backend = "tesseract"
        else:
            backend = self.ocr_backend

        if backend == "easyocr":
            return await self._ocr_easyocr(image_data, languages)
        else:
            return await self._ocr_tesseract(image_data, languages)

    async def _ocr_easyocr(
        self,
        image_data: bytes,
        languages: List[str]
    ) -> Tuple[str, float, Optional[str]]:
        """OCR con EasyOCR (migliore per asiatico)."""
        try:
            import easyocr

            # Lazy init reader
            if self._easyocr_reader is None:
                # Map to EasyOCR language codes
                easyocr_langs = []
                for lang in languages:
                    if lang in self.SUPPORTED_LANGUAGES:
                        easyocr_langs.append(self.SUPPORTED_LANGUAGES[lang][0])
                    else:
                        easyocr_langs.append(lang)

                self._easyocr_reader = easyocr.Reader(
                    easyocr_langs,
                    gpu=False  # CPU per compatibilità
                )

            # Esegui OCR in executor (è blocking)
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._easyocr_reader.readtext(image_data)
            )

            # Combina risultati
            texts = []
            confidences = []
            for bbox, text, conf in result:
                texts.append(text)
                confidences.append(conf)

            full_text = "\n".join(texts)
            avg_confidence = sum(confidences) / len(confidences) if confidences else 0

            return full_text, avg_confidence, None

        except ImportError:
            logger.warning("⚠️ EasyOCR non disponibile, fallback a Tesseract")
            return await self._ocr_tesseract(image_data, languages)

    async def _ocr_tesseract(
        self,
        image_data: bytes,
        languages: List[str]
    ) -> Tuple[str, float, Optional[str]]:
        """OCR con Tesseract."""
        if not self._pytesseract_available:
            raise ImportError("pytesseract non disponibile")

        import pytesseract
        from PIL import Image

        # Converti bytes a PIL Image
        img = Image.open(io.BytesIO(image_data))

        # Map languages
        tess_langs = []
        for lang in languages:
            if lang in self.SUPPORTED_LANGUAGES:
                tess_langs.append(self.SUPPORTED_LANGUAGES[lang][1])
            else:
                tess_langs.append(lang)

        lang_str = "+".join(tess_langs)

        # Esegui OCR in executor
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: pytesseract.image_to_data(
                img,
                lang=lang_str,
                output_type=pytesseract.Output.DICT
            )
        )

        # Combina risultati
        texts = []
        confidences = []
        for i, text in enumerate(result["text"]):
            if text.strip():
                texts.append(text)
                conf = result["conf"][i]
                if conf > 0:
                    confidences.append(conf / 100.0)

        full_text = " ".join(texts)
        avg_confidence = sum(confidences) / len(confidences) if confidences else 0

        return full_text, avg_confidence, None

    # =========================================================================
    # IMAGE EXTRACTION
    # =========================================================================

    def _extract_page_images(self, page) -> List[bytes]:
        """Estrae immagini da una pagina PDF."""
        images = []

        try:
            image_list = page.get_images()

            for img_index, img in enumerate(image_list):
                xref = img[0]
                base_image = page.parent.extract_image(xref)

                if base_image:
                    img_bytes = base_image["image"]
                    # Filtra immagini troppo piccole (icone, etc.)
                    if len(img_bytes) > 5000:  # > 5KB
                        images.append(img_bytes)

        except Exception as e:
            logger.warning(f"⚠️ Errore estrazione immagini: {e}")

        return images

    # =========================================================================
    # STRUCTURE EXTRACTION
    # =========================================================================

    def _extract_structure(self, pages: List[PDFPage]) -> Dict[str, Any]:
        """
        Estrae struttura documento (capitoli, sezioni).

        🔒 PRIVACY: Non include titoli originali del libro.
        """
        structure = {
            "chapters": [],
            "sections": [],
            "toc_detected": False
        }

        chapter_pattern = r"(?:chapter|capitolo|章|第\d+章)\s*(\d+)?\s*[:\.]?\s*(.+?)(?:\n|$)"
        section_pattern = r"(?:section|sezione|節)\s*(\d+\.?\d*)?\s*[:\.]?\s*(.+?)(?:\n|$)"

        import re

        for page in pages:
            text = page.text

            # Trova capitoli
            for match in re.finditer(chapter_pattern, text, re.IGNORECASE):
                chapter_num = match.group(1) or str(len(structure["chapters"]) + 1)
                # 🔒 NON salvare il titolo del capitolo (potrebbe rivelare il libro)
                structure["chapters"].append({
                    "number": chapter_num,
                    "page": page.page_number,
                    # 🔒 NO: "title" - privacy
                })

            # Trova sezioni
            for match in re.finditer(section_pattern, text, re.IGNORECASE):
                section_num = match.group(1) or str(len(structure["sections"]) + 1)
                structure["sections"].append({
                    "number": section_num,
                    "page": page.page_number,
                    # 🔒 NO: "title" - privacy
                })

        structure["toc_detected"] = len(structure["chapters"]) > 0

        return structure

    # =========================================================================
    # UTILITY
    # =========================================================================

    def _detect_primary_language(
        self,
        text: str,
        hint_languages: List[str]
    ) -> Optional[str]:
        """Rileva lingua predominante nel testo."""
        # Euristica semplice basata su caratteri
        chinese_count = len([c for c in text if '\u4e00' <= c <= '\u9fff'])
        japanese_count = len([c for c in text if '\u3040' <= c <= '\u309f' or '\u30a0' <= c <= '\u30ff'])
        korean_count = len([c for c in text if '\uac00' <= c <= '\ud7af'])
        latin_count = len([c for c in text if c.isalpha() and c.isascii()])

        total = chinese_count + japanese_count + korean_count + latin_count
        if total == 0:
            return hint_languages[0] if hint_languages else "en"

        if chinese_count / total > 0.3:
            return "zh"
        if japanese_count / total > 0.1:
            return "ja"
        if korean_count / total > 0.1:
            return "ko"
        if "it" in hint_languages:
            return "it"
        return "en"

    def extract_to_dict(self, doc: PDFDocument) -> List[Dict[str, Any]]:
        """
        Converte PDFDocument in lista di dict per processing.

        🔒 Output anonimizzato.
        """
        items = []
        for page in doc.pages:
            if page.text.strip():
                items.append({
                    "content": page.text,
                    "type": "text",
                    "lang": page.lang_detected or "unknown",
                    "confidence": page.confidence,
                    # 🔒 MAI: "page", "source_file"
                })

            for img in page.images:
                items.append({
                    "content": img,
                    "type": "image",
                    # 🔒 MAI: "page", "source_file"
                })

        return items


# === FACTORY ===

def create_pdf_processor(ocr_backend: str = "auto") -> PDFProcessor:
    """Factory per creare PDFProcessor."""
    return PDFProcessor(ocr_backend=ocr_backend)

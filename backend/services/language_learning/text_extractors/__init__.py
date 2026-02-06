"""
================================================================================
AI_MODULE: Text Extractors Package
AI_VERSION: 1.0.0
AI_DESCRIPTION: Estrattori di testo da vari formati (PDF, EPUB, OCR)
AI_BUSINESS: Supporto multi-formato per estrazione grammatica
AI_TEACHING: PyMuPDF, ebooklib, Tesseract OCR, preprocessing immagini

PRIVACY:
- Text is extracted for grammar rule detection ONLY
- Original content is NEVER stored
- Source references are NEVER saved
================================================================================
"""

from .pdf_extractor import PDFExtractor
from .epub_extractor import EPUBExtractor
from .ocr_extractor import OCRExtractor

__all__ = [
    "PDFExtractor",
    "EPUBExtractor",
    "OCRExtractor",
]

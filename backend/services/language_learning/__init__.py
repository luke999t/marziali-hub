"""
================================================================================
AI_MODULE: Language Learning Services Package
AI_VERSION: 1.0.0
AI_DESCRIPTION: Suite di servizi per estrazione e gestione regole grammaticali
AI_BUSINESS: Apprendimento linguistico AI-first con fonti multiple
AI_TEACHING: Estrazione testo, NLP, anonimizzazione, merge intelligente
AI_DEPENDENCIES: PyMuPDF, ebooklib, pytesseract, pillow
AI_CREATED: 2026-02-05

LEGAL PRINCIPLE:
Grammar rules are FACTS, not copyrightable content.
We extract → Reformulate → Mix → Forget source.
NO source references are EVER stored.
================================================================================
"""

from .grammar_extractor import GrammarExtractor, ExtractionResult
from .rule_normalizer import RuleNormalizer, NormalizedRule
from .grammar_merger import GrammarMergerService

__all__ = [
    "GrammarExtractor",
    "ExtractionResult",
    "RuleNormalizer",
    "NormalizedRule",
    "GrammarMergerService",
]

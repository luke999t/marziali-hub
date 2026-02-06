"""
================================================================================
AI_MODULE: Ads Module Exports
AI_DESCRIPTION: Export centralizzato servizi ads e pause ads
AI_BUSINESS: Monetizzazione tramite advertising per tier FREE e HYBRID
AI_TEACHING: Python module exports pattern

ALTERNATIVE_VALUTATE:
- Import star (*): Scartata perché namespace pollution
- Direct imports in each file: Scartata perché duplicazione codice

PERCHE_QUESTA_SOLUZIONE:
- Export espliciti migliorano IDE autocompletion
- Single source of truth per imports
- Facilita refactoring futuro
================================================================================
"""

from .ads_service import AdsService
from .pause_ad_service import PauseAdService

__all__ = [
    "AdsService",
    "PauseAdService",
]

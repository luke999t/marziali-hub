"""
================================================================================
AI_MODULE: Blockchain Module Exports
AI_DESCRIPTION: Export centralizzato servizi blockchain
AI_BUSINESS: Trasparenza, audit trail, certificazione revenue su Polygon
AI_TEACHING: Python module exports pattern per blockchain services

ALTERNATIVE_VALUTATE:
- Import star (*): Scartata perché namespace pollution
- Separate imports: Scartata perché duplicazione

PERCHE_QUESTA_SOLUZIONE:
- Export espliciti per IDE support
- Single source of truth
- Facilita manutenzione
================================================================================
"""

from .blockchain_service import BlockchainService

__all__ = [
    "BlockchainService",
]

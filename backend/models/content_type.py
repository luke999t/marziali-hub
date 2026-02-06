# POSIZIONE: backend/models/content_type.py
"""
🎓 AI_MODULE: ContentType Enum
🎓 AI_DESCRIPTION: Enum per classificare tipi di contenuto video nelle arti marziali
🎓 AI_BUSINESS: Permette organizzazione gerarchica contenuti didattici, filtri per tipo, workflow specifici per categoria
🎓 AI_TEACHING: Enum Python con str mixin per serializzazione JSON nativa e validazione automatica

🔄 ALTERNATIVE_VALUTATE:
- String libere nel DB: Scartato perché nessuna validazione, typo possibili, no autocompletamento
- Integer codes (1,2,3): Scartato perché non leggibile, richiede mapping manuale, error-prone
- Lookup table separata: Scartato perché overhead query, complessità non necessaria per 5 valori fissi

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Validazione automatica: SQLAlchemy e Pydantic validano il valore a livello DB e API
- Serializzazione JSON nativa: str mixin permette serializzazione senza encoder custom
- Type safety: IDE autocompletamento, errori a compile-time non runtime
- Documentazione inline: Ogni valore ha docstring che spiega il business case
- Estensibilità: Aggiungere nuovo tipo = 1 riga di codice

📊 BUSINESS_IMPACT:
- Organizzazione: Permette filtering "mostrami solo le forme complete"
- Workflow: Ogni tipo ha pipeline diversa (forma → fusion, spiegazione → solo testo)
- UX: Dropdown popolati automaticamente, validazione client-side
- Analytics: Report per tipo di contenuto

⚖️ COMPLIANCE_&_CONSTRAINTS:
- Regulatory: Nessuno specifico
- Technical: Enum deve essere compatibile PostgreSQL e SQLite (test)
- Business: I 5 tipi coprono 95% dei contenuti arti marziali

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: Nessuno (enum standalone)
- Downstream: VideoSection, IngestProject, API filtering
- Data: PostgreSQL ENUM type o VARCHAR con CHECK constraint
"""

from enum import Enum


class ContentType(str, Enum):
    """
    Tipi di contenuto video per classificazione nelle arti marziali.

    🎯 BUSINESS WORKFLOW PER TIPO:

    - FORMA_COMPLETA: Video di sequenza intera (es. "81 posizioni Tai Chi")
      → Pipeline: Multi-video fusion → DTW alignment → Avatar 3D completo
      → Output: Skeleton animato dell'intera forma

    - MOVIMENTO_SINGOLO: Un movimento isolato dalla forma (es. "Nuvola che spinge")
      → Pipeline: Fusion su movimento specifico → Loop animation
      → Output: Skeleton del singolo movimento, ripetibile

    - TECNICA_A_DUE: Applicazione contro avversario (es. "Chin Na polso")
      → Pipeline: Dual skeleton extraction → 2 avatar simultanei
      → Output: Coppia di skeleton sincronizzati

    - SPIEGAZIONE: Maestro che parla/spiega teoria (es. "Principi del Chen style")
      → Pipeline: Solo transcription + translation → Knowledge base
      → Output: Testo tradotto, NO skeleton

    - VARIANTE: Stesso movimento, scuola/stile diverso (es. "Nuvola - Yang vs Chen")
      → Pipeline: Comparazione side-by-side → Diff visualization
      → Output: 2+ skeleton con highlight differenze

    📊 DISTRIBUZIONE TIPICA CONTENUTI:
    - FORMA_COMPLETA: 20%
    - MOVIMENTO_SINGOLO: 40%
    - TECNICA_A_DUE: 15%
    - SPIEGAZIONE: 20%
    - VARIANTE: 5%
    """

    FORMA_COMPLETA = "forma_completa"
    """Sequenza completa dall'inizio alla fine (es. kata, forma tai chi)"""

    MOVIMENTO_SINGOLO = "movimento_singolo"
    """Un singolo movimento isolato dalla forma"""

    TECNICA_A_DUE = "tecnica_a_due"
    """Applicazione marziale con due persone (tori/uke, attaccante/difensore)"""

    SPIEGAZIONE = "spiegazione"
    """Contenuto parlato/teoria senza dimostrazione tecnica"""

    VARIANTE = "variante"
    """Stesso movimento eseguito in stile/scuola diversa per comparazione"""

    @classmethod
    def get_choices(cls) -> list[dict]:
        """
        Ritorna lista di scelte per dropdown UI.

        Returns:
            [{"value": "forma_completa", "label": "Forma Completa"}, ...]
        """
        return [
            {"value": ct.value, "label": ct.name.replace("_", " ").title()}
            for ct in cls
        ]

    @classmethod
    def requires_skeleton(cls, content_type: "ContentType") -> bool:
        """
        Indica se il tipo richiede estrazione skeleton.

        SPIEGAZIONE non richiede skeleton (solo testo).
        Tutti gli altri tipi richiedono skeleton extraction.

        Args:
            content_type: Tipo di contenuto

        Returns:
            True se richiede skeleton extraction
        """
        return content_type != cls.SPIEGAZIONE

    @classmethod
    def requires_dual_skeleton(cls, content_type: "ContentType") -> bool:
        """
        Indica se il tipo richiede due skeleton simultanei.

        Solo TECNICA_A_DUE richiede tracking di 2 persone.

        Args:
            content_type: Tipo di contenuto

        Returns:
            True se richiede dual skeleton extraction
        """
        return content_type == cls.TECNICA_A_DUE

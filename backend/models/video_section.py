# POSIZIONE: backend/models/video_section.py
"""
🎓 AI_MODULE: VideoSection Model
🎓 AI_DESCRIPTION: Modello per taggare sezioni temporali di un video con classificazione contenuto
🎓 AI_BUSINESS: Un video di 60min può contenere 5 forme + 3 spiegazioni + 2 tecniche a due
🎓 AI_TEACHING: Relazione 1:N con Video, timestamp per segmentazione, validazione business rules

🔄 ALTERNATIVE_VALUTATE:
- Un solo content_type per video: Scartato perché un video contiene multipli contenuti
- JSON array in campo Video: Scartato perché non queryable, no FK, no validazione
- Tabella pivot Video-ContentType: Scartato perché mancano timestamp start/end

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Query efficienti: "SELECT * FROM video_sections WHERE content_type = 'movimento_singolo'"
- Timestamp precisi: Ogni sezione ha start_time e end_time per segmentazione
- Relazioni: FK a Video, possibile FK a IngestProject per collegamento
- Validazione: end_time > start_time, no overlap (opzionale)
- Metadata ricco: name, style, notes per ogni sezione

📊 BUSINESS_IMPACT:
- Ricerca: "Trova tutti i movimenti singoli di Tai Chi Chen"
- Playlist: Genera automaticamente playlist per tipo
- Avatar: Estrai skeleton solo per la sezione specifica
- Analytics: Tempo totale per tipo di contenuto

⚖️ COMPLIANCE_&_CONSTRAINTS:
- Regulatory: Nessuno specifico
- Technical: Timestamp in secondi (float) per precisione sub-secondo
- Business: Una sezione non può essere più lunga del video parent

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: Video model (FK), ContentType enum
- Downstream: API content_classification, skeleton extraction pipeline
- Data: PostgreSQL con index su content_type e video_id

🧪 TESTING_STRATEGY:
- Unit tests: Validazione timestamp, enum values
- Integration tests: CRUD completo via API reale
- Performance tests: Query con 10k+ sezioni

📈 MONITORING_&_OBSERVABILITY:
- Key metrics: Sezioni per video, distribuzione tipi
- Alerts: Sezioni con duration < 1s (possibile errore)
- Logging: Creazione/modifica sezioni per audit
"""

from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    ForeignKey,
    DateTime,
    Index,
    CheckConstraint
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ENUM as PG_ENUM
from datetime import datetime
import enum

from core.database import Base
from models import GUID
from models.content_type import ContentType


class VideoSection(Base):
    """
    Sezione temporale di un video con classificazione contenuto.

    📊 ESEMPIO D'USO:
    Video "lezione_tai_chi_01.mp4" (durata: 3600 secondi = 1 ora) contiene:

    | id | start_time | end_time | content_type      | name                    | style         |
    |----|------------|----------|-------------------|-------------------------|---------------|
    | 1  | 0.0        | 330.0    | forma_completa    | 81 posizioni - Parte 1  | tai_chi_chen  |
    | 2  | 330.0      | 360.0    | spiegazione       | Principi respirazione   | tai_chi_chen  |
    | 3  | 360.0      | 390.0    | movimento_singolo | Nuvola che spinge       | tai_chi_chen  |
    | 4  | 390.0      | 450.0    | tecnica_a_due     | Applicazione nuvola     | tai_chi_chen  |
    | 5  | 450.0      | 480.0    | variante          | Nuvola - Yang vs Chen   | tai_chi       |

    🎯 BUSINESS RULES:
    1. end_time > start_time (sempre)
    2. start_time >= 0 (no tempi negativi)
    3. Sezioni possono sovrapporsi (es. spiegazione durante movimento)
    4. name è obbligatorio (identifica il contenuto)
    """

    __tablename__ = "video_sections"

    # === IDENTITY ===
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)

    # === FOREIGN KEYS ===
    # Video parent - usa GUID per compatibilità con Video model esistente
    video_id = Column(
        GUID(),
        ForeignKey("videos.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID del video parent"
    )

    # Opzionale: collegamento a IngestProject per tracciamento
    project_id = Column(
        GUID(),
        ForeignKey("ingest_projects.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="ID progetto ingest (opzionale)"
    )

    # === CONTENT CLASSIFICATION ===
    # Usa String invece di Enum per compatibilità cross-database
    content_type = Column(
        String(50),
        nullable=False,
        index=True,
        comment="Tipo contenuto: forma_completa, movimento_singolo, tecnica_a_due, spiegazione, variante"
    )

    # === TIMESTAMPS (in secondi) ===
    start_time = Column(
        Float,
        nullable=False,
        default=0.0,
        comment="Inizio sezione in secondi dall'inizio video"
    )

    end_time = Column(
        Float,
        nullable=False,
        comment="Fine sezione in secondi dall'inizio video"
    )

    # === METADATA ===
    name = Column(
        String(255),
        nullable=False,
        comment="Nome identificativo della sezione (es. 'Nuvola che spinge')"
    )

    style = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Stile/scuola (es. 'tai_chi_chen', 'wing_chun', 'karate_shotokan')"
    )

    notes = Column(
        Text,
        nullable=True,
        comment="Note aggiuntive libere"
    )

    # === PROCESSING STATUS ===
    # Per tracking estrazione skeleton
    skeleton_extracted = Column(
        Integer,
        default=0,
        nullable=False,
        comment="0=non estratto, 1=in corso, 2=completato, -1=errore"
    )

    skeleton_path = Column(
        String(500),
        nullable=True,
        comment="Path file skeleton estratto (.npy o .json)"
    )

    # === AUDIT ===
    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    updated_at = Column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False
    )

    created_by = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        comment="User che ha creato la sezione"
    )

    # === RELATIONSHIPS ===
    video = relationship(
        "Video",
        back_populates="sections",
        lazy="joined"
    )

    project = relationship(
        "IngestProject",
        back_populates="sections",
        lazy="select"
    )

    creator = relationship(
        "User",
        foreign_keys=[created_by],
        lazy="select"
    )

    # === CONSTRAINTS & INDEXES ===
    __table_args__ = (
        # Constraint: end_time deve essere > start_time
        CheckConstraint(
            "end_time > start_time",
            name="ck_video_sections_end_after_start"
        ),
        # Constraint: start_time non negativo
        CheckConstraint(
            "start_time >= 0",
            name="ck_video_sections_start_non_negative"
        ),
        # Constraint: content_type deve essere uno dei valori validi
        CheckConstraint(
            "content_type IN ('forma_completa', 'movimento_singolo', 'tecnica_a_due', 'spiegazione', 'variante')",
            name="ck_video_sections_valid_content_type"
        ),
        # Index composito per query comuni
        Index("ix_video_sections_video_type", "video_id", "content_type"),
        Index("ix_video_sections_style_type", "style", "content_type"),
        Index("ix_video_sections_project", "project_id", "content_type"),
    )

    # === PROPERTIES ===
    @property
    def duration(self) -> float:
        """Durata della sezione in secondi."""
        return self.end_time - self.start_time

    @property
    def duration_formatted(self) -> str:
        """Durata formattata come MM:SS."""
        total_seconds = int(self.duration)
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        return f"{minutes:02d}:{seconds:02d}"

    @property
    def time_range_formatted(self) -> str:
        """Range temporale formattato come MM:SS - MM:SS."""
        start_min = int(self.start_time) // 60
        start_sec = int(self.start_time) % 60
        end_min = int(self.end_time) // 60
        end_sec = int(self.end_time) % 60
        return f"{start_min:02d}:{start_sec:02d} - {end_min:02d}:{end_sec:02d}"

    @property
    def content_type_enum(self) -> ContentType:
        """Ritorna il ContentType come enum."""
        return ContentType(self.content_type)

    @property
    def requires_skeleton(self) -> bool:
        """Indica se questa sezione richiede estrazione skeleton."""
        return ContentType.requires_skeleton(self.content_type_enum)

    # === METHODS ===
    def __repr__(self) -> str:
        return (
            f"<VideoSection {self.id}: {self.name} "
            f"({self.content_type}) {self.time_range_formatted}>"
        )

    def to_dict(self) -> dict:
        """Serializza la sezione come dizionario."""
        return {
            "id": self.id,
            "video_id": str(self.video_id) if self.video_id else None,
            "project_id": str(self.project_id) if self.project_id else None,
            "content_type": self.content_type,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "name": self.name,
            "style": self.style,
            "notes": self.notes,
            "skeleton_extracted": self.skeleton_extracted,
            "skeleton_path": self.skeleton_path,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

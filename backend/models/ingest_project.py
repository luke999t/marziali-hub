"""
🎓 AI_MODULE: Ingest Project Models (Privacy by Design)
🎓 AI_DESCRIPTION: SQLAlchemy models per progetti ingest con FORGETTING BY DESIGN
🎓 AI_BUSINESS: Gestione lifecycle progetti con anonimizzazione automatica e zero tracking fonti
🎓 AI_TEACHING: Privacy-first data models + JSON columns + cascade patterns

🔄 ALTERNATIVE_VALUTATE:
- NoSQL/MongoDB: Scartato, serve integrazione con altri modelli PostgreSQL
- File-based (JSON): Scartato, non supporta query complesse e concurrency
- SQLite separato: Scartato, duplicazione e sync issues
- Full source tracking: SCARTATO PER PRIVACY - nessuna fonte deve essere tracciabile

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Privacy: FORGETTING BY DESIGN - fonti non tracciabili nel mix finale
- Tecnico: Integrazione nativa con modelli esistenti, ACID transactions
- Business: Query complesse su progetti, audit trail SENZA tracking fonti
- Scalabilita: PostgreSQL pool esistente, JOIN efficienti

📊 METRICHE_SUCCESSO:
- Query tempo: < 50ms per lista progetti
- Insert batch: < 100ms per 100 assets
- Integrity: 100% FK constraints rispettate
- Privacy: 0% leak fonti nel mix finale

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: User model per ownership
- Downstream: Anonymizer, MixGenerator, ProjectManager
"""

from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, Index, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, ArrayType, JSONBType


# === ENUMS ===

class BatchStatus(str, enum.Enum):
    """Status di un batch di upload."""
    PENDING = "pending"           # Upload completato, processing non iniziato
    PROCESSING = "processing"     # Pipeline in esecuzione
    PROCESSED = "processed"       # Completato con successo
    FAILED = "failed"             # Fallito (vedi error_message)
    PARTIAL = "partial"           # Alcuni asset falliti


class AssetType(str, enum.Enum):
    """
    Tipo di asset caricato.

    🔒 PRIVACY NOTE: Il tipo NON viene propagato al mix finale.
    """
    VIDEO = "video"
    AUDIO = "audio"
    IMAGE = "image"
    PDF = "pdf"
    TEXT = "text"                 # Testo manuale incollato
    AI_PASTE = "ai_paste"         # Output da altre AI (Claude/GPT)
    SKELETON = "skeleton"
    EXTERNAL = "external"         # Import da webhook/API


class InputChannel(str, enum.Enum):
    """
    Canale di input per asset.

    🔒 PRIVACY: Questo campo viene CANCELLATO dopo il mix.
    Serve solo per processing temporaneo.
    """
    VIDEO_UPLOAD = "video_upload"
    PDF_UPLOAD = "pdf_upload"
    MANUAL_TEXT = "manual_text"
    AI_PASTE = "ai_paste"
    EXTERNAL_API = "external_api"


class AssetStatus(str, enum.Enum):
    """Status processing singolo asset."""
    UPLOADED = "uploaded"         # File salvato
    QUEUED = "queued"             # In coda per processing
    PROCESSING = "processing"     # Pipeline in esecuzione
    COMPLETED = "completed"       # Processing completato
    FAILED = "failed"             # Processing fallito
    DUPLICATE = "duplicate"       # Duplicato (hash match)
    ANONYMIZED = "anonymized"     # Anonimizzato e pronto per mix


# === MODELS ===

class IngestProject(Base):
    """
    Progetto contenitore per batch di video/media.

    CORE ENTITY: Raggruppa tutti i batch e mix di un progetto specifico
    (es. "Tai Chi Chen", "Karate Shotokan Kata", etc.)
    """
    __tablename__ = "ingest_projects"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)

    # === CONFIGURATION ===
    target_languages = Column(ArrayType(String), default=["it", "en"])
    storage_path = Column(String(500), nullable=False, unique=True)

    # === CONTENT CLASSIFICATION ===
    # Tipo principale di contenuto del progetto
    content_type = Column(
        String(50),
        nullable=True,
        index=True,
        comment="Tipo contenuto: forma_completa, movimento_singolo, tecnica_a_due, spiegazione, variante"
    )
    # Stile/scuola marziale
    style = Column(
        String(100),
        nullable=True,
        index=True,
        comment="Stile marziale: tai_chi_chen, wing_chun, karate_shotokan, etc."
    )

    # === OWNERSHIP ===
    created_by = Column(GUID(), ForeignKey("users.id"), nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # === STATUS ===
    is_active = Column(Boolean, default=True, index=True)
    current_mix_version = Column(String(20), nullable=True)  # "1.0", "1.1", etc.

    # === RELATIONSHIPS ===
    batches = relationship(
        "IngestBatch",
        back_populates="project",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    mix_versions = relationship(
        "IngestMixVersion",
        back_populates="project",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )
    sections = relationship(
        "VideoSection",
        back_populates="project",
        lazy="dynamic"
    )

    # === INDEXES ===
    __table_args__ = (
        Index("ix_ingest_projects_active_updated", "is_active", "updated_at"),
        Index("ix_ingest_projects_content_style", "content_type", "style"),
    )

    def __repr__(self):
        return f"<IngestProject {self.id}: {self.name}>"


class IngestBatch(Base):
    """
    Batch di upload raggruppato per data.

    GROUPING: Tutti i file caricati lo stesso giorno appartengono allo stesso batch
    PATH: {project.storage_path}/temp/batch_{batch_date}/
    """
    __tablename__ = "ingest_batches"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id = Column(
        GUID(),
        ForeignKey("ingest_projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    batch_date = Column(String(10), nullable=False)  # "2025-01-15" (YYYY-MM-DD)

    # === COUNTS (per tipo asset) ===
    video_count = Column(Integer, default=0)
    audio_count = Column(Integer, default=0)
    image_count = Column(Integer, default=0)
    pdf_count = Column(Integer, default=0)
    text_count = Column(Integer, default=0)        # Testi manuali
    ai_paste_count = Column(Integer, default=0)    # Paste da AI
    external_count = Column(Integer, default=0)    # Import esterni
    skeleton_count = Column(Integer, default=0)
    total_size_bytes = Column(BigInteger, default=0)

    # 🔒 PRIVACY: items_count usato in meta.json invece di source_files
    items_count = Column(Integer, default=0)       # Totale items (non file names)

    # === STATUS ===
    status = Column(String(50), default=BatchStatus.PENDING.value, index=True)
    progress_percentage = Column(Integer, default=0)  # 0-100
    current_step = Column(String(100), nullable=True)  # "skeleton_extraction", "translation", etc.
    error_message = Column(Text, nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    processed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    project = relationship("IngestProject", back_populates="batches")
    assets = relationship(
        "IngestAsset",
        back_populates="batch",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )

    # === INDEXES ===
    __table_args__ = (
        Index("ix_ingest_batches_project_date", "project_id", "batch_date"),
        # Note: status index already defined inline with index=True on line 180
    )

    def __repr__(self):
        return f"<IngestBatch {self.batch_date} ({self.status})>"


class IngestAsset(Base):
    """
    Singolo asset (video, audio, etc.) in un batch.

    🔒 PRIVACY BY DESIGN:
    - original_filename NON viene salvato (privacy)
    - input_channel viene cancellato dopo mix
    - file_hash usato solo per dedup, non per tracking

    DEDUPLICATION: file_hash (SHA256) per evitare duplicati
    STORAGE: {batch.path}/{asset_type}_originali/{filename}
    """
    __tablename__ = "ingest_assets"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    batch_id = Column(
        GUID(),
        ForeignKey("ingest_batches.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # === FILE INFO (🔒 NO original_filename per privacy) ===
    filename = Column(String(255), nullable=False)  # UUID-based, non originale
    # 🔒 RIMOSSO: original_filename - violazione privacy
    asset_type = Column(String(50), nullable=False, index=True)  # AssetType enum value
    input_channel = Column(String(50), nullable=True)  # InputChannel enum, cancellato dopo mix
    file_hash = Column(String(64), nullable=False, index=True)   # SHA256 hex (solo per dedup)
    file_size = Column(BigInteger, nullable=False)
    mime_type = Column(String(100), nullable=True)

    # === STORAGE ===
    storage_path = Column(String(500), nullable=False)

    # === STATUS ===
    status = Column(String(50), default=AssetStatus.UPLOADED.value, index=True)
    error_message = Column(Text, nullable=True)

    # === PROCESSING RESULTS ===
    processing_results = Column(JSONBType, nullable=True, default=dict)
    # Example structure:
    # {
    #     "skeleton": {"path": "...", "frames": 1200, "confidence": 0.92},
    #     "transcription": {"path": "...", "duration": 120.5, "language": "ja"},
    #     "translation": {"it": "...", "en": "..."},
    #     "knowledge": {"chunks": 15, "path": "..."},
    #     "techniques": [{"name": "mae-geri", "start": 10.5, "end": 12.3}]
    # }

    # === METADATA ===
    duration_seconds = Column(Integer, nullable=True)  # For video/audio
    width = Column(Integer, nullable=True)             # For video/image
    height = Column(Integer, nullable=True)            # For video/image
    fps = Column(Integer, nullable=True)               # For video

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow)
    processed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    batch = relationship("IngestBatch", back_populates="assets")

    # === INDEXES ===
    __table_args__ = (
        Index("ix_ingest_assets_batch_type", "batch_id", "asset_type"),
        Index("ix_ingest_assets_hash", "file_hash"),
    )

    def __repr__(self):
        return f"<IngestAsset {self.filename} ({self.asset_type})>"


class IngestMixVersion(Base):
    """
    Versione mix blindata.

    🔒 PRIVACY BY DESIGN:
    - NO source_batches - le fonti NON devono essere tracciabili
    - NO source_files - mai lista file originali
    - Solo contatori aggregati (total_items)

    VERSIONING:
    - Prima versione: v1.0
    - Incrementale: v1.1, v1.2, ...
    - Full rebuild: v2.0, v3.0, ...

    STORAGE: {project.storage_path}/mix/v{version}/
    SYMLINK: {project.storage_path}/mix/current -> v{version}
    """
    __tablename__ = "ingest_mix_versions"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id = Column(
        GUID(),
        ForeignKey("ingest_projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    version = Column(String(20), nullable=False)  # "1.0", "1.1", "2.0"

    # === STORAGE ===
    storage_path = Column(String(500), nullable=False, unique=True)

    # === 🔒 PRIVACY: NO source tracking ===
    # RIMOSSO: source_batches - violazione privacy
    # Solo contatori aggregati, MAI liste di fonti

    is_incremental = Column(Boolean, default=True)  # False if full rebuild
    previous_version = Column(String(20), nullable=True)  # For incremental

    # === STATS (🔒 solo contatori, no nomi) ===
    total_items = Column(Integer, default=0)       # Items aggregati (non file names)
    total_skeletons = Column(Integer, default=0)
    total_transcriptions = Column(Integer, default=0)
    total_knowledge_chunks = Column(Integer, default=0)
    total_subtitles = Column(Integer, default=0)
    total_vocabulary_terms = Column(Integer, default=0)
    total_size_bytes = Column(BigInteger, default=0)

    # === MERGE DETAILS (🔒 no file names) ===
    merge_stats = Column(JSONBType, nullable=True, default=dict)
    # Example:
    # {
    #     "new_skeletons": 50,
    #     "merged_items": 200,
    #     "processing_time_seconds": 125.5
    #     // 🔒 MAI: "source_files", "batch_contents"
    # }

    # === OWNERSHIP ===
    created_by = Column(GUID(), ForeignKey("users.id"), nullable=True)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow)

    # === RELATIONSHIPS ===
    project = relationship("IngestProject", back_populates="mix_versions")

    # === INDEXES ===
    __table_args__ = (
        Index("ix_ingest_mix_project_version", "project_id", "version"),
    )

    def __repr__(self):
        return f"<IngestMixVersion v{self.version} ({self.total_items} items)>"

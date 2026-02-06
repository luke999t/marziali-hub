"""
🎓 AI_MODULE: Ingest Pydantic Schemas (Privacy by Design)
🎓 AI_DESCRIPTION: Request/Response schemas per progetti ingest con FORGETTING BY DESIGN
🎓 AI_BUSINESS: Type safety per API ingest con privacy garantita - zero tracking fonti
🎓 AI_TEACHING: Pydantic v2 models con privacy-first validation

🔄 ALTERNATIVE_VALUTATE:
- Dataclasses: Scartato, meno features di validazione
- TypedDict: Scartato, no runtime validation
- Marshmallow: Scartato, Pydantic ha integrazione nativa FastAPI
- Full source tracking: SCARTATO per PRIVACY - nessuna fonte tracciabile

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Privacy: NO original_filename, NO source_batches nel response
- Tecnico: Validation automatica, OpenAPI docs generation
- Business: Error messages chiari per frontend
- DX: Type hints complete per IDE autocomplete

📊 METRICHE_SUCCESSO:
- Privacy leak: 0% (nessun nome file/fonte nei response)
- Validation coverage: 100% campi critici
- API response time: < 50ms

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: models/ingest_project.py
- Downstream: Router API, Frontend services
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator, ConfigDict
from typing import Optional, List, Union, Dict, Any
from datetime import datetime
from enum import Enum
from uuid import UUID


# === ENUMS ===

class BatchStatusEnum(str, Enum):
    """Status di un batch."""
    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    PARTIAL = "partial"


class AssetTypeEnum(str, Enum):
    """
    Tipo di asset.

    🔒 PRIVACY: Il tipo NON viene propagato al mix finale.
    """
    VIDEO = "video"
    AUDIO = "audio"
    IMAGE = "image"
    PDF = "pdf"
    TEXT = "text"           # Testo manuale
    AI_PASTE = "ai_paste"   # Output da altre AI
    SKELETON = "skeleton"
    EXTERNAL = "external"   # Import da webhook


class InputChannelEnum(str, Enum):
    """
    Canale di input per asset.

    🔒 PRIVACY: Questo campo viene CANCELLATO dopo il mix.
    """
    VIDEO_UPLOAD = "video_upload"
    PDF_UPLOAD = "pdf_upload"
    MANUAL_TEXT = "manual_text"
    AI_PASTE = "ai_paste"
    EXTERNAL_API = "external_api"


class ProcessingPresetEnum(str, Enum):
    """Preset di processing."""
    STANDARD = "standard"     # Knowledge + Techniques + Skeleton
    KNOWLEDGE = "knowledge"   # Solo estrazione conoscenza
    SKELETON = "skeleton"     # Solo estrazione skeleton
    VOICE = "voice"           # Voice cloning
    BLENDER = "blender"       # Export per Blender
    STAGE = "stage"           # Staging per review


# === PROJECT SCHEMAS ===

class ProjectCreateRequest(BaseModel):
    """
    Request per creare un nuovo progetto.

    🔒 PRIVACY: Il progetto non traccia le fonti, solo contatori.

    Esempio:
    {
        "name": "Tai Chi Chen",
        "description": "Collezione video forma 24",
        "target_languages": ["it", "en", "zh"]
    }
    """
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Nome progetto univoco"
    )
    description: Optional[str] = Field(
        None,
        max_length=1000,
        description="Descrizione opzionale"
    )
    target_languages: List[str] = Field(
        default=["it", "en"],
        description="Lingue target per traduzione"
    )

    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Valida nome progetto."""
        v = ' '.join(v.split())
        if not v:
            raise ValueError('Nome progetto non puo essere vuoto')
        return v

    @field_validator('target_languages')
    @classmethod
    def validate_languages(cls, v: List[str]) -> List[str]:
        """Valida codici lingua (ISO 639-1)."""
        valid_codes = {'it', 'en', 'es', 'fr', 'de', 'pt', 'zh', 'ja', 'ko', 'ar', 'ru'}
        for lang in v:
            if lang.lower() not in valid_codes:
                raise ValueError(f'Codice lingua non valido: {lang}')
        return [lang.lower() for lang in v]


class ProjectUpdateRequest(BaseModel):
    """Request per aggiornare un progetto."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    target_languages: Optional[List[str]] = None
    is_active: Optional[bool] = None


class ProjectResponse(BaseModel):
    """
    Response con dettagli progetto.

    🔒 PRIVACY: Include solo contatori, MAI liste di file/fonti.
    """
    model_config = ConfigDict(from_attributes=True)

    id: Union[str, UUID]
    name: str
    description: Optional[str] = None
    target_languages: List[str]
    storage_path: str
    created_by: Optional[Union[str, UUID]] = None
    created_at: datetime
    updated_at: datetime
    is_active: bool
    current_mix_version: Optional[str] = None

    # Computed fields (🔒 solo contatori, no nomi)
    batch_count: int = 0
    total_items: int = 0       # Rinominato da total_assets per privacy
    total_size_bytes: int = 0


class ProjectListResponse(BaseModel):
    """Response paginata per lista progetti."""
    projects: List[ProjectResponse]
    total: int
    skip: int = 0
    limit: int = 20


class ProjectDetailResponse(ProjectResponse):
    """Response dettagliata con batch e mix."""
    batches: List['BatchResponse'] = []
    mix_versions: List['MixVersionSummary'] = []


# === BATCH SCHEMAS ===

class BatchResponse(BaseModel):
    """
    Response con dettagli batch.

    🔒 PRIVACY: items_count invece di file list.
    """
    model_config = ConfigDict(from_attributes=True)

    id: Union[str, UUID]
    batch_date: str  # "2025-01-15"
    status: BatchStatusEnum
    # Contatori per tipo (🔒 no file names)
    video_count: int = 0
    audio_count: int = 0
    image_count: int = 0
    pdf_count: int = 0
    text_count: int = 0
    ai_paste_count: int = 0
    external_count: int = 0
    skeleton_count: int = 0
    items_count: int = 0       # Totale items
    total_size_bytes: int = 0
    progress_percentage: int = 0
    current_step: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None


class BatchStatusResponse(BaseModel):
    """Response con stato processing batch."""
    batch_date: str
    status: BatchStatusEnum
    progress_percentage: int
    current_step: Optional[str] = None
    items_processed: int = 0    # Rinominato da assets_processed
    items_total: int = 0        # Rinominato da assets_total
    items_failed: int = 0       # Rinominato da assets_failed
    error_message: Optional[str] = None
    estimated_remaining_seconds: Optional[int] = None


class BatchListResponse(BaseModel):
    """Response con lista batch."""
    batches: List[BatchResponse]
    total: int


# === ASSET SCHEMAS (🔒 PRIVACY: NO original_filename) ===

class AssetResponse(BaseModel):
    """
    Response con dettagli asset.

    🔒 PRIVACY BY DESIGN:
    - NO original_filename (mai esposto)
    - filename è UUID-based
    - input_channel rimosso dopo mix
    """
    model_config = ConfigDict(from_attributes=True)

    id: Union[str, UUID]
    filename: str               # UUID-based, non originale
    # 🔒 RIMOSSO: original_filename - violazione privacy
    asset_type: AssetTypeEnum
    input_channel: Optional[InputChannelEnum] = None  # Cancellato dopo mix
    file_size: int
    mime_type: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    # 🔒 processing_results non contiene riferimenti a fonti
    processing_results: Optional[Dict[str, Any]] = None
    duration_seconds: Optional[int] = None
    width: Optional[int] = None
    height: Optional[int] = None
    fps: Optional[int] = None
    created_at: datetime
    processed_at: Optional[datetime] = None


class AssetListResponse(BaseModel):
    """Response con lista asset di un batch."""
    assets: List[AssetResponse]
    total: int


# === MULTI-CHANNEL UPLOAD SCHEMAS ===

class VideoUploadRequest(BaseModel):
    """
    Request per upload video.

    🔒 PRIVACY: Il nome file originale NON viene salvato.
    """
    preset: ProcessingPresetEnum = Field(
        default=ProcessingPresetEnum.STANDARD,
        description="Preset di processing"
    )
    extract_skeleton: bool = Field(
        default=True,
        description="Estrai skeleton MediaPipe"
    )
    target_languages: str = Field(
        default="it,en",
        description="Lingue target (comma-separated)"
    )
    confidence_threshold: float = Field(
        default=0.65,
        ge=0.0,
        le=1.0,
        description="Soglia confidenza traduzione"
    )


class PdfUploadRequest(BaseModel):
    """
    Request per upload PDF.

    🔒 PRIVACY: OCR output anonimizzato, nome file non salvato.
    """
    extract_images: bool = Field(
        default=True,
        description="Estrai immagini tecniche"
    )
    ocr_languages: str = Field(
        default="it,en,zh,ja",
        description="Lingue per OCR (comma-separated)"
    )
    target_languages: str = Field(
        default="it,en",
        description="Lingue target traduzione"
    )


class TextUploadRequest(BaseModel):
    """
    Request per testo manuale (textarea).

    🔒 PRIVACY:
    - NO logging del contenuto
    - Processato come testo grezzo
    - Nessun riferimento salvato
    """
    content: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="Testo da processare"
    )
    source_language: Optional[str] = Field(
        None,
        description="Lingua sorgente (auto-detect se None)"
    )
    target_languages: str = Field(
        default="it,en",
        description="Lingue target traduzione"
    )
    content_type: str = Field(
        default="notes",
        description="Tipo: notes, translation, technique, correction"
    )


class AiPasteRequest(BaseModel):
    """
    Request per paste da altre AI (Claude/GPT).

    🔒 PRIVACY:
    - Auto-rimuove firme AI ("As an AI...", etc.)
    - Anonimizza automaticamente
    - NO logging prompt originale
    """
    content: str = Field(
        ...,
        min_length=1,
        max_length=100000,
        description="Output da AI da processare"
    )
    remove_ai_signatures: bool = Field(
        default=True,
        description="Rimuovi firme AI automaticamente"
    )
    target_languages: str = Field(
        default="it,en",
        description="Lingue target traduzione"
    )


class WebhookImportRequest(BaseModel):
    """
    Request per import da webhook/API esterni.

    🔒 PRIVACY:
    - NO source tracking
    - Formato standardizzato
    """
    data: Dict[str, Any] = Field(
        ...,
        description="Dati da importare (formato standardizzato)"
    )
    data_type: str = Field(
        ...,
        description="Tipo: skeleton, knowledge, vocabulary, technique"
    )
    # 🔒 NO: source_url, source_name, api_key


class UploadResponse(BaseModel):
    """Response dopo upload."""
    batch_id: Union[str, UUID]
    batch_date: str
    items_uploaded: int         # Rinominato da assets_uploaded
    items_duplicated: int = 0   # Rinominato da assets_duplicated
    total_size_bytes: int
    status_url: str
    message: str = "Upload completato"


# === MIX SCHEMAS (🔒 PRIVACY: NO source_batches) ===

class MixGenerateRequest(BaseModel):
    """Request per generare mix."""
    force_full: bool = Field(
        default=False,
        description="Forza rigenerazione completa invece di incrementale"
    )


class MixVersionSummary(BaseModel):
    """
    Summary versione mix.

    🔒 PRIVACY: Solo contatori, MAI liste fonti.
    """
    version: str
    created_at: datetime
    total_items: int            # Rinominato da total_sources
    is_incremental: bool


class MixVersionResponse(BaseModel):
    """
    Response con dettagli versione mix.

    🔒 PRIVACY BY DESIGN:
    - NO source_batches (rimosso)
    - NO source_files (mai esistito)
    - Solo contatori aggregati
    """
    model_config = ConfigDict(from_attributes=True)

    id: Union[str, UUID]
    version: str
    storage_path: str
    # 🔒 RIMOSSO: source_batches - violazione privacy
    is_incremental: bool
    previous_version: Optional[str] = None
    # Stats (🔒 solo contatori, no nomi)
    total_items: int = 0
    total_skeletons: int = 0
    total_transcriptions: int = 0
    total_knowledge_chunks: int = 0
    total_subtitles: int = 0
    total_vocabulary_terms: int = 0
    total_size_bytes: int = 0
    # 🔒 merge_stats non contiene file names
    merge_stats: Optional[Dict[str, Any]] = None
    created_by: Optional[Union[str, UUID]] = None
    created_at: datetime


class MixVersionListResponse(BaseModel):
    """Response con lista versioni mix."""
    versions: List[MixVersionResponse]
    current_version: Optional[str] = None
    total: int


class MixCurrentResponse(BaseModel):
    """
    Response con mix attuale e contenuti.

    🔒 PRIVACY: File paths sono UUID-based, non nomi originali.
    """
    version: str
    storage_path: str
    # 🔒 Questi sono UUID-based paths, non nomi originali
    skeleton_count: int = 0
    transcription_count: int = 0
    knowledge_count: int = 0
    subtitle_count: int = 0
    vocabulary_count: int = 0
    stats: Dict[str, Any] = {}


# === EXPORT SCHEMAS ===

class ExportRequest(BaseModel):
    """Request per esportare contenuti temp."""
    export_types: List[str] = Field(
        default=["skeleton", "transcription"],
        description="Tipi da esportare: skeleton, transcription, knowledge, vocabulary"
    )
    batch_dates: Optional[List[str]] = Field(
        None,
        description="Batch specifici (null = tutti)"
    )
    format: str = Field(
        default="zip",
        description="Formato export: zip, tar.gz"
    )


class ExportResponse(BaseModel):
    """Response export."""
    export_id: Union[str, UUID]
    download_url: str
    items_count: int            # Rinominato da files_count
    total_size_bytes: int
    expires_at: datetime
    message: str = "Export pronto per download"


# === CLEANUP SCHEMAS ===

class CleanupRequest(BaseModel):
    """
    Request per cancellare temp.

    🔒 PRIVACY: Dopo cleanup, fonti non più recuperabili.
    """
    confirm: bool = Field(
        ...,
        description="Conferma cancellazione (deve essere true)"
    )
    batch_dates: Optional[List[str]] = Field(
        None,
        description="Batch specifici (null = tutti)"
    )


class CleanupResponse(BaseModel):
    """Response cleanup."""
    batches_deleted: int
    items_deleted: int          # Rinominato da files_deleted
    bytes_freed: int
    message: str


# === HEALTH/STATUS SCHEMAS ===

class ProjectHealthResponse(BaseModel):
    """Health status di un progetto."""
    project_id: Union[str, UUID]
    project_name: str
    storage_exists: bool
    storage_size_bytes: int
    batches_pending: int
    batches_processing: int
    batches_processed: int
    batches_failed: int
    current_mix: Optional[str] = None
    last_activity: Optional[datetime] = None


# === LLM CONFIG SCHEMAS ===

class LLMConfigResponse(BaseModel):
    """
    Config LLM per traduzione.

    🔒 PRIVACY: no_history e no_prompt_log abilitati.
    """
    provider: str = "ollama"
    base_url: str = "http://localhost:11434"
    specialists: Dict[str, Dict[str, Any]] = {}
    no_history: bool = True
    no_prompt_log: bool = True


# === BLENDER/AVATAR SCHEMAS ===

class BlenderExportRequest(BaseModel):
    """
    Request per export skeleton verso Blender.

    🔒 PRIVACY: asset_id è UUID, non riferisce alla fonte.
    """
    asset_id: str = Field(
        ...,
        description="ID asset skeleton (UUID)"
    )
    include_script: bool = Field(
        default=True,
        description="Include Python script per import Blender"
    )
    rig_type: str = Field(
        default="mixamo",
        description="Tipo rig: mixamo, rigify, custom"
    )
    fps: int = Field(
        default=30,
        ge=1,
        le=120,
        description="FPS target per animazione"
    )


class BlenderExportResponse(BaseModel):
    """
    Response export Blender.

    🔒 PRIVACY: Solo UUID-based paths.
    """
    export_id: str
    json_path: str
    script_path: Optional[str] = None
    total_frames: int
    duration_seconds: float
    bone_count: int
    download_url: str
    message: str = "Export pronto per Blender"


class AvatarImportRequest(BaseModel):
    """
    Request per import video avatar da Blender.

    🔒 PRIVACY: NO source_filename, NO render_path originale.
    """
    export_id: Optional[str] = Field(
        None,
        description="ID export Blender originale (per tracing interno)"
    )
    render_angles: int = Field(
        default=8,
        ge=1,
        le=16,
        description="Angoli camera (8 = 360°)"
    )


class AvatarResponse(BaseModel):
    """
    Response con dettagli avatar.

    🔒 PRIVACY: UUID-based, no original filenames.
    """
    avatar_id: str
    project_id: str
    status: str
    duration_seconds: float
    width: int
    height: int
    fps: float
    render_angles: int
    is_360: bool
    thumbnail_url: str
    stream_url: str
    download_url: str
    created_at: datetime


class AvatarStatusResponse(BaseModel):
    """Status di un avatar."""
    avatar_id: str
    status: str
    video_exists: bool
    thumbnail_exists: bool
    is_360: bool
    duration_seconds: float
    render_angles: int


class AvatarListResponse(BaseModel):
    """Lista avatar."""
    avatars: List[AvatarResponse]
    total: int


# === DVD/PARALLEL CORPUS SCHEMAS ===

class DvdAnalyzeRequest(BaseModel):
    """
    Request per analizzare tracce DVD.

    🔒 PRIVACY: Solo path temporaneo, non salvato.
    """
    # File uploaded via multipart, path is temporary


class DvdAnalyzeResponse(BaseModel):
    """
    Response analisi tracce DVD.

    🔒 PRIVACY: NO original filename.
    """
    job_id: str
    audio_tracks: List[Dict[str, Any]]
    subtitle_tracks: List[Dict[str, Any]]
    video_duration_seconds: float
    detected_languages: List[str]


class DvdExtractRequest(BaseModel):
    """
    Request per estrazione parallel corpus.

    🔒 PRIVACY: L'estrazione produce pairs anonimi.
    """
    job_id: str = Field(
        ...,
        description="ID dal precedente analyze"
    )
    source_language: str = Field(
        ...,
        min_length=2,
        max_length=5,
        description="Lingua sorgente (es: 'en', 'ja')"
    )
    target_language: str = Field(
        ...,
        min_length=2,
        max_length=5,
        description="Lingua target (es: 'it')"
    )
    subtitle_track_source: int = Field(
        default=0,
        ge=0,
        description="Indice traccia sottotitoli sorgente"
    )
    subtitle_track_target: int = Field(
        default=1,
        ge=0,
        description="Indice traccia sottotitoli target"
    )
    min_confidence: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Confidenza minima per pair"
    )


class DvdExtractResponse(BaseModel):
    """Response estrazione DVD."""
    job_id: str
    status: str
    pairs_extracted: int
    pairs_high_confidence: int
    average_confidence: float
    processing_time_seconds: float


class DvdPair(BaseModel):
    """
    Singola coppia tradotta.

    🔒 PRIVACY BY DESIGN:
    - NO timestamp (anonimizzazione temporale)
    - NO source_file
    - NO scene reference
    """
    source: str
    target: str
    confidence: float


class DvdPairsResponse(BaseModel):
    """
    Response con sentence pairs estratte.

    🔒 PRIVACY: Solo testo e confidenza, zero metadata.
    """
    job_id: str
    source_language: str
    target_language: str
    pairs: List[DvdPair]
    total_pairs: int
    average_confidence: float


class DvdImportToVocabRequest(BaseModel):
    """
    Request per importare pairs in vocabolario.

    🔒 PRIVACY: Import permanente, job_id cancellato dopo.
    """
    job_id: str = Field(
        ...,
        description="ID job con pairs estratte"
    )
    category: str = Field(
        default="martial_arts",
        description="Categoria vocabolario"
    )
    min_confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidenza minima per import"
    )
    use_llm_validation: bool = Field(
        default=True,
        description="Valida con multi-LLM debate"
    )


class DvdImportToVocabResponse(BaseModel):
    """Response import in vocabolario."""
    terms_imported: int
    terms_rejected: int
    terms_already_exist: int
    validation_results: Optional[Dict[str, Any]] = None
    message: str


# Forward references
ProjectDetailResponse.model_rebuild()

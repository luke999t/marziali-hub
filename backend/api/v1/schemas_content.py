# POSIZIONE: backend/api/v1/schemas_content.py
"""
🎓 AI_MODULE: Content Classification Schemas
🎓 AI_DESCRIPTION: Pydantic schemas per validazione request/response classificazione contenuti
🎓 AI_BUSINESS: Validazione input utente, serializzazione output API, documentazione OpenAPI
🎓 AI_TEACHING: Pydantic v2 models con validators, from_attributes per ORM, type hints

🔄 ALTERNATIVE_VALUTATE:
- Dict raw senza validazione: Scartato perché nessun type checking, errori runtime
- Marshmallow: Scartato perché non integrato nativamente con FastAPI
- Dataclasses: Scartato perché meno features di validazione rispetto a Pydantic

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Validazione automatica: Pydantic valida tutti i campi con messaggi di errore chiari
- OpenAPI generation: FastAPI genera docs automaticamente da questi schemas
- ORM integration: from_attributes=True permette conversione diretta da SQLAlchemy model
- Type hints: IDE autocompletamento, errori a compile-time

📊 BUSINESS_IMPACT:
- Developer Experience: Errori chiari invece di 500 Internal Server Error
- Security: Validazione input previene injection attacks
- Documentation: OpenAPI sempre aggiornata automaticamente

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: ContentType enum
- Downstream: content_classification router, tests
"""

from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Optional, List
from datetime import datetime
from uuid import UUID
from enum import Enum


# ═══════════════════════════════════════════════════════════════
# ENUMS PER SCHEMAS
# ═══════════════════════════════════════════════════════════════

class ContentTypeEnum(str, Enum):
    """
    Enum per validazione content_type nelle request.
    Duplica i valori da models.content_type per decoupling layer API/DB.
    """
    FORMA_COMPLETA = "forma_completa"
    MOVIMENTO_SINGOLO = "movimento_singolo"
    TECNICA_A_DUE = "tecnica_a_due"
    SPIEGAZIONE = "spiegazione"
    VARIANTE = "variante"


class SkeletonStatus(int, Enum):
    """Status estrazione skeleton."""
    NOT_EXTRACTED = 0
    IN_PROGRESS = 1
    COMPLETED = 2
    ERROR = -1


# ═══════════════════════════════════════════════════════════════
# CONTENT TYPE SCHEMAS
# ═══════════════════════════════════════════════════════════════

class ContentTypeChoice(BaseModel):
    """Schema per singola scelta content type (per dropdown UI)."""
    value: str = Field(..., description="Valore da salvare nel DB")
    label: str = Field(..., description="Label da mostrare in UI")


class ContentTypeListResponse(BaseModel):
    """Response lista tipi contenuto disponibili."""
    types: List[ContentTypeChoice]
    count: int


# ═══════════════════════════════════════════════════════════════
# VIDEO SECTION SCHEMAS
# ═══════════════════════════════════════════════════════════════

class VideoSectionBase(BaseModel):
    """
    Base schema con campi comuni a create/update.

    📋 VALIDAZIONI:
    - content_type: deve essere uno dei 5 valori enum
    - start_time: >= 0
    - end_time: > start_time
    - name: 1-255 caratteri
    """
    content_type: ContentTypeEnum = Field(
        ...,
        description="Tipo di contenuto: forma_completa, movimento_singolo, tecnica_a_due, spiegazione, variante"
    )
    start_time: float = Field(
        ...,
        ge=0,
        description="Inizio sezione in secondi dall'inizio video"
    )
    end_time: float = Field(
        ...,
        description="Fine sezione in secondi dall'inizio video"
    )
    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Nome identificativo della sezione"
    )
    style: Optional[str] = Field(
        None,
        max_length=100,
        description="Stile/scuola marziale (es. tai_chi_chen)"
    )
    notes: Optional[str] = Field(
        None,
        description="Note aggiuntive"
    )

    @model_validator(mode='after')
    def validate_time_range(self):
        """Valida che end_time > start_time."""
        if self.end_time <= self.start_time:
            raise ValueError(
                f"end_time ({self.end_time}) deve essere maggiore di start_time ({self.start_time})"
            )
        return self


class VideoSectionCreate(VideoSectionBase):
    """
    Schema per creazione nuova sezione.

    Richiede video_id obbligatorio.
    project_id opzionale per collegamento a IngestProject.
    """
    video_id: UUID = Field(
        ...,
        description="ID del video parent"
    )
    project_id: Optional[UUID] = Field(
        None,
        description="ID progetto ingest (opzionale)"
    )


class VideoSectionUpdate(BaseModel):
    """
    Schema per update parziale sezione.

    Tutti i campi opzionali - aggiorna solo quelli forniti.
    """
    content_type: Optional[ContentTypeEnum] = None
    start_time: Optional[float] = Field(None, ge=0)
    end_time: Optional[float] = None
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    style: Optional[str] = Field(None, max_length=100)
    notes: Optional[str] = None
    project_id: Optional[UUID] = None

    @model_validator(mode='after')
    def validate_time_range_if_both(self):
        """Valida time range solo se entrambi forniti."""
        if self.start_time is not None and self.end_time is not None:
            if self.end_time <= self.start_time:
                raise ValueError(
                    f"end_time ({self.end_time}) deve essere maggiore di start_time ({self.start_time})"
                )
        return self


class VideoSectionResponse(BaseModel):
    """
    Schema response completo per sezione video.

    Include tutti i campi + computed properties.
    """
    id: int
    video_id: UUID
    project_id: Optional[UUID] = None
    content_type: str
    start_time: float
    end_time: float
    duration: float = Field(..., description="Durata in secondi (computed)")
    name: str
    style: Optional[str] = None
    notes: Optional[str] = None
    skeleton_extracted: int = Field(
        default=0,
        description="0=non estratto, 1=in corso, 2=completato, -1=errore"
    )
    skeleton_path: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    created_by: Optional[UUID] = None

    model_config = {"from_attributes": True}

    @field_validator('duration', mode='before')
    @classmethod
    def compute_duration(cls, v, info):
        """Calcola duration se non fornito."""
        if v is None and info.data:
            start = info.data.get('start_time', 0)
            end = info.data.get('end_time', 0)
            return end - start
        return v


class VideoSectionListResponse(BaseModel):
    """Response lista sezioni con metadata."""
    sections: List[VideoSectionResponse]
    total: int
    video_id: Optional[UUID] = None
    content_type_filter: Optional[str] = None


# ═══════════════════════════════════════════════════════════════
# PROJECT CONTENT TYPE SCHEMAS
# ═══════════════════════════════════════════════════════════════

class ProjectContentTypeUpdate(BaseModel):
    """Schema per aggiornare content_type di un progetto."""
    content_type: ContentTypeEnum = Field(
        ...,
        description="Nuovo tipo contenuto"
    )
    style: Optional[str] = Field(
        None,
        max_length=100,
        description="Stile/scuola marziale"
    )


class ProjectContentTypeResponse(BaseModel):
    """Response content_type progetto."""
    project_id: UUID
    content_type: Optional[str]
    style: Optional[str]
    updated_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════════
# FILTER SCHEMAS
# ═══════════════════════════════════════════════════════════════

class SectionFilterParams(BaseModel):
    """
    Parametri filtro per lista sezioni.

    Usato internamente per validare query params.
    """
    video_id: Optional[UUID] = None
    project_id: Optional[UUID] = None
    content_type: Optional[ContentTypeEnum] = None
    style: Optional[str] = None
    min_duration: Optional[float] = Field(None, ge=0)
    max_duration: Optional[float] = Field(None, ge=0)
    skeleton_extracted: Optional[int] = Field(None, ge=-1, le=2)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)

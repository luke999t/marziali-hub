"""
AI_MODULE: Avatar Schemas
AI_DESCRIPTION: Pydantic schemas per validazione request/response Avatar API
AI_TEACHING: Separare gli schemas dal modello ORM permette di:
             - Validare input indipendentemente dal database
             - Controllare esattamente cosa esporre nelle response
             - Documentare automaticamente l'API via OpenAPI/Swagger
"""

from pydantic import BaseModel, Field, field_serializer
from typing import Optional, List, Dict, Union
from datetime import datetime
from uuid import UUID


# === Request Schemas ===

class AvatarBase(BaseModel):
    """Campi comuni per create/update avatar"""
    name: str = Field(..., min_length=1, max_length=100,
                      description="Nome visualizzato dell'avatar")
    description: Optional[str] = Field(None, max_length=1000,
                                       description="Descrizione dell'avatar")
    style: str = Field(
        default="generic",
        pattern="^(karate|kung_fu|taekwondo|judo|generic)$",
        description="Stile marziale dell'avatar"
    )


class AvatarCreate(AvatarBase):
    """Schema per creazione nuovo avatar (POST)"""
    rig_type: str = Field(
        default="readyplayerme",
        pattern="^(mixamo|readyplayerme|custom)$",
        description="Tipo di rig/armatura del modello 3D"
    )
    license_type: str = Field(
        default="cc_by",
        pattern="^(cc0|cc_by|proprietary)$",
        description="Tipo di licenza del modello"
    )
    attribution: Optional[str] = Field(None, max_length=500,
                                       description="Testo di attribuzione licenza")


class AvatarUpdate(BaseModel):
    """Schema per update avatar (PUT) - tutti i campi opzionali"""
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=1000)
    style: Optional[str] = Field(None, pattern="^(karate|kung_fu|taekwondo|judo|generic)$")


# === Response Schemas ===

class AvatarResponse(AvatarBase):
    """
    Response standard per singolo avatar.

    WHY from_attributes: Permette conversione diretta da ORM model
    senza dover mappare manualmente ogni campo.
    """
    id: Union[str, UUID]
    model_url: str
    thumbnail_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    rig_type: str
    bone_count: Optional[int] = None
    has_hand_bones: bool = True
    is_public: bool = True
    created_at: datetime

    @field_serializer('id')
    def serialize_id(self, id: Union[str, UUID]) -> str:
        return str(id)

    class Config:
        from_attributes = True


class AvatarDetailResponse(AvatarResponse):
    """Response dettagliata con info aggiuntive"""
    license_type: str = "cc_by"
    attribution: Optional[str] = None
    updated_at: Optional[datetime] = None
    created_by: Optional[Union[str, UUID]] = None

    @field_serializer('created_by')
    def serialize_created_by(self, created_by: Optional[Union[str, UUID]]) -> Optional[str]:
        return str(created_by) if created_by else None


class AvatarListResponse(BaseModel):
    """Response paginata per lista avatar"""
    avatars: List[AvatarResponse]
    total: int
    page: int = 1
    page_size: int = 20


# === Bone Mapping Schemas ===

class BoneMappingResponse(BaseModel):
    """
    Mapping tra indici MediaPipe landmarks e nomi bones avatar.

    WHY struttura separata per body/left_hand/right_hand:
    MediaPipe Holistic produce 3 set distinti di landmarks:
    - Pose (33 landmarks corpo)
    - Left Hand (21 landmarks mano sx)
    - Right Hand (21 landmarks mano dx)
    Totale: 75 landmarks
    """
    body: Dict[int, str] = Field(
        ..., description="Mapping indice pose landmark -> nome bone (33 landmarks)"
    )
    left_hand: Dict[int, str] = Field(
        ..., description="Mapping indice hand landmark -> nome bone (21 landmarks)"
    )
    right_hand: Dict[int, str] = Field(
        ..., description="Mapping indice hand landmark -> nome bone (21 landmarks)"
    )
    total_landmarks: int = Field(default=75, description="Totale landmarks MediaPipe Holistic")
    total_bones: int = Field(..., description="Totale bones mappati nell'avatar")


# === Skeleton Application Schemas ===

class ApplySkeletonRequest(BaseModel):
    """
    Request per applicare dati skeleton a un avatar.

    WHY skeleton_id separato: Il frontend potrebbe avere più skeleton
    (da video diversi) e vuole provare lo stesso avatar con pose diverse.
    """
    skeleton_id: Union[str, UUID] = Field(
        ..., description="ID del skeleton da applicare (dalla Skeleton API)"
    )
    frame_number: Optional[int] = Field(
        None, ge=0,
        description="Frame specifico da applicare. None = tutti i frames"
    )
    output_format: str = Field(
        default="transforms",
        pattern="^(transforms|animation)$",
        description="'transforms' per pose singola, 'animation' per sequenza completa"
    )


class BoneTransform(BaseModel):
    """Trasformazione singolo bone per un frame"""
    bone_name: str
    rotation: List[float] = Field(
        ..., min_length=4, max_length=4,
        description="Quaternion rotation [x, y, z, w]"
    )
    position: List[float] = Field(
        ..., min_length=3, max_length=3,
        description="Position [x, y, z]"
    )


class ApplySkeletonResponse(BaseModel):
    """Response con bone transforms calcolati da skeleton data"""
    avatar_id: Union[str, UUID]
    skeleton_id: Union[str, UUID]
    frame_count: int
    bone_transforms: List[Dict] = Field(
        ...,
        description="Per frame: {bone_name: {rotation: [x,y,z,w], position: [x,y,z]}}"
    )

    @field_serializer('avatar_id', 'skeleton_id')
    def serialize_uuid(self, v: Union[str, UUID]) -> str:
        return str(v)


# === Style Schemas ===

class AvatarStyleInfo(BaseModel):
    """Informazioni su uno stile disponibile"""
    value: str
    label: str
    description: str
    avatar_count: int = 0


class AvatarStylesResponse(BaseModel):
    """Lista stili disponibili con conteggi"""
    styles: List[AvatarStyleInfo]

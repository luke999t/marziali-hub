"""
AI_MODULE: Avatar 3D Model
AI_DESCRIPTION: Modello ORM per gestione avatar 3D con bone mapping MediaPipe
AI_TEACHING: Gli avatar ReadyPlayerMe usano rig Mixamo-compatible,
             permettendo il mapping diretto dai 75 landmarks MediaPipe Holistic.
             Ogni avatar ha metadati su rig type, bone count e supporto mani.
"""

import uuid
import enum
from datetime import datetime
from sqlalchemy import (
    Column, String, Text, Boolean, DateTime, Integer, Index, Enum, ForeignKey
)
from sqlalchemy.orm import relationship
from core.database import Base
from models import GUID


class AvatarStyle(str, enum.Enum):
    """Stili marziali supportati per categorizzazione avatar"""
    KARATE = "karate"
    KUNG_FU = "kung_fu"
    TAEKWONDO = "taekwondo"
    JUDO = "judo"
    GENERIC = "generic"


class AvatarRigType(str, enum.Enum):
    """Tipo di rig/armatura dell'avatar 3D"""
    MIXAMO = "mixamo"
    READYPLAYERME = "readyplayerme"
    CUSTOM = "custom"


class AvatarLicenseType(str, enum.Enum):
    """Licenza del modello 3D"""
    CC0 = "cc0"
    CC_BY = "cc_by"
    PROPRIETARY = "proprietary"


class Avatar(Base):
    """
    Avatar 3D per visualizzazione pose da skeleton MediaPipe.

    WHY: Separare i modelli 3D dai dati skeleton permette di:
    - Riutilizzare lo stesso avatar con skeleton diversi
    - Permettere agli utenti di scegliere il proprio avatar
    - Supportare rig diversi (Mixamo, RPM, custom)
    """
    __tablename__ = "avatars"

    # Identity
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    style = Column(
        Enum(AvatarStyle, values_callable=lambda x: [e.value for e in x],
             name='avatarstyle', create_type=False),
        default=AvatarStyle.GENERIC,
        nullable=False,
        index=True
    )

    # File info
    model_url = Column(String(500), nullable=False)
    thumbnail_url = Column(String(500))
    file_size_bytes = Column(Integer)

    # Rig info - descrive l'armatura del modello 3D
    rig_type = Column(
        Enum(AvatarRigType, values_callable=lambda x: [e.value for e in x],
             name='avatarrigtype', create_type=False),
        default=AvatarRigType.READYPLAYERME,
        nullable=False
    )
    bone_count = Column(Integer)
    has_hand_bones = Column(Boolean, default=True, nullable=False)

    # Visibility & status
    is_public = Column(Boolean, default=True, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    # Ownership
    created_by = Column(GUID(), ForeignKey("users.id"), nullable=True)

    # License
    license_type = Column(
        Enum(AvatarLicenseType, values_callable=lambda x: [e.value for e in x],
             name='avatarlicensetype', create_type=False),
        default=AvatarLicenseType.CC_BY,
        nullable=False
    )
    attribution = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow,
                        onupdate=datetime.utcnow, nullable=False)

    # Indexes per query frequenti
    __table_args__ = (
        Index('idx_avatars_style_active', 'style', 'is_active'),
        Index('idx_avatars_public_active', 'is_public', 'is_active'),
        Index('idx_avatars_created_by', 'created_by'),
    )

    def __repr__(self):
        return f"<Avatar(id={self.id}, name='{self.name}', style='{self.style}')>"

"""
================================================================================
AI_MODULE: Download Model
AI_VERSION: 1.0.0
AI_DESCRIPTION: SQLAlchemy model per gestione download offline
AI_BUSINESS: Retention +20% per utenti che usano offline mode
AI_TEACHING: DRM soft con token temporanei, non encryption pesante

ALTERNATIVE_VALUTATE:
- DRM hardware (Widevine L1): Troppo complesso per MVP
- No DRM: Rischio pirateria inaccettabile
- Token refresh: Scelto, bilancia sicurezza/UX

PERCHE_QUESTA_SOLUZIONE:
- Token-based DRM permette controllo senza complessità hardware
- Limiti per tier incentivano upgrade PREMIUM
- Scadenza obbliga sync online periodico (verifica abbonamento)

METRICHE_SUCCESSO:
- Conversione FREE→PREMIUM: +15% grazie a offline feature
- Retention utenti offline: +20% vs solo streaming
- Piracy rate: <1% grazie a token expiry

INTEGRATION_DEPENDENCIES:
- Upstream: models/user.py, models/video.py
- Downstream: modules/downloads, api/v1/downloads
================================================================================
"""

from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum, ForeignKey, BigInteger, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum

from core.database import Base
from models import GUID


# ==============================================================================
# ENUMS
# ==============================================================================

class DownloadStatus(str, enum.Enum):
    """
    Stati possibili per un download.

    BUSINESS FLOW:
    PENDING → DOWNLOADING → COMPLETED → [EXPIRED | REVOKED]
                         ↘ FAILED
    """
    PENDING = "pending"           # Richiesto, non ancora iniziato
    DOWNLOADING = "downloading"   # In corso
    COMPLETED = "completed"       # Completato, disponibile offline
    EXPIRED = "expired"           # Scaduto, da ri-scaricare
    REVOKED = "revoked"           # Revocato (es. abbonamento scaduto)
    FAILED = "failed"             # Download fallito


class DownloadQuality(str, enum.Enum):
    """
    Qualità video disponibili per download.

    BUSINESS LOGIC:
    - FREE: Nessun download
    - BASIC: Max 720p
    - PREMIUM: Max 1080p
    - VIP: Max 4K

    STORAGE ESTIMATION (per ora di video):
    - 360p: ~150MB
    - 720p: ~500MB
    - 1080p: ~1.5GB
    - 4K: ~4GB
    """
    LOW = "360p"
    MEDIUM = "720p"
    HIGH = "1080p"
    ULTRA = "4K"


# ==============================================================================
# MODELS
# ==============================================================================

class Download(Base):
    """
    Singolo download di un video per un utente.

    BUSINESS PURPOSE:
    Traccia download per:
    1. Enforcement limiti tier
    2. DRM token management
    3. Analytics utilizzo offline

    TECHNICAL EXPLANATION:
    - DRM token scade dopo X giorni → forza sync online
    - offline_views_remaining → limita views senza connessione
    - device_id → limita dispositivi per utente
    """
    __tablename__ = "downloads"

    # === PRIMARY KEY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === FOREIGN KEYS ===
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="CASCADE"), nullable=False, index=True)

    # === STATO E PROGRESSO ===
    status = Column(
        Enum(DownloadStatus, values_callable=lambda x: [e.value for e in x], name='downloadstatus'),
        default=DownloadStatus.PENDING,
        nullable=False
    )
    quality = Column(
        Enum(DownloadQuality, values_callable=lambda x: [e.value for e in x], name='downloadquality'),
        nullable=False
    )
    progress_percent = Column(Integer, default=0)  # 0-100

    # === FILE INFO ===
    file_size_bytes = Column(BigInteger)  # Dimensione totale stimata
    downloaded_bytes = Column(BigInteger, default=0)  # Bytes scaricati

    # === DRM TOKEN ===
    # Token che il client deve presentare per riprodurre offline
    # Scade dopo X giorni, richiede refresh online
    drm_token = Column(String(500))
    drm_expires_at = Column(DateTime)  # Default: 30 giorni da completamento

    # === LIMITI OFFLINE ===
    offline_views_remaining = Column(Integer, default=10)  # Max views senza sync
    last_online_check = Column(DateTime)  # Ultimo sync con server

    # === TIMESTAMPS ===
    requested_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)  # Quando iniziato effettivamente
    completed_at = Column(DateTime)  # Quando completato
    expires_at = Column(DateTime)  # Quando il download scade completamente

    # === DEVICE INFO ===
    # Per limitare numero dispositivi per utente
    device_id = Column(String(100), nullable=False)
    device_name = Column(String(100))  # "iPhone 15", "iPad Pro", etc.

    # === RELATIONSHIPS ===
    user = relationship("User", back_populates="downloads")
    video = relationship("Video", back_populates="downloads")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_downloads_user_status', 'user_id', 'status'),
        Index('idx_downloads_drm_expires', 'drm_expires_at'),
    )

    def is_playable(self) -> bool:
        """
        Verifica se il download è riproducibile offline.

        BUSINESS LOGIC:
        Un download è playable se:
        1. Status = COMPLETED
        2. DRM token non scaduto
        3. Ci sono views rimanenti

        Returns:
            True se riproducibile, False altrimenti
        """
        if self.status != DownloadStatus.COMPLETED:
            return False

        if self.drm_expires_at and datetime.utcnow() > self.drm_expires_at:
            return False

        if self.offline_views_remaining is not None and self.offline_views_remaining <= 0:
            return False

        return True

    def needs_online_refresh(self) -> bool:
        """
        Verifica se serve refresh online.

        Returns:
            True se deve sincronizzare con server
        """
        # DRM sta per scadere (meno di 3 giorni)
        if self.drm_expires_at:
            days_remaining = (self.drm_expires_at - datetime.utcnow()).days
            if days_remaining < 3:
                return True

        # Poche views rimanenti
        if self.offline_views_remaining is not None and self.offline_views_remaining <= 2:
            return True

        return False

    def to_dict(self) -> dict:
        """Serializza per API response."""
        return {
            "id": str(self.id),
            "video_id": str(self.video_id),
            "status": self.status.value if self.status else None,
            "quality": self.quality.value if self.quality else None,
            "progress_percent": self.progress_percent,
            "file_size_bytes": self.file_size_bytes,
            "downloaded_bytes": self.downloaded_bytes,
            "drm_expires_at": self.drm_expires_at.isoformat() if self.drm_expires_at else None,
            "offline_views_remaining": self.offline_views_remaining,
            "requested_at": self.requested_at.isoformat() if self.requested_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "device_id": self.device_id,
            "device_name": self.device_name,
            "is_playable": self.is_playable(),
            "needs_refresh": self.needs_online_refresh()
        }


class DownloadLimit(Base):
    """
    Limiti download per tier utente.

    BUSINESS PURPOSE:
    Differenziazione tier tramite limiti:
    - FREE: 0 downloads (incentivo upgrade)
    - BASIC: 3 downloads, 720p, 7 giorni
    - PREMIUM: 10 downloads, 1080p, 30 giorni
    - VIP: 25 downloads, 4K, 90 giorni

    TECHNICAL NOTE:
    Stored in DB per permettere modifica senza deploy.
    Se non presente, usa default hardcoded nel service.
    """
    __tablename__ = "download_limits"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # Tier identifier (free, basic, premium, vip)
    tier = Column(String(20), unique=True, nullable=False)

    # === LIMITI ===
    max_concurrent_downloads = Column(Integer, default=1)  # Download simultanei
    max_stored_downloads = Column(Integer, default=5)      # Download salvati
    max_quality = Column(
        Enum(DownloadQuality, values_callable=lambda x: [e.value for e in x], name='downloadquality_limit'),
        default=DownloadQuality.MEDIUM
    )

    # === DRM CONFIG ===
    drm_validity_days = Column(Integer, default=30)  # Giorni validità token
    offline_views_per_download = Column(Integer, default=10)  # Views offline

    # === STORAGE LIMIT (opzionale) ===
    max_storage_bytes = Column(BigInteger)  # NULL = illimitato

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self) -> dict:
        """Serializza per API response."""
        return {
            "tier": self.tier,
            "max_concurrent_downloads": self.max_concurrent_downloads,
            "max_stored_downloads": self.max_stored_downloads,
            "max_quality": self.max_quality.value if self.max_quality else None,
            "drm_validity_days": self.drm_validity_days,
            "offline_views_per_download": self.offline_views_per_download,
            "max_storage_bytes": self.max_storage_bytes
        }


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def get_estimated_file_size(duration_seconds: int, quality: DownloadQuality) -> int:
    """
    Stima dimensione file basata su durata e qualità.

    Args:
        duration_seconds: Durata video in secondi
        quality: Qualità richiesta

    Returns:
        Dimensione stimata in bytes
    """
    # Bytes per secondo per qualità
    BYTES_PER_SECOND = {
        DownloadQuality.LOW: 41667,      # ~150MB/ora
        DownloadQuality.MEDIUM: 138889,  # ~500MB/ora
        DownloadQuality.HIGH: 416667,    # ~1.5GB/ora
        DownloadQuality.ULTRA: 1111111,  # ~4GB/ora
    }

    bps = BYTES_PER_SECOND.get(quality, BYTES_PER_SECOND[DownloadQuality.MEDIUM])
    return duration_seconds * bps

"""
🎓 AI_MODULE: Maestro & ASD Models
🎓 AI_DESCRIPTION: Maestri, ASDs, certifications, background checks
🎓 AI_BUSINESS: Teacher profiles with fiscal/legal compliance
🎓 AI_TEACHING: Complex professional profiles + verification workflows

💡 RELATIONSHIPS:
Maestro N ──── 1 User
Maestro N ──── 1 ASD (optional affiliation)
Maestro 1 ──── N Video
Maestro 1 ──── N LiveEvent
ASD 1 ────────  N Maestro
ASD 1 ────────  N Member
"""

from sqlalchemy import Column, String, Boolean, DateTime, Integer, Enum, ForeignKey, Text, Index, ARRAY
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# === ENUMS ===

class BackgroundCheckStatus(str, enum.Enum):
    """Status background check maestro."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"  # Richiede rinnovo annuale


class MaestroStatus(str, enum.Enum):
    """Status maestro."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    INACTIVE = "inactive"


class Discipline(str, enum.Enum):
    """Discipline arti marziali."""
    TAI_CHI = "tai_chi"
    WING_CHUN = "wing_chun"
    SHAOLIN = "shaolin"
    BAGUA_ZHANG = "bagua_zhang"
    XING_YI_QUAN = "xing_yi_quan"
    KARATE = "karate"
    JUDO = "judo"
    AIKIDO = "aikido"
    TAEKWONDO = "taekwondo"
    KUNG_FU = "kung_fu"
    WUSHU = "wushu"
    OTHER = "other"


# === MODELS ===

class Maestro(Base):
    """
    Profilo maestro esteso.

    🎯 TEACHER PROFILE: Maestri certificati che possono pubblicare video/live
    """
    __tablename__ = "maestros"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True)
    asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="SET NULL"), nullable=True)

    # === SPECIALIZATION ===
    disciplines = Column(ARRAY(String), nullable=False)  # ['tai_chi', 'wing_chun']
    primary_discipline = Column(Enum(Discipline), nullable=False)
    years_experience = Column(Integer, nullable=True)

    # === BIO ===
    bio = Column(Text, nullable=True)
    teaching_philosophy = Column(Text, nullable=True)

    # === CERTIFICATIONS ===
    certifications = Column(JSONBType(), nullable=True)
    # Example: [{"name": "Istruttore Tai Chi", "issuer": "CSEN", "date": "2020-01-15", "url": "..."}]

    # === VERIFICATION ===
    background_check_status = Column(
        Enum(BackgroundCheckStatus),
        default=BackgroundCheckStatus.PENDING,
        nullable=False,
        index=True
    )
    background_check_date = Column(DateTime, nullable=True)
    background_check_expiry = Column(DateTime, nullable=True)  # Rinnovo annuale
    background_check_notes = Column(Text, nullable=True)

    identity_verified = Column(Boolean, default=False, nullable=False)
    identity_document_url = Column(Text, nullable=True)  # Encrypted storage
    identity_verified_at = Column(DateTime, nullable=True)

    # === BANKING ===
    iban = Column(String(34), nullable=True)
    paypal_email = Column(String(255), nullable=True)
    stripe_account_id = Column(String(255), nullable=True)

    # === DONATION SETTINGS ===
    donation_split = Column(JSONBType(), nullable=True)
    # Example: {"maestro": 70, "asd": 25, "platform": 5}
    # If null, usa default platform

    default_donation_amounts = Column(ARRAY(Integer), nullable=True)
    # Preset amounts (stelline): [10, 50, 100, 500]

    donation_alert_min = Column(Integer, default=50, nullable=False)  # Min stelline per alert live
    donation_alert_sound_url = Column(Text, nullable=True)

    # === VIDEO MODERATION TRUST ===
    auto_publish_enabled = Column(Boolean, default=False, nullable=False)
    verification_level = Column(Integer, default=0, nullable=False)
    # 0 = Base (sempre moderazione), 1 = Verificato (spot-check), 2 = Trusted (auto-publish)

    # === STATUS ===
    status = Column(Enum(MaestroStatus), default=MaestroStatus.ACTIVE, nullable=False, index=True)
    suspension_reason = Column(Text, nullable=True)
    suspended_until = Column(DateTime, nullable=True)

    # === STATS (denormalized) ===
    total_videos = Column(Integer, default=0, nullable=False)
    total_followers = Column(Integer, default=0, nullable=False)
    total_donations_received = Column(Integer, default=0, nullable=False)  # Stelline

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_active = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="maestro_profile")
    asd = relationship("ASD", back_populates="maestros")
    # NOTE: Videos are uploaded by User, not directly by Maestro. Use user.videos to access.
    # videos = relationship("Video", back_populates="maestro", cascade="all, delete-orphan")
    live_events = relationship("LiveEvent", back_populates="maestro", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_maestro_status', 'status', 'created_at'),
        Index('idx_maestro_asd', 'asd_id'),
        Index('idx_maestro_bg_check', 'background_check_status'),
    )

    # === BUSINESS METHODS ===

    def is_verified(self) -> bool:
        """Check if fully verified (identity + background check)."""
        return (
            self.identity_verified
            and self.background_check_status == BackgroundCheckStatus.APPROVED
            and self.background_check_expiry
            and self.background_check_expiry > datetime.utcnow()
        )

    def can_teach_minors(self) -> bool:
        """Check if can teach minors (background check approved)."""
        return self.background_check_status == BackgroundCheckStatus.APPROVED

    def needs_background_check_renewal(self) -> bool:
        """Check if background check needs renewal."""
        if not self.background_check_expiry:
            return True
        # Alert 30 giorni prima scadenza
        from datetime import timedelta
        return datetime.utcnow() > (self.background_check_expiry - timedelta(days=30))

    def get_effective_split(self, default_platform_split: dict) -> dict:
        """
        Get effective donation split.

        Args:
            default_platform_split: Platform default if no override

        Returns:
            Dict with maestro/asd/platform percentages
        """
        if self.donation_split:
            return self.donation_split

        if self.asd_id:
            # Affiliato ASD: usa default ASD o platform
            return default_platform_split
        else:
            # Indipendente: più % al maestro
            return {"maestro": 95, "asd": 0, "platform": 5}

    def __repr__(self):
        return f"<Maestro {self.user_id} - {self.primary_discipline.value}>"


class ASD(Base):
    """
    Associazione Sportiva Dilettantistica.

    🎯 LEGAL ENTITY: Gestione palestre/scuole arti marziali
    """
    __tablename__ = "asds"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === IDENTITY ===
    name = Column(String(255), nullable=False, index=True)
    codice_fiscale = Column(String(16), unique=True, nullable=False, index=True)

    # === CONTACT ===
    email = Column(String(255), nullable=True)
    phone = Column(String(50), nullable=True)
    website = Column(String(255), nullable=True)

    # === ADDRESS ===
    address = Column(Text, nullable=True)
    city = Column(String(100), nullable=True)
    province = Column(String(2), nullable=True)  # Sigla provincia (MI, RM, etc.)
    postal_code = Column(String(10), nullable=True)
    country = Column(String(100), default="Italia", nullable=False)

    # === LEGAL ===
    presidente_name = Column(String(255), nullable=True)
    presidente_cf = Column(String(16), nullable=True)
    legal_representative_email = Column(String(255), nullable=True)

    # === BANKING ===
    iban = Column(String(34), nullable=True)
    paypal_email = Column(String(255), nullable=True)

    # === SETTINGS ===
    default_donation_split = Column(JSONBType(), nullable=True)
    # Example: {"maestro": 70, "asd": 25, "platform": 5}

    # === BRANDING ===
    logo_url = Column(Text, nullable=True)
    description = Column(Text, nullable=True)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)

    # === STATS (denormalized) ===
    total_maestros = Column(Integer, default=0, nullable=False)
    total_members = Column(Integer, default=0, nullable=False)
    total_donations_received = Column(Integer, default=0, nullable=False)  # Stelline

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    maestros = relationship("Maestro", back_populates="asd")
    members = relationship("ASDMember", back_populates="asd", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_asd_active', 'is_active', 'created_at'),
        Index('idx_asd_cf', 'codice_fiscale'),
    )

    def __repr__(self):
        return f"<ASD {self.name} - CF: {self.codice_fiscale}>"


class ASDMember(Base):
    """
    Socio ASD (studente/praticante).

    🎯 MEMBERSHIP MANAGEMENT: Gestione soci con quote associative
    """
    __tablename__ = "asd_members"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    asd_id = Column(GUID(), ForeignKey("asds.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === MEMBERSHIP ===
    member_number = Column(String(50), nullable=True)  # Numero tessera
    status = Column(String(50), default="active", nullable=False)  # active, suspended, expired

    # === QUOTA ASSOCIATIVA ===
    membership_fee = Column(Integer, nullable=True)  # Euro centesimi
    fee_valid_from = Column(DateTime, nullable=True)
    fee_valid_until = Column(DateTime, nullable=True)
    fee_paid = Column(Boolean, default=False, nullable=False)

    # === DOCUMENTS ===
    medical_certificate_url = Column(Text, nullable=True)  # Certificato medico
    medical_certificate_expiry = Column(DateTime, nullable=True)

    # === METADATA ===
    joined_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    asd = relationship("ASD", back_populates="members")
    user = relationship("User", backref="asd_memberships")

    __table_args__ = (
        Index('idx_asd_member_user', 'asd_id', 'user_id'),
        Index('idx_asd_member_status', 'status', 'joined_at'),
    )

    def is_membership_valid(self) -> bool:
        """Check if membership is valid and paid."""
        if not self.fee_valid_until:
            return False
        return (
            self.status == "active"
            and self.fee_paid
            and self.fee_valid_until > datetime.utcnow()
        )

    def needs_medical_certificate_renewal(self) -> bool:
        """Check if medical certificate needs renewal."""
        if not self.medical_certificate_expiry:
            return True
        # Alert 30 giorni prima
        from datetime import timedelta
        return datetime.utcnow() > (self.medical_certificate_expiry - timedelta(days=30))

    def __repr__(self):
        return f"<ASDMember {self.user_id} - {self.asd_id}>"

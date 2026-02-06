"""
AI_MODULE: Royalty Database Models
AI_DESCRIPTION: SQLAlchemy models per sistema royalties parametrizzabile
AI_BUSINESS: Storage persistente per profili maestri, abbonamenti, views, payouts
AI_TEACHING: SQLAlchemy ORM, relationships, indexes, business methods

ALTERNATIVE_VALUTATE:
- MongoDB: Scartato, meno adatto per transazioni finanziarie
- Raw SQL: Scartato, manutenibilita inferiore
- SQLModel: Scartato, meno maturo di SQLAlchemy

PERCHE_QUESTA_SOLUZIONE:
- SQLAlchemy: Standard industry, ORM maturo
- Indexes ottimizzati: Query veloci su views/payouts
- Relationships: Navigazione naturale tra entita
- Business methods: Logica incapsulata nei models

METRICHE_SUCCESSO:
- Query time views: <50ms (con index)
- Query time dashboard: <200ms
- Data integrity: 100% (constraints)

RELATIONSHIPS:
MasterProfile 1 ────── N ViewRoyalty
MasterProfile 1 ────── N RoyaltyPayout
MasterProfile N ────── 1 User (maestro)
StudentSubscription N ── 1 User (student)
StudentSubscription N ── 1 MasterProfile (optional)
ViewRoyalty N ────────── 1 Video
ViewRoyalty N ────────── 1 ViewSession
"""

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Float,
    ForeignKey, Text, Index, Numeric, UniqueConstraint
)
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# ======================== ENUMS ========================

class PricingModel(str, enum.Enum):
    """
    Modello pricing del maestro.

    FREE: Tutti i contenuti gratuiti
    INCLUDED: Incluso in abbonamento piattaforma
    PREMIUM: Richiede abbonamento specifico maestro
    CUSTOM: Prezzi personalizzati per contenuto
    """
    FREE = "free"
    INCLUDED = "included"
    PREMIUM = "premium"
    CUSTOM = "custom"


class PayoutMethod(str, enum.Enum):
    """
    Metodo pagamento preferito dal maestro.

    BLOCKCHAIN: Pagamento diretto su wallet crypto
    STRIPE: Pagamento via Stripe Connect
    BANK: Bonifico bancario tradizionale
    PAYPAL: Pagamento via PayPal
    """
    BLOCKCHAIN = "blockchain"
    STRIPE = "stripe"
    BANK = "bank"
    PAYPAL = "paypal"


class PayoutStatus(str, enum.Enum):
    """
    Status di un payout.

    PENDING: In attesa di processamento
    PROCESSING: In elaborazione
    COMPLETED: Completato con successo
    FAILED: Fallito (vedi error_message)
    CANCELLED: Cancellato dal sistema/admin
    """
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SubscriptionType(str, enum.Enum):
    """
    Tipo abbonamento studente.

    PLATFORM: Abbonamento piattaforma generale
    MASTER: Abbonamento specifico maestro
    PER_VIDEO: Acquisto singolo video
    """
    PLATFORM = "platform"
    MASTER = "master"
    PER_VIDEO = "per_video"


class StudentMasterMode(str, enum.Enum):
    """
    Modalita relazione studente-maestro.

    SINGLE: Un solo maestro alla volta
    MULTIPLE: Piu maestri contemporaneamente
    """
    SINGLE = "single"
    MULTIPLE = "multiple"


class RoyaltyMilestone(str, enum.Enum):
    """
    Milestone di visualizzazione per calcolo royalty.

    STARTED: Video iniziato (>5 secondi)
    PERCENT_25: Raggiunto 25%
    PERCENT_50: Raggiunto 50%
    PERCENT_75: Raggiunto 75%
    COMPLETED: Video completato (>90%)
    """
    STARTED = "started"
    PERCENT_25 = "25"
    PERCENT_50 = "50"
    PERCENT_75 = "75"
    COMPLETED = "completed"


# ======================== MODELS ========================

class MasterProfile(Base):
    """
    Profilo maestro per sistema royalties.

    Estende il Maestro esistente con configurazioni
    specifiche per royalties e pagamenti.
    Un maestro puo avere pricing model e settings custom.
    """
    __tablename__ = "royalty_master_profiles"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True
    )
    maestro_id = Column(
        GUID(),
        ForeignKey("maestros.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )

    # === PRICING MODEL ===
    pricing_model = Column(
        String(50),
        default=PricingModel.INCLUDED.value,
        nullable=False,
        index=True
    )
    # Override prezzi per subscription type (JSON)
    # Es: {"monthly": 1499, "yearly": 14999}
    custom_prices = Column(JSONBType(), nullable=True)

    # === ROYALTY OVERRIDE ===
    # Override % royalties (null = usa config globale)
    # Es: {"platform_fee_percent": 25, "master_share_percent": 75}
    royalty_override = Column(JSONBType(), nullable=True)

    # === MILESTONE OVERRIDE ===
    # Override importi milestone (null = usa config globale)
    # Es: {"view_started": 0.002, "view_completed": 0.02}
    milestone_override = Column(JSONBType(), nullable=True)

    # === PAYMENT SETTINGS ===
    wallet_address = Column(String(42), nullable=True)  # Ethereum address 0x...
    payout_method = Column(
        String(50),
        default=PayoutMethod.STRIPE.value,
        nullable=False
    )

    # Override minimo payout (null = usa config globale)
    min_payout_override = Column(Integer, nullable=True)

    # === BANKING FALLBACK ===
    iban = Column(String(34), nullable=True)
    paypal_email = Column(String(255), nullable=True)
    stripe_connect_account_id = Column(String(100), nullable=True)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    verified_for_payouts = Column(Boolean, default=False, nullable=False)
    verification_date = Column(DateTime, nullable=True)

    # === STATS (denormalized for performance) ===
    total_views = Column(Integer, default=0, nullable=False)
    total_royalties_cents = Column(Integer, default=0, nullable=False)
    total_paid_out_cents = Column(Integer, default=0, nullable=False)
    pending_payout_cents = Column(Integer, default=0, nullable=False)
    total_subscribers = Column(Integer, default=0, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    last_payout_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    user = relationship("User", backref="royalty_profile")
    view_royalties = relationship("ViewRoyalty", back_populates="master_profile", cascade="all, delete-orphan")
    payouts = relationship("RoyaltyPayout", back_populates="master_profile", cascade="all, delete-orphan")
    subscriptions = relationship("StudentSubscription", back_populates="master_profile")

    __table_args__ = (
        Index('idx_royalty_master_pricing', 'pricing_model', 'is_active'),
        Index('idx_royalty_master_pending', 'pending_payout_cents', 'is_active'),
    )

    # === BUSINESS METHODS ===

    def get_effective_pricing(self, subscription_type: str, global_config: dict) -> int:
        """
        Ottiene prezzo effettivo per tipo abbonamento.

        Priorita: custom_prices > global_config > default

        Args:
            subscription_type: Tipo abbonamento (monthly/yearly/etc)
            global_config: Config globale subscription_types

        Returns:
            Prezzo in centesimi
        """
        if self.custom_prices and subscription_type in self.custom_prices:
            return self.custom_prices[subscription_type]

        if subscription_type in global_config:
            return global_config[subscription_type].get("price_cents", 0)

        return 0

    def get_effective_royalty_split(self, global_config: dict) -> dict:
        """
        Ottiene split royalty effettivo.

        Args:
            global_config: Config globale revenue_split

        Returns:
            Dict con platform_fee_percent e master_share_percent
        """
        if self.royalty_override:
            return self.royalty_override
        return global_config

    def get_effective_milestone_amount(self, milestone: str, global_config: dict) -> float:
        """
        Ottiene importo milestone effettivo.

        Args:
            milestone: Nome milestone (started/25/50/75/completed)
            global_config: Config globale milestones

        Returns:
            Importo in EUR
        """
        if self.milestone_override:
            key = f"view_{milestone}" if milestone != "started" else "view_started"
            if milestone.isdigit():
                key = f"view_{milestone}_percent"
            if key in self.milestone_override:
                return self.milestone_override[key]

        return global_config.get_amount_for_milestone(milestone)

    def get_effective_min_payout(self, global_min: int) -> int:
        """
        Ottiene minimo payout effettivo.

        Args:
            global_min: Minimo globale in centesimi

        Returns:
            Minimo in centesimi
        """
        if self.min_payout_override is not None:
            return self.min_payout_override
        return global_min

    def can_request_payout(self, global_min: int) -> bool:
        """
        Check se puo richiedere payout.

        Args:
            global_min: Minimo globale in centesimi

        Returns:
            True se pending >= min_payout
        """
        min_payout = self.get_effective_min_payout(global_min)
        return self.pending_payout_cents >= min_payout

    def __repr__(self):
        return f"<MasterProfile {self.user_id} - {self.pricing_model.value}>"


class StudentSubscription(Base):
    """
    Abbonamento studente a piattaforma o maestro specifico.

    Traccia tutti gli abbonamenti attivi e storici.
    master_id=NULL indica abbonamento piattaforma generale.
    """
    __tablename__ = "royalty_student_subscriptions"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    student_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    master_id = Column(
        GUID(),
        ForeignKey("royalty_master_profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    # === SUBSCRIPTION DETAILS ===
    subscription_type = Column(
        String(50),
        nullable=False,
        index=True
    )
    subscription_tier = Column(String(50), nullable=False)  # monthly/yearly/lifetime/per_video
    price_paid_cents = Column(Integer, nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)

    # === DATES ===
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)  # NULL = lifetime
    cancelled_at = Column(DateTime, nullable=True)

    # === RENEWAL ===
    auto_renew = Column(Boolean, default=True, nullable=False)
    renewal_price_cents = Column(Integer, nullable=True)  # Prezzo prossimo rinnovo

    # === PAYMENT ===
    stripe_subscription_id = Column(String(100), nullable=True, index=True)
    stripe_payment_intent_id = Column(String(100), nullable=True)

    # === VIDEO SPECIFICO (per per_video) ===
    video_id = Column(
        GUID(),
        ForeignKey("videos.id", ondelete="SET NULL"),
        nullable=True
    )

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    student = relationship("User", backref="master_subscriptions")
    master_profile = relationship("MasterProfile", back_populates="subscriptions")

    __table_args__ = (
        Index('idx_subscription_active', 'is_active', 'expires_at'),
        Index('idx_subscription_student_master', 'student_id', 'master_id', 'is_active'),
        UniqueConstraint(
            'student_id', 'master_id', 'subscription_tier',
            name='uq_student_master_tier',
            # Solo se entrambi non-null
        ),
    )

    # === BUSINESS METHODS ===

    def is_subscription_active(self) -> bool:
        """
        Check se abbonamento attivo.

        Returns:
            True se is_active AND (expires_at is NULL OR expires_at > now)
        """
        if not self.is_active:
            return False

        if self.expires_at is None:
            return True  # Lifetime

        return self.expires_at > datetime.utcnow()

    def days_until_expiry(self) -> int:
        """
        Giorni rimanenti alla scadenza.

        Returns:
            Giorni (-1 se lifetime, 0 se scaduto)
        """
        if self.expires_at is None:
            return -1  # Lifetime

        delta = self.expires_at - datetime.utcnow()
        return max(0, delta.days)

    def __repr__(self):
        master = self.master_id or "platform"
        return f"<StudentSubscription {self.student_id} -> {master}>"


class ViewRoyalty(Base):
    """
    Singola royalty generata da view video.

    Ogni milestone raggiunto genera un record separato.
    Supporta tracking blockchain per verificabilita.
    """
    __tablename__ = "royalty_view_royalties"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === REFERENCES ===
    video_id = Column(
        GUID(),
        ForeignKey("videos.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    master_id = Column(
        GUID(),
        ForeignKey("royalty_master_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    student_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    view_session_id = Column(GUID(), nullable=False, index=True)  # Session tracking

    # === MILESTONE ===
    milestone = Column(
        String(50),
        nullable=False,
        index=True
    )

    # === AMOUNTS ===
    gross_amount_cents = Column(Integer, nullable=False)  # Importo lordo
    platform_fee_cents = Column(Integer, nullable=False)  # Fee piattaforma
    master_amount_cents = Column(Integer, nullable=False)  # Netto maestro

    # === BLOCKCHAIN ===
    blockchain_batch_id = Column(GUID(), nullable=True, index=True)
    blockchain_tx_hash = Column(String(66), nullable=True)
    blockchain_verified = Column(Boolean, default=False, nullable=False)

    # === SETTLEMENT ===
    settled = Column(Boolean, default=False, nullable=False, index=True)
    settled_at = Column(DateTime, nullable=True)
    payout_id = Column(
        GUID(),
        ForeignKey("royalty_payouts.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )

    # === FRAUD DETECTION ===
    fraud_score = Column(Float, default=0.0, nullable=False)
    flagged_suspicious = Column(Boolean, default=False, nullable=False, index=True)
    flag_reason = Column(String(255), nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    video_duration_seconds = Column(Integer, nullable=True)
    watch_time_seconds = Column(Integer, nullable=True)

    # === CONTEXT ===
    ip_hash = Column(String(64), nullable=True)  # SHA256 IP per fraud detection
    device_fingerprint = Column(String(64), nullable=True)
    country_code = Column(String(2), nullable=True)

    # === RELATIONSHIPS ===
    master_profile = relationship("MasterProfile", back_populates="view_royalties")

    __table_args__ = (
        Index('idx_royalty_unsettled', 'settled', 'master_id', 'created_at'),
        Index('idx_royalty_session', 'view_session_id', 'milestone'),
        Index('idx_royalty_blockchain', 'blockchain_batch_id', 'blockchain_verified'),
        Index('idx_royalty_fraud', 'flagged_suspicious', 'fraud_score'),
        # Prevent duplicate milestones per session
        UniqueConstraint(
            'view_session_id', 'milestone',
            name='uq_session_milestone'
        ),
    )

    def __repr__(self):
        return f"<ViewRoyalty {self.view_session_id} - {self.milestone}>"


class RoyaltyPayout(Base):
    """
    Pagamento royalties effettuato a maestro.

    Traccia tutti i payout con dettagli transazione.
    Supporta multiple payment methods.
    """
    __tablename__ = "royalty_payouts"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    master_id = Column(
        GUID(),
        ForeignKey("royalty_master_profiles.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # === AMOUNTS ===
    gross_amount_cents = Column(Integer, nullable=False)  # Totale lordo
    fees_cents = Column(Integer, default=0, nullable=False)  # Fees transazione
    net_amount_cents = Column(Integer, nullable=False)  # Netto pagato

    currency = Column(String(3), default="EUR", nullable=False)

    # === PERIOD ===
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    views_count = Column(Integer, default=0, nullable=False)

    # === PAYMENT METHOD ===
    method = Column(
        String(50),
        nullable=False,
        index=True
    )

    # === BLOCKCHAIN (if method=BLOCKCHAIN) ===
    blockchain_tx_hash = Column(String(66), nullable=True, index=True)
    blockchain_network = Column(String(20), nullable=True)
    blockchain_confirmations = Column(Integer, default=0, nullable=False)
    wallet_address = Column(String(42), nullable=True)

    # === STRIPE (if method=STRIPE) ===
    stripe_transfer_id = Column(String(100), nullable=True)
    stripe_payout_id = Column(String(100), nullable=True)

    # === BANK (if method=BANK) ===
    bank_reference = Column(String(100), nullable=True)
    iban = Column(String(34), nullable=True)

    # === STATUS ===
    status = Column(
        String(50),
        default=PayoutStatus.PENDING.value,
        nullable=False,
        index=True
    )
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    requested_at = Column(DateTime, nullable=True)  # Quando maestro ha richiesto
    processed_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    failed_at = Column(DateTime, nullable=True)

    # === ADMIN ===
    approved_by = Column(GUID(), nullable=True)  # Admin che ha approvato
    notes = Column(Text, nullable=True)

    # === RELATIONSHIPS ===
    master_profile = relationship("MasterProfile", back_populates="payouts")
    royalties = relationship("ViewRoyalty", backref="payout")

    __table_args__ = (
        Index('idx_payout_status', 'status', 'created_at'),
        Index('idx_payout_master_status', 'master_id', 'status'),
        Index('idx_payout_period', 'period_start', 'period_end'),
    )

    # === BUSINESS METHODS ===

    def can_retry(self, max_retries: int = 3) -> bool:
        """
        Check se payout puo essere ritentato.

        Args:
            max_retries: Numero massimo tentativi

        Returns:
            True se status=FAILED e retry_count < max_retries
        """
        return (
            self.status == PayoutStatus.FAILED
            and self.retry_count < max_retries
        )

    def mark_processing(self):
        """Marca payout come in elaborazione."""
        self.status = PayoutStatus.PROCESSING
        self.processed_at = datetime.utcnow()

    def mark_completed(self, tx_hash: str = None):
        """
        Marca payout come completato.

        Args:
            tx_hash: Hash transazione blockchain (optional)
        """
        self.status = PayoutStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        if tx_hash:
            self.blockchain_tx_hash = tx_hash

    def mark_failed(self, error: str):
        """
        Marca payout come fallito.

        Args:
            error: Messaggio errore
        """
        self.status = PayoutStatus.FAILED
        self.failed_at = datetime.utcnow()
        self.error_message = error
        self.retry_count += 1

    def __repr__(self):
        return f"<RoyaltyPayout {self.id} - {self.status.value} - {self.net_amount_cents}c>"


class RoyaltyBlockchainBatch(Base):
    """
    Batch di royalties per submission blockchain.

    Raggruppa multiple ViewRoyalty in un singolo Merkle tree
    per efficienza gas.
    """
    __tablename__ = "royalty_blockchain_batches"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === MERKLE TREE ===
    merkle_root = Column(String(66), nullable=False, index=True)
    merkle_tree_json = Column(JSONBType(), nullable=True)  # Full tree per proof
    leaves_count = Column(Integer, nullable=False)

    # === TOTALS ===
    total_views = Column(Integer, nullable=False)
    total_amount_cents = Column(Integer, nullable=False)

    # === BLOCKCHAIN ===
    tx_hash = Column(String(66), nullable=True, index=True)
    blockchain_batch_id = Column(Integer, nullable=True)  # ID on-chain
    blockchain_network = Column(String(20), nullable=False)
    status = Column(String(20), default="pending", nullable=False, index=True)
    confirmations = Column(Integer, default=0, nullable=False)

    # === GAS ===
    gas_used = Column(Integer, nullable=True)
    gas_price_gwei = Column(Numeric(10, 2), nullable=True)
    gas_cost_cents = Column(Integer, nullable=True)

    # === IPFS ===
    ipfs_hash = Column(String(100), nullable=True)
    ipfs_pinned = Column(Boolean, default=False, nullable=False)

    # === TIMESTAMPS ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    submitted_at = Column(DateTime, nullable=True)
    confirmed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index('idx_batch_status', 'status', 'created_at'),
        Index('idx_batch_merkle', 'merkle_root'),
    )

    def __repr__(self):
        return f"<RoyaltyBlockchainBatch {self.id} - {self.status}>"


class MasterSwitchHistory(Base):
    """
    Storico cambi maestro per studente.

    Traccia quando studente cambia maestro seguito
    per enforcing cooldown period.
    """
    __tablename__ = "royalty_master_switch_history"

    # === IDENTITY ===
    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    student_id = Column(
        GUID(),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )

    # === SWITCH DETAILS ===
    from_master_id = Column(GUID(), nullable=True)  # NULL = primo maestro
    to_master_id = Column(GUID(), nullable=False)
    switched_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # === REASON ===
    reason = Column(String(255), nullable=True)

    __table_args__ = (
        Index('idx_switch_student', 'student_id', 'switched_at'),
    )

    def __repr__(self):
        return f"<MasterSwitch {self.student_id}: {self.from_master_id} -> {self.to_master_id}>"

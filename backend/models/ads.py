"""
================================================================================
AI_MODULE: Ads & Blockchain Models
AI_DESCRIPTION: AdsSession, AdInventory, PauseAd, PauseAdImpression, BlockchainBatch
AI_BUSINESS: Ads batch unlock + pause ads overlay + blockchain consensus tracking
AI_TEACHING: Business logic complessa in models + consensus protocol + pause ads

ALTERNATIVE_VALUTATE:
- Single ads table: Scartata perché pause ads hanno logica diversa
- NoSQL per impressions: Scartata perché necessita join con users/videos
- Separate DB per blockchain: Scartata perché consensus richiede join

PERCHE_QUESTA_SOLUZIONE:
- Modelli separati per batch ads vs pause ads (diversi use case)
- Tracking granulare impressions per blockchain audit
- Relazioni SQLAlchemy per query efficienti

METRICHE_SUCCESSO:
- Query pause ads: < 50ms
- Impression insert: < 10ms
- Batch aggregation: < 5s per 1M records

INTEGRATION_DEPENDENCIES:
- Upstream: models/user.py, models/video.py
- Downstream: modules/ads, modules/blockchain, api/v1/ads

BUSINESS FLOW:
1. User starts ads batch session (batch unlock)
2. Watches X minutes of ads, unlocks Y videos for Z hours
3. User pauses video -> Pause Ad overlay (50/50)
4. Impressions/clicks tracked for blockchain
5. Weekly batch consensus among store nodes
6. Publish to Polygon for transparent audit
================================================================================
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text, Enum, Index
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import uuid
import enum

from core.database import Base
from models import GUID, ArrayType, JSONBType


# === ENUMS ===

class AdsBatchType(str, enum.Enum):
    """Ads batch types."""
    BATCH_3 = "3_video"   # 3 min ads → 3 video × 24h
    BATCH_5 = "5_video"   # 5 min ads → 5 video × 24h
    BATCH_10 = "10_video" # 10 min ads → 10 video × 48h


class AdsSessionStatus(str, enum.Enum):
    """Ads session status."""
    ACTIVE = "active"
    COMPLETED = "completed"
    ABANDONED = "abandoned"
    FAILED = "failed"


class ConsensusStatus(str, enum.Enum):
    """Blockchain batch consensus status."""
    PENDING = "pending"             # Batch creato, waiting validations
    VALIDATING = "validating"       # Nodi stanno validando
    CONSENSUS_REACHED = "consensus_reached"  # 51%+ agreement
    CONSENSUS_FAILED = "consensus_failed"    # <51% agreement
    PUBLISHED = "published"         # Pubblicato su blockchain
    FAILED = "failed"              # Pubblicazione fallita


# === MODELS ===

class AdsSession(Base):
    """
    Ads batch unlock session.

    🎯 MONETIZATION: Track ads viewing per unlock video
    """
    __tablename__ = "ads_sessions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === BATCH CONFIG ===
    batch_type = Column(Enum(AdsBatchType), nullable=False)
    ads_required_duration = Column(Integer, nullable=False)  # seconds (180, 300, 600)
    videos_to_unlock = Column(Integer, nullable=False)       # 3, 5, 10
    validity_hours = Column(Integer, nullable=False)         # 24, 24, 48

    # === PROGRESS ===
    status = Column(
        Enum(AdsSessionStatus, values_callable=lambda x: [e.value for e in x], name='adssessionstatus', create_type=False),
        default=AdsSessionStatus.ACTIVE, nullable=False
    )
    ads_watched = Column(JSONBType(), default=list, nullable=False)  # [{"ad_id": "...", "duration": 30, "watched_at": "..."}]
    total_duration_watched = Column(Integer, default=0, nullable=False)  # seconds
    progress_percentage = Column(Float, default=0.0, nullable=False)

    # === ANTI-FRAUD ===
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    fraud_score = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0

    # === REVENUE ===
    estimated_revenue = Column(Float, default=0.0, nullable=False)  # CPM-based

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index('idx_ads_sessions_user_status', 'user_id', 'status'),
        Index('idx_ads_sessions_created', 'created_at'),
    )

    # === BUSINESS METHODS ===

    def is_complete(self) -> bool:
        """Check if ads session completed."""
        return self.total_duration_watched >= self.ads_required_duration

    def get_unlocked_until(self) -> datetime:
        """Get expiry datetime for unlocked videos."""
        if self.completed_at:
            return self.completed_at + timedelta(hours=self.validity_hours)
        return datetime.utcnow()

    def calculate_revenue(self, cpm_rate: float = 3.00) -> float:
        """
        Calculate revenue from ads.

        🎯 CPM MODEL: €3.00 per 1000 views
        - 1 ad view = 1 impression
        - 3 min = ~6 ads (30s each)
        - Revenue = (ads_count / 1000) * CPM

        Returns: Revenue in EUR
        """
        ads_count = len(self.ads_watched) if isinstance(self.ads_watched, list) else 0
        return (ads_count / 1000.0) * cpm_rate


class AdInventory(Base):
    """
    Ad inventory con targeting.

    🎯 ADS MANAGEMENT: Pool di ads disponibili
    """
    __tablename__ = "ad_inventory"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === AD CONTENT ===
    title = Column(String(255), nullable=False)
    advertiser = Column(String(255), nullable=False)
    video_url = Column(Text, nullable=False)
    thumbnail_url = Column(Text, nullable=True)
    duration = Column(Integer, nullable=False)  # seconds

    # === TARGETING ===
    target_tiers = Column(ArrayType(String), default=["free", "hybrid_light"], nullable=False)
    target_countries = Column(ArrayType(String), default=["IT", "EU"], nullable=False)
    target_age_min = Column(Integer, nullable=True)
    target_age_max = Column(Integer, nullable=True)

    # === PRICING ===
    cpm_rate = Column(Float, nullable=False)  # Cost per 1000 impressions
    budget_remaining = Column(Float, default=0.0, nullable=False)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)

    # === ANALYTICS ===
    impressions = Column(Integer, default=0, nullable=False)
    clicks = Column(Integer, default=0, nullable=False)
    total_revenue = Column(Float, default=0.0, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index('idx_ad_inventory_active', 'is_active', 'start_date', 'end_date'),
    )


class BlockchainBatch(Base):
    """
    Weekly blockchain batch con consensus.

    🎯 BLOCKCHAIN: Aggregate views + consensus + publish Polygon
    """
    __tablename__ = "blockchain_batches"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === BATCH PERIOD ===
    batch_date = Column(DateTime, nullable=False, index=True)  # Week start date
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)

    # === DATA ===
    total_views = Column(Integer, nullable=False)
    unique_users = Column(Integer, nullable=False)
    total_watch_time = Column(Integer, nullable=False)  # seconds
    total_revenue = Column(Float, nullable=False)  # EUR

    # === HASH ===
    data_hash = Column(String(66), nullable=False, unique=True)  # SHA256 hex
    merkle_root = Column(String(66), nullable=True)

    # === CONSENSUS ===
    consensus_status = Column(Enum(ConsensusStatus), default=ConsensusStatus.PENDING, nullable=False, index=True)
    consensus_threshold = Column(Float, default=0.51, nullable=False)
    validations_received = Column(Integer, default=0, nullable=False)
    validations_required = Column(Integer, nullable=True)  # Min 51% of active nodes

    # === BLOCKCHAIN ===
    published_to_blockchain = Column(Boolean, default=False, nullable=False)
    blockchain_tx_hash = Column(String(66), nullable=True)  # Polygon tx hash
    blockchain_block_number = Column(Integer, nullable=True)
    published_at = Column(DateTime, nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    validations = relationship("NodeValidation", back_populates="batch", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_blockchain_batch_date', 'batch_date'),
        Index('idx_blockchain_status', 'consensus_status', 'created_at'),
    )

    # === BUSINESS METHODS ===

    def calculate_consensus_rate(self) -> float:
        """
        Calculate consensus agreement rate.

        Returns: 0.0 - 1.0 (percentage)
        """
        if not self.validations_required or self.validations_required == 0:
            return 0.0

        return self.validations_received / self.validations_required

    def has_consensus(self) -> bool:
        """Check if consensus threshold reached."""
        return self.calculate_consensus_rate() >= self.consensus_threshold

    def can_publish(self) -> bool:
        """Check if batch ready for blockchain publication."""
        return (
            self.consensus_status == ConsensusStatus.CONSENSUS_REACHED
            and not self.published_to_blockchain
            and self.has_consensus()
        )


class StoreNode(Base):
    """
    Store node per consensus.

    🎯 DECENTRALIZATION: Ogni negozio = validatore
    """
    __tablename__ = "store_nodes"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === NODE IDENTITY ===
    node_name = Column(String(255), nullable=False)
    node_address = Column(String(255), nullable=False)  # URL or location
    wallet_address = Column(String(42), unique=True, nullable=False)  # Ethereum address

    # === PUBLIC KEY ===
    public_key = Column(Text, nullable=False)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    is_trusted = Column(Boolean, default=True, nullable=False)  # Blacklist if malicious

    # === ANALYTICS ===
    total_validations = Column(Integer, default=0, nullable=False)
    uptime_percentage = Column(Float, default=100.0, nullable=False)
    last_validation_at = Column(DateTime, nullable=True)

    # === METADATA ===
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    validations = relationship("NodeValidation", back_populates="node")

    __table_args__ = (
        Index('idx_store_nodes_active', 'is_active', 'is_trusted'),
    )


class NodeValidation(Base):
    """
    Node validation per batch.

    🎯 CONSENSUS: Ogni nodo valida il batch hash
    """
    __tablename__ = "node_validations"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    batch_id = Column(GUID(), ForeignKey("blockchain_batches.id", ondelete="CASCADE"), nullable=False)
    node_id = Column(GUID(), ForeignKey("store_nodes.id", ondelete="CASCADE"), nullable=False)

    # === VALIDATION DATA ===
    data_hash = Column(String(66), nullable=False)
    agrees = Column(Boolean, nullable=False)  # True if hash matches

    # === SIGNATURE ===
    signature = Column(Text, nullable=False)  # Cryptographic signature

    # === METADATA ===
    validated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    batch = relationship("BlockchainBatch", back_populates="validations")
    node = relationship("StoreNode", back_populates="validations")

    __table_args__ = (
        Index('idx_node_validations_batch', 'batch_id', 'agrees'),
        Index('idx_node_validations_node', 'node_id', 'validated_at'),
    )


# === PAUSE ADS MODELS ===

class PauseAd(Base):
    """
    Pause ad inventory - ads mostrati durante pausa video.

    🎯 NETFLIX-STYLE PAUSE ADS: Overlay 50/50 quando utente mette in pausa
    - Lato sinistro: Video suggerito (engagement interno)
    - Lato destro: Sponsor ad (monetizzazione)

    BUSINESS_PURPOSE: Monetizzazione non intrusiva per tier FREE/HYBRID
    CPM premium €5.00 perché user-initiated (non interrompe viewing)

    TARGETING: Solo utenti con tier in ["free", "hybrid_light", "hybrid_standard"]
    """
    __tablename__ = "pause_ads"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === ADVERTISER INFO ===
    advertiser_name = Column(String(255), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # === CREATIVE ASSETS ===
    image_url = Column(Text, nullable=False)  # 600x400 recommended
    click_url = Column(Text, nullable=False)  # Destination URL on click

    # === PRICING ===
    cpm_rate = Column(Float, nullable=False, default=5.0)  # EUR per 1000 impressions

    # === TARGETING ===
    target_tiers = Column(ArrayType(String), default=["free", "hybrid_light", "hybrid_standard"], nullable=False)
    target_countries = Column(ArrayType(String), default=["IT"], nullable=True)
    target_styles = Column(ArrayType(String), nullable=True)  # e.g., ["karate", "judo"]

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    start_date = Column(DateTime, nullable=False)
    end_date = Column(DateTime, nullable=False)

    # === BUDGET ===
    budget_total = Column(Float, default=1000.0, nullable=False)  # EUR
    budget_remaining = Column(Float, default=1000.0, nullable=False)
    daily_cap = Column(Integer, default=10000, nullable=True)  # Max impressions/day

    # === ANALYTICS ===
    impressions = Column(Integer, default=0, nullable=False)
    clicks = Column(Integer, default=0, nullable=False)
    total_revenue = Column(Float, default=0.0, nullable=False)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    impressions_records = relationship("PauseAdImpression", back_populates="pause_ad", cascade="all, delete-orphan")

    __table_args__ = (
        Index('idx_pause_ads_active_dates', 'is_active', 'start_date', 'end_date'),
        Index('idx_pause_ads_advertiser', 'advertiser_name'),
        Index('idx_pause_ads_cpm', 'cpm_rate'),
    )

    # === BUSINESS METHODS ===

    def is_valid(self) -> bool:
        """
        Check se ad e attivo e valido per essere mostrato.

        DECISION_TREE:
        1. is_active must be True
        2. Current date must be within start/end
        3. Budget must be > 0

        Returns: True se puo essere mostrato
        """
        now = datetime.utcnow()
        return (
            self.is_active
            and self.start_date <= now <= self.end_date
            and self.budget_remaining > 0
        )

    def calculate_ctr(self) -> float:
        """
        Calculate Click-Through Rate.

        Returns: CTR as percentage (0.0 - 100.0)
        """
        if self.impressions == 0:
            return 0.0
        return (self.clicks / self.impressions) * 100

    def calculate_effective_cpm(self) -> float:
        """
        Calculate effective CPM (revenue / 1000 impressions).

        Returns: eCPM in EUR
        """
        if self.impressions == 0:
            return 0.0
        return (self.total_revenue / self.impressions) * 1000

    def __repr__(self):
        return f"<PauseAd {self.advertiser_name}: {self.title}>"


class PauseAdImpression(Base):
    """
    Traccia ogni impression di pause ad per blockchain batch.

    🎯 GRANULAR TRACKING: Ogni singola impression per:
    - Billing accurato advertiser
    - Blockchain audit trail
    - Analytics dettagliati

    BUSINESS_PURPOSE: Dati granulari permettono:
    - Fatturazione precisa per advertiser
    - Aggregazione settimanale per blockchain
    - A/B testing e ottimizzazione
    """
    __tablename__ = "pause_ad_impressions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === FOREIGN KEYS ===
    pause_ad_id = Column(GUID(), ForeignKey("pause_ads.id", ondelete="SET NULL"), nullable=True)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    video_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)

    # === IMPRESSION TYPE ===
    impression_type = Column(String(20), default="pause", nullable=False)
    # Types: "pause" (overlay shown), "resume" (user resumed), "skip" (user dismissed)

    # === CLICK DATA ===
    clicked = Column(Boolean, default=False, nullable=False, index=True)
    click_type = Column(String(20), nullable=True)
    # Click types: "ad" (clicked sponsor), "suggested" (clicked suggested video), null (no click)

    # === BLOCKCHAIN BATCH ===
    included_in_batch = Column(Boolean, default=False, nullable=False, index=True)
    batch_id = Column(GUID(), ForeignKey("blockchain_batches.id", ondelete="SET NULL"), nullable=True)

    # === METADATA ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(Text, nullable=True)
    device_type = Column(String(20), nullable=True)  # "mobile", "tablet", "desktop"

    # === REVENUE TRACKING ===
    impression_revenue = Column(Float, default=0.005, nullable=False)  # CPM/1000
    click_revenue = Column(Float, default=0.0, nullable=False)  # €0.02 if clicked

    # === RELATIONSHIPS ===
    pause_ad = relationship("PauseAd", back_populates="impressions_records")

    __table_args__ = (
        Index('idx_pause_impressions_user', 'user_id', 'created_at'),
        Index('idx_pause_impressions_ad', 'pause_ad_id', 'created_at'),
        Index('idx_pause_impressions_batch', 'included_in_batch', 'created_at'),
        Index('idx_pause_impressions_clicks', 'clicked', 'click_type'),
    )

    # === BUSINESS METHODS ===

    def calculate_total_revenue(self) -> float:
        """
        Calculate total revenue for this impression.

        REVENUE MODEL:
        - Base impression: CPM/1000 = €0.005
        - Click bonus: +€0.02 if clicked on ad

        Returns: Total revenue in EUR
        """
        total = self.impression_revenue
        if self.clicked and self.click_type == "ad":
            total += 0.02  # Click bonus
        return total

    def __repr__(self):
        click_info = f", clicked={self.click_type}" if self.clicked else ""
        return f"<PauseAdImpression user={self.user_id}{click_info}>"

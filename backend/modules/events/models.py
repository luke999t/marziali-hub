"""
🎓 AI_MODULE: Events Database Models
🎓 AI_DESCRIPTION: SQLAlchemy models per eventi/stage ASD con Stripe Connect
🎓 AI_BUSINESS: Gestione eventi fisici, iscrizioni, split payment - CRITICO per LIBRA (90% ricavi)
🎓 AI_TEACHING: SQLAlchemy ORM, composite indexes, foreign keys, JSONB per config flessibile

🔄 ALTERNATIVE_VALUTATE:
- Separate tables per ogni tipo alert: Scartato, troppo rigido
- NoSQL per config: Scartato, ACID required per transazioni pagamento
- Single event_price: Scartato, serve supporto opzioni multiple (5gg, 3gg, 2gg)

💡 PERCHÉ_QUESTA_SOLUZIONE:
- JSONB per presale_criteria: Flessibilità massima sui criteri
- Capacità condivisa: total_capacity a livello evento, opzioni condividono
- Split payment: stripe_account_id per ASD, split automatico
- Soft delete: Eventi mai cancellati fisicamente, solo status change

TABELLE (8):
1. asd_partners: Partner ASD con Stripe Connect account
2. events: Eventi/stage con capacità e date
3. event_options: Opzioni durata con prezzi (5gg, 3gg, 2gg, etc.)
4. event_subscriptions: Iscrizioni utenti con payment info
5. event_waiting_list: Waiting list per eventi pieni
6. asd_refund_requests: Richieste rimborso da ASD
7. platform_alert_config: Configurazione alert globale piattaforma
8. event_notifications: Notifiche schedulate per eventi
"""

from sqlalchemy import (
    Column, String, Boolean, DateTime, Integer, Float,
    ForeignKey, Text, Index, UniqueConstraint, Date,
    CheckConstraint, Enum as SQLEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime, date, timedelta
import uuid
import enum

from core.database import Base
from models import GUID, JSONBType


# ======================== ENUMS ========================

class EventStatus(str, enum.Enum):
    """
    Status ciclo di vita evento.

    DRAFT: In preparazione, non visibile pubblicamente
    PRESALE: Prevendita attiva (solo utenti con criteri)
    OPEN: Vendita pubblica aperta
    SOLD_OUT: Tutto esaurito, waiting list attiva
    CLOSED: Iscrizioni chiuse
    ONGOING: Evento in corso
    COMPLETED: Evento terminato
    CANCELLED: Evento annullato (trigger refund)
    """
    DRAFT = "draft"
    PRESALE = "presale"
    OPEN = "open"
    SOLD_OUT = "sold_out"
    CLOSED = "closed"
    ONGOING = "ongoing"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class SubscriptionStatus(str, enum.Enum):
    """
    Status iscrizione utente.

    PENDING: In attesa pagamento
    CONFIRMED: Pagato e confermato
    CANCELLED: Annullato (da ASD o admin)
    REFUNDED: Rimborsato
    NO_SHOW: Non presentato
    ATTENDED: Ha partecipato
    """
    PENDING = "pending"
    CONFIRMED = "confirmed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"
    NO_SHOW = "no_show"
    ATTENDED = "attended"


class RefundStatus(str, enum.Enum):
    """
    Status richiesta rimborso.

    PENDING: In attesa approvazione
    APPROVED: Approvato, in elaborazione
    PROCESSED: Rimborso eseguito
    REJECTED: Rifiutato
    """
    PENDING = "pending"
    APPROVED = "approved"
    PROCESSED = "processed"
    REJECTED = "rejected"


class AlertType(str, enum.Enum):
    """
    Tipi di alert configurabili.

    EVENT_REMINDER: Promemoria evento (7/3/1 giorni prima)
    PRESALE_START: Inizio prevendita
    SALE_START: Inizio vendita pubblica
    LOW_CAPACITY: Posti in esaurimento
    THRESHOLD_WARNING: Sotto soglia minima iscritti
    WAITLIST_SPOT: Posto disponibile da waiting list
    REFUND_REQUEST: Nuova richiesta rimborso
    EVENT_CANCELLED: Evento annullato
    """
    EVENT_REMINDER = "event_reminder"
    PRESALE_START = "presale_start"
    SALE_START = "sale_start"
    LOW_CAPACITY = "low_capacity"
    THRESHOLD_WARNING = "threshold_warning"
    WAITLIST_SPOT = "waitlist_spot"
    REFUND_REQUEST = "refund_request"
    EVENT_CANCELLED = "event_cancelled"


class NotificationChannel(str, enum.Enum):
    """
    Canali notifica disponibili.
    """
    EMAIL = "email"
    PUSH = "push"
    DASHBOARD = "dashboard"
    SMS = "sms"  # Future


class PresaleCriteriaType(str, enum.Enum):
    """
    Tipi criteri prevendita.

    EMAIL_LIST: Lista email specifiche
    SUBSCRIPTION_ACTIVE: Abbonamento attivo
    COURSE_PURCHASED: Corso specifico acquistato
    LEARNING_PATH: Percorso completato/in corso
    TIER_MINIMUM: Tier minimo richiesto
    """
    EMAIL_LIST = "email_list"
    SUBSCRIPTION_ACTIVE = "subscription_active"
    COURSE_PURCHASED = "course_purchased"
    LEARNING_PATH = "learning_path"
    TIER_MINIMUM = "tier_minimum"


class RefundApprovalMode(str, enum.Enum):
    """
    Modalità approvazione rimborsi.

    ALWAYS_REQUIRED: Sempre richiesta approvazione admin
    NEVER_REQUIRED: Mai richiesta, ASD può rimborsare direttamente
    PER_EVENT: Configurabile per singolo evento
    """
    ALWAYS_REQUIRED = "always_required"
    NEVER_REQUIRED = "never_required"
    PER_EVENT = "per_event"


# ======================== MODELS ========================

class ASDPartner(Base):
    """
    Partner ASD (Associazione Sportiva Dilettantistica).

    🎯 BUSINESS: Ogni ASD può creare eventi e ricevere pagamenti via Stripe Connect.

    CAMPI CHIAVE:
    - stripe_account_id: Account Stripe Connect per split payment
    - default_split_percentage: Percentuale default per ASD (es. 85%)
    - refund_approval_mode: Come gestire approvazioni rimborsi
    """
    __tablename__ = "asd_partners"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === BASIC INFO ===
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    logo_url = Column(Text, nullable=True)
    website = Column(String(255), nullable=True)

    # === CONTACT ===
    email = Column(String(255), nullable=False)
    phone = Column(String(50), nullable=True)
    address = Column(Text, nullable=True)
    city = Column(String(100), nullable=True)
    province = Column(String(10), nullable=True)
    postal_code = Column(String(10), nullable=True)
    country = Column(String(100), default="Italia", nullable=False)

    # === LEGAL ===
    fiscal_code = Column(String(16), unique=True, nullable=True)  # Codice fiscale ASD
    vat_number = Column(String(20), nullable=True)  # P.IVA se presente

    # === ADMIN USER ===
    admin_user_id = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # === STRIPE CONNECT ===
    stripe_account_id = Column(String(255), unique=True, nullable=True)  # acct_xxx
    stripe_account_status = Column(String(50), default="pending", nullable=False)  # pending, active, restricted
    stripe_onboarding_complete = Column(Boolean, default=False, nullable=False)

    # === PAYMENT CONFIG ===
    default_split_percentage = Column(Float, default=85.0, nullable=False)  # % per ASD (LIBRA = 100 - this)

    # === REFUND POLICY ===
    refund_approval_mode = Column(
        SQLEnum(RefundApprovalMode, name='refund_approval_mode', values_callable=lambda x: [e.value for e in x]),
        default=RefundApprovalMode.PER_EVENT,
        nullable=False
    )

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    verified_at = Column(DateTime, nullable=True)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    admin_user = relationship("User", foreign_keys=[admin_user_id])
    events = relationship("Event", back_populates="asd_partner", lazy="selectin")
    refund_requests = relationship("ASDRefundRequest", back_populates="asd_partner", lazy="selectin")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_asd_partners_active', 'is_active'),
        Index('idx_asd_partners_stripe', 'stripe_account_id'),
    )

    def __repr__(self):
        return f"<ASDPartner {self.name} ({self.slug})>"


class Event(Base):
    """
    Evento/Stage organizzato da ASD.

    🎯 BUSINESS: Evento fisico con capacità, opzioni durata, prevendita, bundle.

    CAMPI CHIAVE:
    - total_capacity: Capacità CONDIVISA tra tutte le opzioni
    - current_subscriptions: Counter iscrizioni confermate
    - presale_criteria: JSONB con criteri prevendita flessibili
    - bundle_course_id: Opzionale, corso digitale incluso
    - requires_refund_approval: Override per singolo evento
    """
    __tablename__ = "events"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    asd_id = Column(GUID(), ForeignKey("asd_partners.id", ondelete="CASCADE"), nullable=False)

    # === BASIC INFO ===
    title = Column(String(255), nullable=False)
    slug = Column(String(150), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    short_description = Column(String(500), nullable=True)
    cover_image_url = Column(Text, nullable=True)

    # === DATES ===
    start_date = Column(Date, nullable=False, index=True)
    end_date = Column(Date, nullable=False)

    # === PRESALE DATES ===
    presale_start = Column(DateTime, nullable=True)
    presale_end = Column(DateTime, nullable=True)
    sale_start = Column(DateTime, nullable=True)  # Inizio vendita pubblica

    # === CAPACITY ===
    total_capacity = Column(Integer, nullable=False)  # Capacità TOTALE condivisa
    current_subscriptions = Column(Integer, default=0, nullable=False)  # Counter
    min_threshold = Column(Integer, nullable=True)  # Soglia minima per conferma evento

    # === LOCATION ===
    location_name = Column(String(255), nullable=True)
    location_address = Column(Text, nullable=True)
    location_city = Column(String(100), nullable=True)
    location_country = Column(String(100), default="Italia", nullable=False)
    location_coordinates = Column(JSONBType(), nullable=True)  # {"lat": x, "lng": y}

    # === PRESALE CRITERIA ===
    presale_enabled = Column(Boolean, default=False, nullable=False)
    presale_criteria = Column(JSONBType(), nullable=True)
    # Esempio struttura:
    # {
    #   "type": "email_list",
    #   "emails": ["vip1@email.com", "vip2@email.com"]
    # }
    # oppure:
    # {
    #   "type": "subscription_active",
    #   "subscription_types": ["premium", "business"]
    # }
    # oppure:
    # {
    #   "type": "course_purchased",
    #   "course_ids": ["uuid1", "uuid2"]
    # }

    # === BUNDLE ===
    bundle_course_id = Column(GUID(), ForeignKey("videos.id", ondelete="SET NULL"), nullable=True)
    bundle_discount_percent = Column(Float, default=0, nullable=False)

    # === PAYMENT ===
    split_percentage = Column(Float, nullable=True)  # Override ASD default, null = usa default

    # === REFUND POLICY ===
    requires_refund_approval = Column(Boolean, nullable=True)  # null = usa ASD default

    # === ALERT CONFIG OVERRIDE ===
    alert_config_override = Column(JSONBType(), nullable=True)
    # Esempio:
    # {
    #   "reminder_days": [7, 3, 1],
    #   "threshold_warning_enabled": true,
    #   "channels": {"email": true, "push": true, "dashboard": false}
    # }

    # === STATUS ===
    status = Column(
        SQLEnum(EventStatus, name='event_status', values_callable=lambda x: [e.value for e in x]),
        default=EventStatus.DRAFT,
        nullable=False,
        index=True
    )

    # === METADATA ===
    discipline = Column(String(100), nullable=True)  # Es: "Wing Chun", "Tai Chi"
    instructor_name = Column(String(255), nullable=True)
    instructor_bio = Column(Text, nullable=True)

    # === AUDIT ===
    created_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    published_at = Column(DateTime, nullable=True)
    cancelled_at = Column(DateTime, nullable=True)
    cancellation_reason = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    asd_partner = relationship("ASDPartner", back_populates="events")
    options = relationship("EventOption", back_populates="event", lazy="selectin", cascade="all, delete-orphan")
    subscriptions = relationship("EventSubscription", back_populates="event", lazy="selectin")
    waiting_list = relationship("EventWaitingList", back_populates="event", lazy="selectin")
    notifications = relationship("EventNotification", back_populates="event", lazy="selectin")
    creator = relationship("User", foreign_keys=[created_by])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_events_asd_status', 'asd_id', 'status'),
        Index('idx_events_dates', 'start_date', 'end_date'),
        Index('idx_events_presale', 'presale_start', 'presale_end'),
        CheckConstraint('end_date >= start_date', name='check_event_dates'),
        CheckConstraint('total_capacity > 0', name='check_event_capacity'),
        CheckConstraint('current_subscriptions >= 0', name='check_event_subscriptions'),
        CheckConstraint('current_subscriptions <= total_capacity', name='check_event_not_overbooked'),
    )

    @property
    def available_spots(self) -> int:
        """Posti disponibili."""
        return self.total_capacity - self.current_subscriptions

    @property
    def is_sold_out(self) -> bool:
        """Evento esaurito."""
        return self.current_subscriptions >= self.total_capacity

    @property
    def is_below_threshold(self) -> bool:
        """Sotto soglia minima."""
        if self.min_threshold is None:
            return False
        return self.current_subscriptions < self.min_threshold

    @property
    def duration_days(self) -> int:
        """Durata in giorni."""
        return (self.end_date - self.start_date).days + 1

    def __repr__(self):
        return f"<Event {self.title} ({self.status.value})>"


class EventOption(Base):
    """
    Opzione evento (es. 5 giorni, 3 giorni, 2 giorni).

    🎯 BUSINESS: Stesso evento con diverse durate/prezzi.
    La capacità è CONDIVISA con l'evento padre.

    ESEMPIO:
    Stage Wing Chun - Capacità totale: 50
    - Opzione 5 giorni: 450€
    - Opzione 3 giorni: 300€
    - Opzione 2 giorni: 200€

    Le 50 persone totali possono scegliere qualsiasi opzione.
    """
    __tablename__ = "event_options"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    event_id = Column(GUID(), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)

    # === OPTION INFO ===
    name = Column(String(100), nullable=False)  # Es: "5 giorni completo", "Weekend only"
    description = Column(Text, nullable=True)

    # === DATES ===
    start_date = Column(Date, nullable=False)  # Può essere subset delle date evento
    end_date = Column(Date, nullable=False)

    # === PRICING ===
    price_cents = Column(Integer, nullable=False)  # Prezzo in centesimi
    early_bird_price_cents = Column(Integer, nullable=True)  # Prezzo early bird
    early_bird_deadline = Column(DateTime, nullable=True)

    # === BUNDLE OVERRIDE ===
    includes_bundle = Column(Boolean, default=True, nullable=False)  # Include bundle corso?

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)
    sort_order = Column(Integer, default=0, nullable=False)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    event = relationship("Event", back_populates="options")
    subscriptions = relationship("EventSubscription", back_populates="option", lazy="selectin")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_event_options_event', 'event_id', 'is_active'),
        Index('idx_event_options_sort', 'event_id', 'sort_order'),
        CheckConstraint('price_cents > 0', name='check_option_price'),
        CheckConstraint('end_date >= start_date', name='check_option_dates'),
    )

    @property
    def current_price_cents(self) -> int:
        """Prezzo corrente (early bird se applicabile)."""
        if (
            self.early_bird_price_cents
            and self.early_bird_deadline
            and datetime.utcnow() < self.early_bird_deadline
        ):
            return self.early_bird_price_cents
        return self.price_cents

    @property
    def duration_days(self) -> int:
        """Durata opzione in giorni."""
        return (self.end_date - self.start_date).days + 1

    def __repr__(self):
        return f"<EventOption {self.name} - {self.price_cents/100}€>"


class EventSubscription(Base):
    """
    Iscrizione utente a evento.

    🎯 BUSINESS: Traccia pagamento, status, e dati per split payment.

    FLUSSO:
    1. Utente sceglie opzione
    2. Checkout Stripe con split payment
    3. Webhook conferma → status = CONFIRMED
    4. Post-evento → status = ATTENDED o NO_SHOW
    """
    __tablename__ = "event_subscriptions"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    event_id = Column(GUID(), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    option_id = Column(GUID(), ForeignKey("event_options.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === PAYMENT ===
    amount_cents = Column(Integer, nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)

    # Split payment tracking
    asd_amount_cents = Column(Integer, nullable=False)  # Quota ASD
    platform_amount_cents = Column(Integer, nullable=False)  # Quota LIBRA

    # Stripe
    stripe_payment_intent_id = Column(String(255), unique=True, nullable=True)
    stripe_transfer_id = Column(String(255), nullable=True)  # Transfer a ASD

    # === STATUS ===
    status = Column(
        SQLEnum(SubscriptionStatus, name='event_subscription_status', values_callable=lambda x: [e.value for e in x]),
        default=SubscriptionStatus.PENDING,
        nullable=False,
        index=True
    )

    # === BUNDLE ===
    bundle_course_granted = Column(Boolean, default=False, nullable=False)
    bundle_course_granted_at = Column(DateTime, nullable=True)

    # === PARTICIPANT INFO ===
    participant_name = Column(String(255), nullable=True)  # Se diverso da user
    participant_email = Column(String(255), nullable=True)
    participant_phone = Column(String(50), nullable=True)
    dietary_requirements = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)

    # === GDPR CONSENT ===
    gdpr_consent = Column(Boolean, default=False, nullable=False)
    gdpr_consent_at = Column(DateTime, nullable=True)
    gdpr_consent_ip = Column(String(45), nullable=True)  # IPv4/IPv6
    marketing_consent = Column(Boolean, default=False, nullable=False)
    marketing_consent_at = Column(DateTime, nullable=True)

    # === CANCELLATION ===
    cancelled_at = Column(DateTime, nullable=True)
    cancelled_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    cancellation_reason = Column(Text, nullable=True)

    # === REFUND ===
    refunded_at = Column(DateTime, nullable=True)
    refund_amount_cents = Column(Integer, nullable=True)
    stripe_refund_id = Column(String(255), nullable=True)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    confirmed_at = Column(DateTime, nullable=True)

    # === RELATIONSHIPS ===
    event = relationship("Event", back_populates="subscriptions")
    option = relationship("EventOption", back_populates="subscriptions")
    user = relationship("User", foreign_keys=[user_id])
    cancelled_by_user = relationship("User", foreign_keys=[cancelled_by])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_subscriptions_event_status', 'event_id', 'status'),
        Index('idx_subscriptions_user', 'user_id', 'status'),
        Index('idx_subscriptions_payment', 'stripe_payment_intent_id'),
        UniqueConstraint('event_id', 'user_id', name='uq_user_event_subscription'),
    )

    def __repr__(self):
        return f"<EventSubscription {self.user_id} -> {self.event_id} ({self.status.value})>"


class EventWaitingList(Base):
    """
    Waiting list per eventi sold out.

    🎯 BUSINESS: Quando si libera un posto, TUTTI in lista vengono notificati.
    Il primo che completa il pagamento vince.
    """
    __tablename__ = "event_waiting_list"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    event_id = Column(GUID(), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    # === PREFERRED OPTION ===
    preferred_option_id = Column(GUID(), ForeignKey("event_options.id", ondelete="SET NULL"), nullable=True)

    # === NOTIFICATION ===
    notified_at = Column(DateTime, nullable=True)  # Ultima notifica posto disponibile
    notification_count = Column(Integer, default=0, nullable=False)

    # === STATUS ===
    is_active = Column(Boolean, default=True, nullable=False)  # False se utente si cancella o ottiene posto
    converted_to_subscription = Column(Boolean, default=False, nullable=False)
    converted_at = Column(DateTime, nullable=True)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    event = relationship("Event", back_populates="waiting_list")
    user = relationship("User")
    preferred_option = relationship("EventOption")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_waiting_list_event', 'event_id', 'is_active'),
        Index('idx_waiting_list_user', 'user_id', 'is_active'),
        UniqueConstraint('event_id', 'user_id', name='uq_user_event_waiting'),
    )

    def __repr__(self):
        return f"<EventWaitingList {self.user_id} -> {self.event_id}>"


class ASDRefundRequest(Base):
    """
    Richiesta rimborso da ASD per iscrizione.

    🎯 BUSINESS: ASD può richiedere rimborso per partecipante.
    L'approvazione può essere automatica o richiedere admin LIBRA.

    FLUSSO:
    1. ASD crea richiesta
    2. Se requires_approval → PENDING, admin deve approvare
    3. Se !requires_approval → APPROVED automatico
    4. Sistema processa refund Stripe
    5. Status → PROCESSED
    """
    __tablename__ = "asd_refund_requests"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    subscription_id = Column(GUID(), ForeignKey("event_subscriptions.id", ondelete="CASCADE"), nullable=False)
    asd_id = Column(GUID(), ForeignKey("asd_partners.id", ondelete="CASCADE"), nullable=False)

    # === REQUEST ===
    requested_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason = Column(Text, nullable=False)
    requested_amount_cents = Column(Integer, nullable=True)  # null = full refund

    # === STATUS ===
    status = Column(
        SQLEnum(RefundStatus, name='event_refund_status', values_callable=lambda x: [e.value for e in x]),
        default=RefundStatus.PENDING,
        nullable=False,
        index=True
    )

    # === APPROVAL ===
    requires_approval = Column(Boolean, nullable=False)
    approved_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(Text, nullable=True)

    # === PROCESSING ===
    processed_at = Column(DateTime, nullable=True)
    processed_amount_cents = Column(Integer, nullable=True)
    stripe_refund_id = Column(String(255), nullable=True)
    processing_notes = Column(Text, nullable=True)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    subscription = relationship("EventSubscription")
    asd_partner = relationship("ASDPartner", back_populates="refund_requests")
    requester = relationship("User", foreign_keys=[requested_by])
    approver = relationship("User", foreign_keys=[approved_by])

    # === INDEXES ===
    __table_args__ = (
        Index('idx_refund_requests_asd_status', 'asd_id', 'status'),
        Index('idx_refund_requests_pending', 'status', 'requires_approval'),
    )

    def __repr__(self):
        return f"<ASDRefundRequest {self.id} ({self.status.value})>"


class PlatformAlertConfig(Base):
    """
    Configurazione alert a livello piattaforma.

    🎯 BUSINESS: Default globali per tutti gli eventi.
    Ogni evento può fare override tramite event.alert_config_override.

    ESEMPIO CONFIG:
    {
        "event_reminder": {
            "enabled": true,
            "days_before": [7, 3, 1],
            "channels": {"email": true, "push": true, "dashboard": true}
        },
        "threshold_warning": {
            "enabled": true,
            "days_before": [14, 7],
            "channels": {"email": true, "push": false, "dashboard": true}
        }
    }
    """
    __tablename__ = "platform_alert_config"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)

    # === ALERT TYPE ===
    alert_type = Column(
        SQLEnum(AlertType, name='event_alert_type', values_callable=lambda x: [e.value for e in x]),
        nullable=False,
        unique=True
    )

    # === CONFIG ===
    enabled = Column(Boolean, default=True, nullable=False)
    days_before = Column(ARRAY(Integer), nullable=True)  # [7, 3, 1] per reminder

    # === CHANNELS ===
    email_enabled = Column(Boolean, default=True, nullable=False)
    push_enabled = Column(Boolean, default=True, nullable=False)
    dashboard_enabled = Column(Boolean, default=True, nullable=False)
    sms_enabled = Column(Boolean, default=False, nullable=False)

    # === TEMPLATES ===
    email_template_id = Column(String(100), nullable=True)
    push_template = Column(Text, nullable=True)

    # === AUDIT ===
    updated_by = Column(GUID(), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<PlatformAlertConfig {self.alert_type.value} enabled={self.enabled}>"


class EventNotification(Base):
    """
    Notifica schedulata per evento.

    🎯 BUSINESS: Record di ogni notifica da inviare/inviata.
    Usato da job scheduler per processare notifiche.
    """
    __tablename__ = "event_notifications"

    id = Column(GUID(), primary_key=True, default=uuid.uuid4)
    event_id = Column(GUID(), ForeignKey("events.id", ondelete="CASCADE"), nullable=False)

    # === TYPE ===
    alert_type = Column(
        SQLEnum(AlertType, name='event_alert_type', values_callable=lambda x: [e.value for e in x]),
        nullable=False
    )

    # === SCHEDULE ===
    scheduled_for = Column(DateTime, nullable=False, index=True)

    # === RECIPIENTS ===
    recipient_type = Column(String(50), nullable=False)  # "all_subscribers", "waiting_list", "specific_user"
    recipient_user_id = Column(GUID(), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)

    # === CHANNELS ===
    channels = Column(ARRAY(String), nullable=False)  # ["email", "push"]

    # === CONTENT ===
    subject = Column(String(255), nullable=True)
    body = Column(Text, nullable=True)
    data = Column(JSONBType(), nullable=True)  # Extra data per template

    # === STATUS ===
    sent = Column(Boolean, default=False, nullable=False)
    sent_at = Column(DateTime, nullable=True)
    send_attempts = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, nullable=True)

    # === AUDIT ===
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # === RELATIONSHIPS ===
    event = relationship("Event", back_populates="notifications")
    recipient = relationship("User")

    # === INDEXES ===
    __table_args__ = (
        Index('idx_notifications_scheduled', 'scheduled_for', 'sent'),
        Index('idx_notifications_event', 'event_id', 'alert_type'),
    )

    def __repr__(self):
        return f"<EventNotification {self.alert_type.value} for {self.event_id}>"

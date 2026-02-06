"""
🎓 AI_MODULE: Events/ASD Module
🎓 AI_DESCRIPTION: Modulo gestione eventi/stage per ASD partner con Stripe Connect
🎓 AI_BUSINESS: Modulo CRITICO per prospect LIBRA (90% ricavi), eventi fisici con split payment
🎓 AI_TEACHING: Modular architecture, Stripe Connect, multi-tenant events

🔄 ALTERNATIVE_VALUTATE:
- Eventbrite integration: Scartato, meno controllo su split payment e branding
- Manual invoicing: Scartato, non scalabile per volumi LIBRA
- Single payment then split: Scartato, Stripe Connect è più trasparente

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Stripe Connect: Split payment automatico, ogni parte paga sue fee
- Multi-tenant: Ogni ASD gestisce suoi eventi autonomamente
- Configurabilità: Alert e policy configurabili a livello piattaforma e evento
- Waiting list: Gestione automatica posti liberati

COMPONENTI:
- models.py: 8 tabelle SQLAlchemy (ASD, eventi, opzioni, iscrizioni, waiting, rimborsi, alert)
- schemas.py: Pydantic v2 schemas per validazione
- config.py: Configurazione alert parametrizzabile 2 livelli
- service.py: Business logic eventi, iscrizioni, rimborsi
- stripe_connect.py: Integrazione Stripe Connect split payment
- notifications.py: Sistema notifiche/alert configurabile
- router.py: API endpoints FastAPI
- tests/: Test suite ZERO MOCK, PostgreSQL reale
"""

from modules.events.models import (
    ASDPartner,
    Event,
    EventOption,
    EventSubscription,
    EventWaitingList,
    ASDRefundRequest,
    PlatformAlertConfig,
    EventNotification,
    EventStatus,
    SubscriptionStatus,
    RefundStatus,
    AlertType,
    NotificationChannel,
    PresaleCriteriaType
)

from modules.events.schemas import (
    ASDPartnerCreate,
    ASDPartnerUpdate,
    ASDPartnerResponse,
    EventCreate,
    EventUpdate,
    EventResponse,
    EventOptionCreate,
    EventOptionUpdate,
    EventSubscriptionCreate,
    EventSubscriptionResponse,
    RefundRequestCreate,
    RefundRequestResponse,
    AlertConfigUpdate,
    WaitingListResponse
)

from modules.events.service import EventService
from modules.events.config import get_events_config, EventsConfig
from modules.events.notifications import NotificationService
from modules.events.stripe_connect import StripeConnectService

__all__ = [
    # Models
    "ASDPartner",
    "Event",
    "EventOption",
    "EventSubscription",
    "EventWaitingList",
    "ASDRefundRequest",
    "PlatformAlertConfig",
    "EventNotification",
    # Enums
    "EventStatus",
    "SubscriptionStatus",
    "RefundStatus",
    "AlertType",
    "NotificationChannel",
    "PresaleCriteriaType",
    # Schemas
    "ASDPartnerCreate",
    "ASDPartnerUpdate",
    "ASDPartnerResponse",
    "EventCreate",
    "EventUpdate",
    "EventResponse",
    "EventOptionCreate",
    "EventOptionUpdate",
    "EventSubscriptionCreate",
    "EventSubscriptionResponse",
    "RefundRequestCreate",
    "RefundRequestResponse",
    "AlertConfigUpdate",
    "WaitingListResponse",
    # Services
    "EventService",
    "NotificationService",
    "StripeConnectService",
    # Config
    "get_events_config",
    "EventsConfig",
]

"""
AI_MODULE: Royalties Blockchain Module
AI_DESCRIPTION: Sistema royalties parametrizzabile con tracking blockchain per maestri arti marziali
AI_BUSINESS: Trasparenza pagamenti maestri, trust 100%, settlement automatici
AI_TEACHING: Web3 integration, Polygon L2, Merkle trees, parametric configuration

ALTERNATIVE_VALUTATE:
- Sistema centralizzato: Scartato, no trasparenza verificabile
- Ethereum mainnet: Scartato, gas fees troppo alti (50+ per tx)
- Solo Stripe: Scartato, no immutabilita proof of view

PERCHE_QUESTA_SOLUZIONE:
- Polygon L2: Gas fees <0.01, finality 2s
- Parametrizzazione totale: Ogni aspetto configurabile da DB/env
- Hybrid settlement: Blockchain per proof, Stripe per payout reali
- Merkle trees: Batch 1000 views in 1 transazione

METRICHE_SUCCESSO:
- Costo per view tracking: <0.001
- Settlement time: <24h (configurable)
- Fraud detection: 99.9%
- Master satisfaction: >95%
"""

from .config import RoyaltyConfig, get_royalty_config
from .models import (
    MasterProfile,
    StudentSubscription,
    ViewRoyalty,
    RoyaltyPayout,
    RoyaltyMilestone,
    PricingModel,
    PayoutMethod,
    PayoutStatus,
    SubscriptionType,
    StudentMasterMode
)
from .schemas import (
    MasterProfileCreate,
    MasterProfileUpdate,
    MasterProfileResponse,
    StudentSubscriptionCreate,
    StudentSubscriptionResponse,
    ViewRoyaltyCreate,
    ViewRoyaltyResponse,
    RoyaltyPayoutResponse,
    RoyaltyDashboard,
    RoyaltyConfigResponse,
    RoyaltyConfigUpdate,
    TrackViewRequest,
    TrackViewResponse
)
from .service import RoyaltyService
from .blockchain_tracker import RoyaltyBlockchainTracker
from .router import router

__all__ = [
    # Config
    "RoyaltyConfig",
    "get_royalty_config",

    # Models
    "MasterProfile",
    "StudentSubscription",
    "ViewRoyalty",
    "RoyaltyPayout",
    "RoyaltyMilestone",
    "PricingModel",
    "PayoutMethod",
    "PayoutStatus",
    "SubscriptionType",
    "StudentMasterMode",

    # Schemas
    "MasterProfileCreate",
    "MasterProfileUpdate",
    "MasterProfileResponse",
    "StudentSubscriptionCreate",
    "StudentSubscriptionResponse",
    "ViewRoyaltyCreate",
    "ViewRoyaltyResponse",
    "RoyaltyPayoutResponse",
    "RoyaltyDashboard",
    "RoyaltyConfigResponse",
    "RoyaltyConfigUpdate",
    "TrackViewRequest",
    "TrackViewResponse",

    # Services
    "RoyaltyService",
    "RoyaltyBlockchainTracker",

    # Router
    "router"
]

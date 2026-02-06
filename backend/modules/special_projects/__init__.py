"""
AI_MODULE: Special Projects Voting System
AI_DESCRIPTION: Sistema votazione progetti speciali con pesi basati su subscription
AI_BUSINESS: Engagement utenti +40%, retention premium +25%, community-driven content
AI_TEACHING: Weighted voting, eligibility rules, monthly vote cycles

ALTERNATIVE_VALUTATE:
- Simple 1-vote-per-user: Scartato, non premia utenti paganti
- Token-based voting: Scartato, troppo complesso per MVP
- Continuous voting: Scartato, difficile da gestire e analizzare

PERCHE_QUESTA_SOLUZIONE:
- Pesi differenziati: Premia chi paga di piu mantenendo inclusivita
- Ciclo mensile: Permette cambio idea, analisi periodiche
- Eligibilita dinamica: Utenti free possono guadagnare diritto voto

METRICHE_SUCCESSO:
- Partecipazione voto: >30% utenti eligibili
- Conversione free->premium: +15% dopo voting feature
- Progetti completati votati: >80%
"""

from .config import SpecialProjectsConfig, get_special_projects_config
from .models import (
    SpecialProject,
    ProjectVote,
    VotingEligibility,
    SpecialProjectsConfigDB,
    ProjectStatus,
    VoteWeight,
    EligibilityStatus
)
from .schemas import (
    SpecialProjectCreate,
    SpecialProjectUpdate,
    SpecialProjectResponse,
    ProjectVoteCreate,
    ProjectVoteResponse,
    EligibilityResponse,
    VotingStatsResponse,
    ConfigUpdateRequest,
    ConfigResponse
)
from .eligibility import EligibilityCalculator
from .service import SpecialProjectsService
from .analytics import SpecialProjectsAnalytics
from .router import router

__all__ = [
    # Config
    "SpecialProjectsConfig",
    "get_special_projects_config",

    # Models
    "SpecialProject",
    "ProjectVote",
    "VotingEligibility",
    "SpecialProjectsConfigDB",
    "ProjectStatus",
    "VoteWeight",
    "EligibilityStatus",

    # Schemas
    "SpecialProjectCreate",
    "SpecialProjectUpdate",
    "SpecialProjectResponse",
    "ProjectVoteCreate",
    "ProjectVoteResponse",
    "EligibilityResponse",
    "VotingStatsResponse",
    "ConfigUpdateRequest",
    "ConfigResponse",

    # Services
    "EligibilityCalculator",
    "SpecialProjectsService",
    "SpecialProjectsAnalytics",

    # Router
    "router"
]

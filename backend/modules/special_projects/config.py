"""
AI_MODULE: Special Projects Configuration
AI_DESCRIPTION: Configurazione parametrizzabile sistema votazione progetti
AI_BUSINESS: Flessibilita 100% per A/B testing e tuning senza deploy
AI_TEACHING: Pydantic Settings, DB override pattern, hot reload config

ALTERNATIVE_VALUTATE:
- Hardcoded values: Scartato, richiede deploy per ogni cambio
- YAML config: Scartato, meno type-safe
- Only env vars: Scartato, non permette override runtime

PERCHE_QUESTA_SOLUZIONE:
- 3-tier config: Default -> Env -> Database (runtime)
- Type validation: Pydantic garantisce correttezza
- Admin control: Cambi immediati senza restart

METRICHE_SUCCESSO:
- Config change time: <1 minuto
- Validation errors: 0 (Pydantic)
- Rollback capability: 100%
"""

import os
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field
from functools import lru_cache


class SubscriptionTier(str, Enum):
    """
    Tier di subscription per calcolo peso voto.

    Gerarchia:
    - PREMIUM_FULL: Paga prezzo pieno, peso massimo
    - PREMIUM_HYBRID: Paga meta + vede ads, peso medio
    - FREE_WITH_ADS: Non paga ma engagement alto, peso minimo
    - FREE_NO_ADS: Non paga, no engagement, no voto
    """
    PREMIUM_FULL = "premium_full"
    PREMIUM_HYBRID = "premium_hybrid"
    FREE_WITH_ADS = "free_with_ads"
    FREE_NO_ADS = "free_no_ads"


class VoteWeightsConfig(BaseModel):
    """
    Pesi voto per tier subscription.

    Configurabili da admin per bilanciare
    potere di voto tra tier.
    """
    premium_full: int = Field(3, ge=1, le=10, description="Peso voto premium full")
    premium_hybrid: int = Field(2, ge=1, le=10, description="Peso voto premium hybrid")
    free_with_ads: int = Field(1, ge=0, le=10, description="Peso voto free con ads")
    free_no_ads: int = Field(0, ge=0, le=10, description="Peso voto free senza ads (0=non puo votare)")

    def get_weight(self, tier: SubscriptionTier) -> int:
        """Ottiene peso per tier specifico."""
        mapping = {
            SubscriptionTier.PREMIUM_FULL: self.premium_full,
            SubscriptionTier.PREMIUM_HYBRID: self.premium_hybrid,
            SubscriptionTier.FREE_WITH_ADS: self.free_with_ads,
            SubscriptionTier.FREE_NO_ADS: self.free_no_ads
        }
        return mapping.get(tier, 0)


class FreeUserRequirements(BaseModel):
    """
    Requisiti per utenti free per ottenere diritto di voto.

    Devono dimostrare engagement minimo per
    guadagnare peso voto = 1.
    """
    min_watch_minutes: int = Field(
        60,
        ge=0,
        description="Minuti totali video guardati nel mese"
    )
    min_ads_watched: int = Field(
        10,
        ge=0,
        description="Numero minimo ads guardate nel mese"
    )
    min_videos_completed: int = Field(
        5,
        ge=0,
        description="Video completati (>90%) nel mese"
    )
    lookback_days: int = Field(
        30,
        ge=7,
        le=90,
        description="Giorni di lookback per calcolo requisiti"
    )


class VotingRulesConfig(BaseModel):
    """
    Regole sistema di voto.

    Definisce comportamento ciclo voto mensile.
    """
    vote_cycle_type: str = Field(
        "monthly",
        description="Tipo ciclo: monthly, weekly, custom"
    )
    votes_per_user_per_cycle: int = Field(
        1,
        ge=1,
        le=5,
        description="Voti per utente per ciclo"
    )
    can_change_vote_same_cycle: bool = Field(
        False,
        description="Puo cambiare voto nello stesso ciclo?"
    )
    vote_persists_next_cycle: bool = Field(
        True,
        description="Voto resta attivo se non cambiato?"
    )
    min_projects_for_voting: int = Field(
        2,
        ge=1,
        description="Minimo progetti attivi per aprire voto"
    )
    max_active_projects: int = Field(
        10,
        ge=1,
        le=50,
        description="Massimo progetti attivi contemporaneamente"
    )


class SpecialProjectsConfig(BaseModel):
    """
    Configurazione principale sistema progetti speciali.

    Raggruppa tutte le sub-config in un unico oggetto.
    Supporta override da database per ogni campo.
    """

    # === VOTE WEIGHTS ===
    vote_weights: VoteWeightsConfig = Field(
        default_factory=VoteWeightsConfig,
        description="Pesi voto per subscription tier"
    )

    # === FREE USER REQUIREMENTS ===
    free_user_requirements: FreeUserRequirements = Field(
        default_factory=FreeUserRequirements,
        description="Requisiti utenti free per votare"
    )

    # === VOTING RULES ===
    voting_rules: VotingRulesConfig = Field(
        default_factory=VotingRulesConfig,
        description="Regole sistema voto"
    )

    # === PROJECT SETTINGS ===
    project_min_description_length: int = Field(
        100,
        ge=10,
        description="Lunghezza minima descrizione progetto"
    )
    project_max_description_length: int = Field(
        5000,
        ge=100,
        description="Lunghezza massima descrizione progetto"
    )
    require_project_image: bool = Field(
        True,
        description="Immagine obbligatoria per progetto"
    )
    require_project_budget: bool = Field(
        True,
        description="Budget obbligatorio per progetto"
    )

    # === NOTIFICATIONS ===
    notify_on_new_project: bool = Field(
        True,
        description="Notifica utenti quando nuovo progetto"
    )
    notify_on_vote_result: bool = Field(
        True,
        description="Notifica quando termina votazione"
    )
    notify_days_before_cycle_end: int = Field(
        3,
        ge=0,
        description="Giorni prima fine ciclo per reminder"
    )

    # === ANALYTICS ===
    track_vote_changes: bool = Field(
        True,
        description="Traccia storico cambi voto"
    )
    track_eligibility_changes: bool = Field(
        True,
        description="Traccia cambi eligibilita"
    )

    class Config:
        use_enum_values = True


def _load_config_from_env() -> Dict[str, Any]:
    """
    Carica config da environment variables.

    Pattern: SPECIAL_PROJECTS_<SECTION>_<KEY>
    """
    config = {}

    # Vote weights
    weights = {}
    weight_mappings = {
        "SPECIAL_PROJECTS_WEIGHT_PREMIUM_FULL": "premium_full",
        "SPECIAL_PROJECTS_WEIGHT_PREMIUM_HYBRID": "premium_hybrid",
        "SPECIAL_PROJECTS_WEIGHT_FREE_WITH_ADS": "free_with_ads",
        "SPECIAL_PROJECTS_WEIGHT_FREE_NO_ADS": "free_no_ads"
    }
    for env_key, config_key in weight_mappings.items():
        value = os.getenv(env_key)
        if value:
            weights[config_key] = int(value)
    if weights:
        config["vote_weights"] = weights

    # Free user requirements
    free_reqs = {}
    free_mappings = {
        "SPECIAL_PROJECTS_FREE_MIN_WATCH_MINUTES": "min_watch_minutes",
        "SPECIAL_PROJECTS_FREE_MIN_ADS_WATCHED": "min_ads_watched",
        "SPECIAL_PROJECTS_FREE_MIN_VIDEOS_COMPLETED": "min_videos_completed"
    }
    for env_key, config_key in free_mappings.items():
        value = os.getenv(env_key)
        if value:
            free_reqs[config_key] = int(value)
    if free_reqs:
        config["free_user_requirements"] = free_reqs

    return config


@lru_cache(maxsize=1)
def get_special_projects_config() -> SpecialProjectsConfig:
    """
    Ottiene configurazione con caching.

    Ordine priorita:
    1. Default (in SpecialProjectsConfig)
    2. Environment variables
    3. Database override (gestito da service)
    """
    env_config = _load_config_from_env()
    return SpecialProjectsConfig(**env_config)


def clear_config_cache():
    """Pulisce cache per forzare reload."""
    get_special_projects_config.cache_clear()

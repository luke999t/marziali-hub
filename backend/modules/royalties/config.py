"""
AI_MODULE: Royalty Configuration System
AI_DESCRIPTION: Configurazione completamente parametrizzabile per sistema royalties
AI_BUSINESS: Flessibilita totale per adattare modello business senza code changes
AI_TEACHING: Pydantic Settings, environment variables, database override pattern

ALTERNATIVE_VALUTATE:
- Hardcoded config: Scartato, richiede deploy per ogni cambio
- Solo env vars: Scartato, non permette override per-maestro
- Config file YAML: Scartato, meno type-safe di Pydantic

PERCHE_QUESTA_SOLUZIONE:
- Pydantic Settings: Type-safe, validation automatica
- 3-level override: Default -> Env -> Database
- Hot reload: Cambi config senza restart
- Per-master override: Ogni maestro puo avere config custom

METRICHE_SUCCESSO:
- Config change time: <1 minuto (no deploy)
- Type errors: 0 (Pydantic validation)
- Backward compatibility: 100%
"""

import os
from enum import Enum
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, field_validator
from functools import lru_cache
import json


# ======================== ENUMS ========================

class StudentMasterModeEnum(str, Enum):
    """
    Modalita relazione studente-maestro.

    SINGLE: Studente segue solo 1 maestro alla volta
    MULTIPLE: Studente puo seguire N maestri contemporaneamente
    """
    SINGLE = "single"
    MULTIPLE = "multiple"


class PricingModelEnum(str, Enum):
    """
    Modelli di pricing per contenuti maestro.

    FREE: Contenuti gratuiti per tutti
    INCLUDED: Incluso nell'abbonamento piattaforma base
    PREMIUM: Richiede abbonamento aggiuntivo al maestro
    CUSTOM: Prezzo personalizzato definito dal maestro
    """
    FREE = "free"
    INCLUDED = "included"
    PREMIUM = "premium"
    CUSTOM = "custom"


class PayoutFrequencyEnum(str, Enum):
    """
    Frequenza pagamenti ai maestri.

    WEEKLY: Payout settimanale (ogni lunedi)
    MONTHLY: Payout mensile (primo del mese)
    ON_DEMAND: Payout su richiesta (min threshold)
    """
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"


class BlockchainNetworkEnum(str, Enum):
    """
    Network blockchain supportati.

    POLYGON: Polygon (MATIC) - L2, gas fees bassi
    ETHEREUM: Ethereum mainnet - costoso ma piu liquido
    BASE: Base (Coinbase L2) - nuovo, fees bassissimi
    """
    POLYGON = "polygon"
    ETHEREUM = "ethereum"
    BASE = "base"


# ======================== SUBSCRIPTION TYPES ========================

class SubscriptionTypeConfig(BaseModel):
    """
    Configurazione singolo tipo abbonamento.

    Ogni tipo ha prezzo e durata configurabili.
    period_days=None indica abbonamento lifetime.
    """
    price_cents: int = Field(..., ge=0, description="Prezzo in centesimi EUR")
    period_days: Optional[int] = Field(None, ge=1, description="Durata in giorni, None=lifetime")
    description: str = Field("", description="Descrizione per UI")
    features: List[str] = Field(default_factory=list, description="Lista features incluse")


# ======================== ROYALTY MILESTONES ========================

class RoyaltyMilestoneConfig(BaseModel):
    """
    Configurazione milestone per calcolo royalties.

    Ogni milestone (started, 25%, 50%, 75%, completed) ha un valore
    in EUR che viene assegnato al maestro quando raggiunto.
    """
    view_started: float = Field(0.001, ge=0, description="EUR per view iniziata")
    view_25_percent: float = Field(0.002, ge=0, description="EUR al 25% completamento")
    view_50_percent: float = Field(0.003, ge=0, description="EUR al 50% completamento")
    view_75_percent: float = Field(0.004, ge=0, description="EUR al 75% completamento")
    view_completed: float = Field(0.01, ge=0, description="EUR per completamento 100%")

    def get_amount_for_milestone(self, milestone: str) -> float:
        """
        Ottiene importo per milestone specifico.

        Args:
            milestone: Nome milestone (started/25/50/75/completed)

        Returns:
            Importo in EUR
        """
        mapping = {
            "started": self.view_started,
            "25": self.view_25_percent,
            "50": self.view_50_percent,
            "75": self.view_75_percent,
            "completed": self.view_completed
        }
        return mapping.get(milestone, 0.0)


# ======================== REVENUE SPLIT CONFIG ========================

class RevenueSplitConfig(BaseModel):
    """
    Configurazione split revenue tra piattaforma e maestro.

    Il totale platform_fee + master_share deve essere 100.
    """
    platform_fee_percent: int = Field(30, ge=0, le=100, description="% piattaforma")
    master_share_percent: int = Field(70, ge=0, le=100, description="% maestro")

    @field_validator('master_share_percent')
    @classmethod
    def validate_total_100(cls, v, info):
        """Valida che platform + master = 100%."""
        platform = info.data.get('platform_fee_percent', 30)
        if platform + v != 100:
            raise ValueError(f"platform_fee ({platform}) + master_share ({v}) must equal 100")
        return v


# ======================== BLOCKCHAIN CONFIG ========================

class BlockchainConfig(BaseModel):
    """
    Configurazione blockchain per tracking on-chain.

    Tutti i parametri sono configurabili per supportare
    diversi network e strategie di gas.
    """
    enabled: bool = Field(True, description="Abilita tracking blockchain")
    network: BlockchainNetworkEnum = Field(
        BlockchainNetworkEnum.POLYGON,
        description="Network blockchain"
    )

    # RPC URLs per network
    polygon_rpc_url: str = Field(
        "https://polygon-rpc.com",
        description="Polygon RPC URL"
    )
    ethereum_rpc_url: str = Field(
        "https://eth.llamarpc.com",
        description="Ethereum RPC URL"
    )
    base_rpc_url: str = Field(
        "https://mainnet.base.org",
        description="Base RPC URL"
    )

    # Chain IDs
    polygon_chain_id: int = Field(137, description="Polygon Mainnet Chain ID")
    ethereum_chain_id: int = Field(1, description="Ethereum Mainnet Chain ID")
    base_chain_id: int = Field(8453, description="Base Mainnet Chain ID")

    # Gas settings
    max_gas_price_gwei: int = Field(500, ge=1, description="Max gas price in Gwei")
    gas_limit_batch: int = Field(500000, ge=21000, description="Gas limit per batch tx")
    gas_buffer_multiplier: float = Field(1.2, ge=1.0, description="Buffer moltiplicatore gas")

    # Batch settings
    batch_size: int = Field(100, ge=1, le=1000, description="Views per batch")
    batch_interval_seconds: int = Field(300, ge=60, description="Intervallo batch (sec)")
    min_batch_size: int = Field(10, ge=1, description="Minimo views per batch")

    # Contract addresses (da configurare per deployment)
    royalty_tracker_contract: Optional[str] = Field(
        None,
        description="Address smart contract royalty tracker"
    )
    payment_token_contract: Optional[str] = Field(
        None,
        description="Address token pagamento (USDT/USDC)"
    )

    # IPFS
    ipfs_enabled: bool = Field(True, description="Abilita storage IPFS metadata")
    ipfs_api_url: str = Field("/ip4/127.0.0.1/tcp/5001", description="IPFS API URL")
    ipfs_gateway_url: str = Field("https://ipfs.io/ipfs/", description="IPFS Gateway URL")

    # Confirmations
    confirmation_blocks: int = Field(3, ge=1, description="Blocchi conferma richiesti")

    def get_rpc_url(self) -> str:
        """Ottiene RPC URL per network configurato."""
        mapping = {
            BlockchainNetworkEnum.POLYGON: self.polygon_rpc_url,
            BlockchainNetworkEnum.ETHEREUM: self.ethereum_rpc_url,
            BlockchainNetworkEnum.BASE: self.base_rpc_url
        }
        return mapping[self.network]

    def get_chain_id(self) -> int:
        """Ottiene Chain ID per network configurato."""
        mapping = {
            BlockchainNetworkEnum.POLYGON: self.polygon_chain_id,
            BlockchainNetworkEnum.ETHEREUM: self.ethereum_chain_id,
            BlockchainNetworkEnum.BASE: self.base_chain_id
        }
        return mapping[self.network]


# ======================== MAIN CONFIG ========================

class RoyaltyConfig(BaseModel):
    """
    Configurazione principale sistema royalties.

    Raggruppa tutte le sub-configurazioni in un unico oggetto.
    Supporta override da environment variables e database.
    """

    # === STUDENT-MASTER RELATIONSHIP ===
    student_master_mode: StudentMasterModeEnum = Field(
        StudentMasterModeEnum.MULTIPLE,
        description="Modalita relazione studente-maestro"
    )
    max_masters_per_student: int = Field(
        5,
        ge=1,
        description="Max maestri seguibili contemporaneamente (0=unlimited)"
    )
    master_switch_cooldown_days: int = Field(
        7,
        ge=0,
        description="Giorni minimo tra cambi maestro (0=nessun cooldown)"
    )

    # === SUBSCRIPTION TYPES ===
    subscription_types: Dict[str, SubscriptionTypeConfig] = Field(
        default_factory=lambda: {
            "monthly": SubscriptionTypeConfig(
                price_cents=999,
                period_days=30,
                description="Abbonamento mensile",
                features=["Accesso tutti i video", "Download offline", "No pubblicita"]
            ),
            "yearly": SubscriptionTypeConfig(
                price_cents=9999,
                period_days=365,
                description="Abbonamento annuale (2 mesi gratis)",
                features=["Accesso tutti i video", "Download offline", "No pubblicita", "Contenuti esclusivi"]
            ),
            "lifetime": SubscriptionTypeConfig(
                price_cents=29999,
                period_days=None,
                description="Accesso lifetime",
                features=["Tutto incluso per sempre", "Badge supporter", "Accesso anticipato"]
            ),
            "per_video": SubscriptionTypeConfig(
                price_cents=299,
                period_days=None,
                description="Acquisto singolo video",
                features=["Accesso permanente al video"]
            )
        },
        description="Tipi abbonamento disponibili"
    )

    # === ROYALTY MILESTONES ===
    royalty_milestones: RoyaltyMilestoneConfig = Field(
        default_factory=RoyaltyMilestoneConfig,
        description="Importi per milestone view"
    )

    # === REVENUE SPLIT ===
    revenue_split: RevenueSplitConfig = Field(
        default_factory=RevenueSplitConfig,
        description="Split revenue piattaforma/maestro"
    )

    # === PAYOUT SETTINGS ===
    min_payout_cents: int = Field(
        5000,
        ge=100,
        description="Minimo EUR centesimi per payout (default 50 EUR)"
    )
    payout_frequency: PayoutFrequencyEnum = Field(
        PayoutFrequencyEnum.MONTHLY,
        description="Frequenza payout automatici"
    )
    payout_processing_days: int = Field(
        3,
        ge=1,
        description="Giorni lavorativi per processare payout"
    )

    # === BLOCKCHAIN ===
    blockchain: BlockchainConfig = Field(
        default_factory=BlockchainConfig,
        description="Configurazione blockchain"
    )

    # === FRAUD DETECTION ===
    fraud_detection_enabled: bool = Field(
        True,
        description="Abilita rilevamento frodi"
    )
    max_views_per_user_per_video_per_day: int = Field(
        10,
        ge=1,
        description="Max views stesso video stesso utente per giorno"
    )
    min_watch_time_seconds: int = Field(
        5,
        ge=1,
        description="Secondi minimi per considerare view valida"
    )
    suspicious_speed_multiplier: float = Field(
        3.0,
        ge=1.0,
        description="Moltiplicatore velocita sospetta (es. 3x = video 10min guardato in 3min)"
    )

    class Config:
        """Pydantic config."""
        use_enum_values = True


# ======================== CONFIG LOADER ========================

def _load_config_from_env() -> Dict[str, Any]:
    """
    Carica configurazione da environment variables.

    Pattern: ROYALTY_<SECTION>_<KEY>
    Es: ROYALTY_STUDENT_MASTER_MODE=single
        ROYALTY_BLOCKCHAIN_ENABLED=false
        ROYALTY_MIN_PAYOUT_CENTS=10000
    """
    config = {}

    # Simple values
    env_mappings = {
        "ROYALTY_STUDENT_MASTER_MODE": "student_master_mode",
        "ROYALTY_MAX_MASTERS_PER_STUDENT": ("max_masters_per_student", int),
        "ROYALTY_MASTER_SWITCH_COOLDOWN_DAYS": ("master_switch_cooldown_days", int),
        "ROYALTY_MIN_PAYOUT_CENTS": ("min_payout_cents", int),
        "ROYALTY_PAYOUT_FREQUENCY": "payout_frequency",
        "ROYALTY_PAYOUT_PROCESSING_DAYS": ("payout_processing_days", int),
        "ROYALTY_FRAUD_DETECTION_ENABLED": ("fraud_detection_enabled", lambda x: x.lower() == "true"),
        "ROYALTY_MAX_VIEWS_PER_USER_PER_VIDEO_PER_DAY": ("max_views_per_user_per_video_per_day", int),
        "ROYALTY_MIN_WATCH_TIME_SECONDS": ("min_watch_time_seconds", int),
    }

    for env_key, mapping in env_mappings.items():
        value = os.getenv(env_key)
        if value is not None:
            if isinstance(mapping, tuple):
                key, converter = mapping
                config[key] = converter(value)
            else:
                config[mapping] = value

    # Royalty milestones
    milestone_prefix = "ROYALTY_MILESTONE_"
    milestones = {}
    for key in ["VIEW_STARTED", "VIEW_25_PERCENT", "VIEW_50_PERCENT", "VIEW_75_PERCENT", "VIEW_COMPLETED"]:
        env_key = f"{milestone_prefix}{key}"
        value = os.getenv(env_key)
        if value is not None:
            milestones[key.lower()] = float(value)
    if milestones:
        config["royalty_milestones"] = milestones

    # Revenue split
    platform_fee = os.getenv("ROYALTY_PLATFORM_FEE_PERCENT")
    master_share = os.getenv("ROYALTY_MASTER_SHARE_PERCENT")
    if platform_fee is not None or master_share is not None:
        config["revenue_split"] = {
            "platform_fee_percent": int(platform_fee) if platform_fee else 30,
            "master_share_percent": int(master_share) if master_share else 70
        }

    # Blockchain config
    blockchain_config = {}
    blockchain_mappings = {
        "ROYALTY_BLOCKCHAIN_ENABLED": ("enabled", lambda x: x.lower() == "true"),
        "ROYALTY_BLOCKCHAIN_NETWORK": "network",
        "ROYALTY_BLOCKCHAIN_MAX_GAS_PRICE_GWEI": ("max_gas_price_gwei", int),
        "ROYALTY_BLOCKCHAIN_BATCH_SIZE": ("batch_size", int),
        "ROYALTY_BLOCKCHAIN_CONTRACT": "royalty_tracker_contract",
        "ROYALTY_BLOCKCHAIN_PAYMENT_TOKEN": "payment_token_contract",
    }

    for env_key, mapping in blockchain_mappings.items():
        value = os.getenv(env_key)
        if value is not None:
            if isinstance(mapping, tuple):
                key, converter = mapping
                blockchain_config[key] = converter(value)
            else:
                blockchain_config[mapping] = value

    if blockchain_config:
        config["blockchain"] = blockchain_config

    return config


@lru_cache(maxsize=1)
def get_royalty_config() -> RoyaltyConfig:
    """
    Ottiene configurazione royalties con caching.

    Ordine priorita (dal piu basso al piu alto):
    1. Default values (definiti in RoyaltyConfig)
    2. Environment variables
    3. Database override (non implementato qui, gestito da service)

    Returns:
        RoyaltyConfig istanza con tutti i valori
    """
    env_config = _load_config_from_env()
    return RoyaltyConfig(**env_config)


def clear_config_cache():
    """
    Pulisce cache configurazione.

    Chiamare quando si modificano env vars o config DB
    per forzare reload.
    """
    get_royalty_config.cache_clear()

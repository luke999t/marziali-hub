"""
🎓 AI_MODULE: Events Configuration
🎓 AI_DESCRIPTION: Configurazione parametrizzabile per eventi/alert a 2 livelli
🎓 AI_BUSINESS: Flessibilità massima per piattaforma e singoli eventi
🎓 AI_TEACHING: Pydantic Settings, environment variables, config hierarchy

🔄 ALTERNATIVE_VALUTATE:
- Hardcoded config: Scartato, zero flessibilità
- Solo DB config: Scartato, serve fallback per bootstrap
- YAML files: Scartato, env vars più standard per deploy

💡 PERCHÉ_QUESTA_SOLUZIONE:
- 2 livelli: Piattaforma (env/DB) -> Evento (DB override)
- Caching: Config cached per performance
- Type safety: Pydantic per validazione

GERARCHIA CONFIG:
1. Environment variables (defaults)
2. PlatformAlertConfig DB (override globali)
3. Event.alert_config_override (override per evento)
"""

from pydantic import Field
from pydantic_settings import BaseSettings
from typing import Optional, List, Dict, Any
from functools import lru_cache
import os

from modules.events.models import AlertType


class AlertChannelDefaults(BaseSettings):
    """Default canali alert."""
    email: bool = True
    push: bool = True
    dashboard: bool = True
    sms: bool = False

    class Config:
        env_prefix = "EVENTS_ALERT_CHANNEL_"


class EventReminderConfig(BaseSettings):
    """Config promemoria evento."""
    enabled: bool = True
    days_before: List[int] = Field(default=[7, 3, 1])
    email: bool = True
    push: bool = True
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_REMINDER_"


class PresaleAlertConfig(BaseSettings):
    """Config alert prevendita."""
    enabled: bool = True
    notify_before_hours: int = 24  # Notifica 24h prima inizio prevendita
    email: bool = True
    push: bool = True
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_PRESALE_ALERT_"


class CapacityAlertConfig(BaseSettings):
    """Config alert capacità."""
    low_capacity_threshold: int = 10  # Posti rimanenti
    low_capacity_enabled: bool = True
    sold_out_enabled: bool = True
    email: bool = True
    push: bool = True
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_CAPACITY_ALERT_"


class ThresholdAlertConfig(BaseSettings):
    """Config alert soglia minima."""
    enabled: bool = True
    days_before: List[int] = Field(default=[14, 7, 3])  # Quando controllare
    notify_admin: bool = True
    notify_asd: bool = True
    email: bool = True
    push: bool = False
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_THRESHOLD_ALERT_"


class WaitlistAlertConfig(BaseSettings):
    """Config alert waiting list."""
    enabled: bool = True
    notify_all: bool = True  # True = tutti, False = FIFO
    email: bool = True
    push: bool = True
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_WAITLIST_ALERT_"


class RefundAlertConfig(BaseSettings):
    """Config alert rimborsi."""
    notify_admin_on_request: bool = True
    notify_user_on_approval: bool = True
    notify_user_on_rejection: bool = True
    notify_user_on_processed: bool = True
    email: bool = True
    push: bool = True
    dashboard: bool = True

    class Config:
        env_prefix = "EVENTS_REFUND_ALERT_"


class StripeConfig(BaseSettings):
    """Config Stripe Connect."""
    platform_fee_percent: float = Field(default=15.0, ge=0, le=50)  # % piattaforma (LIBRA)
    currency: str = "eur"
    connect_application_fee_percent: float = Field(default=0.0)  # Extra fee

    # Stripe API
    secret_key: str = Field(default="sk_test_xxx")
    webhook_secret: str = Field(default="whsec_xxx")
    connect_webhook_secret: str = Field(default="whsec_connect_xxx")

    class Config:
        env_prefix = "STRIPE_"


class EventsConfig(BaseSettings):
    """
    Configurazione principale modulo eventi.

    USAGE:
    ```python
    config = get_events_config()
    if config.reminder.enabled:
        for day in config.reminder.days_before:
            schedule_reminder(event, day)
    ```
    """
    # Sub-configs
    reminder: EventReminderConfig = Field(default_factory=EventReminderConfig)
    presale: PresaleAlertConfig = Field(default_factory=PresaleAlertConfig)
    capacity: CapacityAlertConfig = Field(default_factory=CapacityAlertConfig)
    threshold: ThresholdAlertConfig = Field(default_factory=ThresholdAlertConfig)
    waitlist: WaitlistAlertConfig = Field(default_factory=WaitlistAlertConfig)
    refund: RefundAlertConfig = Field(default_factory=RefundAlertConfig)
    stripe: StripeConfig = Field(default_factory=StripeConfig)

    # General
    default_refund_approval_required: bool = True
    max_waiting_list_per_event: int = 100
    checkout_session_expiry_minutes: int = 30

    # Bundle
    bundle_auto_grant: bool = True  # Auto-grant corso bundle su conferma

    class Config:
        env_prefix = "EVENTS_"
        env_nested_delimiter = "__"


# ======================== CONFIG CACHE ========================

_config_cache: Optional[EventsConfig] = None


def get_events_config() -> EventsConfig:
    """
    Get cached events config.

    PERCHÉ CACHE:
    - Config letta da env, non cambia runtime
    - Evita parsing ripetuto

    COME INVALIDARE:
    - clear_config_cache() per testing
    """
    global _config_cache
    if _config_cache is None:
        _config_cache = EventsConfig()
    return _config_cache


def clear_config_cache():
    """Clear config cache (for testing)."""
    global _config_cache
    _config_cache = None


# ======================== CONFIG RESOLVER ========================

class ConfigResolver:
    """
    Risolve config con gerarchia: Platform -> Event override.

    USAGE:
    ```python
    resolver = ConfigResolver(platform_config, event_override)
    days = resolver.get_reminder_days()  # Returns event override or platform default
    ```
    """

    def __init__(
        self,
        platform_config: EventsConfig,
        event_override: Optional[Dict[str, Any]] = None
    ):
        self.platform = platform_config
        self.override = event_override or {}

    def get_reminder_enabled(self) -> bool:
        """Get reminder enabled status."""
        if "reminder_enabled" in self.override:
            return self.override["reminder_enabled"]
        return self.platform.reminder.enabled

    def get_reminder_days(self) -> List[int]:
        """Get reminder days before event."""
        if "reminder_days" in self.override:
            return self.override["reminder_days"]
        return self.platform.reminder.days_before

    def get_threshold_enabled(self) -> bool:
        """Get threshold warning enabled."""
        if "threshold_warning_enabled" in self.override:
            return self.override["threshold_warning_enabled"]
        return self.platform.threshold.enabled

    def get_threshold_days(self) -> List[int]:
        """Get threshold check days."""
        if "threshold_days" in self.override:
            return self.override["threshold_days"]
        return self.platform.threshold.days_before

    def get_low_capacity_threshold(self) -> int:
        """Get low capacity threshold."""
        if "low_capacity_threshold" in self.override:
            return self.override["low_capacity_threshold"]
        return self.platform.capacity.low_capacity_threshold

    def get_channels(self, alert_type: AlertType) -> Dict[str, bool]:
        """
        Get enabled channels for alert type.

        Returns dict like {"email": True, "push": True, "dashboard": False}
        """
        # Check override first
        if "channels" in self.override:
            return self.override["channels"]

        # Get from platform config based on alert type
        channel_config = self._get_channel_config(alert_type)
        return {
            "email": channel_config.get("email", True),
            "push": channel_config.get("push", True),
            "dashboard": channel_config.get("dashboard", True),
            "sms": channel_config.get("sms", False)
        }

    def _get_channel_config(self, alert_type: AlertType) -> Dict[str, bool]:
        """Get channel config for alert type from platform."""
        mapping = {
            AlertType.EVENT_REMINDER: self.platform.reminder,
            AlertType.PRESALE_START: self.platform.presale,
            AlertType.SALE_START: self.platform.presale,
            AlertType.LOW_CAPACITY: self.platform.capacity,
            AlertType.THRESHOLD_WARNING: self.platform.threshold,
            AlertType.WAITLIST_SPOT: self.platform.waitlist,
            AlertType.REFUND_REQUEST: self.platform.refund,
            AlertType.EVENT_CANCELLED: self.platform.reminder,  # Use reminder config
        }

        config = mapping.get(alert_type, self.platform.reminder)
        return {
            "email": getattr(config, "email", True),
            "push": getattr(config, "push", True),
            "dashboard": getattr(config, "dashboard", True),
            "sms": getattr(config, "sms", False) if hasattr(config, "sms") else False
        }


# ======================== DEFAULT PLATFORM CONFIG ========================

def get_default_alert_configs() -> Dict[AlertType, Dict[str, Any]]:
    """
    Get default alert configs for seeding PlatformAlertConfig table.

    USAGE:
    ```python
    defaults = get_default_alert_configs()
    for alert_type, config in defaults.items():
        await db.execute(
            insert(PlatformAlertConfig).values(
                alert_type=alert_type,
                **config
            ).on_conflict_do_nothing()
        )
    ```
    """
    config = get_events_config()

    return {
        AlertType.EVENT_REMINDER: {
            "enabled": config.reminder.enabled,
            "days_before": config.reminder.days_before,
            "email_enabled": config.reminder.email,
            "push_enabled": config.reminder.push,
            "dashboard_enabled": config.reminder.dashboard,
            "sms_enabled": False,
        },
        AlertType.PRESALE_START: {
            "enabled": config.presale.enabled,
            "days_before": [1],  # 1 day before
            "email_enabled": config.presale.email,
            "push_enabled": config.presale.push,
            "dashboard_enabled": config.presale.dashboard,
            "sms_enabled": False,
        },
        AlertType.SALE_START: {
            "enabled": True,
            "days_before": [1],
            "email_enabled": True,
            "push_enabled": True,
            "dashboard_enabled": True,
            "sms_enabled": False,
        },
        AlertType.LOW_CAPACITY: {
            "enabled": config.capacity.low_capacity_enabled,
            "days_before": None,  # Triggered by capacity
            "email_enabled": config.capacity.email,
            "push_enabled": config.capacity.push,
            "dashboard_enabled": config.capacity.dashboard,
            "sms_enabled": False,
        },
        AlertType.THRESHOLD_WARNING: {
            "enabled": config.threshold.enabled,
            "days_before": config.threshold.days_before,
            "email_enabled": config.threshold.email,
            "push_enabled": config.threshold.push,
            "dashboard_enabled": config.threshold.dashboard,
            "sms_enabled": False,
        },
        AlertType.WAITLIST_SPOT: {
            "enabled": config.waitlist.enabled,
            "days_before": None,  # Triggered on spot available
            "email_enabled": config.waitlist.email,
            "push_enabled": config.waitlist.push,
            "dashboard_enabled": config.waitlist.dashboard,
            "sms_enabled": False,
        },
        AlertType.REFUND_REQUEST: {
            "enabled": config.refund.notify_admin_on_request,
            "days_before": None,  # Immediate
            "email_enabled": config.refund.email,
            "push_enabled": config.refund.push,
            "dashboard_enabled": config.refund.dashboard,
            "sms_enabled": False,
        },
        AlertType.EVENT_CANCELLED: {
            "enabled": True,
            "days_before": None,  # Immediate
            "email_enabled": True,
            "push_enabled": True,
            "dashboard_enabled": True,
            "sms_enabled": False,
        },
    }

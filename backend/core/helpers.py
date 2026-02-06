"""
================================================================================
AI_MODULE: Shared Helpers
AI_VERSION: 1.0.0
AI_DESCRIPTION: Utility functions for API endpoints
AI_BUSINESS: Centralizza logica comune, riduce bug da pattern current_user
AI_TEACHING: Helper robusti per gestire polimorfismo auth (dict vs SQLAlchemy)
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
================================================================================
"""

from typing import Union, Optional, Any


def get_user_id(current_user: Union[dict, Any]) -> str:
    """
    Estrae user_id da current_user (dict o SQLAlchemy object).

    FIX: get_current_user ritorna:
    - dict se DB non disponibile o auth semplificata
    - User SQLAlchemy se DB funziona

    Args:
        current_user: Dict con dati utente o oggetto User SQLAlchemy

    Returns:
        User ID come stringa
    """
    if current_user is None:
        return "unknown"

    if isinstance(current_user, dict):
        # Dict: prova "id", poi "sub" (JWT standard), poi "user_id"
        user_id = current_user.get("id") or current_user.get("sub") or current_user.get("user_id")
        return str(user_id) if user_id else "unknown"
    elif hasattr(current_user, "id"):
        # SQLAlchemy object
        return str(current_user.id)
    else:
        return str(current_user)


def get_user_email(current_user: Union[dict, Any]) -> str:
    """
    Estrae email da current_user (dict o SQLAlchemy object).

    Args:
        current_user: Dict con dati utente o oggetto User SQLAlchemy

    Returns:
        Email come stringa (vuota se non trovata)
    """
    if current_user is None:
        return ""

    if isinstance(current_user, dict):
        return current_user.get("email", "")
    elif hasattr(current_user, "email"):
        return str(current_user.email) if current_user.email else ""
    else:
        return ""


def get_user_tier(current_user: Union[dict, Any]) -> str:
    """
    Estrae tier/subscription level da current_user.

    Args:
        current_user: Dict con dati utente o oggetto User SQLAlchemy

    Returns:
        Tier come stringa (default: "free")
    """
    if current_user is None:
        return "free"

    if isinstance(current_user, dict):
        return current_user.get("tier", "free")
    elif hasattr(current_user, "tier"):
        tier = current_user.tier
        # Se tier è un Enum, prendi il valore
        if hasattr(tier, "value"):
            return str(tier.value)
        return str(tier) if tier else "free"
    else:
        return "free"


def get_user_is_admin(current_user: Union[dict, Any]) -> bool:
    """
    Verifica se user è admin.

    Args:
        current_user: Dict con dati utente o oggetto User SQLAlchemy

    Returns:
        True se admin, False altrimenti
    """
    if current_user is None:
        return False

    if isinstance(current_user, dict):
        return bool(current_user.get("is_admin", False))
    elif hasattr(current_user, "is_admin"):
        return bool(current_user.is_admin)
    else:
        return False


def get_user_username(current_user: Union[dict, Any]) -> str:
    """
    Estrae username da current_user.

    Args:
        current_user: Dict con dati utente o oggetto User SQLAlchemy

    Returns:
        Username come stringa
    """
    if current_user is None:
        return ""

    if isinstance(current_user, dict):
        return current_user.get("username", "") or current_user.get("email", "")
    elif hasattr(current_user, "username"):
        return str(current_user.username) if current_user.username else ""
    else:
        return ""

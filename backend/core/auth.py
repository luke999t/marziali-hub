"""
Authentication utilities re-exported from security module.
This file provides backward compatibility for imports from core.auth.
"""

from core.security import (
    get_current_user,
    get_current_admin_user,
    get_current_active_user,
    get_current_maestro,
    require_admin,
    decode_access_token,
    create_access_token,
)

__all__ = [
    "get_current_user",
    "get_current_admin_user",
    "get_current_active_user",
    "get_current_maestro",
    "require_admin",
    "decode_access_token",
    "create_access_token",
]

"""
🔍 Sentry Error Tracking Configuration
Enterprise-level error monitoring and performance tracking
"""

import os
from typing import Optional, List

# Try to import Sentry SDK (optional dependency)
try:
    import sentry_sdk
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
    from sentry_sdk.integrations.redis import RedisIntegration
    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False
    # Create dummy functions for when Sentry is not available
    class DummyScope:
        def set_tag(self, *args, **kwargs):
            pass
        def set_extra(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    class sentry_sdk:
        @staticmethod
        def init(*args, **kwargs):
            pass
        @staticmethod
        def capture_exception(*args, **kwargs):
            pass
        @staticmethod
        def capture_message(*args, **kwargs):
            pass
        @staticmethod
        def add_breadcrumb(*args, **kwargs):
            pass
        @staticmethod
        def set_user(*args, **kwargs):
            pass
        @staticmethod
        def set_context(*args, **kwargs):
            pass
        @staticmethod
        def push_scope():
            return DummyScope()

# Try to import optional integrations
CELERY_AVAILABLE = False
if SENTRY_AVAILABLE:
    try:
        from sentry_sdk.integrations.celery import CeleryIntegration
        CELERY_AVAILABLE = True
    except (ImportError, Exception):
        CELERY_AVAILABLE = False


def init_sentry(
    dsn: Optional[str] = None,
    environment: str = "production",
    release: Optional[str] = None,
    traces_sample_rate: float = 0.1,
    profiles_sample_rate: float = 0.1,
) -> None:
    """
    Initialize Sentry SDK with comprehensive integrations

    Args:
        dsn: Sentry DSN (Data Source Name)
        environment: Environment name (production, staging, development)
        release: Release version (e.g., "v1.0.0", git commit hash)
        traces_sample_rate: Performance monitoring sample rate (0.0 to 1.0)
        profiles_sample_rate: Profiling sample rate (0.0 to 1.0)
    """

    if not SENTRY_AVAILABLE:
        print("Sentry SDK not installed - error tracking disabled")
        return

    # Get DSN from parameter or environment
    sentry_dsn = dsn or os.getenv("SENTRY_DSN")

    if not sentry_dsn:
        print("⚠️  Sentry DSN not configured - error tracking disabled")
        return

    # Get release from environment if not provided
    if not release:
        release = os.getenv("SENTRY_RELEASE", "unknown")

    # Build integrations list dynamically
    integrations: List = [
        FastApiIntegration(
            transaction_style="url",  # Group by URL pattern
        ),
        SqlalchemyIntegration(),
        RedisIntegration(),
    ]

    # Add optional integrations if available
    if CELERY_AVAILABLE:
        integrations.append(CeleryIntegration())
        print("✅ Celery integration enabled")
    else:
        print("ℹ️  Celery not installed - Celery integration disabled")

    sentry_sdk.init(
        dsn=sentry_dsn,
        environment=environment,
        release=release,

        # Integrations
        integrations=integrations,

        # Performance Monitoring
        traces_sample_rate=traces_sample_rate,
        profiles_sample_rate=profiles_sample_rate,

        # Additional options
        send_default_pii=False,  # Don't send PII by default
        attach_stacktrace=True,  # Always attach stack traces
        max_breadcrumbs=50,  # Keep last 50 breadcrumbs

        # Before send hook for filtering
        before_send=before_send_filter,
    )

    print(f"✅ Sentry initialized: {environment} ({release})")


def before_send_filter(event, hint):
    """
    Filter events before sending to Sentry

    - Ignore certain error types
    - Add custom context
    - Scrub sensitive data
    """

    # Ignore health check errors
    if 'request' in event:
        url = event.get('request', {}).get('url', '')
        if '/health' in url or '/metrics' in url:
            return None

    # Ignore certain exception types
    if 'exception' in event:
        exceptions = event.get('exception', {}).get('values', [])
        for exc in exceptions:
            exc_type = exc.get('type', '')

            # Ignore common non-critical errors
            if exc_type in ['KeyboardInterrupt', 'SystemExit', 'CancelledError']:
                return None

    return event


def set_user_context(user_id: str, email: Optional[str] = None, username: Optional[str] = None):
    """
    Set user context for error tracking

    Args:
        user_id: User ID
        email: User email (optional)
        username: Username (optional)
    """
    sentry_sdk.set_user({
        "id": user_id,
        "email": email,
        "username": username,
    })


def set_custom_context(context_name: str, data: dict):
    """
    Add custom context to error reports

    Args:
        context_name: Name of the context (e.g., "video_processing", "payment")
        data: Dictionary of context data
    """
    sentry_sdk.set_context(context_name, data)


def add_breadcrumb(message: str, category: str, level: str = "info", data: Optional[dict] = None):
    """
    Add a breadcrumb for debugging context

    Args:
        message: Breadcrumb message
        category: Category (e.g., "auth", "video", "payment")
        level: Level (debug, info, warning, error, critical)
        data: Additional data dictionary
    """
    sentry_sdk.add_breadcrumb(
        message=message,
        category=category,
        level=level,
        data=data or {},
    )


def capture_exception(exception: Exception, **scope_kwargs):
    """
    Manually capture an exception

    Args:
        exception: The exception to capture
        scope_kwargs: Additional scope data (tags, extra, etc.)
    """
    with sentry_sdk.push_scope() as scope:
        for key, value in scope_kwargs.items():
            if key == 'tags':
                for tag_key, tag_value in value.items():
                    scope.set_tag(tag_key, tag_value)
            elif key == 'extra':
                for extra_key, extra_value in value.items():
                    scope.set_extra(extra_key, extra_value)

        sentry_sdk.capture_exception(exception)


def capture_message(message: str, level: str = "info", **scope_kwargs):
    """
    Capture a message (not an exception)

    Args:
        message: The message to capture
        level: Message level (debug, info, warning, error, fatal)
        scope_kwargs: Additional scope data
    """
    with sentry_sdk.push_scope() as scope:
        for key, value in scope_kwargs.items():
            if key == 'tags':
                for tag_key, tag_value in value.items():
                    scope.set_tag(tag_key, tag_value)
            elif key == 'extra':
                for extra_key, extra_value in value.items():
                    scope.set_extra(extra_key, extra_value)

        sentry_sdk.capture_message(message, level)

"""
AI_MODULE: Events Test Configuration
AI_DESCRIPTION: Fixture per test events module con auth overrides funzionanti
"""

import os
import pytest
import uuid
from datetime import date, timedelta
from typing import AsyncGenerator

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv()

import httpx
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker


# ======================== SERVICE AVAILABILITY FIXTURES ========================

@pytest.fixture(scope="session")
def stripe_configured():
    """Skip test se Stripe non configurato correttamente."""
    load_dotenv()  # Ensure dotenv is loaded
    key = os.getenv("STRIPE_SECRET_KEY", "")
    if not key.startswith("sk_test_"):
        pytest.skip("Stripe test key non configurata")
    return True


@pytest.fixture(scope="session")
def stripe_webhook_configured():
    """Skip test webhook se secret non configurato."""
    load_dotenv()  # Ensure dotenv is loaded
    secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
    if not secret.startswith("whsec_"):
        pytest.skip("Stripe webhook secret non configurato")
    return True


@pytest.fixture(scope="session")
def mailhog_running():
    """Skip test email se MailHog non attivo."""
    try:
        r = httpx.get("http://localhost:8025/api/v2/messages", timeout=2)
        if r.status_code != 200:
            pytest.skip("MailHog non risponde")
        return True
    except Exception:
        pytest.skip("MailHog non attivo - avvia con: docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog")

from modules.events.models import (
    ASDPartner, Event, EventOption, EventSubscription,
    EventWaitingList, EventNotification, EventStatus,
    SubscriptionStatus, AlertType, ASDRefundRequest, RefundStatus
)
from models.user import User, UserTier


# ======================== DATABASE FIXTURES ========================

@pytest.fixture(scope="function")
async def async_engine():
    """Create async PostgreSQL engine for testing."""
    from core.database import DATABASE_URL_ASYNC
    engine = create_async_engine(DATABASE_URL_ASYNC, echo=False)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(async_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session with explicit transaction management.

    FIX_2025_01_21: Use explicit begin() call (not as context manager around yield)
    to ensure session has active transaction for flush() operations.
    """
    async_session = async_sessionmaker(
        async_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        # Start transaction explicitly
        await session.begin()
        try:
            yield session
        finally:
            # Always rollback to clean up test data
            await session.rollback()


# ======================== USER FIXTURES ========================

@pytest.fixture
async def test_user(db_session) -> User:
    """Create a test user."""
    unique_id = uuid.uuid4().hex[:8]
    user = User(
        id=uuid.uuid4(),
        email=f"event_test_{unique_id}@test.com",
        username=f"eventuser_{unique_id}",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
        tier=UserTier.PREMIUM,
        is_active=True
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest.fixture
async def test_admin_user(db_session) -> User:
    """Create a test admin user."""
    unique_id = uuid.uuid4().hex[:8]
    user = User(
        id=uuid.uuid4(),
        email=f"admin_test_{unique_id}@test.com",
        username=f"adminuser_{unique_id}",
        hashed_password="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy",
        tier=UserTier.PREMIUM,
        is_active=True,
        is_admin=True
    )
    db_session.add(user)
    await db_session.flush()
    return user


# ======================== ASD FIXTURES ========================

@pytest.fixture
async def test_asd_partner(db_session, test_user) -> ASDPartner:
    """Create a test ASD partner."""
    unique_id = uuid.uuid4().hex[:8]
    partner = ASDPartner(
        id=uuid.uuid4(),
        name=f"Test ASD {unique_id}",
        slug=f"test-asd-{unique_id}",
        email=f"asd_{unique_id}@test.com",
        admin_user_id=test_user.id,
        is_active=True,
        default_split_percentage=85.0
    )
    db_session.add(partner)
    await db_session.flush()
    return partner


@pytest.fixture
async def test_asd_with_stripe(db_session, test_user) -> ASDPartner:
    """Create a test ASD partner with Stripe Connect configured."""
    unique_id = uuid.uuid4().hex[:8]
    partner = ASDPartner(
        id=uuid.uuid4(),
        name=f"Stripe ASD {unique_id}",
        slug=f"stripe-asd-{unique_id}",
        email=f"stripe_{unique_id}@asd.com",
        admin_user_id=test_user.id,
        stripe_account_id=f"acct_test_{unique_id}",
        stripe_account_status="active",
        stripe_onboarding_complete=True,
        is_active=True,
        is_verified=True,
        default_split_percentage=85.0
    )
    db_session.add(partner)
    await db_session.flush()
    return partner


# ======================== EVENT FIXTURES ========================

@pytest.fixture
async def test_event(db_session, test_asd_partner) -> Event:
    """Create a test event."""
    unique_id = uuid.uuid4().hex[:8]
    event = Event(
        id=uuid.uuid4(),
        asd_id=test_asd_partner.id,
        title=f"Test Event {unique_id}",
        slug=f"test-event-{unique_id}",
        start_date=date.today() + timedelta(days=30),
        end_date=date.today() + timedelta(days=32),
        total_capacity=100,
        current_subscriptions=0,
        status=EventStatus.DRAFT,
        location_name="Test Location",
        location_city="Test City"
    )
    db_session.add(event)
    await db_session.flush()
    return event


@pytest.fixture
async def test_event_open(db_session, test_asd_partner) -> Event:
    """Create an OPEN test event."""
    unique_id = uuid.uuid4().hex[:8]
    event = Event(
        id=uuid.uuid4(),
        asd_id=test_asd_partner.id,
        title=f"Open Event {unique_id}",
        slug=f"open-event-{unique_id}",
        start_date=date.today() + timedelta(days=30),
        end_date=date.today() + timedelta(days=32),
        total_capacity=100,
        current_subscriptions=0,
        status=EventStatus.OPEN,
        location_name="Open Location"
    )
    db_session.add(event)
    await db_session.flush()
    return event


@pytest.fixture
async def test_event_with_threshold(db_session, test_asd_partner) -> Event:
    """Create a test event with minimum threshold."""
    unique_id = uuid.uuid4().hex[:8]
    event = Event(
        id=uuid.uuid4(),
        asd_id=test_asd_partner.id,
        title=f"Threshold Event {unique_id}",
        slug=f"threshold-event-{unique_id}",
        start_date=date.today() + timedelta(days=30),
        end_date=date.today() + timedelta(days=32),
        total_capacity=100,
        current_subscriptions=5,
        min_threshold=20,
        status=EventStatus.OPEN,
        location_name="Threshold Location"
    )
    db_session.add(event)
    await db_session.flush()
    return event


# ======================== EVENT OPTION FIXTURES ========================

@pytest.fixture
async def test_option(db_session, test_event) -> EventOption:
    """Create a test event option."""
    option = EventOption(
        id=uuid.uuid4(),
        event_id=test_event.id,
        name="Standard Option",
        start_date=test_event.start_date,
        end_date=test_event.end_date,
        price_cents=10000,
        is_active=True
    )
    db_session.add(option)
    await db_session.flush()
    return option


@pytest.fixture
async def test_option_open(db_session, test_event_open) -> EventOption:
    """Create a test event option for open event."""
    option = EventOption(
        id=uuid.uuid4(),
        event_id=test_event_open.id,
        name="Open Event Option",
        start_date=test_event_open.start_date,
        end_date=test_event_open.end_date,
        price_cents=15000,
        is_active=True
    )
    db_session.add(option)
    await db_session.flush()
    return option


# ======================== SUBSCRIPTION FIXTURES ========================

@pytest.fixture
async def test_subscription(db_session, test_event_open, test_option_open, test_user) -> EventSubscription:
    """Create a test subscription."""
    sub = EventSubscription(
        id=uuid.uuid4(),
        event_id=test_event_open.id,
        option_id=test_option_open.id,
        user_id=test_user.id,
        amount_cents=15000,
        asd_amount_cents=12750,
        platform_amount_cents=2250,
        status=SubscriptionStatus.CONFIRMED
    )
    db_session.add(sub)
    await db_session.flush()
    return sub


@pytest.fixture
async def test_subscription_pending(db_session, test_event_open, test_option_open, test_user) -> EventSubscription:
    """Create a pending test subscription."""
    sub = EventSubscription(
        id=uuid.uuid4(),
        event_id=test_event_open.id,
        option_id=test_option_open.id,
        user_id=test_user.id,
        amount_cents=15000,
        asd_amount_cents=12750,
        platform_amount_cents=2250,
        status=SubscriptionStatus.PENDING
    )
    db_session.add(sub)
    await db_session.flush()
    return sub


# ======================== WAITING LIST FIXTURES ========================

@pytest.fixture
async def test_waiting_list_entry(db_session, test_event_open, test_user) -> EventWaitingList:
    """Create a waiting list entry."""
    entry = EventWaitingList(
        id=uuid.uuid4(),
        event_id=test_event_open.id,
        user_id=test_user.id,
        is_active=True
    )
    db_session.add(entry)
    await db_session.flush()
    return entry


# ======================== REFUND REQUEST FIXTURES ========================

@pytest.fixture
async def test_refund_request(db_session, test_subscription, test_asd_partner, test_user) -> ASDRefundRequest:
    """Create a pending refund request."""
    refund = ASDRefundRequest(
        id=uuid.uuid4(),
        asd_id=test_asd_partner.id,
        subscription_id=test_subscription.id,
        requested_by=test_user.id,
        requested_amount_cents=test_subscription.amount_cents,
        reason="Test refund request",
        status=RefundStatus.PENDING,
        requires_approval=True
    )
    db_session.add(refund)
    await db_session.flush()
    return refund


# ======================== APP FIXTURES WITH AUTH ========================

@pytest.fixture
async def app_with_auth(db_session, test_user):
    """Create fresh app instance with auth overrides."""
    from main import app
    from core.database import get_db
    from core.security import get_current_user, get_current_admin_user

    # Override dependencies BEFORE creating client
    async def override_db():
        yield db_session

    async def override_user():
        return test_user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_current_admin_user] = override_user

    yield app

    # Cleanup
    app.dependency_overrides.clear()


@pytest.fixture
async def app_with_admin_auth(db_session, test_admin_user):
    """Create fresh app instance with admin auth overrides."""
    from main import app
    from core.database import get_db
    from core.security import get_current_user, get_current_admin_user

    async def override_db():
        yield db_session

    async def override_user():
        return test_admin_user

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_current_admin_user] = override_user

    yield app

    app.dependency_overrides.clear()


@pytest.fixture
async def auth_client(app_with_auth):
    """Client with working auth."""
    transport = ASGITransport(app=app_with_auth)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def admin_client(app_with_admin_auth):
    """Client with admin auth."""
    transport = ASGITransport(app=app_with_admin_auth)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest.fixture
async def public_client(db_session):
    """Client without auth (public endpoints only)."""
    from main import app
    from core.database import get_db

    async def override_db():
        yield db_session

    app.dependency_overrides[get_db] = override_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()

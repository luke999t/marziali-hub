"""
================================================================================
AI_MODULE: ASD Test Fixtures
AI_VERSION: 1.0.0
AI_DESCRIPTION: Fixtures pytest per ASD (Associazione Sportiva Dilettantistica)
AI_BUSINESS: Test gestionale associazioni sportive con dati reali
AI_TEACHING: Fixtures con scope function per isolamento test

================================================================================

FIXTURES:
- test_asd: Crea ASD di test con dati realistici
- test_asd_id: Ritorna solo l'ID dell'ASD
- test_asd_member: Crea membro ASD di test
- asd_admin_headers: Headers per ASD admin user

DEPENDENCIES:
- test_db: Session database sync
- test_user: Utente base per membership
================================================================================
"""

import pytest
import uuid
from datetime import datetime, timedelta
from typing import Dict


@pytest.fixture(scope="function")
def test_asd(test_db):
    """
    🏢 FIXTURE: Crea ASD (Associazione Sportiva Dilettantistica) di test.

    🎓 AI_BUSINESS: ASD gestisce maestri affiliati, membri, eventi.
    🎓 AI_TEACHING: Fixture con cleanup automatico via yield.

    Returns:
        ASD: Istanza ASD con dati realistici italiani
    """
    from models.maestro import ASD

    unique_id = uuid.uuid4().hex[:8]

    asd = ASD(
        id=uuid.uuid4(),
        name=f"Scuola Arti Marziali Test {unique_id}",
        codice_fiscale=f"TEST{unique_id.upper()}00",  # CF fittizio
        email=f"asd_test_{unique_id}@martialarts.com",
        phone="+39 02 1234567",
        website=f"https://asd-test-{unique_id}.example.com",
        address="Via Test 123",
        city="Milano",
        province="MI",
        postal_code="20100",
        country="Italia",
        presidente_name="Mario Rossi Test",
        presidente_cf=f"RSSMRA{unique_id.upper()}",
        legal_representative_email=f"presidente_{unique_id}@test.com",
        iban="IT60X0542811101000000123456",
        default_donation_split={"maestro": 70, "asd": 25, "platform": 5},
        description="Associazione Sportiva Dilettantistica di test per arti marziali tradizionali",
        is_active=True,
        is_verified=True,
        total_maestros=0,
        total_members=0,
        total_donations_received=0,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    test_db.add(asd)
    test_db.commit()
    test_db.refresh(asd)

    print(f"\n[FIXTURE test_asd] Created ASD: {asd.id} - {asd.name}")

    yield asd

    # Cleanup
    try:
        test_db.delete(asd)
        test_db.commit()
        print(f"[FIXTURE test_asd] Cleaned up ASD: {asd.id}")
    except Exception as e:
        print(f"[FIXTURE test_asd] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="function")
def test_asd_id(test_asd) -> str:
    """
    🆔 FIXTURE: Ritorna solo l'ID dell'ASD di test.

    🎓 AI_TEACHING: Wrapper fixture per quando serve solo l'ID.

    Returns:
        str: UUID dell'ASD come stringa
    """
    return str(test_asd.id)


@pytest.fixture(scope="function")
def test_asd_member(test_db, test_asd, test_user):
    """
    👤 FIXTURE: Crea membro ASD di test.

    🎓 AI_BUSINESS: Membri ASD hanno tessera, quota associativa, certificato medico.

    Dependencies:
        - test_asd: ASD di appartenenza
        - test_user: User collegato al membership

    Returns:
        ASDMember: Membro con dati realistici
    """
    from models.maestro import ASDMember

    member = ASDMember(
        id=uuid.uuid4(),
        asd_id=test_asd.id,
        user_id=test_user.id,
        member_number=f"M{uuid.uuid4().hex[:6].upper()}",
        status="active",
        membership_fee=5000,  # 50 EUR in centesimi
        fee_valid_from=datetime.utcnow(),
        fee_valid_until=datetime.utcnow() + timedelta(days=365),
        fee_paid=True,
        medical_certificate_expiry=datetime.utcnow() + timedelta(days=180),
        joined_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )

    test_db.add(member)
    test_db.commit()
    test_db.refresh(member)

    # Update ASD stats
    test_asd.total_members += 1
    test_db.commit()

    print(f"\n[FIXTURE test_asd_member] Created member: {member.id} for ASD {test_asd.id}")

    yield member

    # Cleanup
    try:
        test_asd.total_members -= 1
        test_db.delete(member)
        test_db.commit()
        print(f"[FIXTURE test_asd_member] Cleaned up member: {member.id}")
    except Exception as e:
        print(f"[FIXTURE test_asd_member] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="session")
def session_asd_admin_token(shared_client) -> str:
    """
    🔑 FIXTURE: Token per utente ASD admin.

    🎓 AI_BUSINESS: ASD admin può gestire maestri affiliati, membri, eventi.
    🎓 AI_TEACHING: Fixture session-scoped per riutilizzo token.

    Returns:
        str: JWT token per ASD admin
    """
    import os
    from core.database import SessionLocal
    from models.user import User, UserTier
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    email = "asd_admin@martialarts.com"
    password = "ASDAdminPassword123!"
    username = "asdadmin"

    print(f"\n[FIXTURE session_asd_admin_token] Setting up ASD admin: {email}")

    # Ensure user exists in DB
    try:
        db = SessionLocal()
        user = db.query(User).filter(User.email == email).first()

        if not user:
            print(f"[FIXTURE session_asd_admin_token] Creating ASD admin user")
            user = User(
                email=email,
                username=username,
                hashed_password=pwd_context.hash(password),
                full_name="ASD Admin Test",
                tier=UserTier.PREMIUM,
                is_admin=False,  # Non admin globale, ma admin ASD
                is_active=True,
                email_verified=True
            )
            db.add(user)
            db.commit()
            print(f"[FIXTURE session_asd_admin_token] Created user: {user.id}")
        else:
            print(f"[FIXTURE session_asd_admin_token] User already exists: {user.id}")

        db.close()
    except Exception as e:
        print(f"[FIXTURE session_asd_admin_token] DB setup failed: {e}")

    # Login
    try:
        response = shared_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password}
        )

        if response.status_code == 200:
            token = response.json()["access_token"]
            print(f"[FIXTURE session_asd_admin_token] [OK] Login successful")
            return token
        else:
            print(f"[FIXTURE session_asd_admin_token] Login failed: {response.status_code}")
    except Exception as e:
        print(f"[FIXTURE session_asd_admin_token] Login exception: {e}")

    return None


@pytest.fixture
def asd_admin_headers(session_asd_admin_token) -> Dict[str, str]:
    """
    📋 FIXTURE: Headers HTTP per richieste ASD admin.

    Returns:
        Dict: Headers con Authorization Bearer token
    """
    if not session_asd_admin_token:
        pytest.skip("ASD admin not available")
    return {"Authorization": f"Bearer {session_asd_admin_token}"}


@pytest.fixture(scope="function")
def test_user_id(test_user) -> str:
    """
    🆔 FIXTURE: Ritorna solo l'ID dell'utente di test.

    Returns:
        str: UUID dell'utente come stringa
    """
    return str(test_user.id)


@pytest.fixture(scope="function")
def test_member_id(test_asd_member) -> str:
    """
    🆔 FIXTURE: Ritorna solo l'ID del membro ASD di test.

    Returns:
        str: UUID del membro come stringa
    """
    return str(test_asd_member.id)

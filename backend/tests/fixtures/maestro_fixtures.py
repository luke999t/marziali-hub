"""
================================================================================
AI_MODULE: Maestro Test Fixtures
AI_VERSION: 1.0.0
AI_DESCRIPTION: Fixtures pytest per profili Maestro (insegnanti arti marziali)
AI_BUSINESS: Test dashboard maestro, video, earnings, live events
AI_TEACHING: Fixtures con dipendenze complesse (User -> Maestro -> ASD)

================================================================================

FIXTURES:
- test_maestro: Crea Maestro profile con user collegato
- test_maestro_user: Crea User con ruolo maestro
- maestro_auth_headers: Headers HTTP per maestro autenticato
- session_maestro_token: Token JWT per maestro (session-scoped)

DEPENDENCIES:
- test_db: Session database sync
- test_asd: ASD per affiliazione (opzionale)
================================================================================
"""

import pytest
import uuid
from datetime import datetime, timedelta
from typing import Dict


@pytest.fixture(scope="function")
def test_maestro_with_user(test_db):
    """
    🎓 FIXTURE: Crea Maestro completo con User associato.

    🎓 AI_BUSINESS: Maestro è un User con profilo esteso per insegnamento.
    🎓 AI_TEACHING: Crea entrambe le entità in una transazione.

    Returns:
        tuple: (User, Maestro) - Entrambe le entità collegate
    """
    from models.user import User, UserTier
    from models.maestro import Maestro, Discipline, BackgroundCheckStatus, MaestroStatus
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    unique_id = uuid.uuid4().hex[:8]

    # Step 1: Crea User
    user = User(
        id=uuid.uuid4(),
        email=f"maestro_{unique_id}@martialarts.com",
        username=f"maestro_{unique_id}",
        hashed_password=pwd_context.hash("MaestroPassword123!"),
        full_name=f"Maestro Test {unique_id}",
        tier=UserTier.PREMIUM,
        is_admin=False,
        is_active=True,
        email_verified=True
    )
    test_db.add(user)
    test_db.flush()  # Get user.id

    # Step 2: Crea Maestro profile
    maestro = Maestro(
        id=uuid.uuid4(),
        user_id=user.id,
        asd_id=None,  # Maestro indipendente
        disciplines=["tai_chi", "karate"],
        primary_discipline=Discipline.TAI_CHI,
        years_experience=15,
        bio="Maestro di test specializzato in Tai Chi e Karate tradizionale.",
        teaching_philosophy="L'arte marziale è un percorso di crescita interiore.",
        certifications=[
            {"name": "Istruttore Tai Chi", "issuer": "CSEN", "date": "2015-01-15"},
            {"name": "Cintura Nera Karate", "issuer": "FIJLKAM", "date": "2010-06-20"}
        ],
        background_check_status=BackgroundCheckStatus.APPROVED,
        background_check_date=datetime.utcnow() - timedelta(days=180),
        background_check_expiry=datetime.utcnow() + timedelta(days=185),
        identity_verified=True,
        identity_verified_at=datetime.utcnow() - timedelta(days=200),
        iban="IT60X0542811101000000654321",
        status=MaestroStatus.ACTIVE,
        verification_level=1,  # Verificato
        total_videos=0,
        total_followers=0,
        total_donations_received=0,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(maestro)
    test_db.commit()
    test_db.refresh(user)
    test_db.refresh(maestro)

    print(f"\n[FIXTURE test_maestro_with_user] Created User: {user.id}, Maestro: {maestro.id}")

    yield (user, maestro)

    # Cleanup
    try:
        test_db.delete(maestro)
        test_db.delete(user)
        test_db.commit()
        print(f"[FIXTURE test_maestro_with_user] Cleaned up")
    except Exception as e:
        print(f"[FIXTURE test_maestro_with_user] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="function")
def test_maestro(test_maestro_with_user):
    """
    🎓 FIXTURE: Ritorna solo il Maestro profile.

    Returns:
        Maestro: Profilo maestro di test
    """
    user, maestro = test_maestro_with_user
    return maestro


@pytest.fixture(scope="function")
def test_maestro_user(test_maestro_with_user):
    """
    👤 FIXTURE: Ritorna lo User con ruolo maestro.

    Returns:
        User: User con Maestro profile associato
    """
    user, maestro = test_maestro_with_user
    return user


@pytest.fixture(scope="function")
def test_maestro_affiliated(test_db, test_asd):
    """
    🎓 FIXTURE: Crea Maestro affiliato a un'ASD.

    🎓 AI_BUSINESS: Maestro affiliato ha split donazioni diverso.

    Dependencies:
        - test_asd: ASD di affiliazione

    Returns:
        tuple: (User, Maestro) affiliato all'ASD
    """
    from models.user import User, UserTier
    from models.maestro import Maestro, Discipline, BackgroundCheckStatus, MaestroStatus
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    unique_id = uuid.uuid4().hex[:8]

    # User
    user = User(
        id=uuid.uuid4(),
        email=f"maestro_aff_{unique_id}@martialarts.com",
        username=f"maestro_aff_{unique_id}",
        hashed_password=pwd_context.hash("MaestroAffPassword123!"),
        full_name=f"Maestro Affiliato {unique_id}",
        tier=UserTier.PREMIUM,
        is_admin=False,
        is_active=True,
        email_verified=True
    )
    test_db.add(user)
    test_db.flush()

    # Maestro affiliato
    maestro = Maestro(
        id=uuid.uuid4(),
        user_id=user.id,
        asd_id=test_asd.id,  # Affiliato!
        disciplines=["karate"],
        primary_discipline=Discipline.KARATE,
        years_experience=10,
        bio="Maestro affiliato all'ASD di test.",
        background_check_status=BackgroundCheckStatus.APPROVED,
        background_check_date=datetime.utcnow() - timedelta(days=90),
        background_check_expiry=datetime.utcnow() + timedelta(days=275),
        identity_verified=True,
        status=MaestroStatus.ACTIVE,
        verification_level=1,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    test_db.add(maestro)

    # Update ASD stats
    test_asd.total_maestros += 1
    test_db.commit()
    test_db.refresh(user)
    test_db.refresh(maestro)

    print(f"\n[FIXTURE test_maestro_affiliated] Created affiliated Maestro: {maestro.id} -> ASD: {test_asd.id}")

    yield (user, maestro)

    # Cleanup
    try:
        test_asd.total_maestros -= 1
        test_db.delete(maestro)
        test_db.delete(user)
        test_db.commit()
        print(f"[FIXTURE test_maestro_affiliated] Cleaned up")
    except Exception as e:
        print(f"[FIXTURE test_maestro_affiliated] Cleanup failed: {e}")
        test_db.rollback()


@pytest.fixture(scope="session")
def session_maestro_token(shared_client) -> str:
    """
    🔑 FIXTURE: Token JWT per utente Maestro (session-scoped).

    🎓 AI_BUSINESS: Token riutilizzabile per tutti i test maestro.
    🎓 AI_TEACHING: Crea user+maestro nel DB e ottiene token via login.

    Returns:
        str: JWT access token per maestro
    """
    from core.database import SessionLocal
    from models.user import User, UserTier
    from models.maestro import Maestro, Discipline, BackgroundCheckStatus, MaestroStatus
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    email = "maestro_test@martialarts.com"
    password = "MaestroTestPassword123!"
    username = "maestro_test"

    print(f"\n[FIXTURE session_maestro_token] Setting up maestro: {email}")

    try:
        db = SessionLocal()

        # Check if user exists
        user = db.query(User).filter(User.email == email).first()

        if not user:
            print(f"[FIXTURE session_maestro_token] Creating maestro user")
            user = User(
                id=uuid.uuid4(),
                email=email,
                username=username,
                hashed_password=pwd_context.hash(password),
                full_name="Maestro Test Session",
                tier=UserTier.PREMIUM,
                is_admin=False,
                is_active=True,
                email_verified=True
            )
            db.add(user)
            db.flush()

            # Create Maestro profile
            maestro = Maestro(
                id=uuid.uuid4(),
                user_id=user.id,
                disciplines=["tai_chi"],
                primary_discipline=Discipline.TAI_CHI,
                years_experience=10,
                bio="Maestro di test per session fixtures",
                background_check_status=BackgroundCheckStatus.APPROVED,
                background_check_date=datetime.utcnow() - timedelta(days=100),
                background_check_expiry=datetime.utcnow() + timedelta(days=265),
                identity_verified=True,
                status=MaestroStatus.ACTIVE,
                verification_level=1,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(maestro)
            db.commit()
            print(f"[FIXTURE session_maestro_token] Created user: {user.id}, maestro: {maestro.id}")
        else:
            print(f"[FIXTURE session_maestro_token] User exists: {user.id}")
            # Verify maestro profile exists
            maestro = db.query(Maestro).filter(Maestro.user_id == user.id).first()
            if not maestro:
                print(f"[FIXTURE session_maestro_token] Creating missing maestro profile")
                maestro = Maestro(
                    id=uuid.uuid4(),
                    user_id=user.id,
                    disciplines=["tai_chi"],
                    primary_discipline=Discipline.TAI_CHI,
                    years_experience=10,
                    background_check_status=BackgroundCheckStatus.APPROVED,
                    identity_verified=True,
                    status=MaestroStatus.ACTIVE,
                    verification_level=1,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(maestro)
                db.commit()
                print(f"[FIXTURE session_maestro_token] Created maestro: {maestro.id}")

        db.close()
    except Exception as e:
        print(f"[FIXTURE session_maestro_token] DB setup failed: {e}")
        return None

    # Login
    try:
        response = shared_client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password}
        )

        if response.status_code == 200:
            token = response.json()["access_token"]
            print(f"[FIXTURE session_maestro_token] [OK] Login successful")
            return token
        else:
            print(f"[FIXTURE session_maestro_token] Login failed: {response.status_code} - {response.text[:200]}")
    except Exception as e:
        print(f"[FIXTURE session_maestro_token] Login exception: {e}")

    return None


@pytest.fixture
def maestro_auth_headers(session_maestro_token) -> Dict[str, str]:
    """
    📋 FIXTURE: Headers HTTP per richieste autenticate da Maestro.

    🎓 AI_TEACHING: Wrapper fixture per headers Authorization.

    Returns:
        Dict: Headers con Bearer token
    """
    if not session_maestro_token:
        pytest.skip("Maestro not available - run scripts/seed_test_data.py first")
    return {"Authorization": f"Bearer {session_maestro_token}"}


@pytest.fixture
def auth_headers_maestro(maestro_auth_headers) -> Dict[str, str]:
    """
    📋 FIXTURE: Alias per maestro_auth_headers (compatibilità).

    Returns:
        Dict: Headers con Bearer token maestro
    """
    return maestro_auth_headers

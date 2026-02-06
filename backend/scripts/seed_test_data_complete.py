"""
================================================================================
AI_MODULE: Complete Test Data Seeder
AI_VERSION: 2.0.0
AI_DESCRIPTION: Popola database con tutti i dati necessari per test integration
AI_BUSINESS: Necessario per test ZERO MOCK con dati reali completi
AI_TEACHING: Script standalone per setup ambiente test

================================================================================

USAGE:
    cd backend
    python scripts/seed_test_data_complete.py

CREATES:
- 3 Test Users (free, premium, admin)
- 1 Maestro User + Maestro Profile
- 1 ASD Admin User
- 1 ASD (Associazione Sportiva Dilettantistica)
- 1 ASD Member
- 1 Maestro affiliated to ASD
- 3 Test Videos (free, premium, featured)
- 1 Scheduled LiveEvent

================================================================================
"""

import sys
import os
import uuid
from datetime import datetime, timedelta

# Load .env first
from dotenv import load_dotenv
load_dotenv()

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import SessionLocal, engine, Base
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_or_create_user(db, email, username, password, full_name, tier, is_admin=False):
    """
    Get existing user or create new one.

    Returns: (User, created: bool)
    """
    from models.user import User, UserTier

    user = db.query(User).filter(User.email == email).first()
    if user:
        return user, False

    tier_enum = getattr(UserTier, tier.upper(), UserTier.FREE)

    user = User(
        id=uuid.uuid4(),
        email=email,
        username=username,
        hashed_password=pwd_context.hash(password),
        full_name=full_name,
        tier=tier_enum,
        is_admin=is_admin,
        is_active=True,
        email_verified=True
    )
    db.add(user)
    db.flush()
    return user, True


def create_test_users(db):
    """Create base test users."""
    from models.user import UserTier

    print("\n" + "="*60)
    print(" CREATING TEST USERS")
    print("="*60)

    users_to_create = [
        ("test@martialarts.com", "testuser", "TestPassword123!", "Test User", "FREE", False),
        ("premium@martialarts.com", "premiumuser", "PremiumPassword123!", "Premium User", "PREMIUM", False),
        ("admin@martialarts.com", "adminuser", "AdminPassword123!", "Admin User", "PREMIUM", True),
    ]

    users = {}
    for email, username, password, full_name, tier, is_admin in users_to_create:
        user, created = get_or_create_user(db, email, username, password, full_name, tier, is_admin)
        action = " Created" if created else " Exists"
        print(f"  {action}: {email} ({tier})")
        users[email] = user

    return users


def create_maestro_user(db):
    """Create maestro user with profile."""
    from models.user import UserTier
    from models.maestro import Maestro, Discipline, BackgroundCheckStatus, MaestroStatus

    print("\n" + "="*60)
    print(" CREATING MAESTRO USER + PROFILE")
    print("="*60)

    email = "maestro_test@martialarts.com"
    username = "maestro_test"
    password = "MaestroTestPassword123!"

    user, user_created = get_or_create_user(
        db, email, username, password,
        "Maestro Test Session", "PREMIUM", False
    )

    # Check if maestro profile exists
    maestro = db.query(Maestro).filter(Maestro.user_id == user.id).first()

    if not maestro:
        maestro = Maestro(
            id=uuid.uuid4(),
            user_id=user.id,
            disciplines=["tai_chi", "karate"],
            primary_discipline=Discipline.TAI_CHI,
            years_experience=15,
            bio="Maestro di test per session fixtures. Specializzato in Tai Chi e Karate.",
            teaching_philosophy="L'arte marziale come percorso di crescita.",
            certifications=[
                {"name": "Istruttore Tai Chi", "issuer": "CSEN", "date": "2015-01-15"},
                {"name": "Cintura Nera Karate 3 Dan", "issuer": "FIJLKAM", "date": "2010-06-20"}
            ],
            background_check_status=BackgroundCheckStatus.APPROVED,
            background_check_date=datetime.utcnow() - timedelta(days=100),
            background_check_expiry=datetime.utcnow() + timedelta(days=265),
            identity_verified=True,
            identity_verified_at=datetime.utcnow() - timedelta(days=150),
            iban="IT60X0542811101000000654321",
            status=MaestroStatus.ACTIVE,
            verification_level=1,
            total_videos=0,
            total_followers=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(maestro)
        db.flush()
        print(f"   Created Maestro profile: {maestro.id}")
    else:
        print(f"   Maestro profile exists: {maestro.id}")

    print(f"  {' Created' if user_created else ' Exists'}: {email}")

    return user, maestro


def create_asd_and_admin(db):
    """Create ASD and ASD admin user."""
    from models.maestro import ASD, ASDMember

    print("\n" + "="*60)
    print(" CREATING ASD + ADMIN")
    print("="*60)

    # ASD Admin user
    admin_email = "asd_admin@martialarts.com"
    admin_user, admin_created = get_or_create_user(
        db, admin_email, "asdadmin", "ASDAdminPassword123!",
        "ASD Admin Test", "PREMIUM", False
    )
    print(f"  {' Created' if admin_created else ' Exists'}: {admin_email}")

    # ASD
    asd = db.query(ASD).filter(ASD.codice_fiscale == "TESTASD00001").first()

    if not asd:
        asd = ASD(
            id=uuid.uuid4(),
            name="Scuola Arti Marziali Test",
            codice_fiscale="TESTASD00001",
            email="asd_test@martialarts.com",
            phone="+39 02 1234567",
            website="https://asd-test.martialarts.com",
            address="Via Test 123",
            city="Milano",
            province="MI",
            postal_code="20100",
            country="Italia",
            presidente_name="Mario Rossi Test",
            presidente_cf="RSSMRA80A01F205X",
            legal_representative_email="presidente@asd-test.com",
            iban="IT60X0542811101000000123456",
            default_donation_split={"maestro": 70, "asd": 25, "platform": 5},
            description="Associazione Sportiva Dilettantistica di test per arti marziali tradizionali",
            is_active=True,
            is_verified=True,
            total_maestros=0,
            total_members=0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(asd)
        db.flush()
        print(f"   Created ASD: {asd.name} (CF: {asd.codice_fiscale})")
    else:
        print(f"   ASD exists: {asd.name}")

    return asd, admin_user


def create_asd_member(db, asd, user):
    """Create ASD member."""
    from models.maestro import ASDMember

    print("\n" + "="*60)
    print(" CREATING ASD MEMBER")
    print("="*60)

    member = db.query(ASDMember).filter(
        ASDMember.asd_id == asd.id,
        ASDMember.user_id == user.id
    ).first()

    if not member:
        member = ASDMember(
            id=uuid.uuid4(),
            asd_id=asd.id,
            user_id=user.id,
            member_number=f"M{uuid.uuid4().hex[:6].upper()}",
            status="active",
            membership_fee=5000,  # 50 EUR
            fee_valid_from=datetime.utcnow(),
            fee_valid_until=datetime.utcnow() + timedelta(days=365),
            fee_paid=True,
            medical_certificate_expiry=datetime.utcnow() + timedelta(days=180),
            joined_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(member)
        asd.total_members += 1
        db.flush()
        print(f"   Created ASD Member: {member.member_number}")
    else:
        print(f"   Member exists: {member.member_number}")

    return member


def create_affiliated_maestro(db, asd):
    """Create maestro affiliated to ASD."""
    from models.maestro import Maestro, Discipline, BackgroundCheckStatus, MaestroStatus

    print("\n" + "="*60)
    print(" CREATING AFFILIATED MAESTRO")
    print("="*60)

    email = "maestro_aff@martialarts.com"
    user, user_created = get_or_create_user(
        db, email, "maestro_aff", "MaestroAffPassword123!",
        "Maestro Affiliato Test", "PREMIUM", False
    )

    maestro = db.query(Maestro).filter(Maestro.user_id == user.id).first()

    if not maestro:
        maestro = Maestro(
            id=uuid.uuid4(),
            user_id=user.id,
            asd_id=asd.id,  # Affiliated!
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
        db.add(maestro)
        asd.total_maestros += 1
        db.flush()
        print(f"   Created Affiliated Maestro: {maestro.id} -> ASD: {asd.id}")
    else:
        print(f"   Affiliated Maestro exists: {maestro.id}")

    print(f"  {' Created' if user_created else ' Exists'}: {email}")

    return user, maestro


def create_test_videos(db):
    """Create test videos."""
    from models.video import Video, VideoStatus, VideoCategory, Difficulty

    print("\n" + "="*60)
    print(" CREATING TEST VIDEOS")
    print("="*60)

    videos_data = [
        {
            "title": "Tai Chi Yang Form - Beginner Guide",
            "slug": "tai-chi-yang-form-beginner",
            "category": VideoCategory.TECHNIQUE,
            "difficulty": Difficulty.BEGINNER,
            "tier": "free",
            "is_premium": False,
            "is_featured": True
        },
        {
            "title": "Karate Kata Heian Shodan",
            "slug": "karate-kata-heian-shodan",
            "category": VideoCategory.KATA,
            "difficulty": Difficulty.INTERMEDIATE,
            "tier": "free",
            "is_premium": False,
            "is_featured": False
        },
        {
            "title": "Advanced Combat Techniques - Premium",
            "slug": "advanced-combat-premium",
            "category": VideoCategory.COMBAT,
            "difficulty": Difficulty.ADVANCED,
            "tier": "premium",
            "is_premium": True,
            "is_featured": False
        }
    ]

    videos = []
    for vdata in videos_data:
        video = db.query(Video).filter(Video.slug == vdata["slug"]).first()

        if not video:
            video = Video(
                id=uuid.uuid4(),
                title=vdata["title"],
                description=f"Test video: {vdata['title']}",
                slug=vdata["slug"],
                category=vdata["category"],
                style="Mixed Martial Arts",
                difficulty=vdata["difficulty"],
                tags=["test", vdata["category"].value],
                video_url=f"https://cdn.test.com/videos/{vdata['slug']}.mp4",
                duration=1800,
                tier_required=vdata["tier"],
                is_premium=vdata["is_premium"],
                is_public=True,
                is_featured=vdata["is_featured"],
                status=VideoStatus.READY,
                view_count=100,
                created_at=datetime.utcnow() - timedelta(days=7),
                updated_at=datetime.utcnow(),
                published_at=datetime.utcnow() - timedelta(days=6)
            )
            db.add(video)
            db.flush()
            print(f"   Created Video: {vdata['title']}")
        else:
            print(f"   Video exists: {vdata['title']}")

        videos.append(video)

    return videos


def create_live_event(db, maestro):
    """Create scheduled live event."""
    from models.video import LiveEvent, LiveEventType, LiveEventStatus

    print("\n" + "="*60)
    print(" CREATING LIVE EVENT")
    print("="*60)

    stream_key = "test_stream_key_001"
    event = db.query(LiveEvent).filter(LiveEvent.stream_key == stream_key).first()

    if not event:
        event = LiveEvent(
            id=uuid.uuid4(),
            maestro_id=maestro.id,
            title="Live Tai Chi Class - Test Event",
            description="Lezione live di Tai Chi per principianti.",
            event_type=LiveEventType.LIVE_CLASS,
            stream_key=stream_key,
            rtmp_url="rtmp://stream.test.com/live/test_001",
            hls_url="https://cdn.test.com/live/test_001/master.m3u8",
            status=LiveEventStatus.SCHEDULED,
            is_active=False,
            scheduled_start=datetime.utcnow() + timedelta(days=1),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        db.add(event)
        db.flush()
        print(f"   Created LiveEvent: {event.title}")
    else:
        print(f"   LiveEvent exists: {event.title}")

    return event


def main():
    """Main seeder function."""
    print("\n" + "="*60)
    print("[SETUP] COMPLETE TEST DATA SEEDER")
    print("="*60)
    print(f" Database URL: {os.getenv('DATABASE_URL', 'NOT SET')[:50]}...")

    # Create tables if not exist
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        # 1. Create base test users
        users = create_test_users(db)

        # 2. Create maestro user with profile
        maestro_user, maestro = create_maestro_user(db)

        # 3. Create ASD and admin
        asd, asd_admin = create_asd_and_admin(db)

        # 4. Create ASD member (using premium user)
        member = create_asd_member(db, asd, users["premium@martialarts.com"])

        # 5. Create affiliated maestro
        aff_user, aff_maestro = create_affiliated_maestro(db, asd)

        # 6. Create test videos
        videos = create_test_videos(db)

        # Store values before potential failure
        asd_cf = asd.codice_fiscale
        video_count = len(videos)

        # Commit core data first
        db.commit()

        # 7. Create live event (optional - may fail if DB schema out of sync)
        live_event_count = 0
        try:
            live_event = create_live_event(db, maestro)
            db.commit()
            live_event_count = 1
        except Exception as e:
            db.rollback()
            print(f"\n   [WARN] LiveEvent creation skipped: {e}")
            print("   (Run Alembic migrations to add missing columns)")

        print("\n" + "="*60)
        print(" SEEDING COMPLETE!")
        print("="*60)
        print("\n Test Credentials:")
        print("  - test@martialarts.com / TestPassword123! (FREE)")
        print("  - premium@martialarts.com / PremiumPassword123! (PREMIUM)")
        print("  - admin@martialarts.com / AdminPassword123! (ADMIN)")
        print("  - maestro_test@martialarts.com / MaestroTestPassword123! (MAESTRO)")
        print("  - asd_admin@martialarts.com / ASDAdminPassword123! (ASD ADMIN)")
        print("  - maestro_aff@martialarts.com / MaestroAffPassword123! (MAESTRO AFFILIATO)")

        print(f"\n Created Entities:")
        print(f"  - Users: 6")
        print(f"  - Maestro profiles: 2")
        print(f"  - ASD: 1 (CF: {asd_cf})")
        print(f"  - ASD Members: 1")
        print(f"  - Videos: {video_count}")
        print(f"  - Live Events: {live_event_count}")

    except Exception as e:
        db.rollback()
        print(f"\n Error: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()


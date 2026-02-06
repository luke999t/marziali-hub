"""
================================================================================
AI_MODULE: Test Data Setup
AI_VERSION: 1.0.0
AI_DESCRIPTION: Popola database con dati test REALI per eliminare skip
AI_BUSINESS: Garantisce test coverage 98%+ senza skip
AI_TEACHING: Direct DB insertion per test fixtures persistenti
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved

PROBLEMA: 21 test skippati per mancanza dati
SOLUZIONE: Crea utenti + video + progetti test nel database

ZERO MOCK POLICY: Dati REALI inseriti in database REALE
================================================================================
"""

import sys
import asyncio
import uuid
from datetime import datetime, timedelta
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from core.database import SessionLocal, async_engine
from models.user import User, UserTier
from models.video import Video, VideoCategory, Difficulty, VideoStatus
from core.security import get_password_hash


async def setup_test_users():
    """
    Crea utenti test standard nel database.

    Utenti creati:
    - test@martialarts.com (FREE)
    - premium@martialarts.com (PREMIUM)
    - admin@martialarts.com (ADMIN)
    """
    print("\n" + "=" * 70)
    print("STEP 1: Setup Test Users")
    print("=" * 70)

    db = SessionLocal()

    users_to_create = [
        {
            "email": "test@martialarts.com",
            "username": "testuser_martial",
            "password": "TestPassword123!",
            "full_name": "Test User Martial Arts",
            "tier": UserTier.FREE,
            "is_admin": False,
            "is_active": True,
            "email_verified": True
        },
        {
            "email": "premium@martialarts.com",
            "username": "premiumuser_martial",
            "password": "PremiumPassword123!",
            "full_name": "Premium User Martial Arts",
            "tier": UserTier.PREMIUM,
            "is_admin": False,
            "is_active": True,
            "email_verified": True
        },
        {
            "email": "admin@martialarts.com",
            "username": "adminuser_martial",
            "password": "AdminPassword123!",
            "full_name": "Admin User Martial Arts",
            "tier": UserTier.PREMIUM,
            "is_admin": True,
            "is_active": True,
            "email_verified": True
        }
    ]

    created_users = []

    for user_data in users_to_create:
        # Check if user exists
        existing_user = db.query(User).filter(User.email == user_data["email"]).first()

        if existing_user:
            print(f"[OK] User {user_data['email']} already exists (ID: {existing_user.id})")

            # Update tier and admin status if needed
            needs_update = False
            if existing_user.tier != user_data["tier"]:
                print(f"  -> Updating tier from {existing_user.tier} to {user_data['tier']}")
                existing_user.tier = user_data["tier"]
                needs_update = True

            if existing_user.is_admin != user_data["is_admin"]:
                print(f"  -> Updating is_admin from {existing_user.is_admin} to {user_data['is_admin']}")
                existing_user.is_admin = user_data["is_admin"]
                needs_update = True

            if not existing_user.email_verified:
                print(f"  -> Setting email_verified = True")
                existing_user.email_verified = True
                needs_update = True

            if not existing_user.is_active:
                print(f"  -> Setting is_active = True")
                existing_user.is_active = True
                needs_update = True

            if needs_update:
                db.commit()
                db.refresh(existing_user)

            created_users.append(existing_user)
        else:
            # Create new user
            password = user_data.pop("password")
            new_user = User(
                id=uuid.uuid4(),
                **user_data,
                hashed_password=get_password_hash(password),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )

            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            print(f"[OK] Created user {new_user.email} (ID: {new_user.id}, Tier: {new_user.tier.value})")
            created_users.append(new_user)

    db.close()

    print(f"\n[SUCCESS] Total users ready: {len(created_users)}")
    return created_users


async def setup_test_videos():
    """
    Crea video test nel database per test che richiedono video esistenti.
    """
    print("\n" + "=" * 70)
    print("STEP 2: Setup Test Videos")
    print("=" * 70)

    db = SessionLocal()

    videos_to_create = [
        {
            "title": "Test Video Karate Gyaku-zuki",
            "slug": "test-video-karate-gyaku-zuki",
            "description": "Video di test per fusion API - Karate reverse punch",
            "duration": 300,
            "is_premium": True,
            "tier_required": "premium",
            "style": "karate",
            "category": VideoCategory.TECHNIQUE,
            "difficulty": Difficulty.INTERMEDIATE,
            "video_url": "https://test.example.com/karate-gyaku-zuki.mp4",
            "status": VideoStatus.READY,
            "is_public": True
        },
        {
            "title": "Test Video Taekwondo Roundhouse",
            "slug": "test-video-taekwondo-roundhouse",
            "description": "Video di test per fusion API - Taekwondo roundhouse kick",
            "duration": 250,
            "is_premium": True,
            "tier_required": "premium",
            "style": "taekwondo",
            "category": VideoCategory.TECHNIQUE,
            "difficulty": Difficulty.ADVANCED,
            "video_url": "https://test.example.com/taekwondo-roundhouse.mp4",
            "status": VideoStatus.READY,
            "is_public": True
        },
        {
            "title": "Test Video Kung Fu Forms",
            "slug": "test-video-kung-fu-forms",
            "description": "Video di test per fusion API - Kung Fu forms",
            "duration": 400,
            "is_premium": False,
            "tier_required": "free",
            "style": "kung-fu",
            "category": VideoCategory.KATA,
            "difficulty": Difficulty.BEGINNER,
            "video_url": "https://test.example.com/kung-fu-forms.mp4",
            "status": VideoStatus.READY,
            "is_public": True
        },
        {
            "title": "Test Video for Downloads",
            "slug": "test-video-for-downloads",
            "description": "Test video for download integration tests",
            "duration": 180,
            "is_premium": True,
            "tier_required": "premium",
            "style": "mixed",
            "category": VideoCategory.TECHNIQUE,
            "difficulty": Difficulty.INTERMEDIATE,
            "video_url": "https://test.example.com/download-test.mp4",
            "status": VideoStatus.READY,
            "is_public": True
        }
    ]

    created_videos = []

    for video_data in videos_to_create:
        # Check if video exists
        existing_video = db.query(Video).filter(Video.slug == video_data["slug"]).first()

        if existing_video:
            print(f"[OK] Video '{video_data['title']}' already exists (ID: {existing_video.id})")
            created_videos.append(existing_video)
        else:
            # Create new video
            new_video = Video(
                id=uuid.uuid4(),
                **video_data,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )

            db.add(new_video)
            db.commit()
            db.refresh(new_video)

            print(f"[OK] Created video '{new_video.title}' (ID: {new_video.id})")
            created_videos.append(new_video)

    db.close()

    print(f"\n[SUCCESS] Total videos ready: {len(created_videos)}")
    return created_videos


async def verify_setup():
    """
    Verifica che tutti i dati siano stati creati correttamente.
    """
    print("\n" + "=" * 70)
    print("STEP 3: Verification")
    print("=" * 70)

    db = SessionLocal()

    # Count users
    total_users = db.query(User).count()
    free_users = db.query(User).filter(User.tier == UserTier.FREE).count()
    premium_users = db.query(User).filter(User.tier == UserTier.PREMIUM).count()
    admin_users = db.query(User).filter(User.is_admin == True).count()

    print(f"\nUsers in database:")
    print(f"  - Total: {total_users}")
    print(f"  - FREE: {free_users}")
    print(f"  - PREMIUM: {premium_users}")
    print(f"  - Admins: {admin_users}")

    # Count videos
    total_videos = db.query(Video).count()
    free_videos = db.query(Video).filter(Video.is_premium == False).count()
    premium_videos = db.query(Video).filter(Video.is_premium == True).count()

    print(f"\nVideos in database:")
    print(f"  - Total: {total_videos}")
    print(f"  - Free: {free_videos}")
    print(f"  - Premium: {premium_videos}")

    # Check specific test users
    test_emails = [
        "test@martialarts.com",
        "premium@martialarts.com",
        "admin@martialarts.com"
    ]

    print(f"\nTest users verification:")
    for email in test_emails:
        user = db.query(User).filter(User.email == email).first()
        if user:
            print(f"  [OK] {email}: Tier={user.tier.value}, Admin={user.is_admin}, Active={user.is_active}")
        else:
            print(f"  [FAIL] {email}: NOT FOUND")

    # Check specific test videos
    test_slugs = [
        "test-video-karate-gyaku-zuki",
        "test-video-for-downloads"
    ]

    print(f"\nTest videos verification:")
    for slug in test_slugs:
        video = db.query(Video).filter(Video.slug == slug).first()
        if video:
            print(f"  [OK] {slug}: ID={video.id}, Duration={video.duration}s")
        else:
            print(f"  [FAIL] {slug}: NOT FOUND")

    db.close()

    print("\n" + "=" * 70)
    print("[SUCCESS] SETUP COMPLETE")
    print("=" * 70)
    print("\nYou can now run tests with:")
    print("  pytest tests/api/test_fusion_api.py -v")
    print("  pytest tests/api/test_skeleton_api.py -v")
    print("  pytest tests/api/ -v --tb=short")
    print("\nExpected result: < 5 skipped, 0 failed")


async def main():
    """Main setup function."""
    print("=" * 70)
    print("MEDIA CENTER ARTI MARZIALI - TEST DATA SETUP")
    print("=" * 70)
    print("\nThis script will:")
    print("1. Create/update test users (FREE, PREMIUM, ADMIN)")
    print("2. Create test videos for fusion/skeleton tests")
    print("3. Verify all data is correctly inserted")
    print("\nZERO MOCK POLICY: All data inserted in REAL database")
    print("=" * 70)

    try:
        users = await setup_test_users()
        videos = await setup_test_videos()
        await verify_setup()

        print("\n[SUCCESS] All test data ready!")
        print(f"   - {len(users)} users configured")
        print(f"   - {len(videos)} videos created")

        return 0

    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)

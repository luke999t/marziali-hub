"""
Script to initialize the database with all tables
"""
import sys
import os
from pathlib import Path
from dotenv import load_dotenv

# Add backend to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

# IMPORTANT: Load .env BEFORE importing database module
env_file = backend_dir / ".env"
if env_file.exists():
    load_dotenv(env_file)
    print(f"Loaded .env from: {env_file}")
    print(f"DATABASE_URL: {os.getenv('DATABASE_URL')}")
else:
    print(f"WARNING: .env file not found at {env_file}")

from core.database import init_db, Base, engine

# Import ALL models - MUST import everything to register with Base.metadata
print("\n📦 Importing models...")

from models.user import User, SubscriptionHistory, ViewingHistory, Favorite, Purchase
print("[OK] User models")

try:
    from models.video import Video, Course, CourseItem, LiveEvent, LibraryItem
    print("[OK] Video models")
except Exception as e:
    print(f"[SKIP] Video: {e}")

try:
    from models.maestro import Maestro, ASD, ASDMember, Discipline
    print("[OK] Maestro models")
except Exception as e:
    print(f"[SKIP] Maestro: {e}")

try:
    from models.ads import AdsSession, AdInventory, BlockchainBatch, PauseAd, PauseAdImpression
    print("[OK] Ads models")
except Exception as e:
    print(f"[SKIP] Ads: {e}")

try:
    from models.donation import StellineWallet, Donation, WithdrawalRequest, WalletTransaction
    print("[OK] Donation models")
except Exception as e:
    print(f"[SKIP] Donation: {e}")

try:
    from models.communication import Message, CorrectionRequest, TranslationDataset, GlossaryTerm
    print("[OK] Communication models")
except Exception as e:
    print(f"[SKIP] Communication: {e}")

try:
    from models.curriculum import Curriculum, CurriculumLevel, CurriculumEnrollment, Certificate
    print("[OK] Curriculum models")
except Exception as e:
    print(f"[SKIP] Curriculum: {e}")

try:
    from models.live_minor import Minor, ParentalApproval, ActivityLog
    print("[OK] Minor models")
except Exception as e:
    print(f"[SKIP] Minor: {e}")

try:
    from models.ingest_project import IngestProject, IngestBatch, IngestAsset
    print("[OK] Ingest models")
except Exception as e:
    print(f"[SKIP] Ingest: {e}")

try:
    from models.user_video import UserVideo
    print("[OK] UserVideo model")
except Exception as e:
    print(f"[SKIP] UserVideo: {e}")

try:
    from models.payment import Subscription
    print("[OK] Payment models")
except Exception as e:
    print(f"[SKIP] Payment: {e}")

try:
    from models.notification import Notification, DeviceToken, NotificationPreference
    print("[OK] Notification models")
except Exception as e:
    print(f"[SKIP] Notification: {e}")

try:
    from models.download import Download, DownloadLimit
    print("[OK] Download models")
except Exception as e:
    print(f"[SKIP] Download: {e}")

print(f"\n📊 Database URL: {os.getenv('DATABASE_URL')}")
print(f"📋 Total tables to create: {len(Base.metadata.tables)}")

# List all tables
print("\n📝 Tables registered:")
for table_name in sorted(Base.metadata.tables.keys()):
    print(f"   - {table_name}")

# Create ALL tables
print("\n🔧 Creating tables...")
try:
    Base.metadata.create_all(bind=engine)
    print(f"\n✅ SUCCESS! {len(Base.metadata.tables)} tables created/verified")
except Exception as e:
    print(f"\n❌ ERROR creating tables: {e}")
    raise

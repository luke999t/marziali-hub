"""
🎓 AI_MODULE: Setup Test Data
🎓 AI_DESCRIPTION: Crea utenti test nel database per eseguire test suite
🎓 AI_BUSINESS: Necessario per test ZERO MOCK con autenticazione reale
"""

import sys
import os

# Carica .env prima di tutto
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import SessionLocal, engine, Base
from models.user import User, UserTier
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_test_users():
    """Crea utenti test nel database."""
    
    print(f"📍 Database URL: {os.getenv('DATABASE_URL', 'NOT SET')}")
    
    # Crea tabelle se non esistono
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    users_to_create = [
        {
            "email": "test@martialarts.com",
            "username": "testuser",
            "password": "TestPassword123!",
            "full_name": "Test User",
            "tier": UserTier.FREE,
            "is_admin": False,
        },
        {
            "email": "premium@martialarts.com",
            "username": "premiumuser",
            "password": "PremiumPassword123!",
            "full_name": "Premium User",
            "tier": UserTier.PREMIUM,
            "is_admin": False,
        },
        {
            "email": "admin@martialarts.com",
            "username": "adminuser",
            "password": "AdminPassword123!",
            "full_name": "Admin User",
            "tier": UserTier.PREMIUM,
            "is_admin": True,
        },
    ]
    
    created = 0
    for user_data in users_to_create:
        # Check if exists
        existing = db.query(User).filter(User.email == user_data["email"]).first()
        if existing:
            print(f"✓ User {user_data['email']} already exists")
            continue
        
        # Create user
        user = User(
            email=user_data["email"],
            username=user_data["username"],
            hashed_password=pwd_context.hash(user_data["password"]),
            full_name=user_data["full_name"],
            tier=user_data["tier"],
            is_admin=user_data["is_admin"],
            is_active=True,
            email_verified=True,
        )
        db.add(user)
        created += 1
        print(f"✅ Created user: {user_data['email']}")
    
    db.commit()
    db.close()
    
    print(f"\n🎉 Setup complete: {created} users created")
    print("\nTest credentials:")
    print("  - test@martialarts.com / TestPassword123!")
    print("  - premium@martialarts.com / PremiumPassword123!")
    print("  - admin@martialarts.com / AdminPassword123!")

if __name__ == "__main__":
    print("🔧 Setting up test data...")
    create_test_users()

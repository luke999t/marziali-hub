"""
Seed test users via API calls
Simple approach without SQLAlchemy relationship issues
"""

import requests
import sys

BASE_URL = "http://localhost:8000"

# Test users for pytest (matching conftest.py)
TEST_USERS = [
    {
        "email": "test@example.com",
        "username": "testuser",
        "password": "TestPassword123!",
        "full_name": "Test User"
    },
    {
        "email": "admin@example.com",
        "username": "adminuser",
        "password": "AdminPassword123!",
        "full_name": "Admin User"
    },
    {
        "email": "premium@example.com",
        "username": "premiumuser",
        "password": "PremiumPassword123!",
        "full_name": "Premium User"
    }
]

def check_backend():
    """Check if backend is running"""
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            print("[OK] Backend is running")
            return True
        else:
            print(f"[ERROR] Backend returned status {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Backend not reachable: {e}")
        print("   Start backend: python -m uvicorn main:app --port 8000")
        return False

def register_user(user_data):
    """Register a single user via API"""
    print(f"\n[REGISTER] {user_data['email']}...")

    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/auth/register",
            json=user_data,
            timeout=10
        )

        if response.status_code in [200, 201]:
            print(f"   [OK] Registered successfully")
            return True
        elif response.status_code == 400:
            error = response.json()
            if "already registered" in str(error).lower() or "already exists" in str(error).lower():
                print(f"   [SKIP] User already exists (OK)")
                return True
            else:
                print(f"   [ERROR] Registration failed: {error}")
                return False
        else:
            print(f"   [ERROR] Registration failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
    except Exception as e:
        print(f"   [ERROR] Error: {e}")
        return False

def test_login(email, password):
    """Test login for a user"""
    print(f"\n[LOGIN] Testing {email}...")

    try:
        response = requests.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"email": email, "password": password},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            print(f"   [OK] Login successful")
            print(f"   Token: {data['access_token'][:50]}...")
            return data['access_token']
        else:
            print(f"   [ERROR] Login failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return None
    except Exception as e:
        print(f"   [ERROR] Error: {e}")
        return None

def main():
    print("\n" + "="*60)
    print("SEED TEST USERS via API")
    print("="*60)

    # 1. Check backend
    if not check_backend():
        sys.exit(1)

    # 2. Register users
    print("\n" + "="*60)
    print("REGISTERING USERS")
    print("="*60)

    success_count = 0
    for user in TEST_USERS:
        if register_user(user):
            success_count += 1

    print(f"\n[RESULT] Registered {success_count}/{len(TEST_USERS)} users")

    # 3. Test logins
    print("\n" + "="*60)
    print("TESTING LOGINS")
    print("="*60)

    login_success = 0
    for user in TEST_USERS:
        token = test_login(user['email'], user['password'])
        if token:
            login_success += 1

    print(f"\n[RESULT] {login_success}/{len(TEST_USERS)} logins successful")

    # 4. Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)

    print("\nTest users credentials:")
    for user in TEST_USERS:
        print(f"  - {user['email']:<30} | Password: {user['password']}")

    print("\n[SUCCESS] Setup complete! Run pytest now:")
    print("   pytest tests/real/ -v")
    print("   pytest tests/ -v --ignore=tests/real/")

    if success_count == len(TEST_USERS) and login_success == len(TEST_USERS):
        sys.exit(0)
    else:
        print("\n[WARNING] Some users failed to register or login")
        sys.exit(1)

if __name__ == "__main__":
    main()

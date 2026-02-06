"""
Script di test automatico per le API del Media Center Arti Marziali
Testa gli endpoint principali per ogni tipo di utente
"""

import requests
import json
from datetime import datetime
from typing import Dict, Optional

BASE_URL = "http://localhost:8000"

# Colori per output terminale
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_section(title: str):
    """Stampa una sezione formattata"""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{title.center(70)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'='*70}{Colors.END}\n")

def print_test(endpoint: str, method: str, status: str, message: str = ""):
    """Stampa il risultato di un test"""
    color = Colors.GREEN if status == "PASS" else Colors.RED if status == "FAIL" else Colors.YELLOW
    status_symbol = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
    print(f"{color}{status_symbol}{Colors.END} {method:6} {endpoint:50} {message}")

def test_health_endpoints():
    """Test degli endpoint di base"""
    print_section("TEST 1: ENDPOINT BASE")

    tests_passed = 0
    tests_total = 3

    # 1. Health Check
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=5)
        if response.status_code == 200:
            data = response.json()
            print_test("/health", "GET", "PASS", f"Status: {data.get('status')}")
            tests_passed += 1
        else:
            print_test("/health", "GET", "FAIL", f"Status code: {response.status_code}")
    except Exception as e:
        print_test("/health", "GET", "FAIL", str(e))

    # 2. Root
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        if response.status_code == 200:
            print_test("/", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/", "GET", "FAIL", f"Status code: {response.status_code}")
    except Exception as e:
        print_test("/", "GET", "FAIL", str(e))

    # 3. OpenAPI docs
    try:
        response = requests.get(f"{BASE_URL}/docs", timeout=5)
        if response.status_code == 200:
            print_test("/docs", "GET", "PASS", "Swagger UI accessible")
            tests_passed += 1
        else:
            print_test("/docs", "GET", "FAIL", f"Status code: {response.status_code}")
    except Exception as e:
        print_test("/docs", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed == tests_total


def test_authentication():
    """Test degli endpoint di autenticazione"""
    print_section("TEST 2: AUTENTICAZIONE")

    users = [
        {"email": "admin@mediacenter.it", "password": "Admin2024!", "role": "Admin"},
        {"email": "maestro.premium@mediacenter.it", "password": "Maestro2024!", "role": "Maestro"},
        {"email": "studente.premium@mediacenter.it", "password": "Student2024!", "role": "Studente"},
        {"email": "utente.hybrid@mediacenter.it", "password": "Hybrid2024!", "role": "Hybrid"},
        {"email": "utente.free@mediacenter.it", "password": "Free2024!", "role": "Free"},
        {"email": "asd.admin@mediacenter.it", "password": "Asd2024!", "role": "ASD Manager"}
    ]

    tokens = {}
    tests_passed = 0
    tests_total = len(users)

    for user in users:
        try:
            response = requests.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={"email": user["email"], "password": user["password"]},
                timeout=10
            )

            if response.status_code == 200:
                data = response.json()
                tokens[user["role"]] = data.get("access_token")
                print_test(f"/api/v1/auth/login ({user['role']})", "POST", "PASS",
                          f"Token: {data.get('access_token', '')[:30]}...")
                tests_passed += 1
            else:
                print_test(f"/api/v1/auth/login ({user['role']})", "POST", "FAIL",
                          f"Status: {response.status_code}")
        except Exception as e:
            print_test(f"/api/v1/auth/login ({user['role']})", "POST", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} login riusciti{Colors.END}")
    return tokens, tests_passed == tests_total


def test_user_profile(tokens: Dict[str, str]):
    """Test endpoint profilo utente"""
    print_section("TEST 3: PROFILO UTENTE")

    tests_passed = 0
    tests_total = len(tokens)

    for role, token in tokens.items():
        try:
            headers = {"Authorization": f"Bearer {token}"}
            response = requests.get(f"{BASE_URL}/api/v1/auth/me", headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                print_test(f"/api/v1/auth/me ({role})", "GET", "PASS",
                          f"Email: {data.get('email', 'N/A')}")
                tests_passed += 1
            else:
                print_test(f"/api/v1/auth/me ({role})", "GET", "FAIL",
                          f"Status: {response.status_code}")
        except Exception as e:
            print_test(f"/api/v1/auth/me ({role})", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed == tests_total


def test_videos_endpoints(tokens: Dict[str, str]):
    """Test endpoint video"""
    print_section("TEST 4: VIDEO")

    tests_passed = 0
    tests_total = 0

    # Test GET videos list (pubblico/autenticato)
    for role in ["Studente", "Maestro", "Admin"]:
        if role not in tokens:
            continue

        tests_total += 1
        try:
            headers = {"Authorization": f"Bearer {tokens[role]}"}
            response = requests.get(f"{BASE_URL}/api/v1/videos/videos", headers=headers, timeout=10)

            if response.status_code == 200:
                data = response.json()
                print_test(f"/api/v1/videos/videos ({role})", "GET", "PASS",
                          f"Videos: {data.get('total', 0)}")
                tests_passed += 1
            else:
                print_test(f"/api/v1/videos/videos ({role})", "GET", "FAIL",
                          f"Status: {response.status_code}")
        except Exception as e:
            print_test(f"/api/v1/videos/videos ({role})", "GET", "FAIL", str(e))

    # Test GET home feed
    if "Studente" in tokens:
        tests_total += 1
        try:
            headers = {"Authorization": f"Bearer {tokens['Studente']}"}
            response = requests.get(f"{BASE_URL}/api/v1/videos/videos/home", headers=headers, timeout=10)

            if response.status_code == 200:
                print_test("/api/v1/videos/videos/home (Studente)", "GET", "PASS")
                tests_passed += 1
            else:
                print_test("/api/v1/videos/videos/home (Studente)", "GET", "FAIL",
                          f"Status: {response.status_code}")
        except Exception as e:
            print_test("/api/v1/videos/videos/home (Studente)", "GET", "FAIL", str(e))

    # Test search
    if "Studente" in tokens:
        tests_total += 1
        try:
            headers = {"Authorization": f"Bearer {tokens['Studente']}"}
            response = requests.get(
                f"{BASE_URL}/api/v1/videos/videos/search?q=karate",
                headers=headers,
                timeout=10
            )

            if response.status_code == 200:
                print_test("/api/v1/videos/videos/search (Studente)", "GET", "PASS")
                tests_passed += 1
            else:
                print_test("/api/v1/videos/videos/search (Studente)", "GET", "FAIL",
                          f"Status: {response.status_code}")
        except Exception as e:
            print_test("/api/v1/videos/videos/search (Studente)", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed, tests_total


def test_maestro_endpoints(tokens: Dict[str, str]):
    """Test endpoint Maestro"""
    print_section("TEST 5: MAESTRO")

    if "Maestro" not in tokens:
        print(f"{Colors.YELLOW}⚠ Nessun token Maestro disponibile - skip{Colors.END}")
        return 0, 0

    tests_passed = 0
    tests_total = 5

    headers = {"Authorization": f"Bearer {tokens['Maestro']}"}

    # Dashboard
    try:
        response = requests.get(f"{BASE_URL}/api/v1/maestro/maestro/dashboard",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/maestro/maestro/dashboard", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/maestro/maestro/dashboard", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/maestro/maestro/dashboard", "GET", "FAIL", str(e))

    # Videos
    try:
        response = requests.get(f"{BASE_URL}/api/v1/maestro/maestro/videos",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/maestro/maestro/videos", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/maestro/maestro/videos", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/maestro/maestro/videos", "GET", "FAIL", str(e))

    # Live Events
    try:
        response = requests.get(f"{BASE_URL}/api/v1/maestro/maestro/live-events",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/maestro/maestro/live-events", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/maestro/maestro/live-events", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/maestro/maestro/live-events", "GET", "FAIL", str(e))

    # Earnings
    try:
        response = requests.get(f"{BASE_URL}/api/v1/maestro/maestro/earnings",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/maestro/maestro/earnings", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/maestro/maestro/earnings", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/maestro/maestro/earnings", "GET", "FAIL", str(e))

    # Withdrawals
    try:
        response = requests.get(f"{BASE_URL}/api/v1/maestro/maestro/withdrawals",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/maestro/maestro/withdrawals", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/maestro/maestro/withdrawals", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/maestro/maestro/withdrawals", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed, tests_total


def test_admin_endpoints(tokens: Dict[str, str]):
    """Test endpoint Admin"""
    print_section("TEST 6: ADMIN")

    if "Admin" not in tokens:
        print(f"{Colors.YELLOW}⚠ Nessun token Admin disponibile - skip{Colors.END}")
        return 0, 0

    tests_passed = 0
    tests_total = 5

    headers = {"Authorization": f"Bearer {tokens['Admin']}"}

    # Dashboard
    try:
        response = requests.get(f"{BASE_URL}/api/v1/admin/admin/dashboard",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/admin/admin/dashboard", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/admin/admin/dashboard", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/admin/admin/dashboard", "GET", "FAIL", str(e))

    # Platform Analytics
    try:
        response = requests.get(f"{BASE_URL}/api/v1/admin/admin/analytics/platform",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/admin/admin/analytics/platform", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/admin/admin/analytics/platform", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/admin/admin/analytics/platform", "GET", "FAIL", str(e))

    # Users
    try:
        response = requests.get(f"{BASE_URL}/api/v1/admin/admin/users",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print_test("/api/v1/admin/admin/users", "GET", "PASS",
                      f"Users: {data.get('total', 0)}")
            tests_passed += 1
        else:
            print_test("/api/v1/admin/admin/users", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/admin/admin/users", "GET", "FAIL", str(e))

    # Maestros
    try:
        response = requests.get(f"{BASE_URL}/api/v1/admin/admin/maestros",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/admin/admin/maestros", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/admin/admin/maestros", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/admin/admin/maestros", "GET", "FAIL", str(e))

    # Tier Configuration
    try:
        response = requests.get(f"{BASE_URL}/api/v1/admin/admin/config/tiers",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/admin/admin/config/tiers", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/admin/admin/config/tiers", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/admin/admin/config/tiers", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed, tests_total


def test_communication_endpoints(tokens: Dict[str, str]):
    """Test endpoint Comunicazione"""
    print_section("TEST 7: COMUNICAZIONE")

    if "Studente" not in tokens:
        print(f"{Colors.YELLOW}⚠ Nessun token disponibile - skip{Colors.END}")
        return 0, 0

    tests_passed = 0
    tests_total = 2

    headers = {"Authorization": f"Bearer {tokens['Studente']}"}

    # List Messages
    try:
        response = requests.get(f"{BASE_URL}/api/v1/communication/messages",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            print_test("/api/v1/communication/messages", "GET", "PASS")
            tests_passed += 1
        else:
            print_test("/api/v1/communication/messages", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/communication/messages", "GET", "FAIL", str(e))

    # Unread Count
    try:
        response = requests.get(f"{BASE_URL}/api/v1/communication/messages/unread/count",
                              headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print_test("/api/v1/communication/messages/unread/count", "GET", "PASS",
                      f"Unread: {data.get('count', 0)}")
            tests_passed += 1
        else:
            print_test("/api/v1/communication/messages/unread/count", "GET", "FAIL",
                      f"Status: {response.status_code}")
    except Exception as e:
        print_test("/api/v1/communication/messages/unread/count", "GET", "FAIL", str(e))

    print(f"\n{Colors.BOLD}Risultato: {tests_passed}/{tests_total} test passati{Colors.END}")
    return tests_passed, tests_total


def main():
    """Main function"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}")
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║     MEDIA CENTER ARTI MARZIALI - TEST SUITE AUTOMATICO            ║")
    print("║                    Test delle API principali                       ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.END}")

    print(f"\n{Colors.CYAN}Backend URL: {BASE_URL}{Colors.END}")
    print(f"{Colors.CYAN}Data: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}{Colors.END}")

    total_passed = 0
    total_tests = 0

    # Test 1: Endpoint base
    if test_health_endpoints():
        total_passed += 3
    total_tests += 3

    # Test 2: Autenticazione
    tokens, auth_ok = test_authentication()
    if auth_ok:
        total_passed += 6
    total_tests += 6

    if not tokens:
        print(f"\n{Colors.RED}ERRORE: Nessun token disponibile. Impossibile continuare.{Colors.END}")
        return

    # Test 3: Profilo utente
    if test_user_profile(tokens):
        total_passed += len(tokens)
    total_tests += len(tokens)

    # Test 4: Video
    passed, total = test_videos_endpoints(tokens)
    total_passed += passed
    total_tests += total

    # Test 5: Maestro
    passed, total = test_maestro_endpoints(tokens)
    total_passed += passed
    total_tests += total

    # Test 6: Admin
    passed, total = test_admin_endpoints(tokens)
    total_passed += passed
    total_tests += total

    # Test 7: Comunicazione
    passed, total = test_communication_endpoints(tokens)
    total_passed += passed
    total_tests += total

    # Riepilogo finale
    print_section("RIEPILOGO FINALE")

    success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

    print(f"{Colors.BOLD}Test Totali:    {total_tests}{Colors.END}")
    print(f"{Colors.GREEN}✓ Test Passati: {total_passed}{Colors.END}")
    print(f"{Colors.RED}✗ Test Falliti: {total_tests - total_passed}{Colors.END}")
    print(f"{Colors.BOLD}Percentuale:    {success_rate:.1f}%{Colors.END}")

    if success_rate >= 90:
        print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 ECCELLENTE! Sistema pronto per il deploy!{Colors.END}")
    elif success_rate >= 70:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠️  BUONO! Alcuni endpoint potrebbero richiedere attenzione.{Colors.END}")
    else:
        print(f"\n{Colors.RED}{Colors.BOLD}❌ ATTENZIONE! Molti endpoint hanno problemi.{Colors.END}")

    print()


if __name__ == "__main__":
    main()

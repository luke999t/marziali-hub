"""
AI_MODULE: Full System Health Check
AI_DESCRIPTION: Verifica completa tutti i componenti Media Center
AI_BUSINESS: Previene downtime, identifica problemi pre-deploy
AI_TEACHING: Health checks, dependency verification, status reporting

ALTERNATIVE_VALUTATE:
- External monitoring only: Scartato, non cattura internal errors
- Manual checklist: Scartato, error-prone
- CI/CD only: Scartato, no runtime checks

PERCHE_QUESTA_SOLUZIONE:
- Comprehensive: Verifica tutti i componenti
- Fast: <10 secondi per check completo
- Actionable: Output chiaro su cosa fixare

METRICHE_SUCCESSO:
- Check time: <10s
- Coverage: 100% critical components
- False negatives: 0%
"""

import asyncio
import os
import sys
from datetime import datetime
from typing import Tuple, List, Dict, Any

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try importing httpx
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Console colors (work on most terminals)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    # ASCII symbols (Windows compatible)
    CHECK = '[OK]'
    CROSS = '[X]'


# Configuration
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# Test credentials
TEST_ADMIN = {
    "email": os.getenv("TEST_ADMIN_EMAIL", "admin@mediacenter.it"),
    "password": os.getenv("TEST_ADMIN_PASSWORD", "Admin2024!")
}


async def check_backend() -> Tuple[bool, str, Dict]:
    """Verifica backend FastAPI attivo."""
    if not HTTPX_AVAILABLE:
        return False, "httpx not installed", {}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BACKEND_URL}/health", timeout=5)
            if response.status_code == 200:
                data = response.json()
                return True, "Backend attivo", {
                    "status": data.get("status"),
                    "environment": data.get("environment"),
                    "version": data.get("release")
                }
            return False, f"HTTP {response.status_code}", {}
    except httpx.ConnectError:
        return False, f"Non raggiungibile su {BACKEND_URL}", {}
    except httpx.TimeoutException:
        return False, "Timeout", {}
    except Exception as e:
        return False, str(e), {}


async def check_database() -> Tuple[bool, str, Dict]:
    """Verifica connessione database."""
    try:
        # Try to import and check SQLAlchemy connection
        from core.database import engine
        from sqlalchemy import text

        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return True, "Database connesso", {"connection": "OK"}
    except ImportError:
        return False, "core.database non importabile", {}
    except Exception as e:
        return False, f"Errore: {str(e)[:50]}", {}


async def check_auth() -> Tuple[bool, str, Dict]:
    """Verifica sistema autenticazione."""
    if not HTTPX_AVAILABLE:
        return False, "httpx not installed", {}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json=TEST_ADMIN,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return True, "Auth funzionante", {
                    "has_token": "access_token" in data
                }
            elif response.status_code == 401:
                return False, "Credenziali test invalide", {}
            return False, f"HTTP {response.status_code}", {}
    except Exception as e:
        return False, str(e)[:50], {}


async def check_royalties_module() -> Tuple[bool, str, Dict]:
    """Verifica modulo royalties caricato."""
    if not HTTPX_AVAILABLE:
        return False, "httpx not installed", {}

    try:
        async with httpx.AsyncClient() as client:
            # First login
            login_response = await client.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json=TEST_ADMIN,
                timeout=10
            )

            if login_response.status_code != 200:
                return False, "Login failed", {}

            token = login_response.json().get("access_token")

            # Check royalties endpoint
            response = await client.get(
                f"{BACKEND_URL}/api/v1/royalties/health",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )

            if response.status_code == 200:
                return True, "Modulo Royalties OK", response.json()
            elif response.status_code == 404:
                # Try admin config endpoint
                config_response = await client.get(
                    f"{BACKEND_URL}/api/v1/royalties/admin/config",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
                if config_response.status_code == 200:
                    return True, "Modulo Royalties OK (no health)", {}
                return False, f"Endpoint non trovato", {}
            return False, f"HTTP {response.status_code}", {}
    except Exception as e:
        return False, str(e)[:50], {}


async def check_special_projects_module() -> Tuple[bool, str, Dict]:
    """Verifica modulo special projects caricato."""
    if not HTTPX_AVAILABLE:
        return False, "httpx not installed", {}

    try:
        async with httpx.AsyncClient() as client:
            # First login
            login_response = await client.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json=TEST_ADMIN,
                timeout=10
            )

            if login_response.status_code != 200:
                return False, "Login failed", {}

            token = login_response.json().get("access_token")

            # Check special-projects endpoint
            response = await client.get(
                f"{BACKEND_URL}/api/v1/special-projects/health",
                headers={"Authorization": f"Bearer {token}"},
                timeout=5
            )

            if response.status_code == 200:
                return True, "Modulo Special Projects OK", response.json()
            elif response.status_code == 404:
                # Try list endpoint
                list_response = await client.get(
                    f"{BACKEND_URL}/api/v1/special-projects",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=5
                )
                if list_response.status_code == 200:
                    return True, "Modulo Special Projects OK", {}
                return False, "Endpoint non trovato", {}
            return False, f"HTTP {response.status_code}", {}
    except Exception as e:
        return False, str(e)[:50], {}


async def check_stripe() -> Tuple[bool, str, Dict]:
    """Verifica configurazione Stripe."""
    try:
        from services.payments.stripe_production_check import check_stripe_production_ready
        result = check_stripe_production_ready()

        if result["ready"]:
            return True, f"Stripe {result['mode']} mode OK", {
                "mode": result["mode"],
                "issues": len(result["issues"]),
                "warnings": len(result["warnings"])
            }
        else:
            return False, f"Stripe: {len(result['issues'])} issues", {
                "issues": result["issues"][:2]
            }
    except ImportError:
        return False, "stripe_production_check non importabile", {}
    except Exception as e:
        return False, str(e)[:50], {}


async def check_frontend() -> Tuple[bool, str, Dict]:
    """Verifica frontend Next.js attivo."""
    if not HTTPX_AVAILABLE:
        return False, "httpx not installed", {}

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(FRONTEND_URL, timeout=5)
            if response.status_code == 200:
                return True, "Frontend attivo", {"status": "OK"}
            return False, f"HTTP {response.status_code}", {}
    except httpx.ConnectError:
        return False, f"Non raggiungibile su {FRONTEND_URL}", {}
    except Exception as e:
        return False, str(e)[:50], {}


async def check_migrations() -> Tuple[bool, str, Dict]:
    """Verifica stato migrations."""
    migrations_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "migrations"
    )

    if not os.path.exists(migrations_path):
        return False, "Cartella migrations non trovata", {}

    migrations = sorted([
        f for f in os.listdir(migrations_path)
        if f.endswith('.sql')
    ])

    expected = [
        "001_", "002_", "003_", "004_", "005_", "006_"
    ]

    found = []
    missing = []
    for exp in expected:
        if any(m.startswith(exp) for m in migrations):
            found.append(exp)
        else:
            missing.append(exp)

    if not missing:
        return True, f"{len(found)} migrations trovate", {"migrations": migrations}
    else:
        return False, f"Missing: {', '.join(missing)}", {"found": found}


async def check_env_vars() -> Tuple[bool, str, Dict]:
    """Verifica variabili ambiente essenziali."""
    required = [
        "DATABASE_URL",
        "SECRET_KEY",
    ]

    recommended = [
        "STRIPE_SECRET_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "SENTRY_DSN",
    ]

    missing_required = [v for v in required if not os.getenv(v)]
    missing_recommended = [v for v in recommended if not os.getenv(v)]

    if missing_required:
        return False, f"Missing: {', '.join(missing_required)}", {}
    elif missing_recommended:
        return True, f"OK (warning: {len(missing_recommended)} recommended missing)", {
            "missing_recommended": missing_recommended
        }
    return True, "Tutte le env vars configurate", {}


async def main():
    """Esegue tutti i check e stampa report."""

    print()
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  MEDIA CENTER - FULL SYSTEM HEALTH CHECK{Colors.RESET}")
    print(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print()

    # Define checks
    checks = [
        ("Backend API", check_backend),
        ("Database", check_database),
        ("Auth System", check_auth),
        ("Royalties Module", check_royalties_module),
        ("Special Projects Module", check_special_projects_module),
        ("Stripe Config", check_stripe),
        ("Migrations", check_migrations),
        ("Environment Vars", check_env_vars),
        ("Frontend", check_frontend),
    ]

    results = []

    for name, check_func in checks:
        try:
            success, message, details = await check_func()
        except Exception as e:
            success, message, details = False, f"Exception: {str(e)[:40]}", {}

        results.append((name, success, message, details))

        # Print result
        if success:
            status = f"{Colors.GREEN}{Colors.CHECK}{Colors.RESET}"
        else:
            status = f"{Colors.RED}{Colors.CROSS}{Colors.RESET}"

        print(f"  {status} {name}: {message}")

        # Print details if any
        if details and not success:
            for key, value in list(details.items())[:2]:
                print(f"       -> {key}: {value}")

    # Summary
    passed = sum(1 for _, success, _, _ in results if success)
    total = len(results)

    print()
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")

    if passed == total:
        print(f"  {Colors.GREEN}TUTTI I CHECK PASSATI ({passed}/{total}){Colors.RESET}")
    elif passed >= total * 0.7:
        print(f"  {Colors.YELLOW}PARZIALE: {passed}/{total} check passati{Colors.RESET}")
    else:
        print(f"  {Colors.RED}CRITICO: Solo {passed}/{total} check passati{Colors.RESET}")

    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print()

    # Actions needed
    failed = [(name, msg) for name, success, msg, _ in results if not success]
    if failed:
        print(f"  {Colors.YELLOW}Azioni necessarie:{Colors.RESET}")
        for name, msg in failed:
            print(f"    - Fix {name}: {msg}")
        print()

    return passed == total


if __name__ == "__main__":
    # Run async main
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    success = asyncio.run(main())
    sys.exit(0 if success else 1)

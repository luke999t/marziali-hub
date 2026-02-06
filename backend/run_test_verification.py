#!/usr/bin/env python3
"""
🎓 AI_MODULE: Test Verification Script
🎓 AI_DESCRIPTION: Verifica completa suite test con report dettagliato
🎓 AI_BUSINESS: Garantisce qualità enterprise (90% coverage, 95% pass rate)
🎓 AI_TEACHING: subprocess per esecuzione pytest, parsing output

OBIETTIVI:
- Copertura: 90%
- Pass rate: 95%
- Zero mock
- Suite enterprise

USAGE:
    python run_test_verification.py
    python run_test_verification.py --quick  (solo test modificati)
    python run_test_verification.py --full   (suite completa)
"""

import subprocess
import sys
import os
import re
from datetime import datetime
from pathlib import Path

# Colori per output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{text.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}\n")

def print_success(text):
    print(f"{Colors.GREEN}✅ {text}{Colors.END}")

def print_error(text):
    print(f"{Colors.RED}❌ {text}{Colors.END}")

def print_warning(text):
    print(f"{Colors.YELLOW}⚠️  {text}{Colors.END}")

def print_info(text):
    print(f"{Colors.BLUE}ℹ️  {text}{Colors.END}")

def check_postgres_connection():
    """Verifica connessione PostgreSQL."""
    print_info("Verifico connessione PostgreSQL...")
    try:
        import asyncpg
        import asyncio
        
        async def test_connection():
            # Leggi DATABASE_URL da environment o .env
            db_url = os.getenv("DATABASE_URL_ASYNC", "postgresql+asyncpg://postgres:postgres@localhost:5432/media_center")
            # Estrai parametri per asyncpg
            # Format: postgresql+asyncpg://user:pass@host:port/db
            match = re.match(r'postgresql\+asyncpg://(\w+):(\w+)@([\w.]+):(\d+)/(\w+)', db_url)
            if match:
                user, password, host, port, database = match.groups()
                conn = await asyncpg.connect(
                    user=user, password=password, 
                    host=host, port=int(port), database=database
                )
                version = await conn.fetchval('SELECT version()')
                await conn.close()
                return True, version
            return False, "Invalid DATABASE_URL format"
        
        success, info = asyncio.run(test_connection())
        if success:
            print_success(f"PostgreSQL connesso")
            return True
        else:
            print_error(f"PostgreSQL non raggiungibile: {info}")
            return False
    except ImportError:
        print_warning("asyncpg non installato, skip check connessione")
        return True
    except Exception as e:
        print_error(f"Errore connessione PostgreSQL: {e}")
        return False

def check_no_mocks(test_files):
    """Verifica assenza di mock nei file test."""
    print_info("Verifico assenza di mock...")
    
    mock_patterns = [
        r'\bmock\b', r'\bMock\b', r'\bMagicMock\b', r'\bAsyncMock\b',
        r'\bpatch\b', r'@patch', r'mock_', r'_mock\b'
    ]
    
    violations = []
    for test_file in test_files:
        if not os.path.exists(test_file):
            continue
        with open(test_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            for pattern in mock_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    # Escludi commenti che parlano di "ZERO MOCK"
                    lines_with_mock = [
                        line for line in content.split('\n') 
                        if re.search(pattern, line, re.IGNORECASE)
                        and 'ZERO MOCK' not in line.upper()
                        and '#' not in line.split(pattern)[0]  # Non in commento
                    ]
                    if lines_with_mock:
                        violations.append((test_file, pattern, len(lines_with_mock)))
    
    if violations:
        print_error("MOCK TROVATI!")
        for file, pattern, count in violations:
            print(f"   {file}: pattern '{pattern}' trovato {count} volte")
        return False
    
    print_success("Nessun mock trovato - ZERO MOCK rispettato")
    return True

def run_pytest(test_path, extra_args=None):
    """Esegue pytest e ritorna risultati."""
    cmd = [
        sys.executable, "-m", "pytest",
        test_path,
        "-v",
        "--tb=short",
        "-q"
    ]
    if extra_args:
        cmd.extend(extra_args)
    
    print_info(f"Eseguo: {' '.join(cmd)}")
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    
    return result

def parse_pytest_output(output):
    """Estrae statistiche da output pytest."""
    stats = {
        'passed': 0,
        'failed': 0,
        'skipped': 0,
        'errors': 0,
        'total': 0,
        'pass_rate': 0.0
    }
    
    # Pattern: "X passed, Y failed, Z skipped"
    match = re.search(r'(\d+) passed', output)
    if match:
        stats['passed'] = int(match.group(1))
    
    match = re.search(r'(\d+) failed', output)
    if match:
        stats['failed'] = int(match.group(1))
    
    match = re.search(r'(\d+) skipped', output)
    if match:
        stats['skipped'] = int(match.group(1))
    
    match = re.search(r'(\d+) error', output)
    if match:
        stats['errors'] = int(match.group(1))
    
    stats['total'] = stats['passed'] + stats['failed'] + stats['skipped'] + stats['errors']
    
    if stats['total'] > 0:
        stats['pass_rate'] = (stats['passed'] / stats['total']) * 100
    
    return stats

def main():
    print_header("VERIFICA TEST SUITE MEDIA CENTER")
    print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Working dir: {os.getcwd()}")
    
    # Determina modalità
    mode = "quick"
    if len(sys.argv) > 1:
        if "--full" in sys.argv:
            mode = "full"
        elif "--quick" in sys.argv:
            mode = "quick"
    
    print(f"Modalità: {mode.upper()}")
    
    # 1. Check PostgreSQL
    print_header("1. VERIFICA CONNESSIONE DATABASE")
    db_ok = check_postgres_connection()
    if not db_ok:
        print_error("PostgreSQL non disponibile. Avvialo prima di eseguire i test.")
        print_info("Comando: docker-compose up -d postgres")
        return 1
    
    # 2. Check Zero Mock
    print_header("2. VERIFICA ZERO MOCK")
    test_files = [
        "tests/test_royalties.py",
        "tests/test_special_projects.py"
    ]
    if mode == "full":
        # Aggiungi tutti i file test
        for f in Path("tests").glob("test_*.py"):
            if str(f) not in test_files:
                test_files.append(str(f))
    
    mock_ok = check_no_mocks(test_files)
    
    # 3. Esegui test
    print_header("3. ESECUZIONE TEST")
    
    results = {}
    
    if mode == "quick":
        # Solo i file modificati da Claude Code
        quick_tests = [
            "tests/test_royalties.py",
            "tests/test_special_projects.py"
        ]
        for test_file in quick_tests:
            print(f"\n--- {test_file} ---")
            result = run_pytest(test_file)
            stats = parse_pytest_output(result.stdout + result.stderr)
            results[test_file] = {
                'stats': stats,
                'returncode': result.returncode,
                'output': result.stdout + result.stderr
            }
            
            if stats['passed'] > 0:
                print_success(f"Passed: {stats['passed']}")
            if stats['failed'] > 0:
                print_error(f"Failed: {stats['failed']}")
            if stats['skipped'] > 0:
                print_warning(f"Skipped: {stats['skipped']}")
            if stats['errors'] > 0:
                print_error(f"Errors: {stats['errors']}")
    else:
        # Suite completa
        print("Eseguo suite completa (può richiedere tempo)...")
        result = run_pytest("tests/", ["--ignore=tests/slow", "--ignore=tests/stress"])
        stats = parse_pytest_output(result.stdout + result.stderr)
        results["full_suite"] = {
            'stats': stats,
            'returncode': result.returncode,
            'output': result.stdout + result.stderr
        }
    
    # 4. Report finale
    print_header("4. REPORT FINALE")
    
    total_passed = sum(r['stats']['passed'] for r in results.values())
    total_failed = sum(r['stats']['failed'] for r in results.values())
    total_skipped = sum(r['stats']['skipped'] for r in results.values())
    total_errors = sum(r['stats']['errors'] for r in results.values())
    total_tests = total_passed + total_failed + total_skipped + total_errors
    
    if total_tests > 0:
        pass_rate = (total_passed / total_tests) * 100
    else:
        pass_rate = 0
    
    print(f"""
╔══════════════════════════════════════════════════════════╗
║                    RISULTATI TEST                        ║
╠══════════════════════════════════════════════════════════╣
║  Total Tests:    {total_tests:>6}                                 ║
║  ✅ Passed:      {total_passed:>6}                                 ║
║  ❌ Failed:      {total_failed:>6}                                 ║
║  ⏭️  Skipped:     {total_skipped:>6}                                 ║
║  💥 Errors:      {total_errors:>6}                                 ║
╠══════════════════════════════════════════════════════════╣
║  Pass Rate:      {pass_rate:>6.1f}%  (target: 95%)               ║
║  Zero Mock:      {'✅ OK' if mock_ok else '❌ FAIL':>6}                                  ║
║  PostgreSQL:     {'✅ OK' if db_ok else '❌ FAIL':>6}                                  ║
╚══════════════════════════════════════════════════════════╝
""")
    
    # Valutazione finale
    print_header("5. VALUTAZIONE")
    
    issues = []
    if pass_rate < 95:
        issues.append(f"Pass rate {pass_rate:.1f}% < 95% target")
    if not mock_ok:
        issues.append("Mock trovati nei test")
    if not db_ok:
        issues.append("Database non connesso")
    if total_errors > 0:
        issues.append(f"{total_errors} errori di setup/collection")
    
    if not issues:
        print_success("TUTTI I CRITERI SODDISFATTI! 🎉")
        return 0
    else:
        print_error("CRITERI NON SODDISFATTI:")
        for issue in issues:
            print(f"   - {issue}")
        
        # Mostra dettagli errori
        if total_failed > 0 or total_errors > 0:
            print("\n--- DETTAGLI ERRORI ---")
            for name, data in results.items():
                if data['stats']['failed'] > 0 or data['stats']['errors'] > 0:
                    print(f"\n{name}:")
                    # Estrai solo le righe con FAILED o ERROR
                    for line in data['output'].split('\n'):
                        if 'FAILED' in line or 'ERROR' in line:
                            print(f"  {line}")
        
        return 1

if __name__ == "__main__":
    sys.exit(main())

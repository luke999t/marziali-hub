#!/usr/bin/env python3
"""
================================================================================
LOAD TEST SCRIPT - Backend Concurrency Test
================================================================================
Testa il limite di concorrenza reale del backend FastAPI con PostgreSQL.

Pool PostgreSQL: pool_size=5, max_overflow=10 (max 15 connessioni)

Uso: python scripts/load_test.py
================================================================================
"""

import asyncio
import httpx
import json
import time
import statistics
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass, asdict


# ==============================================================================
# CONFIGURATION
# ==============================================================================
BACKEND_URL = "http://localhost:8000"
ENDPOINT = "/api/v1/videos/trending"
TIMEOUT_SECONDS = 30
CONCURRENCY_LEVELS = [10, 20, 30, 50, 75, 100]
RESULTS_FILE = "load_test_results.json"


# ==============================================================================
# DATA CLASSES
# ==============================================================================
@dataclass
class RequestResult:
    """Risultato di una singola richiesta."""
    success: bool
    status_code: int
    response_time_ms: float
    error: str = None


@dataclass
class ConcurrencyTestResult:
    """Risultato test per un livello di concorrenza."""
    concurrency: int
    total_requests: int
    successful: int
    failed: int
    success_rate: float
    avg_response_time_ms: float
    min_response_time_ms: float
    max_response_time_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    timeouts: int
    connection_errors: int
    server_errors: int
    error_details: List[str]


# ==============================================================================
# LOAD TEST FUNCTIONS
# ==============================================================================

async def make_request(client: httpx.AsyncClient, request_id: int) -> RequestResult:
    """Esegue una singola richiesta HTTP."""
    start_time = time.perf_counter()

    try:
        response = await client.get(
            f"{BACKEND_URL}{ENDPOINT}",
            timeout=TIMEOUT_SECONDS
        )
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return RequestResult(
            success=response.status_code == 200,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            error=None if response.status_code == 200 else f"HTTP {response.status_code}"
        )

    except httpx.TimeoutException:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            success=False,
            status_code=0,
            response_time_ms=elapsed_ms,
            error="TIMEOUT"
        )

    except httpx.ConnectError as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            success=False,
            status_code=0,
            response_time_ms=elapsed_ms,
            error=f"CONNECTION_ERROR: {str(e)[:50]}"
        )

    except Exception as e:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        return RequestResult(
            success=False,
            status_code=0,
            response_time_ms=elapsed_ms,
            error=f"ERROR: {str(e)[:50]}"
        )


async def run_concurrent_test(concurrency: int) -> ConcurrencyTestResult:
    """Esegue N richieste in parallelo."""
    print(f"\n{'='*60}")
    print(f"Testing {concurrency} concurrent requests...")
    print(f"{'='*60}")

    # Crea client con limiti alti per non bloccare le richieste
    async with httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=concurrency + 10,
            max_keepalive_connections=concurrency
        )
    ) as client:

        # Crea tutte le task
        tasks = [make_request(client, i) for i in range(concurrency)]

        # Lancia TUTTE le richieste insieme
        start_time = time.perf_counter()
        results: List[RequestResult] = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time

        print(f"All {concurrency} requests completed in {total_time:.2f}s")

    # Analizza risultati
    successful = sum(1 for r in results if r.success)
    failed = concurrency - successful
    success_rate = (successful / concurrency) * 100

    response_times = [r.response_time_ms for r in results]
    successful_times = [r.response_time_ms for r in results if r.success]

    # Conta tipi di errore
    timeouts = sum(1 for r in results if r.error == "TIMEOUT")
    connection_errors = sum(1 for r in results if r.error and "CONNECTION" in r.error)
    server_errors = sum(1 for r in results if r.status_code >= 500)

    # Raccoglie dettagli errori
    error_details = [r.error for r in results if r.error]

    # Calcola statistiche
    if successful_times:
        avg_time = statistics.mean(successful_times)
        min_time = min(successful_times)
        max_time = max(successful_times)
        sorted_times = sorted(successful_times)
        p50 = sorted_times[len(sorted_times) // 2]
        p95 = sorted_times[int(len(sorted_times) * 0.95)] if len(sorted_times) > 1 else sorted_times[0]
        p99 = sorted_times[int(len(sorted_times) * 0.99)] if len(sorted_times) > 1 else sorted_times[0]
    else:
        avg_time = min_time = max_time = p50 = p95 = p99 = 0

    return ConcurrencyTestResult(
        concurrency=concurrency,
        total_requests=concurrency,
        successful=successful,
        failed=failed,
        success_rate=success_rate,
        avg_response_time_ms=avg_time,
        min_response_time_ms=min_time,
        max_response_time_ms=max_time,
        p50_ms=p50,
        p95_ms=p95,
        p99_ms=p99,
        timeouts=timeouts,
        connection_errors=connection_errors,
        server_errors=server_errors,
        error_details=error_details[:10]  # Max 10 errori
    )


async def run_all_tests() -> List[ConcurrencyTestResult]:
    """Esegue tutti i test di concorrenza."""
    results = []

    print("\n" + "="*60)
    print("LOAD TEST - Backend Concurrency Test")
    print(f"Target: {BACKEND_URL}{ENDPOINT}")
    print(f"Concurrency levels: {CONCURRENCY_LEVELS}")
    print(f"Timeout: {TIMEOUT_SECONDS}s")
    print("="*60)

    # Verifica che il backend sia raggiungibile
    print("\nChecking backend availability...")
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BACKEND_URL}/health", timeout=5)
            print(f"Backend OK: {response.status_code}")
    except Exception as e:
        print(f"ERROR: Backend not reachable - {e}")
        return []

    # Esegui test per ogni livello
    for concurrency in CONCURRENCY_LEVELS:
        result = await run_concurrent_test(concurrency)
        results.append(result)

        # Breve pausa tra i test per permettere al backend di recuperare
        print(f"Waiting 2s before next test...")
        await asyncio.sleep(2)

    return results


def print_report(results: List[ConcurrencyTestResult]):
    """Stampa il report finale."""
    print("\n")
    print("="*70)
    print("                    === LOAD TEST REPORT ===")
    print("="*70)
    print(f"{'Concurrent':<12} {'Result':<15} {'Success%':<10} {'Avg(ms)':<10} {'P95(ms)':<10} {'Errors'}")
    print("-"*70)

    for r in results:
        error_info = ""
        if r.timeouts > 0:
            error_info += f"{r.timeouts} timeout "
        if r.server_errors > 0:
            error_info += f"{r.server_errors} 5xx "
        if r.connection_errors > 0:
            error_info += f"{r.connection_errors} conn "

        print(f"{r.concurrency:<12} {r.successful}/{r.total_requests} OK{'':<7} "
              f"{r.success_rate:>6.1f}%    {r.avg_response_time_ms:>7.0f}    "
              f"{r.p95_ms:>7.0f}    {error_info}")

    print("-"*70)

    # Trova il punto di rottura
    for r in results:
        if r.success_rate < 100:
            print(f"\n[!] Primo fallimento a {r.concurrency} richieste concorrenti")
            break
    else:
        print(f"\n[OK] Tutti i livelli completati con successo!")

    # Calcola throughput massimo
    successful_results = [r for r in results if r.successful > 0]
    if successful_results:
        best = max(successful_results, key=lambda x: x.successful)
        print(f"[STATS] Max throughput stabile: {best.successful} req a {best.concurrency} concorrenti")

    print("="*70)


def save_results(results: List[ConcurrencyTestResult]):
    """Salva i risultati in JSON."""
    data = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": f"{BACKEND_URL}{ENDPOINT}",
        "timeout_seconds": TIMEOUT_SECONDS,
        "results": [asdict(r) for r in results]
    }

    with open(RESULTS_FILE, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n[FILE] Risultati salvati in: {RESULTS_FILE}")


# ==============================================================================
# MAIN
# ==============================================================================

async def main():
    """Entry point."""
    results = await run_all_tests()

    if results:
        print_report(results)
        save_results(results)


if __name__ == "__main__":
    asyncio.run(main())

"""
================================================================================
AI_MODULE: HealthCheckJob
AI_VERSION: 1.0.0
AI_DESCRIPTION: Verifica stato servizi e log per monitoring
AI_BUSINESS: Uptime monitoring, alerting, dashboard stato sistema
AI_TEACHING: Health check pattern async con timeout + system metrics

ALTERNATIVE_VALUTATE:
- External monitoring (Datadog): Scartato, costo e dipendenza esterna
- Prometheus pull model: Scartato, complessità infrastrutturale
- Simple /health endpoint only: Scartato, no storico per trend analysis

PERCHÉ_QUESTA_SOLUZIONE:
- Health check interno = zero dipendenze esterne
- Log in DB = storico per uptime graphs su dashboard
- System metrics = alerting proattivo su risorse
================================================================================
"""

import asyncio
import logging
import os
import time
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

import psutil
from sqlalchemy import text

from core.database import async_session_maker
from models.analytics import SystemHealthLog
from modules.scheduler.scheduler_service import JobResult, JobStatus

logger = logging.getLogger(__name__)

# 💡 Configurazione
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
STORAGE_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
HEALTH_CHECK_TIMEOUT = int(os.getenv("HEALTH_CHECK_TIMEOUT", "5"))  # seconds

# Cache per /health endpoint
_last_health_status: Dict[str, Any] = {}


async def health_check_job() -> JobResult:
    """
    🎯 BUSINESS: Verifica stato servizi ogni 5 minuti
    📊 KPI: Uptime %, latency servizi, resource usage
    ⏱️ SCHEDULE: Ogni 5 minuti

    LOGICA:
    1. Ping PostgreSQL con query semplice
    2. Ping Redis con PING command
    3. Ping Storage (MinIO) con list buckets
    4. Raccolta metriche sistema (CPU, RAM, Disk)
    5. Log risultati in system_health_log
    6. Update cache per /health endpoint

    💡 Timeout 5 secondi per servizio:
    - Evita blocco scheduler se servizio non risponde
    - Latenza > 5s = considerato down per alerting
    """
    global _last_health_status

    result = JobResult(
        job_id="health_check",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    health_data: Dict[str, Any] = {
        "database": {"ok": False, "latency_ms": None, "error": None},
        "redis": {"ok": False, "latency_ms": None, "error": None},
        "storage": {"ok": False, "latency_ms": None, "error": None},
        "scheduler": {"ok": True},  # Se job gira, scheduler funziona
        "system": {"cpu_percent": None, "memory_percent": None, "disk_percent": None},
        "checked_at": datetime.utcnow().isoformat(),
    }

    try:
        # === CHECK 1: PostgreSQL ===
        db_ok, db_latency, db_error = await _check_database()
        health_data["database"]["ok"] = db_ok
        health_data["database"]["latency_ms"] = db_latency
        health_data["database"]["error"] = db_error

        if not db_ok:
            logger.warning(f"Health check: PostgreSQL DOWN - {db_error}")

        # === CHECK 2: Redis ===
        redis_ok, redis_latency, redis_error = await _check_redis()
        health_data["redis"]["ok"] = redis_ok
        health_data["redis"]["latency_ms"] = redis_latency
        health_data["redis"]["error"] = redis_error

        if not redis_ok:
            logger.warning(f"Health check: Redis DOWN - {redis_error}")

        # === CHECK 3: Storage (MinIO) ===
        storage_ok, storage_latency, storage_error = await _check_storage()
        health_data["storage"]["ok"] = storage_ok
        health_data["storage"]["latency_ms"] = storage_latency
        health_data["storage"]["error"] = storage_error

        if not storage_ok:
            logger.warning(f"Health check: Storage DOWN - {storage_error}")

        # === CHECK 4: System Metrics ===
        system_metrics = _get_system_metrics()
        health_data["system"] = system_metrics

        # Alert su risorse critiche
        if system_metrics["cpu_percent"] and system_metrics["cpu_percent"] > 90:
            logger.warning(f"Health check: CPU HIGH ({system_metrics['cpu_percent']}%)")
        if system_metrics["memory_percent"] and system_metrics["memory_percent"] > 90:
            logger.warning(f"Health check: Memory HIGH ({system_metrics['memory_percent']}%)")
        if system_metrics["disk_percent"] and system_metrics["disk_percent"] > 90:
            logger.warning(f"Health check: Disk HIGH ({system_metrics['disk_percent']}%)")

        # === LOG TO DATABASE ===
        await _save_health_log(health_data)

        # === UPDATE CACHE ===
        _last_health_status = health_data

        # Determina status job
        all_services_ok = db_ok and redis_ok and storage_ok
        result.status = JobStatus.SUCCESS
        result.records_processed = 1
        result.details = health_data

        if not all_services_ok:
            # Job success ma segnala warning nei details
            errors = []
            if not db_ok:
                errors.append(f"database: {db_error}")
            if not redis_ok:
                errors.append(f"redis: {redis_error}")
            if not storage_ok:
                errors.append(f"storage: {storage_error}")
            result.details["warnings"] = errors

        logger.info(
            f"health_check_job: DB={db_ok}, Redis={redis_ok}, "
            f"Storage={storage_ok}, CPU={system_metrics.get('cpu_percent')}%"
        )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("health_check_job failed")

    result.finished_at = datetime.now()
    return result


async def _check_database() -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Verifica connessione PostgreSQL con query semplice.

    Returns:
        (ok, latency_ms, error_message)
    """
    try:
        start = time.perf_counter()

        async with async_session_maker() as session:
            # Query minima per verificare connessione
            await asyncio.wait_for(
                session.execute(text("SELECT 1")),
                timeout=HEALTH_CHECK_TIMEOUT,
            )

        latency = (time.perf_counter() - start) * 1000
        return True, round(latency, 2), None

    except asyncio.TimeoutError:
        return False, None, f"Timeout ({HEALTH_CHECK_TIMEOUT}s)"

    except Exception as e:
        return False, None, str(e)


async def _check_redis() -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Verifica connessione Redis con PING command.

    Returns:
        (ok, latency_ms, error_message)
    """
    try:
        import redis.asyncio as aioredis
        from urllib.parse import urlparse

        parsed = urlparse(REDIS_URL)

        start = time.perf_counter()

        client = aioredis.Redis(
            host=parsed.hostname or "localhost",
            port=parsed.port or 6379,
            db=int(parsed.path.lstrip("/") or "0"),
            decode_responses=True,
        )

        try:
            pong = await asyncio.wait_for(
                client.ping(),
                timeout=HEALTH_CHECK_TIMEOUT,
            )
            latency = (time.perf_counter() - start) * 1000

            if pong:
                return True, round(latency, 2), None
            else:
                return False, None, "PING returned False"

        finally:
            await client.close()

    except asyncio.TimeoutError:
        return False, None, f"Timeout ({HEALTH_CHECK_TIMEOUT}s)"

    except ImportError:
        # Redis non installato, skip check
        return True, None, "redis package not installed (skipped)"

    except Exception as e:
        return False, None, str(e)


async def _check_storage() -> Tuple[bool, Optional[float], Optional[str]]:
    """
    Verifica connessione MinIO/Storage.

    Returns:
        (ok, latency_ms, error_message)
    """
    try:
        from minio import Minio

        access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
        secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
        secure = os.getenv("MINIO_SECURE", "false").lower() == "true"

        start = time.perf_counter()

        client = Minio(
            STORAGE_ENDPOINT,
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )

        # List buckets con timeout
        # 💡 MinIO client è sync, eseguiamo in thread pool
        loop = asyncio.get_event_loop()
        buckets = await asyncio.wait_for(
            loop.run_in_executor(None, client.list_buckets),
            timeout=HEALTH_CHECK_TIMEOUT,
        )

        latency = (time.perf_counter() - start) * 1000
        return True, round(latency, 2), None

    except asyncio.TimeoutError:
        return False, None, f"Timeout ({HEALTH_CHECK_TIMEOUT}s)"

    except ImportError:
        # MinIO non installato, skip check
        return True, None, "minio package not installed (skipped)"

    except Exception as e:
        return False, None, str(e)


def _get_system_metrics() -> Dict[str, Optional[float]]:
    """
    Raccolta metriche sistema via psutil.

    💡 Metriche raccolte:
    - CPU: utilizzo percentuale (media su tutti i core)
    - Memory: RAM utilizzata percentuale
    - Disk: spazio disco utilizzato percentuale
    """
    try:
        return {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage("/").percent,
        }
    except Exception as e:
        logger.warning(f"Failed to get system metrics: {e}")
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "disk_percent": None,
        }


async def _save_health_log(health_data: Dict[str, Any]) -> None:
    """
    Salva health check in database per storico.

    💡 Retention: 7 giorni (cleanup in job separato se necessario)
    """
    try:
        async with async_session_maker() as session:
            async with session.begin():
                log_entry = SystemHealthLog(
                    database_ok=1 if health_data["database"]["ok"] else 0,
                    redis_ok=1 if health_data["redis"]["ok"] else 0,
                    storage_ok=1 if health_data["storage"]["ok"] else 0,
                    scheduler_ok=1 if health_data["scheduler"]["ok"] else 0,
                    database_latency_ms=health_data["database"]["latency_ms"],
                    redis_latency_ms=health_data["redis"]["latency_ms"],
                    storage_latency_ms=health_data["storage"]["latency_ms"],
                    cpu_percent=health_data["system"].get("cpu_percent"),
                    memory_percent=health_data["system"].get("memory_percent"),
                    disk_percent=health_data["system"].get("disk_percent"),
                    error_details=_format_errors(health_data),
                )
                session.add(log_entry)
                await session.commit()

    except Exception as e:
        logger.warning(f"Failed to save health log: {e}")


def _format_errors(health_data: Dict[str, Any]) -> Optional[str]:
    """Formatta errori per storage in DB."""
    errors = []

    for service in ["database", "redis", "storage"]:
        if not health_data[service]["ok"] and health_data[service]["error"]:
            errors.append(f"{service}: {health_data[service]['error']}")

    return "; ".join(errors) if errors else None


def get_health_status() -> Dict[str, Any]:
    """
    Ritorna ultimo stato health per endpoint /health.

    💡 Usato da api/health.py per risposta immediata
    senza dover ricalcolare tutto.
    """
    if not _last_health_status:
        return {
            "status": "unknown",
            "message": "Health check not yet executed",
            "checked_at": None,
        }

    all_ok = (
        _last_health_status.get("database", {}).get("ok", False) and
        _last_health_status.get("redis", {}).get("ok", False) and
        _last_health_status.get("storage", {}).get("ok", False)
    )

    return {
        "status": "healthy" if all_ok else "degraded",
        "services": {
            "database": _last_health_status.get("database", {}),
            "redis": _last_health_status.get("redis", {}),
            "storage": _last_health_status.get("storage", {}),
            "scheduler": _last_health_status.get("scheduler", {}),
        },
        "system": _last_health_status.get("system", {}),
        "checked_at": _last_health_status.get("checked_at"),
    }

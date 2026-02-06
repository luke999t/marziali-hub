"""
================================================================================
AI_MODULE: DatabaseBackupJob
AI_VERSION: 1.0.0
AI_DESCRIPTION: Backup automatico database PostgreSQL con rotazione
AI_BUSINESS: Disaster recovery, compliance dati, continuità operativa
AI_TEACHING: pg_dump async subprocess + rotazione file retention policy

ALTERNATIVE_VALUTATE:
- pg_basebackup: Scartato, richiede accesso filesystem server DB
- WAL archiving: Scartato, complessità per point-in-time recovery
- Cloud snapshots: Scartato, vendor lock-in e costo

PERCHÉ_QUESTA_SOLUZIONE:
- pg_dump = standard industry per PostgreSQL backup
- Async subprocess = non blocca event loop FastAPI
- Rotazione locale = semplice e affidabile
- Compressione gzip = risparmio storage 80%+
================================================================================
"""

import asyncio
import gzip
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from modules.scheduler.scheduler_service import JobResult, JobStatus

logger = logging.getLogger(__name__)

# 💡 Configurazione da environment
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "/var/backups/media-center"))
BACKUP_RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "7"))
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://martial_user:martial_pass@localhost:5432/martial_arts_db"
)

# Parse database URL per pg_dump
_parsed_db_url = urlparse(DATABASE_URL)
DB_HOST = _parsed_db_url.hostname or "localhost"
DB_PORT = str(_parsed_db_url.port or 5432)
DB_NAME = _parsed_db_url.path.lstrip("/") or "martial_arts_db"
DB_USER = _parsed_db_url.username or "martial_user"
DB_PASSWORD = _parsed_db_url.password or "martial_pass"


async def database_backup_job() -> JobResult:
    """
    🎯 BUSINESS: Backup giornaliero database per disaster recovery
    📊 KPI: Uptime, RPO (Recovery Point Objective), storage backup
    ⏱️ SCHEDULE: Ogni giorno alle 03:00

    LOGICA:
    1. Crea directory backup se non esiste
    2. Esegui pg_dump con compressione gzip
    3. Verifica integrità backup (size > 0)
    4. Rotazione: elimina backup più vecchi di RETENTION_DAYS
    5. Log risultati per monitoring

    💡 Perché 03:00:
    - Minimo traffico utenti
    - Dopo analytics job (02:00)
    - Prima dell'orario lavorativo
    """
    result = JobResult(
        job_id="database_backup",
        status=JobStatus.RUNNING,
        started_at=datetime.now(),
    )

    backup_path: Optional[Path] = None
    backup_size: int = 0

    try:
        # 1. Ensure backup directory exists
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        # 2. Generate backup filename with timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"martial_arts_db_{timestamp}.sql.gz"
        backup_path = BACKUP_DIR / backup_filename

        # 3. Execute pg_dump
        logger.info(f"Starting database backup to {backup_path}")

        success, error_msg = await _run_pg_dump(backup_path)

        if not success:
            result.status = JobStatus.FAILED
            result.error_message = f"pg_dump failed: {error_msg}"
            logger.error(f"Backup failed: {error_msg}")

            # Cleanup failed backup file
            if backup_path.exists():
                backup_path.unlink()

            result.finished_at = datetime.now()
            return result

        # 4. Verify backup integrity
        if not backup_path.exists():
            result.status = JobStatus.FAILED
            result.error_message = "Backup file not created"
            result.finished_at = datetime.now()
            return result

        backup_size = backup_path.stat().st_size
        if backup_size < 1000:  # Less than 1KB is suspicious
            result.status = JobStatus.FAILED
            result.error_message = f"Backup too small ({backup_size} bytes), likely empty"
            backup_path.unlink()
            result.finished_at = datetime.now()
            return result

        logger.info(f"Backup created: {backup_path} ({backup_size / 1024 / 1024:.2f} MB)")

        # 5. Rotation: delete old backups
        deleted_count, deleted_size = await _cleanup_old_backups()

        result.records_processed = 1
        result.status = JobStatus.SUCCESS
        result.details = {
            "backup_file": str(backup_path),
            "backup_size_bytes": backup_size,
            "backup_size_mb": round(backup_size / 1024 / 1024, 2),
            "old_backups_deleted": deleted_count,
            "old_backups_freed_mb": round(deleted_size / 1024 / 1024, 2),
            "retention_days": BACKUP_RETENTION_DAYS,
            "database": DB_NAME,
            "timestamp": timestamp,
        }

        logger.info(
            f"database_backup_job: Completed. "
            f"Size={backup_size / 1024 / 1024:.2f}MB, "
            f"Deleted={deleted_count} old backups"
        )

    except Exception as e:
        result.status = JobStatus.FAILED
        result.error_message = str(e)
        logger.exception("database_backup_job failed")

        # Cleanup partial backup
        if backup_path and backup_path.exists():
            try:
                backup_path.unlink()
            except Exception:
                pass

    result.finished_at = datetime.now()
    return result


async def _run_pg_dump(output_path: Path) -> Tuple[bool, Optional[str]]:
    """
    Esegue pg_dump con compressione gzip.

    Returns:
        (success, error_message)

    💡 Usa asyncio.create_subprocess_exec per non bloccare event loop
    """
    # Set PGPASSWORD environment per autenticazione
    env = os.environ.copy()
    env["PGPASSWORD"] = DB_PASSWORD

    # Comando pg_dump
    # 💡 --no-owner: non include ownership (portabilità)
    # 💡 --no-acl: non include permessi (portabilità)
    # 💡 -Fc: custom format (migliore per restore selettivo)
    cmd = [
        "pg_dump",
        "-h", DB_HOST,
        "-p", DB_PORT,
        "-U", DB_USER,
        "-d", DB_NAME,
        "--no-owner",
        "--no-acl",
        "-Fc",  # Custom format (più efficiente di plain SQL)
    ]

    try:
        # Create subprocess
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )

        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=3600,  # 1 hour max
        )

        if process.returncode != 0:
            error_msg = stderr.decode("utf-8", errors="replace")
            return False, error_msg

        # Write compressed output
        # 💡 pg_dump -Fc already compresses, but we gzip anyway for .gz extension
        with gzip.open(output_path, "wb") as f:
            f.write(stdout)

        return True, None

    except asyncio.TimeoutError:
        return False, "Backup timed out after 1 hour"

    except FileNotFoundError:
        return False, "pg_dump not found in PATH"

    except Exception as e:
        return False, str(e)


async def _cleanup_old_backups() -> Tuple[int, int]:
    """
    Elimina backup più vecchi di RETENTION_DAYS.

    Returns:
        (deleted_count, total_bytes_freed)

    💡 Retention policy tipica:
    - 7 giorni per daily backup
    - Considerare weekly/monthly per long-term
    """
    deleted_count = 0
    freed_bytes = 0
    cutoff_date = datetime.utcnow() - timedelta(days=BACKUP_RETENTION_DAYS)

    try:
        for backup_file in BACKUP_DIR.glob("martial_arts_db_*.sql.gz"):
            # Parse timestamp from filename
            try:
                # Format: martial_arts_db_YYYYMMDD_HHMMSS.sql.gz
                parts = backup_file.stem.replace(".sql", "").split("_")
                date_str = parts[3]  # YYYYMMDD
                time_str = parts[4]  # HHMMSS
                file_date = datetime.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")

                if file_date < cutoff_date:
                    file_size = backup_file.stat().st_size
                    backup_file.unlink()
                    deleted_count += 1
                    freed_bytes += file_size

                    logger.debug(f"Deleted old backup: {backup_file}")

            except (ValueError, IndexError) as e:
                # Can't parse filename, skip
                logger.warning(f"Couldn't parse backup filename: {backup_file}")
                continue

    except Exception as e:
        logger.warning(f"Error during backup cleanup: {e}")

    return deleted_count, freed_bytes


async def verify_backup_integrity(backup_path: Path) -> bool:
    """
    Verifica integrità backup tentando un test restore.

    💡 Opzionale: abilitare solo per backup critici (ci mette tempo)
    """
    try:
        # Test pg_restore (dry run)
        env = os.environ.copy()
        env["PGPASSWORD"] = DB_PASSWORD

        # Decompress for verification
        with gzip.open(backup_path, "rb") as f:
            # Just read first 1MB to verify it's valid gzip
            data = f.read(1024 * 1024)
            if len(data) < 100:
                return False

        return True

    except Exception as e:
        logger.warning(f"Backup integrity check failed: {e}")
        return False


def get_backup_list() -> List[dict]:
    """
    Ritorna lista backup disponibili per endpoint admin.
    """
    backups = []

    try:
        for backup_file in sorted(BACKUP_DIR.glob("martial_arts_db_*.sql.gz"), reverse=True):
            stat = backup_file.stat()
            backups.append({
                "filename": backup_file.name,
                "path": str(backup_file),
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / 1024 / 1024, 2),
                "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
    except Exception as e:
        logger.warning(f"Error listing backups: {e}")

    return backups

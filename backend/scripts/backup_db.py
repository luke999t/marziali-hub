#!/usr/bin/env python3
"""
Database Backup Script
PostgreSQL backup with retention policy and compression
"""

import os
import sys
import subprocess
import gzip
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv

# Load environment
load_dotenv(Path(__file__).parent.parent / ".env")

# Configuration
BACKUP_DIR = Path(__file__).parent.parent / "backups"
RETENTION_DAYS = 7  # Keep backups for 7 days
MAX_BACKUPS = 10    # Keep max 10 backups

# Database config from env
DATABASE_URL = os.getenv("DATABASE_URL", "")


def parse_db_url(url: str) -> dict:
    """Parse PostgreSQL URL into components"""
    # postgresql://user:pass@host:port/dbname
    if not url.startswith("postgresql://"):
        raise ValueError("Invalid PostgreSQL URL")

    url = url.replace("postgresql://", "")
    user_pass, rest = url.split("@")
    user, password = user_pass.split(":")
    host_port, dbname = rest.split("/")

    if ":" in host_port:
        host, port = host_port.split(":")
    else:
        host, port = host_port, "5432"

    return {
        "user": user,
        "password": password,
        "host": host,
        "port": port,
        "dbname": dbname
    }


def create_backup():
    """Create a compressed database backup"""
    if not DATABASE_URL:
        print("[ERROR] DATABASE_URL not set in .env")
        sys.exit(1)

    # Parse DB config
    db = parse_db_url(DATABASE_URL)

    # Create backup directory
    BACKUP_DIR.mkdir(exist_ok=True)

    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = BACKUP_DIR / f"backup_{db['dbname']}_{timestamp}.sql"
    compressed_file = backup_file.with_suffix(".sql.gz")

    print(f"[BACKUP] Creating backup: {compressed_file.name}")

    # Set password in environment
    env = os.environ.copy()
    env["PGPASSWORD"] = db["password"]

    # Run pg_dump
    cmd = [
        "pg_dump",
        "-h", db["host"],
        "-p", db["port"],
        "-U", db["user"],
        "-d", db["dbname"],
        "-F", "p",  # Plain SQL format
        "--no-owner",
        "--no-acl",
        "-f", str(backup_file)
    ]

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"[ERROR] pg_dump failed: {result.stderr}")
            sys.exit(1)
    except FileNotFoundError:
        print("[ERROR] pg_dump not found. Ensure PostgreSQL is installed.")
        sys.exit(1)

    # Compress backup
    with open(backup_file, 'rb') as f_in:
        with gzip.open(compressed_file, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Remove uncompressed file
    backup_file.unlink()

    # Get file size
    size_mb = compressed_file.stat().st_size / (1024 * 1024)
    print(f"[OK] Backup created: {compressed_file.name} ({size_mb:.2f} MB)")

    return compressed_file


def cleanup_old_backups():
    """Remove old backups based on retention policy"""
    if not BACKUP_DIR.exists():
        return

    backups = sorted(BACKUP_DIR.glob("backup_*.sql.gz"), key=lambda p: p.stat().st_mtime)

    # Remove by age
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    removed = 0

    for backup in backups:
        mtime = datetime.fromtimestamp(backup.stat().st_mtime)
        if mtime < cutoff:
            backup.unlink()
            removed += 1
            print(f"[CLEANUP] Removed old backup: {backup.name}")

    # Keep only MAX_BACKUPS
    backups = sorted(BACKUP_DIR.glob("backup_*.sql.gz"), key=lambda p: p.stat().st_mtime)
    while len(backups) > MAX_BACKUPS:
        oldest = backups.pop(0)
        oldest.unlink()
        removed += 1
        print(f"[CLEANUP] Removed excess backup: {oldest.name}")

    if removed:
        print(f"[CLEANUP] Cleaned up {removed} old backup(s)")


def list_backups():
    """List all available backups"""
    if not BACKUP_DIR.exists():
        print("[INFO] No backups found")
        return

    backups = sorted(BACKUP_DIR.glob("backup_*.sql.gz"), key=lambda p: p.stat().st_mtime, reverse=True)

    if not backups:
        print("[INFO] No backups found")
        return

    print(f"\nAvailable backups ({len(backups)}):\n")
    for backup in backups:
        size_mb = backup.stat().st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(backup.stat().st_mtime)
        print(f"  - {backup.name} ({size_mb:.2f} MB) - {mtime.strftime('%Y-%m-%d %H:%M')}")


def restore_backup(backup_name: str):
    """Restore a backup file"""
    if not DATABASE_URL:
        print("[ERROR] DATABASE_URL not set")
        sys.exit(1)

    backup_path = BACKUP_DIR / backup_name
    if not backup_path.exists():
        print(f"[ERROR] Backup not found: {backup_name}")
        sys.exit(1)

    db = parse_db_url(DATABASE_URL)
    env = os.environ.copy()
    env["PGPASSWORD"] = db["password"]

    print(f"[WARNING] Restoring {backup_name} to {db['dbname']}...")
    print("[WARNING] This will OVERWRITE the current database!")

    # Decompress to temp file
    temp_sql = BACKUP_DIR / "temp_restore.sql"
    with gzip.open(backup_path, 'rb') as f_in:
        with open(temp_sql, 'wb') as f_out:
            shutil.copyfileobj(f_in, f_out)

    # Run psql restore
    cmd = [
        "psql",
        "-h", db["host"],
        "-p", db["port"],
        "-U", db["user"],
        "-d", db["dbname"],
        "-f", str(temp_sql)
    ]

    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True)
        temp_sql.unlink()

        if result.returncode != 0:
            print(f"[ERROR] Restore failed: {result.stderr}")
            sys.exit(1)
    except FileNotFoundError:
        temp_sql.unlink()
        print("[ERROR] psql not found")
        sys.exit(1)

    print(f"[OK] Database restored from {backup_name}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Database Backup Tool")
    parser.add_argument("action", choices=["backup", "list", "restore", "cleanup"],
                        help="Action to perform")
    parser.add_argument("--file", help="Backup file to restore (for restore action)")

    args = parser.parse_args()

    if args.action == "backup":
        create_backup()
        cleanup_old_backups()
    elif args.action == "list":
        list_backups()
    elif args.action == "cleanup":
        cleanup_old_backups()
    elif args.action == "restore":
        if not args.file:
            print("[ERROR] Specify backup file with --file")
            sys.exit(1)
        restore_backup(args.file)

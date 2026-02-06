#!/usr/bin/env python3
"""
================================================================================
🧹 CLEANUP TEST DATA - Pulizia dati di test dopo test massivi
================================================================================

Questo script elimina TUTTI i dati creati durante i test massivi.
Identifica i dati di test tramite:
1. Prefisso "TEST_" nel nome/email
2. Creati dopo una certa data (timestamp inizio test)
3. ID specifici salvati durante i test

⚠️ ATTENZIONE: Eseguire solo dopo aver verificato i risultati dei test!

USO:
    python cleanup_test_data.py --dry-run    # Mostra cosa verrebbe eliminato
    python cleanup_test_data.py --execute    # Esegue la pulizia
    python cleanup_test_data.py --reset-all  # Reset COMPLETO (pericoloso!)
================================================================================
"""

import asyncio
import argparse
import json
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Database URL - deve matchare quello in .env
DATABASE_URL = "postgresql+asyncpg://martial_user:martial_pass@localhost:5432/martial_arts_db"

# Prefissi che identificano dati di test
TEST_PREFIXES = [
    "TEST_",
    "test_",
    "AUTOTEST_",
    "E2E_",
    "CHROME_TEST_",
]

# Email patterns di test
TEST_EMAIL_PATTERNS = [
    "%test_%@%",
    "%autotest%@%",
    "%e2e_%@%",
    "%chrome_test%@%",
]

# Tabelle da pulire (in ordine per rispettare FK)
TABLES_TO_CLEAN = [
    # Prima le tabelle dipendenti
    "viewing_history",
    "favorites", 
    "downloads",
    "subscription_history",
    "notifications",
    "video_progress",
    "curriculum_enrollments",
    "curriculum_progress",
    "fusion_videos",
    "fusion_projects",
    "skeleton_data",
    "ingest_batches",
    "ingest_projects",
    "special_project_participations",
    # Poi le tabelle principali
    "videos",
    "avatars",
    "curricula",
    "curriculum_levels",
    "curriculum_modules",
    "special_projects",
    "live_events",
    "donations",
    # Infine utenti (se necessario)
    # "users",  # Commentato per sicurezza
]


async def get_session():
    """Crea sessione database."""
    engine = create_async_engine(DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return async_session()


async def count_test_data(session: AsyncSession, table: str, dry_run: bool = True) -> int:
    """Conta i record di test in una tabella."""
    
    # Costruisci query in base alla tabella
    if table == "users":
        conditions = " OR ".join([f"email LIKE '{p}'" for p in TEST_EMAIL_PATTERNS])
        query = f"SELECT COUNT(*) FROM {table} WHERE {conditions}"
    elif table in ["videos", "avatars", "curricula", "fusion_projects", "ingest_projects", "special_projects"]:
        conditions = " OR ".join([f"name LIKE '{p}%'" for p in TEST_PREFIXES])
        query = f"SELECT COUNT(*) FROM {table} WHERE {conditions}"
    else:
        # Per altre tabelle, conta quelle create nelle ultime 24 ore con pattern test
        query = f"""
            SELECT COUNT(*) FROM {table} 
            WHERE created_at > NOW() - INTERVAL '24 hours'
        """
    
    try:
        result = await session.execute(text(query))
        count = result.scalar()
        return count or 0
    except Exception as e:
        print(f"  ⚠️ Errore conteggio {table}: {e}")
        return 0


async def delete_test_data(session: AsyncSession, table: str, dry_run: bool = True) -> int:
    """Elimina i record di test da una tabella."""
    
    # Costruisci query DELETE
    if table == "users":
        conditions = " OR ".join([f"email LIKE '{p}'" for p in TEST_EMAIL_PATTERNS])
        query = f"DELETE FROM {table} WHERE {conditions}"
    elif table in ["videos", "avatars", "curricula", "fusion_projects", "ingest_projects", "special_projects"]:
        conditions = " OR ".join([f"name LIKE '{p}%'" for p in TEST_PREFIXES])
        query = f"DELETE FROM {table} WHERE {conditions}"
    else:
        query = f"""
            DELETE FROM {table} 
            WHERE created_at > NOW() - INTERVAL '24 hours'
        """
    
    if dry_run:
        # In dry-run, solo conta
        return await count_test_data(session, table)
    
    try:
        result = await session.execute(text(query))
        await session.commit()
        return result.rowcount
    except Exception as e:
        print(f"  ❌ Errore eliminazione {table}: {e}")
        await session.rollback()
        return 0


async def cleanup_test_data(dry_run: bool = True, reset_all: bool = False):
    """Esegue la pulizia dei dati di test."""
    
    print("\n" + "="*60)
    print("🧹 CLEANUP DATI DI TEST")
    print("="*60)
    print(f"Modalità: {'DRY-RUN (simulazione)' if dry_run else '⚠️ ESECUZIONE REALE'}")
    print(f"Database: {DATABASE_URL.split('@')[1]}")
    print("="*60 + "\n")
    
    session = await get_session()
    
    total_deleted = 0
    
    try:
        for table in TABLES_TO_CLEAN:
            count = await count_test_data(session, table)
            
            if count > 0:
                if dry_run:
                    print(f"  📋 {table}: {count} record da eliminare")
                else:
                    deleted = await delete_test_data(session, table, dry_run=False)
                    print(f"  🗑️ {table}: {deleted} record eliminati")
                    total_deleted += deleted
            else:
                print(f"  ✅ {table}: nessun dato di test")
        
        print("\n" + "="*60)
        if dry_run:
            print(f"📊 TOTALE: {total_deleted} record verrebbero eliminati")
            print("💡 Esegui con --execute per eliminare davvero")
        else:
            print(f"🗑️ TOTALE: {total_deleted} record eliminati")
        print("="*60 + "\n")
        
    finally:
        await session.close()


async def reset_all_data():
    """⚠️ RESET COMPLETO - Elimina TUTTI i dati (pericoloso!)"""
    
    print("\n" + "="*60)
    print("⚠️⚠️⚠️ RESET COMPLETO DATABASE ⚠️⚠️⚠️")
    print("="*60)
    print("Questo eliminerà TUTTI i dati dal database!")
    print("="*60)
    
    confirm = input("\nSei SICURO? Digita 'RESET TUTTO' per confermare: ")
    
    if confirm != "RESET TUTTO":
        print("❌ Reset annullato")
        return
    
    session = await get_session()
    
    try:
        # Elimina in ordine inverso di dipendenza
        all_tables = TABLES_TO_CLEAN + ["users", "maestros", "asds"]
        
        for table in all_tables:
            try:
                result = await session.execute(text(f"DELETE FROM {table}"))
                await session.commit()
                print(f"  🗑️ {table}: {result.rowcount} record eliminati")
            except Exception as e:
                print(f"  ⚠️ {table}: {e}")
                await session.rollback()
        
        print("\n✅ Reset completato!")
        print("💡 Esegui seed_database.py per ripopolare con dati demo")
        
    finally:
        await session.close()


def main():
    parser = argparse.ArgumentParser(description="Cleanup dati di test")
    parser.add_argument("--dry-run", action="store_true", help="Mostra cosa verrebbe eliminato")
    parser.add_argument("--execute", action="store_true", help="Esegue la pulizia")
    parser.add_argument("--reset-all", action="store_true", help="Reset COMPLETO (pericoloso!)")
    
    args = parser.parse_args()
    
    if args.reset_all:
        asyncio.run(reset_all_data())
    elif args.execute:
        asyncio.run(cleanup_test_data(dry_run=False))
    else:
        # Default: dry-run
        asyncio.run(cleanup_test_data(dry_run=True))


if __name__ == "__main__":
    main()

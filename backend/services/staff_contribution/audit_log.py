"""
# AI_MODULE: AuditLog
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Log di audit immutabile per tracciamento azioni staff
# AI_BUSINESS: Registra ogni azione (creazione, modifica, approvazione) per
#              compliance, debugging, e accountability.
# AI_TEACHING: SQLite append-only con hash chain per immutabilita,
#              nessuna DELETE/UPDATE su entries, query ottimizzate con indici.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

AuditLog Module
===============

Log di audit immutabile con:
- Append-only (nessuna modifica/cancellazione)
- Hash chain per verifica integrita
- Indici per query veloci
- Export JSON/CSV per compliance
- Retention policy configurabile
"""

import asyncio
import csv
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncIterator
import logging
import uuid

from .schemas import AuditEntry, AuditAction

logger = logging.getLogger(__name__)


class AuditLog:
    """
    Log di audit immutabile.

    Singleton pattern con _reset_for_testing per test isolation.

    Schema:
        audit_entries: Entry log (append-only)
        Indici su: timestamp, action, actor_id, target_type, project_id
        Hash chain per verifica integrita
    """

    _instance: Optional["AuditLog"] = None
    _lock = asyncio.Lock()

    # Schema SQL
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS audit_entries (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        action TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        project_id TEXT,
        details TEXT DEFAULT '{}',
        ip_address TEXT,
        user_agent TEXT,
        previous_state TEXT,
        new_state TEXT,
        previous_hash TEXT,
        entry_hash TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_entries(actor_id);
    CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_entries(target_type, target_id);
    CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_entries(project_id);

    CREATE TABLE IF NOT EXISTS audit_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inizializza AuditLog.

        Args:
            db_path: Path database SQLite. Se None, usa default.
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "storage", "staff", "audit.db")
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False
        self._last_hash: Optional[str] = None

    @classmethod
    async def get_instance(cls, db_path: Optional[str] = None) -> "AuditLog":
        """
        Ottiene istanza singleton.

        Args:
            db_path: Path database (solo alla prima chiamata)

        Returns:
            Istanza AuditLog
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path)
                await cls._instance._initialize()
            return cls._instance

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset singleton per test isolation."""
        if cls._instance is not None:
            if cls._instance._conn:
                cls._instance._conn.close()
        cls._instance = None

    async def _initialize(self) -> None:
        """Inizializza database e schema."""
        if self._initialized:
            return

        # Crea directory se non esiste
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Connessione SQLite
        self._conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row

        # Crea schema
        self._conn.executescript(self._SCHEMA)
        self._conn.commit()

        # Carica ultimo hash
        cursor = self._conn.execute(
            "SELECT entry_hash FROM audit_entries ORDER BY timestamp DESC LIMIT 1"
        )
        row = cursor.fetchone()
        self._last_hash = row["entry_hash"] if row else None

        self._initialized = True
        logger.info(f"AuditLog inizializzato: {self._db_path}")

    def _generate_id(self) -> str:
        """Genera ID univoco."""
        return str(uuid.uuid4())

    def _compute_hash(self, entry: AuditEntry, previous_hash: Optional[str]) -> str:
        """
        Calcola hash per entry.

        Args:
            entry: Entry da hashare
            previous_hash: Hash entry precedente

        Returns:
            Hash SHA256
        """
        content = json.dumps({
            "id": entry.id,
            "timestamp": entry.timestamp,
            "action": entry.action,
            "actor_id": entry.actor_id,
            "target_type": entry.target_type,
            "target_id": entry.target_id,
            "details": entry.details,
            "previous_hash": previous_hash or "",
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    async def log(
        self,
        action: AuditAction,
        actor_id: str,
        target_type: str,
        target_id: str,
        project_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        previous_state: Optional[Dict[str, Any]] = None,
        new_state: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """
        Registra azione nel log.

        Args:
            action: Tipo azione
            actor_id: ID attore
            target_type: Tipo target
            target_id: ID target
            project_id: ID progetto
            details: Dettagli aggiuntivi
            ip_address: IP address
            user_agent: User agent
            previous_state: Stato precedente
            new_state: Nuovo stato

        Returns:
            AuditEntry registrata
        """
        entry_id = self._generate_id()
        timestamp = datetime.now().isoformat()

        entry = AuditEntry(
            id=entry_id,
            timestamp=timestamp,
            action=action.value,
            actor_id=actor_id,
            target_type=target_type,
            target_id=target_id,
            project_id=project_id,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            previous_state=previous_state,
            new_state=new_state,
        )

        # Calcola hash con chain
        entry_hash = self._compute_hash(entry, self._last_hash)

        # Inserisci (append-only)
        self._conn.execute(
            """
            INSERT INTO audit_entries
            (id, timestamp, action, actor_id, target_type, target_id, project_id,
             details, ip_address, user_agent, previous_state, new_state,
             previous_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id,
                entry.timestamp,
                entry.action,
                entry.actor_id,
                entry.target_type,
                entry.target_id,
                entry.project_id,
                json.dumps(entry.details),
                entry.ip_address,
                entry.user_agent,
                json.dumps(entry.previous_state) if entry.previous_state else None,
                json.dumps(entry.new_state) if entry.new_state else None,
                self._last_hash,
                entry_hash,
            )
        )
        self._conn.commit()

        # Aggiorna ultimo hash
        self._last_hash = entry_hash

        logger.debug(f"Audit log: {action.value} by {actor_id} on {target_type}:{target_id}")
        return entry

    async def get(self, entry_id: str) -> Optional[AuditEntry]:
        """
        Ottiene entry per ID.

        Args:
            entry_id: ID entry

        Returns:
            AuditEntry o None
        """
        cursor = self._conn.execute(
            "SELECT * FROM audit_entries WHERE id = ?",
            (entry_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_entry(row)
        return None

    def _row_to_entry(self, row: sqlite3.Row) -> AuditEntry:
        """Converte row SQLite in AuditEntry."""
        return AuditEntry(
            id=row["id"],
            timestamp=row["timestamp"],
            action=row["action"],
            actor_id=row["actor_id"],
            target_type=row["target_type"],
            target_id=row["target_id"],
            project_id=row["project_id"],
            details=json.loads(row["details"]) if row["details"] else {},
            ip_address=row["ip_address"],
            user_agent=row["user_agent"],
            previous_state=json.loads(row["previous_state"]) if row["previous_state"] else None,
            new_state=json.loads(row["new_state"]) if row["new_state"] else None,
        )

    async def query(
        self,
        action: Optional[AuditAction] = None,
        actor_id: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        project_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """
        Cerca entries nel log.

        Args:
            action: Filtra per azione
            actor_id: Filtra per attore
            target_type: Filtra per tipo target
            target_id: Filtra per ID target
            project_id: Filtra per progetto
            start_date: Data inizio
            end_date: Data fine
            limit: Numero massimo risultati
            offset: Offset paginazione

        Returns:
            Lista AuditEntry
        """
        conditions = []
        params = []

        if action:
            conditions.append("action = ?")
            params.append(action.value)

        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)

        if target_type:
            conditions.append("target_type = ?")
            params.append(target_type)

        if target_id:
            conditions.append("target_id = ?")
            params.append(target_id)

        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT * FROM audit_entries
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        cursor = self._conn.execute(query, params)
        return [self._row_to_entry(row) for row in cursor.fetchall()]

    async def get_by_actor(
        self,
        actor_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Ottiene entries per attore."""
        return await self.query(actor_id=actor_id, limit=limit, offset=offset)

    async def get_by_target(
        self,
        target_type: str,
        target_id: str,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Ottiene entries per target."""
        return await self.query(
            target_type=target_type,
            target_id=target_id,
            limit=limit
        )

    async def get_by_project(
        self,
        project_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Ottiene entries per progetto."""
        return await self.query(project_id=project_id, limit=limit, offset=offset)

    async def get_recent(
        self,
        hours: int = 24,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Ottiene entries recenti."""
        start_date = datetime.now() - timedelta(hours=hours)
        return await self.query(start_date=start_date, limit=limit)

    async def count(
        self,
        action: Optional[AuditAction] = None,
        actor_id: Optional[str] = None,
        project_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """
        Conta entries con filtri.

        Returns:
            Numero entries
        """
        conditions = []
        params = []

        if action:
            conditions.append("action = ?")
            params.append(action.value)

        if actor_id:
            conditions.append("actor_id = ?")
            params.append(actor_id)

        if project_id:
            conditions.append("project_id = ?")
            params.append(project_id)

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        cursor = self._conn.execute(
            f"SELECT COUNT(*) FROM audit_entries WHERE {where_clause}",
            params
        )
        return cursor.fetchone()[0]

    async def verify_integrity(self) -> Dict[str, Any]:
        """
        Verifica integrita hash chain.

        Returns:
            Dict con risultato verifica
        """
        result = {
            "valid": True,
            "total_entries": 0,
            "verified_entries": 0,
            "first_invalid_id": None,
            "first_invalid_reason": None,
        }

        cursor = self._conn.execute(
            "SELECT * FROM audit_entries ORDER BY timestamp ASC"
        )

        previous_hash = None
        for row in cursor:
            result["total_entries"] += 1

            entry = self._row_to_entry(row)
            stored_hash = row["entry_hash"]
            stored_previous = row["previous_hash"]

            # Verifica previous_hash
            if stored_previous != previous_hash:
                result["valid"] = False
                result["first_invalid_id"] = entry.id
                result["first_invalid_reason"] = "previous_hash_mismatch"
                break

            # Ricalcola hash
            computed_hash = self._compute_hash(entry, previous_hash)
            if computed_hash != stored_hash:
                result["valid"] = False
                result["first_invalid_id"] = entry.id
                result["first_invalid_reason"] = "entry_hash_mismatch"
                break

            result["verified_entries"] += 1
            previous_hash = stored_hash

        return result

    async def export_json(
        self,
        output_path: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """
        Esporta log in JSON.

        Args:
            output_path: Path file output
            start_date: Data inizio
            end_date: Data fine

        Returns:
            Numero entries esportate
        """
        entries = await self.query(
            start_date=start_date,
            end_date=end_date,
            limit=1000000  # Limite alto per export
        )

        data = [e.to_dict() for e in entries]

        # Deserializza details per output pulito
        for item in data:
            if isinstance(item.get("details"), str):
                item["details"] = json.loads(item["details"])

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return len(data)

    async def export_csv(
        self,
        output_path: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> int:
        """
        Esporta log in CSV.

        Args:
            output_path: Path file output
            start_date: Data inizio
            end_date: Data fine

        Returns:
            Numero entries esportate
        """
        entries = await self.query(
            start_date=start_date,
            end_date=end_date,
            limit=1000000
        )

        if not entries:
            return 0

        fieldnames = [
            "id", "timestamp", "action", "actor_id",
            "target_type", "target_id", "project_id", "details",
        ]

        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                row = {
                    "id": entry.id,
                    "timestamp": entry.timestamp,
                    "action": entry.action,
                    "actor_id": entry.actor_id,
                    "target_type": entry.target_type,
                    "target_id": entry.target_id,
                    "project_id": entry.project_id or "",
                    "details": json.dumps(entry.details),
                }
                writer.writerow(row)

        return len(entries)

    async def get_stats(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche log.

        Returns:
            Dict con statistiche
        """
        conditions = []
        params = []

        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date.isoformat())

        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date.isoformat())

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        # Totale
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM audit_entries WHERE {where_clause}",
            params
        ).fetchone()[0]

        # Per azione
        by_action = {}
        for row in self._conn.execute(
            f"SELECT action, COUNT(*) as cnt FROM audit_entries WHERE {where_clause} GROUP BY action",
            params
        ):
            by_action[row["action"]] = row["cnt"]

        # Per attore (top 10)
        top_actors = []
        for row in self._conn.execute(
            f"""
            SELECT actor_id, COUNT(*) as cnt
            FROM audit_entries WHERE {where_clause}
            GROUP BY actor_id
            ORDER BY cnt DESC
            LIMIT 10
            """,
            params
        ):
            top_actors.append({"actor_id": row["actor_id"], "count": row["cnt"]})

        # Per giorno
        by_day = {}
        for row in self._conn.execute(
            f"""
            SELECT DATE(timestamp) as day, COUNT(*) as cnt
            FROM audit_entries WHERE {where_clause}
            GROUP BY DATE(timestamp)
            ORDER BY day DESC
            LIMIT 30
            """,
            params
        ):
            by_day[row["day"]] = row["cnt"]

        return {
            "total_entries": total,
            "by_action": by_action,
            "top_actors": top_actors,
            "by_day": by_day,
        }

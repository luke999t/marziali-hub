"""
# AI_MODULE: VersionControl
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Versioning copy-on-write per contributi staff
# AI_BUSINESS: Mantiene storico versioni di ogni contributo,
#              permette rollback, confronto versioni, tracking modifiche.
# AI_TEACHING: Pattern copy-on-write dove ogni modifica crea nuova versione,
#              diff calcolo tra versioni, restore point-in-time.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

VersionControl Module
=====================

Gestione versioni contributi con:
- Copy-on-write (ogni modifica crea nuova versione)
- Diff tra versioni
- Restore a versione precedente
- History completa per contributo
- Merge automatico per conflitti semplici
"""

import asyncio
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from difflib import unified_diff, SequenceMatcher
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import logging
import uuid

from .schemas import ContributionVersion

logger = logging.getLogger(__name__)


@dataclass
class VersionDiff:
    """Differenze tra due versioni."""
    from_version: int
    to_version: int
    added_fields: List[str]
    removed_fields: List[str]
    modified_fields: Dict[str, Dict[str, Any]]  # field -> {old, new}
    text_diffs: Dict[str, str]  # field -> unified diff string
    similarity: float  # 0-1

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return {
            "from_version": self.from_version,
            "to_version": self.to_version,
            "added_fields": self.added_fields,
            "removed_fields": self.removed_fields,
            "modified_fields": self.modified_fields,
            "text_diffs": self.text_diffs,
            "similarity": self.similarity,
        }


from dataclasses import dataclass


class VersionControl:
    """
    Controllo versione per contributi.

    Singleton pattern con _reset_for_testing per test isolation.

    Ogni contributo ha versioni numerate sequenzialmente (1, 2, 3...).
    Ogni modifica crea nuova versione con copy-on-write.
    """

    _instance: Optional["VersionControl"] = None
    _lock = asyncio.Lock()

    # Schema SQL
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS versions (
        id TEXT PRIMARY KEY,
        contribution_id TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL,
        created_by TEXT NOT NULL,
        change_summary TEXT,
        diff_from_previous TEXT,
        UNIQUE(contribution_id, version_number)
    );

    CREATE INDEX IF NOT EXISTS idx_versions_contribution ON versions(contribution_id);
    CREATE INDEX IF NOT EXISTS idx_versions_number ON versions(contribution_id, version_number);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inizializza VersionControl.

        Args:
            db_path: Path database SQLite. Se None, usa default.
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "storage", "staff", "versions.db")
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    @classmethod
    async def get_instance(cls, db_path: Optional[str] = None) -> "VersionControl":
        """
        Ottiene istanza singleton.

        Args:
            db_path: Path database (solo alla prima chiamata)

        Returns:
            Istanza VersionControl
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

        self._initialized = True
        logger.info(f"VersionControl inizializzato: {self._db_path}")

    def _generate_id(self) -> str:
        """Genera ID univoco."""
        return str(uuid.uuid4())

    async def create_version(
        self,
        contribution_id: str,
        content: Dict[str, Any],
        created_by: str,
        change_summary: Optional[str] = None,
    ) -> ContributionVersion:
        """
        Crea nuova versione di un contributo.

        Args:
            contribution_id: ID contributo
            content: Contenuto della versione
            created_by: ID autore modifica
            change_summary: Riepilogo modifiche

        Returns:
            ContributionVersion creata
        """
        # Determina numero versione
        cursor = self._conn.execute(
            "SELECT MAX(version_number) FROM versions WHERE contribution_id = ?",
            (contribution_id,)
        )
        row = cursor.fetchone()
        version_number = (row[0] or 0) + 1

        # Calcola diff dalla versione precedente
        diff_from_previous = None
        if version_number > 1:
            prev_version = await self.get_version(contribution_id, version_number - 1)
            if prev_version:
                diff = self.compute_diff(prev_version.content, content)
                diff_from_previous = diff.to_dict()

        # Crea versione
        version_id = self._generate_id()
        now = datetime.now().isoformat()

        version = ContributionVersion(
            id=version_id,
            contribution_id=contribution_id,
            version_number=version_number,
            content=content,
            created_at=now,
            created_by=created_by,
            change_summary=change_summary,
            diff_from_previous=diff_from_previous,
        )

        # Inserisci nel DB
        self._conn.execute(
            """
            INSERT INTO versions
            (id, contribution_id, version_number, content, created_at, created_by,
             change_summary, diff_from_previous)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                version.id,
                version.contribution_id,
                version.version_number,
                json.dumps(version.content),
                version.created_at,
                version.created_by,
                version.change_summary,
                json.dumps(version.diff_from_previous) if version.diff_from_previous else None,
            )
        )
        self._conn.commit()

        logger.info(f"Versione creata: {contribution_id} v{version_number}")
        return version

    async def get_version(
        self,
        contribution_id: str,
        version_number: int,
    ) -> Optional[ContributionVersion]:
        """
        Ottiene versione specifica.

        Args:
            contribution_id: ID contributo
            version_number: Numero versione

        Returns:
            ContributionVersion o None
        """
        cursor = self._conn.execute(
            "SELECT * FROM versions WHERE contribution_id = ? AND version_number = ?",
            (contribution_id, version_number)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_version(row)
        return None

    async def get_latest_version(
        self,
        contribution_id: str,
    ) -> Optional[ContributionVersion]:
        """
        Ottiene ultima versione.

        Args:
            contribution_id: ID contributo

        Returns:
            ContributionVersion o None
        """
        cursor = self._conn.execute(
            """
            SELECT * FROM versions
            WHERE contribution_id = ?
            ORDER BY version_number DESC
            LIMIT 1
            """,
            (contribution_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_version(row)
        return None

    async def get_version_count(self, contribution_id: str) -> int:
        """
        Conta versioni di un contributo.

        Args:
            contribution_id: ID contributo

        Returns:
            Numero versioni
        """
        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM versions WHERE contribution_id = ?",
            (contribution_id,)
        )
        return cursor.fetchone()[0]

    async def get_history(
        self,
        contribution_id: str,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ContributionVersion]:
        """
        Ottiene storico versioni.

        Args:
            contribution_id: ID contributo
            limit: Numero massimo risultati
            offset: Offset paginazione

        Returns:
            Lista ContributionVersion (dalla piu' recente)
        """
        cursor = self._conn.execute(
            """
            SELECT * FROM versions
            WHERE contribution_id = ?
            ORDER BY version_number DESC
            LIMIT ? OFFSET ?
            """,
            (contribution_id, limit, offset)
        )
        return [self._row_to_version(row) for row in cursor.fetchall()]

    def _row_to_version(self, row: sqlite3.Row) -> ContributionVersion:
        """Converte row SQLite in ContributionVersion."""
        return ContributionVersion(
            id=row["id"],
            contribution_id=row["contribution_id"],
            version_number=row["version_number"],
            content=json.loads(row["content"]),
            created_at=row["created_at"],
            created_by=row["created_by"],
            change_summary=row["change_summary"],
            diff_from_previous=json.loads(row["diff_from_previous"]) if row["diff_from_previous"] else None,
        )

    def compute_diff(
        self,
        old_content: Dict[str, Any],
        new_content: Dict[str, Any],
    ) -> VersionDiff:
        """
        Calcola differenze tra due versioni.

        Args:
            old_content: Contenuto vecchio
            new_content: Contenuto nuovo

        Returns:
            VersionDiff
        """
        old_keys = set(old_content.keys())
        new_keys = set(new_content.keys())

        added = list(new_keys - old_keys)
        removed = list(old_keys - new_keys)
        common = old_keys & new_keys

        modified = {}
        text_diffs = {}

        for key in common:
            old_val = old_content[key]
            new_val = new_content[key]

            if old_val != new_val:
                modified[key] = {"old": old_val, "new": new_val}

                # Genera diff testuale per stringhe
                if isinstance(old_val, str) and isinstance(new_val, str):
                    diff_lines = list(unified_diff(
                        old_val.splitlines(keepends=True),
                        new_val.splitlines(keepends=True),
                        fromfile=f"{key} (v-1)",
                        tofile=f"{key} (v)",
                    ))
                    if diff_lines:
                        text_diffs[key] = "".join(diff_lines)

        # Calcola similarita
        old_str = json.dumps(old_content, sort_keys=True)
        new_str = json.dumps(new_content, sort_keys=True)
        similarity = SequenceMatcher(None, old_str, new_str).ratio()

        return VersionDiff(
            from_version=0,  # Sara' impostato dal chiamante
            to_version=0,
            added_fields=added,
            removed_fields=removed,
            modified_fields=modified,
            text_diffs=text_diffs,
            similarity=similarity,
        )

    async def compare_versions(
        self,
        contribution_id: str,
        from_version: int,
        to_version: int,
    ) -> Optional[VersionDiff]:
        """
        Confronta due versioni.

        Args:
            contribution_id: ID contributo
            from_version: Numero versione origine
            to_version: Numero versione destinazione

        Returns:
            VersionDiff o None se versioni non trovate
        """
        v_from = await self.get_version(contribution_id, from_version)
        v_to = await self.get_version(contribution_id, to_version)

        if not v_from or not v_to:
            return None

        diff = self.compute_diff(v_from.content, v_to.content)
        diff.from_version = from_version
        diff.to_version = to_version

        return diff

    async def restore_version(
        self,
        contribution_id: str,
        version_number: int,
        restored_by: str,
    ) -> Optional[ContributionVersion]:
        """
        Ripristina una versione precedente.

        Crea nuova versione con contenuto della versione specificata.

        Args:
            contribution_id: ID contributo
            version_number: Numero versione da ripristinare
            restored_by: ID utente che ripristina

        Returns:
            Nuova ContributionVersion o None
        """
        old_version = await self.get_version(contribution_id, version_number)
        if not old_version:
            return None

        # Crea nuova versione con contenuto ripristinato
        return await self.create_version(
            contribution_id=contribution_id,
            content=old_version.content,
            created_by=restored_by,
            change_summary=f"Ripristinato da versione {version_number}",
        )

    async def delete_contribution_versions(self, contribution_id: str) -> int:
        """
        Elimina tutte le versioni di un contributo.

        Args:
            contribution_id: ID contributo

        Returns:
            Numero versioni eliminate
        """
        cursor = self._conn.execute(
            "DELETE FROM versions WHERE contribution_id = ?",
            (contribution_id,)
        )
        self._conn.commit()
        deleted = cursor.rowcount
        logger.info(f"Eliminate {deleted} versioni per {contribution_id}")
        return deleted

    async def get_versions_by_author(
        self,
        author_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ContributionVersion]:
        """
        Ottiene versioni create da un autore.

        Args:
            author_id: ID autore
            limit: Numero massimo
            offset: Offset

        Returns:
            Lista ContributionVersion
        """
        cursor = self._conn.execute(
            """
            SELECT * FROM versions
            WHERE created_by = ?
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
            """,
            (author_id, limit, offset)
        )
        return [self._row_to_version(row) for row in cursor.fetchall()]

    async def get_changes_summary(
        self,
        contribution_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Ottiene riepilogo modifiche per contributo.

        Args:
            contribution_id: ID contributo

        Returns:
            Lista di modifiche [{version, date, author, summary}, ...]
        """
        cursor = self._conn.execute(
            """
            SELECT version_number, created_at, created_by, change_summary
            FROM versions
            WHERE contribution_id = ?
            ORDER BY version_number ASC
            """,
            (contribution_id,)
        )

        return [
            {
                "version": row["version_number"],
                "date": row["created_at"],
                "author": row["created_by"],
                "summary": row["change_summary"],
            }
            for row in cursor.fetchall()
        ]

    def merge_contents(
        self,
        base: Dict[str, Any],
        ours: Dict[str, Any],
        theirs: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """
        Merge a tre vie per contenuti.

        Args:
            base: Versione base comune
            ours: Nostra versione
            theirs: Loro versione

        Returns:
            Tuple (contenuto merged, lista conflitti)
        """
        merged = {}
        conflicts = []

        all_keys = set(base.keys()) | set(ours.keys()) | set(theirs.keys())

        for key in all_keys:
            base_val = base.get(key)
            our_val = ours.get(key)
            their_val = theirs.get(key)

            if our_val == their_val:
                # Nessun conflitto, stessa modifica
                if our_val is not None:
                    merged[key] = our_val
            elif our_val == base_val:
                # Solo loro hanno modificato
                if their_val is not None:
                    merged[key] = their_val
            elif their_val == base_val:
                # Solo noi abbiamo modificato
                if our_val is not None:
                    merged[key] = our_val
            else:
                # Conflitto: entrambi hanno modificato
                conflicts.append(key)
                # Default: teniamo il nostro
                if our_val is not None:
                    merged[key] = our_val
                elif their_val is not None:
                    merged[key] = their_val

        return merged, conflicts

    async def get_stats(self) -> Dict[str, Any]:
        """
        Ottiene statistiche versioning.

        Returns:
            Dict con statistiche
        """
        # Totale versioni
        total = self._conn.execute(
            "SELECT COUNT(*) FROM versions"
        ).fetchone()[0]

        # Contributi con versioni
        contributions = self._conn.execute(
            "SELECT COUNT(DISTINCT contribution_id) FROM versions"
        ).fetchone()[0]

        # Media versioni per contributo
        avg_versions = total / contributions if contributions > 0 else 0

        # Top contributors (per versioni create)
        top_contributors = []
        for row in self._conn.execute(
            """
            SELECT created_by, COUNT(*) as cnt
            FROM versions
            GROUP BY created_by
            ORDER BY cnt DESC
            LIMIT 10
            """
        ):
            top_contributors.append({
                "author_id": row["created_by"],
                "versions_created": row["cnt"],
            })

        return {
            "total_versions": total,
            "contributions_with_versions": contributions,
            "average_versions_per_contribution": round(avg_versions, 2),
            "top_contributors": top_contributors,
        }

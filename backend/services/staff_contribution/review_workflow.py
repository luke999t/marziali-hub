"""
# AI_MODULE: ReviewWorkflow
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Workflow approvazione contributi con assegnazione, commenti, decisioni
# AI_BUSINESS: Gestisce ciclo di vita revisione: submit, assign, review, approve/reject.
#              Supporta commenti inline, richieste modifiche, escalation.
# AI_TEACHING: State machine per transizioni stato, assegnazione automatica/manuale,
#              notifiche (hook), SLA tracking per tempi revisione.
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

ReviewWorkflow Module
=====================

Workflow revisione contributi con:
- Sottomissione per review
- Assegnazione reviewer (auto/manuale)
- Commenti inline durante revisione
- Richiesta modifiche
- Approvazione/rifiuto
- Escalation per timeout
- SLA tracking
"""

import asyncio
import json
import os
import sqlite3
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Awaitable
import logging
import uuid

from .schemas import (
    ContributionStatus,
    ReviewStatus,
    ReviewComment,
    ReviewRequest,
    can_transition,
)

logger = logging.getLogger(__name__)


class ReviewDecision(Enum):
    """Decisioni possibili per una revisione."""
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


class ReviewWorkflow:
    """
    Workflow gestione revisioni.

    Singleton pattern con _reset_for_testing per test isolation.

    Flusso tipico:
    1. Contributor sottomette (submit_for_review)
    2. Sistema assegna reviewer (assign_reviewer)
    3. Reviewer inizia revisione (start_review)
    4. Reviewer aggiunge commenti (add_comment)
    5. Reviewer decide (approve / reject / request_changes)
    """

    _instance: Optional["ReviewWorkflow"] = None
    _lock = asyncio.Lock()

    # SLA defaults
    DEFAULT_SLA_HOURS = {
        "low": 168,  # 7 giorni
        "normal": 72,  # 3 giorni
        "high": 24,  # 1 giorno
        "urgent": 4,  # 4 ore
    }

    # Schema SQL
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS review_requests (
        id TEXT PRIMARY KEY,
        contribution_id TEXT NOT NULL,
        requester_id TEXT NOT NULL,
        assigned_reviewer_id TEXT,
        status TEXT NOT NULL DEFAULT 'pending',
        priority TEXT NOT NULL DEFAULT 'normal',
        due_date TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        completed_at TEXT,
        decision TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_reviews_contribution ON review_requests(contribution_id);
    CREATE INDEX IF NOT EXISTS idx_reviews_reviewer ON review_requests(assigned_reviewer_id);
    CREATE INDEX IF NOT EXISTS idx_reviews_status ON review_requests(status);

    CREATE TABLE IF NOT EXISTS review_comments (
        id TEXT PRIMARY KEY,
        contribution_id TEXT NOT NULL,
        reviewer_id TEXT NOT NULL,
        version_number INTEGER NOT NULL,
        comment TEXT NOT NULL,
        line_reference TEXT,
        status TEXT DEFAULT 'open',
        created_at TEXT NOT NULL,
        resolved_at TEXT,
        resolved_by TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_comments_contribution ON review_comments(contribution_id);
    CREATE INDEX IF NOT EXISTS idx_comments_reviewer ON review_comments(reviewer_id);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inizializza ReviewWorkflow.

        Args:
            db_path: Path database SQLite. Se None, usa default.
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "storage", "staff", "reviews.db")
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

        # Callbacks per notifiche
        self._on_submitted: List[Callable[[str, str], Awaitable[None]]] = []
        self._on_assigned: List[Callable[[str, str, str], Awaitable[None]]] = []
        self._on_decision: List[Callable[[str, str, str], Awaitable[None]]] = []

    @classmethod
    async def get_instance(cls, db_path: Optional[str] = None) -> "ReviewWorkflow":
        """
        Ottiene istanza singleton.

        Args:
            db_path: Path database (solo alla prima chiamata)

        Returns:
            Istanza ReviewWorkflow
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
        logger.info(f"ReviewWorkflow inizializzato: {self._db_path}")

    def _generate_id(self) -> str:
        """Genera ID univoco."""
        return str(uuid.uuid4())

    # ==================== Callbacks ====================

    def on_submitted(
        self,
        callback: Callable[[str, str], Awaitable[None]]
    ) -> None:
        """Registra callback per submit. Args: contribution_id, requester_id"""
        self._on_submitted.append(callback)

    def on_assigned(
        self,
        callback: Callable[[str, str, str], Awaitable[None]]
    ) -> None:
        """Registra callback per assign. Args: contribution_id, reviewer_id, requester_id"""
        self._on_assigned.append(callback)

    def on_decision(
        self,
        callback: Callable[[str, str, str], Awaitable[None]]
    ) -> None:
        """Registra callback per decision. Args: contribution_id, decision, reviewer_id"""
        self._on_decision.append(callback)

    async def _notify_submitted(self, contribution_id: str, requester_id: str) -> None:
        """Notifica submit."""
        for callback in self._on_submitted:
            try:
                await callback(contribution_id, requester_id)
            except Exception as e:
                logger.error(f"Errore callback on_submitted: {e}")

    async def _notify_assigned(
        self,
        contribution_id: str,
        reviewer_id: str,
        requester_id: str
    ) -> None:
        """Notifica assign."""
        for callback in self._on_assigned:
            try:
                await callback(contribution_id, reviewer_id, requester_id)
            except Exception as e:
                logger.error(f"Errore callback on_assigned: {e}")

    async def _notify_decision(
        self,
        contribution_id: str,
        decision: str,
        reviewer_id: str
    ) -> None:
        """Notifica decision."""
        for callback in self._on_decision:
            try:
                await callback(contribution_id, decision, reviewer_id)
            except Exception as e:
                logger.error(f"Errore callback on_decision: {e}")

    # ==================== Review Requests ====================

    async def submit_for_review(
        self,
        contribution_id: str,
        requester_id: str,
        priority: str = "normal",
        notes: Optional[str] = None,
    ) -> ReviewRequest:
        """
        Sottomette contributo per revisione.

        Args:
            contribution_id: ID contributo
            requester_id: ID richiedente
            priority: Priorita (low, normal, high, urgent)
            notes: Note per reviewer

        Returns:
            ReviewRequest creata
        """
        request_id = self._generate_id()
        now = datetime.now()

        # Calcola due date basato su SLA
        sla_hours = self.DEFAULT_SLA_HOURS.get(priority, 72)
        due_date = (now + timedelta(hours=sla_hours)).isoformat()

        request = ReviewRequest(
            id=request_id,
            contribution_id=contribution_id,
            requester_id=requester_id,
            status=ReviewStatus.PENDING.value,
            priority=priority,
            due_date=due_date,
            notes=notes,
            created_at=now.isoformat(),
        )

        self._conn.execute(
            """
            INSERT INTO review_requests
            (id, contribution_id, requester_id, status, priority, due_date, notes, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                request.id, request.contribution_id, request.requester_id,
                request.status, request.priority, request.due_date,
                request.notes, request.created_at,
            )
        )
        self._conn.commit()

        await self._notify_submitted(contribution_id, requester_id)

        logger.info(f"Review richiesta: {contribution_id} da {requester_id}")
        return request

    async def assign_reviewer(
        self,
        contribution_id: str,
        reviewer_id: str,
    ) -> Optional[ReviewRequest]:
        """
        Assegna reviewer a contributo.

        Args:
            contribution_id: ID contributo
            reviewer_id: ID reviewer

        Returns:
            ReviewRequest aggiornata o None
        """
        cursor = self._conn.execute(
            "SELECT * FROM review_requests WHERE contribution_id = ? AND status = ?",
            (contribution_id, ReviewStatus.PENDING.value)
        )
        row = cursor.fetchone()
        if not row:
            return None

        self._conn.execute(
            "UPDATE review_requests SET assigned_reviewer_id = ? WHERE id = ?",
            (reviewer_id, row["id"])
        )
        self._conn.commit()

        await self._notify_assigned(contribution_id, reviewer_id, row["requester_id"])

        return await self.get_request(row["id"])

    async def start_review(
        self,
        contribution_id: str,
        reviewer_id: str,
    ) -> Optional[ReviewRequest]:
        """
        Inizia revisione.

        Args:
            contribution_id: ID contributo
            reviewer_id: ID reviewer

        Returns:
            ReviewRequest aggiornata o None
        """
        now = datetime.now().isoformat()

        self._conn.execute(
            """
            UPDATE review_requests
            SET status = ?, started_at = ?, assigned_reviewer_id = ?
            WHERE contribution_id = ? AND status IN (?, ?)
            """,
            (
                ReviewStatus.IN_PROGRESS.value, now, reviewer_id,
                contribution_id, ReviewStatus.PENDING.value, ReviewStatus.PENDING.value
            )
        )
        self._conn.commit()

        logger.info(f"Review iniziata: {contribution_id} da {reviewer_id}")
        return await self.get_request_by_contribution(contribution_id)

    async def complete_review(
        self,
        contribution_id: str,
        reviewer_id: str,
        decision: ReviewDecision,
        notes: Optional[str] = None,
    ) -> Optional[ReviewRequest]:
        """
        Completa revisione con decisione.

        Args:
            contribution_id: ID contributo
            reviewer_id: ID reviewer
            decision: Decisione (APPROVED, REJECTED, CHANGES_REQUESTED)
            notes: Note sulla decisione

        Returns:
            ReviewRequest aggiornata o None
        """
        now = datetime.now().isoformat()

        # Aggiorna request
        update_notes = notes if notes else ""

        cursor = self._conn.execute(
            """
            UPDATE review_requests
            SET status = ?, completed_at = ?, decision = ?, notes = COALESCE(notes || ' | ', '') || ?
            WHERE contribution_id = ? AND assigned_reviewer_id = ? AND status = ?
            """,
            (
                ReviewStatus.COMPLETED.value, now, decision.value, update_notes,
                contribution_id, reviewer_id, ReviewStatus.IN_PROGRESS.value
            )
        )

        if cursor.rowcount == 0:
            return None

        self._conn.commit()

        await self._notify_decision(contribution_id, decision.value, reviewer_id)

        logger.info(f"Review completata: {contribution_id} -> {decision.value}")
        return await self.get_request_by_contribution(contribution_id)

    async def get_request(self, request_id: str) -> Optional[ReviewRequest]:
        """Ottiene request per ID."""
        cursor = self._conn.execute(
            "SELECT * FROM review_requests WHERE id = ?",
            (request_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_request(row)
        return None

    async def get_request_by_contribution(
        self,
        contribution_id: str,
    ) -> Optional[ReviewRequest]:
        """Ottiene request per contributo (piu' recente)."""
        cursor = self._conn.execute(
            """
            SELECT * FROM review_requests
            WHERE contribution_id = ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (contribution_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_request(row)
        return None

    def _row_to_request(self, row: sqlite3.Row) -> ReviewRequest:
        """Converte row SQLite in ReviewRequest."""
        return ReviewRequest(
            id=row["id"],
            contribution_id=row["contribution_id"],
            requester_id=row["requester_id"],
            assigned_reviewer_id=row["assigned_reviewer_id"],
            status=row["status"],
            priority=row["priority"],
            due_date=row["due_date"],
            notes=row["notes"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            decision=row["decision"],
        )

    async def get_pending_reviews(
        self,
        reviewer_id: Optional[str] = None,
        priority: Optional[str] = None,
        limit: int = 50,
    ) -> List[ReviewRequest]:
        """
        Ottiene review in attesa.

        Args:
            reviewer_id: Filtra per reviewer assegnato
            priority: Filtra per priorita
            limit: Numero massimo

        Returns:
            Lista ReviewRequest
        """
        conditions = ["status IN (?, ?)"]
        params = [ReviewStatus.PENDING.value, ReviewStatus.IN_PROGRESS.value]

        if reviewer_id:
            conditions.append("assigned_reviewer_id = ?")
            params.append(reviewer_id)

        if priority:
            conditions.append("priority = ?")
            params.append(priority)

        where = " AND ".join(conditions)

        cursor = self._conn.execute(
            f"""
            SELECT * FROM review_requests
            WHERE {where}
            ORDER BY
                CASE priority
                    WHEN 'urgent' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'normal' THEN 3
                    WHEN 'low' THEN 4
                END,
                created_at ASC
            LIMIT ?
            """,
            params + [limit]
        )

        return [self._row_to_request(row) for row in cursor.fetchall()]

    async def get_overdue_reviews(self) -> List[ReviewRequest]:
        """Ottiene review scadute."""
        now = datetime.now().isoformat()

        cursor = self._conn.execute(
            """
            SELECT * FROM review_requests
            WHERE status IN (?, ?) AND due_date < ?
            ORDER BY due_date ASC
            """,
            (ReviewStatus.PENDING.value, ReviewStatus.IN_PROGRESS.value, now)
        )

        return [self._row_to_request(row) for row in cursor.fetchall()]

    # ==================== Comments ====================

    async def add_comment(
        self,
        contribution_id: str,
        reviewer_id: str,
        version_number: int,
        comment: str,
        line_reference: Optional[str] = None,
    ) -> ReviewComment:
        """
        Aggiunge commento durante revisione.

        Args:
            contribution_id: ID contributo
            reviewer_id: ID reviewer
            version_number: Numero versione commentata
            comment: Testo commento
            line_reference: Riferimento riga/sezione

        Returns:
            ReviewComment creato
        """
        comment_id = self._generate_id()
        now = datetime.now().isoformat()

        review_comment = ReviewComment(
            id=comment_id,
            contribution_id=contribution_id,
            reviewer_id=reviewer_id,
            version_number=version_number,
            comment=comment,
            line_reference=line_reference,
            status="open",
            created_at=now,
        )

        self._conn.execute(
            """
            INSERT INTO review_comments
            (id, contribution_id, reviewer_id, version_number, comment,
             line_reference, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_comment.id, review_comment.contribution_id,
                review_comment.reviewer_id, review_comment.version_number,
                review_comment.comment, review_comment.line_reference,
                review_comment.status, review_comment.created_at,
            )
        )
        self._conn.commit()

        logger.debug(f"Commento aggiunto: {contribution_id} da {reviewer_id}")
        return review_comment

    async def get_comments(
        self,
        contribution_id: str,
        version_number: Optional[int] = None,
        status: Optional[str] = None,
    ) -> List[ReviewComment]:
        """
        Ottiene commenti per contributo.

        Args:
            contribution_id: ID contributo
            version_number: Filtra per versione
            status: Filtra per stato (open, resolved, wontfix)

        Returns:
            Lista ReviewComment
        """
        conditions = ["contribution_id = ?"]
        params = [contribution_id]

        if version_number:
            conditions.append("version_number = ?")
            params.append(version_number)

        if status:
            conditions.append("status = ?")
            params.append(status)

        where = " AND ".join(conditions)

        cursor = self._conn.execute(
            f"""
            SELECT * FROM review_comments
            WHERE {where}
            ORDER BY created_at ASC
            """,
            params
        )

        return [self._row_to_comment(row) for row in cursor.fetchall()]

    def _row_to_comment(self, row: sqlite3.Row) -> ReviewComment:
        """Converte row SQLite in ReviewComment."""
        return ReviewComment(
            id=row["id"],
            contribution_id=row["contribution_id"],
            reviewer_id=row["reviewer_id"],
            version_number=row["version_number"],
            comment=row["comment"],
            line_reference=row["line_reference"],
            status=row["status"],
            created_at=row["created_at"],
            resolved_at=row["resolved_at"],
            resolved_by=row["resolved_by"],
        )

    async def resolve_comment(
        self,
        comment_id: str,
        resolved_by: str,
        status: str = "resolved",
    ) -> Optional[ReviewComment]:
        """
        Risolve un commento.

        Args:
            comment_id: ID commento
            resolved_by: ID chi risolve
            status: Stato risoluzione (resolved, wontfix)

        Returns:
            ReviewComment aggiornato o None
        """
        now = datetime.now().isoformat()

        self._conn.execute(
            "UPDATE review_comments SET status = ?, resolved_at = ?, resolved_by = ? WHERE id = ?",
            (status, now, resolved_by, comment_id)
        )
        self._conn.commit()

        cursor = self._conn.execute(
            "SELECT * FROM review_comments WHERE id = ?",
            (comment_id,)
        )
        row = cursor.fetchone()
        if row:
            return self._row_to_comment(row)
        return None

    async def get_open_comments_count(self, contribution_id: str) -> int:
        """Conta commenti aperti."""
        cursor = self._conn.execute(
            "SELECT COUNT(*) FROM review_comments WHERE contribution_id = ? AND status = 'open'",
            (contribution_id,)
        )
        return cursor.fetchone()[0]

    # ==================== Stats ====================

    async def get_reviewer_stats(
        self,
        reviewer_id: str,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Ottiene statistiche per reviewer.

        Args:
            reviewer_id: ID reviewer
            start_date: Data inizio
            end_date: Data fine

        Returns:
            Dict con statistiche
        """
        conditions = ["assigned_reviewer_id = ?"]
        params = [reviewer_id]

        if start_date:
            conditions.append("created_at >= ?")
            params.append(start_date.isoformat())

        if end_date:
            conditions.append("created_at <= ?")
            params.append(end_date.isoformat())

        where = " AND ".join(conditions)

        # Conteggi
        total = self._conn.execute(
            f"SELECT COUNT(*) FROM review_requests WHERE {where}",
            params
        ).fetchone()[0]

        completed = self._conn.execute(
            f"SELECT COUNT(*) FROM review_requests WHERE {where} AND status = ?",
            params + [ReviewStatus.COMPLETED.value]
        ).fetchone()[0]

        # Decisioni
        decisions = {}
        for row in self._conn.execute(
            f"""
            SELECT decision, COUNT(*) as cnt
            FROM review_requests
            WHERE {where} AND decision IS NOT NULL
            GROUP BY decision
            """,
            params
        ):
            decisions[row["decision"]] = row["cnt"]

        # Tempo medio revisione
        cursor = self._conn.execute(
            f"""
            SELECT AVG(
                JULIANDAY(completed_at) - JULIANDAY(started_at)
            ) * 24 as avg_hours
            FROM review_requests
            WHERE {where} AND completed_at IS NOT NULL AND started_at IS NOT NULL
            """,
            params
        )
        avg_hours = cursor.fetchone()[0] or 0

        return {
            "reviewer_id": reviewer_id,
            "total_reviews": total,
            "completed_reviews": completed,
            "completion_rate": completed / total if total > 0 else 0,
            "decisions": decisions,
            "average_review_hours": round(avg_hours, 2),
        }

    async def get_workflow_stats(self) -> Dict[str, Any]:
        """Ottiene statistiche workflow generale."""
        # Per stato
        by_status = {}
        for row in self._conn.execute(
            "SELECT status, COUNT(*) as cnt FROM review_requests GROUP BY status"
        ):
            by_status[row["status"]] = row["cnt"]

        # Per priorita
        by_priority = {}
        for row in self._conn.execute(
            "SELECT priority, COUNT(*) as cnt FROM review_requests GROUP BY priority"
        ):
            by_priority[row["priority"]] = row["cnt"]

        # Scadute
        now = datetime.now().isoformat()
        overdue = self._conn.execute(
            """
            SELECT COUNT(*) FROM review_requests
            WHERE status IN (?, ?) AND due_date < ?
            """,
            (ReviewStatus.PENDING.value, ReviewStatus.IN_PROGRESS.value, now)
        ).fetchone()[0]

        return {
            "by_status": by_status,
            "by_priority": by_priority,
            "overdue_count": overdue,
        }

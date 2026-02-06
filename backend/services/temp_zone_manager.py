"""
AI_MODULE: Temp Zone Manager
AI_DESCRIPTION: Gestisce zona temporanea per file sensibili con auto-cleanup configurabile
AI_BUSINESS: Privacy by design - dati sensibili cancellabili su richiesta utente
AI_TEACHING: Scheduled cleanup, retention policies, audit trail, filesystem management

ALTERNATIVE_VALUTATE:
- Cloud storage temporaneo (S3 lifecycle): Scartato, aggiunge complessità e costi
- Database BLOB storage: Scartato, non scala per file grandi (video, PDF)
- Symlinks con cleanup cron: Considerato, ma meno controllo e audit
- Redis TTL per metadati: Considerato, aggiunge dipendenza

PERCHE_QUESTA_SOLUZIONE:
- Filesystem locale: Semplice, veloce, nessuna dipendenza
- Metadata in memoria: Performance, persistenza su disco opzionale
- Audit trail: Traccia chi accede/cancella
- Configurazione runtime: Admin può cambiare policy senza restart

METRICHE_SUCCESSO:
- Cleanup reliability: 100% (no orphan files)
- Audit coverage: 100% operazioni sensibili
- Performance: < 100ms per operazioni CRUD
- Disk recovery: < 5s per scan batch esistenti

PRIVACY_BY_DESIGN:
- File sensibili MAI in backup automatici
- Path randomizzati (UUID)
- Audit log per compliance GDPR
- Cancellazione sicura (overwrite opzionale)

CONFIGURAZIONE:
- Auto-cleanup: ON/OFF (default OFF per sviluppo)
- Retention: 7-90 giorni (configurabile)
- Warning: X giorni prima di cancellazione
- Encrypt at rest: opzionale

INTEGRATION_DEPENDENCIES:
- Upstream: Nessuno (servizio base)
- Downstream: BilingualBookProcessor, MangaProcessor, AudioSystem, tutti i processori
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import shutil
import logging
import asyncio
import json
import hashlib
import os
import uuid


class BatchStatus(str, Enum):
    """
    Stati possibili di un batch temporaneo.

    AI_TEACHING: Usiamo Enum per type safety e autocompletamento IDE.
    Il valore stringa permette serializzazione JSON diretta.
    """
    PROCESSING = "processing"    # Batch in elaborazione
    COMPLETED = "completed"      # Processing completato, pronto per uso
    FAILED = "failed"            # Processing fallito
    EXPIRED = "expired"          # Scaduto (pre-cancellazione)
    ARCHIVED = "archived"        # Spostato in permanent storage


class BatchType(str, Enum):
    """
    Tipi di batch supportati.

    AI_TEACHING: Categorizzazione aiuta filtering e statistiche.
    """
    BILINGUAL_BOOK = "bilingual_book"
    MANGA_PROCESSING = "manga_processing"
    DVD_EXTRACTION = "dvd_extraction"
    AUDIO_PROCESSING = "audio_processing"
    PDF_OCR = "pdf_ocr"
    SKELETON_EXTRACTION = "skeleton_extraction"
    VOICE_CLONE = "voice_clone"
    GENERIC = "generic"


@dataclass
class TempBatch:
    """
    Rappresenta un batch di file temporanei.

    AI_TEACHING: Dataclass per struttura dati immutabile.
    Tutti i campi hanno tipi espliciti per documentazione automatica.

    PRIVACY: 'path' contiene UUID, non nome originale file.
    """
    id: str                      # UUID univoco
    batch_type: BatchType        # Tipo di processing
    created_at: datetime         # Timestamp creazione
    status: BatchStatus          # Stato corrente
    size_bytes: int              # Dimensione totale
    file_count: int              # Numero file nel batch
    path: Path                   # Path filesystem (UUID-based)

    # Metadata flessibile (NO source filenames per privacy)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Tracking
    created_by: str = "system"   # Chi ha creato (user_id o "system")
    updated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Risultati processing (senza source tracking)
    output_summary: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Serializza batch per API response.

        PRIVACY: Non include path completo, solo ID.
        """
        return {
            "id": self.id,
            "batch_type": self.batch_type.value,
            "created_at": self.created_at.isoformat(),
            "status": self.status.value,
            "size_bytes": self.size_bytes,
            "file_count": self.file_count,
            "created_by": self.created_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "output_summary": self.output_summary,
            "error_message": self.error_message,
            # PRIVACY: NO path, NO metadata con source files
        }


@dataclass
class TempZoneConfig:
    """
    Configurazione Temp Zone.

    AI_TEACHING: Dataclass con defaults permette configurazione parziale.
    Ogni campo ha valore ragionevole di default.
    """
    # Cleanup automatico
    auto_cleanup_enabled: bool = False       # Default OFF per sviluppo
    delete_after_days: int = 30              # Giorni prima di cancellazione
    warn_before_days: int = 7                # Warning X giorni prima
    cleanup_check_interval_hours: int = 1    # Frequenza check

    # Percorsi
    temp_base_path: str = "storage/temp"     # Path relativo a root progetto

    # Limiti
    max_batch_size_gb: float = 10.0          # Max dimensione singolo batch
    max_total_size_gb: float = 100.0         # Max dimensione totale temp zone
    max_batches: int = 1000                  # Max numero batch

    # Sicurezza
    allowed_roles: List[str] = field(default_factory=lambda: ["ADMIN", "STAFF"])
    audit_all_access: bool = True            # Log ogni accesso
    secure_delete: bool = False              # Overwrite prima di cancellare

    # Persistenza
    persist_metadata: bool = True            # Salva metadata su disco
    metadata_file: str = "temp_zone_metadata.json"


@dataclass
class AuditEntry:
    """
    Entry per audit log.

    AI_TEACHING: Tracciamo chi, cosa, quando per compliance GDPR.
    """
    timestamp: datetime
    action: str                  # CREATE, DELETE, ACCESS, CONFIG_CHANGE
    target_id: str               # Batch ID o "config"
    user_id: str                 # Chi ha eseguito l'azione
    details: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None


# === UTILITY FUNCTIONS ===

def _format_size(size_bytes: int) -> str:
    """
    Formatta dimensione in formato human-readable.

    AI_TEACHING: Utility standalone per testing e riuso.
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} PB"


class TempZoneManager:
    """
    Manager per Temp Zone - gestione file temporanei sensibili.

    AI_TEACHING: Pattern Singleton per accesso globale.
    Gestisce lifecycle completo: create -> process -> complete/fail -> cleanup.

    WORKFLOW TIPICO:
    1. Processore crea batch con create_batch()
    2. Salva file nella batch.path
    3. Processa file
    4. Chiama complete_batch() o fail_batch()
    5. (Opzionale) Utente scarica risultati
    6. Auto-cleanup dopo X giorni o manuale

    SECURITY:
    - Solo ruoli autorizzati possono accedere
    - Ogni operazione è loggata
    - File sensibili mai in backup standard
    """

    _instance: Optional['TempZoneManager'] = None

    def __new__(cls, config: Optional[TempZoneConfig] = None):
        """Singleton pattern."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config: Optional[TempZoneConfig] = None):
        if self._initialized:
            return

        self.config = config or TempZoneConfig()
        self._batches: Dict[str, TempBatch] = {}
        self._audit_log: List[AuditEntry] = []
        self._cleanup_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

        self.logger = logging.getLogger(__name__)
        self._initialized = True

    @classmethod
    def _reset_for_testing(cls, config: Optional[TempZoneConfig] = None):
        """
        Reset singleton for testing purposes.

        AI_TEACHING: Consente test isolati resettando lo stato globale.
        MAI usare in produzione.
        """
        cls._instance = None
        return cls(config)

    async def start(self):
        """
        Avvia manager e inizializza.

        AI_TEACHING: Separare __init__ da start() permette
        inizializzazione asincrona dopo creazione oggetto.
        """
        self.logger.info("TempZoneManager starting...")

        # Crea directory base se non esiste
        base_path = Path(self.config.temp_base_path)
        base_path.mkdir(parents=True, exist_ok=True)

        # Carica metadata persistiti
        if self.config.persist_metadata:
            await self._load_persisted_metadata()

        # Scan batch esistenti su filesystem
        await self._scan_existing_batches()

        # Avvia scheduler cleanup se abilitato
        if self.config.auto_cleanup_enabled:
            self._cleanup_task = asyncio.create_task(self._cleanup_scheduler())
            self.logger.info(
                f"Auto-cleanup enabled: delete after {self.config.delete_after_days} days"
            )

        self.logger.info(
            f"TempZoneManager started: {len(self._batches)} batches, "
            f"base_path={self.config.temp_base_path}"
        )

    async def stop(self):
        """Ferma manager e cleanup."""
        self.logger.info("TempZoneManager stopping...")

        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Persisti metadata
        if self.config.persist_metadata:
            await self._persist_metadata()

        self.logger.info("TempZoneManager stopped")

    async def create_batch(
        self,
        batch_type: BatchType,
        created_by: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
        retention_days: Optional[int] = None
    ) -> TempBatch:
        """
        Crea nuovo batch in temp zone.

        Args:
            batch_type: Tipo di processing
            created_by: User ID o "system"
            metadata: Metadata opzionali (NO source filenames!)
            retention_days: Override giorni retention (default da config)

        Returns:
            TempBatch con path dove salvare file

        Raises:
            ValueError: Se limiti superati

        AI_TEACHING: Il batch ID è UUID, path contiene solo UUID.
        Nessun riferimento a file originali per privacy.
        """
        async with self._lock:
            # Check limiti
            if len(self._batches) >= self.config.max_batches:
                raise ValueError(
                    f"Max batches limit reached ({self.config.max_batches})"
                )

            total_size = sum(b.size_bytes for b in self._batches.values())
            if total_size >= self.config.max_total_size_gb * (1024**3):
                raise ValueError(
                    f"Max total size limit reached ({self.config.max_total_size_gb} GB)"
                )

            # Genera ID univoco
            batch_id = str(uuid.uuid4())

            # Crea path con timestamp per ordinamento
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
            batch_dir_name = f"{batch_type.value}_{timestamp_str}_{batch_id[:8]}"
            batch_path = Path(self.config.temp_base_path) / batch_dir_name
            batch_path.mkdir(parents=True, exist_ok=True)

            # Calcola expiration
            retention = retention_days or self.config.delete_after_days
            expires_at = datetime.utcnow() + timedelta(days=retention)

            # Crea batch
            now = datetime.utcnow()
            batch = TempBatch(
                id=batch_id,
                batch_type=batch_type,
                created_at=now,
                status=BatchStatus.PROCESSING,
                size_bytes=0,
                file_count=0,
                path=batch_path,
                metadata=metadata or {},
                created_by=created_by,
                updated_at=now,
                expires_at=expires_at
            )

            self._batches[batch_id] = batch

            # Audit
            await self._log_audit(
                action="CREATE",
                target_id=batch_id,
                user_id=created_by,
                details={
                    "batch_type": batch_type.value,
                    "retention_days": retention
                }
            )

            # Persist
            if self.config.persist_metadata:
                await self._persist_metadata()

            self.logger.info(
                f"Created batch {batch_id[:8]} ({batch_type.value}) "
                f"expires {expires_at.strftime('%Y-%m-%d')}"
            )

            return batch

    async def complete_batch(
        self,
        batch_id: str,
        output_summary: Optional[Dict[str, Any]] = None
    ):
        """
        Marca batch come completato.

        AI_TEACHING: Chiamare dopo che processing è finito con successo.
        output_summary può contenere statistiche (NO source filenames).
        """
        async with self._lock:
            if batch_id not in self._batches:
                raise ValueError(f"Batch not found: {batch_id}")

            batch = self._batches[batch_id]
            batch.status = BatchStatus.COMPLETED
            batch.updated_at = datetime.utcnow()

            # Calcola size e file count
            size, count = self._calculate_batch_size(batch.path)
            batch.size_bytes = size
            batch.file_count = count

            if output_summary:
                batch.output_summary = output_summary

            # Audit
            await self._log_audit(
                action="COMPLETE",
                target_id=batch_id,
                user_id="system",
                details={
                    "size_bytes": size,
                    "file_count": count,
                    "output_summary": output_summary
                }
            )

            # Persist
            if self.config.persist_metadata:
                await self._persist_metadata()

            self.logger.info(
                f"Completed batch {batch_id[:8]}: "
                f"{count} files, {self._format_size(size)}"
            )

    async def fail_batch(
        self,
        batch_id: str,
        error_message: str
    ):
        """
        Marca batch come fallito.

        AI_TEACHING: Chiamare se processing fallisce.
        I file rimangono per debug, ma batch è marcato failed.
        """
        async with self._lock:
            if batch_id not in self._batches:
                raise ValueError(f"Batch not found: {batch_id}")

            batch = self._batches[batch_id]
            batch.status = BatchStatus.FAILED
            batch.updated_at = datetime.utcnow()
            batch.error_message = error_message

            # Audit
            await self._log_audit(
                action="FAIL",
                target_id=batch_id,
                user_id="system",
                details={"error": error_message}
            )

            # Persist
            if self.config.persist_metadata:
                await self._persist_metadata()

            self.logger.warning(f"Failed batch {batch_id[:8]}: {error_message}")

    async def delete_batch(
        self,
        batch_id: str,
        deleted_by: str
    ) -> bool:
        """
        Cancella batch e tutti i suoi file.

        SECURITY: Richiede user_id per audit trail.
        Se secure_delete=True, sovrascrive file prima di cancellare.

        Args:
            batch_id: ID batch da cancellare
            deleted_by: User ID che richiede cancellazione

        Returns:
            True se cancellato, False se non trovato
        """
        async with self._lock:
            if batch_id not in self._batches:
                return False

            batch = self._batches[batch_id]

            try:
                # Secure delete se abilitato
                if self.config.secure_delete:
                    await self._secure_delete_directory(batch.path)
                elif batch.path.exists():
                    shutil.rmtree(batch.path)

                del self._batches[batch_id]

                # Audit
                await self._log_audit(
                    action="DELETE",
                    target_id=batch_id,
                    user_id=deleted_by,
                    details={
                        "batch_type": batch.batch_type.value,
                        "size_bytes": batch.size_bytes,
                        "file_count": batch.file_count,
                        "age_days": (datetime.utcnow() - batch.created_at).days
                    }
                )

                # Persist
                if self.config.persist_metadata:
                    await self._persist_metadata()

                self.logger.info(
                    f"Deleted batch {batch_id[:8]} by {deleted_by} "
                    f"({self._format_size(batch.size_bytes)})"
                )

                return True

            except Exception as e:
                self.logger.error(f"Error deleting batch {batch_id}: {e}")
                return False

    async def delete_all_completed(
        self,
        deleted_by: str,
        older_than_days: Optional[int] = None
    ) -> int:
        """
        Cancella tutti i batch completati.

        Args:
            deleted_by: User ID per audit
            older_than_days: Se specificato, solo batch più vecchi di X giorni

        Returns:
            Numero batch cancellati
        """
        cutoff = None
        if older_than_days:
            cutoff = datetime.utcnow() - timedelta(days=older_than_days)

        deleted = 0
        batch_ids = list(self._batches.keys())

        for batch_id in batch_ids:
            batch = self._batches.get(batch_id)
            if not batch:
                continue

            if batch.status != BatchStatus.COMPLETED:
                continue

            if cutoff and batch.created_at > cutoff:
                continue

            if await self.delete_batch(batch_id, deleted_by):
                deleted += 1

        self.logger.info(f"Bulk delete: {deleted} batches by {deleted_by}")
        return deleted

    async def delete_all_failed(
        self,
        deleted_by: str
    ) -> int:
        """Cancella tutti i batch falliti."""
        deleted = 0
        batch_ids = list(self._batches.keys())

        for batch_id in batch_ids:
            batch = self._batches.get(batch_id)
            if batch and batch.status == BatchStatus.FAILED:
                if await self.delete_batch(batch_id, deleted_by):
                    deleted += 1

        return deleted

    async def get_batch(self, batch_id: str) -> Optional[TempBatch]:
        """Recupera batch per ID."""
        return self._batches.get(batch_id)

    async def get_batch_path(self, batch_id: str) -> Optional[Path]:
        """
        Recupera path batch per accesso file.

        AI_TEACHING: Separato da get_batch per chiarezza.
        Usato dai processori per accedere ai file.
        """
        batch = self._batches.get(batch_id)
        if batch:
            return batch.path
        return None

    async def list_batches(
        self,
        status: Optional[BatchStatus] = None,
        batch_type: Optional[BatchType] = None,
        created_by: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[TempBatch]:
        """
        Lista batch con filtri.

        Args:
            status: Filtra per status
            batch_type: Filtra per tipo
            created_by: Filtra per creatore
            limit: Max risultati
            offset: Offset paginazione

        Returns:
            Lista batch ordinati per created_at DESC
        """
        batches = list(self._batches.values())

        # Applica filtri
        if status:
            batches = [b for b in batches if b.status == status]
        if batch_type:
            batches = [b for b in batches if b.batch_type == batch_type]
        if created_by:
            batches = [b for b in batches if b.created_by == created_by]

        # Ordina per data DESC
        batches.sort(key=lambda b: b.created_at, reverse=True)

        # Paginazione
        return batches[offset:offset + limit]

    async def get_stats(self) -> Dict[str, Any]:
        """
        Statistiche complete temp zone.

        Returns:
            Dict con statistiche aggregate
        """
        batches = list(self._batches.values())

        total_size = sum(b.size_bytes for b in batches)
        total_files = sum(b.file_count for b in batches)

        # Oldest batch
        oldest_days = 0
        if batches:
            oldest = min(batches, key=lambda b: b.created_at)
            oldest_days = (datetime.utcnow() - oldest.created_at).days

        # By status
        by_status = {}
        for status in BatchStatus:
            count = sum(1 for b in batches if b.status == status)
            if count > 0:
                by_status[status.value] = count

        # By type
        by_type = {}
        for btype in BatchType:
            count = sum(1 for b in batches if b.batch_type == btype)
            if count > 0:
                by_type[btype.value] = count

        # Expiring soon (within warn days)
        warn_cutoff = datetime.utcnow() + timedelta(days=self.config.warn_before_days)
        expiring_soon = sum(
            1 for b in batches
            if b.expires_at and b.expires_at < warn_cutoff and b.status == BatchStatus.COMPLETED
        )

        return {
            "total_batches": len(batches),
            "total_size_bytes": total_size,
            "total_size_formatted": self._format_size(total_size),
            "total_files": total_files,
            "oldest_batch_days": oldest_days,
            "expiring_soon": expiring_soon,
            "by_status": by_status,
            "by_type": by_type,
            "config": {
                "auto_cleanup_enabled": self.config.auto_cleanup_enabled,
                "delete_after_days": self.config.delete_after_days,
                "max_total_size_gb": self.config.max_total_size_gb,
            },
            "limits": {
                "size_used_percent": round(
                    total_size / (self.config.max_total_size_gb * 1024**3) * 100, 1
                ),
                "batches_used_percent": round(
                    len(batches) / self.config.max_batches * 100, 1
                ),
            }
        }

    async def get_expiring_batches(self) -> List[TempBatch]:
        """Recupera batch in scadenza (entro warn_before_days)."""
        warn_cutoff = datetime.utcnow() + timedelta(days=self.config.warn_before_days)

        return [
            b for b in self._batches.values()
            if b.expires_at and b.expires_at < warn_cutoff
            and b.status == BatchStatus.COMPLETED
        ]

    async def update_config(
        self,
        updated_by: str,
        auto_cleanup_enabled: Optional[bool] = None,
        delete_after_days: Optional[int] = None,
        warn_before_days: Optional[int] = None,
        secure_delete: Optional[bool] = None
    ) -> TempZoneConfig:
        """
        Aggiorna configurazione runtime.

        SECURITY: Solo admin dovrebbe chiamare questo.
        Tutte le modifiche sono loggate.
        """
        changes = {}

        if auto_cleanup_enabled is not None:
            changes["auto_cleanup_enabled"] = {
                "old": self.config.auto_cleanup_enabled,
                "new": auto_cleanup_enabled
            }
            self.config.auto_cleanup_enabled = auto_cleanup_enabled

        if delete_after_days is not None:
            if delete_after_days < 1 or delete_after_days > 365:
                raise ValueError("delete_after_days must be 1-365")
            changes["delete_after_days"] = {
                "old": self.config.delete_after_days,
                "new": delete_after_days
            }
            self.config.delete_after_days = delete_after_days

        if warn_before_days is not None:
            if warn_before_days < 1 or warn_before_days > 30:
                raise ValueError("warn_before_days must be 1-30")
            changes["warn_before_days"] = {
                "old": self.config.warn_before_days,
                "new": warn_before_days
            }
            self.config.warn_before_days = warn_before_days

        if secure_delete is not None:
            changes["secure_delete"] = {
                "old": self.config.secure_delete,
                "new": secure_delete
            }
            self.config.secure_delete = secure_delete

        if changes:
            # Audit
            await self._log_audit(
                action="CONFIG_CHANGE",
                target_id="config",
                user_id=updated_by,
                details=changes
            )

            self.logger.info(f"Config updated by {updated_by}: {changes}")

        # Restart cleanup scheduler se necessario
        if "auto_cleanup_enabled" in changes:
            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass

            if self.config.auto_cleanup_enabled:
                self._cleanup_task = asyncio.create_task(self._cleanup_scheduler())

        return self.config

    async def get_audit_log(
        self,
        limit: int = 100,
        action: Optional[str] = None,
        target_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Recupera audit log.

        SECURITY: Solo admin dovrebbe accedere.
        """
        logs = self._audit_log

        if action:
            logs = [l for l in logs if l.action == action]
        if target_id:
            logs = [l for l in logs if l.target_id == target_id]

        # Sort by timestamp DESC
        logs = sorted(logs, key=lambda l: l.timestamp, reverse=True)

        return [
            {
                "timestamp": l.timestamp.isoformat(),
                "action": l.action,
                "target_id": l.target_id,
                "user_id": l.user_id,
                "details": l.details,
            }
            for l in logs[:limit]
        ]

    # === PRIVATE METHODS ===

    async def _cleanup_scheduler(self):
        """
        Scheduler per auto-cleanup.

        AI_TEACHING: Esegue in background, controlla periodicamente
        batch scaduti e li cancella.
        """
        interval_seconds = self.config.cleanup_check_interval_hours * 3600

        while True:
            try:
                await asyncio.sleep(interval_seconds)
                await self._run_cleanup()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup scheduler error: {e}")

    async def _run_cleanup(self):
        """Esegue cleanup batch scaduti."""
        if not self.config.auto_cleanup_enabled:
            return

        now = datetime.utcnow()
        deleted_count = 0

        batch_ids = list(self._batches.keys())

        for batch_id in batch_ids:
            batch = self._batches.get(batch_id)
            if not batch:
                continue

            # Solo batch completati
            if batch.status != BatchStatus.COMPLETED:
                continue

            # Check expiration
            if batch.expires_at and batch.expires_at < now:
                if await self.delete_batch(batch_id, "auto_cleanup"):
                    deleted_count += 1

        if deleted_count > 0:
            self.logger.info(f"Auto-cleanup: deleted {deleted_count} expired batches")

    async def _scan_existing_batches(self):
        """
        Scan filesystem per batch esistenti non in memoria.

        AI_TEACHING: Chiamato all'avvio per recovery dopo restart.
        """
        base_path = Path(self.config.temp_base_path)
        if not base_path.exists():
            return

        discovered = 0

        for item in base_path.iterdir():
            if not item.is_dir():
                continue

            # Check se già conosciuto
            batch_id_from_name = None
            for bid, batch in self._batches.items():
                if batch.path == item:
                    batch_id_from_name = bid
                    break

            if batch_id_from_name:
                continue

            # Batch sconosciuto - ricostruisci
            try:
                # Parse batch type from dir name
                dir_name = item.name
                parts = dir_name.split("_")

                batch_type = BatchType.GENERIC
                for btype in BatchType:
                    if dir_name.startswith(btype.value):
                        batch_type = btype
                        break

                # Calcola size
                size, count = self._calculate_batch_size(item)

                # Genera nuovo ID
                batch_id = str(uuid.uuid4())

                batch = TempBatch(
                    id=batch_id,
                    batch_type=batch_type,
                    created_at=datetime.fromtimestamp(item.stat().st_ctime),
                    status=BatchStatus.COMPLETED,  # Assume completed se su disco
                    size_bytes=size,
                    file_count=count,
                    path=item,
                    created_by="recovered",
                    updated_at=datetime.utcnow(),
                    expires_at=datetime.utcnow() + timedelta(days=self.config.delete_after_days)
                )

                self._batches[batch_id] = batch
                discovered += 1

            except Exception as e:
                self.logger.warning(f"Error recovering batch from {item}: {e}")

        if discovered > 0:
            self.logger.info(f"Discovered {discovered} existing batches on filesystem")

    async def _log_audit(
        self,
        action: str,
        target_id: str,
        user_id: str,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None
    ):
        """Log entry per audit."""
        entry = AuditEntry(
            timestamp=datetime.utcnow(),
            action=action,
            target_id=target_id,
            user_id=user_id,
            details=details or {},
            ip_address=ip_address
        )

        self._audit_log.append(entry)

        # Trim log se troppo lungo
        max_entries = 10000
        if len(self._audit_log) > max_entries:
            self._audit_log = self._audit_log[-max_entries:]

        if self.config.audit_all_access:
            self.logger.debug(f"AUDIT: {action} {target_id} by {user_id}")

    async def _persist_metadata(self):
        """Salva metadata su disco per recovery."""
        metadata_path = Path(self.config.temp_base_path) / self.config.metadata_file

        data = {
            "batches": {
                bid: {
                    "id": batch.id,
                    "batch_type": batch.batch_type.value,
                    "created_at": batch.created_at.isoformat(),
                    "status": batch.status.value,
                    "size_bytes": batch.size_bytes,
                    "file_count": batch.file_count,
                    "path": str(batch.path),
                    "created_by": batch.created_by,
                    "updated_at": batch.updated_at.isoformat() if batch.updated_at else None,
                    "expires_at": batch.expires_at.isoformat() if batch.expires_at else None,
                    "metadata": batch.metadata,
                    "output_summary": batch.output_summary,
                    "error_message": batch.error_message,
                }
                for bid, batch in self._batches.items()
            },
            "config": {
                "auto_cleanup_enabled": self.config.auto_cleanup_enabled,
                "delete_after_days": self.config.delete_after_days,
                "warn_before_days": self.config.warn_before_days,
                "secure_delete": self.config.secure_delete,
            },
            "saved_at": datetime.utcnow().isoformat()
        }

        try:
            with open(metadata_path, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error persisting metadata: {e}")

    async def _load_persisted_metadata(self):
        """Carica metadata da disco."""
        metadata_path = Path(self.config.temp_base_path) / self.config.metadata_file

        if not metadata_path.exists():
            return

        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)

            # Ricostruisci batches
            for bid, bdata in data.get("batches", {}).items():
                batch_path = Path(bdata["path"])

                # Skip se path non esiste più
                if not batch_path.exists():
                    continue

                batch = TempBatch(
                    id=bdata["id"],
                    batch_type=BatchType(bdata["batch_type"]),
                    created_at=datetime.fromisoformat(bdata["created_at"]),
                    status=BatchStatus(bdata["status"]),
                    size_bytes=bdata["size_bytes"],
                    file_count=bdata["file_count"],
                    path=batch_path,
                    created_by=bdata["created_by"],
                    updated_at=datetime.fromisoformat(bdata["updated_at"]) if bdata.get("updated_at") else None,
                    expires_at=datetime.fromisoformat(bdata["expires_at"]) if bdata.get("expires_at") else None,
                    metadata=bdata.get("metadata", {}),
                    output_summary=bdata.get("output_summary", {}),
                    error_message=bdata.get("error_message"),
                )

                self._batches[bid] = batch

            # Ripristina config se presente
            saved_config = data.get("config", {})
            if saved_config:
                self.config.auto_cleanup_enabled = saved_config.get(
                    "auto_cleanup_enabled", self.config.auto_cleanup_enabled
                )
                self.config.delete_after_days = saved_config.get(
                    "delete_after_days", self.config.delete_after_days
                )

            self.logger.info(f"Loaded {len(self._batches)} batches from persisted metadata")

        except Exception as e:
            self.logger.error(f"Error loading persisted metadata: {e}")

    async def _secure_delete_directory(self, path: Path):
        """
        Cancellazione sicura: sovrascrive file prima di cancellare.

        AI_TEACHING: Per dati sensibili, semplice rm non basta.
        Sovrascriviamo con dati random prima di cancellare.
        """
        if not path.exists():
            return

        for file_path in path.rglob("*"):
            if file_path.is_file():
                try:
                    # Overwrite con random bytes
                    file_size = file_path.stat().st_size
                    with open(file_path, 'wb') as f:
                        f.write(os.urandom(file_size))

                    # Poi cancella
                    file_path.unlink()
                except Exception as e:
                    self.logger.warning(f"Secure delete error for {file_path}: {e}")

        # Rimuovi directory
        shutil.rmtree(path, ignore_errors=True)

    def _calculate_batch_size(self, path: Path) -> tuple:
        """Calcola dimensione e numero file."""
        total_size = 0
        file_count = 0

        if not path.exists():
            return 0, 0

        for item in path.rglob("*"):
            if item.is_file():
                try:
                    total_size += item.stat().st_size
                    file_count += 1
                except OSError:
                    pass

        return total_size, file_count

    def _format_size(self, size_bytes: int) -> str:
        """Formatta size in human readable."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"


# === SINGLETON ACCESSOR ===

_temp_zone_manager: Optional[TempZoneManager] = None


async def get_temp_zone_manager(
    config: Optional[TempZoneConfig] = None
) -> TempZoneManager:
    """
    Get singleton TempZoneManager instance.

    AI_TEACHING: Pattern comune per servizi singleton asincroni.
    Primo chiamante può passare config, chiamate successive la ignorano.
    """
    global _temp_zone_manager

    if _temp_zone_manager is None:
        _temp_zone_manager = TempZoneManager(config)
        await _temp_zone_manager.start()

    return _temp_zone_manager


async def shutdown_temp_zone_manager():
    """Shutdown singleton for clean exit."""
    global _temp_zone_manager

    if _temp_zone_manager is not None:
        await _temp_zone_manager.stop()
        _temp_zone_manager = None


# === FACTORY PER TESTING ===

def create_temp_zone_manager(
    config: Optional[TempZoneConfig] = None
) -> TempZoneManager:
    """
    Factory per creare nuova istanza (NON singleton).

    AI_TEACHING: Usare per testing, dove ogni test vuole
    istanza pulita. Singleton per produzione.
    """
    # Reset singleton per testing
    TempZoneManager._instance = None
    return TempZoneManager(config)

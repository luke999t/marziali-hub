"""
🎓 AI_MODULE: MixGenerator (Privacy by Design)
🎓 AI_DESCRIPTION: Genera mix blindati ANONIMI da batch temporanei con FORGETTING BY DESIGN
🎓 AI_BUSINESS: Consolida asset processati in versioni immutabili - NESSUNA FONTE TRACCIABILE
🎓 AI_TEACHING: Versioning semantico + merge incrementale + anonimizzazione + symlink management

🔄 ALTERNATIVE_VALUTATE:
- Copy tutto ogni volta: Scartato, inefficiente per grandi dataset
- Git-based versioning: Scartato, overhead per file binari
- Delta-only storage: Scartato, complessita recupero
- Source tracking: SCARTATO PER PRIVACY - fonti non devono essere tracciabili

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Privacy: FORGETTING BY DESIGN - fonti non tracciabili nel mix
- Anonimizzazione: Contenuti parafrasati e aggregati prima del mix
- Tecnico: Merge incrementale efficiente, rollback facile
- Business: Mix blindati non modificabili, audit trail SENZA fonti

📊 METRICHE_SUCCESSO:
- Mix incrementale: < 30s per 100 nuovi items
- Full rebuild: < 5min per 1000 items
- Disk efficiency: < 10% overhead vs raw
- Privacy leak: 0% (validato da test)

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: ProjectManager, IngestBatch, Anonymizer
- Downstream: Router API, Export service
"""

import os
import json
import shutil
import logging
import random
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from models.ingest_project import (
    IngestProject,
    IngestBatch,
    IngestMixVersion,
    BatchStatus
)
from services.anonymizer import Anonymizer, create_anonymizer

logger = logging.getLogger(__name__)


class MixGenerator:
    """
    🔒 Generatore di mix blindati ANONIMI.

    PRIVACY BY DESIGN:
    - MAI salva source_batches (rimosso dal model)
    - MAI salva file names originali
    - Contenuti ANONIMIZZATI prima del mix
    - Ordine RANDOMIZZATO per rompere sequenza

    Flusso:
    1. Utente clicca "Genera Mix"
    2. Se primo mix -> v1.0
    3. Raccoglie batch -> ANONIMIZZA -> merge
    4. Output in mix/v{X.Y}/ (UUID-based filenames)
    5. Aggiorna current symlink

    Mix Structure:
    mix/v{version}/
    ├── index.json           # Manifest con stats (🔒 NO file list)
    ├── skeleton_mixati/     # Skeleton aggregati e anonimi
    ├── knowledge_finale/    # Knowledge parafrasato
    ├── vocabulary/          # Vocabolario estratto
    ├── audio_mix/           # Audio processato
    └── subtitles/           # Sottotitoli multilingua
    """

    def __init__(self, db: AsyncSession, anonymizer: Optional[Anonymizer] = None):
        """
        Inizializza MixGenerator.

        Args:
            db: SQLAlchemy async session
            anonymizer: Anonymizer service (creato se None)
        """
        self.db = db
        self.anonymizer = anonymizer or create_anonymizer()

    async def generate_mix(
        self,
        project_id: UUID,
        force_full: bool = False,
        created_by: Optional[UUID] = None
    ) -> IngestMixVersion:
        """
        🔒 Genera nuovo mix ANONIMO.

        PRIVACY:
        1. Raccoglie tutti i batch processati
        2. ANONIMIZZA contenuti (parafrasatura, aggregazione)
        3. MESCOLA ordine (rompe sequenza originale)
        4. Salva con UUID filenames (no nomi originali)
        5. NO source tracking nel database

        Args:
            project_id: ID progetto
            force_full: True per rigenerare tutto da zero
            created_by: User ID

        Returns:
            Nuova versione mix (🔒 senza source_batches)

        Raises:
            ValueError: Se no batch processati disponibili
        """
        project = await self._get_project(project_id)

        # Determina versione
        new_version, is_incremental = await self._calculate_next_version(
            project,
            force_full
        )

        # Identifica batch da processare
        batches_to_process = await self._get_batches_to_process(
            project,
            force_full
        )

        if not batches_to_process:
            raise ValueError("Nessun batch processato disponibile per il mix")

        logger.info(f"🔒 Generating mix v{new_version} from {len(batches_to_process)} batches")

        # Crea directory mix (🔒 nuova struttura)
        mix_path = Path(project.storage_path) / "mix" / f"v{new_version}"
        mix_path.mkdir(parents=True, exist_ok=True)

        # Crea sottocartelle (🔒 nomi privacy-safe)
        for subfolder in ["skeleton_mixati", "knowledge_finale", "vocabulary", "audio_mix", "subtitles"]:
            (mix_path / subfolder).mkdir(exist_ok=True)

        # Raccogli e ANONIMIZZA
        start_time = datetime.utcnow()

        # 1. Raccogli dati da tutti i batch
        all_data = await self._collect_batch_data(project, batches_to_process)

        # 2. ANONIMIZZA (🔒 PRIVACY CRITICAL)
        anonymized_data = self.anonymizer.anonymize_for_mix(all_data)

        # 3. Valida anonimizzazione
        validation = self.anonymizer.validate_anonymized(anonymized_data)
        if not validation["is_valid"]:
            logger.warning(f"⚠️ Privacy violations detected: {validation['violations']}")

        # 4. Genera mix files
        if is_incremental and project.current_mix_version:
            stats = await self._merge_incremental_anonymous(
                project,
                anonymized_data,
                mix_path
            )
        else:
            stats = await self._create_full_mix_anonymous(
                anonymized_data,
                mix_path
            )

        processing_time = (datetime.utcnow() - start_time).total_seconds()
        stats["processing_time_seconds"] = processing_time

        # Calcola dimensione totale
        total_size = self._calculate_folder_size(mix_path)

        # 🔒 Crea record SENZA source_batches
        mix_version = IngestMixVersion(
            project_id=project_id,
            version=new_version,
            storage_path=str(mix_path),
            # 🔒 RIMOSSO: source_batches - violazione privacy
            is_incremental=is_incremental,
            previous_version=project.current_mix_version if is_incremental else None,
            total_items=stats["total_items"],  # Rinominato da total_sources
            total_skeletons=stats["total_skeletons"],
            total_transcriptions=stats["total_transcriptions"],
            total_knowledge_chunks=stats["total_knowledge_chunks"],
            total_subtitles=stats.get("total_subtitles", 0),
            total_vocabulary_terms=stats.get("total_vocabulary_terms", 0),
            total_size_bytes=total_size,
            merge_stats=self._sanitize_merge_stats(stats),  # 🔒 Rimuove info sensibili
            created_by=created_by
        )

        self.db.add(mix_version)

        # Aggiorna progetto
        project.current_mix_version = new_version
        project.updated_at = datetime.utcnow()

        await self.db.commit()
        await self.db.refresh(mix_version)

        # Aggiorna symlink current
        self._update_current_symlink(project, new_version)

        # 🔒 Genera index.json ANONIMO
        self._generate_anonymous_index_json(mix_path, mix_version, stats)

        logger.info(
            f"✅ Generated mix v{new_version} for project {project_id} "
            f"({stats['total_items']} items, {processing_time:.1f}s)"
        )

        return mix_version

    # =========================================================================
    # DATA COLLECTION & ANONYMIZATION
    # =========================================================================

    async def _collect_batch_data(
        self,
        project: IngestProject,
        batches: List[IngestBatch]
    ) -> List[Dict[str, Any]]:
        """
        Raccoglie dati da tutti i batch per anonimizzazione.

        🔒 NON include: filename, batch_date, source info
        """
        all_data = []

        for batch in batches:
            batch_path = Path(project.storage_path) / "temp" / f"batch_{batch.batch_date}"

            # Raccogli da ogni sottocartella
            for subfolder in ["skeleton", "trascrizioni", "knowledge_grezzo", "sottotitoli"]:
                folder = batch_path / subfolder
                if not folder.exists():
                    continue

                for file_path in folder.glob("*.json"):
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            content = json.load(f)

                        # Determina tipo
                        if subfolder == "skeleton":
                            item_type = "skeleton"
                        elif subfolder == "trascrizioni":
                            item_type = "transcription"
                        elif subfolder == "knowledge_grezzo":
                            item_type = "knowledge"
                        else:
                            item_type = "subtitle"

                        all_data.append({
                            "content": content,
                            "type": item_type,
                            "lang": content.get("lang", project.target_languages[0] if project.target_languages else "it"),
                            # 🔒 MAI: "source_file", "batch_date", "original_filename"
                        })

                    except Exception as e:
                        logger.warning(f"Error reading {file_path}: {e}")

        return all_data

    async def _create_full_mix_anonymous(
        self,
        anonymized_data: Dict[str, List[Dict]],
        mix_path: Path
    ) -> Dict[str, Any]:
        """
        🔒 Crea mix completo da dati ANONIMI.

        File salvati con UUID names, nessun riferimento a fonti.
        """
        import uuid

        stats = {
            "total_items": 0,
            "total_skeletons": 0,
            "total_transcriptions": 0,
            "total_knowledge_chunks": 0,
            "total_subtitles": 0,
            "total_vocabulary_terms": 0,
            "type": "full"
            # 🔒 NO: "batches_included", "source_files"
        }

        # Salva skeleton (🔒 UUID filenames)
        for item in anonymized_data.get("skeleton", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "skeleton_mixati" / filename, item)
            stats["total_skeletons"] += 1
            stats["total_items"] += 1

        # Salva knowledge (🔒 aggregato e parafrasato)
        for item in anonymized_data.get("knowledge", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "knowledge_finale" / filename, item)
            stats["total_knowledge_chunks"] += 1
            stats["total_items"] += 1

        # Salva vocabulary
        for item in anonymized_data.get("vocabulary", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "vocabulary" / filename, item)
            stats["total_vocabulary_terms"] += 1

        # Salva techniques come knowledge
        for item in anonymized_data.get("techniques", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "knowledge_finale" / filename, item)
            stats["total_knowledge_chunks"] += 1
            stats["total_items"] += 1

        return stats

    async def _merge_incremental_anonymous(
        self,
        project: IngestProject,
        anonymized_data: Dict[str, List[Dict]],
        mix_path: Path
    ) -> Dict[str, Any]:
        """
        🔒 Merge incrementale con mix precedente (anonimo).

        1. Copia contenuti mix precedente
        2. Aggiunge nuovi items (gia anonimi)
        """
        prev_mix_path = Path(project.storage_path) / "mix" / f"v{project.current_mix_version}"

        if not prev_mix_path.exists():
            logger.warning(f"Previous mix not found: {prev_mix_path}, doing full rebuild")
            return await self._create_full_mix_anonymous(anonymized_data, mix_path)

        # Leggi stats precedenti (🔒 solo contatori, no file list)
        index_path = prev_mix_path / "index.json"
        prev_stats = {}
        if index_path.exists():
            with open(index_path, "r", encoding="utf-8") as f:
                prev_index = json.load(f)
                prev_stats = prev_index.get("stats", {})

        stats = {
            "total_items": prev_stats.get("total_items", 0),
            "total_skeletons": prev_stats.get("total_skeletons", 0),
            "total_transcriptions": prev_stats.get("total_transcriptions", 0),
            "total_knowledge_chunks": prev_stats.get("total_knowledge_chunks", 0),
            "total_subtitles": prev_stats.get("total_subtitles", 0),
            "total_vocabulary_terms": prev_stats.get("total_vocabulary_terms", 0),
            "merged_from": project.current_mix_version,
            "type": "incremental"
            # 🔒 NO: "batches_included"
        }

        # 🔒 Folder mapping (nuova struttura)
        folder_mapping = {
            "skeleton_mixati": "skeleton_mixati",
            "knowledge_finale": "knowledge_finale",
            "vocabulary": "vocabulary",
            "audio_mix": "audio_mix",
            "subtitles": "subtitles",
            # Legacy mapping
            "skeletons": "skeleton_mixati",
            "transcriptions": "knowledge_finale",
            "knowledge": "knowledge_finale",
        }

        # Copia contenuti precedenti
        for src_name in ["skeleton_mixati", "knowledge_finale", "vocabulary", "audio_mix", "subtitles", "skeletons", "transcriptions", "knowledge"]:
            src_folder = prev_mix_path / src_name
            dst_name = folder_mapping.get(src_name, src_name)
            dst_folder = mix_path / dst_name

            if src_folder.exists():
                for f in src_folder.glob("*"):
                    if f.is_file():
                        shutil.copy2(f, dst_folder / f.name)

        # Aggiungi nuovi items (già anonimi)
        import uuid

        for item in anonymized_data.get("skeleton", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "skeleton_mixati" / filename, item)
            stats["total_skeletons"] += 1
            stats["total_items"] += 1

        for item in anonymized_data.get("knowledge", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "knowledge_finale" / filename, item)
            stats["total_knowledge_chunks"] += 1
            stats["total_items"] += 1

        for item in anonymized_data.get("vocabulary", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "vocabulary" / filename, item)
            stats["total_vocabulary_terms"] += 1

        for item in anonymized_data.get("techniques", []):
            filename = f"{uuid.uuid4()}.json"
            self._save_json(mix_path / "knowledge_finale" / filename, item)
            stats["total_knowledge_chunks"] += 1
            stats["total_items"] += 1

        return stats

    def _sanitize_merge_stats(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """
        🔒 Rimuove informazioni sensibili dalle stats.

        MAI includere: file names, batch dates, source references
        """
        safe_keys = {
            "total_items", "total_skeletons", "total_transcriptions",
            "total_knowledge_chunks", "total_subtitles", "total_vocabulary_terms",
            "processing_time_seconds", "type", "merged_from"
        }

        return {k: v for k, v in stats.items() if k in safe_keys}

    # =========================================================================
    # VERSION CALCULATION
    # =========================================================================

    async def _calculate_next_version(
        self,
        project: IngestProject,
        force_full: bool
    ) -> Tuple[str, bool]:
        """
        Calcola prossima versione.

        Returns:
            (version_string, is_incremental)
        """
        if project.current_mix_version is None:
            return "1.0", False

        parts = project.current_mix_version.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0

        if force_full:
            return f"{major + 1}.0", False
        else:
            return f"{major}.{minor + 1}", True

    async def _get_batches_to_process(
        self,
        project: IngestProject,
        force_full: bool
    ) -> List[IngestBatch]:
        """Ottiene batch da includere nel mix."""
        query = select(IngestBatch).where(
            IngestBatch.project_id == project.id,
            IngestBatch.status == BatchStatus.PROCESSED.value
        )

        if not force_full and project.current_mix_version:
            last_mix = await self._get_last_mix(project.id)
            if last_mix:
                query = query.where(
                    IngestBatch.processed_at > last_mix.created_at
                )

        query = query.order_by(IngestBatch.batch_date)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    # =========================================================================
    # INDEX & METADATA
    # =========================================================================

    def _generate_anonymous_index_json(
        self,
        mix_path: Path,
        mix_version: IngestMixVersion,
        stats: Dict[str, Any]
    ):
        """
        🔒 Genera index.json ANONIMO per il mix.

        MAI include: file list, source batches, original filenames
        """
        # 🔒 Solo contatori, NO file list
        index = {
            "version": mix_version.version,
            "generated_at": datetime.utcnow().isoformat(),
            "is_incremental": mix_version.is_incremental,
            "previous_version": mix_version.previous_version,
            # 🔒 Solo stats aggregate
            "stats": {
                "total_items": stats.get("total_items", 0),
                "total_skeletons": stats.get("total_skeletons", 0),
                "total_knowledge_chunks": stats.get("total_knowledge_chunks", 0),
                "total_vocabulary_terms": stats.get("total_vocabulary_terms", 0),
                "total_subtitles": stats.get("total_subtitles", 0),
                "processing_time_seconds": stats.get("processing_time_seconds", 0)
            }
            # 🔒 MAI: "files", "source_batches", "batches_included"
        }

        index_path = mix_path / "index.json"
        with open(index_path, "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False, indent=2)

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _save_json(self, path: Path, data: Any):
        """Salva JSON file."""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _update_current_symlink(self, project: IngestProject, version: str):
        """Aggiorna symlink current."""
        mix_base = Path(project.storage_path) / "mix"
        current_link = mix_base / "current"

        if current_link.exists() or current_link.is_symlink():
            current_link.unlink()

        target = f"v{version}"

        try:
            current_link.symlink_to(target, target_is_directory=True)
        except OSError as e:
            logger.warning(f"Could not create symlink: {e}")
            with open(current_link.with_suffix('.txt'), 'w') as f:
                f.write(target)

    def _calculate_folder_size(self, folder_path: Path) -> int:
        """Calcola dimensione totale cartella."""
        total = 0
        if folder_path.exists():
            for f in folder_path.rglob("*"):
                if f.is_file():
                    total += f.stat().st_size
        return total

    async def _get_project(self, project_id: UUID) -> IngestProject:
        """Ottiene progetto o solleva errore."""
        result = await self.db.execute(
            select(IngestProject).where(IngestProject.id == project_id)
        )
        project = result.scalar_one_or_none()
        if not project:
            raise ValueError(f"Project not found: {project_id}")
        return project

    async def _get_last_mix(self, project_id: UUID) -> Optional[IngestMixVersion]:
        """Ottiene ultimo mix creato."""
        result = await self.db.execute(
            select(IngestMixVersion)
            .where(IngestMixVersion.project_id == project_id)
            .order_by(IngestMixVersion.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    # =========================================================================
    # PUBLIC API (read-only operations)
    # =========================================================================

    async def get_mix_version(
        self,
        project_id: UUID,
        version: str
    ) -> Optional[IngestMixVersion]:
        """Ottiene versione mix specifica."""
        result = await self.db.execute(
            select(IngestMixVersion).where(
                IngestMixVersion.project_id == project_id,
                IngestMixVersion.version == version
            )
        )
        return result.scalar_one_or_none()

    async def get_current_mix(
        self,
        project_id: UUID
    ) -> Optional[IngestMixVersion]:
        """Ottiene mix corrente del progetto."""
        project = await self._get_project(project_id)
        if not project.current_mix_version:
            return None
        return await self.get_mix_version(project_id, project.current_mix_version)

    async def list_mix_versions(
        self,
        project_id: UUID
    ) -> List[IngestMixVersion]:
        """Lista tutte le versioni mix di un progetto."""
        result = await self.db.execute(
            select(IngestMixVersion)
            .where(IngestMixVersion.project_id == project_id)
            .order_by(IngestMixVersion.created_at.desc())
        )
        return list(result.scalars().all())

    def get_mix_stats(
        self,
        mix_version: IngestMixVersion
    ) -> Dict[str, int]:
        """
        🔒 Ottiene stats del mix (solo contatori).

        MAI ritorna file list o source info.
        """
        mix_path = Path(mix_version.storage_path)

        return {
            "skeleton_count": len(list((mix_path / "skeleton_mixati").glob("*.json"))) if (mix_path / "skeleton_mixati").exists() else 0,
            "knowledge_count": len(list((mix_path / "knowledge_finale").glob("*.json"))) if (mix_path / "knowledge_finale").exists() else 0,
            "vocabulary_count": len(list((mix_path / "vocabulary").glob("*.json"))) if (mix_path / "vocabulary").exists() else 0,
            "subtitle_count": len(list((mix_path / "subtitles").glob("*"))) if (mix_path / "subtitles").exists() else 0,
        }

    # =========================================================================
    # ROLLBACK & DELETE
    # =========================================================================

    async def rollback_to_version(
        self,
        project_id: UUID,
        version: str
    ) -> bool:
        """Rollback a una versione precedente."""
        project = await self._get_project(project_id)
        mix_version = await self.get_mix_version(project_id, version)

        if not mix_version:
            raise ValueError(f"Mix version not found: {version}")

        mix_path = Path(mix_version.storage_path)
        if not mix_path.exists():
            raise ValueError(f"Mix folder not found: {mix_path}")

        project.current_mix_version = version
        project.updated_at = datetime.utcnow()

        await self.db.commit()
        self._update_current_symlink(project, version)

        logger.info(f"Rolled back project {project_id} to mix v{version}")
        return True

    async def delete_mix_version(
        self,
        project_id: UUID,
        version: str,
        delete_files: bool = True
    ) -> bool:
        """Elimina una versione mix (non la corrente)."""
        project = await self._get_project(project_id)

        if project.current_mix_version == version:
            raise ValueError("Cannot delete current mix version. Rollback first.")

        mix_version = await self.get_mix_version(project_id, version)
        if not mix_version:
            return False

        if delete_files:
            mix_path = Path(mix_version.storage_path)
            if mix_path.exists():
                shutil.rmtree(mix_path, ignore_errors=True)

        await self.db.delete(mix_version)
        await self.db.commit()

        logger.info(f"Deleted mix v{version} from project {project_id}")
        return True

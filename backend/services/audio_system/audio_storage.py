"""
# AI_MODULE: AudioStorage
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Gestione storage file audio con metadata, cleanup automatico, deduplicazione
# AI_BUSINESS: Organizza audio generati (TTS, cloning, styled) con naming consistente,
#              cleanup automatico file temporanei, deduplicazione basata su hash
# AI_TEACHING: Storage audio con struttura cartelle per tipo, metadata JSON sidecar,
#              hash SHA256 per dedup, cleanup basato su età file. Thread-safe con asyncio locks.
# AI_DEPENDENCIES: aiofiles, soundfile, hashlib
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

AudioStorage Module
===================

Gestisce lo storage dei file audio con:
- Organizzazione per tipo (tts/, cloned/, styled/, temp/)
- Metadata JSON sidecar per ogni file
- Deduplicazione basata su SHA256 hash
- Cleanup automatico file temporanei
- Secure delete opzionale (GDPR)
"""

import asyncio
import hashlib
import json
import os
import shutil
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, AsyncIterator
import uuid
import logging

logger = logging.getLogger(__name__)


class AudioFormat(Enum):
    """Formati audio supportati."""
    WAV = "wav"
    MP3 = "mp3"
    OGG = "ogg"
    FLAC = "flac"
    M4A = "m4a"

    @classmethod
    def from_extension(cls, ext: str) -> "AudioFormat":
        """Ottiene formato da estensione file."""
        ext = ext.lower().lstrip(".")
        for fmt in cls:
            if fmt.value == ext:
                return fmt
        raise ValueError(f"Formato non supportato: {ext}")

    @property
    def mime_type(self) -> str:
        """Restituisce MIME type per il formato."""
        mime_map = {
            AudioFormat.WAV: "audio/wav",
            AudioFormat.MP3: "audio/mpeg",
            AudioFormat.OGG: "audio/ogg",
            AudioFormat.FLAC: "audio/flac",
            AudioFormat.M4A: "audio/mp4",
        }
        return mime_map[self]


class AudioCategory(Enum):
    """Categorie di audio storage."""
    TTS = "tts"
    CLONED = "cloned"
    STYLED = "styled"
    REFERENCE = "reference"
    TEMP = "temp"
    EXPORT = "export"


@dataclass
class AudioMetadata:
    """Metadata per file audio."""
    id: str
    filename: str
    category: str
    format: str
    size_bytes: int
    duration_seconds: Optional[float]
    sample_rate: Optional[int]
    channels: Optional[int]
    bit_depth: Optional[int]
    hash_sha256: str
    created_at: str
    source_text: Optional[str] = None
    language: Optional[str] = None
    voice_id: Optional[str] = None
    style_applied: Optional[str] = None
    reference_audio_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AudioMetadata":
        """Crea da dizionario."""
        return cls(**data)

    def to_json(self) -> str:
        """Serializza in JSON."""
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)

    @classmethod
    def from_json(cls, json_str: str) -> "AudioMetadata":
        """Deserializza da JSON."""
        return cls.from_dict(json.loads(json_str))


@dataclass
class StorageConfig:
    """Configurazione storage."""
    base_path: str
    temp_retention_hours: int = 24
    max_storage_gb: float = 50.0
    enable_dedup: bool = True
    secure_delete: bool = False
    auto_cleanup: bool = True
    cleanup_interval_hours: int = 6


@dataclass
class StorageStats:
    """Statistiche storage."""
    total_files: int
    total_size_bytes: int
    files_by_category: Dict[str, int]
    size_by_category: Dict[str, int]
    oldest_file_date: Optional[str]
    newest_file_date: Optional[str]
    dedup_savings_bytes: int


class AudioStorage:
    """
    Gestore storage file audio.

    Singleton pattern con _reset_for_testing per test isolation.

    Struttura cartelle:
        base_path/
        ├── tts/           # Audio TTS generati
        ├── cloned/        # Audio con voice cloning
        ├── styled/        # Audio con effetti applicati
        ├── reference/     # Audio di riferimento per cloning
        ├── temp/          # File temporanei (auto-cleanup)
        └── export/        # File pronti per export
    """

    _instance: Optional["AudioStorage"] = None
    _lock = asyncio.Lock()

    def __init__(self, config: Optional[StorageConfig] = None):
        """
        Inizializza AudioStorage.

        Args:
            config: Configurazione storage. Se None, usa default.
        """
        if config is None:
            config = StorageConfig(
                base_path=os.path.join(os.getcwd(), "storage", "audio")
            )
        self.config = config
        self._base_path = Path(config.base_path)
        self._metadata_cache: Dict[str, AudioMetadata] = {}
        self._hash_index: Dict[str, str] = {}  # hash -> audio_id
        self._cleanup_task: Optional[asyncio.Task] = None
        self._initialized = False

    @classmethod
    async def get_instance(cls, config: Optional[StorageConfig] = None) -> "AudioStorage":
        """
        Ottiene istanza singleton.

        Args:
            config: Configurazione (solo alla prima chiamata)

        Returns:
            Istanza AudioStorage
        """
        async with cls._lock:
            if cls._instance is None:
                cls._instance = cls(config)
                await cls._instance._initialize()
            return cls._instance

    @classmethod
    def _reset_for_testing(cls) -> None:
        """Reset singleton per test isolation."""
        if cls._instance is not None:
            if cls._instance._cleanup_task:
                cls._instance._cleanup_task.cancel()
        cls._instance = None

    async def _initialize(self) -> None:
        """Inizializza storage e struttura cartelle."""
        if self._initialized:
            return

        # Crea struttura cartelle
        for category in AudioCategory:
            category_path = self._base_path / category.value
            category_path.mkdir(parents=True, exist_ok=True)

        # Carica metadata esistenti
        await self._load_metadata_cache()

        # Costruisci indice hash
        await self._build_hash_index()

        # Avvia cleanup automatico
        if self.config.auto_cleanup:
            self._cleanup_task = asyncio.create_task(self._auto_cleanup_loop())

        self._initialized = True
        logger.info(f"AudioStorage inizializzato: {self._base_path}")

    async def _load_metadata_cache(self) -> None:
        """Carica tutti i metadata in cache."""
        for category in AudioCategory:
            category_path = self._base_path / category.value
            if not category_path.exists():
                continue

            for meta_file in category_path.glob("*.meta.json"):
                try:
                    content = meta_file.read_text(encoding="utf-8")
                    metadata = AudioMetadata.from_json(content)
                    self._metadata_cache[metadata.id] = metadata
                except Exception as e:
                    logger.warning(f"Errore caricamento metadata {meta_file}: {e}")

    async def _build_hash_index(self) -> None:
        """Costruisce indice hash per deduplicazione."""
        self._hash_index.clear()
        for audio_id, metadata in self._metadata_cache.items():
            if metadata.hash_sha256:
                self._hash_index[metadata.hash_sha256] = audio_id

    async def _auto_cleanup_loop(self) -> None:
        """Loop cleanup automatico file temporanei."""
        while True:
            try:
                await asyncio.sleep(self.config.cleanup_interval_hours * 3600)
                await self.cleanup_temp_files()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Errore cleanup automatico: {e}")

    def _generate_filename(
        self,
        category: AudioCategory,
        format: AudioFormat,
        prefix: str = ""
    ) -> str:
        """
        Genera nome file univoco.

        Args:
            category: Categoria audio
            format: Formato audio
            prefix: Prefisso opzionale

        Returns:
            Nome file univoco
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = uuid.uuid4().hex[:8]
        if prefix:
            return f"{prefix}_{timestamp}_{unique_id}.{format.value}"
        return f"{category.value}_{timestamp}_{unique_id}.{format.value}"

    async def _calculate_hash(self, file_path: Path) -> str:
        """
        Calcola SHA256 hash del file.

        Args:
            file_path: Path del file

        Returns:
            Hash SHA256 come stringa hex
        """
        sha256 = hashlib.sha256()
        chunk_size = 8192

        def _read_chunks():
            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    sha256.update(chunk)
            return sha256.hexdigest()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _read_chunks)

    async def _get_audio_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Ottiene informazioni tecniche audio.

        Args:
            file_path: Path del file audio

        Returns:
            Dict con duration, sample_rate, channels, bit_depth
        """
        info = {
            "duration_seconds": None,
            "sample_rate": None,
            "channels": None,
            "bit_depth": None,
        }

        try:
            import soundfile as sf
            with sf.SoundFile(str(file_path)) as f:
                info["duration_seconds"] = len(f) / f.samplerate
                info["sample_rate"] = f.samplerate
                info["channels"] = f.channels
                # bit_depth non sempre disponibile
                if hasattr(f, 'subtype'):
                    subtype = f.subtype
                    if 'PCM_16' in subtype:
                        info["bit_depth"] = 16
                    elif 'PCM_24' in subtype:
                        info["bit_depth"] = 24
                    elif 'PCM_32' in subtype:
                        info["bit_depth"] = 32
        except ImportError:
            logger.warning("soundfile non installato, info audio limitate")
        except Exception as e:
            logger.warning(f"Errore lettura info audio {file_path}: {e}")

        return info

    async def store(
        self,
        source_path: str,
        category: AudioCategory,
        format: Optional[AudioFormat] = None,
        metadata_extra: Optional[Dict[str, Any]] = None,
        move: bool = False
    ) -> AudioMetadata:
        """
        Memorizza un file audio.

        Args:
            source_path: Path del file sorgente
            category: Categoria di destinazione
            format: Formato audio (auto-detect se None)
            metadata_extra: Metadata aggiuntivi
            move: Se True, sposta invece di copiare

        Returns:
            AudioMetadata del file memorizzato

        Raises:
            FileNotFoundError: Se source_path non esiste
            ValueError: Se formato non supportato
        """
        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"File non trovato: {source_path}")

        # Auto-detect formato
        if format is None:
            format = AudioFormat.from_extension(source.suffix)

        # Calcola hash per dedup
        file_hash = await self._calculate_hash(source)

        # Controlla deduplicazione
        if self.config.enable_dedup and file_hash in self._hash_index:
            existing_id = self._hash_index[file_hash]
            if existing_id in self._metadata_cache:
                logger.info(f"File duplicato trovato, riuso {existing_id}")
                return self._metadata_cache[existing_id]

        # Genera nome file e path destinazione
        filename = self._generate_filename(category, format)
        dest_path = self._base_path / category.value / filename

        # Copia o sposta file
        if move:
            shutil.move(str(source), str(dest_path))
        else:
            shutil.copy2(str(source), str(dest_path))

        # Ottieni info audio
        audio_info = await self._get_audio_info(dest_path)

        # Crea metadata
        audio_id = str(uuid.uuid4())
        metadata = AudioMetadata(
            id=audio_id,
            filename=filename,
            category=category.value,
            format=format.value,
            size_bytes=dest_path.stat().st_size,
            duration_seconds=audio_info["duration_seconds"],
            sample_rate=audio_info["sample_rate"],
            channels=audio_info["channels"],
            bit_depth=audio_info["bit_depth"],
            hash_sha256=file_hash,
            created_at=datetime.now().isoformat(),
            extra=metadata_extra or {},
        )

        # Salva metadata sidecar
        meta_path = dest_path.with_suffix(dest_path.suffix + ".meta.json")
        meta_path.write_text(metadata.to_json(), encoding="utf-8")

        # Aggiorna cache
        self._metadata_cache[audio_id] = metadata
        self._hash_index[file_hash] = audio_id

        logger.info(f"Audio memorizzato: {audio_id} -> {dest_path}")
        return metadata

    async def store_bytes(
        self,
        data: bytes,
        category: AudioCategory,
        format: AudioFormat,
        metadata_extra: Optional[Dict[str, Any]] = None
    ) -> AudioMetadata:
        """
        Memorizza audio da bytes.

        Args:
            data: Bytes audio
            category: Categoria
            format: Formato
            metadata_extra: Metadata aggiuntivi

        Returns:
            AudioMetadata del file memorizzato
        """
        # Scrivi in file temp
        temp_path = self._base_path / "temp" / f"upload_{uuid.uuid4().hex}.{format.value}"
        temp_path.write_bytes(data)

        try:
            return await self.store(
                str(temp_path),
                category,
                format,
                metadata_extra,
                move=True
            )
        except Exception:
            # Cleanup temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

    async def get(self, audio_id: str) -> Optional[Path]:
        """
        Ottiene path di un file audio.

        Args:
            audio_id: ID audio

        Returns:
            Path del file o None se non trovato
        """
        if audio_id not in self._metadata_cache:
            return None

        metadata = self._metadata_cache[audio_id]
        file_path = self._base_path / metadata.category / metadata.filename

        if not file_path.exists():
            logger.warning(f"File mancante per {audio_id}: {file_path}")
            return None

        return file_path

    async def get_metadata(self, audio_id: str) -> Optional[AudioMetadata]:
        """
        Ottiene metadata di un audio.

        Args:
            audio_id: ID audio

        Returns:
            AudioMetadata o None
        """
        return self._metadata_cache.get(audio_id)

    async def delete(self, audio_id: str, secure: Optional[bool] = None) -> bool:
        """
        Elimina un file audio.

        Args:
            audio_id: ID audio
            secure: Se True, sovrascrive prima di eliminare (GDPR)

        Returns:
            True se eliminato, False se non trovato
        """
        if audio_id not in self._metadata_cache:
            return False

        metadata = self._metadata_cache[audio_id]
        file_path = self._base_path / metadata.category / metadata.filename
        meta_path = file_path.with_suffix(file_path.suffix + ".meta.json")

        use_secure = secure if secure is not None else self.config.secure_delete

        if file_path.exists():
            if use_secure:
                await self._secure_delete_file(file_path)
            else:
                file_path.unlink()

        if meta_path.exists():
            meta_path.unlink()

        # Rimuovi da cache
        if metadata.hash_sha256 in self._hash_index:
            del self._hash_index[metadata.hash_sha256]
        del self._metadata_cache[audio_id]

        logger.info(f"Audio eliminato: {audio_id}")
        return True

    async def _secure_delete_file(self, file_path: Path) -> None:
        """
        Elimina file in modo sicuro (sovrascrittura).

        Args:
            file_path: Path del file
        """
        if not file_path.exists():
            return

        size = file_path.stat().st_size

        def _overwrite():
            with open(file_path, "r+b") as f:
                # 3 passate di sovrascrittura
                for pattern in [b'\x00', b'\xff', os.urandom(1)]:
                    f.seek(0)
                    f.write(pattern * size)
                    f.flush()
                    os.fsync(f.fileno())
            file_path.unlink()

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _overwrite)

    async def list_by_category(
        self,
        category: AudioCategory,
        limit: int = 100,
        offset: int = 0
    ) -> List[AudioMetadata]:
        """
        Lista audio per categoria.

        Args:
            category: Categoria
            limit: Numero massimo risultati
            offset: Offset paginazione

        Returns:
            Lista AudioMetadata
        """
        results = [
            m for m in self._metadata_cache.values()
            if m.category == category.value
        ]
        # Ordina per data creazione desc
        results.sort(key=lambda x: x.created_at, reverse=True)
        return results[offset:offset + limit]

    async def search(
        self,
        query: str,
        category: Optional[AudioCategory] = None,
        language: Optional[str] = None
    ) -> List[AudioMetadata]:
        """
        Cerca audio per testo sorgente.

        Args:
            query: Query di ricerca
            category: Filtra per categoria
            language: Filtra per lingua

        Returns:
            Lista AudioMetadata corrispondenti
        """
        query_lower = query.lower()
        results = []

        for metadata in self._metadata_cache.values():
            # Filtra categoria
            if category and metadata.category != category.value:
                continue
            # Filtra lingua
            if language and metadata.language != language:
                continue
            # Cerca in source_text
            if metadata.source_text and query_lower in metadata.source_text.lower():
                results.append(metadata)

        return results

    async def find_by_hash(self, file_hash: str) -> Optional[AudioMetadata]:
        """
        Trova audio per hash.

        Args:
            file_hash: SHA256 hash

        Returns:
            AudioMetadata o None
        """
        audio_id = self._hash_index.get(file_hash)
        if audio_id:
            return self._metadata_cache.get(audio_id)
        return None

    async def cleanup_temp_files(self, max_age_hours: Optional[int] = None) -> int:
        """
        Elimina file temporanei vecchi.

        Args:
            max_age_hours: Età massima in ore (default da config)

        Returns:
            Numero file eliminati
        """
        max_age = max_age_hours or self.config.temp_retention_hours
        cutoff = datetime.now() - timedelta(hours=max_age)
        deleted = 0

        temp_audios = [
            m for m in self._metadata_cache.values()
            if m.category == AudioCategory.TEMP.value
        ]

        for metadata in temp_audios:
            created = datetime.fromisoformat(metadata.created_at)
            if created < cutoff:
                if await self.delete(metadata.id):
                    deleted += 1

        logger.info(f"Cleanup temp: {deleted} file eliminati")
        return deleted

    async def get_stats(self) -> StorageStats:
        """
        Ottiene statistiche storage.

        Returns:
            StorageStats con metriche
        """
        files_by_cat: Dict[str, int] = {}
        size_by_cat: Dict[str, int] = {}
        dates = []
        dedup_count = 0

        for metadata in self._metadata_cache.values():
            cat = metadata.category
            files_by_cat[cat] = files_by_cat.get(cat, 0) + 1
            size_by_cat[cat] = size_by_cat.get(cat, 0) + metadata.size_bytes
            dates.append(metadata.created_at)

        # Calcola savings dedup (hash con count > 1)
        hash_counts: Dict[str, int] = {}
        for audio_id, metadata in self._metadata_cache.items():
            h = metadata.hash_sha256
            hash_counts[h] = hash_counts.get(h, 0) + 1

        dedup_savings = sum(
            self._metadata_cache[self._hash_index[h]].size_bytes * (count - 1)
            for h, count in hash_counts.items()
            if count > 1 and h in self._hash_index
        )

        return StorageStats(
            total_files=len(self._metadata_cache),
            total_size_bytes=sum(m.size_bytes for m in self._metadata_cache.values()),
            files_by_category=files_by_cat,
            size_by_category=size_by_cat,
            oldest_file_date=min(dates) if dates else None,
            newest_file_date=max(dates) if dates else None,
            dedup_savings_bytes=dedup_savings,
        )

    async def export_to_directory(
        self,
        audio_ids: List[str],
        dest_dir: str,
        flatten: bool = True
    ) -> List[str]:
        """
        Esporta audio in una directory.

        Args:
            audio_ids: Lista ID audio da esportare
            dest_dir: Directory destinazione
            flatten: Se True, tutti i file nella stessa cartella

        Returns:
            Lista path file esportati
        """
        dest_path = Path(dest_dir)
        dest_path.mkdir(parents=True, exist_ok=True)
        exported = []

        for audio_id in audio_ids:
            source = await self.get(audio_id)
            if source is None:
                continue

            metadata = self._metadata_cache[audio_id]

            if flatten:
                dest = dest_path / metadata.filename
            else:
                cat_dir = dest_path / metadata.category
                cat_dir.mkdir(exist_ok=True)
                dest = cat_dir / metadata.filename

            shutil.copy2(str(source), str(dest))
            exported.append(str(dest))

        return exported

    async def get_total_size(self) -> int:
        """Ottiene dimensione totale storage in bytes."""
        return sum(m.size_bytes for m in self._metadata_cache.values())

    async def is_storage_full(self) -> bool:
        """Controlla se storage ha raggiunto limite."""
        total = await self.get_total_size()
        max_bytes = int(self.config.max_storage_gb * 1024 * 1024 * 1024)
        return total >= max_bytes

    async def iter_all(self) -> AsyncIterator[AudioMetadata]:
        """Itera su tutti i metadata."""
        for metadata in self._metadata_cache.values():
            yield metadata

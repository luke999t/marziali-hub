"""
# AI_MODULE: PronunciationDB
# AI_VERSION: 1.0.0
# AI_DESCRIPTION: Database SQLite per pronuncie corrette termini arti marziali multilingua
# AI_BUSINESS: Garantisce pronuncia corretta di termini giapponesi, cinesi, coreani
#              nei video tutorial. Supporta IPA, romaji, pinyin e audio reference.
# AI_TEACHING: SQLite con FTS5 per ricerca veloce, tabelle per termini/pronuncie/audio,
#              sistema voting per validazione community, import/export JSON/CSV.
# AI_DEPENDENCIES: aiosqlite
# AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
# AI_CREATED: 2025-12-13

PronunciationDB Module
======================

Database per pronuncie corrette dei termini delle arti marziali.

Features:
- Termini multilingua (giapponese, cinese, coreano, italiano, inglese)
- IPA (International Phonetic Alphabet) per pronuncia precisa
- Romanizzazione (romaji, pinyin, romanizzazione coreana)
- Link a file audio di riferimento
- Sistema voting per validazione
- Import/export JSON e CSV
- Ricerca full-text con FTS5
"""

import asyncio
import csv
import json
import os
import sqlite3
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)


class LanguageCode(Enum):
    """Codici lingua supportati."""
    JA = "ja"  # Giapponese
    ZH = "zh"  # Cinese (Mandarino)
    KO = "ko"  # Coreano
    IT = "it"  # Italiano
    EN = "en"  # Inglese
    ES = "es"  # Spagnolo
    FR = "fr"  # Francese
    DE = "de"  # Tedesco
    PT = "pt"  # Portoghese

    @property
    def display_name(self) -> str:
        """Nome visualizzato della lingua."""
        names = {
            LanguageCode.JA: "Giapponese",
            LanguageCode.ZH: "Cinese",
            LanguageCode.KO: "Coreano",
            LanguageCode.IT: "Italiano",
            LanguageCode.EN: "Inglese",
            LanguageCode.ES: "Spagnolo",
            LanguageCode.FR: "Francese",
            LanguageCode.DE: "Tedesco",
            LanguageCode.PT: "Portoghese",
        }
        return names[self]


class MartialArtStyle(Enum):
    """Stili di arti marziali."""
    KARATE = "karate"
    JUDO = "judo"
    AIKIDO = "aikido"
    KENDO = "kendo"
    TAEKWONDO = "taekwondo"
    KUNG_FU = "kung_fu"
    TAI_CHI = "tai_chi"
    JIU_JITSU = "jiu_jitsu"
    MMA = "mma"
    GENERAL = "general"


class TermCategory(Enum):
    """Categoria del termine."""
    TECHNIQUE = "technique"  # Tecniche (oi-zuki, mae-geri)
    STANCE = "stance"  # Posizioni (zenkutsu-dachi)
    COMMAND = "command"  # Comandi (hajime, yame)
    COUNT = "count"  # Numeri (ichi, ni, san)
    GREETING = "greeting"  # Saluti (osu, rei)
    EQUIPMENT = "equipment"  # Attrezzatura (gi, obi)
    BODY_PART = "body_part"  # Parti corpo (seiken, shuto)
    CONCEPT = "concept"  # Concetti (kime, kiai)
    RANK = "rank"  # Gradi (kyu, dan)
    OTHER = "other"


@dataclass
class PronunciationEntry:
    """Entry di pronuncia per un termine."""
    id: str
    term: str  # Termine originale (es. "追い突き")
    language: str  # Lingua del termine (ja, zh, ko, etc.)
    romanization: str  # Romanizzazione (romaji, pinyin, etc.)
    ipa: Optional[str]  # IPA per pronuncia precisa
    meaning_it: Optional[str]  # Significato italiano
    meaning_en: Optional[str]  # Significato inglese
    category: str  # Categoria termine
    martial_art: str  # Arte marziale di riferimento
    audio_reference_id: Optional[str]  # ID audio di riferimento
    notes: Optional[str]  # Note aggiuntive
    created_at: str
    updated_at: str
    created_by: Optional[str]
    upvotes: int = 0
    downvotes: int = 0
    verified: bool = False
    alternatives: List[str] = field(default_factory=list)  # Varianti ortografiche

    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario."""
        d = asdict(self)
        d['alternatives'] = json.dumps(d['alternatives'])
        return d

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "PronunciationEntry":
        """Crea da row SQLite."""
        data = dict(row)
        data['alternatives'] = json.loads(data.get('alternatives', '[]'))
        return cls(**data)

    @property
    def score(self) -> int:
        """Punteggio netto (upvotes - downvotes)."""
        return self.upvotes - self.downvotes


@dataclass
class PronunciationStats:
    """Statistiche database pronuncie."""
    total_entries: int
    entries_by_language: Dict[str, int]
    entries_by_martial_art: Dict[str, int]
    entries_by_category: Dict[str, int]
    verified_count: int
    with_audio_count: int
    average_score: float


class PronunciationDB:
    """
    Database SQLite per pronuncie termini arti marziali.

    Singleton pattern con _reset_for_testing per test isolation.

    Schema:
        pronunciations: Tabella principale termini
        pronunciations_fts: FTS5 per ricerca full-text
        votes: Storico voti utenti
    """

    _instance: Optional["PronunciationDB"] = None
    _lock = asyncio.Lock()

    # Schema SQL
    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS pronunciations (
        id TEXT PRIMARY KEY,
        term TEXT NOT NULL,
        language TEXT NOT NULL,
        romanization TEXT NOT NULL,
        ipa TEXT,
        meaning_it TEXT,
        meaning_en TEXT,
        category TEXT NOT NULL,
        martial_art TEXT NOT NULL,
        audio_reference_id TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        created_by TEXT,
        upvotes INTEGER DEFAULT 0,
        downvotes INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 0,
        alternatives TEXT DEFAULT '[]'
    );

    CREATE INDEX IF NOT EXISTS idx_pron_language ON pronunciations(language);
    CREATE INDEX IF NOT EXISTS idx_pron_martial_art ON pronunciations(martial_art);
    CREATE INDEX IF NOT EXISTS idx_pron_category ON pronunciations(category);
    CREATE INDEX IF NOT EXISTS idx_pron_verified ON pronunciations(verified);

    CREATE VIRTUAL TABLE IF NOT EXISTS pronunciations_fts USING fts5(
        term, romanization, meaning_it, meaning_en, notes,
        content='pronunciations',
        content_rowid='rowid'
    );

    CREATE TRIGGER IF NOT EXISTS pron_ai AFTER INSERT ON pronunciations BEGIN
        INSERT INTO pronunciations_fts(rowid, term, romanization, meaning_it, meaning_en, notes)
        VALUES (new.rowid, new.term, new.romanization, new.meaning_it, new.meaning_en, new.notes);
    END;

    CREATE TRIGGER IF NOT EXISTS pron_ad AFTER DELETE ON pronunciations BEGIN
        INSERT INTO pronunciations_fts(pronunciations_fts, rowid, term, romanization, meaning_it, meaning_en, notes)
        VALUES ('delete', old.rowid, old.term, old.romanization, old.meaning_it, old.meaning_en, old.notes);
    END;

    CREATE TRIGGER IF NOT EXISTS pron_au AFTER UPDATE ON pronunciations BEGIN
        INSERT INTO pronunciations_fts(pronunciations_fts, rowid, term, romanization, meaning_it, meaning_en, notes)
        VALUES ('delete', old.rowid, old.term, old.romanization, old.meaning_it, old.meaning_en, old.notes);
        INSERT INTO pronunciations_fts(rowid, term, romanization, meaning_it, meaning_en, notes)
        VALUES (new.rowid, new.term, new.romanization, new.meaning_it, new.meaning_en, new.notes);
    END;

    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pronunciation_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        vote INTEGER NOT NULL,  -- 1 = upvote, -1 = downvote
        created_at TEXT NOT NULL,
        FOREIGN KEY (pronunciation_id) REFERENCES pronunciations(id),
        UNIQUE(pronunciation_id, user_id)
    );
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Inizializza PronunciationDB.

        Args:
            db_path: Path database SQLite. Se None, usa default.
        """
        if db_path is None:
            db_path = os.path.join(os.getcwd(), "storage", "audio", "pronunciation.db")
        self._db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    @classmethod
    async def get_instance(cls, db_path: Optional[str] = None) -> "PronunciationDB":
        """
        Ottiene istanza singleton.

        Args:
            db_path: Path database (solo alla prima chiamata)

        Returns:
            Istanza PronunciationDB
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
        logger.info(f"PronunciationDB inizializzato: {self._db_path}")

    def _generate_id(self) -> str:
        """Genera ID univoco."""
        import uuid
        return str(uuid.uuid4())

    async def add(
        self,
        term: str,
        language: LanguageCode,
        romanization: str,
        category: TermCategory,
        martial_art: MartialArtStyle,
        ipa: Optional[str] = None,
        meaning_it: Optional[str] = None,
        meaning_en: Optional[str] = None,
        audio_reference_id: Optional[str] = None,
        notes: Optional[str] = None,
        created_by: Optional[str] = None,
        alternatives: Optional[List[str]] = None,
    ) -> PronunciationEntry:
        """
        Aggiunge un termine al database.

        Args:
            term: Termine originale
            language: Lingua del termine
            romanization: Romanizzazione
            category: Categoria termine
            martial_art: Arte marziale
            ipa: Trascrizione IPA opzionale
            meaning_it: Significato italiano
            meaning_en: Significato inglese
            audio_reference_id: ID audio di riferimento
            notes: Note aggiuntive
            created_by: ID utente creatore
            alternatives: Varianti ortografiche

        Returns:
            PronunciationEntry creata
        """
        now = datetime.now().isoformat()
        entry_id = self._generate_id()

        entry = PronunciationEntry(
            id=entry_id,
            term=term,
            language=language.value,
            romanization=romanization,
            ipa=ipa,
            meaning_it=meaning_it,
            meaning_en=meaning_en,
            category=category.value,
            martial_art=martial_art.value,
            audio_reference_id=audio_reference_id,
            notes=notes,
            created_at=now,
            updated_at=now,
            created_by=created_by,
            alternatives=alternatives or [],
        )

        self._conn.execute(
            """
            INSERT INTO pronunciations
            (id, term, language, romanization, ipa, meaning_it, meaning_en,
             category, martial_art, audio_reference_id, notes, created_at,
             updated_at, created_by, alternatives)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry.id, entry.term, entry.language, entry.romanization,
                entry.ipa, entry.meaning_it, entry.meaning_en, entry.category,
                entry.martial_art, entry.audio_reference_id, entry.notes,
                entry.created_at, entry.updated_at, entry.created_by,
                json.dumps(entry.alternatives)
            )
        )
        self._conn.commit()

        logger.info(f"Termine aggiunto: {entry.id} - {term}")
        return entry

    async def get(self, entry_id: str) -> Optional[PronunciationEntry]:
        """
        Ottiene un termine per ID.

        Args:
            entry_id: ID del termine

        Returns:
            PronunciationEntry o None
        """
        cursor = self._conn.execute(
            "SELECT * FROM pronunciations WHERE id = ?",
            (entry_id,)
        )
        row = cursor.fetchone()
        if row:
            return PronunciationEntry.from_row(row)
        return None

    async def update(
        self,
        entry_id: str,
        **updates
    ) -> Optional[PronunciationEntry]:
        """
        Aggiorna un termine.

        Args:
            entry_id: ID del termine
            **updates: Campi da aggiornare

        Returns:
            PronunciationEntry aggiornata o None
        """
        entry = await self.get(entry_id)
        if entry is None:
            return None

        # Campi aggiornabili
        allowed = {
            'term', 'romanization', 'ipa', 'meaning_it', 'meaning_en',
            'category', 'martial_art', 'audio_reference_id', 'notes',
            'verified', 'alternatives'
        }

        updates = {k: v for k, v in updates.items() if k in allowed}
        if not updates:
            return entry

        updates['updated_at'] = datetime.now().isoformat()

        # Serializza alternatives se presente
        if 'alternatives' in updates:
            updates['alternatives'] = json.dumps(updates['alternatives'])

        # Costruisci query
        set_clause = ', '.join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [entry_id]

        self._conn.execute(
            f"UPDATE pronunciations SET {set_clause} WHERE id = ?",
            values
        )
        self._conn.commit()

        return await self.get(entry_id)

    async def delete(self, entry_id: str) -> bool:
        """
        Elimina un termine.

        Args:
            entry_id: ID del termine

        Returns:
            True se eliminato
        """
        cursor = self._conn.execute(
            "DELETE FROM pronunciations WHERE id = ?",
            (entry_id,)
        )
        self._conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Termine eliminato: {entry_id}")
        return deleted

    async def search(
        self,
        query: str,
        language: Optional[LanguageCode] = None,
        martial_art: Optional[MartialArtStyle] = None,
        category: Optional[TermCategory] = None,
        verified_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> List[PronunciationEntry]:
        """
        Cerca termini con full-text search.

        Args:
            query: Query di ricerca
            language: Filtra per lingua
            martial_art: Filtra per arte marziale
            category: Filtra per categoria
            verified_only: Solo termini verificati
            limit: Numero massimo risultati
            offset: Offset paginazione

        Returns:
            Lista PronunciationEntry
        """
        # Costruisci query FTS
        conditions = []
        params = []

        if query:
            # Ricerca full-text
            fts_query = f"""
                SELECT p.* FROM pronunciations p
                INNER JOIN pronunciations_fts fts ON p.rowid = fts.rowid
                WHERE pronunciations_fts MATCH ?
            """
            params.append(query + "*")  # Prefix search
        else:
            fts_query = "SELECT * FROM pronunciations WHERE 1=1"

        if language:
            conditions.append("language = ?")
            params.append(language.value)

        if martial_art:
            conditions.append("martial_art = ?")
            params.append(martial_art.value)

        if category:
            conditions.append("category = ?")
            params.append(category.value)

        if verified_only:
            conditions.append("verified = 1")

        # Aggiungi condizioni
        if conditions:
            if "WHERE" in fts_query:
                fts_query += " AND " + " AND ".join(conditions)
            else:
                fts_query += " WHERE " + " AND ".join(conditions)

        # Ordinamento e paginazione
        fts_query += " ORDER BY upvotes - downvotes DESC, created_at DESC"
        fts_query += f" LIMIT {limit} OFFSET {offset}"

        cursor = self._conn.execute(fts_query, params)
        return [PronunciationEntry.from_row(row) for row in cursor.fetchall()]

    async def find_by_term(
        self,
        term: str,
        language: Optional[LanguageCode] = None
    ) -> List[PronunciationEntry]:
        """
        Trova per termine esatto.

        Args:
            term: Termine da cercare
            language: Lingua opzionale

        Returns:
            Lista risultati
        """
        if language:
            cursor = self._conn.execute(
                "SELECT * FROM pronunciations WHERE term = ? AND language = ?",
                (term, language.value)
            )
        else:
            cursor = self._conn.execute(
                "SELECT * FROM pronunciations WHERE term = ?",
                (term,)
            )
        return [PronunciationEntry.from_row(row) for row in cursor.fetchall()]

    async def find_by_romanization(
        self,
        romanization: str,
        language: Optional[LanguageCode] = None
    ) -> List[PronunciationEntry]:
        """
        Trova per romanizzazione.

        Args:
            romanization: Romanizzazione (case insensitive)
            language: Lingua opzionale

        Returns:
            Lista risultati
        """
        if language:
            cursor = self._conn.execute(
                "SELECT * FROM pronunciations WHERE LOWER(romanization) = LOWER(?) AND language = ?",
                (romanization, language.value)
            )
        else:
            cursor = self._conn.execute(
                "SELECT * FROM pronunciations WHERE LOWER(romanization) = LOWER(?)",
                (romanization,)
            )
        return [PronunciationEntry.from_row(row) for row in cursor.fetchall()]

    async def vote(
        self,
        entry_id: str,
        user_id: str,
        upvote: bool
    ) -> Tuple[int, int]:
        """
        Vota un termine.

        Args:
            entry_id: ID termine
            user_id: ID utente
            upvote: True per upvote, False per downvote

        Returns:
            Tuple (upvotes, downvotes) aggiornati
        """
        vote_value = 1 if upvote else -1
        now = datetime.now().isoformat()

        # Controlla voto esistente
        cursor = self._conn.execute(
            "SELECT vote FROM votes WHERE pronunciation_id = ? AND user_id = ?",
            (entry_id, user_id)
        )
        existing = cursor.fetchone()

        if existing:
            old_vote = existing['vote']
            if old_vote == vote_value:
                # Stesso voto, rimuovi
                self._conn.execute(
                    "DELETE FROM votes WHERE pronunciation_id = ? AND user_id = ?",
                    (entry_id, user_id)
                )
                # Aggiorna contatori
                if upvote:
                    self._conn.execute(
                        "UPDATE pronunciations SET upvotes = upvotes - 1 WHERE id = ?",
                        (entry_id,)
                    )
                else:
                    self._conn.execute(
                        "UPDATE pronunciations SET downvotes = downvotes - 1 WHERE id = ?",
                        (entry_id,)
                    )
            else:
                # Cambio voto
                self._conn.execute(
                    "UPDATE votes SET vote = ?, created_at = ? WHERE pronunciation_id = ? AND user_id = ?",
                    (vote_value, now, entry_id, user_id)
                )
                if upvote:
                    self._conn.execute(
                        "UPDATE pronunciations SET upvotes = upvotes + 1, downvotes = downvotes - 1 WHERE id = ?",
                        (entry_id,)
                    )
                else:
                    self._conn.execute(
                        "UPDATE pronunciations SET downvotes = downvotes + 1, upvotes = upvotes - 1 WHERE id = ?",
                        (entry_id,)
                    )
        else:
            # Nuovo voto
            self._conn.execute(
                "INSERT INTO votes (pronunciation_id, user_id, vote, created_at) VALUES (?, ?, ?, ?)",
                (entry_id, user_id, vote_value, now)
            )
            if upvote:
                self._conn.execute(
                    "UPDATE pronunciations SET upvotes = upvotes + 1 WHERE id = ?",
                    (entry_id,)
                )
            else:
                self._conn.execute(
                    "UPDATE pronunciations SET downvotes = downvotes + 1 WHERE id = ?",
                    (entry_id,)
                )

        self._conn.commit()

        # Ritorna contatori aggiornati
        entry = await self.get(entry_id)
        if entry:
            return entry.upvotes, entry.downvotes
        return 0, 0

    async def verify(self, entry_id: str, verified: bool = True) -> bool:
        """
        Marca termine come verificato.

        Args:
            entry_id: ID termine
            verified: Stato verifica

        Returns:
            True se aggiornato
        """
        cursor = self._conn.execute(
            "UPDATE pronunciations SET verified = ?, updated_at = ? WHERE id = ?",
            (1 if verified else 0, datetime.now().isoformat(), entry_id)
        )
        self._conn.commit()
        return cursor.rowcount > 0

    async def list_by_martial_art(
        self,
        martial_art: MartialArtStyle,
        limit: int = 100,
        offset: int = 0
    ) -> List[PronunciationEntry]:
        """Lista termini per arte marziale."""
        cursor = self._conn.execute(
            """
            SELECT * FROM pronunciations
            WHERE martial_art = ?
            ORDER BY category, romanization
            LIMIT ? OFFSET ?
            """,
            (martial_art.value, limit, offset)
        )
        return [PronunciationEntry.from_row(row) for row in cursor.fetchall()]

    async def list_by_category(
        self,
        category: TermCategory,
        martial_art: Optional[MartialArtStyle] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[PronunciationEntry]:
        """Lista termini per categoria."""
        if martial_art:
            cursor = self._conn.execute(
                """
                SELECT * FROM pronunciations
                WHERE category = ? AND martial_art = ?
                ORDER BY romanization
                LIMIT ? OFFSET ?
                """,
                (category.value, martial_art.value, limit, offset)
            )
        else:
            cursor = self._conn.execute(
                """
                SELECT * FROM pronunciations
                WHERE category = ?
                ORDER BY romanization
                LIMIT ? OFFSET ?
                """,
                (category.value, limit, offset)
            )
        return [PronunciationEntry.from_row(row) for row in cursor.fetchall()]

    async def get_stats(self) -> PronunciationStats:
        """Ottiene statistiche database."""
        # Totale
        total = self._conn.execute("SELECT COUNT(*) FROM pronunciations").fetchone()[0]

        # Per lingua
        by_lang = {}
        for row in self._conn.execute(
            "SELECT language, COUNT(*) as cnt FROM pronunciations GROUP BY language"
        ):
            by_lang[row['language']] = row['cnt']

        # Per arte marziale
        by_ma = {}
        for row in self._conn.execute(
            "SELECT martial_art, COUNT(*) as cnt FROM pronunciations GROUP BY martial_art"
        ):
            by_ma[row['martial_art']] = row['cnt']

        # Per categoria
        by_cat = {}
        for row in self._conn.execute(
            "SELECT category, COUNT(*) as cnt FROM pronunciations GROUP BY category"
        ):
            by_cat[row['category']] = row['cnt']

        # Verificati
        verified = self._conn.execute(
            "SELECT COUNT(*) FROM pronunciations WHERE verified = 1"
        ).fetchone()[0]

        # Con audio
        with_audio = self._conn.execute(
            "SELECT COUNT(*) FROM pronunciations WHERE audio_reference_id IS NOT NULL"
        ).fetchone()[0]

        # Score medio
        avg_score = self._conn.execute(
            "SELECT AVG(upvotes - downvotes) FROM pronunciations"
        ).fetchone()[0] or 0.0

        return PronunciationStats(
            total_entries=total,
            entries_by_language=by_lang,
            entries_by_martial_art=by_ma,
            entries_by_category=by_cat,
            verified_count=verified,
            with_audio_count=with_audio,
            average_score=avg_score,
        )

    async def export_json(self, output_path: str) -> int:
        """
        Esporta database in JSON.

        Args:
            output_path: Path file output

        Returns:
            Numero entries esportate
        """
        cursor = self._conn.execute("SELECT * FROM pronunciations")
        entries = [dict(row) for row in cursor.fetchall()]

        # Parse alternatives
        for entry in entries:
            entry['alternatives'] = json.loads(entry.get('alternatives', '[]'))

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)

        return len(entries)

    async def export_csv(self, output_path: str) -> int:
        """
        Esporta database in CSV.

        Args:
            output_path: Path file output

        Returns:
            Numero entries esportate
        """
        cursor = self._conn.execute("SELECT * FROM pronunciations")
        rows = cursor.fetchall()

        if not rows:
            return 0

        fieldnames = rows[0].keys()

        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow(dict(row))

        return len(rows)

    async def import_json(self, input_path: str) -> int:
        """
        Importa da JSON.

        Args:
            input_path: Path file input

        Returns:
            Numero entries importate
        """
        with open(input_path, 'r', encoding='utf-8') as f:
            entries = json.load(f)

        imported = 0
        for entry in entries:
            # Salta se ID esiste
            if await self.get(entry.get('id', '')):
                continue

            try:
                await self.add(
                    term=entry['term'],
                    language=LanguageCode(entry['language']),
                    romanization=entry['romanization'],
                    category=TermCategory(entry['category']),
                    martial_art=MartialArtStyle(entry['martial_art']),
                    ipa=entry.get('ipa'),
                    meaning_it=entry.get('meaning_it'),
                    meaning_en=entry.get('meaning_en'),
                    audio_reference_id=entry.get('audio_reference_id'),
                    notes=entry.get('notes'),
                    created_by=entry.get('created_by'),
                    alternatives=entry.get('alternatives', []),
                )
                imported += 1
            except Exception as e:
                logger.warning(f"Errore import entry: {e}")

        return imported

    async def seed_basic_terms(self) -> int:
        """
        Popola con termini base di karate.

        Returns:
            Numero termini aggiunti
        """
        basic_terms = [
            # Numeri
            ("一", "ja", "ichi", "count", "karate", "/iˈtʃi/", "uno", "one"),
            ("二", "ja", "ni", "count", "karate", "/ni/", "due", "two"),
            ("三", "ja", "san", "count", "karate", "/sɑn/", "tre", "three"),
            ("四", "ja", "shi/yon", "count", "karate", "/ʃi/, /joɴ/", "quattro", "four"),
            ("五", "ja", "go", "count", "karate", "/ɡo/", "cinque", "five"),

            # Comandi
            ("礼", "ja", "rei", "command", "karate", "/ɾeː/", "saluto", "bow"),
            ("始め", "ja", "hajime", "command", "karate", "/hadʒime/", "iniziare", "begin"),
            ("止め", "ja", "yame", "command", "karate", "/jame/", "fermare", "stop"),

            # Posizioni
            ("前屈立ち", "ja", "zenkutsu-dachi", "stance", "karate", None, "posizione avanzata", "front stance"),
            ("騎馬立ち", "ja", "kiba-dachi", "stance", "karate", None, "posizione del cavaliere", "horse stance"),
            ("猫足立ち", "ja", "neko-ashi-dachi", "stance", "karate", None, "posizione del gatto", "cat stance"),

            # Tecniche
            ("追い突き", "ja", "oi-zuki", "technique", "karate", None, "pugno avanzando", "lunge punch"),
            ("逆突き", "ja", "gyaku-zuki", "technique", "karate", None, "pugno contrario", "reverse punch"),
            ("前蹴り", "ja", "mae-geri", "technique", "karate", None, "calcio frontale", "front kick"),
            ("回し蹴り", "ja", "mawashi-geri", "technique", "karate", None, "calcio circolare", "roundhouse kick"),
            ("揚げ受け", "ja", "age-uke", "technique", "karate", None, "parata alta", "rising block"),
            ("外受け", "ja", "soto-uke", "technique", "karate", None, "parata esterna", "outside block"),
            ("内受け", "ja", "uchi-uke", "technique", "karate", None, "parata interna", "inside block"),
            ("下段払い", "ja", "gedan-barai", "technique", "karate", None, "parata bassa", "downward block"),

            # Concetti
            ("気合", "ja", "kiai", "concept", "karate", "/kiːai/", "grido di spirito", "spirit shout"),
            ("決め", "ja", "kime", "concept", "karate", "/kime/", "concentrazione della forza", "focus"),
        ]

        added = 0
        for term_data in basic_terms:
            term, lang, roman, cat, ma, ipa, meaning_it, meaning_en = term_data

            # Controlla se esiste
            existing = await self.find_by_romanization(roman)
            if existing:
                continue

            await self.add(
                term=term,
                language=LanguageCode(lang),
                romanization=roman,
                category=TermCategory(cat),
                martial_art=MartialArtStyle(ma),
                ipa=ipa,
                meaning_it=meaning_it,
                meaning_en=meaning_en,
            )
            added += 1

        logger.info(f"Seed completato: {added} termini aggiunti")
        return added

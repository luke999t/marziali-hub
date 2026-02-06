# annotation_manager.py
"""
🎓 AI_MODULE: Frame-Level Annotation Manager
🎓 AI_DESCRIPTION: Sistema per annotare frame specifici nei video analizzati
🎓 AI_BUSINESS: Permette ai maestri di commentare tecniche frame-per-frame
🎓 AI_TEACHING: Timeline annotations + export per knowledge sharing

🔄 ALTERNATIVE_VALUTATE:
- Video editing tools: Scartato, troppo complesso per annotazioni semplici
- Manual timestamp notes: Scartato, difficile sincronizzazione
- Embedded subtitles: Scartato, non supporta metadata strutturati

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Frame-accurate annotations (33ms precision @ 30fps)
- Structured metadata per tipo annotation
- Export/import per sharing knowledge base
- Integrazione diretta con skeleton data
"""

from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any
from pathlib import Path
import json
from datetime import datetime
from enum import Enum
import uuid


class AnnotationType(Enum):
    """Tipi di annotation disponibili"""
    TECHNIQUE = "technique"           # Nome tecnica
    COMMENT = "comment"               # Commento generico
    MARKER = "marker"                 # Marker importante
    CORRECTION = "correction"         # Correzione postura/movimento
    QUESTION = "question"             # Domanda/dubbio
    HIGHLIGHT = "highlight"           # Momento da evidenziare
    ERROR = "error"                   # Errore tecnico
    TIP = "tip"                       # Suggerimento/consiglio


@dataclass
class FrameAnnotation:
    """Annotazione su un frame specifico"""
    id: str
    video_id: str
    frame_number: int
    timestamp: float                  # Secondi
    annotation_type: AnnotationType
    content: str                      # Testo annotation
    author: str = "anonymous"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    modified_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Optional: riferimento a tecnica/pattern se applicabile
    technique_name: Optional[str] = None
    confidence: Optional[float] = None

    # Optional: landmarks specifici coinvolti
    relevant_landmarks: List[int] = field(default_factory=list)

    # Optional: tags per ricerca
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Converte a dictionary per JSON serialization"""
        data = asdict(self)
        data['annotation_type'] = self.annotation_type.value
        return data

    @classmethod
    def from_dict(cls, data: Dict) -> 'FrameAnnotation':
        """Crea da dictionary"""
        # Convert annotation_type string to enum
        if isinstance(data.get('annotation_type'), str):
            data['annotation_type'] = AnnotationType(data['annotation_type'])
        return cls(**data)


class AnnotationManager:
    """
    Gestisce le annotations per i video analizzati
    """

    def __init__(self, storage_dir: str = "./annotations"):
        """
        Inizializza manager annotations

        Args:
            storage_dir: Directory per salvare annotations JSON
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Cache in-memory per performance
        self.annotations_cache: Dict[str, List[FrameAnnotation]] = {}

    def _get_annotation_file(self, video_id: str) -> Path:
        """Ottieni path file annotations per video"""
        return self.storage_dir / f"{video_id}_annotations.json"

    def add_annotation(
        self,
        video_id: str,
        frame_number: int,
        timestamp: float,
        annotation_type: AnnotationType,
        content: str,
        author: str = "anonymous",
        **kwargs
    ) -> FrameAnnotation:
        """
        Aggiungi nuova annotation

        Args:
            video_id: ID del video
            frame_number: Numero frame
            timestamp: Timestamp in secondi
            annotation_type: Tipo annotation
            content: Contenuto testuale
            author: Nome autore
            **kwargs: Parametri opzionali (metadata, technique_name, etc.)

        Returns:
            FrameAnnotation creata
        """
        annotation = FrameAnnotation(
            id=str(uuid.uuid4()),
            video_id=video_id,
            frame_number=frame_number,
            timestamp=timestamp,
            annotation_type=annotation_type,
            content=content,
            author=author,
            **kwargs
        )

        # Aggiungi a cache
        if video_id not in self.annotations_cache:
            self.annotations_cache[video_id] = []

        self.annotations_cache[video_id].append(annotation)

        # Salva su disco
        self._save_annotations(video_id)

        return annotation

    def get_annotations(
        self,
        video_id: str,
        annotation_type: Optional[AnnotationType] = None,
        frame_range: Optional[tuple] = None
    ) -> List[FrameAnnotation]:
        """
        Ottieni annotations per video

        Args:
            video_id: ID del video
            annotation_type: Filtra per tipo (opzionale)
            frame_range: Tuple (start_frame, end_frame) per filtrare (opzionale)

        Returns:
            Lista di FrameAnnotation
        """
        # Carica da cache o da disco
        if video_id not in self.annotations_cache:
            self._load_annotations(video_id)

        annotations = self.annotations_cache.get(video_id, [])

        # Filtra per tipo
        if annotation_type:
            annotations = [a for a in annotations if a.annotation_type == annotation_type]

        # Filtra per frame range
        if frame_range:
            start_frame, end_frame = frame_range
            annotations = [
                a for a in annotations
                if start_frame <= a.frame_number <= end_frame
            ]

        # Ordina per frame number
        return sorted(annotations, key=lambda a: a.frame_number)

    def get_annotation_by_id(self, video_id: str, annotation_id: str) -> Optional[FrameAnnotation]:
        """Ottieni annotation specifica per ID"""
        annotations = self.get_annotations(video_id)
        for annotation in annotations:
            if annotation.id == annotation_id:
                return annotation
        return None

    def update_annotation(
        self,
        video_id: str,
        annotation_id: str,
        content: Optional[str] = None,
        annotation_type: Optional[AnnotationType] = None,
        **kwargs
    ) -> Optional[FrameAnnotation]:
        """
        Aggiorna annotation esistente

        Args:
            video_id: ID del video
            annotation_id: ID annotation
            content: Nuovo contenuto (opzionale)
            annotation_type: Nuovo tipo (opzionale)
            **kwargs: Altri campi da aggiornare

        Returns:
            FrameAnnotation aggiornata o None se non trovata
        """
        annotation = self.get_annotation_by_id(video_id, annotation_id)

        if not annotation:
            return None

        # Aggiorna campi
        if content is not None:
            annotation.content = content

        if annotation_type is not None:
            annotation.annotation_type = annotation_type

        # Aggiorna altri campi da kwargs
        for key, value in kwargs.items():
            if hasattr(annotation, key):
                setattr(annotation, key, value)

        # Aggiorna timestamp modifica
        annotation.modified_at = datetime.now().isoformat()

        # Salva
        self._save_annotations(video_id)

        return annotation

    def delete_annotation(self, video_id: str, annotation_id: str) -> bool:
        """
        Elimina annotation

        Args:
            video_id: ID del video
            annotation_id: ID annotation

        Returns:
            True se eliminata, False se non trovata
        """
        if video_id not in self.annotations_cache:
            self._load_annotations(video_id)

        annotations = self.annotations_cache.get(video_id, [])

        # Trova e rimuovi
        for i, annotation in enumerate(annotations):
            if annotation.id == annotation_id:
                annotations.pop(i)
                self._save_annotations(video_id)
                return True

        return False

    def delete_all_annotations(self, video_id: str) -> int:
        """
        Elimina tutte le annotations di un video

        Returns:
            Numero di annotations eliminate
        """
        count = len(self.annotations_cache.get(video_id, []))

        # Rimuovi da cache
        if video_id in self.annotations_cache:
            del self.annotations_cache[video_id]

        # Rimuovi file
        annotation_file = self._get_annotation_file(video_id)
        if annotation_file.exists():
            annotation_file.unlink()

        return count

    def get_annotations_by_technique(self, video_id: str, technique_name: str) -> List[FrameAnnotation]:
        """Ottieni annotations per una tecnica specifica"""
        annotations = self.get_annotations(video_id)
        return [a for a in annotations if a.technique_name == technique_name]

    def get_annotations_by_tag(self, video_id: str, tag: str) -> List[FrameAnnotation]:
        """Ottieni annotations con un tag specifico"""
        annotations = self.get_annotations(video_id)
        return [a for a in annotations if tag in a.tags]

    def get_statistics(self, video_id: str) -> Dict[str, Any]:
        """
        Ottieni statistiche annotations per video

        Returns:
            Dictionary con statistiche
        """
        annotations = self.get_annotations(video_id)

        # Conta per tipo
        type_counts = {}
        for annotation in annotations:
            type_name = annotation.annotation_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        # Autori unici
        authors = set(a.author for a in annotations)

        # Frame con annotations
        annotated_frames = set(a.frame_number for a in annotations)

        return {
            'total_annotations': len(annotations),
            'by_type': type_counts,
            'unique_authors': len(authors),
            'authors': list(authors),
            'annotated_frames': len(annotated_frames),
            'first_annotation': annotations[0].created_at if annotations else None,
            'last_annotation': annotations[-1].created_at if annotations else None
        }

    def export_to_json(self, video_id: str, output_path: Optional[str] = None) -> str:
        """
        Esporta annotations in formato JSON

        Args:
            video_id: ID del video
            output_path: Path output (opzionale, default: auto-generato)

        Returns:
            Path al file esportato
        """
        annotations = self.get_annotations(video_id)

        export_data = {
            'video_id': video_id,
            'export_date': datetime.now().isoformat(),
            'total_annotations': len(annotations),
            'annotations': [a.to_dict() for a in annotations],
            'statistics': self.get_statistics(video_id)
        }

        if output_path is None:
            output_path = self.storage_dir / f"{video_id}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def export_to_csv(self, video_id: str, output_path: Optional[str] = None) -> str:
        """
        Esporta annotations in formato CSV

        Args:
            video_id: ID del video
            output_path: Path output (opzionale)

        Returns:
            Path al file esportato
        """
        import csv

        annotations = self.get_annotations(video_id)

        if output_path is None:
            output_path = self.storage_dir / f"{video_id}_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                'ID', 'Frame', 'Timestamp', 'Type', 'Content',
                'Author', 'Created', 'Technique', 'Tags'
            ])

            # Rows
            for a in annotations:
                writer.writerow([
                    a.id,
                    a.frame_number,
                    f"{a.timestamp:.3f}",
                    a.annotation_type.value,
                    a.content,
                    a.author,
                    a.created_at,
                    a.technique_name or '',
                    ';'.join(a.tags)
                ])

        return str(output_path)

    def import_from_json(self, json_path: str) -> int:
        """
        Importa annotations da file JSON

        Args:
            json_path: Path al file JSON

        Returns:
            Numero di annotations importate
        """
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        video_id = data['video_id']
        annotations_data = data['annotations']

        # Converte e aggiungi
        count = 0
        for ann_data in annotations_data:
            annotation = FrameAnnotation.from_dict(ann_data)

            # Aggiungi a cache
            if video_id not in self.annotations_cache:
                self.annotations_cache[video_id] = []

            self.annotations_cache[video_id].append(annotation)
            count += 1

        # Salva
        self._save_annotations(video_id)

        return count

    def _load_annotations(self, video_id: str) -> None:
        """Carica annotations da disco"""
        annotation_file = self._get_annotation_file(video_id)

        if not annotation_file.exists():
            self.annotations_cache[video_id] = []
            return

        try:
            with open(annotation_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Converti da dict a FrameAnnotation
            annotations = [FrameAnnotation.from_dict(a) for a in data]
            self.annotations_cache[video_id] = annotations

        except Exception as e:
            print(f"⚠️ Errore caricamento annotations per {video_id}: {e}")
            self.annotations_cache[video_id] = []

    def _save_annotations(self, video_id: str) -> None:
        """Salva annotations su disco"""
        annotation_file = self._get_annotation_file(video_id)

        annotations = self.annotations_cache.get(video_id, [])

        # Converti a dict per JSON
        data = [a.to_dict() for a in annotations]

        with open(annotation_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# Singleton per accesso globale
_annotation_manager_instance: Optional[AnnotationManager] = None


def get_annotation_manager(storage_dir: str = "./annotations") -> AnnotationManager:
    """
    Ottieni singleton AnnotationManager

    Args:
        storage_dir: Directory storage (solo prima chiamata)

    Returns:
        AnnotationManager instance
    """
    global _annotation_manager_instance

    if _annotation_manager_instance is None:
        _annotation_manager_instance = AnnotationManager(storage_dir)

    return _annotation_manager_instance

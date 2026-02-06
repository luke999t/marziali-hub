"""
Knowledge Base Manager - JSON RAG Merge System
================================================

Gestisce merge intelligente di JSON RAG multipli con:
- Deduplicazione automatica
- Risoluzione conflitti
- Merge incrementale
- Stats e validazione

Author: AI Assistant
Date: 2025-11-06
"""

import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class KnowledgeBaseManager:
    """
    Gestisce merge di JSON RAG multipli con deduplicazione intelligente

    Supporta:
    - forms: Kata, taolu, forme complete
    - sequences: Sequenze tecniche
    - patterns: Pattern di movimento
    - qa_pairs: Q&A dataset
    """

    def __init__(self, output_dir: Path = None):
        self.output_dir = output_dir or Path("knowledge_base_martial_arts")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Storage interno
        self.forms = []
        self.sequences = []
        self.patterns = []
        self.qa_pairs = []

        # Tracking deduplicazione
        self.forms_hashes = set()
        self.sequences_hashes = set()
        self.patterns_hashes = set()
        self.qa_hashes = set()

        # Stats
        self.stats = {
            'total_loaded': 0,
            'duplicates_removed': 0,
            'conflicts_resolved': 0,
            'sources_merged': 0
        }

    def _calculate_hash(self, item: Dict[str, Any], item_type: str) -> str:
        """
        Calcola hash univoco per item (per deduplicazione)

        Args:
            item: Dizionario da hashare
            item_type: 'form', 'sequence', 'pattern', 'qa'

        Returns:
            Hash MD5 stringa
        """
        if item_type == 'form':
            # Hash basato su: name + style + duration
            key = f"{item.get('name', '')}_{item.get('style', '')}_{item.get('duration', 0)}"

        elif item_type == 'sequence':
            # Hash basato su: name + techniques
            techs = sorted(item.get('techniques', []))
            key = f"{item.get('name', '')}_{','.join(techs)}"

        elif item_type == 'pattern':
            # Hash basato su: name + pattern_type
            key = f"{item.get('name', '')}_{item.get('pattern_type', '')}"

        elif item_type == 'qa':
            # Hash basato su: question (ignora variazioni minori)
            question = item.get('question_it', '') or item.get('question', '')
            key = question.lower().strip()

        else:
            # Fallback: JSON completo
            key = json.dumps(item, sort_keys=True)

        return hashlib.md5(key.encode('utf-8')).hexdigest()

    def _merge_item_attributes(self, existing: Dict, new: Dict, item_type: str) -> Dict:
        """
        Merge attributi di 2 item duplicati (risoluzione conflitti)

        Strategia:
        - Se attributo manca in existing, prendi da new
        - Se attributo presente in entrambi, usa quello più ricco
        - Arrays: merge senza duplicati
        - Numeri: prendi max (assume miglioramento)
        """
        merged = existing.copy()

        for key, new_value in new.items():
            if key not in merged or merged[key] is None:
                # Attributo mancante, aggiungi
                merged[key] = new_value

            elif isinstance(new_value, list):
                # Array: merge senza duplicati
                existing_list = merged[key] if isinstance(merged[key], list) else []
                merged[key] = list(set(existing_list + new_value))

            elif isinstance(new_value, (int, float)):
                # Numero: prendi max (assume miglioramento)
                merged[key] = max(merged[key], new_value)

            elif isinstance(new_value, str) and len(new_value) > len(str(merged[key])):
                # Stringa: prendi la più lunga (assume più dettaglio)
                merged[key] = new_value

            elif isinstance(new_value, dict):
                # Dict: merge ricorsivo
                merged[key] = self._merge_dicts(merged[key], new_value)

        # Aggiungi metadata merge
        if 'merged_sources' not in merged:
            merged['merged_sources'] = []

        merged['merged_sources'].append({
            'timestamp': datetime.now().isoformat(),
            'source': new.get('source', 'unknown')
        })

        return merged

    def _merge_dicts(self, dict1: Dict, dict2: Dict) -> Dict:
        """Merge ricorsivo di 2 dict"""
        merged = dict1.copy()

        for key, value in dict2.items():
            if key not in merged:
                merged[key] = value
            elif isinstance(value, dict) and isinstance(merged[key], dict):
                merged[key] = self._merge_dicts(merged[key], value)
            elif isinstance(value, list) and isinstance(merged[key], list):
                merged[key] = list(set(merged[key] + value))
            else:
                # Keep existing
                pass

        return merged

    def load_json(self, json_path: Path, source_name: str = None) -> Dict[str, int]:
        """
        Carica JSON RAG e merge con knowledge base esistente

        Args:
            json_path: Path al JSON da caricare
            source_name: Nome sorgente per tracking

        Returns:
            Dict con stats: {'forms': N, 'sequences': N, 'duplicates': N}
        """
        logger.info(f"Loading JSON: {json_path}")

        if not json_path.exists():
            logger.error(f"File not found: {json_path}")
            return {'error': 'File not found'}

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        source = source_name or json_path.stem
        stats_local = {'forms': 0, 'sequences': 0, 'patterns': 0, 'qa_pairs': 0, 'duplicates': 0}

        # Process forms
        for form in data.get('forms', []):
            form['source'] = source
            form_hash = self._calculate_hash(form, 'form')

            if form_hash in self.forms_hashes:
                # Duplicato: merge attributes
                existing_idx = next((i for i, f in enumerate(self.forms)
                                   if self._calculate_hash(f, 'form') == form_hash), None)
                if existing_idx is not None:
                    self.forms[existing_idx] = self._merge_item_attributes(
                        self.forms[existing_idx], form, 'form'
                    )
                    self.stats['conflicts_resolved'] += 1
                stats_local['duplicates'] += 1
            else:
                self.forms.append(form)
                self.forms_hashes.add(form_hash)
                stats_local['forms'] += 1

        # Process sequences
        for seq in data.get('sequences', []):
            seq['source'] = source
            seq_hash = self._calculate_hash(seq, 'sequence')

            if seq_hash in self.sequences_hashes:
                existing_idx = next((i for i, s in enumerate(self.sequences)
                                   if self._calculate_hash(s, 'sequence') == seq_hash), None)
                if existing_idx is not None:
                    self.sequences[existing_idx] = self._merge_item_attributes(
                        self.sequences[existing_idx], seq, 'sequence'
                    )
                    self.stats['conflicts_resolved'] += 1
                stats_local['duplicates'] += 1
            else:
                self.sequences.append(seq)
                self.sequences_hashes.add(seq_hash)
                stats_local['sequences'] += 1

        # Process patterns
        for pattern in data.get('patterns', []):
            pattern['source'] = source
            pattern_hash = self._calculate_hash(pattern, 'pattern')

            if pattern_hash in self.patterns_hashes:
                existing_idx = next((i for i, p in enumerate(self.patterns)
                                   if self._calculate_hash(p, 'pattern') == pattern_hash), None)
                if existing_idx is not None:
                    self.patterns[existing_idx] = self._merge_item_attributes(
                        self.patterns[existing_idx], pattern, 'pattern'
                    )
                    self.stats['conflicts_resolved'] += 1
                stats_local['duplicates'] += 1
            else:
                self.patterns.append(pattern)
                self.patterns_hashes.add(pattern_hash)
                stats_local['patterns'] += 1

        # Process Q&A pairs
        for qa in data.get('qa_pairs', []):
            qa['source'] = source
            qa_hash = self._calculate_hash(qa, 'qa')

            if qa_hash in self.qa_hashes:
                existing_idx = next((i for i, q in enumerate(self.qa_pairs)
                                   if self._calculate_hash(q, 'qa') == qa_hash), None)
                if existing_idx is not None:
                    self.qa_pairs[existing_idx] = self._merge_item_attributes(
                        self.qa_pairs[existing_idx], qa, 'qa'
                    )
                    self.stats['conflicts_resolved'] += 1
                stats_local['duplicates'] += 1
            else:
                self.qa_pairs.append(qa)
                self.qa_hashes.add(qa_hash)
                stats_local['qa_pairs'] += 1

        # Update global stats
        self.stats['total_loaded'] += sum([v for k, v in stats_local.items() if k != 'duplicates'])
        self.stats['duplicates_removed'] += stats_local['duplicates']
        self.stats['sources_merged'] += 1

        logger.info(f"Loaded: {stats_local}")

        return stats_local

    def load_directory(self, directory: Path, pattern: str = "*.json") -> Dict[str, Any]:
        """
        Carica tutti i JSON da una directory

        Args:
            directory: Path directory
            pattern: Pattern file (default: *.json)

        Returns:
            Dict con stats aggregate
        """
        logger.info(f"Loading directory: {directory}")

        json_files = list(directory.glob(pattern))
        logger.info(f"Found {len(json_files)} JSON files")

        total_stats = defaultdict(int)

        for json_file in json_files:
            try:
                stats = self.load_json(json_file, source_name=json_file.stem)
                for key, value in stats.items():
                    total_stats[key] += value
            except Exception as e:
                logger.error(f"Error loading {json_file}: {e}")

        return dict(total_stats)

    def export_merged(self, output_path: Path = None) -> Path:
        """
        Esporta knowledge base merged in JSON

        Args:
            output_path: Path output (default: knowledge_base_martial_arts/merged_knowledge.json)

        Returns:
            Path file esportato
        """
        if output_path is None:
            output_path = self.output_dir / "merged_knowledge.json"

        merged_data = {
            'version': '1.0',
            'creation_date': datetime.now().isoformat(),
            'metadata': {
                'total_forms': len(self.forms),
                'total_sequences': len(self.sequences),
                'total_patterns': len(self.patterns),
                'total_qa_pairs': len(self.qa_pairs),
                'total_items': len(self.forms) + len(self.sequences) + len(self.patterns) + len(self.qa_pairs),
                'sources_merged': self.stats['sources_merged'],
                'duplicates_removed': self.stats['duplicates_removed'],
                'conflicts_resolved': self.stats['conflicts_resolved']
            },
            'forms': self.forms,
            'sequences': self.sequences,
            'patterns': self.patterns,
            'qa_pairs': self.qa_pairs
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, indent=2, ensure_ascii=False)

        logger.info(f"Exported merged knowledge base to: {output_path}")
        logger.info(f"Total items: {merged_data['metadata']['total_items']}")

        return output_path

    def get_stats(self) -> Dict[str, Any]:
        """Ottieni statistiche dettagliate"""

        # Aggregate styles
        styles = defaultdict(int)
        for form in self.forms:
            style = form.get('style', 'unknown')
            styles[style] += 1

        for seq in self.sequences:
            style = seq.get('style', 'unknown')
            styles[style] += 1

        # Aggregate difficulties
        difficulties = defaultdict(int)
        for qa in self.qa_pairs:
            diff = qa.get('difficulty', 'unknown')
            difficulties[diff] += 1

        # Sources
        sources = set()
        for item in self.forms + self.sequences + self.patterns + self.qa_pairs:
            sources.add(item.get('source', 'unknown'))

        return {
            'summary': {
                'total_forms': len(self.forms),
                'total_sequences': len(self.sequences),
                'total_patterns': len(self.patterns),
                'total_qa_pairs': len(self.qa_pairs),
                'total_items': len(self.forms) + len(self.sequences) + len(self.patterns) + len(self.qa_pairs)
            },
            'merge_stats': self.stats,
            'styles': dict(styles),
            'difficulties': dict(difficulties),
            'sources': list(sources),
            'total_styles': len(styles),
            'total_sources': len(sources)
        }

    def validate_knowledge_base(self) -> Dict[str, List[str]]:
        """
        Valida knowledge base per errori comuni

        Returns:
            Dict con warnings/errors per categoria
        """
        issues = {
            'errors': [],
            'warnings': []
        }

        # Check forms
        for i, form in enumerate(self.forms):
            if 'name' not in form or not form['name']:
                issues['errors'].append(f"Form #{i}: missing 'name'")

            if 'style' not in form:
                issues['warnings'].append(f"Form #{i} ({form.get('name', 'unknown')}): missing 'style'")

            if 'techniques' in form and not isinstance(form['techniques'], list):
                issues['errors'].append(f"Form #{i}: 'techniques' is not a list")

        # Check sequences
        for i, seq in enumerate(self.sequences):
            if 'name' not in seq or not seq['name']:
                issues['errors'].append(f"Sequence #{i}: missing 'name'")

            if 'techniques' not in seq or len(seq.get('techniques', [])) == 0:
                issues['warnings'].append(f"Sequence #{i} ({seq.get('name', 'unknown')}): no techniques")

        # Check Q&A
        for i, qa in enumerate(self.qa_pairs):
            if 'question_it' not in qa and 'question' not in qa:
                issues['errors'].append(f"Q&A #{i}: missing question")

            if 'answer_it' not in qa and 'answer' not in qa:
                issues['errors'].append(f"Q&A #{i}: missing answer")

            if 'category' not in qa:
                issues['warnings'].append(f"Q&A #{i}: missing 'category'")

        logger.info(f"Validation: {len(issues['errors'])} errors, {len(issues['warnings'])} warnings")

        return issues

    def preview_merge(self, json_path: Path) -> Dict[str, Any]:
        """
        Preview merge senza applicarlo (dry-run)

        Returns:
            Dict con preview stats e conflicts
        """
        logger.info(f"Preview merge: {json_path}")

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        preview = {
            'new_forms': 0,
            'new_sequences': 0,
            'new_patterns': 0,
            'new_qa_pairs': 0,
            'duplicates': [],
            'conflicts': []
        }

        # Check forms
        for form in data.get('forms', []):
            form_hash = self._calculate_hash(form, 'form')
            if form_hash in self.forms_hashes:
                preview['duplicates'].append({
                    'type': 'form',
                    'name': form.get('name', 'unknown'),
                    'action': 'merge_attributes'
                })
            else:
                preview['new_forms'] += 1

        # Check sequences
        for seq in data.get('sequences', []):
            seq_hash = self._calculate_hash(seq, 'sequence')
            if seq_hash in self.sequences_hashes:
                preview['duplicates'].append({
                    'type': 'sequence',
                    'name': seq.get('name', 'unknown'),
                    'action': 'merge_attributes'
                })
            else:
                preview['new_sequences'] += 1

        # Check patterns
        for pattern in data.get('patterns', []):
            pattern_hash = self._calculate_hash(pattern, 'pattern')
            if pattern_hash in self.patterns_hashes:
                preview['duplicates'].append({
                    'type': 'pattern',
                    'name': pattern.get('name', 'unknown'),
                    'action': 'merge_attributes'
                })
            else:
                preview['new_patterns'] += 1

        # Check Q&A
        for qa in data.get('qa_pairs', []):
            qa_hash = self._calculate_hash(qa, 'qa')
            if qa_hash in self.qa_hashes:
                preview['duplicates'].append({
                    'type': 'qa',
                    'question': qa.get('question_it', qa.get('question', 'unknown'))[:50],
                    'action': 'merge_attributes'
                })
            else:
                preview['new_qa_pairs'] += 1

        logger.info(f"Preview: {preview['new_forms']} new forms, {len(preview['duplicates'])} duplicates")

        return preview


def main():
    """Test/Demo Knowledge Base Manager"""

    print("=" * 60)
    print("KNOWLEDGE BASE MANAGER - Demo")
    print("=" * 60)

    # Initialize manager
    manager = KnowledgeBaseManager()

    # Load Q&A dataset
    qa_path = Path(r"C:\Users\utente\Desktop\knowledge_base_martial_arts\qa_dataset.json")

    if qa_path.exists():
        print(f"\n>> Loading: {qa_path.name}")
        stats = manager.load_json(qa_path, source_name="qa_dataset")
        print(f"[OK] Loaded: {stats}")

    # Get stats
    print("\n" + "=" * 60)
    print("KNOWLEDGE BASE STATS")
    print("=" * 60)

    kb_stats = manager.get_stats()

    print(f"\nSummary:")
    for key, value in kb_stats['summary'].items():
        print(f"  {key}: {value}")

    print(f"\nStyles ({kb_stats['total_styles']}):")
    for style, count in sorted(kb_stats['styles'].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {style}: {count}")

    print(f"\nDifficulties:")
    for diff, count in kb_stats['difficulties'].items():
        print(f"  {diff}: {count}")

    print(f"\nMerge Stats:")
    for key, value in kb_stats['merge_stats'].items():
        print(f"  {key}: {value}")

    # Validate
    print("\n" + "=" * 60)
    print("VALIDATION")
    print("=" * 60)

    issues = manager.validate_knowledge_base()
    print(f"Errors: {len(issues['errors'])}")
    print(f"Warnings: {len(issues['warnings'])}")

    if issues['errors']:
        print("\n[ERROR] Errors:")
        for error in issues['errors'][:5]:
            print(f"  - {error}")

    if issues['warnings']:
        print("\n[WARN] Warnings:")
        for warning in issues['warnings'][:5]:
            print(f"  - {warning}")

    # Export
    print("\n" + "=" * 60)
    print("EXPORT")
    print("=" * 60)

    output_path = manager.export_merged()
    print(f"[OK] Exported to: {output_path}")
    print(f"Size: {output_path.stat().st_size / 1024:.1f} KB")

    print("\n" + "=" * 60)
    print("[OK] DEMO COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()

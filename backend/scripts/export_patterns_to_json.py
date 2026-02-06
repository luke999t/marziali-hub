"""
================================================================================
AI_MODULE: Export Martial Arts Patterns to JSON
AI_VERSION: 1.0.0
AI_DESCRIPTION: Converte martial_arts_patterns.py in JSON per RAG system
AI_BUSINESS: Abilita AI Coach knowledge search usando dati esistenti
AI_TEACHING: Script di migrazione dati - da Python dataclass a JSON per RAG
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
================================================================================

Questo script:
1. Importa i pattern esistenti da martial_arts_patterns.py
2. Li converte in formato JSON ottimizzato per RAG retrieval
3. Crea file separati per ogni stile + file combinato
4. Aggiunge metadati per AI agent indexing
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Aggiungi path backend per import
backend_path = Path(__file__).parent.parent
sys.path.insert(0, str(backend_path))

from services.video_studio.martial_arts_patterns import (
    MARTIAL_ARTS_DATABASE,
    MartialArtStyle,
    TechniquePattern,
    get_all_patterns,
    get_database_stats
)


def pattern_to_dict(pattern_id: str, pattern: TechniquePattern) -> Dict[str, Any]:
    """Converte TechniquePattern in dizionario JSON-serializable"""
    return {
        "id": pattern_id,
        "name": pattern.name,
        "style": pattern.style.value,
        "description": pattern.description,
        "keywords": pattern.keywords,
        "velocity_profile": pattern.velocity_profile,
        "temporal_signature": pattern.temporal_signature,
        "duration_range": list(pattern.duration_range),
        "key_landmarks": pattern.key_landmarks,
        "angle_ranges": pattern.angle_ranges,
        "hand_positions": pattern.hand_positions,
        "distance_ratios": {k: list(v) for k, v in pattern.distance_ratios.items()},
        "confidence_threshold": pattern.confidence_threshold,
        # Campo ottimizzato per RAG text search
        "text_for_rag": f"{pattern.name} - {pattern.description}. Keywords: {', '.join(pattern.keywords)}"
    }


def export_techniques_by_style(output_dir: Path) -> int:
    """Esporta tecniche separate per stile"""
    total_exported = 0

    for style, patterns in MARTIAL_ARTS_DATABASE.items():
        style_data = {
            "_metadata": {
                "type": "martial_arts_techniques",
                "style": style.value,
                "style_name": style.name,
                "source": "martial_arts_patterns.py",
                "exported_at": datetime.now().isoformat(),
                "pattern_count": len(patterns),
                "ai_indexable": True,
                "rag_enabled": True
            },
            "techniques": []
        }

        for pattern_id, pattern in patterns.items():
            pattern_dict = pattern_to_dict(pattern_id, pattern)
            style_data["techniques"].append(pattern_dict)

        # Salva file per stile
        output_file = output_dir / f"{style.value}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(style_data, f, indent=2, ensure_ascii=False)

        print(f"  [OK] {style.value}.json - {len(patterns)} tecniche")
        total_exported += len(patterns)

    return total_exported


def export_combined_for_rag(output_dir: Path) -> int:
    """Esporta file combinato ottimizzato per RAG retrieval"""
    all_techniques = []

    for style, patterns in MARTIAL_ARTS_DATABASE.items():
        for pattern_id, pattern in patterns.items():
            technique = {
                "id": pattern_id,
                "name": pattern.name,
                "style": pattern.style.value,
                "category": "technique",
                "description": pattern.description,
                "keywords": pattern.keywords,
                "velocity": pattern.velocity_profile,
                "duration_seconds": pattern.duration_range,
                # Testo concatenato per RAG vector search
                "content": f"""
Tecnica: {pattern.name}
Stile: {pattern.style.value}
Descrizione: {pattern.description}
Parole chiave: {', '.join(pattern.keywords)}
Velocità: {pattern.velocity_profile}
Pattern temporale: {pattern.temporal_signature}
""".strip(),
                "summary": f"{pattern.name} ({pattern.style.value}) - {pattern.description[:100]}..."
            }
            all_techniques.append(technique)

    combined_data = {
        "_metadata": {
            "type": "knowledge_base",
            "category": "techniques",
            "source": "martial_arts_patterns.py",
            "exported_at": datetime.now().isoformat(),
            "total_items": len(all_techniques),
            "ai_indexable": True,
            "rag_enabled": True,
            "supported_queries": [
                "technique search",
                "style filtering",
                "keyword matching",
                "semantic search"
            ]
        },
        "items": all_techniques
    }

    output_file = output_dir / "all_techniques.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(combined_data, f, indent=2, ensure_ascii=False)

    print(f"  [OK] all_techniques.json - {len(all_techniques)} tecniche totali")
    return len(all_techniques)


def export_forms(output_dir: Path) -> int:
    """Esporta forme/kata basate sui pattern esistenti"""
    forms_dir = output_dir.parent / "forms"
    forms_dir.mkdir(parents=True, exist_ok=True)

    # Estrai forme dai pattern (quelli con temporal_signature "cyclic" sono spesso forme)
    forms_data = {
        "_metadata": {
            "type": "martial_arts_forms",
            "source": "martial_arts_patterns.py",
            "exported_at": datetime.now().isoformat(),
            "ai_indexable": True
        },
        "forms": []
    }

    form_count = 0
    for style, patterns in MARTIAL_ARTS_DATABASE.items():
        for pattern_id, pattern in patterns.items():
            # Forme hanno tipicamente durata lunga e pattern ciclico
            if pattern.temporal_signature == "cyclic" or pattern.duration_range[1] > 10:
                form = {
                    "id": f"form_{pattern_id}",
                    "name": pattern.name,
                    "style": pattern.style.value,
                    "type": "sequence" if pattern.temporal_signature == "cyclic" else "kata",
                    "description": pattern.description,
                    "duration_range": list(pattern.duration_range),
                    "keywords": pattern.keywords
                }
                forms_data["forms"].append(form)
                form_count += 1

    output_file = forms_dir / "martial_arts_forms.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(forms_data, f, indent=2, ensure_ascii=False)

    print(f"  [OK] forms/martial_arts_forms.json - {form_count} forme")
    return form_count


def export_terminology(output_dir: Path) -> int:
    """Esporta terminologia estratta dai pattern"""
    terminology_dir = output_dir.parent / "terminology"
    terminology_dir.mkdir(parents=True, exist_ok=True)

    # Estrai termini dai nomi e keywords
    chinese_terms = []
    japanese_terms = []

    for style, patterns in MARTIAL_ARTS_DATABASE.items():
        for pattern_id, pattern in patterns.items():
            # Estrai nome cinese/giapponese dal nome (formato: "caratteri (pinyin - english)")
            name_parts = pattern.name.split("(")
            if len(name_parts) >= 2:
                original = name_parts[0].strip()
                romanization = name_parts[1].replace(")", "").strip()

                term = {
                    "original": original,
                    "romanization": romanization.split(" - ")[0] if " - " in romanization else romanization,
                    "english": romanization.split(" - ")[1] if " - " in romanization else "",
                    "style": pattern.style.value,
                    "context": "technique"
                }

                if style in [MartialArtStyle.TAI_CHI, MartialArtStyle.WING_CHUN,
                            MartialArtStyle.SHAOLIN, MartialArtStyle.BAGUA]:
                    chinese_terms.append(term)
                elif style == MartialArtStyle.KARATE:
                    japanese_terms.append(term)

    # Salva terminologia cinese
    chinese_data = {
        "_metadata": {
            "type": "terminology",
            "language": "chinese",
            "source": "martial_arts_patterns.py",
            "exported_at": datetime.now().isoformat()
        },
        "terms": chinese_terms
    }
    with open(terminology_dir / "chinese_terms.json", 'w', encoding='utf-8') as f:
        json.dump(chinese_data, f, indent=2, ensure_ascii=False)

    # Salva terminologia giapponese
    japanese_data = {
        "_metadata": {
            "type": "terminology",
            "language": "japanese",
            "source": "martial_arts_patterns.py",
            "exported_at": datetime.now().isoformat()
        },
        "terms": japanese_terms
    }
    with open(terminology_dir / "japanese_terms.json", 'w', encoding='utf-8') as f:
        json.dump(japanese_data, f, indent=2, ensure_ascii=False)

    print(f"  [OK] terminology/chinese_terms.json - {len(chinese_terms)} termini")
    print(f"  [OK] terminology/japanese_terms.json - {len(japanese_terms)} termini")

    return len(chinese_terms) + len(japanese_terms)


def main():
    """Esegue esportazione completa"""
    print("=" * 60)
    print("EXPORT MARTIAL ARTS PATTERNS TO JSON")
    print("=" * 60)

    # Directory output
    output_dir = backend_path / "services" / "video_studio" / "knowledge_base" / "techniques"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Statistiche iniziali
    stats = get_database_stats()
    print(f"\nSorgente: martial_arts_patterns.py")
    print(f"Stili disponibili: {stats['total_styles']}")
    print(f"Pattern totali: {stats['total_patterns']}")
    print(f"Pattern per stile: {stats['patterns_per_style']}")

    print("\n--- Esportazione Tecniche per Stile ---")
    techniques_count = export_techniques_by_style(output_dir)

    print("\n--- Esportazione File Combinato RAG ---")
    combined_count = export_combined_for_rag(output_dir)

    print("\n--- Esportazione Forme ---")
    forms_count = export_forms(output_dir)

    print("\n--- Esportazione Terminologia ---")
    terms_count = export_terminology(output_dir)

    print("\n" + "=" * 60)
    print("EXPORT COMPLETATO")
    print("=" * 60)
    print(f"Tecniche esportate: {techniques_count}")
    print(f"File combinato: {combined_count} items")
    print(f"Forme estratte: {forms_count}")
    print(f"Termini estratti: {terms_count}")
    print(f"\nOutput directory: {output_dir}")
    print("\nFile creati:")
    for f in output_dir.glob("*.json"):
        print(f"  - {f.name}")
    for f in (output_dir.parent / "forms").glob("*.json"):
        print(f"  - forms/{f.name}")
    for f in (output_dir.parent / "terminology").glob("*.json"):
        print(f"  - terminology/{f.name}")


if __name__ == "__main__":
    main()

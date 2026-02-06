#!/usr/bin/env python3
"""
🎓 AI_MODULE: Curriculum Seeder
🎓 AI_DESCRIPTION: Popola DB con 5 curricula di arti marziali di esempio
🎓 AI_BUSINESS: Consente testing e demo della funzionalità curricula
🎓 AI_TEACHING: Script standalone con raw SQL per insert idempotente

Uso:
    cd backend
    python scripts/seed_curricula.py
"""

import asyncio
import uuid
import json
import io
from datetime import datetime
from pathlib import Path
import sys

# Fix Windows console encoding for unicode output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import text
from core.database import AsyncSessionLocal


def generate_uuid() -> str:
    return str(uuid.uuid4())


def slugify(text: str) -> str:
    import re
    import unicodedata
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('ascii')
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')


# =============================================================================
# CURRICULA DATA (matching actual Curriculum model schema)
# =============================================================================

CURRICULA = [
    {
        "name": "Wing Chun - Forme Base",
        "description": "Percorso completo delle forme base del Wing Chun: Siu Nim Tao, Chum Kiu, Biu Jee. Impara le fondamenta di questa arte marziale del Sud della Cina.",
        "discipline": "WING_CHUN",
        "style_variant": "Ip Man Lineage",
        "visibility": "PUBLIC",
        "pricing_model": "FREE",
        "levels": [
            {"order": 0, "name": "Siu Nim Tao", "belt_color": "white", "description": "La prima forma: piccola idea. Fondamenti di struttura e centerline."},
            {"order": 1, "name": "Chum Kiu", "belt_color": "yellow", "description": "Cercare il ponte. Movimenti rotatori, passi e calci."},
            {"order": 2, "name": "Biu Jee", "belt_color": "green", "description": "Dita che trafiggono. Tecniche avanzate di recupero e attacco."},
        ]
    },
    {
        "name": "Karate Shotokan - Kata Fondamentali",
        "description": "I kata fondamentali dello Shotokan, dal Taikyoku ai Heian. Perfetto per principianti e intermedi che vogliono padroneggiare le forme classiche.",
        "discipline": "KARATE",
        "style_variant": "Shotokan",
        "visibility": "PUBLIC",
        "pricing_model": "INCLUDED_IN_SUBSCRIPTION",
        "levels": [
            {"order": 0, "name": "10° Kyu - Cintura Bianca", "belt_color": "white", "description": "Taikyoku Shodan, posizioni base, parate e attacchi fondamentali."},
            {"order": 1, "name": "9° Kyu - Cintura Bianca/Gialla", "belt_color": "white-yellow", "description": "Heian Shodan, combinazioni base di attacco e difesa."},
            {"order": 2, "name": "8° Kyu - Cintura Gialla", "belt_color": "yellow", "description": "Heian Nidan, tecniche di gamba e combinazioni avanzate."},
            {"order": 3, "name": "7° Kyu - Cintura Arancione", "belt_color": "orange", "description": "Heian Sandan, tecniche di presa e proiezione integrate."},
            {"order": 4, "name": "6° Kyu - Cintura Verde", "belt_color": "green", "description": "Heian Yondan, calci e movimenti fluidi avanzati."},
        ]
    },
    {
        "name": "Tai Chi Chen - 18 Movimenti",
        "description": "Forma breve Tai Chi stile Chen per principianti. Movimenti lenti e morbidi combinati con esplosioni di energia (fajin).",
        "discipline": "TAI_CHI",
        "style_variant": "Chen Style",
        "visibility": "PUBLIC",
        "pricing_model": "FREE",
        "levels": [
            {"order": 0, "name": "Fondamenti", "belt_color": "white", "description": "Postura, respirazione, Chan Si Jin (forza a spirale)."},
            {"order": 1, "name": "18 Movimenti Completi", "belt_color": "blue", "description": "Forma completa dei 18 movimenti con transizioni fluide."},
        ]
    },
    {
        "name": "Kung Fu Wushu - Combinazioni di Combattimento",
        "description": "Tecniche di combattimento e combinazioni per agonismo nel Wushu moderno. Calci acrobatici, pugni e forme libere.",
        "discipline": "WUSHU",
        "style_variant": "Sanda + Taolu",
        "visibility": "PUBLIC",
        "pricing_model": "INCLUDED_IN_SUBSCRIPTION",
        "levels": [
            {"order": 0, "name": "Fondamentali Sanda", "belt_color": "white", "description": "Guardia, footwork, pugni diretti e calci base."},
            {"order": 1, "name": "Combinazioni Intermedie", "belt_color": "blue", "description": "Combinazioni pugno-calcio, schivate e contrattacchi."},
            {"order": 2, "name": "Tecniche Avanzate", "belt_color": "red", "description": "Calci volanti, sweep, takedown e combinazioni avanzate."},
            {"order": 3, "name": "Competizione", "belt_color": "black", "description": "Strategie di gara, sparring controllato, preparazione agonistica."},
        ]
    },
    {
        "name": "Judo - Tecniche di Proiezione",
        "description": "Le tecniche di proiezione fondamentali del Gokyo no Waza. Dalle cadute (ukemi) fino alle proiezioni avanzate per cintura marrone.",
        "discipline": "JUDO",
        "style_variant": "Kodokan",
        "visibility": "PUBLIC",
        "pricing_model": "FREE",
        "levels": [
            {"order": 0, "name": "6° Kyu - Cintura Bianca", "belt_color": "white", "description": "Ukemi (cadute), O-Soto-Gari, De-Ashi-Harai, posizioni fondamentali."},
            {"order": 1, "name": "5° Kyu - Cintura Gialla", "belt_color": "yellow", "description": "Ippon-Seoi-Nage, Ko-Soto-Gari, Tai-Otoshi, randori base."},
            {"order": 2, "name": "4° Kyu - Cintura Arancione", "belt_color": "orange", "description": "Uchi-Mata, Harai-Goshi, Osae-Komi-Waza (immobilizzazioni)."},
            {"order": 3, "name": "3° Kyu - Cintura Verde", "belt_color": "green", "description": "Tomoe-Nage, Sumi-Gaeshi, combinazioni e transizioni ne-waza."},
        ]
    }
]


async def seed_curricula():
    """
    🎓 AI_MODULE: Seed Curricula
    🎓 AI_DESCRIPTION: Inserisce curricula di esempio nel database
    🎓 AI_BUSINESS: Abilita testing e demo del sistema curricula
    """
    print("\n" + "=" * 60)
    print("📚 SEED CURRICULA - Media Center Arti Marziali")
    print("=" * 60)

    async with AsyncSessionLocal() as db:
        try:
            created = 0
            skipped = 0
            levels_created = 0

            for curriculum_data in CURRICULA:
                name = curriculum_data["name"]
                slug = slugify(name)

                # Check se esiste già
                result = await db.execute(
                    text("SELECT id FROM curricula WHERE slug = :slug"),
                    {"slug": slug}
                )
                existing = result.fetchone()

                if existing:
                    print(f"  ⏭️  Già esistente: {name}")
                    skipped += 1
                    continue

                curriculum_id = generate_uuid()
                now = datetime.utcnow()

                # Settings di default
                settings = json.dumps({
                    "sequential_progression": True,
                    "min_days_between_levels": 30,
                    "exam_required_for_promotion": True,
                    "ai_feedback_enabled": True,
                    "teacher_review_required": False,
                    "allow_level_skip": False,
                    "max_exam_attempts": 3,
                    "certificate_auto_issue": True
                })

                await db.execute(text("""
                    INSERT INTO curricula (
                        id, name, slug, description,
                        discipline, style_variant,
                        owner_type, visibility, pricing_model,
                        currency, settings,
                        total_levels, total_enrollments, total_completions,
                        is_active, is_featured,
                        created_at, updated_at, published_at
                    ) VALUES (
                        :id, :name, :slug, :description,
                        :discipline, :style_variant,
                        :owner_type, :visibility, :pricing_model,
                        'EUR', :settings,
                        :total_levels, 0, 0,
                        true, false,
                        :created_at, :updated_at, :published_at
                    )
                """), {
                    "id": curriculum_id,
                    "name": name,
                    "slug": slug,
                    "description": curriculum_data["description"],
                    "discipline": curriculum_data["discipline"],
                    "style_variant": curriculum_data.get("style_variant"),
                    "owner_type": "PLATFORM",
                    "visibility": curriculum_data.get("visibility", "PUBLIC"),
                    "pricing_model": curriculum_data.get("pricing_model", "FREE"),
                    "settings": settings,
                    "total_levels": len(curriculum_data.get("levels", [])),
                    "created_at": now,
                    "updated_at": now,
                    "published_at": now,
                })
                created += 1
                print(f"  ✅ Creato: {name}")

                # Inserisci livelli
                for level in curriculum_data.get("levels", []):
                    level_id = generate_uuid()

                    # Requirements di default per ogni livello
                    requirements = json.dumps([
                        {
                            "type": "technique",
                            "name": f"Tecniche livello {level['order'] + 1}",
                            "description": level["description"],
                            "passing_score": 70
                        }
                    ])

                    await db.execute(text("""
                        INSERT INTO curriculum_levels (
                            id, curriculum_id, "order",
                            name, belt_color, description,
                            requirements, exam_type, passing_score,
                            reference_video_ids, is_free, is_active,
                            created_at, updated_at
                        ) VALUES (
                            :id, :curriculum_id, :order,
                            :name, :belt_color, :description,
                            :requirements, 'VIDEO_SUBMISSION', 70,
                            '[]', false, true,
                            :created_at, :updated_at
                        )
                    """), {
                        "id": level_id,
                        "curriculum_id": curriculum_id,
                        "order": level["order"],
                        "name": level["name"],
                        "belt_color": level.get("belt_color"),
                        "description": level.get("description"),
                        "requirements": requirements,
                        "created_at": now,
                        "updated_at": now,
                    })
                    levels_created += 1

            await db.commit()

            print("\n" + "=" * 60)
            print("✅ SEED COMPLETATO!")
            print(f"   📚 Curricula creati:  {created}")
            print(f"   📈 Livelli creati:    {levels_created}")
            print(f"   ⏭️  Saltati (già esistenti): {skipped}")
            print("=" * 60 + "\n")

        except Exception as e:
            await db.rollback()
            print(f"\n❌ ERRORE: {e}")
            import traceback
            traceback.print_exc()
            raise


if __name__ == "__main__":
    asyncio.run(seed_curricula())

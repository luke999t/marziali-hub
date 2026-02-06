"""
AI_MODULE: Avatar Seed Data
AI_DESCRIPTION: Popola il database con avatar iniziali ReadyPlayerMe
AI_TEACHING: Lo script di seed inserisce i 2 avatar scaricati da ReadyPlayerMe
             nel database, creando i record necessari per il funzionamento
             della galleria avatar nel frontend.
             Eseguire dopo la migration della tabella avatars.

USAGE:
    cd backend
    python scripts/seed_avatars.py
"""

import sys
import os
import uuid
from datetime import datetime
from pathlib import Path

# Aggiungi backend al path per import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.database import SessionLocal, engine, Base
from models.avatar import Avatar, AvatarStyle, AvatarRigType, AvatarLicenseType


SEED_AVATARS = [
    {
        "name": "Male Martial Artist",
        "description": "Avatar maschile ottimizzato per arti marziali. "
                       "Rig ReadyPlayerMe con supporto completo mani (21 bones per mano). "
                       "Adatto per karate, kung fu e tutte le discipline.",
        "style": AvatarStyle.GENERIC,
        "model_filename": "male_martial_artist.glb",
        "rig_type": AvatarRigType.READYPLAYERME,
        "bone_count": 65,
        "has_hand_bones": True,
        "license_type": AvatarLicenseType.CC_BY,
        "attribution": "ReadyPlayerMe - https://readyplayer.me - CC BY 4.0",
    },
    {
        "name": "Female Martial Artist",
        "description": "Avatar femminile ottimizzato per arti marziali. "
                       "Rig ReadyPlayerMe con supporto completo mani (21 bones per mano). "
                       "Adatto per taekwondo, judo e tutte le discipline.",
        "style": AvatarStyle.GENERIC,
        "model_filename": "female_martial_artist.glb",
        "rig_type": AvatarRigType.READYPLAYERME,
        "bone_count": 65,
        "has_hand_bones": True,
        "license_type": AvatarLicenseType.CC_BY,
        "attribution": "ReadyPlayerMe - https://readyplayer.me - CC BY 4.0",
    },
]


def seed_avatars():
    """Inserisce gli avatar seed nel database"""
    storage_path = Path(__file__).parent.parent / "storage" / "avatars" / "models"

    # Assicurati che le tabelle esistano
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    created = 0
    skipped = 0

    try:
        for avatar_data in SEED_AVATARS:
            # Controlla se esiste gia'
            existing = db.query(Avatar).filter(
                Avatar.name == avatar_data["name"]
            ).first()

            if existing:
                print(f"[SKIP] Avatar '{avatar_data['name']}' esiste gia' (id={existing.id})")
                skipped += 1
                continue

            # Verifica che il file GLB esista su disco
            model_path = storage_path / avatar_data["model_filename"]
            file_size = 0
            if model_path.exists():
                file_size = model_path.stat().st_size
                print(f"[OK] File trovato: {model_path} ({file_size} bytes)")
            else:
                print(f"[WARN] File non trovato: {model_path} - avatar creato senza file")

            avatar_id = uuid.uuid4()
            avatar = Avatar(
                id=avatar_id,
                name=avatar_data["name"],
                description=avatar_data["description"],
                style=avatar_data["style"],
                model_url=f"/api/v1/avatars/{avatar_id}/file",
                file_size_bytes=file_size,
                rig_type=avatar_data["rig_type"],
                bone_count=avatar_data["bone_count"],
                has_hand_bones=avatar_data["has_hand_bones"],
                is_public=True,
                is_active=True,
                license_type=avatar_data["license_type"],
                attribution=avatar_data["attribution"],
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )

            db.add(avatar)
            created += 1
            print(f"[CREATED] Avatar '{avatar_data['name']}' (id={avatar_id})")

        db.commit()
        print(f"\nSeed completato: {created} creati, {skipped} saltati")

    except Exception as e:
        db.rollback()
        print(f"\n[ERROR] Seed fallito: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("=" * 60)
    print("SEED AVATARS - Media Center Arti Marziali")
    print("=" * 60)
    seed_avatars()

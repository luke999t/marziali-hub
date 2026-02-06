"""
🔍 SCRIPT VERIFICA SETUP AVATAR
Esegui con: python scripts/verify_avatar_setup.py

Verifica:
1. Tabella avatars esiste
2. Avatar seed presenti
3. File GLB presenti
4. API raggiungibile
"""

import sys
import os
from pathlib import Path

# Aggiungi backend al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check_database():
    """Verifica tabella avatars e contenuto"""
    print("\n" + "="*60)
    print("1️⃣  VERIFICA DATABASE")
    print("="*60)
    
    try:
        from sqlalchemy import create_engine, text
        from core.config import settings
        
        engine = create_engine(settings.DATABASE_URL)
        
        with engine.connect() as conn:
            # Check tabella esiste
            result = conn.execute(text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'avatars'
                );
            """))
            exists = result.scalar()
            
            if not exists:
                print("❌ Tabella 'avatars' NON ESISTE!")
                print("   → Esegui: psql -U martial_user -d martial_arts_db -f migrations/008_add_avatars_table.sql")
                return False, 0
            
            print("✅ Tabella 'avatars' esiste")
            
            # Count records
            result = conn.execute(text("SELECT COUNT(*) FROM avatars"))
            count = result.scalar()
            
            if count == 0:
                print("⚠️  Tabella vuota - nessun avatar")
                print("   → Esegui: python scripts/seed_avatars.py")
                return True, 0
            
            print(f"✅ {count} avatar presenti nel database")
            
            # Lista avatar
            result = conn.execute(text("SELECT id, name, style FROM avatars LIMIT 5"))
            print("\n   Avatar trovati:")
            for row in result:
                print(f"   - {row[1]} (style: {row[2]}, id: {str(row[0])[:8]}...)")
            
            return True, count
            
    except Exception as e:
        print(f"❌ Errore connessione database: {e}")
        print("   → Verifica che PostgreSQL sia attivo")
        return False, 0


def check_glb_files():
    """Verifica file GLB presenti"""
    print("\n" + "="*60)
    print("2️⃣  VERIFICA FILE GLB")
    print("="*60)
    
    models_path = Path(__file__).parent.parent / "storage" / "avatars" / "models"
    
    if not models_path.exists():
        print(f"❌ Cartella non esiste: {models_path}")
        return []
    
    glb_files = list(models_path.glob("*.glb"))
    
    if not glb_files:
        print("❌ Nessun file .glb trovato!")
        return []
    
    print(f"✅ {len(glb_files)} file GLB trovati:")
    for f in glb_files:
        size_mb = f.stat().st_size / (1024 * 1024)
        print(f"   - {f.name} ({size_mb:.2f} MB)")
    
    return glb_files


def check_thumbnails():
    """Verifica thumbnails presenti"""
    print("\n" + "="*60)
    print("3️⃣  VERIFICA THUMBNAILS")
    print("="*60)
    
    thumbs_path = Path(__file__).parent.parent / "storage" / "avatars" / "thumbnails"
    
    if not thumbs_path.exists():
        print(f"⚠️  Cartella thumbnails non esiste: {thumbs_path}")
        thumbs_path.mkdir(parents=True, exist_ok=True)
        print("   → Creata cartella vuota")
        return []
    
    thumb_files = list(thumbs_path.glob("*.png")) + list(thumbs_path.glob("*.jpg"))
    
    if not thumb_files:
        print("⚠️  Nessun thumbnail trovato (opzionale)")
        return []
    
    print(f"✅ {len(thumb_files)} thumbnail trovati")
    return thumb_files


def check_api():
    """Verifica API raggiungibile"""
    print("\n" + "="*60)
    print("4️⃣  VERIFICA API BACKEND")
    print("="*60)
    
    try:
        import httpx
        
        response = httpx.get("http://localhost:8000/api/v1/avatars/", timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ API risponde - {data.get('total', len(data.get('items', [])))} avatar")
            return True
        else:
            print(f"⚠️  API risponde con status {response.status_code}")
            return False
            
    except httpx.ConnectError:
        print("❌ Backend non raggiungibile su localhost:8000")
        print("   → Avvia backend: python -m uvicorn main:app --port 8000")
        return False
    except Exception as e:
        print(f"⚠️  Errore test API: {e}")
        return False


def main():
    print("\n" + "🔍"*30)
    print("   VERIFICA SETUP AVATAR - Media Center")
    print("🔍"*30)
    
    # Esegui verifiche
    db_ok, avatar_count = check_database()
    glb_files = check_glb_files()
    thumbnails = check_thumbnails()
    api_ok = check_api()
    
    # Riepilogo
    print("\n" + "="*60)
    print("📊 RIEPILOGO")
    print("="*60)
    
    all_ok = True
    
    if not db_ok:
        print("❌ Database: PROBLEMA - esegui migration")
        all_ok = False
    elif avatar_count == 0:
        print("⚠️  Database: OK ma vuoto - esegui seed")
        all_ok = False
    else:
        print(f"✅ Database: OK ({avatar_count} avatar)")
    
    if not glb_files:
        print("❌ File GLB: MANCANTI")
        all_ok = False
    else:
        print(f"✅ File GLB: OK ({len(glb_files)} file)")
    
    if not thumbnails:
        print("⚠️  Thumbnails: Vuoto (opzionale, CODE 1 li creerà)")
    else:
        print(f"✅ Thumbnails: OK ({len(thumbnails)} file)")
    
    if not api_ok:
        print("⚠️  API: Non testata (backend spento)")
    else:
        print("✅ API: OK")
    
    print("\n" + "="*60)
    if all_ok:
        print("🎉 SETUP COMPLETO - Puoi lanciare i CODE!")
    else:
        print("⚠️  AZIONI RICHIESTE:")
        if not db_ok:
            print("   1. psql -U martial_user -d martial_arts_db -f migrations/008_add_avatars_table.sql")
        if db_ok and avatar_count == 0:
            print("   2. python scripts/seed_avatars.py")
        if not glb_files:
            print("   3. Scarica modelli GLB (vedi istruzioni precedenti)")
    print("="*60 + "\n")
    
    return all_ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

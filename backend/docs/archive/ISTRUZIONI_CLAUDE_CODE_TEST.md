# 🎯 ISTRUZIONI CLAUDE CODE - VERIFICA TEST SUITE

**Data:** 11 Gennaio 2026
**Progetto:** Media Center Arti Marziali
**Path:** `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend`

---

## OBIETTIVO

Verificare che le modifiche fatte ai test funzionino correttamente:
- **Pass rate target:** 95%
- **Coverage target:** 90%
- **Zero mock:** Nessun mock, solo backend reale
- **Database:** PostgreSQL reale

---

## STEP 1: VERIFICA PREREQUISITI

```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

# Verifica PostgreSQL attivo
docker ps | grep postgres

# Se non attivo, avvialo
docker-compose up -d postgres

# Attendi 10 secondi
timeout 10
```

---

## STEP 2: ESEGUI SCRIPT VERIFICA

```bash
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend

# Test rapido (solo file modificati)
python run_test_verification.py --quick

# Se tutto OK, test completo
python run_test_verification.py --full
```

---

## STEP 3: SE CI SONO ERRORI

### Errore: "PostgreSQL non disponibile"
```bash
docker-compose up -d postgres
# Attendi 30 secondi
python run_test_verification.py --quick
```

### Errore: "No published video found"
I test royalties richiedono almeno un video nel DB. Crea un video di test:
```bash
python -c "
import asyncio
from core.database import get_async_session, DATABASE_URL_ASYNC
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from models.video import Video, VideoStatus, VideoCategory, Difficulty
from models.maestro import Maestro
from models.user import User, UserTier
from uuid import uuid4

async def create_test_data():
    engine = create_async_engine(DATABASE_URL_ASYNC)
    async_session = async_sessionmaker(engine, class_=AsyncSession)
    
    async with async_session() as db:
        # Crea user
        user = User(
            id=uuid4(),
            email='test_maestro_seed@test.com',
            username='test_maestro_seed',
            hashed_password='\$2b\$12\$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.I4.VYl1G/WdHuy',
            tier=UserTier.PREMIUM,
            is_active=True
        )
        db.add(user)
        await db.flush()
        
        # Crea maestro
        maestro = Maestro(
            id=uuid4(),
            user_id=user.id,
            disciplines=['karate'],
            bio='Test maestro'
        )
        db.add(maestro)
        await db.flush()
        
        # Crea video
        video = Video(
            id=uuid4(),
            maestro_id=maestro.id,
            title='Test Video for Royalties',
            description='Video di test',
            category=VideoCategory.TECHNIQUE,
            difficulty=Difficulty.BEGINNER,
            duration=300,
            status=VideoStatus.READY
        )
        db.add(video)
        await db.commit()
        print(f'Video creato: {video.id}')

asyncio.run(create_test_data())
"
```

### Errore: "Foreign key violation"
Le fixture creano utenti con ID univoci. Se persiste:
```bash
# Reset tabelle test
python -c "
import asyncio
from core.database import DATABASE_URL_ASYNC
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

async def cleanup():
    engine = create_async_engine(DATABASE_URL_ASYNC)
    async with engine.begin() as conn:
        await conn.execute(text('DELETE FROM royalty_view_royalties WHERE created_at > NOW() - INTERVAL 1 DAY'))
        await conn.execute(text('DELETE FROM royalty_master_profiles WHERE created_at > NOW() - INTERVAL 1 DAY'))
    print('Cleanup completato')

asyncio.run(cleanup())
"
```

---

## STEP 4: REPORT FINALE

Quando i test passano, riporta:

```
✅ test_special_projects.py: XX passed, X failed
✅ test_royalties.py: XX passed, X failed
✅ Pass rate: XX%
✅ Zero mock: confermato
✅ PostgreSQL: connesso
```

---

## FILE MODIFICATI DA VERIFICARE

1. `tests/test_royalties.py`
   - [x] DATABASE_URL_ASYNC (PostgreSQL, non SQLite)
   - [x] Fixture test_user, test_maestro_user con utenti reali
   - [x] Fixture test_video cerca video esistente
   - [x] Zero mock

2. `tests/test_special_projects.py`
   - [x] DATABASE_URL_ASYNC (PostgreSQL, non SQLite)
   - [x] Fixture test_users con username e is_admin
   - [x] Zero mock

3. `pytest.ini`
   - [x] Marker e2e e system aggiunti

---

## COMANDI RAPIDI

```bash
# Solo test modificati
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
python -m pytest tests/test_royalties.py tests/test_special_projects.py -v --tb=short

# Verifica mock
grep -r "mock\|Mock\|patch" tests/test_royalties.py tests/test_special_projects.py

# Test con coverage
python -m pytest tests/test_royalties.py tests/test_special_projects.py --cov=modules --cov-report=term-missing
```

---

## CRITERI SUCCESSO

| Criterio | Target | Come verificare |
|----------|--------|-----------------|
| Pass rate | ≥95% | Output pytest |
| Zero mock | 0 violazioni | grep mock |
| PostgreSQL | Connesso | docker ps |
| Errori collection | 0 | pytest --collect-only |

---

**IMPORTANTE:** Non procedere con altri sviluppi finché pass rate < 95%

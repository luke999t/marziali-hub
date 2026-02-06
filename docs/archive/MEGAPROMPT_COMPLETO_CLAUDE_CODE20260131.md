# 🤖 MEGAPROMPT COMPLETO - MEDIA CENTER ARTI MARZIALI
## Per Claude Code - Versione DEFINITIVA
## Data: 31 Gennaio 2026

---

# SEZIONE 1: CONTESTO PROGETTO

## 📁 PATH E STRUTTURA

```
PROGETTO: Media Center Arti Marziali
PATH: C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\

├── backend\              # FastAPI + Python 3.11
│   ├── main.py           # Entry point
│   ├── routers\          # API endpoints (27 router)
│   ├── services\         # Business logic
│   │   ├── video_studio\
│   │   │   ├── multi_video_fusion.py    # ✅ NON TOCCARE
│   │   │   ├── skeleton_extraction_holistic.py  # ✅ NON TOCCARE
│   │   │   └── mix_generator.py         # ✅ NON TOCCARE
│   │   ├── anonymizer.py                # ✅ NON TOCCARE
│   │   └── blender_export.py            # ✅ NON TOCCARE
│   ├── models\           # SQLAlchemy models
│   ├── tests\            # Test suite
│   └── venv\             # Virtual environment
│
└── frontend\             # Next.js 14 + React + TypeScript
    ├── src\
    │   ├── app\          # Pages (App Router)
    │   └── components\
    └── package.json
```

## 🚀 COMANDI AVVIO

```powershell
# Backend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000

# Frontend  
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\frontend
npm run dev --port 3000
```

## ✅ STATO ATTUALE

| Area | Completamento | Note |
|------|---------------|------|
| Backend API | 92% test pass | 27 router attivi |
| Frontend | 87.5% | 28/32 pagine funzionanti |
| Skeleton extraction | 100% | MediaPipe Holistic 75 landmarks |
| Multi-video fusion | 100% | DTW + weighted averaging |
| Anonimizzazione | 100% | Forgetting by design |

---

# SEZIONE 2: REGOLE AI-FIRST SYSTEM V2.0

## 📋 DEFINIZIONE

L'approccio **AI-First System** indica una struttura nativa pensata per:
- Usare attivamente l'intelligenza artificiale come parte integrante
- Ottimizzare ogni modulo per interagire, apprendere o essere spiegato da AI

> **OBIETTIVO**: Tutti i moduli devono essere nativamente progettati per essere **tracciabili**, **descrivibili**, **modificabili**, **debuggabili** e **estendibili** da AI agent.

---

## 🎯 HEADER OBBLIGATORIO PER OGNI FILE

```python
# POSIZIONE: percorso/completo/del/file.py
"""
🎓 AI_MODULE: Nome Modulo
🎓 AI_DESCRIPTION: Descrizione in una riga di cosa fa
🎓 AI_BUSINESS: Valore business specifico e KPI impattati
🎓 AI_TEACHING: Concetto tecnico principale da imparare

🔄 ALTERNATIVE_VALUTATE:
- Opzione A: Scartata perché [motivo tecnico + business]
- Opzione B: Scartata perché [motivo tecnico + business]  
- Opzione C: Scartata perché [motivo tecnico + business]

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Vantaggio tecnico 1: [spiegazione dettagliata]
- Vantaggio business 1: [impatto quantificato]
- Vantaggio scalabilità: [considerazioni future]
- Trade-off accettati: [svantaggi consapevoli]

📊 BUSINESS_IMPACT:
- Metrica 1: Valore baseline → Target (+X% improvement)
- Metrica 2: Costo attuale → Costo target (-Y% reduction)  
- Revenue impact: €X per [unità di misura]

⚖️ COMPLIANCE_&_CONSTRAINTS:
- Regulatory: [GDPR, CCPA, industry standards]
- Technical: [performance, security, scalability limits]
- Business: [budget, timeline, resource constraints]

🔗 INTEGRATION_DEPENDENCIES:
- Upstream: [servizi che questo modulo usa]
- Downstream: [servizi che usano questo modulo]
- Data: [database, cache, external APIs]

🧪 TESTING_STRATEGY:
- Unit tests: [coverage %, key scenarios]
- Integration tests: [critical paths]
- Performance tests: [benchmarks, load testing]

📈 MONITORING_&_OBSERVABILITY:
- Key metrics: [cosa monitoriamo in production]
- Alerts: [quando scattano gli allarmi]
- Logging: [cosa loggiamo per debugging]
"""
```

---

## 📝 TAG DICTIONARY (OBBLIGATORIO PER OGNI MODULO)

```python
TAG_DICTIONARY = {
    "ai_concepts": [
        "machine-learning", "natural-language-processing", "computer-vision",
        "recommendation-systems", "anomaly-detection", "predictive-modeling"
    ],
    "business_rules": [
        "gdpr-compliance", "revenue-optimization", "user-experience",
        "cost-efficiency", "scalability-requirements", "security-protocols"
    ],
    "integration_points": [
        "database-connections", "api-endpoints", "messaging-queues",
        "caching-layers", "monitoring-systems", "external-services"
    ],
    "error_patterns": [
        "connection-timeouts", "data-validation-failures", "rate-limits",
        "authentication-errors", "resource-exhaustion", "dependency-failures"
    ],
    "optimization_targets": [
        "response-time", "throughput", "memory-usage", "cpu-utilization",
        "accuracy-metrics", "user-satisfaction", "conversion-rates"
    ]
}
```

---

## 💬 COMMENTI DIDATTICI - ESEMPI

```python
# ❌ ESEMPIO SBAGLIATO - Commento inutile
response = requests.get(url)  # Fa una GET request

# ✅ ESEMPIO CORRETTO - Spiega il PERCHÉ
# Requests con timeout 30s perché YouTube a volte ritarda
# la risposta di 20s per detectare bot. Timeout default 
# di 10s causerebbe 40% false negative
response = requests.get(url, timeout=30)

# ✅ ALTRO ESEMPIO - Decision making
# OpenCV invece di Pillow perché:
# 1. Hardware acceleration su GPU quando disponibile
# 2. 5x più veloce su batch processing
# 3. Supporta codec video nativamente
import cv2  # Non PIL/Pillow

# ✅ Business logic spiegata
# Threshold 0.7 derivato da analisi 500 video kata:
# - 0.6 = troppi falsi positivi (30% frames inutili)
# - 0.8 = perdiamo transizioni tecniche (miss 20% key moments)
SCENE_CHANGE_THRESHOLD = 0.7
```

---

# SEZIONE 3: ENTERPRISE TEST SUITE

## 🎯 OBIETTIVI OBBLIGATORI

| Metrica | Target | Descrizione |
|---------|--------|-------------|
| **Coverage** | ≥ 90% | Copertura codice minima |
| **Pass Rate** | ≥ 95% | Test che devono passare |
| **Categories** | 6 tipi | Unit, Integration, Security, Performance, Stress, Holistic |

---

## 📊 STRUTTURA TEST SUITE ENTERPRISE

```python
"""
🎓 AI_MODULE: Enterprise Test Suite
🎓 AI_DESCRIPTION: Suite completa test enterprise-grade
🎓 AI_BUSINESS: Zero bug in produzione, compliance garantita
🎓 AI_TEACHING: Testing piramidale con focus su integrazione reale
"""

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 1: UNIT TESTS (40% della suite)
# ═══════════════════════════════════════════════════════════════
# - Testano singole funzioni/metodi in isolamento
# - Veloci (< 100ms ciascuno)
# - Coprono edge cases e validazioni input

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 2: INTEGRATION TESTS (30% della suite)
# ═══════════════════════════════════════════════════════════════
# - Testano interazione tra moduli
# - Usano database REALE (test DB, non mock)
# - Verificano flussi end-to-end

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 3: SECURITY TESTS (10% della suite)
# ═══════════════════════════════════════════════════════════════
# - SQL Injection prevention
# - XSS prevention
# - CSRF protection
# - Authentication/Authorization
# - OWASP Top 10 compliance

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 4: PERFORMANCE TESTS (10% della suite)
# ═══════════════════════════════════════════════════════════════
# - Response time < 200ms per API standard
# - Response time < 2s per operazioni complesse
# - Memory leak detection
# - CPU usage profiling

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 5: STRESS TESTS (5% della suite)
# ═══════════════════════════════════════════════════════════════
# - Concurrent users simulation
# - Rate limiting verification
# - Graceful degradation under load
# - Recovery after failure

# ═══════════════════════════════════════════════════════════════
# CATEGORIA 6: HOLISTIC TESTS (5% della suite)
# ═══════════════════════════════════════════════════════════════
# - User journey complete
# - Business workflow validation
# - Cross-module consistency
# - Data integrity verification
```

---

## 📋 TEMPLATE TEST FILE

```python
# POSIZIONE: backend/tests/test_[modulo].py
"""
🎓 AI_MODULE: Test Suite per [Nome Modulo]
🎓 AI_DESCRIPTION: Test completi per [cosa testa]
🎓 AI_BUSINESS: Garantisce [valore business]
🎓 AI_TEACHING: [Pattern di testing insegnato]

📊 COVERAGE TARGET: 90%+
📊 PASS RATE TARGET: 95%+

🧪 TEST CATEGORIES:
- Unit: [X test]
- Integration: [Y test]
- Security: [Z test]
- Performance: [W test]
"""

import pytest
import httpx
from datetime import datetime

# ═══════════════════════════════════════════════════════════════
# FIXTURES - Setup condiviso
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def api_client():
    """
    Client HTTP per chiamate API REALI.
    NON è un mock. Chiama il backend vero.
    """
    with httpx.Client(base_url="http://localhost:8000", timeout=30.0) as client:
        yield client


@pytest.fixture
def auth_headers(api_client):
    """
    Headers con token JWT REALE per test autenticati.
    """
    response = api_client.post("/api/v1/auth/login", json={
        "email": "admin@mediacenter.it",
        "password": "Test123!"
    })
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════════
# UNIT TESTS
# ═══════════════════════════════════════════════════════════════

class TestUnit:
    """Unit tests per funzioni isolate"""
    
    def test_validation_valid_input(self):
        """Verifica validazione con input corretto"""
        # Arrange
        valid_data = {"name": "Test", "type": "forma_completa"}
        
        # Act
        result = validate_project_data(valid_data)
        
        # Assert
        assert result.is_valid is True
        assert len(result.errors) == 0
    
    def test_validation_invalid_input(self):
        """Verifica validazione con input errato"""
        # Arrange
        invalid_data = {"name": "", "type": "invalid_type"}
        
        # Act
        result = validate_project_data(invalid_data)
        
        # Assert
        assert result.is_valid is False
        assert "name" in result.errors


# ═══════════════════════════════════════════════════════════════
# INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════

class TestIntegration:
    """Integration tests con backend REALE"""
    
    def test_create_project_full_flow(self, api_client, auth_headers):
        """
        🎯 TESTA: Flusso completo creazione progetto
        🔌 BACKEND: Deve essere attivo su localhost:8000
        """
        # 1. Crea progetto
        response = api_client.post(
            "/api/v1/projects",
            json={
                "name": f"TEST_Project_{datetime.now().timestamp()}",
                "content_type": "forma_completa",
                "style": "tai_chi"
            },
            headers=auth_headers
        )
        assert response.status_code == 201
        project_id = response.json()["id"]
        
        # 2. Verifica creazione
        response = api_client.get(
            f"/api/v1/projects/{project_id}",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["name"].startswith("TEST_")
        
        # 3. Cleanup
        api_client.delete(
            f"/api/v1/projects/{project_id}",
            headers=auth_headers
        )


# ═══════════════════════════════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════════════════════════════

class TestSecurity:
    """Security tests OWASP compliant"""
    
    def test_sql_injection_prevention(self, api_client, auth_headers):
        """Verifica protezione SQL injection"""
        malicious_input = "'; DROP TABLE users; --"
        response = api_client.get(
            f"/api/v1/projects?name={malicious_input}",
            headers=auth_headers
        )
        # Non deve crashare, deve gestire input
        assert response.status_code in [200, 400]
    
    def test_unauthorized_access(self, api_client):
        """Verifica protezione endpoint senza auth"""
        response = api_client.get("/api/v1/admin/users")
        assert response.status_code == 401


# ═══════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════════

class TestPerformance:
    """Performance tests con metriche"""
    
    def test_api_response_time(self, api_client, auth_headers):
        """API deve rispondere in < 200ms"""
        import time
        
        start = time.time()
        response = api_client.get("/api/v1/projects", headers=auth_headers)
        elapsed = time.time() - start
        
        assert response.status_code == 200
        assert elapsed < 0.2, f"Response too slow: {elapsed:.3f}s"


# ═══════════════════════════════════════════════════════════════
# HOLISTIC TESTS
# ═══════════════════════════════════════════════════════════════

class TestHolistic:
    """End-to-end business workflow tests"""
    
    def test_complete_user_journey(self, api_client):
        """
        Testa journey completo:
        Register → Login → Create Project → Add Video → View Result
        """
        # 1. Register
        email = f"test_{datetime.now().timestamp()}@example.com"
        response = api_client.post("/api/v1/auth/register", json={
            "email": email,
            "password": "Test123!",
            "name": "Test User"
        })
        assert response.status_code in [200, 201]
        
        # 2. Login
        response = api_client.post("/api/v1/auth/login", json={
            "email": email,
            "password": "Test123!"
        })
        assert response.status_code == 200
        token = response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 3. Create Project
        response = api_client.post("/api/v1/projects", json={
            "name": "TEST_Journey_Project",
            "content_type": "forma_completa"
        }, headers=headers)
        assert response.status_code == 201
        
        # 4. Cleanup (delete user and project)
        # ... cleanup code
```

---

# SEZIONE 4: LEGGE SUPREMA ZERO MOCK

## ⛔ REGOLA ASSOLUTA

**TUTTI I TEST DEVONO USARE IL BACKEND REALE. ZERO MOCK.**

---

## ❌ LISTA COMPLETA COSE VIETATE

```python
# ═══════════════════════════════════════════════════════════════
# ⛔⛔⛔ VIETATO - NON USARE MAI ⛔⛔⛔
# ═══════════════════════════════════════════════════════════════

# JavaScript/TypeScript
jest.mock()           # ❌ VIETATO
jest.fn()             # ❌ VIETATO
jest.spyOn().mockImplementation()  # ❌ VIETATO
jest.spyOn().mockReturnValue()     # ❌ VIETATO
jest.spyOn().mockResolvedValue()   # ❌ VIETATO
mockReturnValue()     # ❌ VIETATO
mockResolvedValue()   # ❌ VIETATO
mockRejectedValue()   # ❌ VIETATO
mockImplementation()  # ❌ VIETATO

# Python
from unittest.mock import *   # ❌ VIETATO
from unittest import mock     # ❌ VIETATO
import unittest.mock          # ❌ VIETATO
@patch()              # ❌ VIETATO
@mock.patch()         # ❌ VIETATO
patch()               # ❌ VIETATO
MagicMock()           # ❌ VIETATO
AsyncMock()           # ❌ VIETATO
Mock()                # ❌ VIETATO
.return_value =       # ❌ VIETATO
.side_effect =        # ❌ VIETATO
PropertyMock          # ❌ VIETATO
create_autospec       # ❌ VIETATO

# Nomi variabili sospetti
mock_*                # ❌ VIETATO
*_mock                # ❌ VIETATO
fake_*                # ❌ VIETATO
stub_*                # ❌ VIETATO
dummy_*               # ❌ VIETATO
```

---

## ✅ COME SCRIVERE TEST REALI

```python
# ═══════════════════════════════════════════════════════════════
# ✅ ESEMPIO TEST REALE CORRETTO
# ═══════════════════════════════════════════════════════════════

import pytest
import httpx

def test_login_utente_reale(api_client):
    """
    🎯 COSA TESTA: Login con credenziali valide
    🔌 BACKEND: Deve essere attivo su localhost:8000
    📊 VERIFICA: Token JWT valido ricevuto
    """
    
    # 1. ARRANGE: Prepara dati REALI
    credentials = {
        "email": "admin@mediacenter.it",
        "password": "Test123!"
    }
    
    # 2. ACT: Chiama API REALE
    response = api_client.post("/api/v1/auth/login", json=credentials)
    
    # 3. ASSERT: Verifica risposta REALE
    assert response.status_code == 200, f"Login fallito: {response.text}"
    
    data = response.json()
    assert "access_token" in data, "Token non presente"
    assert len(data["access_token"]) > 20, "Token troppo corto"
    
    # 4. VERIFICA EXTRA: Token funziona davvero?
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    me_response = api_client.get("/api/v1/users/me", headers=headers)
    assert me_response.status_code == 200, "Token non valido"
```

---

## 🔒 CONFTEST.PY OBBLIGATORIO

```python
# File: backend/tests/conftest.py
"""
⛔ BLOCCO AUTOMATICO MOCK
Questo file impedisce FISICAMENTE l'uso di mock.
"""

import pytest
import httpx
import os

BACKEND_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")

# ═══════════════════════════════════════════════════════════════
# VERIFICA BACKEND ATTIVO PRIMA DI OGNI TEST
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def verifica_backend_attivo():
    """
    Se il backend è spento, TUTTI i test falliscono.
    Questo garantisce che stiamo testando codice REALE.
    """
    print(f"\n🔍 Verifico backend attivo su {BACKEND_URL}...")
    
    try:
        with httpx.Client(timeout=5.0) as client:
            response = client.get(f"{BACKEND_URL}/health")
            if response.status_code != 200:
                raise RuntimeError(f"Backend risponde {response.status_code}")
        print("✅ Backend attivo\n")
    except Exception as e:
        pytest.exit(f"""
⛔⛔⛔ BACKEND NON ATTIVO - TEST BLOCCATI ⛔⛔⛔

Prima di eseguire i test:
1. cd backend
2. .\\venv\\Scripts\\Activate.ps1
3. python -m uvicorn main:app --port 8000
4. Attendi "Application startup complete"
5. Riesegui i test

Errore: {e}
""", returncode=1)


@pytest.fixture
def api_client():
    """Client HTTP per chiamate API REALI."""
    with httpx.Client(base_url=BACKEND_URL, timeout=30.0) as client:
        yield client


@pytest.fixture
def auth_headers(api_client):
    """Headers con token JWT REALE."""
    response = api_client.post("/api/v1/auth/login", json={
        "email": "admin@mediacenter.it",
        "password": "Test123!"
    })
    if response.status_code != 200:
        pytest.skip(f"Login fallito: {response.text}")
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
```

---

## 📊 TABELLA COMPARATIVA

| Aspetto | Test FASULLO ❌ | Test REALE ✅ |
|---------|-----------------|---------------|
| Usa mock? | Sì | **No** |
| Backend richiesto? | No | **Sì** |
| Trova bug reali? | No | **Sì** |
| Passa con codice rotto? | Sì | **No** |
| Tempo esecuzione | ~1ms | ~100ms-5s |
| Valore | Zero | **Alto** |
| Affidabilità | Zero | **Alta** |

---

# SEZIONE 5: TASK SPECIFICO - CLASSIFICAZIONE CONTENUTI

## 🎯 PROBLEMA DA RISOLVERE

Un video può contenere diversi tipi di contenuto che devono essere classificati:

| Tipo | Descrizione | Esempio |
|------|-------------|---------|
| `FORMA_COMPLETA` | Sequenza intera dall'inizio alla fine | "81 posizioni Tai Chi" |
| `MOVIMENTO_SINGOLO` | Un movimento isolato dalla forma | "Nuvola che spinge" |
| `TECNICA_A_DUE` | Applicazione contro avversario | "Chin Na polso" |
| `SPIEGAZIONE` | Maestro che parla/spiega | "Principi del Chen style" |
| `VARIANTE` | Stesso movimento, scuola diversa | "Nuvola - Yang vs Chen" |

---

## 📋 COSA IMPLEMENTARE

### 1. Modello ContentType (Enum)

**File:** `backend/models/content_type.py`

```python
# POSIZIONE: backend/models/content_type.py
"""
🎓 AI_MODULE: ContentType Enum
🎓 AI_DESCRIPTION: Enum per classificare tipi di contenuto video
🎓 AI_BUSINESS: Permette organizzazione gerarchica contenuti didattici
🎓 AI_TEACHING: Enum Python con str mixin per serializzazione JSON

🔄 ALTERNATIVE_VALUTATE:
- String libere: Scartato, nessuna validazione, typo possibili
- Integer codes: Scartato, non leggibile, richiede mapping

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Validazione automatica a livello DB e API
- Serializzazione JSON nativa (str mixin)
- Autocompletamento IDE
- Documentazione inline
"""

from enum import Enum

class ContentType(str, Enum):
    """
    Tipi di contenuto video per classificazione.
    
    🎯 BUSINESS: Ogni tipo ha workflow diverso:
    - FORMA_COMPLETA: Multi-video fusion → Avatar completo
    - MOVIMENTO_SINGOLO: Fusion su movimento specifico
    - TECNICA_A_DUE: 2 skeleton simultanei
    - SPIEGAZIONE: Solo knowledge extraction
    - VARIANTE: Comparazione side-by-side
    """
    FORMA_COMPLETA = "forma_completa"
    MOVIMENTO_SINGOLO = "movimento_singolo"
    TECNICA_A_DUE = "tecnica_a_due"
    SPIEGAZIONE = "spiegazione"
    VARIANTE = "variante"
```

### 2. Modello VideoSection (NUOVO)

**File:** `backend/models/video_section.py`

```python
# POSIZIONE: backend/models/video_section.py
"""
🎓 AI_MODULE: VideoSection Model
🎓 AI_DESCRIPTION: Modello per taggare sezioni temporali di un video
🎓 AI_BUSINESS: Un video di 10min può contenere 3 forme + 2 spiegazioni
🎓 AI_TEACHING: Relazione 1:N con Video, timestamp per segmentazione

🔄 ALTERNATIVE_VALUTATE:
- Un record per video: Scartato, un video ha più contenuti
- JSON array in campo: Scartato, non queryable, no foreign keys

💡 PERCHÉ_QUESTA_SOLUZIONE:
- Query efficienti per tipo ("tutti i movimenti singoli")
- Relazioni con Skeleton e Project
- Validazione timestamp (end > start)
"""

from sqlalchemy import Column, Integer, String, Float, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from database import Base
from models.content_type import ContentType

class VideoSection(Base):
    """
    Sezione temporale di un video con classificazione.
    
    📊 ESEMPIO:
    Video "lezione_01.mp4" (10 minuti) contiene:
    - 0:00-5:30 → FORMA_COMPLETA "81 posizioni"
    - 5:30-6:00 → MOVIMENTO_SINGOLO "Nuvola che spinge"
    - 6:00-8:00 → TECNICA_A_DUE "Applicazione nuvola"
    - 8:00-10:00 → SPIEGAZIONE "Principi respirazione"
    """
    __tablename__ = "video_sections"
    
    id = Column(Integer, primary_key=True, index=True)
    video_id = Column(Integer, ForeignKey("videos.id"), nullable=False)
    content_type = Column(Enum(ContentType), nullable=False)
    start_time = Column(Float, nullable=False)  # Secondi dall'inizio
    end_time = Column(Float, nullable=False)    # Secondi dall'inizio
    name = Column(String(200), nullable=False)  # Es. "Nuvola che spinge"
    style = Column(String(100))                 # Es. "Tai Chi Chen"
    notes = Column(Text)                        # Note aggiuntive
    
    # Relazioni
    video = relationship("Video", back_populates="sections")
    
    def __repr__(self):
        return f"<VideoSection {self.name} ({self.content_type.value}) {self.start_time}-{self.end_time}>"
```

### 3. Aggiornamento Modello Project

**File:** `backend/models/project.py` (MODIFICA)

Aggiungi campo `content_type`:

```python
# Aggiungi a Project esistente:
content_type = Column(Enum(ContentType), nullable=True)
style = Column(String(100))  # Es. "Tai Chi Chen", "Wing Chun", "Karate"
```

### 4. API Endpoints

**File:** `backend/routers/content_classification.py` (NUOVO)

```python
# POSIZIONE: backend/routers/content_classification.py
"""
🎓 AI_MODULE: Content Classification Router
🎓 AI_DESCRIPTION: API per classificazione contenuti video
🎓 AI_BUSINESS: Permette organizzazione e ricerca contenuti didattici
🎓 AI_TEACHING: CRUD completo con filtri e validazione

📊 ENDPOINTS:
- POST /sections - Crea sezione video
- GET /sections - Lista con filtri
- GET /sections/{id} - Dettaglio
- PATCH /sections/{id} - Modifica
- DELETE /sections/{id} - Elimina
- GET /content-types - Lista tipi disponibili
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, validator

from database import get_db
from models.video_section import VideoSection
from models.content_type import ContentType
from auth import get_current_user

router = APIRouter(prefix="/api/v1", tags=["Content Classification"])

# ═══════════════════════════════════════════════════════════════
# SCHEMAS
# ═══════════════════════════════════════════════════════════════

class VideoSectionCreate(BaseModel):
    """Schema creazione sezione"""
    video_id: int
    content_type: ContentType
    start_time: float
    end_time: float
    name: str
    style: Optional[str] = None
    notes: Optional[str] = None
    
    @validator('end_time')
    def end_after_start(cls, v, values):
        if 'start_time' in values and v <= values['start_time']:
            raise ValueError('end_time deve essere > start_time')
        return v

class VideoSectionResponse(BaseModel):
    """Schema risposta sezione"""
    id: int
    video_id: int
    content_type: ContentType
    start_time: float
    end_time: float
    name: str
    style: Optional[str]
    notes: Optional[str]
    
    class Config:
        from_attributes = True

# ═══════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@router.get("/content-types")
async def list_content_types():
    """
    Lista tutti i tipi di contenuto disponibili.
    
    🎯 USE CASE: Popolare dropdown in UI
    """
    return [
        {"value": ct.value, "label": ct.name.replace("_", " ").title()}
        for ct in ContentType
    ]


@router.post("/sections", response_model=VideoSectionResponse, status_code=201)
async def create_section(
    section: VideoSectionCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Crea nuova sezione video.
    
    🎯 USE CASE: Utente tagga porzione di video con tipo
    """
    db_section = VideoSection(**section.dict())
    db.add(db_section)
    db.commit()
    db.refresh(db_section)
    return db_section


@router.get("/sections", response_model=List[VideoSectionResponse])
async def list_sections(
    video_id: Optional[int] = Query(None),
    content_type: Optional[ContentType] = Query(None),
    style: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Lista sezioni con filtri opzionali.
    
    🎯 USE CASES:
    - Tutte le sezioni di un video: ?video_id=123
    - Tutti i movimenti singoli: ?content_type=movimento_singolo
    - Tutto il Tai Chi: ?style=tai_chi
    """
    query = db.query(VideoSection)
    
    if video_id:
        query = query.filter(VideoSection.video_id == video_id)
    if content_type:
        query = query.filter(VideoSection.content_type == content_type)
    if style:
        query = query.filter(VideoSection.style.ilike(f"%{style}%"))
    
    return query.all()


@router.get("/sections/{section_id}", response_model=VideoSectionResponse)
async def get_section(
    section_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Dettaglio singola sezione"""
    section = db.query(VideoSection).filter(VideoSection.id == section_id).first()
    if not section:
        raise HTTPException(status_code=404, detail="Sezione non trovata")
    return section


@router.patch("/sections/{section_id}", response_model=VideoSectionResponse)
async def update_section(
    section_id: int,
    updates: dict,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Modifica sezione esistente"""
    section = db.query(VideoSection).filter(VideoSection.id == section_id).first()
    if not section:
        raise HTTPException(status_code=404, detail="Sezione non trovata")
    
    for key, value in updates.items():
        if hasattr(section, key):
            setattr(section, key, value)
    
    db.commit()
    db.refresh(section)
    return section


@router.delete("/sections/{section_id}", status_code=204)
async def delete_section(
    section_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Elimina sezione"""
    section = db.query(VideoSection).filter(VideoSection.id == section_id).first()
    if not section:
        raise HTTPException(status_code=404, detail="Sezione non trovata")
    
    db.delete(section)
    db.commit()
```

### 5. Test Suite

**File:** `backend/tests/test_content_classification.py`

```python
# POSIZIONE: backend/tests/test_content_classification.py
"""
🎓 AI_MODULE: Test Content Classification
🎓 AI_DESCRIPTION: Test suite REALE per classificazione contenuti
🎓 AI_BUSINESS: Garantisce funzionamento classificazione
🎓 AI_TEACHING: Test integration con backend reale, ZERO MOCK

📊 COVERAGE TARGET: 90%+
📊 PASS RATE TARGET: 95%+
"""

import pytest
import httpx
from datetime import datetime

class TestContentClassification:
    """Test classificazione contenuti con backend REALE"""
    
    def test_list_content_types(self, api_client, auth_headers):
        """Verifica lista tipi contenuto"""
        response = api_client.get("/api/v1/content-types", headers=auth_headers)
        
        assert response.status_code == 200
        types = response.json()
        assert len(types) == 5
        assert any(t["value"] == "forma_completa" for t in types)
    
    def test_create_section(self, api_client, auth_headers):
        """Crea sezione video"""
        section_data = {
            "video_id": 1,  # Assumiamo esista video con id 1
            "content_type": "movimento_singolo",
            "start_time": 0.0,
            "end_time": 30.5,
            "name": f"TEST_Movimento_{datetime.now().timestamp()}",
            "style": "tai_chi_chen"
        }
        
        response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"].startswith("TEST_")
        assert data["content_type"] == "movimento_singolo"
        
        # Cleanup
        api_client.delete(f"/api/v1/sections/{data['id']}", headers=auth_headers)
    
    def test_validation_end_before_start(self, api_client, auth_headers):
        """Verifica validazione timestamp"""
        section_data = {
            "video_id": 1,
            "content_type": "forma_completa",
            "start_time": 30.0,
            "end_time": 10.0,  # ❌ Prima di start!
            "name": "TEST_Invalid"
        }
        
        response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_filter_by_type(self, api_client, auth_headers):
        """Filtra sezioni per tipo"""
        response = api_client.get(
            "/api/v1/sections?content_type=forma_completa",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        sections = response.json()
        for s in sections:
            assert s["content_type"] == "forma_completa"
```

---

## 🚫 NON TOCCARE

Questi file funzionano, NON modificarli:

- `skeleton_extraction_holistic.py` ✅
- `multi_video_fusion.py` ✅
- `mix_generator.py` ✅
- `anonymizer.py` ✅
- `blender_export.py` ✅
- Auth system ✅

---

## ✅ OUTPUT ATTESO

Dopo implementazione:

1. ✅ Enum `ContentType` con 5 valori
2. ✅ Modello `VideoSection` con relazione a Video
3. ✅ Campo `content_type` in Project
4. ✅ Router `/api/v1/sections` con CRUD
5. ✅ Router `/api/v1/content-types` per lista tipi
6. ✅ Test suite con 90%+ coverage, 95%+ pass rate
7. ✅ ZERO mock nei test

---

## 🏁 VERIFICA FINALE

```bash
# 1. Avvia backend
cd C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend
.\venv\Scripts\Activate.ps1
python -m uvicorn main:app --reload --port 8000

# 2. Test API manuale
curl http://localhost:8000/api/v1/content-types
curl http://localhost:8000/api/v1/sections

# 3. Esegui test suite
pytest tests/test_content_classification.py -v

# 4. Coverage
pytest --cov=. --cov-report=html tests/
```

---

## 📝 INIZIA

1. Leggi struttura esistente:
```powershell
dir C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\models
dir C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend\routers
```

2. Proponi piano implementazione
3. Attendi conferma prima di scrivere codice
4. Implementa un file alla volta
5. Testa dopo ogni file

---

# FINE MEGAPROMPT

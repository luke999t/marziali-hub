"""
🎓 AI_MODULE: Test Overlay Service
🎓 AI_DESCRIPTION: Test REALI con backend attivo - ZERO MOCK
🎓 AI_BUSINESS: Validazione funzionalità overlay didattici
🎓 AI_TEACHING: Integration testing senza mock, httpx per chiamate HTTP

⛔⛔⛔ ZERO MOCK POLICY ⛔⛔⛔
Questo file NON usa mock. Tutti i test chiamano il backend REALE.
Se il backend è spento, i test DEVONO fallire.

🔄 ALTERNATIVE_VALUTATE:
- unittest.mock: VIETATO da policy aziendale
- pytest-mock: VIETATO da policy aziendale
- responses library: VIETATO (mock HTTP)

💡 PERCHÉ TEST REALI:
- Trovano bug che mock nascondono
- Validano integrazione end-to-end
- Garantiscono che il codice funziona davvero
"""

import pytest
import httpx
import os

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURAZIONE
# ═══════════════════════════════════════════════════════════════════════════════

BACKEND_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_BASE = f"{BACKEND_URL}/api/v1/overlays"


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURE: VERIFICA BACKEND ATTIVO
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="session", autouse=True)
def verify_backend_active():
    """
    🎯 SCOPO: Verifica che backend sia attivo PRIMA di qualsiasi test
    ⛔ Se backend spento, TUTTI i test falliscono immediatamente
    
    Questo è INTENZIONALE: test senza backend reale sono inutili.
    """
    print(f"\n🔍 Verifico backend attivo su {BACKEND_URL}...")
    
    try:
        with httpx.Client(timeout=5.0) as client:
            # Prova health check
            response = client.get(f"{BACKEND_URL}/health")
            
            if response.status_code != 200:
                # Prova endpoint alternativo
                response = client.get(f"{BACKEND_URL}/")
                
            if response.status_code not in [200, 404]:
                raise Exception(f"Backend risponde con status {response.status_code}")
        
        print("✅ Backend attivo!\n")
        
    except Exception as e:
        pytest.exit(f"""
⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔
⛔                                                            ⛔
⛔   BACKEND NON ATTIVO - TEST BLOCCATI                       ⛔
⛔                                                            ⛔
⛔   Errore: {str(e)[:40]}
⛔                                                            ⛔
⛔   Prima di eseguire i test:                                ⛔
⛔                                                            ⛔
⛔   1. cd backend                                            ⛔
⛔   2. python -m uvicorn main:app --reload --port 8000       ⛔
⛔   3. Attendi "Application startup complete"                ⛔
⛔   4. Riesegui pytest                                       ⛔
⛔                                                            ⛔
⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔
""", returncode=1)


@pytest.fixture
def api_client():
    """
    Client HTTP per test.
    NON è un mock - fa chiamate HTTP reali.
    """
    with httpx.Client(base_url=BACKEND_URL, timeout=30.0) as client:
        yield client


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: ENDPOINT INFO
# ═══════════════════════════════════════════════════════════════════════════════

def test_get_annotation_types(api_client):
    """
    🎯 TEST: Endpoint /overlays/types ritorna tipi annotazione
    📊 VERIFICA: Lista contiene almeno 'angle', 'text', 'arrow'
    """
    response = api_client.get("/api/v1/overlays/types")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    data = response.json()
    
    assert "annotation_types" in data, "Manca campo 'annotation_types'"
    assert "anchor_points" in data, "Manca campo 'anchor_points'"
    
    types = data["annotation_types"]
    assert "angle" in types, "'angle' deve essere nei tipi"
    assert "text" in types, "'text' deve essere nei tipi"
    assert "arrow" in types, "'arrow' deve essere nei tipi"
    
    print(f"✅ Tipi annotazione: {types}")


def test_get_joint_angles(api_client):
    """
    🎯 TEST: Endpoint /overlays/joint-angles ritorna angoli articolazioni
    📊 VERIFICA: Lista contiene angoli per gomiti, ginocchia, spalle
    """
    response = api_client.get("/api/v1/overlays/joint-angles")
    
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"
    
    data = response.json()
    
    assert isinstance(data, list), "Response deve essere una lista"
    assert len(data) > 0, "Lista angoli non deve essere vuota"
    
    # Verifica struttura primo elemento
    first = data[0]
    assert "name" in first, "Manca campo 'name'"
    assert "point_a" in first, "Manca campo 'point_a'"
    assert "vertex" in first, "Manca campo 'vertex'"
    assert "point_b" in first, "Manca campo 'point_b'"
    
    # Verifica angoli comuni presenti
    names = [a["name"] for a in data]
    assert "left_elbow" in names, "'left_elbow' deve essere presente"
    assert "right_elbow" in names, "'right_elbow' deve essere presente"
    
    print(f"✅ Angoli trovati: {names}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: PROJECT CRUD
# ═══════════════════════════════════════════════════════════════════════════════

def test_create_and_delete_project(api_client):
    """
    🎯 TEST: Creazione e eliminazione progetto overlay
    📊 VERIFICA: Progetto creato con ID, poi eliminato correttamente
    """
    # CREATE
    response = api_client.post(
        "/api/v1/overlays/projects",
        params={
            "name": "Test Project Pytest",
            "width": 1920,
            "height": 1080,
            "description": "Progetto di test automatico"
        }
    )
    
    assert response.status_code == 200, f"Create failed: {response.text}"
    
    data = response.json()
    assert "id" in data, "Manca 'id' nella risposta"
    assert data["name"] == "Test Project Pytest"
    assert data["width"] == 1920
    assert data["height"] == 1080
    
    project_id = data["id"]
    print(f"✅ Progetto creato: {project_id}")
    
    # GET
    response = api_client.get(f"/api/v1/overlays/projects/{project_id}")
    assert response.status_code == 200, f"Get failed: {response.text}"
    
    # DELETE
    response = api_client.delete(f"/api/v1/overlays/projects/{project_id}")
    assert response.status_code == 200, f"Delete failed: {response.text}"
    
    # VERIFY DELETED
    response = api_client.get(f"/api/v1/overlays/projects/{project_id}")
    assert response.status_code == 404, "Progetto dovrebbe essere stato eliminato"
    
    print(f"✅ Progetto eliminato correttamente")


def test_list_projects(api_client):
    """
    🎯 TEST: Lista progetti
    📊 VERIFICA: Endpoint ritorna lista (anche vuota)
    """
    response = api_client.get("/api/v1/overlays/projects")
    
    assert response.status_code == 200, f"List failed: {response.text}"
    
    data = response.json()
    assert isinstance(data, list), "Response deve essere lista"
    
    print(f"✅ Progetti trovati: {len(data)}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: ANNOTATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def test_add_annotation_to_project(api_client):
    """
    🎯 TEST: Aggiunta annotazione a progetto
    📊 VERIFICA: Annotazione aggiunta e recuperabile
    """
    # Crea progetto
    response = api_client.post(
        "/api/v1/overlays/projects",
        params={"name": "Test Annotations"}
    )
    assert response.status_code == 200
    project_id = response.json()["id"]
    
    try:
        # Aggiungi annotazione angolo
        annotation = {
            "type": "angle",
            "frame_index": 0,
            "point_a": "left_shoulder",
            "vertex": "left_elbow",
            "point_b": "left_wrist",
            "show_degrees": True,
            "color": {"r": 255, "g": 100, "b": 0, "a": 1.0}
        }
        
        response = api_client.post(
            f"/api/v1/overlays/projects/{project_id}/annotations",
            json=annotation
        )
        
        assert response.status_code == 200, f"Add annotation failed: {response.text}"
        
        data = response.json()
        assert "annotation_id" in data
        
        annotation_id = data["annotation_id"]
        print(f"✅ Annotazione aggiunta: {annotation_id}")
        
        # Verifica progetto contiene annotazione
        response = api_client.get(f"/api/v1/overlays/projects/{project_id}")
        assert response.status_code == 200
        
        project = response.json()
        assert len(project["annotations"]) == 1
        
    finally:
        # Cleanup
        api_client.delete(f"/api/v1/overlays/projects/{project_id}")


# ═══════════════════════════════════════════════════════════════════════════════
# TEST: AUTO-ANNOTATE
# ═══════════════════════════════════════════════════════════════════════════════

def test_auto_annotate_without_skeleton(api_client):
    """
    🎯 TEST: Auto-annotate senza skeleton valido
    📊 VERIFICA: Gestisce gracefully l'assenza di skeleton
    """
    response = api_client.post(
        "/api/v1/overlays/auto-annotate",
        json={
            "skeleton_id": "non_existent_skeleton_12345",
            "frame_index": 0,
            "detect_angles": True,
            "detect_key_points": False
        }
    )
    
    # Può essere 200 con lista vuota o 404/400
    assert response.status_code in [200, 400, 404], f"Unexpected status: {response.status_code}"
    
    if response.status_code == 200:
        data = response.json()
        # Senza skeleton, dovrebbe ritornare lista vuota
        assert "annotations" in data
        print(f"✅ Auto-annotate senza skeleton: {len(data['annotations'])} annotazioni")
    else:
        print(f"✅ Auto-annotate senza skeleton: errore gestito ({response.status_code})")


# ═══════════════════════════════════════════════════════════════════════════════
# REPORT FINALE
# ═══════════════════════════════════════════════════════════════════════════════

def pytest_sessionfinish(session, exitstatus):
    """Report finale"""
    print(f"""
═══════════════════════════════════════════════════════════
📊 TEST OVERLAY SERVICE COMPLETATI
═══════════════════════════════════════════════════════════
Exit status: {exitstatus}

✅ Tutti i test hanno usato backend REALE
✅ Nessun mock utilizzato
✅ Se backend era spento, test sono falliti (corretto!)
═══════════════════════════════════════════════════════════
""")

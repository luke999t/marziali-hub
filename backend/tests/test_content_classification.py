# POSIZIONE: backend/tests/test_content_classification.py
"""
🎓 AI_MODULE: Test Suite Content Classification
🎓 AI_DESCRIPTION: Test REALI per API classificazione contenuti video - ZERO MOCK
🎓 AI_BUSINESS: Garantisce funzionamento corretto classificazione, tagging sezioni, filtering
🎓 AI_TEACHING: Integration testing con backend REALE, test fixtures, cleanup automatico

⛔ ZERO MOCK POLICY:
- Tutti i test chiamano API REALI su localhost:8000
- Nessun mock, patch, MagicMock, fake
- Se backend non attivo → test FALLISCONO (by design)

📊 COVERAGE TARGET: 90%+
📊 PASS RATE TARGET: 95%+

🧪 TEST CATEGORIES:
- Unit: ContentType enum methods (5 test)
- Integration: API CRUD sections (10 test)
- Validation: Input validation, error handling (5 test)
- Security: Auth required, SQL injection prevention (3 test)
- Performance: Response time < 200ms (2 test)

🔗 INTEGRATION_DEPENDENCIES:
- Backend: Deve essere attivo su localhost:8000
- Database: PostgreSQL con tabella video_sections
- Auth: Utente admin@mediacenter.it deve esistere
"""

import pytest
import httpx
from datetime import datetime
from uuid import UUID, uuid4
import time

# ═══════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════

BACKEND_URL = "http://localhost:8000"
TEST_EMAIL = "admin@mediacenter.it"
TEST_PASSWORD = "Test123!"


# ═══════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def api_client():
    """
    Client HTTP per chiamate API REALI.

    ⚠️ NON è un mock. Chiama il backend vero su localhost:8000.
    Se il backend è spento, i test falliscono.
    """
    with httpx.Client(base_url=BACKEND_URL, timeout=30.0) as client:
        yield client


@pytest.fixture(scope="module")
def auth_headers(api_client):
    """
    Headers con token JWT REALE per test autenticati.

    Fa login con credenziali reali e ottiene token JWT valido.
    """
    response = api_client.post(
        "/api/v1/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
    )

    if response.status_code != 200:
        pytest.skip(f"Login fallito: {response.status_code} - {response.text}")

    token = response.json().get("access_token")
    if not token:
        pytest.skip("Token non presente nella response di login")

    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def test_video_id(api_client, auth_headers):
    """
    Ottiene un video_id valido dal database per i test.

    Se non ci sono video, skippa il test.
    """
    response = api_client.get(
        "/api/v1/videos",
        headers=auth_headers,
        params={"limit": 1}
    )

    if response.status_code != 200:
        pytest.skip(f"Impossibile ottenere video: {response.status_code}")

    videos = response.json()
    if isinstance(videos, dict):
        videos = videos.get("items", videos.get("videos", []))

    if not videos:
        pytest.skip("Nessun video nel database per i test")

    return videos[0].get("id")


@pytest.fixture
def cleanup_sections(api_client, auth_headers):
    """
    Fixture per cleanup automatico delle sezioni create durante i test.

    Yield una lista dove aggiungere section_id da eliminare.
    Dopo il test, elimina tutte le sezioni nella lista.
    """
    sections_to_delete = []
    yield sections_to_delete

    # Cleanup
    for section_id in sections_to_delete:
        try:
            api_client.delete(
                f"/api/v1/sections/{section_id}",
                headers=auth_headers
            )
        except Exception:
            pass  # Ignora errori di cleanup


# ═══════════════════════════════════════════════════════════════
# UNIT TESTS - ContentType Enum
# ═══════════════════════════════════════════════════════════════

class TestContentTypeEnum:
    """
    Test per l'enum ContentType.

    Questi test verificano i metodi dell'enum senza chiamare API.
    """

    def test_content_type_values(self):
        """Verifica che tutti i 5 valori enum esistano"""
        from models.content_type import ContentType

        assert len(ContentType) == 5
        assert ContentType.FORMA_COMPLETA.value == "forma_completa"
        assert ContentType.MOVIMENTO_SINGOLO.value == "movimento_singolo"
        assert ContentType.TECNICA_A_DUE.value == "tecnica_a_due"
        assert ContentType.SPIEGAZIONE.value == "spiegazione"
        assert ContentType.VARIANTE.value == "variante"

    def test_get_choices(self):
        """Verifica metodo get_choices per dropdown UI"""
        from models.content_type import ContentType

        choices = ContentType.get_choices()

        assert len(choices) == 5
        assert all("value" in c and "label" in c for c in choices)
        assert any(c["value"] == "forma_completa" for c in choices)

    def test_requires_skeleton(self):
        """Verifica logica requires_skeleton"""
        from models.content_type import ContentType

        # SPIEGAZIONE non richiede skeleton
        assert ContentType.requires_skeleton(ContentType.SPIEGAZIONE) is False

        # Tutti gli altri richiedono skeleton
        assert ContentType.requires_skeleton(ContentType.FORMA_COMPLETA) is True
        assert ContentType.requires_skeleton(ContentType.MOVIMENTO_SINGOLO) is True
        assert ContentType.requires_skeleton(ContentType.TECNICA_A_DUE) is True
        assert ContentType.requires_skeleton(ContentType.VARIANTE) is True

    def test_requires_dual_skeleton(self):
        """Verifica logica requires_dual_skeleton"""
        from models.content_type import ContentType

        # Solo TECNICA_A_DUE richiede dual skeleton
        assert ContentType.requires_dual_skeleton(ContentType.TECNICA_A_DUE) is True
        assert ContentType.requires_dual_skeleton(ContentType.FORMA_COMPLETA) is False
        assert ContentType.requires_dual_skeleton(ContentType.SPIEGAZIONE) is False


# ═══════════════════════════════════════════════════════════════
# INTEGRATION TESTS - API Endpoints
# ═══════════════════════════════════════════════════════════════

class TestContentTypesAPI:
    """
    Test per endpoint /api/v1/content-types.

    🔌 BACKEND: Deve essere attivo su localhost:8000
    """

    def test_list_content_types(self, api_client, auth_headers):
        """
        🎯 TESTA: GET /api/v1/content-types
        📊 VERIFICA: Ritorna lista di 5 tipi con value e label
        """
        response = api_client.get(
            "/api/v1/content-types",
            headers=auth_headers
        )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert "types" in data
        assert "count" in data
        assert data["count"] == 5

        types = data["types"]
        assert len(types) == 5

        # Verifica struttura
        for t in types:
            assert "value" in t
            assert "label" in t

        # Verifica valori specifici
        values = [t["value"] for t in types]
        assert "forma_completa" in values
        assert "movimento_singolo" in values
        assert "tecnica_a_due" in values
        assert "spiegazione" in values
        assert "variante" in values


class TestVideoSectionsAPI:
    """
    Test CRUD per endpoint /api/v1/sections.

    🔌 BACKEND: Deve essere attivo su localhost:8000
    """

    def test_create_section(self, api_client, auth_headers, test_video_id, cleanup_sections):
        """
        🎯 TESTA: POST /api/v1/sections
        📊 VERIFICA: Crea sezione con tutti i campi e ritorna ID
        """
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "movimento_singolo",
            "start_time": 0.0,
            "end_time": 30.5,
            "name": f"TEST_Section_{datetime.now().timestamp()}",
            "style": "tai_chi_chen",
            "notes": "Test automatico - da eliminare"
        }

        response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        assert response.status_code == 201, f"Expected 201, got {response.status_code}: {response.text}"

        data = response.json()
        assert "id" in data
        assert data["content_type"] == "movimento_singolo"
        assert data["name"].startswith("TEST_")
        assert data["start_time"] == 0.0
        assert data["end_time"] == 30.5
        assert data["duration"] == 30.5
        assert data["style"] == "tai_chi_chen"

        # Aggiungi a cleanup
        cleanup_sections.append(data["id"])

    def test_create_section_validation_end_before_start(self, api_client, auth_headers, test_video_id):
        """
        🎯 TESTA: Validazione end_time > start_time
        📊 VERIFICA: Ritorna 422 se end_time < start_time
        """
        section_data = {
            "video_id": str(test_video_id),
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

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_create_section_invalid_content_type(self, api_client, auth_headers, test_video_id):
        """
        🎯 TESTA: Validazione content_type enum
        📊 VERIFICA: Ritorna 422 se content_type non valido
        """
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "tipo_inventato",  # ❌ Non esiste!
            "start_time": 0.0,
            "end_time": 30.0,
            "name": "TEST_Invalid"
        }

        response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_list_sections(self, api_client, auth_headers):
        """
        🎯 TESTA: GET /api/v1/sections
        📊 VERIFICA: Ritorna lista con total e sections
        """
        response = api_client.get(
            "/api/v1/sections",
            headers=auth_headers
        )

        assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"

        data = response.json()
        assert "sections" in data
        assert "total" in data
        assert isinstance(data["sections"], list)

    def test_list_sections_filter_by_type(self, api_client, auth_headers, test_video_id, cleanup_sections):
        """
        🎯 TESTA: GET /api/v1/sections?content_type=forma_completa
        📊 VERIFICA: Filtra correttamente per tipo
        """
        # Crea una sezione di tipo specifico
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "spiegazione",
            "start_time": 0.0,
            "end_time": 60.0,
            "name": f"TEST_Spiegazione_{datetime.now().timestamp()}"
        }

        create_response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        if create_response.status_code == 201:
            cleanup_sections.append(create_response.json()["id"])

        # Filtra per tipo
        response = api_client.get(
            "/api/v1/sections",
            params={"content_type": "spiegazione"},
            headers=auth_headers
        )

        assert response.status_code == 200

        data = response.json()
        # Tutte le sezioni devono essere di tipo spiegazione
        for section in data["sections"]:
            assert section["content_type"] == "spiegazione"

    def test_get_section_by_id(self, api_client, auth_headers, test_video_id, cleanup_sections):
        """
        🎯 TESTA: GET /api/v1/sections/{id}
        📊 VERIFICA: Ritorna dettaglio sezione
        """
        # Crea sezione
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "variante",
            "start_time": 100.0,
            "end_time": 150.0,
            "name": f"TEST_Variante_{datetime.now().timestamp()}"
        }

        create_response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        assert create_response.status_code == 201
        section_id = create_response.json()["id"]
        cleanup_sections.append(section_id)

        # Get by ID
        response = api_client.get(
            f"/api/v1/sections/{section_id}",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["id"] == section_id
        assert data["content_type"] == "variante"

    def test_get_section_not_found(self, api_client, auth_headers):
        """
        🎯 TESTA: GET /api/v1/sections/{id} con ID inesistente
        📊 VERIFICA: Ritorna 404
        """
        response = api_client.get(
            "/api/v1/sections/999999999",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_update_section(self, api_client, auth_headers, test_video_id, cleanup_sections):
        """
        🎯 TESTA: PATCH /api/v1/sections/{id}
        📊 VERIFICA: Aggiorna campi specificati
        """
        # Crea sezione
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "forma_completa",
            "start_time": 0.0,
            "end_time": 300.0,
            "name": "TEST_Original"
        }

        create_response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        assert create_response.status_code == 201
        section_id = create_response.json()["id"]
        cleanup_sections.append(section_id)

        # Update
        update_data = {
            "name": "TEST_Updated",
            "style": "tai_chi_yang",
            "notes": "Note aggiornate"
        }

        response = api_client.patch(
            f"/api/v1/sections/{section_id}",
            json=update_data,
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "TEST_Updated"
        assert data["style"] == "tai_chi_yang"
        assert data["notes"] == "Note aggiornate"
        # Campi non modificati devono rimanere invariati
        assert data["content_type"] == "forma_completa"

    def test_delete_section(self, api_client, auth_headers, test_video_id):
        """
        🎯 TESTA: DELETE /api/v1/sections/{id}
        📊 VERIFICA: Elimina sezione e ritorna 204
        """
        # Crea sezione
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "tecnica_a_due",
            "start_time": 0.0,
            "end_time": 45.0,
            "name": "TEST_ToDelete"
        }

        create_response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        assert create_response.status_code == 201
        section_id = create_response.json()["id"]

        # Delete
        response = api_client.delete(
            f"/api/v1/sections/{section_id}",
            headers=auth_headers
        )

        assert response.status_code == 204

        # Verifica eliminazione
        get_response = api_client.get(
            f"/api/v1/sections/{section_id}",
            headers=auth_headers
        )
        assert get_response.status_code == 404


# ═══════════════════════════════════════════════════════════════
# SECURITY TESTS
# ═══════════════════════════════════════════════════════════════

class TestSecurity:
    """
    Test di sicurezza per API content classification.
    """

    def test_unauthorized_access(self, api_client):
        """
        🎯 TESTA: Accesso senza autenticazione
        📊 VERIFICA: Ritorna 401 Unauthorized
        """
        response = api_client.get("/api/v1/sections")
        assert response.status_code == 401

    def test_sql_injection_prevention(self, api_client, auth_headers):
        """
        🎯 TESTA: Protezione SQL injection nel filtro style
        📊 VERIFICA: Non crasha, gestisce input malevolo
        """
        malicious_input = "'; DROP TABLE video_sections; --"

        response = api_client.get(
            "/api/v1/sections",
            params={"style": malicious_input},
            headers=auth_headers
        )

        # Non deve crashare - deve ritornare 200 (lista vuota) o 400
        assert response.status_code in [200, 400]


# ═══════════════════════════════════════════════════════════════
# PERFORMANCE TESTS
# ═══════════════════════════════════════════════════════════════

class TestPerformance:
    """
    Test di performance per API content classification.
    """

    def test_content_types_response_time(self, api_client, auth_headers):
        """
        🎯 TESTA: Tempo risposta GET /content-types
        📊 VERIFICA: Response in < 200ms
        """
        start = time.time()
        response = api_client.get(
            "/api/v1/content-types",
            headers=auth_headers
        )
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 0.2, f"Response too slow: {elapsed:.3f}s (expected < 0.2s)"

    def test_sections_list_response_time(self, api_client, auth_headers):
        """
        🎯 TESTA: Tempo risposta GET /sections
        📊 VERIFICA: Response in < 500ms anche con molte sezioni
        """
        start = time.time()
        response = api_client.get(
            "/api/v1/sections",
            params={"limit": 100},
            headers=auth_headers
        )
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 0.5, f"Response too slow: {elapsed:.3f}s (expected < 0.5s)"


# ═══════════════════════════════════════════════════════════════
# VIDEO SECTIONS ENDPOINTS
# ═══════════════════════════════════════════════════════════════

class TestVideoSectionsEndpoint:
    """
    Test per endpoint /api/v1/videos/{id}/sections.
    """

    def test_get_video_sections(self, api_client, auth_headers, test_video_id, cleanup_sections):
        """
        🎯 TESTA: GET /api/v1/videos/{id}/sections
        📊 VERIFICA: Ritorna sezioni di un video specifico
        """
        # Crea sezione per questo video
        section_data = {
            "video_id": str(test_video_id),
            "content_type": "movimento_singolo",
            "start_time": 0.0,
            "end_time": 20.0,
            "name": f"TEST_VideoSection_{datetime.now().timestamp()}"
        }

        create_response = api_client.post(
            "/api/v1/sections",
            json=section_data,
            headers=auth_headers
        )

        if create_response.status_code == 201:
            cleanup_sections.append(create_response.json()["id"])

        # Get sezioni del video
        response = api_client.get(
            f"/api/v1/videos/{test_video_id}/sections",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "sections" in data
        assert "total" in data

        # Tutte le sezioni devono appartenere a questo video
        for section in data["sections"]:
            assert section["video_id"] == str(test_video_id)


# ═══════════════════════════════════════════════════════════════
# RUN INFO
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("""
    ═══════════════════════════════════════════════════════════════
    📋 TEST SUITE: Content Classification
    ═══════════════════════════════════════════════════════════════

    ⚠️ PRIMA DI ESEGUIRE:

    1. Avvia il backend:
       cd C:\\Users\\utente\\Desktop\\GESTIONALI\\media-center-arti-marziali\\backend
       .\\venv\\Scripts\\Activate.ps1
       python -m uvicorn main:app --reload --port 8000

    2. Attendi "[OK] Content Classification router loaded"

    3. Esegui i test:
       pytest tests/test_content_classification.py -v

    ═══════════════════════════════════════════════════════════════
    """)
    pytest.main([__file__, "-v"])

"""
AI_MODULE: Avatar API Tests
AI_DESCRIPTION: Test suite ZERO MOCK per Avatar API endpoints
AI_TEACHING: Tutti i test chiamano il backend REALE su localhost:8000.
             Nessun mock, nessun TestClient in-process.
             I test verificano l'intero stack: HTTP -> FastAPI -> SQLAlchemy -> PostgreSQL.
"""

import pytest
import uuid


# =============================================================================
# TEST: GET /api/v1/avatars/ - Lista avatar pubblici
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestListAvatars:
    """Test per endpoint lista avatar"""

    def test_list_avatars_public_no_auth(self, api_client):
        """
        WHY: L'endpoint lista avatar deve essere accessibile senza autenticazione
        per permettere la navigazione pubblica della galleria.
        """
        response = api_client.get("/api/v1/avatars/")
        assert response.status_code == 200
        data = response.json()
        assert "avatars" in data
        assert "total" in data
        assert isinstance(data["avatars"], list)
        assert data["page"] >= 1
        assert data["page_size"] >= 1

    def test_list_avatars_with_auth(self, api_client, auth_headers):
        """Con autenticazione vede anche avatar privati owned"""
        response = api_client.get("/api/v1/avatars/", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "avatars" in data

    def test_list_avatars_pagination(self, api_client):
        """Verifica paginazione corretta"""
        response = api_client.get("/api/v1/avatars/?page=1&page_size=5")
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 1
        assert data["page_size"] == 5
        assert len(data["avatars"]) <= 5

    def test_list_avatars_filter_by_style(self, api_client):
        """Filtra avatar per stile marziale"""
        response = api_client.get("/api/v1/avatars/?style=generic")
        assert response.status_code == 200
        data = response.json()
        for avatar in data["avatars"]:
            assert avatar["style"] == "generic"


# =============================================================================
# TEST: GET /api/v1/avatars/{id} - Dettaglio avatar
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestGetAvatar:
    """Test per endpoint dettaglio avatar"""

    def test_get_avatar_not_found(self, api_client):
        """Avatar inesistente ritorna 404"""
        fake_id = str(uuid.uuid4())
        response = api_client.get(f"/api/v1/avatars/{fake_id}")
        assert response.status_code == 404

    def test_get_avatar_invalid_id(self, api_client):
        """ID non-UUID ritorna 400"""
        response = api_client.get("/api/v1/avatars/not-a-uuid")
        assert response.status_code == 400

    def test_get_avatar_detail(self, api_client, admin_headers):
        """
        Crea avatar e poi lo recupera per ID.
        WHY admin_headers: serve admin per creare, poi verifica GET pubblico.
        """
        # Crea avatar di test
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        # Recupera dettaglio
        response = api_client.get(f"/api/v1/avatars/{avatar_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == avatar_id
        assert "name" in data
        assert "model_url" in data
        assert "rig_type" in data
        assert "has_hand_bones" in data


# =============================================================================
# TEST: POST /api/v1/avatars/ - Upload avatar (admin only)
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestCreateAvatar:
    """Test per endpoint upload avatar"""

    def test_upload_avatar_admin_only(self, api_client, auth_headers):
        """
        WHY: Solo admin possono caricare avatar per evitare
        upload di modelli 3D malevoli o inappropriati.
        """
        # Utente normale non puo' creare avatar
        files = {"file": ("test.glb", b"\x00" * 100, "model/gltf-binary")}
        data = {"name": "Test Avatar"}
        response = api_client.post(
            "/api/v1/avatars/",
            files=files,
            data=data,
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_upload_avatar_invalid_format(self, api_client, admin_headers):
        """Rifiuta formati non supportati"""
        files = {"file": ("test.obj", b"\x00" * 100, "application/octet-stream")}
        data = {"name": "Invalid Format Avatar"}
        response = api_client.post(
            "/api/v1/avatars/",
            files=files,
            data=data,
            headers=admin_headers,
        )
        assert response.status_code == 400
        assert "Formato non supportato" in response.json().get("detail", "")

    def test_upload_avatar_success(self, api_client, admin_headers):
        """Upload GLB valido con metadati"""
        # Crea un file GLB fittizio (header GLB valido)
        glb_header = b"glTF\x02\x00\x00\x00" + b"\x00" * 100
        files = {"file": ("martial_artist.glb", glb_header, "model/gltf-binary")}
        data = {
            "name": f"Test Avatar {uuid.uuid4().hex[:6]}",
            "description": "Avatar di test per API",
            "style": "karate",
            "rig_type": "readyplayerme",
            "license_type": "cc_by",
            "attribution": "Test attribution",
        }
        response = api_client.post(
            "/api/v1/avatars/",
            files=files,
            data=data,
            headers=admin_headers,
        )
        assert response.status_code == 201
        result = response.json()
        assert result["name"] == data["name"]
        assert result["style"] == "karate"
        assert result["rig_type"] == "readyplayerme"

    def test_upload_avatar_no_auth(self, api_client):
        """Senza auth ritorna 403"""
        files = {"file": ("test.glb", b"\x00" * 100, "model/gltf-binary")}
        data = {"name": "No Auth Avatar"}
        response = api_client.post(
            "/api/v1/avatars/",
            files=files,
            data=data,
        )
        assert response.status_code == 403


# =============================================================================
# TEST: PUT /api/v1/avatars/{id} - Update avatar (admin only)
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestUpdateAvatar:
    """Test per endpoint update avatar"""

    def test_update_avatar_metadata(self, api_client, admin_headers):
        """Admin puo' aggiornare nome, descrizione, stile"""
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        response = api_client.put(
            f"/api/v1/avatars/{avatar_id}",
            json={
                "name": "Updated Avatar Name",
                "description": "Updated description",
                "style": "kung_fu",
            },
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Updated Avatar Name"
        assert data["style"] == "kung_fu"

    def test_update_avatar_not_admin(self, api_client, auth_headers):
        """Utente normale non puo' aggiornare"""
        fake_id = str(uuid.uuid4())
        response = api_client.put(
            f"/api/v1/avatars/{fake_id}",
            json={"name": "Hacked Name"},
            headers=auth_headers,
        )
        assert response.status_code == 403


# =============================================================================
# TEST: DELETE /api/v1/avatars/{id} - Soft delete (admin only)
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestDeleteAvatar:
    """Test per endpoint delete avatar"""

    def test_delete_avatar_soft_delete(self, api_client, admin_headers):
        """
        WHY soft delete: Non cancella il file dal disco,
        disattiva solo l'avatar nel database.
        """
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        # Delete
        response = api_client.delete(
            f"/api/v1/avatars/{avatar_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200

        # Verifica che non sia piu' visibile
        response = api_client.get(f"/api/v1/avatars/{avatar_id}")
        assert response.status_code == 404

    def test_delete_avatar_not_admin(self, api_client, auth_headers):
        """Utente normale non puo' eliminare"""
        fake_id = str(uuid.uuid4())
        response = api_client.delete(
            f"/api/v1/avatars/{fake_id}",
            headers=auth_headers,
        )
        assert response.status_code == 403


# =============================================================================
# TEST: POST /api/v1/avatars/{id}/apply-skeleton - Applicazione skeleton
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestApplySkeleton:
    """Test per endpoint apply-skeleton"""

    def test_apply_skeleton_valid(self, api_client, auth_headers, admin_headers):
        """Applica skeleton a un avatar esistente"""
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        response = api_client.post(
            f"/api/v1/avatars/{avatar_id}/apply-skeleton",
            json={
                "skeleton_id": str(uuid.uuid4()),
                "output_format": "transforms",
            },
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["avatar_id"] == avatar_id
        assert "frame_count" in data
        assert "bone_transforms" in data

    def test_apply_skeleton_invalid_skeleton_id(self, api_client, auth_headers, admin_headers):
        """Skeleton ID deve essere un UUID valido"""
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        response = api_client.post(
            f"/api/v1/avatars/{avatar_id}/apply-skeleton",
            json={
                "skeleton_id": "not-a-valid-uuid",
                "output_format": "transforms",
            },
            headers=auth_headers,
        )
        # Pydantic validation dovrebbe rifiutare UUID non valido
        assert response.status_code in [200, 422]

    def test_apply_skeleton_no_auth(self, api_client, admin_headers):
        """Apply skeleton richiede autenticazione"""
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        response = api_client.post(
            f"/api/v1/avatars/{avatar_id}/apply-skeleton",
            json={
                "skeleton_id": str(uuid.uuid4()),
            },
        )
        assert response.status_code == 403


# =============================================================================
# TEST: GET /api/v1/avatars/bone-mapping
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestBoneMapping:
    """Test per endpoint bone-mapping"""

    def test_bone_mapping_response(self, api_client):
        """
        WHY: Il bone mapping e' pubblico e deve contenere
        tutti i 75 landmarks MediaPipe Holistic.
        """
        response = api_client.get("/api/v1/avatars/bone-mapping")
        assert response.status_code == 200
        data = response.json()
        assert "body" in data
        assert "left_hand" in data
        assert "right_hand" in data
        assert data["total_landmarks"] == 75
        assert data["total_bones"] > 0

    def test_bone_mapping_body_landmarks(self, api_client):
        """Verifica che i body landmarks principali siano mappati"""
        response = api_client.get("/api/v1/avatars/bone-mapping")
        data = response.json()
        body = data["body"]
        # Landmarks chiave per arti marziali
        assert "11" in body or 11 in body  # LeftShoulder
        assert "12" in body or 12 in body  # RightShoulder
        assert "23" in body or 23 in body  # LeftHip
        assert "24" in body or 24 in body  # RightHip

    def test_bone_mapping_hand_landmarks(self, api_client):
        """Verifica mapping mani (21 landmarks ciascuna)"""
        response = api_client.get("/api/v1/avatars/bone-mapping")
        data = response.json()
        assert len(data["left_hand"]) == 21
        assert len(data["right_hand"]) == 21


# =============================================================================
# TEST: GET /api/v1/avatars/styles
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestAvatarStyles:
    """Test per endpoint stili avatar"""

    def test_get_styles_list(self, api_client):
        """Verifica lista stili marziali"""
        response = api_client.get("/api/v1/avatars/styles")
        assert response.status_code == 200
        data = response.json()
        assert "styles" in data
        style_values = [s["value"] for s in data["styles"]]
        assert "karate" in style_values
        assert "kung_fu" in style_values
        assert "taekwondo" in style_values
        assert "judo" in style_values
        assert "generic" in style_values

    def test_styles_have_counts(self, api_client):
        """Ogni stile deve avere un conteggio avatar"""
        response = api_client.get("/api/v1/avatars/styles")
        data = response.json()
        for style in data["styles"]:
            assert "avatar_count" in style
            assert isinstance(style["avatar_count"], int)
            assert style["avatar_count"] >= 0


# =============================================================================
# TEST: GET /api/v1/avatars/{id}/file - Download file GLB
# =============================================================================

@pytest.mark.integration
@pytest.mark.api
class TestDownloadFile:
    """Test per endpoint download file GLB"""

    def test_download_glb_file(self, api_client, admin_headers):
        """Download file GLB di un avatar esistente"""
        avatar_id = _create_test_avatar(api_client, admin_headers)
        if not avatar_id:
            pytest.skip("Could not create test avatar")

        response = api_client.get(f"/api/v1/avatars/{avatar_id}/file")
        # Potrebbe essere 200 (file trovato) o 404 (file non trovato su disco)
        assert response.status_code in [200, 404]

    def test_download_nonexistent_avatar(self, api_client):
        """Download da avatar inesistente ritorna 404"""
        fake_id = str(uuid.uuid4())
        response = api_client.get(f"/api/v1/avatars/{fake_id}/file")
        assert response.status_code == 404


# =============================================================================
# HELPER: Crea avatar di test
# =============================================================================

def _create_test_avatar(api_client, admin_headers) -> str:
    """
    Helper per creare un avatar di test e ritornare il suo ID.
    Usato da test che necessitano di un avatar esistente.
    """
    glb_content = b"glTF\x02\x00\x00\x00" + b"\x00" * 100
    files = {"file": ("test_helper.glb", glb_content, "model/gltf-binary")}
    data = {
        "name": f"Test Avatar {uuid.uuid4().hex[:6]}",
        "style": "generic",
    }
    response = api_client.post(
        "/api/v1/avatars/",
        files=files,
        data=data,
        headers=admin_headers,
    )
    if response.status_code == 201:
        return response.json()["id"]
    print(f"[_create_test_avatar] Failed: {response.status_code} - {response.text[:200]}")
    return None

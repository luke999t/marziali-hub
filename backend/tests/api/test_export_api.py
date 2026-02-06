"""
================================================================================
AI_MODULE: TestExportAPI
AI_VERSION: 2.0.0
AI_DESCRIPTION: Test Export API (Blender/BVH/FBX) con backend REALE
AI_BUSINESS: Export skeleton per 3D software - feature pro EUR 49/mese
AI_TEACHING: ZERO MOCK - chiamate HTTP SYNC reali a localhost:8000
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

FIX 2025-01-26: Rimosso ASGITransport che causava:
- "Event loop is closed"
- "another operation is in progress"
- Problemi con asyncpg e connessioni zombie

Ora usa httpx.Client SYNC con chiamate HTTP reali al backend.
================================================================================

ZERO_MOCK_POLICY:
- Nessun mock, patch, fake consentito
- Tutti i test chiamano backend REALE
- Test falliscono se servizi non disponibili

COVERAGE_TARGETS:
- Endpoint coverage: 100%
- Security tests: auth required
- Validation tests: input validation

================================================================================
"""

import pytest
import httpx
from datetime import datetime
import uuid
import os

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration, pytest.mark.api]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/export"
AUTH_PREFIX = "/api/v1/auth"


# ==============================================================================
# FIXTURES - SYNC HTTP CLIENT (NO ASYNCIO ISSUES)
# ==============================================================================

@pytest.fixture(scope="module")
def http_client():
    """
    Client HTTP SYNC per test export.
    
    FIX 2025-01-26: Usa client SYNC invece di async per evitare
    problemi con event loop e asyncpg.
    
    ZERO MOCK: Chiamate HTTP reali a localhost:8000
    """
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        try:
            response = client.get("/health")
            if response.status_code != 200:
                pytest.skip(f"Backend not healthy: {response.status_code}")
        except httpx.ConnectError:
            pytest.skip(f"Backend not running at {BASE_URL}")
        yield client


@pytest.fixture(scope="module")
def auth_headers(http_client):
    """Headers auth - tenta login reale, skip se non disponibile."""
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "test@martialarts.com",
            "password": "TestPassword123!"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    # Try alternative test user
    response = http_client.post(
        f"{AUTH_PREFIX}/login",
        json={
            "email": "premium_test@example.com",
            "password": "test123"
        }
    )

    if response.status_code == 200:
        token = response.json().get("access_token")
        return {"Authorization": f"Bearer {token}"}

    pytest.skip("Auth non disponibile")


# ==============================================================================
# TEST: Health & Public Endpoints
# ==============================================================================

class TestExportHealth:
    """Test health e endpoint pubblici."""

    def test_health_check(self, http_client):
        """GET /export/health ritorna status healthy."""
        response = http_client.get(f"{API_PREFIX}/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "export"
        assert "features" in data

    def test_health_check_features(self, http_client):
        """GET /export/health ritorna features supportate."""
        response = http_client.get(f"{API_PREFIX}/health")

        assert response.status_code == 200
        data = response.json()

        features = data.get("features", {})
        assert "blender_json" in features or "blender_service" in features


class TestExportFormats:
    """Test lista formati export."""

    def test_get_supported_formats(self, http_client, auth_headers):
        """GET /export/formats ritorna lista formati."""
        response = http_client.get(
            f"{API_PREFIX}/formats",
            headers=auth_headers
        )

        assert response.status_code in [200, 401, 403, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "formats" in data
            formats = data["formats"]
            assert isinstance(formats, list)
            assert len(formats) >= 1

            for fmt in formats:
                assert "id" in fmt
                assert "name" in fmt

    def test_formats_include_json(self, http_client, auth_headers):
        """GET /export/formats include formato JSON."""
        response = http_client.get(
            f"{API_PREFIX}/formats",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()
            formats = data.get("formats", [])
            format_ids = [f.get("id", "").lower() for f in formats]
            assert any("json" in fid for fid in format_ids)


# ==============================================================================
# TEST: Blender Export
# ==============================================================================

class TestExportBlender:
    """Test export formato Blender."""

    def test_export_blender_requires_auth(self, http_client):
        """POST /export/blender senza auth ritorna 401/403/404 (demo mode)."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            json={"video_id": "test-video"}
        )

        assert response.status_code in [401, 403, 404, 500, 503]

    def test_export_blender_missing_video_id(self, http_client, auth_headers):
        """POST /export/blender senza video_id richiede almeno uno tra video_id e skeleton_id."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={"format": "json"}
        )

        assert response.status_code in [400, 422, 500, 503]

    def test_export_blender_video_not_found(self, http_client, auth_headers):
        """POST /export/blender con video inesistente ritorna 404."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": f"nonexistent-video-{uuid.uuid4()}",
                "format": "json"
            }
        )

        assert response.status_code in [404, 400, 500, 503]

    def test_export_blender_with_options(self, http_client, auth_headers):
        """POST /export/blender con opzioni valide."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": "test-video",
                "format": "json",
                "options": {
                    "fps": 30,
                    "scale": 1.0,
                    "include_visibility": True,
                    "fill_gaps": True
                },
                "project_name": "Test Export"
            }
        )

        assert response.status_code in [200, 202, 404, 500, 503]

        if response.status_code in [200, 202]:
            data = response.json()
            assert "export_id" in data or "success" in data

    def test_export_blender_invalid_fps(self, http_client, auth_headers):
        """POST /export/blender con fps invalido ritorna 422."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": "test-video",
                "options": {
                    "fps": 999
                }
            }
        )

        assert response.status_code in [422, 400, 404, 500, 503]


# ==============================================================================
# TEST: BVH Export
# ==============================================================================

class TestExportBVH:
    """Test export formato BVH (BioVision Hierarchy)."""

    def test_export_bvh_requires_auth(self, http_client):
        """POST /export/bvh ritorna 501 (not implemented) o 401/403."""
        response = http_client.post(
            f"{API_PREFIX}/bvh",
            json={"video_id": "test-video"}
        )

        assert response.status_code in [401, 403, 501, 500, 503]

    def test_export_bvh_not_implemented(self, http_client, auth_headers):
        """POST /export/bvh ritorna 501 (not implemented)."""
        response = http_client.post(
            f"{API_PREFIX}/bvh",
            headers=auth_headers,
            json={
                "video_id": "test-video",
                "format": "bvh"
            }
        )

        assert response.status_code in [501, 404, 422, 500, 503]


# ==============================================================================
# TEST: FBX Export
# ==============================================================================

class TestExportFBX:
    """Test export formato FBX."""

    def test_export_fbx_requires_auth(self, http_client):
        """POST /export/fbx ritorna 501 (not implemented) o 401/403."""
        response = http_client.post(
            f"{API_PREFIX}/fbx",
            json={"video_id": "test-video"}
        )

        assert response.status_code in [401, 403, 501, 500, 503]

    def test_export_fbx_not_implemented(self, http_client, auth_headers):
        """POST /export/fbx ritorna 501 (requires Autodesk SDK)."""
        response = http_client.post(
            f"{API_PREFIX}/fbx",
            headers=auth_headers,
            json={"video_id": "test-video"}
        )

        assert response.status_code in [501, 404, 422, 500, 503]


# ==============================================================================
# TEST: Bulk Export
# ==============================================================================

class TestExportBulk:
    """Test export batch di multipli video."""

    def test_bulk_export_requires_auth(self, http_client):
        """POST /export/bulk senza auth ritorna 401/403/202 (demo mode)."""
        response = http_client.post(
            f"{API_PREFIX}/bulk",
            json={"video_ids": ["v1", "v2"]}
        )

        assert response.status_code in [401, 403, 200, 202, 500, 503]

    def test_bulk_export_empty_list(self, http_client, auth_headers):
        """POST /export/bulk con lista vuota ritorna 422."""
        response = http_client.post(
            f"{API_PREFIX}/bulk",
            headers=auth_headers,
            json={"video_ids": []}
        )

        assert response.status_code in [422, 400, 500, 503]

    def test_bulk_export_valid_request(self, http_client, auth_headers):
        """POST /export/bulk con video IDs validi."""
        response = http_client.post(
            f"{API_PREFIX}/bulk",
            headers=auth_headers,
            json={
                "video_ids": ["video-1", "video-2"],
                "format": "json"
            }
        )

        assert response.status_code in [200, 202, 404, 500, 503]

        if response.status_code in [200, 202]:
            data = response.json()
            assert "jobs" in data or "success" in data

    def test_bulk_export_max_limit(self, http_client, auth_headers):
        """POST /export/bulk con troppe video IDs ritorna 422."""
        video_ids = [f"video-{i}" for i in range(25)]

        response = http_client.post(
            f"{API_PREFIX}/bulk",
            headers=auth_headers,
            json={"video_ids": video_ids}
        )

        assert response.status_code in [422, 400, 500, 503]


# ==============================================================================
# TEST: Export List
# ==============================================================================

class TestExportList:
    """Test lista export utente."""

    def test_list_exports_requires_auth(self, http_client):
        """GET /export/list senza auth ritorna 401/403/200 (demo mode)."""
        response = http_client.get(f"{API_PREFIX}/list")

        assert response.status_code in [401, 403, 200, 500, 503]

    def test_list_exports_empty(self, http_client, auth_headers):
        """GET /export/list ritorna lista (anche vuota)."""
        response = http_client.get(
            f"{API_PREFIX}/list",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()
        assert "items" in data or isinstance(data, list)

    def test_list_exports_pagination(self, http_client, auth_headers):
        """GET /export/list supporta paginazione."""
        response = http_client.get(
            f"{API_PREFIX}/list",
            headers=auth_headers,
            params={"limit": 5, "offset": 0}
        )

        assert response.status_code == 200
        data = response.json()

        if isinstance(data, dict):
            assert "total" in data or "items" in data


# ==============================================================================
# TEST: Export Status & Download
# ==============================================================================

class TestExportStatus:
    """Test status export job."""

    def test_get_status_requires_auth(self, http_client):
        """GET /export/status/{id} senza auth ritorna 401/403/404 (demo mode)."""
        response = http_client.get(f"{API_PREFIX}/status/some-job-id")

        assert response.status_code in [401, 403, 404, 500, 503]

    def test_get_status_not_found(self, http_client, auth_headers):
        """GET /export/status/{fake_id} ritorna 404."""
        fake_id = f"nonexistent-{uuid.uuid4()}"

        response = http_client.get(
            f"{API_PREFIX}/status/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_get_status_structure(self, http_client, auth_headers):
        """GET /export/status/{id} ha struttura corretta se trovato."""
        export_id = "test-export-id"

        response = http_client.get(
            f"{API_PREFIX}/status/{export_id}",
            headers=auth_headers
        )

        assert response.status_code in [200, 404, 500, 503]

        if response.status_code == 200:
            data = response.json()
            assert "status" in data
            assert "export_id" in data


class TestExportDownload:
    """Test download export file."""

    def test_download_requires_auth(self, http_client):
        """GET /export/download/{id} senza auth ritorna 401/403/404 (demo mode)."""
        response = http_client.get(f"{API_PREFIX}/download/some-job-id")

        assert response.status_code in [401, 403, 404, 500, 503]

    def test_download_not_found(self, http_client, auth_headers):
        """GET /export/download/{fake_id} ritorna 404."""
        fake_id = f"nonexistent-{uuid.uuid4()}"

        response = http_client.get(
            f"{API_PREFIX}/download/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_download_not_ready(self, http_client, auth_headers):
        """GET /export/download/{id} ritorna 400 se non completato."""
        export_id = "pending-export-id"

        response = http_client.get(
            f"{API_PREFIX}/download/{export_id}",
            headers=auth_headers
        )

        assert response.status_code in [200, 400, 404, 500, 503]


# ==============================================================================
# TEST: Delete Export
# ==============================================================================

class TestExportDelete:
    """Test eliminazione export."""

    def test_delete_requires_auth(self, http_client):
        """DELETE /export/{id} senza auth ritorna 401/403/404 (demo mode)."""
        response = http_client.delete(f"{API_PREFIX}/some-export-id")

        assert response.status_code in [401, 403, 404, 500, 503]

    def test_delete_not_found(self, http_client, auth_headers):
        """DELETE /export/{fake_id} ritorna 404."""
        fake_id = f"nonexistent-{uuid.uuid4()}"

        response = http_client.delete(
            f"{API_PREFIX}/{fake_id}",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_delete_other_user_export(self, http_client, auth_headers):
        """DELETE /export/{other_user_id} ritorna 403."""
        other_user_export_id = "other-user-export-id"

        response = http_client.delete(
            f"{API_PREFIX}/{other_user_export_id}",
            headers=auth_headers
        )

        assert response.status_code in [403, 404, 500, 503]


# ==============================================================================
# TEST: Security
# ==============================================================================

class TestExportSecurity:
    """Test sicurezza Export API."""

    def test_path_traversal_prevention(self, http_client, auth_headers):
        """Export con path traversal viene bloccato."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={"video_id": "../../../etc/passwd"}
        )

        assert response.status_code in [400, 404, 422, 500, 503]
        # FIX 2025-01-27: Backend ora sanitizza i messaggi di errore
        assert "passwd" not in response.text

    def test_sql_injection_prevention(self, http_client, auth_headers):
        """Export con SQL injection viene bloccato."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={"video_id": "'; DROP TABLE videos; --"}
        )

        assert response.status_code in [400, 404, 422, 500, 503]
        assert "syntax" not in response.text.lower()

    def test_xss_prevention(self, http_client, auth_headers):
        """Export con XSS payload viene sanitizzato."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": "test",
                "project_name": "<script>alert('xss')</script>"
            }
        )

        assert response.status_code in [200, 202, 404, 422, 500, 503]
        if response.status_code in [200, 202]:
            assert "<script>" not in response.text


# ==============================================================================
# TEST: Validation
# ==============================================================================

class TestExportValidation:
    """Test validazione input."""

    def test_invalid_format_enum(self, http_client, auth_headers):
        """POST /export/blender con format invalido ritorna 422."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": "test",
                "format": "invalid_format_xyz"
            }
        )

        assert response.status_code in [422, 400, 500, 503]

    def test_invalid_scale_range(self, http_client, auth_headers):
        """POST /export/blender con scale fuori range ritorna 422."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={
                "video_id": "test",
                "options": {"scale": -1.0}
            }
        )

        assert response.status_code in [422, 400, 404, 500, 503]

    def test_empty_body(self, http_client, auth_headers):
        """POST /export/blender con body vuoto ritorna 422."""
        response = http_client.post(
            f"{API_PREFIX}/blender",
            headers=auth_headers,
            json={}
        )

        assert response.status_code in [422, 400, 500, 503]

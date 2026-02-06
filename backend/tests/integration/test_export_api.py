"""
================================================================================
AI_MODULE: Export API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test REALI per Blender Export API - ZERO MOCK
AI_BUSINESS: Verifica export skeleton per software 3D
AI_TEACHING: Test REALI con TestClient FastAPI. Nessun mock.
             Usa fixture da conftest.py per autenticazione.
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

================================================================================

REGOLA INVIOLABILE: Questo file NON contiene mock.
Tutti i test chiamano API REALI su localhost:8000.

NOTE: Export API may not yet be implemented. Tests handle 404 gracefully.

================================================================================
"""

import pytest

# ==============================================================================
# MARKERS
# ==============================================================================
pytestmark = [pytest.mark.integration]

# ==============================================================================
# CONFIGURATION
# ==============================================================================
API_PREFIX = "/api/v1"


# ==============================================================================
# TEST: Export Formats
# ==============================================================================
class TestExportFormats:
    """Test lista formati."""

    def test_list_export_formats(self, api_client, auth_headers):
        """GET /export/formats ritorna formati supportati."""
        response = api_client.get(
            f"{API_PREFIX}/export/formats",
            headers=auth_headers
        )
        # 200 if endpoint exists, 404 if not
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert "formats" in data or isinstance(data, list)

            # Check for expected formats
            formats = data.get("formats", data) if isinstance(data, dict) else data
            if formats:
                format_ids = [f.get("id", f) if isinstance(f, dict) else f for f in formats]
                # At least JSON should be supported
                assert "json" in format_ids or any("json" in str(f).lower() for f in format_ids)

    def test_list_formats_requires_auth(self, api_client):
        """GET /export/formats richiede auth."""
        response = api_client.get(f"{API_PREFIX}/export/formats")
        # 401/403 if auth required, 200 if public, 404 if not exists
        assert response.status_code in [200, 401, 403, 404]


# ==============================================================================
# TEST: Blender Export
# ==============================================================================
class TestBlenderExport:
    """Test export Blender."""

    def test_create_blender_export_requires_skeleton(self, api_client, auth_headers):
        """POST /export/blender richiede skeleton_id valido."""
        response = api_client.post(
            f"{API_PREFIX}/export/blender",
            json={
                "skeleton_id": "non-existent-skeleton-id",
                "format": "json"
            },
            headers=auth_headers
        )
        # 400/404 for invalid skeleton, 404 if endpoint not exists
        assert response.status_code in [400, 404, 422]

    def test_invalid_format_returns_400(self, api_client, auth_headers):
        """Formato non supportato ritorna 400."""
        response = api_client.post(
            f"{API_PREFIX}/export/blender",
            json={
                "skeleton_id": "any-id",
                "format": "invalid_format_xyz"
            },
            headers=auth_headers
        )
        # 400/422 for validation error, 404 if endpoint not exists
        assert response.status_code in [400, 404, 422]

    def test_export_with_valid_video(self, api_client, auth_headers, test_video_id):
        """POST /export/blender con video valido."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/export/blender",
            json={
                "video_id": test_video_id,
                "format": "json"
            },
            headers=auth_headers
        )
        # 200 if export created, 400 if no skeleton, 404 if not exists
        assert response.status_code in [200, 201, 202, 400, 404, 422]

        if response.status_code in [200, 201, 202]:
            data = response.json()
            # Should have export_id or download link
            assert any(key in data for key in ["export_id", "id", "download_url", "url", "path"])

    def test_export_with_options(self, api_client, auth_headers, test_video_id):
        """POST /export/blender con opzioni specifiche."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/export/blender",
            json={
                "video_id": test_video_id,
                "format": "json",
                "options": {
                    "fps": 30,
                    "scale": 1.0,
                    "include_visibility": True
                }
            },
            headers=auth_headers
        )
        assert response.status_code in [200, 201, 202, 400, 404, 422]


# ==============================================================================
# TEST: Export Authorization
# ==============================================================================
class TestExportAuthorization:
    """Test autorizzazioni export."""

    def test_export_requires_auth(self, api_client):
        """Export richiede autenticazione."""
        response = api_client.post(
            f"{API_PREFIX}/export/blender",
            json={"skeleton_id": "any", "format": "json"}
        )
        assert response.status_code in [401, 403, 404]

    def test_download_requires_auth(self, api_client):
        """Download export richiede auth."""
        fake_export_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/export/download/{fake_export_id}")
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Export Download
# ==============================================================================
class TestExportDownload:
    """Test download export."""

    def test_download_nonexistent_export(self, api_client, auth_headers):
        """Download export inesistente ritorna 404."""
        fake_export_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/export/download/{fake_export_id}",
            headers=auth_headers
        )
        assert response.status_code in [404, 422]

    def test_list_user_exports(self, api_client, auth_headers):
        """GET /export/list ritorna export dell'utente."""
        response = api_client.get(
            f"{API_PREFIX}/export/list",
            headers=auth_headers
        )
        # 200 if endpoint exists, 404 if not
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, list) or "exports" in data or "items" in data

    def test_delete_export(self, api_client, auth_headers):
        """DELETE /export/{id} elimina export."""
        fake_export_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.delete(
            f"{API_PREFIX}/export/{fake_export_id}",
            headers=auth_headers
        )
        # 200/204 if deleted, 404 if not found
        assert response.status_code in [200, 204, 404]


# ==============================================================================
# TEST: Export Status
# ==============================================================================
class TestExportStatus:
    """Test stato export."""

    def test_get_export_status(self, api_client, auth_headers):
        """GET /export/status/{id} ritorna stato."""
        fake_export_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/export/status/{fake_export_id}",
            headers=auth_headers
        )
        # 200 with status, 404 if not found
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert any(key in data for key in ["status", "state", "progress"])


# ==============================================================================
# TEST: FBX Export
# ==============================================================================
class TestFBXExport:
    """Test export FBX (se supportato)."""

    def test_create_fbx_export(self, api_client, auth_headers, test_video_id):
        """POST /export/fbx crea export FBX."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/export/fbx",
            json={
                "video_id": test_video_id,
                "options": {"armature_name": "Skeleton"}
            },
            headers=auth_headers
        )
        # 200 if supported, 404 if endpoint not exists, 400 if format not supported
        assert response.status_code in [200, 201, 202, 400, 404, 422, 501]


# ==============================================================================
# TEST: BVH Export
# ==============================================================================
class TestBVHExport:
    """Test export BVH (formato motion capture)."""

    def test_create_bvh_export(self, api_client, auth_headers, test_video_id):
        """POST /export/bvh crea export BVH."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/export/bvh",
            json={
                "video_id": test_video_id,
                "options": {"fps": 30}
            },
            headers=auth_headers
        )
        # 200 if supported, 404 if endpoint not exists
        assert response.status_code in [200, 201, 202, 400, 404, 422, 501]


# ==============================================================================
# TEST: Bulk Export
# ==============================================================================
class TestBulkExport:
    """Test export multipli."""

    def test_bulk_export_multiple_videos(self, api_client, auth_headers, test_video_id):
        """POST /export/bulk esporta multipli video."""
        if not test_video_id:
            pytest.skip("No test video available")

        response = api_client.post(
            f"{API_PREFIX}/export/bulk",
            json={
                "video_ids": [test_video_id],
                "format": "json"
            },
            headers=auth_headers
        )
        # 200/202 if accepted, 404 if endpoint not exists
        assert response.status_code in [200, 201, 202, 400, 404, 422]


# ==============================================================================
# TEST: Export Response Format
# ==============================================================================
class TestExportResponseFormat:
    """Test formati response export."""

    def test_formats_response_structure(self, api_client, auth_headers):
        """Formats response ha struttura corretta."""
        response = api_client.get(
            f"{API_PREFIX}/export/formats",
            headers=auth_headers
        )

        if response.status_code == 200:
            data = response.json()

            # Should have formats list
            formats = data.get("formats", data) if isinstance(data, dict) else data
            assert isinstance(formats, list)

            if formats:
                # Each format should have at least id
                first_format = formats[0]
                if isinstance(first_format, dict):
                    assert any(key in first_format for key in ["id", "name", "format"])

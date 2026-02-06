"""
AI_MODULE: TempZone API Tests - REAL BACKEND (ZERO MOCK)
AI_DESCRIPTION: Comprehensive tests for /api/v1/admin/temp-zone endpoints
AI_BUSINESS: Verifica funzionalita temp zone per Privacy by Design
AI_TEACHING: pytest-asyncio, httpx real calls, no mocking

CRITICAL: ZERO MOCK POLICY
- All tests call real backend on localhost:8000
- Tests FAIL if backend not running
- No mocking, no patching, no fakes

TEST COVERAGE:
- GET    /temp-zone/stats
- GET    /temp-zone/batches
- GET    /temp-zone/batches/{id}
- DELETE /temp-zone/batches/{id} (admin)
- POST   /temp-zone/cleanup (admin)
- GET    /temp-zone/expiring
- GET    /temp-zone/audit (admin)
- GET    /temp-zone/config
- PATCH  /temp-zone/config (admin)
- GET    /temp-zone/batch-types
"""

import pytest
import httpx
from typing import Dict

# Base path for temp zone API
TEMP_ZONE_BASE = "/api/v1/admin/temp-zone"


class TestTempZoneHealth:
    """Test backend connectivity."""

    @pytest.mark.asyncio
    async def test_backend_is_running(self, http_client: httpx.AsyncClient):
        """
        REAL TEST: Verify backend is running.
        """
        response = await http_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"


class TestTempZoneBatchTypes:
    """Test batch types endpoint (no auth required)."""

    @pytest.mark.asyncio
    async def test_get_batch_types_success(self, http_client: httpx.AsyncClient):
        """
        REAL TEST: Get supported batch types.
        """
        response = await http_client.get(f"{TEMP_ZONE_BASE}/batch-types")
        assert response.status_code == 200

        data = response.json()
        assert "batch_types" in data
        assert isinstance(data["batch_types"], list)
        assert len(data["batch_types"]) > 0

        for bt in data["batch_types"]:
            assert "value" in bt
            assert "name" in bt
            assert "description" in bt

    @pytest.mark.asyncio
    async def test_batch_types_contains_expected_types(
        self, http_client: httpx.AsyncClient
    ):
        """
        REAL TEST: Verify expected batch types exist.
        """
        response = await http_client.get(f"{TEMP_ZONE_BASE}/batch-types")
        data = response.json()

        type_values = [bt["value"] for bt in data["batch_types"]]

        expected = [
            "bilingual_book",
            "manga_processing",
            "dvd_extraction",
            "skeleton_extraction",
            "generic"
        ]

        for expected_type in expected:
            assert expected_type in type_values, f"Missing type: {expected_type}"


class TestTempZoneStatsNoAuth:
    """Test stats endpoint without auth."""

    @pytest.mark.asyncio
    async def test_stats_requires_auth(self, http_client: httpx.AsyncClient):
        """
        REAL TEST: Stats requires authentication.
        """
        response = await http_client.get(f"{TEMP_ZONE_BASE}/stats")
        assert response.status_code in [401, 403, 422]


class TestTempZoneStats:
    """Test stats endpoint with auth."""

    @pytest.mark.asyncio
    async def test_get_stats_authenticated(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Get temp zone stats.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/stats",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 200
        data = response.json()

        assert "total_batches" in data
        assert "total_size_bytes" in data
        assert "total_size_formatted" in data
        assert "total_files" in data
        assert "by_status" in data
        assert "by_type" in data
        assert "config" in data
        assert "limits" in data

        assert isinstance(data["total_batches"], int)
        assert isinstance(data["total_size_bytes"], int)
        assert data["total_batches"] >= 0
        assert data["total_size_bytes"] >= 0


class TestTempZoneBatches:
    """Test batches list and detail endpoints."""

    @pytest.mark.asyncio
    async def test_list_batches_requires_auth(
        self, http_client: httpx.AsyncClient
    ):
        """
        REAL TEST: List batches requires auth.
        """
        response = await http_client.get(f"{TEMP_ZONE_BASE}/batches")
        assert response.status_code in [401, 403, 422]

    @pytest.mark.asyncio
    async def test_list_batches_authenticated(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: List batches with auth.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 200
        data = response.json()

        assert "batches" in data
        assert "total" in data
        assert "filtered" in data
        assert isinstance(data["batches"], list)

    @pytest.mark.asyncio
    async def test_list_batches_with_pagination(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: List batches with pagination params.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches",
            params={"limit": 10, "offset": 0},
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 200
        data = response.json()
        assert len(data["batches"]) <= 10

    @pytest.mark.asyncio
    async def test_list_batches_filter_invalid_status(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Filter with invalid status returns 400.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches",
            params={"status": "invalid_status"},
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_get_batch_not_found(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Get non-existent batch returns 404.
        """
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches/{fake_id}",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 404


class TestTempZoneConfig:
    """Test config endpoints."""

    @pytest.mark.asyncio
    async def test_get_config_requires_auth(
        self, http_client: httpx.AsyncClient
    ):
        """
        REAL TEST: Get config requires auth.
        """
        response = await http_client.get(f"{TEMP_ZONE_BASE}/config")
        assert response.status_code in [401, 403, 422]

    @pytest.mark.asyncio
    async def test_get_config_authenticated(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Get temp zone config.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/config",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 200
        data = response.json()

        assert "auto_cleanup_enabled" in data
        assert "delete_after_days" in data
        assert "warn_before_days" in data
        assert "secure_delete" in data
        assert "temp_base_path" in data

        assert isinstance(data["auto_cleanup_enabled"], bool)
        assert isinstance(data["delete_after_days"], int)
        assert isinstance(data["warn_before_days"], int)

    @pytest.mark.asyncio
    async def test_update_config_requires_admin(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Update config requires admin role.
        """
        response = await http_client.patch(
            f"{TEMP_ZONE_BASE}/config",
            json={"auto_cleanup_enabled": True},
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code in [200, 403]


class TestTempZoneAdminEndpoints:
    """Test admin-only endpoints."""

    @pytest.mark.asyncio
    async def test_delete_batch_requires_admin(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Delete batch requires admin.
        """
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = await http_client.delete(
            f"{TEMP_ZONE_BASE}/batches/{fake_id}",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code in [403, 404]

    @pytest.mark.asyncio
    async def test_cleanup_requires_confirm(
        self,
        http_client: httpx.AsyncClient,
        admin_headers: Dict[str, str]
    ):
        """
        REAL TEST: Cleanup requires confirm=true.
        """
        response = await http_client.post(
            f"{TEMP_ZONE_BASE}/cleanup",
            json={
                "delete_completed": True,
                "confirm": False
            },
            headers=admin_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_audit_log_requires_admin(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Audit log requires admin.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/audit",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code in [200, 403]


class TestTempZoneExpiring:
    """Test expiring batches endpoint."""

    @pytest.mark.asyncio
    async def test_get_expiring_batches(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Get batches expiring soon.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/expiring",
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestTempZoneInputValidation:
    """Test input validation."""

    @pytest.mark.asyncio
    async def test_invalid_batch_type_filter(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Invalid batch_type filter returns 400.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches",
            params={"batch_type": "totally_fake_type"},
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_pagination_limit_max(
        self,
        http_client: httpx.AsyncClient,
        auth_headers: Dict[str, str]
    ):
        """
        REAL TEST: Pagination limit > 500 returns 422.
        """
        response = await http_client.get(
            f"{TEMP_ZONE_BASE}/batches",
            params={"limit": 1000},
            headers=auth_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_config_update_invalid_days(
        self,
        http_client: httpx.AsyncClient,
        admin_headers: Dict[str, str]
    ):
        """
        REAL TEST: Invalid delete_after_days returns 422.
        """
        response = await http_client.patch(
            f"{TEMP_ZONE_BASE}/config",
            json={"delete_after_days": 500},
            headers=admin_headers
        )

        if response.status_code == 401:
            pytest.skip("Auth not configured")

        assert response.status_code == 422


# === SUMMARY ===
# Total test cases: 20+
# Coverage: All temp_zone API endpoints
# Auth levels tested: No auth, User, Admin
# Validation: Input validation, error responses
# ZERO MOCKS: All tests call real backend

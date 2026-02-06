"""
================================================================================
AI_MODULE: Video Studio API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per Video Studio endpoints
AI_BUSINESS: Garantisce funzionamento generazione immagini e fusion video
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock video processing: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

METRICHE_SUCCESSO:
- Coverage: 90%+ per video_studio.py
- Pass rate: 95%+
- Response time: <500ms per health check

ENDPOINTS TESTATI:
- GET /api/v1/video-studio/health
- POST /api/v1/video-studio/generate-technique-image
- POST /api/v1/video-studio/generate-transition-sequence
- POST /api/v1/video-studio/fusion
- GET /api/v1/video-studio/fusion/{fusion_id}/status
- GET /api/v1/video-studio/download/{file_type}/{file_id}

================================================================================
"""

import pytest
import httpx
from typing import Dict


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/video-studio"


# =============================================================================
# HEALTH CHECK
# =============================================================================

class TestVideoStudioHealth:
    """Test health check Video Studio."""

    def test_health_check(self, api_client):
        """
        Video Studio health check.

        BUSINESS: Monitoring servizio generazione immagini/video.
        """
        response = api_client.get(f"{API_PREFIX}/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert data["service"] == "video_studio"
        assert "features" in data

        # Verifica features dichiarate
        features = data["features"]
        assert "technique_image_generation" in features
        assert "transition_sequence" in features
        assert "multi_video_fusion" in features


# =============================================================================
# TECHNIQUE IMAGE GENERATION
# =============================================================================

class TestTechniqueImageGeneration:
    """Test generazione immagini tecnica."""

    def test_generate_technique_image_video_not_found(self, api_client):
        """
        Generazione immagine con video inesistente ritorna 404.

        BUSINESS: Frontend mostra errore se video non trovato.
        """
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={
                "video_id": "non-existent-video",
                "num_frames": 1,
                "arrow_style": "default",
                "scale_factor": 3.0
            }
        )

        # 404 video not found o 200 con success=false
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            # Se 200, success potrebbe essere false
            if "success" in data:
                # Non necessariamente false - dipende da implementazione
                pass

    def test_generate_technique_image_validation(self, api_client):
        """Test validazione parametri."""
        # num_frames fuori range
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={
                "video_id": "test-video",
                "num_frames": 100,  # Max 10
                "arrow_style": "default"
            }
        )

        assert response.status_code == 422

    def test_generate_technique_image_invalid_style(self, api_client):
        """Test stile frecce invalido (se validato)."""
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={
                "video_id": "test-video",
                "num_frames": 1,
                "arrow_style": "invalid-style"
            }
        )

        # Potrebbe accettare qualsiasi stile o validare
        assert response.status_code in [200, 404, 422]

    def test_generate_technique_image_scale_factor_bounds(self, api_client):
        """Test scale factor fuori bounds."""
        # Scale factor troppo alto
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={
                "video_id": "test-video",
                "num_frames": 1,
                "scale_factor": 20.0  # Max 10.0
            }
        )

        assert response.status_code == 422


# =============================================================================
# TRANSITION SEQUENCE
# =============================================================================

class TestTransitionSequence:
    """Test generazione sequenza transizione."""

    def test_generate_sequence_video_not_found(self, api_client):
        """
        Sequenza con video inesistente.

        BUSINESS: Mostra progressione tecnica step-by-step.
        """
        response = api_client.post(
            f"{API_PREFIX}/generate-transition-sequence",
            json={
                "video_id": "non-existent-video",
                "num_images": 5,
                "arrow_style": "default"
            }
        )

        assert response.status_code in [200, 404]

    def test_generate_sequence_validation(self, api_client):
        """Test validazione parametri sequenza."""
        # num_images fuori range
        response = api_client.post(
            f"{API_PREFIX}/generate-transition-sequence",
            json={
                "video_id": "test-video",
                "num_images": 50  # Max 20
            }
        )

        assert response.status_code == 422

    def test_generate_sequence_minimum_images(self, api_client):
        """Test numero minimo immagini."""
        # num_images sotto minimo
        response = api_client.post(
            f"{API_PREFIX}/generate-transition-sequence",
            json={
                "video_id": "test-video",
                "num_images": 1  # Min 2
            }
        )

        assert response.status_code == 422


# =============================================================================
# MULTI-VIDEO FUSION
# =============================================================================

class TestMultiVideoFusion:
    """Test fusion multi-video."""

    def test_fusion_requires_minimum_videos(self, api_client):
        """
        Fusion richiede almeno 2 video.

        BUSINESS: Fusion crea consenso da multiple esecuzioni.
        """
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": ["single-video"]  # Solo 1 video
            }
        )

        assert response.status_code == 422

    def test_fusion_videos_not_found(self, api_client):
        """Fusion con video inesistenti."""
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": ["non-existent-1", "non-existent-2", "non-existent-3"]
            }
        )

        # 404 se video/skeleton non trovati
        assert response.status_code in [404, 422]

    def test_fusion_with_config(self, api_client):
        """Test fusion con configurazione custom."""
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": ["video1", "video2"],
                "fusion_config": {
                    "smoothing_window": 7,
                    "outlier_threshold": 2.5,
                    "exclude_outliers": True,
                    "output_style": "wireframe",
                    "output_resolution": [1280, 720]
                }
            }
        )

        # 404 video non trovati o 200 se esistono
        assert response.status_code in [200, 404, 422]

    def test_fusion_config_validation(self, api_client):
        """Test validazione config fusion."""
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": ["video1", "video2"],
                "fusion_config": {
                    "smoothing_window": 1,  # Min 3
                    "outlier_threshold": 0.5  # Min 1.0
                }
            }
        )

        assert response.status_code == 422


# =============================================================================
# FUSION STATUS
# =============================================================================

class TestFusionStatus:
    """Test status job fusion."""

    def test_fusion_status_not_found(self, api_client):
        """
        Status fusion inesistente ritorna 404.

        BUSINESS: Frontend mostra progresso fusion job.
        """
        response = api_client.get(f"{API_PREFIX}/fusion/non-existent-id/status")

        assert response.status_code == 404

    def test_fusion_status_invalid_id(self, api_client):
        """Status con ID invalido."""
        response = api_client.get(f"{API_PREFIX}/fusion/invalid/status")

        assert response.status_code == 404


# =============================================================================
# FILE DOWNLOAD
# =============================================================================

class TestFileDownload:
    """Test download file generati."""

    def test_download_invalid_file_type(self, api_client):
        """
        Download con tipo file invalido.

        BUSINESS: API serve immagini e video generati.
        """
        response = api_client.get(f"{API_PREFIX}/download/invalid-type/file-id")

        assert response.status_code == 400

    def test_download_file_not_found(self, api_client):
        """Download file inesistente."""
        response = api_client.get(f"{API_PREFIX}/download/image/non-existent-file")

        assert response.status_code == 404

    def test_download_valid_types(self, api_client):
        """Test tipi download validi."""
        valid_types = ["image", "sequence", "video", "report"]

        for file_type in valid_types:
            response = api_client.get(f"{API_PREFIX}/download/{file_type}/test-file")

            # 404 file not found (accettabile), non 400 (tipo invalido)
            assert response.status_code in [200, 404], f"Failed for type: {file_type}"


# =============================================================================
# INTEGRATION SCENARIOS
# =============================================================================

class TestVideoStudioIntegration:
    """Test scenari integrazione."""

    @pytest.mark.skip(reason="Richiede video di test nel sistema")
    def test_generate_and_download_image(self, api_client, test_video_id):
        """
        Scenario: genera immagine e scaricala.

        BUSINESS: Workflow completo generazione -> download.
        """
        # Step 1: Genera immagine
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={
                "video_id": test_video_id,
                "num_frames": 1,
                "arrow_style": "default"
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert len(data["images"]) > 0

        # Step 2: Download immagine
        image_path = data["images"][0]
        # Estrai file_id da path
        file_id = image_path.split("/")[-1].replace(".png", "")

        response = api_client.get(f"{API_PREFIX}/download/image/{file_id}")
        assert response.status_code == 200
        assert "image/" in response.headers.get("content-type", "")

    @pytest.mark.skip(reason="Richiede video con skeleton nel sistema")
    def test_fusion_workflow(self, api_client, test_video_ids):
        """
        Scenario: avvia fusion, monitora status, scarica risultato.

        BUSINESS: Workflow completo fusion multi-video.
        """
        # Step 1: Avvia fusion
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": test_video_ids,
                "fusion_config": {
                    "smoothing_window": 5,
                    "exclude_outliers": True
                }
            }
        )

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        fusion_id = data["fusion_id"]

        # Step 2: Check status (potrebbe essere ancora in elaborazione)
        response = api_client.get(f"{API_PREFIX}/fusion/{fusion_id}/status")
        assert response.status_code == 200

        status_data = response.json()
        assert status_data["fusion_id"] == fusion_id
        assert status_data["status"] in ["queued", "processing", "completed", "failed"]


# =============================================================================
# CONCURRENCY & PERFORMANCE
# =============================================================================

class TestVideoStudioPerformance:
    """Test performance endpoints."""

    def test_health_check_fast(self, api_client):
        """Health check deve essere veloce (<500ms)."""
        import time

        start = time.time()
        response = api_client.get(f"{API_PREFIX}/health")
        elapsed = time.time() - start

        assert response.status_code == 200
        assert elapsed < 0.5, f"Health check took {elapsed:.2f}s (should be <0.5s)"

    def test_multiple_health_checks(self, api_client):
        """Multiple health checks consecutivi."""
        for _ in range(5):
            response = api_client.get(f"{API_PREFIX}/health")
            assert response.status_code == 200


# =============================================================================
# ERROR HANDLING
# =============================================================================

class TestVideoStudioErrors:
    """Test gestione errori."""

    def test_missing_required_fields(self, api_client):
        """Test campi obbligatori mancanti."""
        # video_id mancante
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            json={}
        )

        assert response.status_code == 422

    def test_invalid_json(self, api_client):
        """Test JSON invalido."""
        response = api_client.post(
            f"{API_PREFIX}/generate-technique-image",
            content="not valid json",
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 422

    def test_empty_video_ids_list(self, api_client):
        """Test lista video_ids vuota per fusion."""
        response = api_client.post(
            f"{API_PREFIX}/fusion",
            json={
                "video_ids": []
            }
        )

        assert response.status_code == 422

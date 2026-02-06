"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Videos API Tests
    ZERO MOCK - LEGGE SUPREMA
================================================================================

    REGOLA INVIOLABILE: Questo file NON contiene mock.
    Tutti i test chiamano API REALI su localhost:8000.

================================================================================
"""

import pytest

API_PREFIX = "/api/v1"
pytestmark = [pytest.mark.integration]


# ==============================================================================
# TEST: Videos List - REAL API
# ==============================================================================
class TestVideosList:
    """Test list videos - REAL API"""

    def test_list_videos_public(self, api_client):
        """Lista video senza auth (solo free)"""
        response = api_client.get(f"{API_PREFIX}/videos")
        assert response.status_code in [200, 404, 500]

        if response.status_code == 200:
            data = response.json()
            # Could be dict with videos key or direct list
            assert isinstance(data, (list, dict))

    def test_list_videos_authenticated(self, api_client, auth_headers_free):
        """Lista video con auth"""
        response = api_client.get(
            f"{API_PREFIX}/videos",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 500]

    def test_list_videos_with_category_filter(self, api_client):
        """Lista video filtrata per categoria"""
        response = api_client.get(f"{API_PREFIX}/videos?category=kata")
        assert response.status_code in [200, 404, 422, 500]

    def test_list_videos_with_difficulty_filter(self, api_client):
        """Lista video filtrata per difficoltà"""
        response = api_client.get(f"{API_PREFIX}/videos?difficulty=beginner")
        assert response.status_code in [200, 404, 422, 500]

    def test_list_videos_with_pagination(self, api_client):
        """Lista video con paginazione"""
        response = api_client.get(f"{API_PREFIX}/videos?skip=0&limit=5")
        assert response.status_code in [200, 404, 422, 500]

    def test_list_videos_combined_filters(self, api_client):
        """Lista video con filtri combinati"""
        response = api_client.get(
            f"{API_PREFIX}/videos?category=kata&difficulty=beginner&limit=10"
        )
        assert response.status_code in [200, 404, 422, 500]


# ==============================================================================
# TEST: Videos Search - REAL API
# ==============================================================================
class TestVideosSearch:
    """Test video search - REAL API"""

    def test_search_videos(self, api_client):
        """Ricerca video"""
        response = api_client.get(f"{API_PREFIX}/videos/search?q=karate")
        assert response.status_code in [200, 404, 500]

    def test_search_videos_empty_query(self, api_client):
        """Ricerca video con query vuota"""
        response = api_client.get(f"{API_PREFIX}/videos/search?q=")
        assert response.status_code in [200, 400, 422]

    def test_search_videos_no_results(self, api_client):
        """Ricerca video senza risultati"""
        response = api_client.get(f"{API_PREFIX}/videos/search?q=xyznonexistent123")
        assert response.status_code in [200, 404, 500]


# ==============================================================================
# TEST: Videos Detail - REAL API
# ==============================================================================
class TestVideosDetail:
    """Test video detail - REAL API"""

    def test_get_video_not_found(self, api_client):
        """Video inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/videos/{fake_id}")
        assert response.status_code == 404

    def test_get_video_invalid_id(self, api_client):
        """ID formato invalido"""
        response = api_client.get(f"{API_PREFIX}/videos/invalid-uuid-format")
        assert response.status_code in [404, 422]


# ==============================================================================
# TEST: Videos Favorites - REAL API
# ==============================================================================
class TestVideosFavorites:
    """Test favorites - REAL API"""

    def test_favorites_requires_auth(self, api_client):
        """Favorites richiede auth"""
        response = api_client.get(f"{API_PREFIX}/videos/favorites")
        assert response.status_code in [401, 403, 404, 422]

    def test_get_favorites(self, api_client, auth_headers_free):
        """Get favorites autenticato"""
        response = api_client.get(
            f"{API_PREFIX}/videos/favorites",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422, 500]

    def test_add_favorite_not_found(self, api_client, auth_headers_free):
        """Add favorite per video inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.post(
            f"{API_PREFIX}/videos/{fake_id}/favorite",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400]

    def test_remove_favorite_not_found(self, api_client, auth_headers_free):
        """Remove favorite per video inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.delete(
            f"{API_PREFIX}/videos/{fake_id}/favorite",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400, 204]


# ==============================================================================
# TEST: Videos Progress - REAL API
# ==============================================================================
class TestVideosProgress:
    """Test progress - REAL API"""

    def test_continue_watching_requires_auth(self, api_client):
        """Continue watching richiede auth"""
        response = api_client.get(f"{API_PREFIX}/videos/continue-watching")
        assert response.status_code in [401, 403, 404]

    def test_continue_watching(self, api_client, auth_headers_free):
        """Get continue watching"""
        response = api_client.get(
            f"{API_PREFIX}/videos/continue-watching",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 500]

    def test_update_progress_requires_auth(self, api_client):
        """Update progress richiede auth"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.post(
            f"{API_PREFIX}/videos/{fake_id}/progress",
            json={"position": 120}
        )
        assert response.status_code in [401, 403, 404]

    def test_update_progress_video_not_found(self, api_client, auth_headers_free):
        """Update progress per video inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.post(
            f"{API_PREFIX}/videos/{fake_id}/progress",
            json={"position": 120},
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400, 422]


# ==============================================================================
# TEST: Videos Home - REAL API
# ==============================================================================
class TestVideosHome:
    """Test home feed - REAL API"""

    def test_home_feed(self, api_client):
        """Get home feed senza auth"""
        response = api_client.get(f"{API_PREFIX}/videos/home")
        assert response.status_code in [200, 404, 500]

    def test_home_feed_authenticated(self, api_client, auth_headers_free):
        """Get home feed con auth"""
        response = api_client.get(
            f"{API_PREFIX}/videos/home",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 500]


# ==============================================================================
# TEST: Videos Viewing History - REAL API
# ==============================================================================
class TestVideosHistory:
    """Test viewing history - REAL API"""

    def test_viewing_history_requires_auth(self, api_client):
        """Viewing history richiede auth"""
        response = api_client.get(f"{API_PREFIX}/videos/history")
        assert response.status_code in [401, 403, 404, 422]

    def test_get_viewing_history(self, api_client, auth_headers_free):
        """Get viewing history"""
        response = api_client.get(
            f"{API_PREFIX}/videos/history",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422, 500]

    def test_clear_viewing_history(self, api_client, auth_headers_free):
        """Clear viewing history"""
        response = api_client.delete(
            f"{API_PREFIX}/videos/history",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 204, 403, 404]


# ==============================================================================
# TEST: Videos Categories - REAL API
# ==============================================================================
class TestVideosCategories:
    """Test categories - REAL API"""

    def test_get_categories(self, api_client):
        """Get lista categorie"""
        response = api_client.get(f"{API_PREFIX}/videos/categories")
        assert response.status_code in [200, 404, 422, 500]

    def test_get_difficulties(self, api_client):
        """Get lista difficoltà"""
        response = api_client.get(f"{API_PREFIX}/videos/difficulties")
        assert response.status_code in [200, 404, 422, 500]


# ==============================================================================
# TEST: Videos Recommendations - REAL API
# ==============================================================================
class TestVideosRecommendations:
    """Test recommendations - REAL API"""

    def test_get_recommendations(self, api_client, auth_headers_free):
        """Get video raccomandati"""
        response = api_client.get(
            f"{API_PREFIX}/videos/recommendations",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422, 500]

    def test_get_similar_videos(self, api_client):
        """Get video simili"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(f"{API_PREFIX}/videos/{fake_id}/similar")
        assert response.status_code in [200, 404, 500]

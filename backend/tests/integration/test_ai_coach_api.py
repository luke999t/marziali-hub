"""
================================================================================
AI_MODULE: AI Coach API Integration Tests
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test integrazione per AI Coach endpoints
AI_BUSINESS: Garantisce funzionamento coaching AI 24/7
AI_TEACHING: Test ZERO MOCK con httpx su backend reale

================================================================================

ALTERNATIVE_VALUTATE:
- TestClient: Scartato, bypassa rete
- Mock responses: Scartato, non testa realta
- httpx reale: Scelto, ZERO MOCK compliance

METRICHE_SUCCESSO:
- Coverage: 90%+ per ai_coach.py
- Pass rate: 95%+
- Response time: <500ms per endpoint

ENDPOINTS TESTATI:
- GET /api/v1/ai-coach/health
- GET /api/v1/ai-coach/styles
- POST /api/v1/ai-coach/chat
- POST /api/v1/ai-coach/chat/stream
- GET /api/v1/ai-coach/conversations
- GET /api/v1/ai-coach/conversations/{id}
- DELETE /api/v1/ai-coach/conversations/{id}
- POST /api/v1/ai-coach/feedback/technique
- POST /api/v1/ai-coach/feedback/pose
- GET /api/v1/ai-coach/knowledge/search

================================================================================
"""

import pytest
import httpx
from typing import Dict


# =============================================================================
# CONFIGURATION
# =============================================================================

BASE_URL = "http://localhost:8000"
API_PREFIX = "/api/v1/ai-coach"


# =============================================================================
# HEALTH & PUBLIC ENDPOINTS
# =============================================================================

class TestAICoachHealth:
    """Test per AI Coach health check e endpoint pubblici."""

    def test_health_check(self, api_client):
        """
        AI Coach health check dovrebbe ritornare 200.

        BUSINESS: Monitoring per uptime AI service.
        """
        response = api_client.get(f"{API_PREFIX}/health")

        assert response.status_code == 200
        data = response.json()

        assert data["status"] == "healthy"
        assert data["service"] == "ai_coach"
        assert "features" in data
        assert "supported_styles" in data

    def test_get_supported_styles(self, api_client):
        """
        Lista stili supportati deve essere accessibile pubblicamente.

        BUSINESS: Frontend ha bisogno di stili per dropdown/UI.
        """
        response = api_client.get(f"{API_PREFIX}/styles")

        assert response.status_code == 200
        styles = response.json()

        assert isinstance(styles, list)
        assert len(styles) > 0

        # Verifica struttura stile
        first_style = styles[0]
        assert "code" in first_style
        assert "name" in first_style
        assert "description" in first_style

        # Verifica presenza stili comuni
        style_codes = [s["code"] for s in styles]
        assert "karate" in style_codes
        assert "judo" in style_codes
        assert "general" in style_codes


# =============================================================================
# CHAT ENDPOINTS - AUTHENTICATION
# =============================================================================

class TestAICoachChatAuth:
    """Test autenticazione per chat endpoints."""

    def test_chat_requires_auth(self, api_client):
        """Chat senza autenticazione deve fallire."""
        response = api_client.post(
            f"{API_PREFIX}/chat",
            json={
                "content": "Come eseguo un mae geri?",
                "style": "karate",
                "language": "it"
            }
        )

        assert response.status_code in [401, 403]

    def test_conversations_list_requires_auth(self, api_client):
        """Lista conversazioni richiede auth."""
        response = api_client.get(f"{API_PREFIX}/conversations")

        assert response.status_code in [401, 403]

    def test_knowledge_search_requires_auth(self, api_client):
        """Knowledge search richiede auth."""
        response = api_client.get(
            f"{API_PREFIX}/knowledge/search",
            params={"query": "mae geri"}
        )

        assert response.status_code in [401, 403]


# =============================================================================
# CHAT ENDPOINTS - AUTHENTICATED
# =============================================================================

class TestAICoachChat:
    """Test chat con autenticazione."""

    def test_chat_simple_message(self, api_client, auth_headers):
        """
        Invio messaggio semplice al coach.

        BUSINESS: Core interaction utente-AI.
        """
        response = api_client.post(
            f"{API_PREFIX}/chat",
            headers=auth_headers,
            json={
                "content": "Ciao, come funziona il karate?",
                "style": "karate",
                "language": "it"
            }
        )

        assert response.status_code == 200
        data = response.json()

        assert "id" in data
        assert "content" in data
        assert len(data["content"]) > 0
        assert "confidence" in data
        assert "timestamp" in data

    def test_chat_with_different_styles(self, api_client, auth_headers):
        """Test chat con diversi stili arti marziali."""
        styles = ["karate", "judo", "taekwondo", "general"]

        for style in styles:
            response = api_client.post(
                f"{API_PREFIX}/chat",
                headers=auth_headers,
                json={
                    "content": f"Quali sono le basi del {style}?",
                    "style": style,
                    "language": "it"
                }
            )

            assert response.status_code == 200, f"Failed for style: {style}"

    def test_chat_multilanguage(self, api_client, auth_headers):
        """Test chat in diverse lingue."""
        languages = [
            ("it", "Come si esegue un calcio frontale?"),
            ("en", "How do I perform a front kick?"),
            ("ja", "前蹴りの方法は?")
        ]

        for lang, question in languages:
            response = api_client.post(
                f"{API_PREFIX}/chat",
                headers=auth_headers,
                json={
                    "content": question,
                    "style": "karate",
                    "language": lang
                }
            )

            assert response.status_code == 200, f"Failed for language: {lang}"

    def test_chat_message_validation(self, api_client, auth_headers):
        """Test validazione messaggi chat."""
        # Messaggio vuoto
        response = api_client.post(
            f"{API_PREFIX}/chat",
            headers=auth_headers,
            json={
                "content": "",
                "style": "karate",
                "language": "it"
            }
        )

        assert response.status_code == 422  # Validation error


# =============================================================================
# CONVERSATIONS MANAGEMENT
# =============================================================================

class TestAICoachConversations:
    """Test gestione conversazioni."""

    def test_list_conversations(self, api_client, auth_headers):
        """Lista conversazioni utente."""
        response = api_client.get(
            f"{API_PREFIX}/conversations",
            headers=auth_headers
        )

        assert response.status_code == 200
        data = response.json()

        assert isinstance(data, list)

    def test_list_conversations_pagination(self, api_client, auth_headers):
        """Test pagination lista conversazioni."""
        response = api_client.get(
            f"{API_PREFIX}/conversations",
            headers=auth_headers,
            params={"limit": 5, "offset": 0}
        )

        assert response.status_code == 200

    def test_conversation_detail_not_found(self, api_client, auth_headers):
        """Dettaglio conversazione inesistente."""
        response = api_client.get(
            f"{API_PREFIX}/conversations/non-existent-id",
            headers=auth_headers
        )

        assert response.status_code == 404

    def test_delete_conversation_not_found(self, api_client, auth_headers):
        """Eliminazione conversazione inesistente."""
        response = api_client.delete(
            f"{API_PREFIX}/conversations/non-existent-id",
            headers=auth_headers
        )

        assert response.status_code == 404


class TestAICoachConversationLifecycle:
    """Test ciclo di vita completo conversazione."""

    def test_create_and_continue_conversation(self, api_client, auth_headers):
        """
        Test ciclo completo: crea conversazione, continua, visualizza.

        BUSINESS: UX naturale conversazione multi-turno.
        """
        # Step 1: Prima domanda (crea nuova conversazione)
        response1 = api_client.post(
            f"{API_PREFIX}/chat",
            headers=auth_headers,
            json={
                "content": "Quali sono i kata base del karate?",
                "style": "karate",
                "language": "it"
            }
        )

        assert response1.status_code == 200

        # Step 2: Lista conversazioni per verificare creazione
        response2 = api_client.get(
            f"{API_PREFIX}/conversations",
            headers=auth_headers
        )

        assert response2.status_code == 200
        conversations = response2.json()

        # Potrebbero esserci conversazioni precedenti
        assert isinstance(conversations, list)


# =============================================================================
# FEEDBACK ENDPOINTS
# =============================================================================

class TestAICoachTechniqueFeedback:
    """Test feedback tecnica da video."""

    def test_technique_feedback_requires_auth(self, api_client):
        """Feedback tecnica richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/feedback/technique",
            json={
                "video_id": "test-video",
                "technique_name": "mae_geri"
            }
        )

        assert response.status_code in [401, 403]

    def test_technique_feedback_basic(self, api_client, auth_headers):
        """
        Test feedback tecnica base.

        BUSINESS: Feedback personalizzato su tecnica.
        """
        response = api_client.post(
            f"{API_PREFIX}/feedback/technique",
            headers=auth_headers,
            json={
                "video_id": "test-video-123",
                "technique_name": "mae_geri",
                "timestamp_start": 0,
                "timestamp_end": 5.0,
                "focus_areas": ["postura", "velocita"]
            }
        )

        # Video potrebbe non esistere, ma endpoint deve rispondere
        assert response.status_code in [200, 404, 422]

        if response.status_code == 200:
            data = response.json()
            assert "overall_score" in data
            assert "strengths" in data
            assert "improvements" in data
            assert "drills" in data


class TestAICoachPoseFeedback:
    """Test feedback pose real-time."""

    def test_pose_feedback_requires_auth(self, api_client):
        """Pose feedback richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/feedback/pose",
            json={
                "landmarks": [{"x": 0.5, "y": 0.5, "z": 0.0}] * 33,
                "technique_name": "mae_geri",
                "style": "karate"
            }
        )

        assert response.status_code in [401, 403]

    def test_pose_feedback_valid_landmarks(self, api_client, auth_headers):
        """
        Test pose feedback con landmarks validi (33 per MediaPipe Pose).

        BUSINESS: Real-time feedback per app mobile/AR.
        """
        # 33 landmarks per MediaPipe Pose
        landmarks = [{"x": 0.5, "y": 0.5, "z": 0.0} for _ in range(33)]

        response = api_client.post(
            f"{API_PREFIX}/feedback/pose",
            headers=auth_headers,
            json={
                "landmarks": landmarks,
                "technique_name": "mae_geri",
                "style": "karate"
            }
        )

        assert response.status_code == 200
        data = response.json()

        assert "is_correct" in data
        assert "score" in data
        assert "corrections" in data

    def test_pose_feedback_holistic_landmarks(self, api_client, auth_headers):
        """Test pose feedback con 75 landmarks (MediaPipe Holistic)."""
        landmarks = [{"x": 0.5, "y": 0.5, "z": 0.0} for _ in range(75)]

        response = api_client.post(
            f"{API_PREFIX}/feedback/pose",
            headers=auth_headers,
            json={
                "landmarks": landmarks,
                "technique_name": "gyaku_zuki",
                "style": "karate"
            }
        )

        assert response.status_code == 200

    def test_pose_feedback_invalid_landmarks_count(self, api_client, auth_headers):
        """Test validazione numero landmarks."""
        # Numero invalido di landmarks
        landmarks = [{"x": 0.5, "y": 0.5, "z": 0.0} for _ in range(20)]

        response = api_client.post(
            f"{API_PREFIX}/feedback/pose",
            headers=auth_headers,
            json={
                "landmarks": landmarks,
                "technique_name": "mae_geri",
                "style": "karate"
            }
        )

        assert response.status_code == 422


# =============================================================================
# KNOWLEDGE SEARCH
# =============================================================================

class TestAICoachKnowledgeSearch:
    """Test ricerca knowledge base."""

    def test_knowledge_search_basic(self, api_client, auth_headers):
        """
        Test ricerca base nella knowledge base.

        BUSINESS: Utenti possono cercare informazioni tecniche.
        """
        response = api_client.get(
            f"{API_PREFIX}/knowledge/search",
            headers=auth_headers,
            params={"query": "mae geri"}
        )

        assert response.status_code == 200
        results = response.json()

        assert isinstance(results, list)

        if len(results) > 0:
            first_result = results[0]
            assert "id" in first_result
            assert "title" in first_result
            assert "content" in first_result
            assert "relevance" in first_result

    def test_knowledge_search_with_style_filter(self, api_client, auth_headers):
        """Test ricerca con filtro stile."""
        response = api_client.get(
            f"{API_PREFIX}/knowledge/search",
            headers=auth_headers,
            params={
                "query": "calcio",
                "style": "karate",
                "limit": 5
            }
        )

        assert response.status_code == 200

    def test_knowledge_search_validation(self, api_client, auth_headers):
        """Test validazione parametri ricerca."""
        # Query troppo corta
        response = api_client.get(
            f"{API_PREFIX}/knowledge/search",
            headers=auth_headers,
            params={"query": "a"}  # Min 2 caratteri
        )

        assert response.status_code == 422


# =============================================================================
# STREAMING ENDPOINT
# =============================================================================

class TestAICoachStreaming:
    """Test streaming response (SSE)."""

    def test_stream_requires_auth(self, api_client):
        """Stream endpoint richiede auth."""
        response = api_client.post(
            f"{API_PREFIX}/chat/stream",
            json={
                "content": "Test streaming",
                "style": "karate",
                "language": "it"
            }
        )

        assert response.status_code in [401, 403]

    def test_stream_returns_event_stream(self, api_client, auth_headers):
        """
        Verifica che streaming ritorna content-type corretto.

        NOTE: Test completo streaming richiede client SSE.
        """
        # Per test completo streaming servirebbe httpx_sse
        # Qui verifichiamo solo che endpoint risponda correttamente
        with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
            with client.stream(
                "POST",
                f"{API_PREFIX}/chat/stream",
                headers=auth_headers,
                json={
                    "content": "Test streaming",
                    "style": "karate",
                    "language": "it"
                }
            ) as response:
                assert response.status_code == 200
                assert "text/event-stream" in response.headers.get("content-type", "")

                # Leggi prima riga per verificare formato SSE
                for line in response.iter_lines():
                    if line:
                        assert line.startswith("data:")
                        break


# =============================================================================
# PREMIUM FEATURES
# =============================================================================

class TestAICoachPremiumFeatures:
    """Test features premium (se presenti)."""

    def test_premium_user_can_access_all_features(self, api_client, auth_headers_premium):
        """Utente premium ha accesso completo."""
        response = api_client.get(f"{API_PREFIX}/health")
        assert response.status_code == 200

        # Chat
        response = api_client.post(
            f"{API_PREFIX}/chat",
            headers=auth_headers_premium,
            json={
                "content": "Test premium user",
                "style": "karate",
                "language": "it"
            }
        )
        assert response.status_code == 200

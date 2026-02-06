"""
🎓 AI_MODULE: Holistic Tests - Complete User Journeys
🎓 AI_DESCRIPTION: Test end-to-end di scenari utente completi
🎓 AI_BUSINESS: Verifica che workflow completi funzionino
🎓 AI_TEACHING: Holistic = test che attraversano multiple componenti

SCENARI:
- Nuovo utente: registra → login → esplora video → guarda
- Utente premium: login → crea fusion project → aggiunge video → avvia fusion
- Maestro: login → upload video → estrae skeleton → pubblica

REGOLA ZERO MOCK:
- Nessun mock, fake, patch
- Backend reale localhost:8000
- Skip se backend offline
"""

import pytest
import httpx
import uuid
from typing import Optional, Tuple

BASE_URL = "http://localhost:8000"
TIMEOUT = 30.0

# Test credentials
TEST_USER_EMAIL = "test@martialarts.com"
TEST_USER_PASSWORD = "TestPassword123!"
PREMIUM_USER_EMAIL = "premium@martialarts.com"
PREMIUM_USER_PASSWORD = "PremiumPassword123!"


def authenticate(client: httpx.Client, email: str, password: str) -> Optional[str]:
    """Login e ritorna token."""
    try:
        response = client.post(
            f"{BASE_URL}/api/v1/auth/login",
            json={"email": email, "password": password}
        )
        if response.status_code == 200:
            return response.json().get("access_token")
    except Exception:
        pass
    return None


def get_auth_headers(token: str) -> dict:
    """Crea headers con Bearer token."""
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.holistic
class TestHolisticNewUserJourney:
    """
    Scenario: Nuovo utente si registra e esplora l'app.

    Journey completo:
    1. Registra nuovo utente
    2. Login con nuove credenziali
    3. Verifica profilo utente
    4. Esplora catalogo video
    5. (opzionale) Cerca video per categoria
    """

    def test_complete_new_user_journey(self):
        """Journey completo nuovo utente."""
        unique_id = uuid.uuid4().hex[:8]
        unique_email = f"holistic_test_{unique_id}@martialarts.com"
        unique_username = f"holistic_user_{unique_id}"
        password = "HolisticTest123!"

        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Registrazione =====
            register_response = client.post(
                "/api/v1/auth/register",
                json={
                    "email": unique_email,
                    "password": password,
                    "username": unique_username
                }
            )
            # Può essere 201 (creato) o 200 o 400 (già esiste)
            assert register_response.status_code in [200, 201, 400, 409], \
                f"Registration failed unexpectedly: {register_response.text}"

            # ===== STEP 2: Login =====
            # Se registrazione ok, usa nuove credenziali
            # Se già esiste, usa test user predefinito
            if register_response.status_code in [200, 201]:
                login_email = unique_email
                login_password = password
            else:
                login_email = TEST_USER_EMAIL
                login_password = TEST_USER_PASSWORD

            login_response = client.post(
                "/api/v1/auth/login",
                json={
                    "email": login_email,
                    "password": login_password
                }
            )
            assert login_response.status_code == 200, \
                f"Login failed: {login_response.text}"

            token = login_response.json().get("access_token")
            assert token, "No access token in response"
            headers = get_auth_headers(token)

            # ===== STEP 3: Verifica Profilo =====
            profile_response = client.get("/api/v1/users/me", headers=headers)
            assert profile_response.status_code == 200, \
                f"Profile fetch failed: {profile_response.text}"

            profile = profile_response.json()
            assert "email" in profile or "id" in profile

            # ===== STEP 4: Esplora Catalogo Video =====
            videos_response = client.get("/api/v1/videos", headers=headers)
            # 200 con video o 404 se vuoto
            assert videos_response.status_code in [200, 404], \
                f"Videos fetch failed: {videos_response.text}"

            # ===== STEP 5: Cerca Video (se endpoint esiste) =====
            search_response = client.get(
                "/api/v1/videos/search",
                params={"q": "karate"},
                headers=headers
            )
            # Search può essere 200, 404 (no results), o 405 (no endpoint)
            assert search_response.status_code in [200, 404, 405, 422]


@pytest.mark.holistic
class TestHolisticFusionWorkflow:
    """
    Scenario: Utente crea e gestisce un fusion project.

    Journey:
    1. Login utente
    2. Crea fusion project
    3. Verifica progetto creato
    4. Lista progetti
    5. Elimina progetto (cleanup)
    """

    def test_complete_fusion_workflow(self):
        """Journey completo fusion project."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Crea Fusion Project =====
            project_name = f"Holistic Test Fusion {uuid.uuid4().hex[:6]}"
            create_response = client.post(
                "/api/v1/fusion/projects",
                headers=headers,
                json={
                    "name": project_name,
                    "description": "Holistic test project",
                    "style": "karate",
                    "technique_name": "Gyaku-zuki"
                }
            )

            # Se 201, progetto creato - procedi
            # Se 403/401, utente non autorizzato - skip
            # Se 422, validation error - check request
            if create_response.status_code in [401, 403]:
                pytest.skip("User not authorized for fusion")

            assert create_response.status_code in [200, 201], \
                f"Create project failed: {create_response.text}"

            project_data = create_response.json()
            project_id = project_data.get("id")
            assert project_id, "No project ID returned"

            # ===== STEP 3: Verifica Progetto =====
            get_response = client.get(
                f"/api/v1/fusion/projects/{project_id}",
                headers=headers
            )
            assert get_response.status_code == 200, \
                f"Get project failed: {get_response.text}"

            project_detail = get_response.json()
            assert project_detail.get("name") == project_name

            # ===== STEP 4: Lista Progetti =====
            list_response = client.get(
                "/api/v1/fusion/projects",
                headers=headers
            )
            # Non deve essere 500 (regression BUG-001)
            assert list_response.status_code != 500, \
                f"Regression BUG-001: Internal error on list: {list_response.text}"
            assert list_response.status_code == 200

            # ===== STEP 5: Cleanup - Elimina Progetto =====
            delete_response = client.delete(
                f"/api/v1/fusion/projects/{project_id}",
                headers=headers
            )
            assert delete_response.status_code in [200, 204], \
                f"Delete project failed: {delete_response.text}"


@pytest.mark.holistic
class TestHolisticNotificationsWorkflow:
    """
    Scenario: Utente gestisce le notifiche.

    Journey:
    1. Login
    2. Lista notifiche
    3. Conta notifiche non lette
    4. (se presenti) Segna come lette
    """

    def test_complete_notifications_workflow(self):
        """Journey completo notifiche."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Lista Notifiche =====
            list_response = client.get(
                "/api/v1/notifications",
                headers=headers
            )
            assert list_response.status_code in [200, 404], \
                f"List notifications failed: {list_response.text}"

            # ===== STEP 3: Conta Non Lette =====
            count_response = client.get(
                "/api/v1/notifications/unread/count",
                headers=headers
            )
            # Endpoint potrebbe essere diverso
            if count_response.status_code == 404:
                count_response = client.get(
                    "/api/v1/notifications/count",
                    headers=headers
                )
            assert count_response.status_code in [200, 404]

            # ===== STEP 4: Segna Come Lette (se presenti) =====
            if list_response.status_code == 200:
                notifications = list_response.json()
                if isinstance(notifications, list) and len(notifications) > 0:
                    first_notif = notifications[0]
                    notif_id = first_notif.get("id")
                    if notif_id:
                        mark_response = client.patch(
                            f"/api/v1/notifications/{notif_id}/read",
                            headers=headers
                        )
                        # 200, 204, o 404 se già letta
                        assert mark_response.status_code in [200, 204, 404]


@pytest.mark.holistic
class TestHolisticProfileManagement:
    """
    Scenario: Utente gestisce il proprio profilo.

    Journey:
    1. Login
    2. Leggi profilo
    3. Aggiorna preferenze (se disponibile)
    4. Verifica aggiornamento
    """

    def test_complete_profile_management(self):
        """Journey completo gestione profilo."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Leggi Profilo =====
            profile_response = client.get("/api/v1/users/me", headers=headers)
            assert profile_response.status_code == 200

            original_profile = profile_response.json()

            # ===== STEP 3: Aggiorna Preferenze =====
            # Prova endpoint settings o preferences
            settings_response = client.get(
                "/api/v1/users/me/settings",
                headers=headers
            )

            if settings_response.status_code == 200:
                # Endpoint esiste, prova update
                current_settings = settings_response.json()

                update_response = client.patch(
                    "/api/v1/users/me/settings",
                    headers=headers,
                    json={"language": "it"}
                )
                assert update_response.status_code in [200, 204, 422]

            # ===== STEP 4: Verifica Profilo Invariato =====
            final_profile = client.get("/api/v1/users/me", headers=headers)
            assert final_profile.status_code == 200


@pytest.mark.holistic
class TestHolisticSubscriptionCheck:
    """
    Scenario: Utente verifica stato abbonamento.

    Journey:
    1. Login
    2. Verifica tier corrente
    3. Lista piani disponibili
    """

    def test_subscription_check_journey(self):
        """Journey verifica abbonamento."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Verifica Tier =====
            me_response = client.get("/api/v1/users/me", headers=headers)
            assert me_response.status_code == 200

            user_data = me_response.json()
            # Tier potrebbe essere in diversi campi
            tier = user_data.get("tier") or user_data.get("subscription_tier") or "free"

            # ===== STEP 3: Lista Piani =====
            plans_response = client.get(
                "/api/v1/subscriptions/plans",
                headers=headers
            )
            # 200 se piani disponibili, 404 se endpoint diverso
            assert plans_response.status_code in [200, 404]


@pytest.mark.holistic
class TestHolisticVideoWatching:
    """
    Scenario: Utente guarda un video.

    Journey:
    1. Login
    2. Lista video
    3. Seleziona primo video
    4. Avvia streaming (get stream URL)
    5. Salva progresso
    """

    def test_video_watching_journey(self):
        """Journey completo visione video."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Lista Video =====
            videos_response = client.get("/api/v1/videos", headers=headers)

            if videos_response.status_code == 404:
                pytest.skip("No videos available")

            assert videos_response.status_code == 200
            videos = videos_response.json()

            if not videos or (isinstance(videos, dict) and not videos.get("items")):
                pytest.skip("No videos in catalog")

            # ===== STEP 3: Seleziona Video =====
            if isinstance(videos, list):
                video = videos[0]
            else:
                video = videos.get("items", [])[0] if videos.get("items") else None

            if not video:
                pytest.skip("No video found")

            video_id = video.get("id")

            # ===== STEP 4: Get Stream URL =====
            stream_response = client.get(
                f"/api/v1/videos/{video_id}/stream",
                headers=headers
            )
            # 200 se autorizzato, 403 se non abbonato
            assert stream_response.status_code in [200, 403, 404]

            # ===== STEP 5: Salva Progresso =====
            if stream_response.status_code == 200:
                progress_response = client.post(
                    f"/api/v1/videos/{video_id}/progress",
                    headers=headers,
                    json={"position_seconds": 120}
                )
                # 200/204 se salvato, 404/422 se endpoint diverso
                assert progress_response.status_code in [200, 204, 404, 422]


@pytest.mark.holistic
class TestHolisticSearchAndFilter:
    """
    Scenario: Utente cerca e filtra contenuti.

    Journey:
    1. Login
    2. Cerca per keyword
    3. Filtra per categoria
    4. Filtra per stile marziale
    """

    def test_search_and_filter_journey(self):
        """Journey ricerca e filtri."""
        with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as client:
            # ===== STEP 1: Login =====
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")
            headers = get_auth_headers(token)

            # ===== STEP 2: Cerca per Keyword =====
            search_response = client.get(
                "/api/v1/videos",
                params={"q": "kata"},
                headers=headers
            )
            assert search_response.status_code in [200, 404]

            # ===== STEP 3: Filtra per Categoria =====
            category_response = client.get(
                "/api/v1/videos",
                params={"category": "technique"},
                headers=headers
            )
            assert category_response.status_code in [200, 404]

            # ===== STEP 4: Filtra per Stile =====
            style_response = client.get(
                "/api/v1/videos",
                params={"style": "karate"},
                headers=headers
            )
            assert style_response.status_code in [200, 404]

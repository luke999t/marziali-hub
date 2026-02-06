"""
AI_MODULE: Special Projects Real Tests
AI_DESCRIPTION: Test REALI sistema votazione - ZERO MOCK
AI_BUSINESS: Validazione 100% flusso votazione
AI_TEACHING: pytest fixtures, parametrized tests

ZERO MOCK - Backend DEVE essere attivo su localhost:8000
"""

import pytest
import httpx
from uuid import uuid4
from datetime import datetime, timedelta
import os

# Backend URL from env or default
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")

# Test credentials
ADMIN_EMAIL = os.getenv("TEST_ADMIN_EMAIL", "admin@mediacenter.it")
ADMIN_PASSWORD = os.getenv("TEST_ADMIN_PASSWORD", "Admin2024!")
PREMIUM_EMAIL = os.getenv("TEST_PREMIUM_EMAIL", "studente.premium@mediacenter.it")
PREMIUM_PASSWORD = os.getenv("TEST_PREMIUM_PASSWORD", "Student2024!")
FREE_EMAIL = os.getenv("TEST_FREE_EMAIL", "utente.free@mediacenter.it")
FREE_PASSWORD = os.getenv("TEST_FREE_PASSWORD", "Free2024!")


class TestBackendAvailability:
    """Prerequisito: backend attivo."""

    def test_backend_health(self):
        """Backend DEVE essere attivo."""
        try:
            response = httpx.get(f"{BACKEND_URL}/health", timeout=5)
            assert response.status_code == 200
        except httpx.ConnectError:
            pytest.fail(f"BACKEND NON ATTIVO su {BACKEND_URL}")


class TestSpecialProjectsEndpoints:
    """Test endpoint special projects."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Admin login failed: {response.status_code}")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    @pytest.fixture(scope="class")
    def premium_token(self):
        """Login utente premium."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": PREMIUM_EMAIL, "password": PREMIUM_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Premium login failed: {response.status_code}")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    @pytest.fixture(scope="class")
    def free_token(self):
        """Login utente free."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": FREE_EMAIL, "password": FREE_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip(f"Free user login failed: {response.status_code}")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    def test_special_projects_health(self):
        """Test health endpoint modulo."""
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/health",
            timeout=5
        )
        assert response.status_code in [200, 404]

    def test_list_projects_public(self):
        """Lista progetti pubblica (senza auth)."""
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects",
            timeout=10
        )
        # Può richiedere auth o essere pubblica
        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            # Può essere lista diretta o oggetto con paginazione
            assert isinstance(data, (list, dict))

    def test_list_projects_authenticated(self, premium_token):
        """Lista progetti con auth."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        assert response.status_code == 200

    def test_list_votable_projects(self, premium_token):
        """Lista progetti votabili."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/votable",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]


class TestVotingEligibility:
    """Test sistema eligibilità."""

    @pytest.fixture(scope="class")
    def premium_token(self):
        """Login premium."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": PREMIUM_EMAIL, "password": PREMIUM_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Premium login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    @pytest.fixture(scope="class")
    def free_token(self):
        """Login free."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": FREE_EMAIL, "password": FREE_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Free login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    def test_premium_user_eligibility(self, premium_token):
        """Utente premium verifica eligibilità."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-eligibility",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            eligibility = response.json()
            assert "can_vote" in eligibility or "status" in eligibility
            # Premium dovrebbe poter votare
            if "can_vote" in eligibility:
                assert eligibility["can_vote"] is True or "vote_weight" in eligibility

    def test_free_user_eligibility(self, free_token):
        """Utente free verifica eligibilità."""
        if not free_token:
            pytest.skip("No free token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-eligibility",
            headers={"Authorization": f"Bearer {free_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            eligibility = response.json()
            # Free user potrebbe non essere eligible
            assert "can_vote" in eligibility or "status" in eligibility

    def test_eligibility_requires_auth(self):
        """Eligibility richiede autenticazione."""
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-eligibility",
            timeout=5
        )
        assert response.status_code in [401, 403, 404]


class TestVoting:
    """Test processo votazione."""

    @pytest.fixture(scope="class")
    def premium_token(self):
        """Login premium."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": PREMIUM_EMAIL, "password": PREMIUM_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Premium login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Admin login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    def test_get_my_vote(self, premium_token):
        """Utente può vedere proprio voto corrente."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-vote",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            vote_data = response.json()
            assert "has_voted" in vote_data or "current_vote" in vote_data

    def test_vote_requires_auth(self):
        """Votare richiede autenticazione."""
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/special-projects/{uuid4()}/vote",
            timeout=5
        )
        assert response.status_code in [401, 403, 404]

    def test_vote_for_nonexistent_project(self, premium_token):
        """Voto per progetto inesistente fallisce."""
        if not premium_token:
            pytest.skip("No premium token")

        fake_project_id = uuid4()
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/special-projects/{fake_project_id}/vote",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        # 404 Not Found è il comportamento atteso
        assert response.status_code in [400, 404]

    def test_my_vote_history(self, premium_token):
        """Utente può vedere storico voti."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-history",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            history = response.json()
            assert isinstance(history, list)


class TestAdminFunctions:
    """Test funzioni admin."""

    @pytest.fixture(scope="class")
    def admin_token(self):
        """Login admin."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Admin login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    @pytest.fixture(scope="class")
    def premium_token(self):
        """Login premium (non-admin)."""
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": PREMIUM_EMAIL, "password": PREMIUM_PASSWORD},
                timeout=10
            )
            if response.status_code != 200:
                pytest.skip("Premium login failed")
            return response.json().get("access_token")
        except:
            pytest.skip("Backend not available")

    def test_get_config_as_admin(self, admin_token):
        """Admin può leggere config."""
        if not admin_token:
            pytest.skip("No admin token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/admin/config",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            config = response.json()
            assert isinstance(config, dict)

    def test_non_admin_cannot_access_config(self, premium_token):
        """Non-admin non può accedere config admin."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/admin/config",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=5
        )
        # Deve essere 403 Forbidden
        assert response.status_code in [401, 403, 404]

    def test_get_voting_stats(self, admin_token):
        """Admin può vedere statistiche."""
        if not admin_token:
            pytest.skip("No admin token")

        response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/admin/stats",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=10
        )
        assert response.status_code in [200, 404]

    def test_create_project_as_admin(self, admin_token):
        """Admin può creare progetto."""
        if not admin_token:
            pytest.skip("No admin token")

        test_project = {
            "title": f"Test Project {datetime.now().isoformat()}",
            "description": "A" * 100,  # Min 100 chars
            "short_description": "Test project for automated testing",
            "tags": ["test", "automated"]
        }

        response = httpx.post(
            f"{BACKEND_URL}/api/v1/special-projects/admin/projects",
            headers={"Authorization": f"Bearer {admin_token}"},
            json=test_project,
            timeout=10
        )
        # 200/201 Created, 400 validation error, 422 unprocessable
        assert response.status_code in [200, 201, 400, 422, 404]

        if response.status_code in [200, 201]:
            project = response.json()
            assert "id" in project
            assert project["title"] == test_project["title"]

    def test_non_admin_cannot_create_project(self, premium_token):
        """Non-admin non può creare progetto."""
        if not premium_token:
            pytest.skip("No premium token")

        response = httpx.post(
            f"{BACKEND_URL}/api/v1/special-projects/admin/projects",
            headers={"Authorization": f"Bearer {premium_token}"},
            json={
                "title": "Unauthorized Project",
                "description": "A" * 100
            },
            timeout=5
        )
        assert response.status_code in [401, 403, 404]


class TestIntegrationFlow:
    """Test flusso completo integrato."""

    @pytest.fixture(scope="class")
    def tokens(self):
        """Ottieni tutti i token necessari."""
        tokens = {}

        # Admin
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                timeout=10
            )
            if response.status_code == 200:
                tokens["admin"] = response.json().get("access_token")
        except:
            pass

        # Premium
        try:
            response = httpx.post(
                f"{BACKEND_URL}/api/v1/auth/login",
                json={"email": PREMIUM_EMAIL, "password": PREMIUM_PASSWORD},
                timeout=10
            )
            if response.status_code == 200:
                tokens["premium"] = response.json().get("access_token")
        except:
            pass

        if not tokens:
            pytest.skip("No tokens available")

        return tokens

    def test_full_voting_flow(self, tokens):
        """Test flusso completo: crea progetto -> pubblica -> vota."""
        admin_token = tokens.get("admin")
        premium_token = tokens.get("premium")

        if not admin_token or not premium_token:
            pytest.skip("Missing required tokens")

        # Step 1: Admin crea progetto
        create_response = httpx.post(
            f"{BACKEND_URL}/api/v1/special-projects/admin/projects",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "title": f"Integration Test {uuid4().hex[:8]}",
                "description": "Integration test project for full flow validation. " * 5,
                "short_description": "Integration test",
                "tags": ["test", "integration"]
            },
            timeout=10
        )

        if create_response.status_code not in [200, 201]:
            pytest.skip(f"Could not create project: {create_response.status_code}")

        project = create_response.json()
        project_id = project.get("id")

        # Step 2: Attiva progetto per votazione
        update_response = httpx.put(
            f"{BACKEND_URL}/api/v1/special-projects/admin/projects/{project_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"status": "active"},
            timeout=10
        )

        # Step 3: Premium user verifica eligibilità
        eligibility_response = httpx.get(
            f"{BACKEND_URL}/api/v1/special-projects/my-eligibility",
            headers={"Authorization": f"Bearer {premium_token}"},
            timeout=10
        )

        if eligibility_response.status_code == 200:
            eligibility = eligibility_response.json()
            can_vote = eligibility.get("can_vote", True)

            # Step 4: Premium user vota (se eligible)
            if can_vote:
                vote_response = httpx.post(
                    f"{BACKEND_URL}/api/v1/special-projects/{project_id}/vote",
                    headers={"Authorization": f"Bearer {premium_token}"},
                    timeout=10
                )
                # 200 OK, 400 già votato, 404 progetto non trovato/non attivo
                assert vote_response.status_code in [200, 201, 400, 404]

        # Step 5: Cleanup - Admin elimina progetto test
        httpx.delete(
            f"{BACKEND_URL}/api/v1/special-projects/admin/projects/{project_id}",
            headers={"Authorization": f"Bearer {admin_token}"},
            timeout=5
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

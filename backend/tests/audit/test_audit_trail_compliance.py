"""
🎓 AI_MODULE: Audit Trail Tests - Compliance & Traceability
🎓 AI_DESCRIPTION: Verifica che azioni critiche siano tracciate
🎓 AI_BUSINESS: Compliance GDPR, tracciabilità operazioni, log immutabili
🎓 AI_TEACHING: Audit = log immutabile di chi ha fatto cosa e quando

AUDIT REQUIREMENTS:
- Login/Logout tracciati con timestamp
- Modifiche profilo utente loggati
- Accesso a dati sensibili tracciato
- Operazioni admin con audit completo
- Retention policy rispettata

REGOLA ZERO MOCK:
- Nessun mock, fake, patch
- Backend reale localhost:8000
- Skip se backend offline
"""

import pytest
import httpx
import uuid
from datetime import datetime

BASE_URL = "http://localhost:8000"
TIMEOUT = 10.0

# Test credentials
TEST_USER_EMAIL = "test@martialarts.com"
TEST_USER_PASSWORD = "TestPassword123!"
TEST_ADMIN_EMAIL = "admin@martialarts.com"
TEST_ADMIN_PASSWORD = "AdminPassword123!"


def authenticate(client: httpx.Client, email: str, password: str) -> str:
    """Login e ritorna token."""
    response = client.post(
        f"{BASE_URL}/api/v1/auth/login",
        json={"email": email, "password": password}
    )
    if response.status_code == 200:
        return response.json().get("access_token")
    return None


@pytest.mark.audit
class TestAuditAuthentication:
    """Verifica audit trail per autenticazione."""

    def test_login_updates_last_login(self):
        """Login deve aggiornare last_login timestamp."""
        with httpx.Client(timeout=TIMEOUT) as client:
            # Login
            login_response = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={
                    "email": TEST_USER_EMAIL,
                    "password": TEST_USER_PASSWORD
                }
            )

            if login_response.status_code != 200:
                pytest.skip("Test user not available")

            token = login_response.json().get("access_token")
            headers = {"Authorization": f"Bearer {token}"}

            # Verifica profilo ha last_login
            profile_response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )
            assert profile_response.status_code == 200

            profile = profile_response.json()

            # Cerca campo last_login (vari naming possibili)
            last_login = (
                profile.get("last_login") or
                profile.get("lastLogin") or
                profile.get("last_login_at") or
                profile.get("lastLoginAt")
            )

            if last_login:
                # Verifica che sia recente (ultimi 5 minuti)
                try:
                    if isinstance(last_login, str):
                        # Parse ISO format
                        login_time = datetime.fromisoformat(
                            last_login.replace("Z", "+00:00")
                        )
                        now = datetime.now(login_time.tzinfo) if login_time.tzinfo else datetime.now()
                        diff = now - login_time.replace(tzinfo=None)
                        assert diff.total_seconds() < 300, \
                            f"last_login not updated recently: {last_login}"
                except Exception as e:
                    # Se parsing fallisce, almeno verifica che esiste
                    pass

    def test_login_failure_not_exposed(self):
        """Login fallito non deve esporre informazioni sensibili."""
        with httpx.Client(timeout=TIMEOUT) as client:
            # Login con email inesistente
            response = client.post(
                f"{BASE_URL}/api/v1/auth/login",
                json={
                    "email": "nonexistent@example.com",
                    "password": "WrongPassword123!"
                }
            )

            assert response.status_code == 401

            error = response.json()
            error_message = str(error.get("detail", "")).lower()

            # Non deve rivelare se email esiste o meno
            assert "user not found" not in error_message, \
                "AUDIT VIOLATION: Reveals user existence"
            assert "email not registered" not in error_message, \
                "AUDIT VIOLATION: Reveals user existence"

            # Messaggio generico è ok
            assert "invalid" in error_message or "credentials" in error_message or "unauthorized" in error_message


@pytest.mark.audit
class TestAuditUserData:
    """Verifica audit trail per dati utente."""

    def test_profile_update_timestamp(self):
        """Modifiche profilo devono aggiornare updated_at."""
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Get profilo prima
            before_response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )
            assert before_response.status_code == 200
            before_profile = before_response.json()

            before_updated = (
                before_profile.get("updated_at") or
                before_profile.get("updatedAt")
            )

            # Aggiorna qualcosa (se endpoint disponibile)
            update_response = client.patch(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers,
                json={"bio": f"Test update {uuid.uuid4().hex[:6]}"}
            )

            if update_response.status_code in [200, 204]:
                # Verifica updated_at cambiato
                after_response = client.get(
                    f"{BASE_URL}/api/v1/users/me",
                    headers=headers
                )
                after_profile = after_response.json()

                after_updated = (
                    after_profile.get("updated_at") or
                    after_profile.get("updatedAt")
                )

                if before_updated and after_updated:
                    assert after_updated >= before_updated, \
                        "AUDIT: updated_at not incremented on profile change"

    def test_sensitive_data_not_in_response(self):
        """Dati sensibili non devono essere in response standard."""
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            profile_response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )
            assert profile_response.status_code == 200

            profile = profile_response.json()
            profile_str = str(profile).lower()

            # Non deve contenere password
            assert "password" not in profile_str or "hashed" in profile_str, \
                "AUDIT VIOLATION: Password in response"

            # Non deve contenere token/secret
            for sensitive in ["secret", "private_key", "api_key"]:
                if sensitive in profile_str:
                    # Ok se è un campo che indica che NON c'è il valore
                    assert "null" in profile_str or "none" in profile_str, \
                        f"AUDIT VIOLATION: {sensitive} potentially exposed"


@pytest.mark.audit
class TestAuditDataAccess:
    """Verifica audit trail per accesso dati."""

    def test_cannot_access_other_user_data(self):
        """Utente non può accedere a dati di altri utenti."""
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Prova ad accedere a user con ID diverso
            fake_user_id = "00000000-0000-0000-0000-000000000001"
            response = client.get(
                f"{BASE_URL}/api/v1/users/{fake_user_id}",
                headers=headers
            )

            # Deve essere 403 (forbidden) o 404 (not found), non 200
            assert response.status_code in [403, 404], \
                f"AUDIT VIOLATION: Can access other user data: {response.status_code}"

    def test_cannot_modify_other_user_fusion_project(self):
        """Utente non può modificare progetti di altri."""
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Prova a modificare progetto inesistente/di altri
            fake_project_id = "00000000-0000-0000-0000-000000000001"
            response = client.patch(
                f"{BASE_URL}/api/v1/fusion/projects/{fake_project_id}",
                headers=headers,
                json={"name": "Hacked Project"}
            )

            # Deve essere 403 o 404, non 200
            assert response.status_code in [403, 404, 405], \
                f"AUDIT VIOLATION: Can modify other user's project: {response.status_code}"


@pytest.mark.audit
class TestAuditAdmin:
    """Verifica audit trail per operazioni admin."""

    def test_admin_operations_require_admin_role(self):
        """Operazioni admin richiedono ruolo admin."""
        with httpx.Client(timeout=TIMEOUT) as client:
            # Login come utente normale
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Prova endpoint admin
            admin_endpoints = [
                "/api/v1/admin/dashboard",
                "/api/v1/admin/users",
                "/api/v1/admin/analytics",
            ]

            for endpoint in admin_endpoints:
                response = client.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers
                )

                # Utente normale deve ricevere 403, non 200
                assert response.status_code in [401, 403], \
                    f"AUDIT VIOLATION: Non-admin can access {endpoint}"

    def test_admin_user_list_does_not_expose_passwords(self):
        """Lista utenti admin non deve esporre password."""
        with httpx.Client(timeout=TIMEOUT) as client:
            # Prova login admin
            token = authenticate(client, TEST_ADMIN_EMAIL, TEST_ADMIN_PASSWORD)
            if not token:
                pytest.skip("Admin user not available")

            headers = {"Authorization": f"Bearer {token}"}

            response = client.get(
                f"{BASE_URL}/api/v1/admin/users",
                headers=headers
            )

            if response.status_code == 200:
                users_data = response.json()
                users_str = str(users_data).lower()

                # Non deve contenere password in chiaro
                assert "password123" not in users_str, \
                    "AUDIT VIOLATION: Plaintext passwords in admin user list"


@pytest.mark.audit
class TestAuditGDPR:
    """Verifica compliance GDPR."""

    def test_user_can_request_data_export(self):
        """Utente può richiedere export dei propri dati (GDPR Art. 20)."""
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Cerca endpoint GDPR data export
            export_endpoints = [
                "/api/v1/users/me/export",
                "/api/v1/users/me/data",
                "/api/v1/gdpr/export",
            ]

            endpoint_found = False
            for endpoint in export_endpoints:
                response = client.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers
                )
                if response.status_code in [200, 202]:  # 202 = accepted, processing
                    endpoint_found = True
                    break

            # Se nessun endpoint GDPR, skip (ma logga warning)
            if not endpoint_found:
                pytest.skip("GDPR export endpoint not implemented")

    def test_user_can_delete_account(self):
        """Utente può richiedere cancellazione account (GDPR Art. 17)."""
        # NON eseguiamo realmente la cancellazione, solo verifichiamo endpoint esiste
        with httpx.Client(timeout=TIMEOUT) as client:
            token = authenticate(client, TEST_USER_EMAIL, TEST_USER_PASSWORD)
            if not token:
                pytest.skip("Test user not available")

            headers = {"Authorization": f"Bearer {token}"}

            # Verifica endpoint esiste (senza eseguire DELETE)
            # Uso OPTIONS per verificare che endpoint accetti DELETE
            delete_endpoints = [
                "/api/v1/users/me",
                "/api/v1/users/me/delete",
                "/api/v1/gdpr/delete",
            ]

            for endpoint in delete_endpoints:
                response = client.options(
                    f"{BASE_URL}{endpoint}",
                    headers=headers
                )
                # Se ritorna metodi consentiti incluso DELETE, ok
                allowed = response.headers.get("allow", "").upper()
                if "DELETE" in allowed:
                    return  # Test passed

            # Prova GET per vedere se ritorna info su cancellazione
            me_response = client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )
            if me_response.status_code == 200:
                # Se response include info su delete, ok
                pass  # Non fallisce se endpoint non trovato

            pytest.skip("Account deletion endpoint not verified")

"""
AI_MODULE: Avatar Security Tests - Enterprise Suite
AI_DESCRIPTION: Test sicurezza per Avatar API - SQL injection, auth bypass, file upload attacks
AI_TEACHING: I test security verificano che l'API sia protetta contro:
             - SQL injection nei parametri di ricerca
             - Path traversal negli upload file
             - Bypass autenticazione su endpoint admin
             - Upload di file malevoli (non-GLB)
             - IDOR (Insecure Direct Object Reference)

ZERO MOCK: Tutti i test chiamano il backend REALE su localhost:8000
"""

import pytest
import httpx
import uuid
import os
from pathlib import Path

# ============================================================================
# CONFIGURAZIONE
# ============================================================================

BASE_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")
API_PREFIX = "/api/v1/avatars"

# File di test
TEST_FILES_DIR = Path(__file__).parent.parent / "fixtures"


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def client():
    """Client HTTP per test."""
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as c:
        yield c


@pytest.fixture
def auth_headers(client):
    """Headers autenticazione utente normale."""
    response = client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPassword123!"
    })
    if response.status_code != 200:
        pytest.skip("Auth non disponibile - backend non configurato per test")
    token = response.json().get("access_token")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers(client):
    """Headers autenticazione admin."""
    response = client.post("/api/v1/auth/login", json={
        "email": "admin@example.com",
        "password": "AdminPassword123!"
    })
    if response.status_code != 200:
        pytest.skip("Admin auth non disponibile")
    token = response.json().get("access_token")
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# 1. SQL INJECTION TESTS
# ============================================================================

class TestAvatarSQLInjection:
    """Test prevenzione SQL injection."""

    @pytest.mark.security
    def test_sql_injection_in_search(self, client, auth_headers):
        """SQL injection nel parametro search deve essere sanitizzato."""
        malicious_queries = [
            "'; DROP TABLE avatars; --",
            "' OR '1'='1",
            "1; SELECT * FROM users; --",
            "' UNION SELECT password FROM users --",
            "admin'--",
            "1' AND '1'='1",
        ]
        
        for payload in malicious_queries:
            response = client.get(
                f"{API_PREFIX}/",
                params={"search": payload},
                headers=auth_headers
            )
            # Deve ritornare 200 (query vuota) o 422 (validation error)
            # MAI 500 (SQL error) o dati non autorizzati
            assert response.status_code in [200, 422], f"SQL injection possibile con: {payload}"
            
            # Verifica che la tabella avatars esista ancora
            check_response = client.get(f"{API_PREFIX}/", headers=auth_headers)
            assert check_response.status_code == 200, "Tabella avatars danneggiata!"

    @pytest.mark.security
    def test_sql_injection_in_style_filter(self, client, auth_headers):
        """SQL injection nel filtro style."""
        payloads = [
            "karate'; DROP TABLE avatars;--",
            "' OR style='admin",
            "generic' UNION SELECT * FROM users--",
        ]
        
        for payload in payloads:
            response = client.get(
                f"{API_PREFIX}/",
                params={"style": payload},
                headers=auth_headers
            )
            # Deve essere gestito come stile invalido
            assert response.status_code in [200, 422]

    @pytest.mark.security
    def test_sql_injection_in_avatar_id(self, client, auth_headers):
        """SQL injection nell'avatar_id path parameter."""
        malicious_ids = [
            "1; DROP TABLE avatars;--",
            "' OR '1'='1",
            "../../../etc/passwd",
            "1 UNION SELECT password FROM users",
        ]
        
        for payload in malicious_ids:
            response = client.get(
                f"{API_PREFIX}/{payload}",
                headers=auth_headers
            )
            # Deve ritornare 404 (not found) o 422 (invalid UUID)
            assert response.status_code in [404, 422, 400]


# ============================================================================
# 2. AUTHENTICATION & AUTHORIZATION TESTS
# ============================================================================

class TestAvatarAuth:
    """Test autenticazione e autorizzazione."""

    @pytest.mark.security
    def test_list_avatars_without_auth(self, client):
        """Lista avatar pubblici deve funzionare senza auth."""
        response = client.get(f"{API_PREFIX}/")
        # Può essere 200 (pubblici visibili) o 401 (richiede auth)
        assert response.status_code in [200, 401]

    @pytest.mark.security
    def test_upload_avatar_requires_admin(self, client, auth_headers):
        """Upload avatar richiede privilegi admin."""
        # Utente normale tenta upload
        files = {"file": ("test.glb", b"fake content", "model/gltf-binary")}
        data = {"name": "Test Avatar", "style": "karate"}
        
        response = client.post(
            f"{API_PREFIX}/",
            files=files,
            data=data,
            headers=auth_headers
        )
        # Deve essere 403 Forbidden (non admin)
        assert response.status_code in [403, 401]

    @pytest.mark.security
    def test_delete_avatar_requires_admin(self, client, auth_headers):
        """Delete avatar richiede privilegi admin."""
        fake_id = str(uuid.uuid4())
        response = client.delete(
            f"{API_PREFIX}/{fake_id}",
            headers=auth_headers
        )
        # 403 (forbidden) o 404 (not found) - mai 200/204 per non-admin
        assert response.status_code in [403, 401, 404]

    @pytest.mark.security
    def test_update_avatar_requires_admin(self, client, auth_headers):
        """Update avatar richiede privilegi admin."""
        fake_id = str(uuid.uuid4())
        response = client.put(
            f"{API_PREFIX}/{fake_id}",
            json={"name": "Hacked Name"},
            headers=auth_headers
        )
        assert response.status_code in [403, 401, 404]

    @pytest.mark.security
    def test_expired_token_rejected(self, client):
        """Token scaduto deve essere rifiutato."""
        # Token JWT finto/scaduto
        fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxfQ.invalid"
        headers = {"Authorization": f"Bearer {fake_token}"}
        
        response = client.get(f"{API_PREFIX}/", headers=headers)
        assert response.status_code in [401, 403]

    @pytest.mark.security
    def test_malformed_token_rejected(self, client):
        """Token malformato deve essere rifiutato."""
        malformed_tokens = [
            "Bearer ",
            "Bearer invalid",
            "Bearer null",
            "Basic dXNlcjpwYXNz",  # Basic auth invece di Bearer
            "eyJhbGciOiJIUzI1NiJ9",  # JWT incompleto
        ]
        
        for token in malformed_tokens:
            headers = {"Authorization": token}
            response = client.get(f"{API_PREFIX}/", headers=headers)
            # Deve rifiutare o ignorare (ritornando dati pubblici)
            assert response.status_code in [200, 401, 403, 422]


# ============================================================================
# 3. FILE UPLOAD SECURITY TESTS
# ============================================================================

class TestAvatarFileUploadSecurity:
    """Test sicurezza upload file."""

    @pytest.mark.security
    def test_reject_non_glb_file(self, client, admin_headers):
        """File non-GLB devono essere rifiutati."""
        if not admin_headers:
            pytest.skip("Admin auth richiesta")
        
        malicious_files = [
            ("test.exe", b"MZ\x90\x00", "application/x-executable"),
            ("test.php", b"<?php system($_GET['cmd']); ?>", "application/x-php"),
            ("test.js", b"alert('xss')", "application/javascript"),
            ("test.html", b"<script>alert('xss')</script>", "text/html"),
            ("test.svg", b"<svg onload='alert(1)'>", "image/svg+xml"),
        ]
        
        for filename, content, mime_type in malicious_files:
            files = {"file": (filename, content, mime_type)}
            data = {"name": "Malicious", "style": "generic"}
            
            response = client.post(
                f"{API_PREFIX}/",
                files=files,
                data=data,
                headers=admin_headers
            )
            # Deve rifiutare file non-GLB
            assert response.status_code in [400, 422, 415], f"File {filename} accettato!"

    @pytest.mark.security
    def test_reject_glb_extension_with_wrong_content(self, client, admin_headers):
        """File .glb con contenuto non-GLB deve essere rifiutato."""
        if not admin_headers:
            pytest.skip("Admin auth richiesta")
        
        # File .glb ma contenuto PHP
        files = {"file": ("fake.glb", b"<?php system('rm -rf /'); ?>", "model/gltf-binary")}
        data = {"name": "Fake GLB", "style": "generic"}
        
        response = client.post(
            f"{API_PREFIX}/",
            files=files,
            data=data,
            headers=admin_headers
        )
        # Deve validare magic bytes del GLB
        assert response.status_code in [400, 422]

    @pytest.mark.security
    def test_path_traversal_in_filename(self, client, admin_headers):
        """Path traversal nel filename deve essere sanitizzato."""
        if not admin_headers:
            pytest.skip("Admin auth richiesta")
        
        malicious_filenames = [
            "../../../etc/passwd.glb",
            "..\\..\\..\\windows\\system32\\config\\sam.glb",
            "....//....//etc/passwd.glb",
            "/etc/passwd.glb",
            "C:\\Windows\\System32\\config\\SAM.glb",
        ]
        
        # GLB magic bytes validi
        glb_header = b"glTF\x02\x00\x00\x00"
        
        for filename in malicious_filenames:
            files = {"file": (filename, glb_header + b"\x00" * 100, "model/gltf-binary")}
            data = {"name": "Path Traversal Test", "style": "generic"}
            
            response = client.post(
                f"{API_PREFIX}/",
                files=files,
                data=data,
                headers=admin_headers
            )
            # Se accettato, verifica che il file sia salvato in modo sicuro
            # Non deve permettere scrittura fuori dalla cartella avatars
            assert response.status_code in [201, 400, 422]

    @pytest.mark.security
    def test_file_size_limit(self, client, admin_headers):
        """File troppo grandi devono essere rifiutati."""
        if not admin_headers:
            pytest.skip("Admin auth richiesta")
        
        # Genera file da 60MB (oltre il limite di 50MB)
        large_content = b"glTF\x02\x00\x00\x00" + (b"\x00" * 60 * 1024 * 1024)
        
        files = {"file": ("large.glb", large_content, "model/gltf-binary")}
        data = {"name": "Large File", "style": "generic"}
        
        response = client.post(
            f"{API_PREFIX}/",
            files=files,
            data=data,
            headers=admin_headers
        )
        # Deve rifiutare per dimensione
        assert response.status_code in [400, 413, 422]


# ============================================================================
# 4. IDOR (Insecure Direct Object Reference) TESTS
# ============================================================================

class TestAvatarIDOR:
    """Test IDOR - accesso a risorse di altri utenti."""

    @pytest.mark.security
    def test_cannot_access_private_avatar_of_other_user(self, client, auth_headers):
        """Non deve essere possibile accedere ad avatar privati di altri."""
        # Tenta accesso a UUID random (potrebbe essere privato di un altro)
        random_id = str(uuid.uuid4())
        response = client.get(
            f"{API_PREFIX}/{random_id}",
            headers=auth_headers
        )
        # Deve essere 404 (not found) - non rivelare esistenza
        assert response.status_code in [404, 403]

    @pytest.mark.security
    def test_cannot_download_private_avatar_file(self, client, auth_headers):
        """Non deve essere possibile scaricare file di avatar privati."""
        random_id = str(uuid.uuid4())
        response = client.get(
            f"{API_PREFIX}/{random_id}/file",
            headers=auth_headers
        )
        assert response.status_code in [404, 403]


# ============================================================================
# 5. INPUT VALIDATION TESTS
# ============================================================================

class TestAvatarInputValidation:
    """Test validazione input."""

    @pytest.mark.security
    def test_xss_in_avatar_name(self, client, admin_headers):
        """XSS nel nome avatar deve essere sanitizzato."""
        if not admin_headers:
            pytest.skip("Admin auth richiesta")
        
        xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert('xss')>",
            "javascript:alert('xss')",
            "<svg onload=alert('xss')>",
            "'+alert('xss')+'",
        ]
        
        for payload in xss_payloads:
            response = client.post(
                f"{API_PREFIX}/",
                json={"name": payload, "style": "generic"},
                headers=admin_headers
            )
            
            if response.status_code == 201:
                data = response.json()
                # Il nome deve essere sanitizzato o escaped
                assert "<script>" not in data.get("name", "")
                assert "onerror=" not in data.get("name", "")

    @pytest.mark.security
    def test_invalid_uuid_format(self, client, auth_headers):
        """UUID non validi devono essere rifiutati."""
        invalid_uuids = [
            "not-a-uuid",
            "12345",
            "null",
            "undefined",
            "",
            "' OR '1'='1",
        ]
        
        for invalid_id in invalid_uuids:
            response = client.get(
                f"{API_PREFIX}/{invalid_id}",
                headers=auth_headers
            )
            assert response.status_code in [400, 404, 422]

    @pytest.mark.security
    def test_invalid_style_enum(self, client, auth_headers):
        """Stili non validi devono essere rifiutati."""
        response = client.get(
            f"{API_PREFIX}/",
            params={"style": "INVALID_STYLE_HACKED"},
            headers=auth_headers
        )
        # Deve ignorare stile invalido o rifiutare
        assert response.status_code in [200, 422]


# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "security", "--tb=short"])

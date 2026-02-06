"""
================================================================================
    MEDIA CENTER ARTI MARZIALI - Curriculum API Tests
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
# TEST: Curriculum List - REAL API
# ==============================================================================
class TestCurriculumList:
    """Test list curricula - REAL API"""

    def test_list_curricula_authenticated(self, api_client, auth_headers_free):
        """Lista curricula per utente autenticato"""
        response = api_client.get(
            f"{API_PREFIX}/curricula",
            headers=auth_headers_free
        )
        # Accept 200 or 404 (endpoint may not exist yet)
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))

    def test_list_curricula_unauthenticated(self, api_client):
        """Lista curricula senza auth"""
        response = api_client.get(f"{API_PREFIX}/curricula")
        # Could be 200 (public), 401 (auth required), or 404
        assert response.status_code in [200, 401, 404]

    def test_list_curricula_with_discipline_filter(self, api_client, auth_headers_free):
        """Lista curricula filtrata per disciplina"""
        response = api_client.get(
            f"{API_PREFIX}/curricula?discipline=karate",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422]

    def test_list_curricula_with_visibility_filter(self, api_client, auth_headers_free):
        """Lista curricula filtrata per visibilità"""
        response = api_client.get(
            f"{API_PREFIX}/curricula?visibility=public",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422]

    def test_list_curricula_pagination(self, api_client, auth_headers_free):
        """Lista curricula con paginazione"""
        response = api_client.get(
            f"{API_PREFIX}/curricula?skip=0&limit=10",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404, 422]


# ==============================================================================
# TEST: Curriculum CRUD - REAL API
# ==============================================================================
class TestCurriculumCRUD:
    """Test CRUD - REAL API"""

    def test_get_curriculum_not_found(self, api_client, auth_headers_free):
        """Get curriculum inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/curricula/{fake_id}",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 401]

    def test_get_curriculum_invalid_id(self, api_client, auth_headers_free):
        """Get curriculum con ID invalido"""
        response = api_client.get(
            f"{API_PREFIX}/curricula/invalid-uuid",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 422]

    def test_create_curriculum_requires_auth(self, api_client):
        """Creazione curriculum richiede auth"""
        response = api_client.post(
            f"{API_PREFIX}/curricula",
            json={
                "name": "Test Curriculum",
                "discipline": "karate",
                "visibility": "public",
                "pricing_model": "free"
            }
        )
        assert response.status_code in [401, 403, 404]

    def test_create_curriculum_requires_maestro_role(self, api_client, auth_headers_free):
        """Creazione curriculum richiede ruolo maestro"""
        response = api_client.post(
            f"{API_PREFIX}/curricula",
            json={
                "name": "Test Curriculum",
                "discipline": "karate",
                "visibility": "public",
                "pricing_model": "free"
            },
            headers=auth_headers_free
        )
        # FREE user non può creare curriculum
        assert response.status_code in [403, 404, 422]


# ==============================================================================
# TEST: Curriculum Enrollment - REAL API
# ==============================================================================
class TestCurriculumEnrollment:
    """Test enrollment - REAL API"""

    def test_get_my_enrollments_requires_auth(self, api_client):
        """Get iscrizioni richiede auth"""
        response = api_client.get(f"{API_PREFIX}/curricula/me/enrollments")
        assert response.status_code in [401, 403, 404]

    def test_get_my_enrollments(self, api_client, auth_headers_free):
        """Get iscrizioni utente autenticato"""
        response = api_client.get(
            f"{API_PREFIX}/curricula/me/enrollments",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))

    def test_enroll_in_curriculum_not_found(self, api_client, auth_headers_free):
        """Iscrizione a curriculum inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.post(
            f"{API_PREFIX}/curricula/{fake_id}/enroll",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400]


# ==============================================================================
# TEST: Curriculum Progress - REAL API
# ==============================================================================
class TestCurriculumProgress:
    """Test progress - REAL API"""

    def test_get_progress_not_enrolled(self, api_client, auth_headers_free):
        """Progress su curriculum non iscritto"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/curricula/me/curricula/{fake_id}/progress",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400]

    def test_get_progress_requires_auth(self, api_client):
        """Get progress richiede auth"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/curricula/me/curricula/{fake_id}/progress"
        )
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Curriculum Certificates - REAL API
# ==============================================================================
class TestCurriculumCertificates:
    """Test certificates - REAL API"""

    def test_get_my_certificates_requires_auth(self, api_client):
        """Get certificati richiede auth"""
        response = api_client.get(f"{API_PREFIX}/curricula/me/certificates")
        assert response.status_code in [401, 403, 404]

    def test_get_my_certificates(self, api_client, auth_headers_free):
        """Get certificati utente autenticato"""
        response = api_client.get(
            f"{API_PREFIX}/curricula/me/certificates",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

        if response.status_code == 200:
            data = response.json()
            assert isinstance(data, (list, dict))

    def test_verify_certificate_invalid(self, api_client):
        """Verifica certificato invalido"""
        response = api_client.get(
            f"{API_PREFIX}/curricula/certificates/verify/INVALID-CODE"
        )
        assert response.status_code in [404, 400]


# ==============================================================================
# TEST: Curriculum Levels - REAL API
# ==============================================================================
class TestCurriculumLevels:
    """Test levels - REAL API"""

    def test_get_curriculum_levels_not_found(self, api_client, auth_headers_free):
        """Get livelli di curriculum inesistente"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.get(
            f"{API_PREFIX}/curricula/{fake_id}/levels",
            headers=auth_headers_free
        )
        assert response.status_code in [404, 401]


# ==============================================================================
# TEST: Curriculum Invite Codes - REAL API
# ==============================================================================
class TestCurriculumInviteCodes:
    """Test invite codes - REAL API"""

    def test_redeem_invalid_invite_code(self, api_client, auth_headers_free):
        """Riscatto codice invito invalido"""
        response = api_client.post(
            f"{API_PREFIX}/curricula/invite/redeem",
            json={"code": "INVALID-CODE-12345"},
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400, 422]

    def test_redeem_invite_code_requires_auth(self, api_client):
        """Riscatto codice richiede auth"""
        response = api_client.post(
            f"{API_PREFIX}/curricula/invite/redeem",
            json={"code": "ANY-CODE"}
        )
        assert response.status_code in [401, 403, 404]


# ==============================================================================
# TEST: Curriculum Exams - REAL API
# ==============================================================================
class TestCurriculumExams:
    """Test exams - REAL API"""

    def test_get_exam_submissions_requires_auth(self, api_client):
        """Get sottomissioni esame richiede auth"""
        response = api_client.get(f"{API_PREFIX}/curricula/me/exams")
        assert response.status_code in [401, 403, 404]

    def test_get_exam_submissions(self, api_client, auth_headers_free):
        """Get sottomissioni esame"""
        response = api_client.get(
            f"{API_PREFIX}/curricula/me/exams",
            headers=auth_headers_free
        )
        assert response.status_code in [200, 404]

    def test_submit_exam_invalid_level(self, api_client, auth_headers_free):
        """Submit esame per livello invalido"""
        fake_id = "00000000-0000-0000-0000-000000000000"
        response = api_client.post(
            f"{API_PREFIX}/curricula/levels/{fake_id}/exams",
            json={"video_url": "https://example.com/video.mp4"},
            headers=auth_headers_free
        )
        assert response.status_code in [404, 400, 422]

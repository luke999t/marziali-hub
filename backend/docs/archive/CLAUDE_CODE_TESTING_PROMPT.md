# PROMPT PER CLAUDE CODE - TEST ENTERPRISE SUITE

## CONTESTO PROGETTO

**Progetto**: Media Center Arti Marziali - Backend FastAPI
**Path**: `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali\backend`
**Linguaggio**: Python 3.11 + FastAPI + SQLAlchemy 2.x async + PostgreSQL

**Stato attuale test integration**:
- 281 passed, 3 failed (WebSocket), 162 skipped
- Copertura: NON misurata ancora

---

## OBIETTIVO

Creare una **suite di test enterprise completa** con:

1. **Copertura minima 90%**
2. **Pass rate minimo 95%**
3. **ZERO MOCK** - tutti i test chiamano backend reale
4. **Tipologie test**: Unit, Integration, Security (OWASP), Stress/Load, Regression

---

## LEGGE SUPREMA: ZERO MOCK

### VIETATO ASSOLUTAMENTE:
```python
# VIETATO
from unittest.mock import Mock, MagicMock, AsyncMock, patch
from unittest import mock
import mock
pytest.mock
mocker fixture
```

### OBBLIGATORIO:
```python
# CORRETTO - Test REALI
def test_login_real(api_client):
    response = api_client.post("/api/v1/auth/login", json={
        "email": "test@example.com",
        "password": "TestPassword123!"
    })
    assert response.status_code == 200
```

---

## COMANDI DA ESEGUIRE

```bash
# 1. Backend attivo
python -m uvicorn main:app --port 8000 --reload

# 2. Test con copertura
python -m pytest tests/ --cov=. --cov-report=term-missing --cov-report=html -v

# 3. Verifica ZERO MOCK
Select-String -Path "tests\**\*.py" -Pattern "mock|Mock|patch|MagicMock" -Recurse
```

---

## REGOLE AI-FIRST

Ogni file test DEVE avere header:

```python
"""
AI_MODULE: TestNomeModulo
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test [tipo] per [cosa testa] - ZERO MOCK
AI_BUSINESS: [Valore business del test]
AI_TEACHING: [Pattern tecnico usato]

ZERO_MOCK_POLICY:
- Tutti i test usano backend REALE
- Test FALLISCONO se backend spento

COVERAGE_TARGET: 90%+
PASS_RATE_TARGET: 95%+
"""
```

---

## CHECKLIST FINALE

- [ ] `python -m pytest tests/ --cov=. --cov-fail-under=90` passa
- [ ] Pass rate >= 95%
- [ ] Zero import di mock/patch/MagicMock
- [ ] Test FALLISCONO con backend spento
- [ ] Ogni file ha header AI-First

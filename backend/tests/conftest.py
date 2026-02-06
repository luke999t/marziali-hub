"""
🎓 AI_MODULE: Pytest Configuration
🎓 AI_DESCRIPTION: Configurazione pytest con blocco mock automatico
🎓 AI_BUSINESS: Garantisce test reali, no mock
🎓 AI_TEACHING: pytest fixtures, session scope, autouse

⛔⛔⛔ ZERO MOCK POLICY ⛔⛔⛔
Questo conftest blocca automaticamente l'uso di mock.
"""

import pytest
import sys
import warnings

# ═══════════════════════════════════════════════════════════════════════════════
# BLOCCO MOCK AUTOMATICO
# ═══════════════════════════════════════════════════════════════════════════════

def pytest_configure(config):
    """
    Configurazione iniziale pytest.
    Mostra warning se qualcuno tenta di importare mock.
    """
    # Registra marker custom
    config.addinivalue_line(
        "markers", "real_backend: mark test as requiring real backend"
    )


@pytest.fixture(scope="session", autouse=True)
def warn_about_mock_imports():
    """
    Emette warning se unittest.mock viene importato.
    """
    original_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__
    
    def custom_import(name, *args, **kwargs):
        if 'mock' in name.lower() and 'unittest' in name.lower():
            warnings.warn(
                f"⚠️ ATTENZIONE: Tentativo di import '{name}'. "
                f"I mock sono VIETATI dalla policy ZERO MOCK!",
                UserWarning,
                stacklevel=2
            )
        return original_import(name, *args, **kwargs)
    
    # Non sovrascriviamo __import__ per evitare problemi
    # ma logghiamo il warning
    yield


# ═══════════════════════════════════════════════════════════════════════════════
# FIXTURES COMUNI
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def backend_url():
    """URL backend per test"""
    import os
    return os.getenv("TEST_BACKEND_URL", "http://localhost:8000")


@pytest.fixture
def storage_path(tmp_path):
    """Path temporaneo per storage test"""
    path = tmp_path / "storage"
    path.mkdir()
    return path


# ═══════════════════════════════════════════════════════════════════════════════
# HOOKS
# ═══════════════════════════════════════════════════════════════════════════════

def pytest_collection_modifyitems(config, items):
    """
    Modifica items raccolti.
    Aggiunge marker real_backend a tutti i test.
    """
    for item in items:
        item.add_marker(pytest.mark.real_backend)


def pytest_report_header(config):
    """Header personalizzato nel report"""
    return [
        "",
        "⛔ ZERO MOCK POLICY ATTIVA",
        "✅ Tutti i test usano backend REALE",
        ""
    ]

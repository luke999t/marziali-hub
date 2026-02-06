"""
================================================================================
AI_MODULE: Test Fixtures Package
AI_VERSION: 1.0.0
AI_DESCRIPTION: Fixtures per test integration con dati reali nel database
AI_BUSINESS: Supporta test ZERO MOCK con entità reali (ASD, Maestro, Video)
AI_TEACHING: Fixtures pytest con cleanup automatico

================================================================================

CONTENUTO:
- asd_fixtures.py: ASD e ASDMember fixtures
- maestro_fixtures.py: Maestro profile e token fixtures
- video_fixtures.py: Video e LiveEvent fixtures

USAGE:
Le fixtures sono auto-registrate tramite conftest.py.
Ogni fixture crea dati REALI nel database e li rimuove dopo il test.
"""

from tests.fixtures.asd_fixtures import *
from tests.fixtures.maestro_fixtures import *
from tests.fixtures.video_fixtures import *

"""
================================================================================
AI_MODULE: TestGlassesWebSocket
AI_VERSION: 2.0.0
AI_DESCRIPTION: Integration tests per WebSocket glasses control - ZERO MOCK
AI_BUSINESS: Verifica funzionamento real-time control glasses su backend REALE
AI_TEACHING: Test WebSocket con websockets library su localhost:8000
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2025-12-14

ZERO_MOCK_POLICY:
- Tutti i test usano WebSocket REALE a localhost:8000
- Nessuna simulazione o intercettazione
- Test FALLISCONO se backend spento

REQUISITI:
- Backend deve essere avviato: uvicorn main:app --host 127.0.0.1 --port 8000
- websockets library installata
================================================================================
"""

import pytest
import asyncio
import json
import httpx
from websockets import connect as ws_connect
from websockets.exceptions import ConnectionClosed

# Backend URL - REAL server
BASE_URL = "http://127.0.0.1:8000"
WS_URL = "ws://127.0.0.1:8000"


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture(scope="module")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def verify_backend():
    """Verifica backend REALE attivo - FALLISCE se spento."""
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(f"{BASE_URL}/health", timeout=5)
            if response.status_code != 200:
                pytest.fail("Backend health check failed")
        except httpx.ConnectError:
            pytest.fail(
                f"BACKEND NON ATTIVO a {BASE_URL}. "
                "Avvia con: uvicorn main:app --host 127.0.0.1 --port 8000"
            )


# =============================================================================
# CONNECTION TESTS
# =============================================================================

class TestWebSocketConnection:
    """Test connessione WebSocket REALE."""

    @pytest.mark.asyncio
    async def test_connect_success(self, verify_backend):
        """Connessione WebSocket a backend REALE."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_conn_1?device_type=phone",
            close_timeout=5
        ) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "state_sync"
            assert "state" in data
            assert data["state"]["zoom_level"] == 1.0

    @pytest.mark.asyncio
    async def test_connect_phone_device(self, verify_backend):
        """Connessione come phone device."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_conn_2?device_type=phone",
            close_timeout=5
        ) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["your_device"] == "phone"

    @pytest.mark.asyncio
    async def test_connect_glasses_device(self, verify_backend):
        """Connessione come glasses device."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_conn_3?device_type=glasses",
            close_timeout=5
        ) as ws:
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["your_device"] == "glasses"


# =============================================================================
# COMMAND TESTS
# =============================================================================

class TestCommands:
    """Test comandi su backend REALE."""

    @pytest.mark.asyncio
    async def test_zoom_command(self, verify_backend):
        """Comando zoom aggiorna stato."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_zoom?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)  # state_sync

            await ws.send(json.dumps({
                "type": "command",
                "command": "zoom",
                "value": 2.5
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "state_update"
            assert data["command"] == "zoom"
            assert data["state"]["zoom_level"] == 2.5

    @pytest.mark.asyncio
    async def test_speed_command(self, verify_backend):
        """Comando speed snappa a valore valido."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_speed?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "speed",
                "value": 1.3  # Snappa a 1.25
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["playback_speed"] == 1.25

    @pytest.mark.asyncio
    async def test_play_command(self, verify_backend):
        """Comando play avvia riproduzione."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_play?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "play",
                "value": None
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["is_playing"] is True

    @pytest.mark.asyncio
    async def test_pause_command(self, verify_backend):
        """Comando pause ferma riproduzione."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_pause?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            # Prima play
            await ws.send(json.dumps({"type": "command", "command": "play", "value": None}))
            await asyncio.wait_for(ws.recv(), timeout=5)

            # Poi pause
            await ws.send(json.dumps({"type": "command", "command": "pause", "value": None}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["is_playing"] is False

    @pytest.mark.asyncio
    async def test_toggle_play_command(self, verify_backend):
        """Comando toggle_play alterna stato."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_toggle?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            # Toggle 1: False -> True
            await ws.send(json.dumps({"type": "command", "command": "toggle_play", "value": None}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            assert json.loads(msg)["state"]["is_playing"] is True

            # Toggle 2: True -> False
            await ws.send(json.dumps({"type": "command", "command": "toggle_play", "value": None}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            assert json.loads(msg)["state"]["is_playing"] is False

    @pytest.mark.asyncio
    async def test_seek_command(self, verify_backend):
        """Comando seek imposta posizione."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_seek?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "seek",
                "value": 45000
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["current_time_ms"] == 45000

    @pytest.mark.asyncio
    async def test_brightness_command(self, verify_backend):
        """Comando brightness imposta luminosita'."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_bright?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "brightness",
                "value": 60
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["brightness"] == 60

    @pytest.mark.asyncio
    async def test_volume_command(self, verify_backend):
        """Comando volume imposta audio."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_vol?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "volume",
                "value": 30
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["volume"] == 30

    @pytest.mark.asyncio
    async def test_skeleton_command(self, verify_backend):
        """Comando skeleton abilita overlay."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_skel?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "skeleton",
                "value": True
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["skeleton_visible"] is True

    @pytest.mark.asyncio
    async def test_set_video_command(self, verify_backend):
        """Comando set_video carica video."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_cmd_video?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "set_video",
                "value": "my_video_123"
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["video_id"] == "my_video_123"
            assert data["state"]["current_time_ms"] == 0
            assert data["state"]["is_playing"] is False


# =============================================================================
# PING/PONG TESTS
# =============================================================================

class TestPingPong:
    """Test ping/pong keep-alive."""

    @pytest.mark.asyncio
    async def test_ping_responds_pong(self, verify_backend):
        """Ping riceve pong."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_ping?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({"type": "ping"}))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "pong"
            assert "timestamp" in data


# =============================================================================
# STATE REQUEST TESTS
# =============================================================================

class TestStateRequest:
    """Test state_request."""

    @pytest.mark.asyncio
    async def test_state_request_returns_state(self, verify_backend):
        """state_request ritorna stato corrente."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_state_req?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            # Modifica stato
            await ws.send(json.dumps({"type": "command", "command": "brightness", "value": 42}))
            await asyncio.wait_for(ws.recv(), timeout=5)

            # Richiedi stato
            await ws.send(json.dumps({"type": "state_request"}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "state_sync"
            assert data["state"]["brightness"] == 42


# =============================================================================
# ERROR HANDLING TESTS
# =============================================================================

class TestErrorHandling:
    """Test gestione errori."""

    @pytest.mark.asyncio
    async def test_invalid_json_returns_error(self, verify_backend):
        """JSON invalido ritorna errore."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_err_json?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send("not valid json {{{")

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "error"
            assert "Invalid JSON" in data["error"]

    @pytest.mark.asyncio
    async def test_unknown_command_returns_error(self, verify_backend):
        """Comando sconosciuto ritorna errore."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_err_cmd?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({
                "type": "command",
                "command": "invalid_command",
                "value": 123
            }))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "error"
            assert "Unknown command" in data["error"]

    @pytest.mark.asyncio
    async def test_unknown_message_type_returns_error(self, verify_backend):
        """Message type sconosciuto ritorna errore."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_err_type?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({"type": "unknown_type"}))

            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["type"] == "error"


# =============================================================================
# REST ENDPOINT TESTS
# =============================================================================

class TestRESTEndpoints:
    """Test endpoint REST."""

    @pytest.mark.asyncio
    async def test_rooms_endpoint(self, verify_backend):
        """GET /glasses/rooms funziona."""
        async with httpx.AsyncClient() as client:
            response = await client.get(f"{BASE_URL}/api/v1/glasses/rooms")

            assert response.status_code == 200
            data = response.json()
            assert "active_rooms" in data
            assert "total_connections" in data
            assert "rooms" in data

    @pytest.mark.asyncio
    async def test_room_not_found(self, verify_backend):
        """GET /glasses/room/{id} ritorna 404 se non esiste."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{BASE_URL}/api/v1/glasses/room/nonexistent_room_xyz"
            )

            assert response.status_code == 404


# =============================================================================
# VALUE CLAMPING TESTS
# =============================================================================

class TestValueClamping:
    """Test clamping valori fuori range."""

    @pytest.mark.asyncio
    async def test_zoom_clamp_max(self, verify_backend):
        """Zoom > 3.0 clampato a 3.0."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_clamp_zoom?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({"type": "command", "command": "zoom", "value": 10.0}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["zoom_level"] == 3.0

    @pytest.mark.asyncio
    async def test_brightness_clamp_max(self, verify_backend):
        """Brightness > 100 clampato a 100."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_clamp_bright?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({"type": "command", "command": "brightness", "value": 200}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["brightness"] == 100

    @pytest.mark.asyncio
    async def test_seek_clamp_negative(self, verify_backend):
        """Seek negativo clampato a 0."""
        async with ws_connect(
            f"{WS_URL}/api/v1/ws/glasses/test_clamp_seek?device_type=phone",
            close_timeout=5
        ) as ws:
            await asyncio.wait_for(ws.recv(), timeout=5)

            await ws.send(json.dumps({"type": "command", "command": "seek", "value": -5000}))
            msg = await asyncio.wait_for(ws.recv(), timeout=5)
            data = json.loads(msg)

            assert data["state"]["current_time_ms"] == 0

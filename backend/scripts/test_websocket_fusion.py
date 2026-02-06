"""
================================================================================
AI_MODULE: WebSocket Fusion Tester
AI_VERSION: 1.0.0
AI_DESCRIPTION: Test manuale WebSocket real-time progress per Fusion API
AI_BUSINESS: Verifica che progress fusion arrivi in tempo reale ai client
AI_TEACHING: websockets library, asyncio, real-time bidirectional communication
AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
AI_CREATED: 2026-01-18

================================================================================

USAGE:
    cd backend
    pip install websockets
    python scripts/test_websocket_fusion.py

PREREQUISITI:
    - Backend attivo: python -m uvicorn main:app --port 8000
    - websockets: pip install websockets

================================================================================
"""

import asyncio
import json
import sys
from datetime import datetime

try:
    import websockets
except ImportError:
    print("ERROR: websockets not installed")
    print("Run: pip install websockets")
    sys.exit(1)


def print_banner():
    """Stampa banner iniziale."""
    print("=" * 60)
    print("  FUSION WEBSOCKET TESTER")
    print("  Real-time Progress Monitor")
    print("=" * 60)
    print()


def print_progress_bar(progress: float, width: int = 40) -> str:
    """Genera barra progresso ASCII."""
    filled = int(width * progress / 100)
    empty = width - filled
    bar = "" * filled + "" * empty
    return f"[{bar}] {progress:.1f}%"


async def test_fusion_websocket(project_id: str = "test-project-123", timeout: int = 60):
    """
    Test connessione WebSocket Fusion.

    Args:
        project_id: ID progetto da monitorare (usa ID reale se disponibile)
        timeout: Secondi di attesa messaggi prima di chiudere

    Returns:
        True se connessione riuscita, False altrimenti
    """
    uri = f"ws://localhost:8000/api/v1/fusion/ws/{project_id}"

    print(f"[{datetime.now().strftime('%H:%M:%S')}] Connecting to: {uri}")
    print()

    try:
        async with websockets.connect(uri) as websocket:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Connected!")
            print()

            # Invia messaggio di subscribe
            subscribe_msg = {
                "type": "subscribe",
                "project_id": project_id,
                "client_type": "tester"
            }
            await websocket.send(json.dumps(subscribe_msg))
            print(f"[TX] Sent: {json.dumps(subscribe_msg)}")
            print()

            # Ascolta messaggi
            print(f"[RX] Listening for messages (timeout: {timeout}s)...")
            print("-" * 60)

            message_count = 0
            try:
                while True:
                    message = await asyncio.wait_for(
                        websocket.recv(),
                        timeout=float(timeout)
                    )

                    message_count += 1
                    timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]

                    try:
                        data = json.loads(message)
                        print(f"\n[{timestamp}] Message #{message_count}:")

                        # Mostra tipo messaggio
                        msg_type = data.get('type', 'unknown')
                        print(f"  Type: {msg_type}")

                        # Se e progress, mostra barra
                        if 'progress' in data:
                            progress = data['progress']
                            print(f"  {print_progress_bar(progress)}")

                        # Stage/Phase
                        if 'stage' in data:
                            print(f"  Stage: {data['stage']}")
                        if 'phase' in data:
                            print(f"  Phase: {data['phase']}")

                        # Message/Status
                        if 'message' in data:
                            print(f"  Message: {data['message']}")
                        if 'status' in data:
                            print(f"  Status: {data['status']}")

                        # Error
                        if 'error' in data:
                            print(f"  ERROR: {data['error']}")

                        # Full JSON (debug)
                        # print(f"  Raw: {json.dumps(data, indent=4)}")

                    except json.JSONDecodeError:
                        print(f"\n[{timestamp}] Raw message: {message[:200]}")

            except asyncio.TimeoutError:
                print()
                print("-" * 60)
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Timeout - no messages for {timeout}s")
                print(f"Total messages received: {message_count}")

            return True

    except websockets.exceptions.ConnectionClosed as e:
        print(f"\n[ERROR] Connection closed: {e}")
        return False

    except ConnectionRefusedError:
        print(f"\n[ERROR] Connection refused - is backend running?")
        print("Start backend with: python -m uvicorn main:app --port 8000")
        return False

    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {type(e).__name__}: {e}")
        return False


async def send_test_ping(project_id: str = "test-project-123"):
    """
    Invia ping di test e attende pong.

    Utile per verificare che il WebSocket risponda.
    """
    uri = f"ws://localhost:8000/api/v1/fusion/ws/{project_id}"

    print(f"Sending ping to: {uri}")

    try:
        async with websockets.connect(uri) as websocket:
            # Invia ping
            ping_msg = {"type": "ping", "timestamp": datetime.now().isoformat()}
            await websocket.send(json.dumps(ping_msg))
            print(f"[TX] Ping sent")

            # Attendi pong
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                data = json.loads(response)
                print(f"[RX] Response: {data}")

                if data.get('type') == 'pong':
                    print(" Pong received!")
                    return True

            except asyncio.TimeoutError:
                print("[WARN] No pong received within 5s")

            return False

    except Exception as e:
        print(f"[ERROR] {e}")
        return False


def print_usage():
    """Mostra usage."""
    print("""
Usage: python scripts/test_websocket_fusion.py [command] [options]

Commands:
    listen [project_id] [timeout]  - Listen for WebSocket messages (default)
    ping [project_id]              - Send ping and wait for pong

Examples:
    python scripts/test_websocket_fusion.py
    python scripts/test_websocket_fusion.py listen my-project-id 120
    python scripts/test_websocket_fusion.py ping my-project-id

Options:
    project_id  - Fusion project ID to monitor (default: test-project-123)
    timeout     - Seconds to wait for messages (default: 60)
""")


if __name__ == "__main__":
    print_banner()

    # Parse arguments
    command = "listen"
    project_id = "test-project-123"
    timeout = 60

    if len(sys.argv) >= 2:
        if sys.argv[1] in ["-h", "--help", "help"]:
            print_usage()
            sys.exit(0)
        command = sys.argv[1]

    if len(sys.argv) >= 3:
        project_id = sys.argv[2]

    if len(sys.argv) >= 4:
        try:
            timeout = int(sys.argv[3])
        except ValueError:
            print(f"Invalid timeout: {sys.argv[3]}")
            sys.exit(1)

    print("Configuration:")
    print(f"  Command:    {command}")
    print(f"  Project ID: {project_id}")
    print(f"  Timeout:    {timeout}s")
    print()

    # Execute
    if command == "ping":
        result = asyncio.run(send_test_ping(project_id))
    else:
        result = asyncio.run(test_fusion_websocket(project_id, timeout))

    print()
    if result:
        print(" Test completed successfully")
        sys.exit(0)
    else:
        print(" Test failed")
        sys.exit(1)

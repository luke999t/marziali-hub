# 🎯 CLAUDE CODE PROMPT - GLASSES CONTROL + REACT NATIVE MVP

**Progetto:** Media Center Arti Marziali
**Path:** `C:\Users\utente\Desktop\GESTIONALI\media-center-arti-marziali`
**Focus:** React Native app + Modulo controllo Smart Glasses
**Data:** 14 Dicembre 2025

---

# ⚠️ SEZIONE 0: LEGGI PRIMA DI TUTTO

## REGOLE INVIOLABILI

```
❌ MAI MENTIRE - Se non sai fare qualcosa, DILLO
❌ MAI PLACEHOLDER - Tutto il codice deve essere FUNZIONANTE
❌ MAI SIMULARE - Non fingere implementazioni
❌ MAI TODO/FIXME - Implementa ORA o non farlo
❌ MAI MOCK NEI TEST - Solo backend REALE
```

---

# 📋 SEZIONE 1: AI-FIRST SYSTEM RULES

## 1.1 HEADER OBBLIGATORIO PER OGNI FILE

```typescript
/**
 * ================================================================================
 * 🎓 AI_MODULE: [Nome Modulo]
 * 🎓 AI_DESCRIPTION: [Cosa fa in una riga]
 * 🎓 AI_BUSINESS: [Valore business, KPI, revenue impact]
 * 🎓 AI_TEACHING: [Concetto tecnico principale da imparare]
 *
 * 🔄 ALTERNATIVE_VALUTATE:
 * - [Opzione A]: Scartata perché [motivo tecnico + business]
 * - [Opzione B]: Scartata perché [motivo tecnico + business]
 *
 * 💡 PERCHÉ_QUESTA_SOLUZIONE:
 * - Vantaggio tecnico 1: [spiegazione]
 * - Vantaggio business 1: [impatto quantificato]
 * - Trade-off accettati: [svantaggi consapevoli]
 *
 * 📊 METRICHE_SUCCESSO:
 * - [Metrica 1]: [Target]
 * - [Metrica 2]: [Target]
 *
 * 🔗 INTEGRATION_DEPENDENCIES:
 * - Upstream: [servizi che questo modulo usa]
 * - Downstream: [servizi che usano questo modulo]
 *
 * 🧪 ZERO_MOCK_POLICY:
 * - Tutti i test chiamano backend REALE
 * - Se backend spento, test DEVE fallire
 * ================================================================================
 */
```

## 1.2 COMMENTI DIDATTICI

```typescript
// ❌ SBAGLIATO - Commento inutile
const response = await fetch(url); // Fa fetch

// ✅ CORRETTO - Spiega il PERCHÉ
// Timeout 30s perché backend può ritardare fino a 20s
// sotto carico. Default 10s causerebbe 40% false timeout.
const response = await fetch(url, { timeout: 30000 });
```

## 1.3 NOMENCLATURA

```typescript
// ✅ CORRETTO
const userSubscriptionTier = 'premium';  // Descrittivo
const MAX_ZOOM_LEVEL = 3.0;              // Costante UPPERCASE
const isGlassesConnected = true;         // Boolean con is/has/can

// ❌ SBAGLIATO
const x = 'premium';      // Non descrittivo
const max = 3.0;          // Ambiguo
const glasses = true;     // Non chiaro che è boolean
```

---

# 🔒 SEZIONE 2: ZERO MOCK TEST - LEGGE SUPREMA

## 2.1 COSA È VIETATO

```typescript
// ❌❌❌ TUTTO QUESTO È VIETATO ❌❌❌

jest.mock('@/services/api');
jest.fn();
jest.spyOn().mockImplementation();
jest.spyOn().mockReturnValue();
jest.spyOn().mockResolvedValue();

// Python equivalenti VIETATI:
// MagicMock, AsyncMock, Mock(), patch(), @patch
// from unittest.mock import *
// mock_*, *_mock, fake_*, stub_*, dummy_*
```

## 2.2 COME SCRIVERE TEST REALI

```typescript
// ✅ TEST REALE - Chiama backend vero

describe('GlassesController', () => {
  const API_URL = process.env.TEST_API_URL || 'http://localhost:8000';
  
  beforeAll(async () => {
    // VERIFICA BACKEND ATTIVO
    const health = await fetch(`${API_URL}/health`);
    if (!health.ok) {
      throw new Error('BACKEND NON ATTIVO - Avvialo prima dei test');
    }
  });

  it('should connect to glasses via WebSocket', async () => {
    // 1. ARRANGE - Dati reali
    const ws = new WebSocket(`${API_URL.replace('http', 'ws')}/ws/glasses`);
    
    // 2. ACT - Operazione reale
    await new Promise((resolve) => {
      ws.onopen = resolve;
    });
    
    ws.send(JSON.stringify({ action: 'ping' }));
    
    // 3. ASSERT - Verifica risposta reale
    const response = await new Promise((resolve) => {
      ws.onmessage = (event) => resolve(JSON.parse(event.data));
    });
    
    expect(response.action).toBe('pong');
    
    ws.close();
  });

  it('should control zoom level', async () => {
    const response = await fetch(`${API_URL}/api/v1/glasses/zoom`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ level: 2.0 })
    });
    
    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.zoom_level).toBe(2.0);
  });
});
```

## 2.3 VERIFICA ANTI-MOCK

Prima di committare, esegui:

```bash
# Cerca mock nel codice
grep -r "jest.mock\|MagicMock\|AsyncMock\|@patch" --include="*.ts" --include="*.tsx" --include="*.py" .

# Se trova qualcosa → RIMUOVI E RISCRIVI
```

## 2.4 TEST DEVONO FALLIRE CON BACKEND SPENTO

```bash
# 1. Spegni backend
# 2. Esegui test
npm test

# 3. Se i test PASSANO → SONO MOCK (SBAGLIATO!)
# 4. Se i test FALLISCONO → SONO REALI (CORRETTO!)
```

---

# 🎯 SEZIONE 3: TASK DA IMPLEMENTARE

## 3.1 MODULO GLASSES CONTROL

### Path: `mobile/src/services/glassesService.ts`

```typescript
/**
 * ================================================================================
 * 🎓 AI_MODULE: GlassesService
 * 🎓 AI_DESCRIPTION: Controllo remoto smart glasses via WebSocket
 * 🎓 AI_BUSINESS: Permette controllo video su glasses da smartphone
 * 🎓 AI_TEACHING: WebSocket bidirectional, reconnection logic, state sync
 *
 * 🔄 ALTERNATIVE_VALUTATE:
 * - HTTP polling: Scartato, latenza 500ms+ inaccettabile per controlli real-time
 * - Bluetooth direct: Scartato, richiede SDK nativi diversi per ogni glasses
 * - WebRTC: Scartato, overkill per semplici comandi
 *
 * 💡 PERCHÉ_QUESTA_SOLUZIONE:
 * - WebSocket: Latenza <50ms, bidirezionale, cross-platform
 * - Backend come bridge: Funziona con qualsiasi glasses che supporta WiFi
 * - State sync: Glasses e phone sempre sincronizzati
 *
 * 📊 METRICHE_SUCCESSO:
 * - Latenza comando: <100ms
 * - Reconnection time: <3s
 * - Sync accuracy: 100%
 *
 * 🔗 INTEGRATION_DEPENDENCIES:
 * - Backend: WebSocket /ws/glasses
 * - Glasses: Qualsiasi con WiFi (Rokid, XREAL, etc)
 * ================================================================================
 */

export interface GlassesState {
  connected: boolean;
  zoomLevel: number;        // 1.0 - 3.0
  playbackSpeed: number;    // 0.25, 0.5, 1.0, 1.5, 2.0
  isPlaying: boolean;
  currentTime: number;      // milliseconds
  skeletonVisible: boolean;
  brightness: number;       // 0 - 100
  volume: number;           // 0 - 100
}

export interface GlassesCommand {
  action: 'zoom' | 'speed' | 'play' | 'pause' | 'seek' | 'skeleton' | 'brightness' | 'volume';
  value?: number | boolean;
}

export type GlassesEventCallback = (state: GlassesState) => void;

class GlassesService {
  private ws: WebSocket | null = null;
  private state: GlassesState;
  private listeners: Set<GlassesEventCallback> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;

  constructor() {
    this.state = {
      connected: false,
      zoomLevel: 1.0,
      playbackSpeed: 1.0,
      isPlaying: false,
      currentTime: 0,
      skeletonVisible: false,
      brightness: 80,
      volume: 70,
    };
  }

  /**
   * Connette ai glasses via WebSocket attraverso backend
   * 
   * 🎯 BUSINESS: Entry point per controllo glasses
   * 📚 TEACHING: WebSocket connection con auto-reconnect
   */
  async connect(backendUrl: string): Promise<boolean> {
    // ... implementazione completa richiesta
  }

  /**
   * Invia comando ai glasses
   * 
   * 🎯 BUSINESS: Core control function
   * 📚 TEACHING: Message queue per reliability
   */
  sendCommand(command: GlassesCommand): void {
    // ... implementazione completa richiesta
  }

  // ... altri metodi
}

export const glassesService = new GlassesService();
export default glassesService;
```

### Path: `mobile/src/components/GlassesControlPanel.tsx`

```typescript
/**
 * ================================================================================
 * 🎓 AI_MODULE: GlassesControlPanel
 * 🎓 AI_DESCRIPTION: UI controllo remoto glasses (zoom, speed, play/pause)
 * 🎓 AI_BUSINESS: Interfaccia touch-friendly per controllo one-handed
 * 🎓 AI_TEACHING: React Native gestures, haptic feedback, accessibility
 * ================================================================================
 */
```

**Funzionalità richieste:**
- Slider zoom (1x - 3x) con haptic feedback
- Bottoni velocità (0.25x, 0.5x, 1x, 1.5x, 2x)
- Play/Pause grande (thumb-friendly)
- Seek bar con preview
- Toggle skeleton ON/OFF
- Slider brightness
- Slider volume
- Indicatore connessione glasses
- Auto-reconnect con feedback visivo

### Path: `mobile/src/screens/GlassesPlayerScreen.tsx`

```typescript
/**
 * ================================================================================
 * 🎓 AI_MODULE: GlassesPlayerScreen
 * 🎓 AI_DESCRIPTION: Screen dedicato quando glasses connessi
 * 🎓 AI_BUSINESS: UX ottimizzata per controllo remoto (no video su phone)
 * 🎓 AI_TEACHING: Conditional rendering, state management, battery optimization
 * ================================================================================
 */
```

**Layout:**
- NO video player (risparmia batteria, video è su glasses)
- GlassesControlPanel prominente
- Info video (titolo, maestro, durata)
- Lista tecniche/capitoli per jump
- Indicatore batteria glasses (se disponibile)

---

## 3.2 BACKEND WEBSOCKET ENDPOINT

### Path: `backend/api/v1/glasses_ws.py`

```python
"""
================================================================================
🎓 AI_MODULE: GlassesWebSocket
🎓 AI_DESCRIPTION: WebSocket endpoint per controllo glasses
🎓 AI_BUSINESS: Bridge tra smartphone e smart glasses
🎓 AI_TEACHING: FastAPI WebSocket, room management, state broadcast

🔄 ALTERNATIVE_VALUTATE:
- Socket.IO: Scartato, dipendenza extra non necessaria
- gRPC streaming: Scartato, overkill per questo use case
- Server-Sent Events: Scartato, unidirezionale

💡 PERCHÉ_QUESTA_SOLUZIONE:
- FastAPI WebSocket: Nativo, leggero, async
- Room-based: Isola sessioni utente
- State machine: Garantisce consistenza

📊 METRICHE_SUCCESSO:
- Latenza broadcast: <20ms
- Concurrent sessions: >1000
- Memory per session: <1KB

ZERO_MOCK_POLICY:
- Test con WebSocket client reale
- Test con multiple connessioni simultanee
================================================================================
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set
import asyncio
import json
import logging

router = APIRouter()

# Room management: user_id -> set of connections (phone + glasses)
rooms: Dict[str, Set[WebSocket]] = {}

# State per room
room_states: Dict[str, dict] = {}


@router.websocket("/ws/glasses/{user_id}")
async def glasses_websocket(websocket: WebSocket, user_id: str):
    """
    WebSocket endpoint per controllo glasses.
    
    🎯 BUSINESS: Collega phone e glasses dello stesso utente
    📚 TEACHING: Room pattern per isolamento sessioni
    
    Protocol:
    - Phone invia comandi (zoom, play, etc)
    - Backend broadcast a glasses nella stessa room
    - Glasses conferma e invia stato aggiornato
    - Backend broadcast stato a phone
    """
    await websocket.accept()
    
    # Aggiungi a room
    if user_id not in rooms:
        rooms[user_id] = set()
        room_states[user_id] = create_default_state()
    
    rooms[user_id].add(websocket)
    
    try:
        # Invia stato corrente
        await websocket.send_json({
            "type": "state_sync",
            "state": room_states[user_id]
        })
        
        while True:
            data = await websocket.receive_json()
            await handle_message(user_id, websocket, data)
            
    except WebSocketDisconnect:
        rooms[user_id].discard(websocket)
        if not rooms[user_id]:
            del rooms[user_id]
            del room_states[user_id]


async def handle_message(user_id: str, sender: WebSocket, data: dict):
    """
    Gestisce messaggi e broadcast.
    
    📚 TEACHING: Pattern command handler con broadcast
    """
    msg_type = data.get("type")
    
    if msg_type == "command":
        # Aggiorna stato
        command = data.get("command")
        value = data.get("value")
        
        update_state(user_id, command, value)
        
        # Broadcast a tutti nella room (incluso sender per conferma)
        await broadcast_to_room(user_id, {
            "type": "state_update",
            "command": command,
            "value": value,
            "state": room_states[user_id]
        })
    
    elif msg_type == "ping":
        await sender.send_json({"type": "pong"})


def create_default_state() -> dict:
    return {
        "zoom_level": 1.0,
        "playback_speed": 1.0,
        "is_playing": False,
        "current_time": 0,
        "skeleton_visible": False,
        "brightness": 80,
        "volume": 70
    }


def update_state(user_id: str, command: str, value) -> None:
    """Aggiorna stato room."""
    state = room_states[user_id]
    
    if command == "zoom":
        state["zoom_level"] = max(1.0, min(3.0, float(value)))
    elif command == "speed":
        state["playback_speed"] = float(value)
    elif command == "play":
        state["is_playing"] = True
    elif command == "pause":
        state["is_playing"] = False
    elif command == "seek":
        state["current_time"] = int(value)
    elif command == "skeleton":
        state["skeleton_visible"] = bool(value)
    elif command == "brightness":
        state["brightness"] = max(0, min(100, int(value)))
    elif command == "volume":
        state["volume"] = max(0, min(100, int(value)))


async def broadcast_to_room(user_id: str, message: dict) -> None:
    """Broadcast a tutti i client nella room."""
    if user_id not in rooms:
        return
    
    disconnected = set()
    
    for ws in rooms[user_id]:
        try:
            await ws.send_json(message)
        except:
            disconnected.add(ws)
    
    # Cleanup disconnected
    rooms[user_id] -= disconnected
```

---

# 🧪 SEZIONE 4: TEST SUITE ENTERPRISE

## 4.1 STRUTTURA TEST

```
mobile/
├── __tests__/
│   ├── unit/                    # Unit tests
│   │   ├── services/
│   │   │   └── glassesService.test.ts
│   │   └── components/
│   │       └── GlassesControlPanel.test.tsx
│   │
│   ├── integration/             # Integration tests
│   │   ├── glassesFlow.test.ts
│   │   └── playerGlassesSync.test.ts
│   │
│   ├── e2e/                     # End-to-end tests
│   │   └── glassesJourney.test.ts
│   │
│   ├── security/                # Security tests
│   │   ├── auth/
│   │   │   └── tokenValidation.test.ts
│   │   └── penetration/
│   │       └── wsInjection.test.ts
│   │
│   ├── stress/                  # Stress tests
│   │   └── multipleConnections.test.ts
│   │
│   ├── slow/                    # Performance tests (tag: slow)
│   │   └── latencyBenchmark.test.ts
│   │
│   └── regression/              # Regression tests
│       └── criticalBugs.test.ts

backend/
├── tests/
│   ├── unit/
│   │   └── test_glasses_ws.py
│   │
│   ├── integration/
│   │   └── test_glasses_full_flow.py
│   │
│   ├── security/
│   │   └── test_ws_security.py
│   │
│   ├── stress/
│   │   └── test_concurrent_rooms.py
│   │
│   └── conftest.py              # Fixtures + MOCK BLOCKER
```

## 4.2 METRICHE TARGET

| Metrica | Target | Minimo Accettabile |
|---------|--------|-------------------|
| **Coverage** | 90% | 85% |
| **Pass Rate** | 95% | 92% |
| **Unit Tests** | 200+ | 150 |
| **Integration Tests** | 50+ | 30 |
| **E2E Tests** | 20+ | 10 |
| **Security Tests** | 30+ | 20 |
| **Stress Tests** | 10+ | 5 |
| **Performance Tests** | 10+ | 5 |

## 4.3 TEST EXAMPLES

### Unit Test - GlassesService

```typescript
// mobile/__tests__/unit/services/glassesService.test.ts

/**
 * 🧪 TEST: GlassesService Unit Tests
 * 
 * ⚠️ ZERO MOCK POLICY:
 * - WebSocket connette a backend REALE
 * - Se backend spento, test FALLISCE (corretto!)
 */

import { glassesService, GlassesState } from '../../../src/services/glassesService';

const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';
const WS_URL = BACKEND_URL.replace('http', 'ws');

describe('GlassesService', () => {
  
  beforeAll(async () => {
    // VERIFICA BACKEND ATTIVO
    const response = await fetch(`${BACKEND_URL}/health`);
    if (!response.ok) {
      throw new Error(`
        ⛔⛔⛔ BACKEND NON ATTIVO ⛔⛔⛔
        
        Avvia il backend prima dei test:
        cd backend && python -m uvicorn main:app --port 8000
        
        I test DEVONO chiamare backend reale.
        Se passano con backend spento, sono MOCK (sbagliato!)
      `);
    }
  });

  afterEach(async () => {
    await glassesService.disconnect();
  });

  describe('Connection', () => {
    
    it('should connect to WebSocket endpoint', async () => {
      const result = await glassesService.connect(BACKEND_URL);
      
      expect(result).toBe(true);
      expect(glassesService.isConnected()).toBe(true);
    });

    it('should receive initial state on connect', async () => {
      let receivedState: GlassesState | null = null;
      
      glassesService.onStateChange((state) => {
        receivedState = state;
      });
      
      await glassesService.connect(BACKEND_URL);
      
      // Aspetta state sync
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(receivedState).not.toBeNull();
      expect(receivedState!.zoomLevel).toBe(1.0);
      expect(receivedState!.playbackSpeed).toBe(1.0);
    });

    it('should reconnect on disconnect', async () => {
      await glassesService.connect(BACKEND_URL);
      
      // Simula disconnect forzando close
      glassesService.forceDisconnect();
      
      // Aspetta reconnect
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      expect(glassesService.isConnected()).toBe(true);
    });

  });

  describe('Commands', () => {
    
    beforeEach(async () => {
      await glassesService.connect(BACKEND_URL);
    });

    it('should update zoom level', async () => {
      let currentState: GlassesState | null = null;
      
      glassesService.onStateChange((state) => {
        currentState = state;
      });
      
      glassesService.sendCommand({ action: 'zoom', value: 2.5 });
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(currentState!.zoomLevel).toBe(2.5);
    });

    it('should clamp zoom to valid range', async () => {
      let currentState: GlassesState | null = null;
      
      glassesService.onStateChange((state) => {
        currentState = state;
      });
      
      // Zoom oltre il massimo
      glassesService.sendCommand({ action: 'zoom', value: 5.0 });
      
      await new Promise(resolve => setTimeout(resolve, 100));
      
      expect(currentState!.zoomLevel).toBe(3.0); // Clamped to max
    });

    it('should toggle play/pause', async () => {
      let currentState: GlassesState | null = null;
      
      glassesService.onStateChange((state) => {
        currentState = state;
      });
      
      // Play
      glassesService.sendCommand({ action: 'play' });
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(currentState!.isPlaying).toBe(true);
      
      // Pause
      glassesService.sendCommand({ action: 'pause' });
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(currentState!.isPlaying).toBe(false);
    });

  });

});
```

### Integration Test - Full Flow

```typescript
// mobile/__tests__/integration/glassesFlow.test.ts

/**
 * 🧪 TEST: Glasses Control Full Flow
 * 
 * Simula flusso completo:
 * 1. Phone connette
 * 2. Glasses connette
 * 3. Phone invia comandi
 * 4. Glasses riceve aggiornamenti
 */

describe('Glasses Control Flow', () => {
  
  const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';
  const WS_URL = BACKEND_URL.replace('http', 'ws');
  const TEST_USER_ID = 'test_user_' + Date.now();
  
  let phoneWs: WebSocket;
  let glassesWs: WebSocket;

  beforeAll(async () => {
    // Verifica backend
    const response = await fetch(`${BACKEND_URL}/health`);
    if (!response.ok) {
      throw new Error('BACKEND NON ATTIVO');
    }
  });

  beforeEach(async () => {
    // Connetti phone
    phoneWs = new WebSocket(`${WS_URL}/ws/glasses/${TEST_USER_ID}`);
    await new Promise(resolve => { phoneWs.onopen = resolve; });
    
    // Connetti glasses
    glassesWs = new WebSocket(`${WS_URL}/ws/glasses/${TEST_USER_ID}`);
    await new Promise(resolve => { glassesWs.onopen = resolve; });
  });

  afterEach(() => {
    phoneWs?.close();
    glassesWs?.close();
  });

  it('should sync state between phone and glasses', async () => {
    const glassesMessages: any[] = [];
    
    glassesWs.onmessage = (event) => {
      glassesMessages.push(JSON.parse(event.data));
    };
    
    // Phone invia comando zoom
    phoneWs.send(JSON.stringify({
      type: 'command',
      command: 'zoom',
      value: 2.0
    }));
    
    // Aspetta broadcast
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Verifica glasses ha ricevuto
    const zoomUpdate = glassesMessages.find(
      m => m.type === 'state_update' && m.command === 'zoom'
    );
    
    expect(zoomUpdate).toBeDefined();
    expect(zoomUpdate.state.zoom_level).toBe(2.0);
  });

  it('should handle rapid commands', async () => {
    const glassesStates: any[] = [];
    
    glassesWs.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'state_update') {
        glassesStates.push(data.state);
      }
    };
    
    // Invia 10 comandi rapidi
    for (let i = 1; i <= 10; i++) {
      phoneWs.send(JSON.stringify({
        type: 'command',
        command: 'zoom',
        value: 1.0 + (i * 0.2)
      }));
    }
    
    // Aspetta
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Verifica tutti ricevuti
    expect(glassesStates.length).toBeGreaterThanOrEqual(10);
    
    // Ultimo stato deve essere zoom = 3.0 (clamped)
    const lastState = glassesStates[glassesStates.length - 1];
    expect(lastState.zoom_level).toBe(3.0);
  });

});
```

### Security Test - WebSocket Injection

```typescript
// mobile/__tests__/security/penetration/wsInjection.test.ts

/**
 * 🧪 SECURITY TEST: WebSocket Injection Prevention
 * 
 * Verifica che backend gestisca correttamente:
 * - Messaggi malformati
 * - Comandi non validi
 * - Valori fuori range
 * - Tentativi di injection
 */

describe('WebSocket Security', () => {
  
  const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';
  const WS_URL = BACKEND_URL.replace('http', 'ws');
  
  let ws: WebSocket;

  beforeEach(async () => {
    ws = new WebSocket(`${WS_URL}/ws/glasses/security_test`);
    await new Promise(resolve => { ws.onopen = resolve; });
  });

  afterEach(() => {
    ws?.close();
  });

  it('should reject malformed JSON', async () => {
    let errorReceived = false;
    
    ws.onerror = () => { errorReceived = true; };
    
    // Invia JSON malformato
    ws.send('{ invalid json }');
    
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Connessione dovrebbe essere ancora attiva (graceful handling)
    expect(ws.readyState).toBe(WebSocket.OPEN);
  });

  it('should reject unknown commands', async () => {
    let lastMessage: any = null;
    
    ws.onmessage = (event) => {
      lastMessage = JSON.parse(event.data);
    };
    
    // Comando non esistente
    ws.send(JSON.stringify({
      type: 'command',
      command: 'hack_system',
      value: 'malicious'
    }));
    
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Non dovrebbe crashare, stato invariato
    expect(ws.readyState).toBe(WebSocket.OPEN);
  });

  it('should sanitize extreme values', async () => {
    let lastState: any = null;
    
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.state) {
        lastState = data.state;
      }
    };
    
    // Valori estremi
    ws.send(JSON.stringify({
      type: 'command',
      command: 'zoom',
      value: 999999
    }));
    
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Deve essere clampato a 3.0
    expect(lastState.zoom_level).toBe(3.0);
    
    // Valore negativo
    ws.send(JSON.stringify({
      type: 'command',
      command: 'zoom',
      value: -100
    }));
    
    await new Promise(resolve => setTimeout(resolve, 200));
    
    // Deve essere clampato a 1.0
    expect(lastState.zoom_level).toBe(1.0);
  });

  it('should prevent SQL injection in user_id', async () => {
    // Tenta SQL injection nel path
    const maliciousWs = new WebSocket(
      `${WS_URL}/ws/glasses/'; DROP TABLE users; --`
    );
    
    let connected = false;
    
    maliciousWs.onopen = () => { connected = true; };
    maliciousWs.onerror = () => { connected = false; };
    
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Backend NON deve crashare
    const healthResponse = await fetch(`${BACKEND_URL}/health`);
    expect(healthResponse.ok).toBe(true);
    
    maliciousWs.close();
  });

});
```

### Stress Test - Multiple Connections

```typescript
// mobile/__tests__/stress/multipleConnections.test.ts

/**
 * 🧪 STRESS TEST: Multiple Concurrent Connections
 * 
 * Verifica che backend gestisca:
 * - 100+ connessioni simultanee
 * - Broadcast a tutti i client
 * - Cleanup corretto su disconnect
 */

describe('Stress Test - Multiple Connections', () => {
  
  const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';
  const WS_URL = BACKEND_URL.replace('http', 'ws');
  
  it('should handle 100 concurrent connections', async () => {
    const NUM_CONNECTIONS = 100;
    const connections: WebSocket[] = [];
    const connected: boolean[] = [];
    
    // Crea 100 connessioni
    for (let i = 0; i < NUM_CONNECTIONS; i++) {
      const ws = new WebSocket(`${WS_URL}/ws/glasses/stress_user_${i}`);
      connections.push(ws);
      
      ws.onopen = () => { connected[i] = true; };
    }
    
    // Aspetta connessioni
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Verifica tutte connesse
    const successCount = connected.filter(Boolean).length;
    console.log(`Connected: ${successCount}/${NUM_CONNECTIONS}`);
    
    expect(successCount).toBeGreaterThanOrEqual(NUM_CONNECTIONS * 0.95); // 95%+
    
    // Cleanup
    connections.forEach(ws => ws.close());
    
    // Verifica backend ancora healthy
    const healthResponse = await fetch(`${BACKEND_URL}/health`);
    expect(healthResponse.ok).toBe(true);
    
  }, 30000); // Timeout 30s

  it('should broadcast to all clients in room efficiently', async () => {
    const ROOM_SIZE = 50;
    const ROOM_ID = 'broadcast_test_room';
    const connections: WebSocket[] = [];
    const receivedMessages: number[] = new Array(ROOM_SIZE).fill(0);
    
    // Crea connessioni nella stessa room
    for (let i = 0; i < ROOM_SIZE; i++) {
      const ws = new WebSocket(`${WS_URL}/ws/glasses/${ROOM_ID}`);
      connections.push(ws);
      
      ws.onmessage = () => { receivedMessages[i]++; };
    }
    
    // Aspetta connessioni
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Un client invia comando
    connections[0].send(JSON.stringify({
      type: 'command',
      command: 'zoom',
      value: 2.0
    }));
    
    // Aspetta broadcast
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Tutti devono aver ricevuto
    const receivedCount = receivedMessages.filter(c => c > 0).length;
    console.log(`Received broadcast: ${receivedCount}/${ROOM_SIZE}`);
    
    expect(receivedCount).toBe(ROOM_SIZE);
    
    // Cleanup
    connections.forEach(ws => ws.close());
    
  }, 30000);

});
```

### Performance Test - Latency

```typescript
// mobile/__tests__/slow/latencyBenchmark.test.ts

/**
 * 🧪 PERFORMANCE TEST: Command Latency
 * 
 * Misura latenza round-trip dei comandi
 * Target: <100ms
 */

describe('Performance - Latency', () => {
  
  const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';
  const WS_URL = BACKEND_URL.replace('http', 'ws');
  
  it('should have command latency under 100ms', async () => {
    const ws = new WebSocket(`${WS_URL}/ws/glasses/latency_test`);
    await new Promise(resolve => { ws.onopen = resolve; });
    
    const latencies: number[] = [];
    
    for (let i = 0; i < 100; i++) {
      const start = performance.now();
      
      ws.send(JSON.stringify({
        type: 'command',
        command: 'zoom',
        value: 1.0 + (i % 20) * 0.1
      }));
      
      await new Promise<void>(resolve => {
        ws.onmessage = () => {
          const latency = performance.now() - start;
          latencies.push(latency);
          resolve();
        };
      });
    }
    
    ws.close();
    
    // Calcola statistiche
    const avg = latencies.reduce((a, b) => a + b) / latencies.length;
    const max = Math.max(...latencies);
    const p95 = latencies.sort((a, b) => a - b)[Math.floor(latencies.length * 0.95)];
    
    console.log(`Latency - Avg: ${avg.toFixed(2)}ms, Max: ${max.toFixed(2)}ms, P95: ${p95.toFixed(2)}ms`);
    
    expect(avg).toBeLessThan(50);   // Avg <50ms
    expect(p95).toBeLessThan(100);  // P95 <100ms
    
  }, 60000);

});
```

## 4.4 CONFTEST.PY - MOCK BLOCKER (Backend)

```python
# backend/tests/conftest.py

"""
⛔⛔⛔ BLOCCO AUTOMATICO MOCK ⛔⛔⛔

Questo file impedisce FISICAMENTE l'uso di mock.
NON MODIFICARE. NON RIMUOVERE. NON COMMENTARE.
"""

import pytest
import httpx
import warnings
import os
from typing import Set

BACKEND_URL = os.getenv("TEST_BACKEND_URL", "http://localhost:8000")

# Moduli VIETATI per mock
MODULI_VIETATI: Set[str] = {
    "httpx", "requests", "aiohttp",
    "sqlalchemy", "databases", "asyncpg",
    "fastapi", "websocket",
    "app.services", "app.api", "app.core",
}


def _blocca_mock():
    """Blocca fisicamente mock su moduli vietati."""
    try:
        from unittest import mock
        from unittest.mock import patch
        
        original_patch = patch
        
        def patch_bloccato(target, *args, **kwargs):
            for vietato in MODULI_VIETATI:
                if vietato in str(target):
                    raise RuntimeError(f"""
⛔⛔⛔ MOCK VIETATO ⛔⛔⛔

Hai tentato di mockare: {target}

QUESTO È VIETATO.
Riscrivi il test usando backend REALE.
""")
            return original_patch(target, *args, **kwargs)
        
        mock.patch = patch_bloccato
        
    except ImportError:
        pass


_blocca_mock()


@pytest.fixture(scope="session", autouse=True)
def verifica_backend_attivo():
    """Verifica backend PRIMA di qualsiasi test."""
    print(f"\n🔍 Verifico backend su {BACKEND_URL}...")
    
    try:
        response = httpx.get(f"{BACKEND_URL}/health", timeout=5.0)
        if response.status_code != 200:
            raise RuntimeError(f"Backend risponde {response.status_code}")
        print("✅ Backend attivo\n")
    except Exception as e:
        pytest.exit(f"""
⛔⛔⛔ BACKEND NON ATTIVO ⛔⛔⛔

Errore: {e}

Prima di eseguire test:
1. cd backend
2. python -m uvicorn main:app --port 8000
3. Riesegui pytest
""", returncode=1)


@pytest.fixture
def api_client():
    """Client HTTP per test REALI."""
    with httpx.Client(base_url=BACKEND_URL, timeout=30.0) as client:
        yield client


@pytest.fixture
async def async_api_client():
    """Client HTTP async per test REALI."""
    async with httpx.AsyncClient(base_url=BACKEND_URL, timeout=30.0) as client:
        yield client
```

## 4.5 JEST.SETUP.JS - MOCK BLOCKER (Frontend)

```javascript
// mobile/jest.setup.js

/**
 * ⛔⛔⛔ BLOCCO AUTOMATICO MOCK ⛔⛔⛔
 * 
 * NON MODIFICARE. NON RIMUOVERE. NON COMMENTARE.
 */

const BACKEND_URL = process.env.TEST_BACKEND_URL || 'http://localhost:8000';

// Moduli VIETATI
const MODULI_VIETATI = [
  '@/services',
  '@/api',
  'axios',
  'fetch',
  '../services/',
  '../api/',
];

// Intercetta jest.mock
const originalMock = jest.mock;
jest.mock = function(moduleName, factory, options) {
  const isVietato = MODULI_VIETATI.some(v => moduleName.includes(v));
  
  if (isVietato) {
    throw new Error(`
⛔⛔⛔ MOCK VIETATO ⛔⛔⛔

Hai tentato di mockare: ${moduleName}

QUESTO È VIETATO.
Riscrivi il test usando backend REALE.
`);
  }
  
  return originalMock.call(this, moduleName, factory, options);
};

// Verifica backend PRIMA di ogni suite
beforeAll(async () => {
  console.log(`🔍 Verifico backend su ${BACKEND_URL}...`);
  
  try {
    const response = await fetch(`${BACKEND_URL}/health`, { timeout: 5000 });
    if (!response.ok) {
      throw new Error(`Backend risponde ${response.status}`);
    }
    console.log('✅ Backend attivo');
  } catch (error) {
    console.error(`
⛔⛔⛔ BACKEND NON ATTIVO ⛔⛔⛔

Errore: ${error.message}

Prima di eseguire test:
1. cd backend
2. python -m uvicorn main:app --port 8000
3. Riesegui npm test
`);
    process.exit(1);
  }
});
```

---

# 📋 SEZIONE 5: CHECKLIST IMPLEMENTAZIONE

## Prima di iniziare:

```
□ Backend avviato su localhost:8000
□ Letto TUTTE le sezioni di questo prompt
□ Capito ZERO MOCK policy
```

## Durante implementazione:

```
□ Ogni file ha header AI-First completo
□ Commenti spiegano il PERCHÉ, non il cosa
□ Nessun TODO, FIXME, placeholder
□ Test chiamano backend REALE
□ Test FALLISCONO con backend spento
```

## Prima di completare:

```
□ Coverage >= 90%
□ Pass rate >= 95%
□ grep "jest.mock\|MagicMock" restituisce 0 risultati
□ Backend spento → tutti i test FALLISCONO
□ Backend acceso → tutti i test PASSANO
```

---

# 🚀 SEZIONE 6: ORDINE IMPLEMENTAZIONE

1. **Backend WebSocket** (`backend/api/v1/glasses_ws.py`)
2. **Backend Tests** (`backend/tests/`)
3. **GlassesService** (`mobile/src/services/glassesService.ts`)
4. **GlassesService Tests** (`mobile/__tests__/unit/services/`)
5. **GlassesControlPanel** (`mobile/src/components/`)
6. **GlassesPlayerScreen** (`mobile/src/screens/`)
7. **Integration Tests** (`mobile/__tests__/integration/`)
8. **Security Tests** (`mobile/__tests__/security/`)
9. **Stress Tests** (`mobile/__tests__/stress/`)
10. **Performance Tests** (`mobile/__tests__/slow/`)

---

**VERSIONE:** 1.0
**DATA:** 14 Dicembre 2025
**PROGETTO:** Media Center Arti Marziali - Glasses Control Module

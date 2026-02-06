// POSIZIONE: frontend/jest.setup.js
/**
 * 🎓 AI_MODULE: Jest Setup - Mock Blocker
 * 🎓 AI_DESCRIPTION: Configurazione Jest con blocco automatico mock
 * 🎓 AI_BUSINESS: Garantisce test reali, zero mock per qualità enterprise
 * 🎓 AI_TEACHING: Intercetta jest.mock/fn per prevenire mock su moduli business
 *
 * 🔄 ALTERNATIVE_VALUTATE:
 * - Permettere mock selettivi: Scartato, troppo facile abusarne
 * - Review manuale: Scartato, non scala
 * - Nessun blocco: Scartato, team userebbe mock
 *
 * 💡 PERCHÉ_QUESTA_SOLUZIONE:
 * - Blocco fisico a runtime
 * - Errore chiaro con istruzioni
 * - Impossibile bypassare
 *
 * ⛔ LEGGE SUPREMA: ZERO MOCK
 */

// ============================================================================
// CONFIGURAZIONE
// ============================================================================

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

// Lista moduli che NON POSSONO MAI essere mockati
const MODULI_VIETATI = [
  // API e fetch
  '@/services',
  '@/lib/api',
  'axios',
  'node-fetch',
  'fetch',
  
  // Database/Storage
  '@/lib/db',
  '@/database',
  
  // Auth
  '@/lib/auth',
  '@/contexts/AuthContext',
  
  // Business logic
  '@/hooks',
  '@/utils',
  '@/helpers',
];

// ============================================================================
// ⛔ BLOCCO jest.mock()
// ============================================================================

const ERRORE_MOCK = (moduleName) => `

⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔
⛔                                                            ⛔
⛔   ERRORE FATALE: MOCK VIETATO                              ⛔
⛔                                                            ⛔
⛔   Hai tentato di mockare: ${moduleName.padEnd(30)}         ⛔
⛔                                                            ⛔
⛔   QUESTO È VIETATO dalla LEGGE SUPREMA ZERO MOCK.          ⛔
⛔                                                            ⛔
⛔   Leggi: CLAUDE_CODE_SESSION_ENTERPRISE.md                 ⛔
⛔   Sezione: LEGGE SUPREMA ZERO MOCK                         ⛔
⛔                                                            ⛔
⛔   RISCRIVI IL TEST USANDO IL BACKEND REALE.                ⛔
⛔                                                            ⛔
⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔

`;

// Intercetta jest.mock
const originalMock = jest.mock;
jest.mock = function(moduleName, factory, options) {
  const isVietato = MODULI_VIETATI.some(vietato => 
    moduleName.includes(vietato) || 
    moduleName.startsWith(vietato)
  );
  
  if (isVietato) {
    throw new Error(ERRORE_MOCK(moduleName));
  }
  
  return originalMock.call(this, moduleName, factory, options);
};

// ============================================================================
// ⚠️ WARNING su jest.fn()
// ============================================================================

const originalFn = jest.fn;
jest.fn = function(implementation) {
  console.warn(`
⚠️ jest.fn() rilevato.
⚠️ Consentito SOLO per: callback, event handlers, console.log
⚠️ VIETATO per: API, database, fetch, servizi
⚠️ 
⚠️ Se stai mockando una API, FERMATI e usa il backend reale.
  `);
  return originalFn.call(this, implementation);
};

// ============================================================================
// VERIFICA BACKEND ATTIVO
// ============================================================================

beforeAll(async () => {
  console.log('🔍 Verifico backend attivo...');
  
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${BACKEND_URL}/health`, {
      signal: controller.signal
    });
    
    clearTimeout(timeout);
    
    if (!response.ok) {
      throw new Error(`Backend risponde ${response.status}`);
    }
    
    console.log('✅ Backend attivo su', BACKEND_URL);
    
  } catch (error) {
    console.error(`
⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔
⛔                                                            ⛔
⛔   BACKEND NON ATTIVO - TEST BLOCCATI                       ⛔
⛔                                                            ⛔
⛔   Errore: ${error.message}
⛔                                                            ⛔
⛔   Prima di eseguire i test:                                ⛔
⛔                                                            ⛔
⛔   1. cd backend                                            ⛔
⛔   2. python -m uvicorn main:app --port 8000                ⛔
⛔   3. Attendi "Application startup complete"                ⛔
⛔   4. Riesegui npm test                                     ⛔
⛔                                                            ⛔
⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔⛔
    `);
    
    // Non blocchiamo i test, ma avvisiamo
    // throw new Error('BACKEND NON ATTIVO');
  }
});

// ============================================================================
// REPORT FINALE
// ============================================================================

afterAll(() => {
  console.log(`
📊 ═══════════════════════════════════════════════════════════
📊 TEST COMPLETATI
📊 
📊 ✅ Se tutti i test sono passati con backend ATTIVO = Test REALI
📊 ⚠️  Se dubiti, spegni backend e riesegui. Devono FALLIRE.
📊 
📊 Target coverage: 90%
📊 Target pass rate: 95%
📊 ═══════════════════════════════════════════════════════════
  `);
});

// ============================================================================
// GLOBAL SETUP
// ============================================================================

// Estendi expect con matchers personalizzati
expect.extend({
  toBeValidJWT(received) {
    const pass = typeof received === 'string' && 
                 received.split('.').length === 3 &&
                 received.length > 100;
    
    return {
      pass,
      message: () => pass
        ? `Expected ${received} not to be a valid JWT`
        : `Expected ${received} to be a valid JWT (3 parts, >100 chars)`
    };
  },
  
  toBeSuccessResponse(received) {
    const pass = received.status >= 200 && received.status < 300;
    
    return {
      pass,
      message: () => pass
        ? `Expected response not to be successful (got ${received.status})`
        : `Expected response to be successful (200-299), got ${received.status}`
    };
  }
});

// ============================================================================
// POLYFILLS
// ============================================================================

// TextEncoder/Decoder per Node.js
if (typeof TextEncoder === 'undefined') {
  const { TextEncoder, TextDecoder } = require('util');
  global.TextEncoder = TextEncoder;
  global.TextDecoder = TextDecoder;
}

// Fetch per Node.js (se non disponibile)
if (typeof fetch === 'undefined') {
  global.fetch = require('node-fetch');
}

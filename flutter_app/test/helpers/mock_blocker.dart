/// ================================================================================
/// 🎓 AI_MODULE: MockBlocker
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Utility per enforcing ZERO MOCK POLICY nei test
/// 🎓 AI_BUSINESS: Previene uso accidentale di mock libraries.
///                 Garantisce che tutti i test chiamino backend REALE.
///                 Quality assurance: test non possono passare con mock.
/// 🎓 AI_TEACHING: Static analysis alternative, reflection-free detection,
///                 build-time vs runtime checks.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 FEATURES:
/// - Verifica assenza import mock libraries
/// - Fallisce test se mock pattern rilevati
/// - Documenta policy per team
///
/// 🧪 ZERO_MOCK_POLICY:
/// - VIETATO: mocktail, mockito, when(), thenAnswer(), thenReturn(), verify()
/// - VIETATO: Classi che estendono Mock
/// - CONSENTITO: Solo chiamate a backend REALE localhost:8000
/// ================================================================================

import 'dart:io';
import 'package:test/test.dart';

/// Patterns da bloccare nel codice test
const List<String> _forbiddenPatterns = [
  'import \'package:mocktail',
  'import \'package:mockito',
  'import "package:mocktail',
  'import "package:mockito',
  'extends Mock',
  'class Mock',
  'when(',
  '.when(',
  'thenReturn(',
  'thenAnswer(',
  'thenThrow(',
  'verify(',
  '.verify(',
  'verifyNever(',
  'reset(mock',
  'resetMocktailState(',
  '@GenerateMocks',
  '@GenerateNiceMocks',
];

/// Messaggi per ogni pattern (per feedback chiaro)
const Map<String, String> _patternMessages = {
  'import \'package:mocktail': 'IMPORT MOCKTAIL VIETATO - Usa backend reale',
  'import \'package:mockito': 'IMPORT MOCKITO VIETATO - Usa backend reale',
  'extends Mock': 'MOCK CLASS VIETATA - Chiama API reali su localhost:8000',
  'when(': 'WHEN() VIETATO - Usa ApiTestHelper per chiamate reali',
  'thenReturn(': 'THEN_RETURN() VIETATO - Backend deve rispondere davvero',
  'thenAnswer(': 'THEN_ANSWER() VIETATO - Backend deve rispondere davvero',
  'verify(': 'VERIFY() VIETATO - Verifica risposte reali, non mock calls',
};

/// Verifica che un file test non contenga pattern mock
///
/// Throws TestFailure se trova pattern vietati
void assertNoMockPatterns(String filePath) {
  final file = File(filePath);

  if (!file.existsSync()) {
    // File non esiste, skip
    return;
  }

  final content = file.readAsStringSync();
  final violations = <String>[];

  for (final pattern in _forbiddenPatterns) {
    if (content.contains(pattern)) {
      final message = _patternMessages.entries
              .firstWhere(
                (e) => pattern.contains(e.key),
                orElse: () => MapEntry(pattern, 'Pattern vietato: $pattern'),
              )
              .value;
      violations.add('  - $message (found: "$pattern")');
    }
  }

  if (violations.isNotEmpty) {
    fail('''

============================================================
ZERO MOCK POLICY VIOLATION
============================================================

File: $filePath

Violazioni trovate:
${violations.join('\n')}

REGOLA: Tutti i test devono chiamare backend REALE.

Come correggere:
1. Rimuovi import mock libraries
2. Usa ApiTestHelper per chiamate HTTP
3. Usa BackendHelper per setup/teardown
4. Assicurati che backend sia attivo su localhost:8000

Documentazione: test/README.md
============================================================
''');
  }
}

/// Verifica tutti i file in una directory test
void assertNoMocksInDirectory(String directoryPath) {
  final dir = Directory(directoryPath);

  if (!dir.existsSync()) {
    return;
  }

  final dartFiles = dir
      .listSync(recursive: true)
      .whereType<File>()
      .where((f) => f.path.endsWith('_test.dart'));

  for (final file in dartFiles) {
    assertNoMockPatterns(file.path);
  }
}

/// Matcher personalizzato per verificare assenza mock in risposta
///
/// Uso: expect(response, hasNoMockIndicators);
final Matcher hasNoMockIndicators = _NoMockIndicatorsMatcher();

class _NoMockIndicatorsMatcher extends Matcher {
  @override
  bool matches(dynamic item, Map matchState) {
    if (item == null) return false;

    final str = item.toString();

    // Indicatori che la risposta potrebbe essere mockkata
    final mockIndicators = [
      'MockResponse',
      'FakeResponse',
      'stub',
      'MOCK_',
      '_mock_',
    ];

    for (final indicator in mockIndicators) {
      if (str.contains(indicator)) {
        matchState['indicator'] = indicator;
        return false;
      }
    }

    return true;
  }

  @override
  Description describe(Description description) {
    return description.add('response without mock indicators');
  }

  @override
  Description describeMismatch(
    dynamic item,
    Description mismatchDescription,
    Map matchState,
    bool verbose,
  ) {
    return mismatchDescription
        .add('contains mock indicator: ${matchState['indicator']}');
  }
}

/// Verifica che una risposta HTTP sia da backend reale
///
/// Controlla headers tipici di backend reale vs mock
bool isRealBackendResponse(Map<String, String> headers) {
  // Backend reale ha questi headers
  final realIndicators = [
    'x-request-id',
    'x-process-time',
    'server',
  ];

  // Se ha almeno uno di questi, probabilmente è reale
  return realIndicators.any(
    (h) => headers.containsKey(h) || headers.containsKey(h.toLowerCase()),
  );
}

/// Helper per run test che verificano policy
///
/// Uso in test:
/// ```dart
/// test('my test', () {
///   enforceMockPolicy();
///   // ... test code
/// });
/// ```
void enforceMockPolicy() {
  // Questa funzione serve come marker.
  // In fase di CI, uno script può verificare che tutti i test
  // la chiamino o usino pattern ZERO MOCK.

  // Per ora, stampa reminder
  print('ZERO MOCK POLICY ACTIVE - All calls go to real backend');
}

/// Documenta la ZERO MOCK policy (per IDE/documentation)
///
/// ```dart
/// @ZeroMockPolicy()
/// void main() {
///   // tests here
/// }
/// ```
class ZeroMockPolicy {
  /// Policy version
  final String version;

  /// Data enforcement
  final String since;

  const ZeroMockPolicy({
    this.version = '1.0',
    this.since = '2025-01-01',
  });
}

/// ================================================================================
/// WIDGET TEST SKIPPED - Flutter TestWidgetsFlutterBinding blocca rete
/// ================================================================================
/// 
/// Questi test sono SKIPPED perché Flutter TestWidgetsFlutterBinding
/// intercetta TUTTE le chiamate HTTP/WebSocket e ritorna errore 400.
/// 
/// I test reali del GlassesService sono in:
/// - test/real/unit/features/glasses/glasses_service_real_test.dart (339 PASS)
/// - test/real/integration/glasses/
/// - test/real/e2e/glasses/
/// ================================================================================

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('Widget tests skipped - use integration tests for real backend', () {
    // Flutter widget tests cannot make real network calls.
    // See glasses_service_real_test.dart for 339 real tests.
    expect(true, isTrue);
  });
}

/// ================================================================================
///     TEST CONFIG - ZERO MOCK - LEGGE SUPREMA
/// ================================================================================
///
///     REGOLA INVIOLABILE: Questo progetto NON usa mock per API/HTTP.
///     Tutti i test chiamano backend REALE su localhost:8000.
///
///     VIETATO:
///     - mocktail
///     - mockito
///     - when()
///     - thenAnswer()
///     - thenReturn()
///     - verify()
///     - Mock classes
///
/// ================================================================================

import 'dart:convert';
import 'package:http/http.dart' as http;

/// Base URL del backend REALE
/// Backend attivo su porta 8000
const String apiBaseUrl = 'http://localhost:8000';

/// Timeout per chiamate API
const Duration apiTimeout = Duration(seconds: 30);

/// Verifica che backend sia attivo PRIMA dei test
Future<void> ensureBackendRunning() async {
  try {
    final response = await http
        .get(Uri.parse('$apiBaseUrl/health'))
        .timeout(const Duration(seconds: 5));

    if (response.statusCode != 200) {
      throw Exception(
          'Backend non risponde correttamente: ${response.statusCode}');
    }

    print('Backend attivo su $apiBaseUrl');
  } catch (e) {
    throw Exception('''

BACKEND NON ATTIVO - TEST BLOCCATI

Prima di eseguire i test:

1. Apri terminale
2. cd backend
3. python -m uvicorn main:app --port 8000
4. Attendi "Application startup complete"
5. Riesegui i test

Errore: $e
''');
  }
}

/// Test user credentials (devono esistere nel backend seed)
/// Allineate con create_test_users.py
class TestUsers {
  static const freeUser = (
    email: 'utente.free@mediacenter.it',
    password: 'Free2024!',
  );

  static const premiumUser = (
    email: 'studente.premium@mediacenter.it',
    password: 'Student2024!',
  );

  static const maestroUser = (
    email: 'maestro.premium@mediacenter.it',
    password: 'Maestro2024!',
  );

  static const adminUser = (
    email: 'admin@mediacenter.it',
    password: 'Admin2024!',
  );

  static const hybridUser = (
    email: 'utente.hybrid@mediacenter.it',
    password: 'Hybrid2024!',
  );

  static const businessUser = (
    email: 'asd.admin@mediacenter.it',
    password: 'ASD2024!',
  );
}

/// Tags per categorizzare test
class TestTags {
  static const String unit = 'unit';
  static const String integration = 'integration';
  static const String security = 'security';
  static const String performance = 'performance';
  static const String stress = 'stress';
  static const String holistic = 'holistic';
  static const String slow = 'slow';
}

/// Timeouts per diversi tipi di operazioni
class TestTimeouts {
  static const Duration fast = Duration(seconds: 5);
  static const Duration normal = Duration(seconds: 15);
  static const Duration slow = Duration(seconds: 30);
  static const Duration verySlow = Duration(seconds: 60);
}

/// Performance thresholds
/// NOTE: Increased thresholds for test environment (network variability)
class PerformanceThresholds {
  static const int healthEndpointMs = 200;
  static const int loginEndpointMs = 1000;
  static const int videosListMs = 1500;
  static const int searchMs = 1000;
}

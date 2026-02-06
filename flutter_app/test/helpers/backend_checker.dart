/// 🎓 AI_MODULE: BackendChecker
/// 🎓 AI_DESCRIPTION: Helper per verificare disponibilità backend - ZERO MOCK
/// 🎓 AI_BUSINESS: Garantisce test con backend reale o skip esplicito
/// 🎓 AI_TEACHING: Pattern test enterprise - backend reale obbligatorio
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:http/http.dart' as http;
import 'package:flutter_test/flutter_test.dart';

/// Eccezione per test skippati causa backend offline
class BackendOfflineException implements Exception {
  final String message;
  BackendOfflineException(this.message);

  @override
  String toString() => 'BackendOfflineException: $message';
}

/// Helper per verificare backend attivo prima dei test
class BackendChecker {
  static const String baseUrl = 'http://localhost:8000';
  static const String apiBaseUrl = '$baseUrl/api/v1';

  /// Cache del risultato per evitare chiamate ripetute
  static bool? _cachedResult;
  static DateTime? _cacheTime;
  static const Duration _cacheDuration = Duration(seconds: 30);

  /// Verifica backend attivo, ritorna true se OK
  static Future<bool> isBackendAvailable() async {
    // Usa cache se valida
    if (_cachedResult != null && _cacheTime != null) {
      if (DateTime.now().difference(_cacheTime!) < _cacheDuration) {
        return _cachedResult!;
      }
    }

    try {
      // Prova health endpoint
      final response = await http.get(
        Uri.parse('$baseUrl/health'),
      ).timeout(const Duration(seconds: 5));

      _cachedResult = response.statusCode == 200;
      _cacheTime = DateTime.now();
      return _cachedResult!;
    } catch (e) {
      // Prova docs endpoint come fallback
      try {
        final response = await http.get(
          Uri.parse('$baseUrl/docs'),
        ).timeout(const Duration(seconds: 5));

        _cachedResult = response.statusCode == 200;
        _cacheTime = DateTime.now();
        return _cachedResult!;
      } catch (_) {
        _cachedResult = false;
        _cacheTime = DateTime.now();
        return false;
      }
    }
  }

  /// Invalida la cache
  static void invalidateCache() {
    _cachedResult = null;
    _cacheTime = null;
  }

  /// Skip test se backend non disponibile
  /// Lancia BackendOfflineException che causa skip del test
  static Future<void> requireBackend() async {
    if (!await isBackendAvailable()) {
      throw BackendOfflineException(
        'Backend non disponibile su $baseUrl - '
        'Avvia il backend con: cd backend && uvicorn main:app --reload',
      );
    }
  }

  /// Esegue test solo se backend disponibile
  /// Altrimenti marca come skipped
  static Future<void> runWithBackend(
    Future<void> Function() testBody, {
    String? skipReason,
  }) async {
    final isAvailable = await isBackendAvailable();

    if (!isAvailable) {
      markTestSkipped(
        skipReason ??
            'Backend non disponibile su $baseUrl - test skipped. '
                'Avvia il backend per eseguire questo test.',
      );
      return;
    }

    await testBody();
  }

  /// Verifica che una chiamata API funzioni
  static Future<bool> canCallApi(String endpoint) async {
    try {
      final response = await http.get(
        Uri.parse('$apiBaseUrl$endpoint'),
      ).timeout(const Duration(seconds: 10));

      return response.statusCode >= 200 && response.statusCode < 500;
    } catch (e) {
      return false;
    }
  }
}

/// Extension per test group con backend check
extension BackendTestGroup on void Function() {
  /// Esegue gruppo di test solo se backend disponibile
  void withBackend(String description, void Function() body) {
    group(description, () {
      setUpAll(() async {
        await BackendChecker.requireBackend();
      });

      body();
    });
  }
}

/// Helper per creare test che richiedono backend
void testWithBackend(
  String description,
  Future<void> Function() body, {
  String? skip,
  List<String>? tags,
}) {
  test(
    description,
    () async {
      await BackendChecker.runWithBackend(body);
    },
    skip: skip,
    tags: tags,
  );
}

/// Helper per verificare response API
class ApiTestHelper {
  /// Verifica che endpoint risponda con status valido
  static Future<http.Response> getEndpoint(String path) async {
    final url = '${BackendChecker.apiBaseUrl}$path';
    return await http.get(Uri.parse(url)).timeout(
          const Duration(seconds: 10),
        );
  }

  /// Verifica che endpoint POST funzioni
  static Future<http.Response> postEndpoint(
    String path, {
    Map<String, dynamic>? body,
    Map<String, String>? headers,
  }) async {
    final url = '${BackendChecker.apiBaseUrl}$path';
    return await http
        .post(
          Uri.parse(url),
          headers: {
            'Content-Type': 'application/json',
            ...?headers,
          },
          body: body != null ? body.toString() : null,
        )
        .timeout(const Duration(seconds: 10));
  }
}

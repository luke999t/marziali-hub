/// ================================================================================
/// 🎓 AI_MODULE: BackendHelper
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Helper avanzato per verifica e setup backend nei test ZERO MOCK
/// 🎓 AI_BUSINESS: Garantisce che tutti i test chiamino backend REALE.
///                 Setup/teardown consistente per test isolation.
///                 Zero false positive da mock: se backend giù, test fallisce.
/// 🎓 AI_TEACHING: Pattern per test infrastructure, health checks,
///                 data cleanup, WebSocket test setup.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 FEATURES:
/// - Health check multi-endpoint (REST, WebSocket, Database)
/// - Retry logic per instabilità temporanea network
/// - Cleanup automatico test data tra run
/// - WebSocket connection verifier
/// - Performance baseline capture
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Nessun mock: tutte le chiamate vanno a localhost:8000
/// - Se backend spento, test DEVONO FALLIRE
/// ================================================================================

import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;
import 'package:web_socket_channel/web_socket_channel.dart';
import 'test_config.dart';

/// Helper avanzato per operazioni backend nei test
class BackendHelper {
  /// Singleton instance
  static final BackendHelper instance = BackendHelper._();

  BackendHelper._();

  /// Token JWT corrente per test autenticati
  String? _currentToken;

  /// User ID corrente per test glasses
  String? _currentUserId;

  /// Stato backend verificato
  bool _backendVerified = false;

  // ---------------------------------------------------------------------------
  // Getters
  // ---------------------------------------------------------------------------

  String? get currentToken => _currentToken;
  String? get currentUserId => _currentUserId;
  bool get isBackendVerified => _backendVerified;

  // ---------------------------------------------------------------------------
  // Health Checks
  // ---------------------------------------------------------------------------

  /// Verifica completa salute backend (REST + DB)
  ///
  /// Throws se backend non disponibile - QUESTO È VOLUTO.
  /// Test devono fallire se backend non è attivo.
  Future<void> verifyBackendHealth({
    int maxRetries = 3,
    Duration retryDelay = const Duration(seconds: 2),
  }) async {
    Exception? lastError;

    for (int i = 0; i < maxRetries; i++) {
      try {
        // Check REST API
        final healthResponse = await http
            .get(Uri.parse('$apiBaseUrl/health'))
            .timeout(const Duration(seconds: 5));

        if (healthResponse.statusCode != 200) {
          throw Exception('Health check failed: ${healthResponse.statusCode}');
        }

        // Parse health data per verificare stato
        final healthData = jsonDecode(healthResponse.body);
        // Backend può avere 'database: connected' o solo 'status: healthy'
        final dbStatus = healthData['database'];
        final status = healthData['status'];
        if (dbStatus != null && dbStatus != 'connected') {
          throw Exception('Database not connected');
        }
        if (status != 'healthy') {
          throw Exception('Backend not healthy: $status');
        }

        _backendVerified = true;
        print('Backend health verified on attempt ${i + 1}');
        return;
      } catch (e) {
        lastError = e is Exception ? e : Exception(e.toString());
        print('Health check attempt ${i + 1} failed: $e');

        if (i < maxRetries - 1) {
          await Future.delayed(retryDelay);
        }
      }
    }

    _backendVerified = false;
    throw Exception('''

============================================================
BACKEND NON DISPONIBILE - TEST BLOCCATI (ZERO MOCK POLICY)
============================================================

Il backend deve essere attivo per eseguire i test.
Questo è VOLUTO: nessun mock è consentito.

Per avviare il backend:
  cd backend
  python -m uvicorn main:app --reload --port 8000

Ultimo errore: $lastError
============================================================
''');
  }

  /// Verifica WebSocket endpoint è raggiungibile
  Future<bool> verifyWebSocketHealth({
    required String userId,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    WebSocketChannel? channel;

    try {
      final wsUrl = apiBaseUrl
          .replaceFirst('http://', 'ws://')
          .replaceFirst('https://', 'wss://');

      channel = WebSocketChannel.connect(
        Uri.parse('$wsUrl/api/v1/ws/glasses/$userId?device_type=test'),
      );

      await channel.ready.timeout(timeout);

      // Send ping to verify
      channel.sink.add(jsonEncode({'type': 'ping'}));

      // Wait for pong (with timeout)
      await channel.stream
          .timeout(timeout)
          .firstWhere((msg) {
            final data = jsonDecode(msg as String);
            return data['type'] == 'pong' || data['type'] == 'state_sync';
          });

      return true;
    } catch (e) {
      print('WebSocket health check failed: $e');
      return false;
    } finally {
      await channel?.sink.close();
    }
  }

  // ---------------------------------------------------------------------------
  // Authentication
  // ---------------------------------------------------------------------------

  /// Login e salva token per test successivi
  Future<String> authenticate({
    String email = 'utente.free@mediacenter.it',
    String password = 'Free2024!',
  }) async {
    final response = await http
        .post(
          Uri.parse('$apiBaseUrl/api/v1/auth/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'email': email, 'password': password}),
        )
        .timeout(apiTimeout);

    if (response.statusCode != 200) {
      throw Exception('Authentication failed: ${response.body}');
    }

    final data = jsonDecode(response.body);
    _currentToken = data['access_token'];
    _currentUserId = data['user']['id'];

    return _currentToken!;
  }

  /// Logout e pulisci token
  Future<void> logout() async {
    if (_currentToken != null) {
      try {
        await http.post(
          Uri.parse('$apiBaseUrl/api/v1/auth/logout'),
          headers: {'Authorization': 'Bearer $_currentToken'},
        );
      } catch (e) {
        // Ignora errori logout
      }
    }
    _currentToken = null;
    _currentUserId = null;
  }

  /// Reset completo stato
  void reset() {
    _currentToken = null;
    _currentUserId = null;
    _backendVerified = false;
  }

  // ---------------------------------------------------------------------------
  // Data Helpers
  // ---------------------------------------------------------------------------

  /// Crea video di test e ritorna ID
  Future<String> createTestVideo({
    String title = 'Test Video',
    String? discipline,
  }) async {
    if (_currentToken == null) {
      throw Exception('Must authenticate first');
    }

    final response = await http
        .post(
          Uri.parse('$apiBaseUrl/api/v1/videos'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $_currentToken',
          },
          body: jsonEncode({
            'title': title,
            'discipline': discipline ?? 'kung_fu',
            'duration_seconds': 300,
            'is_premium': false,
          }),
        )
        .timeout(apiTimeout);

    if (response.statusCode != 201) {
      throw Exception('Failed to create test video: ${response.body}');
    }

    final data = jsonDecode(response.body);
    return data['id'] as String;
  }

  /// Elimina video di test
  Future<void> deleteTestVideo(String videoId) async {
    if (_currentToken == null) return;

    try {
      await http.delete(
        Uri.parse('$apiBaseUrl/api/v1/videos/$videoId'),
        headers: {'Authorization': 'Bearer $_currentToken'},
      );
    } catch (e) {
      // Ignora errori cleanup
    }
  }

  // ---------------------------------------------------------------------------
  // Performance Baseline
  // ---------------------------------------------------------------------------

  /// Misura latenza media endpoint
  Future<int> measureEndpointLatency(
    String endpoint, {
    int samples = 5,
  }) async {
    final times = <int>[];

    for (int i = 0; i < samples; i++) {
      final stopwatch = Stopwatch()..start();

      await http
          .get(
            Uri.parse('$apiBaseUrl$endpoint'),
            headers: _currentToken != null
                ? {'Authorization': 'Bearer $_currentToken'}
                : null,
          )
          .timeout(apiTimeout);

      stopwatch.stop();
      times.add(stopwatch.elapsedMilliseconds);
    }

    // Ritorna media
    return (times.reduce((a, b) => a + b) / samples).round();
  }
}

/// Alias per accesso rapido
final backendHelper = BackendHelper.instance;

/// Setup function per test groups
Future<void> setUpBackendTests() async {
  await backendHelper.verifyBackendHealth();
}

/// Teardown function per test groups
Future<void> tearDownBackendTests() async {
  await backendHelper.logout();
  backendHelper.reset();
}

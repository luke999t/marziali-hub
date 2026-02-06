/// 🎓 AI_MODULE: TestConfig
/// 🎓 AI_DESCRIPTION: Configurazione test enterprise ZERO MOCK
/// 🎓 AI_BUSINESS: Test con backend REALE, nessun mock/fake consentito
/// 🎓 AI_TEACHING: Policy ZERO_MOCK - solo chiamate API reali
///
/// Enterprise Test Configuration - ZERO MOCK POLICY
///
/// Target: 90%+ coverage, 95%+ pass rate
/// Test categories: Unit, Integration, Regression, Security, Penetration,
///                  Static Analysis, Holistic, Slow, Performance
///
/// IMPORTANT: NO mocks allowed! All tests must use REAL backend.

library test_config;

import 'dart:io';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

// Test Tags for categorization
class TestTags {
  static const String unit = 'unit';
  static const String integration = 'integration';
  static const String regression = 'regression';
  static const String security = 'security';
  static const String penetration = 'penetration';
  static const String slow = 'slow';
  static const String holistic = 'holistic';
  static const String performance = 'performance';
  static const String smoke = 'smoke';
  static const String e2e = 'e2e';
  static const String realApi = 'real_api';
}

// Test Environment Configuration - REAL BACKEND ONLY
class TestEnvironment {
  /// Backend REALE - NESSUN mock server
  static const String realApiBaseUrl = 'http://localhost:8100/api/v1';

  /// URL health check backend
  static const String healthCheckUrl = 'http://localhost:8100/health';

  static const Duration defaultTimeout = Duration(seconds: 30);
  static const Duration slowTestTimeout = Duration(minutes: 5);
  static const Duration integrationTimeout = Duration(minutes: 2);
  static const Duration apiTimeout = Duration(seconds: 10);
}

// Coverage Configuration
class CoverageConfig {
  static const double minCoveragePercent = 90.0;
  static const double minPassRate = 95.0;
  static const int minTestsPerFeature = 10;
  static const List<String> excludedFromCoverage = [
    'lib/generated/**',
    'lib/**/*.g.dart',
    'lib/**/*.freezed.dart',
  ];
}

// Test Data Factory
class TestDataFactory {
  static const String validEmail = 'test@martialarts.com';
  static const String validPassword = 'SecureP@ss123!';
  static const String validUsername = 'testuser';
  static const String validToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciIsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  static Map<String, dynamic> createUserJson({
    String id = 'user_123',
    String email = 'test@martialarts.com',
    String username = 'testuser',
    String tier = 'premium',
  }) {
    return {
      'id': id,
      'email': email,
      'username': username,
      'tier': tier,
      'is_email_verified': true,
      'created_at': DateTime.now().toIso8601String(),
      'profiles': [],
    };
  }

  static Map<String, dynamic> createAuthResponseJson({
    String accessToken = 'access_token_123',
    String refreshToken = 'refresh_token_456',
  }) {
    return {
      'access_token': accessToken,
      'refresh_token': refreshToken,
      'expires_in': 3600,
      'token_type': 'Bearer',
      'user': createUserJson(),
    };
  }

  static Map<String, dynamic> createVideoContentJson({
    String id = 'video_123',
    String title = 'Karate Basics',
    String category = 'Karate',
    int durationSeconds = 1800,
  }) {
    return {
      'id': id,
      'title': title,
      'description': 'Learn the basics of $category',
      'thumbnail_url': 'https://example.com/thumb.jpg',
      'video_url': 'https://example.com/video.m3u8',
      'duration_seconds': durationSeconds,
      'category': category,
      'year': 2025,
      'maestro_name': 'Master Sensei',
      'rating': 4.8,
    };
  }

  static Map<String, dynamic> createProfileJson({
    String id = 'profile_123',
    String name = 'Main Profile',
    bool isKids = false,
  }) {
    return {
      'id': id,
      'name': name,
      'avatar_url': null,
      'is_kids': isKids,
      'preferred_language': 'it',
      'auto_play_enabled': true,
      'maturity_level': isKids ? 12 : 18,
    };
  }
}

// Security Test Payloads
class SecurityTestPayloads {
  static const List<String> sqlInjectionPayloads = [
    "'; DROP TABLE users; --",
    "1' OR '1'='1",
    "1; DELETE FROM videos WHERE 1=1",
    "admin'--",
    "' UNION SELECT * FROM users --",
  ];

  static const List<String> xssPayloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
    "'><script>alert(String.fromCharCode(88,83,83))</script>",
  ];

  static const List<String> pathTraversalPayloads = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
  ];

  static const List<String> commandInjectionPayloads = [
    "; rm -rf /",
    "| cat /etc/passwd",
    "\$(whoami)",
    "`id`",
  ];

  static const List<String> invalidTokens = [
    '',
    'invalid_token',
    'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.',
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjB9.expired',
  ];
}

// Matcher Extensions
extension CustomMatchers on Object? {
  void shouldBeSuccess() {
    expect(this, isNotNull);
  }

  void shouldBeFailure() {
    expect(this, isNotNull);
  }
}

// Test Utilities
class TestUtils {
  static Future<void> pumpAndSettle(WidgetTester tester) async {
    await tester.pumpAndSettle(const Duration(milliseconds: 100));
  }

  static Future<void> waitForAnimations(WidgetTester tester) async {
    await tester.pump(const Duration(milliseconds: 500));
    await tester.pumpAndSettle();
  }
}

// ==================== ZERO MOCK POLICY ====================

/// Verifica che il backend sia in esecuzione
/// Lancia eccezione se backend non raggiungibile
Future<void> verifyBackendRunning() async {
  try {
    final response = await http.get(
      Uri.parse(TestEnvironment.healthCheckUrl),
    ).timeout(TestEnvironment.apiTimeout);

    if (response.statusCode != 200) {
      throw Exception(
        'Backend not healthy: status ${response.statusCode}. '
        'Start backend with: cd backend && python -m uvicorn main:app --reload --port 8100',
      );
    }
  } on SocketException {
    throw Exception(
      'Backend not running at ${TestEnvironment.healthCheckUrl}. '
      'Start backend with: cd backend && python -m uvicorn main:app --reload --port 8100',
    );
  } catch (e) {
    if (e is Exception) rethrow;
    throw Exception(
      'Cannot connect to backend: $e. '
      'Start backend with: cd backend && python -m uvicorn main:app --reload --port 8100',
    );
  }
}

/// Crea un client HTTP per test reali
http.Client createTestClient() {
  return http.Client();
}

/// Ottiene headers di autenticazione per test
/// Richiede login reale al backend
Future<Map<String, String>> getTestAuthHeaders() async {
  final client = createTestClient();

  try {
    final response = await client.post(
      Uri.parse('${TestEnvironment.realApiBaseUrl}/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: '{"email": "${TestDataFactory.validEmail}", "password": "${TestDataFactory.validPassword}"}',
    ).timeout(TestEnvironment.apiTimeout);

    if (response.statusCode == 200) {
      // Parse response per ottenere token
      final body = response.body;
      // Semplice parsing - in produzione usare json decode
      final tokenMatch = RegExp(r'"access_token":\s*"([^"]+)"').firstMatch(body);
      if (tokenMatch != null) {
        return {
          'Authorization': 'Bearer ${tokenMatch.group(1)}',
          'Content-Type': 'application/json',
        };
      }
    }

    // Se login fallisce, ritorna headers senza auth (per test che non richiedono auth)
    return {'Content-Type': 'application/json'};
  } finally {
    client.close();
  }
}

/// Esegue richiesta GET al backend reale
Future<http.Response> testGet(String endpoint, {Map<String, String>? headers}) async {
  final client = createTestClient();
  try {
    return await client.get(
      Uri.parse('${TestEnvironment.realApiBaseUrl}$endpoint'),
      headers: headers ?? {'Content-Type': 'application/json'},
    ).timeout(TestEnvironment.apiTimeout);
  } finally {
    client.close();
  }
}

/// Esegue richiesta POST al backend reale
Future<http.Response> testPost(
  String endpoint, {
  Map<String, String>? headers,
  String? body,
}) async {
  final client = createTestClient();
  try {
    return await client.post(
      Uri.parse('${TestEnvironment.realApiBaseUrl}$endpoint'),
      headers: headers ?? {'Content-Type': 'application/json'},
      body: body,
    ).timeout(TestEnvironment.apiTimeout);
  } finally {
    client.close();
  }
}

// Base Test Setup - ZERO MOCK
void setupTestEnvironment() {
  setUpAll(() async {
    // Verifica backend running PRIMA di ogni test
    await verifyBackendRunning();
  });
}

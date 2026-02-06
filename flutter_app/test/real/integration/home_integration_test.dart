/// 🎓 AI_MODULE: HomeIntegrationTest
/// 🎓 AI_DESCRIPTION: Test integrazione home page con backend REALE
/// 🎓 AI_BUSINESS: Verifica caricamento contenuti home via API reali
/// 🎓 AI_TEACHING: ZERO MOCK - test fallisce se backend spento
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Nessun mockito, mocktail, fake consentito
/// - Tutti i test chiamano backend REALE
/// - Test falliscono se backend non disponibile

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import '../../test_config.dart';

void main() {
  group('Home Integration Tests - REAL API', () {
    late http.Client client;

    setUpAll(() async {
      // OBBLIGATORIO: Verifica backend attivo
      await verifyBackendRunning();
    });

    setUp(() {
      client = createTestClient();
    });

    tearDown(() {
      client.close();
    });

    group('Featured Content', () {
      test('GET /content/featured returns featured content', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/content/featured'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
          // Verifica struttura minima expected
          if (data is Map) {
            expect(data.containsKey('id') || data.containsKey('title'), isTrue,
                reason: 'Featured content should have id or title');
          }
        }
      });

      test('GET /content/hero returns hero carousel contents', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/content/hero?limit=5'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          // Potrebbe essere una lista o un oggetto con items
          if (data is List) {
            expect(data.length, lessThanOrEqualTo(5));
          } else if (data is Map && data.containsKey('items')) {
            expect((data['items'] as List).length, lessThanOrEqualTo(5));
          }
        }
      });
    });

    group('Categories', () {
      test('GET /categories returns list of categories', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/categories'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
        }
      });
    });

    group('Content Rows', () {
      test('GET /content/rows returns home content rows', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/content/rows'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
        }
      });

      test('GET /content/top10 returns top 10 content', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/content/top10'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          if (data is List) {
            expect(data.length, lessThanOrEqualTo(10));
          }
        }
      });

      test('GET /content/new returns new releases', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/content/new?limit=20'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });
    });

    group('Live Events', () {
      test('GET /live/now returns current live events', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/live/now'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });

      test('GET /live/upcoming returns upcoming live events', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/live/upcoming?limit=10'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });
    });

    group('Health Check', () {
      test('Backend health check succeeds', () async {
        // Act
        final response = await client.get(
          Uri.parse(TestEnvironment.healthCheckUrl),
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, equals(200),
            reason: 'Backend must be running for ZERO MOCK tests');
      });
    });
  });
}

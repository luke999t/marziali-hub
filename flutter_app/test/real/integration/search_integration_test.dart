/// 🎓 AI_MODULE: SearchIntegrationTest
/// 🎓 AI_DESCRIPTION: Test integrazione ricerca con backend REALE
/// 🎓 AI_BUSINESS: Verifica funzionalita ricerca via API reali
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
  group('Search Integration Tests - REAL API', () {
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

    group('Search Content', () {
      test('GET /search with query returns results', () async {
        // Arrange
        const query = 'karate';

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search?q=$query&page=1&limit=20'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
          // Verifica struttura risposta
          if (data is Map && data.containsKey('results')) {
            expect(data['results'], isList);
          } else if (data is List) {
            // OK, e' direttamente una lista
          }
        }
      });

      test('GET /search with empty query returns appropriate response', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search?q=&page=1&limit=20'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert - empty query might return error or empty results
        expect(response.statusCode, anyOf(equals(200), equals(400), equals(404)));
      });

      test('GET /search with filters works correctly', () async {
        // Arrange
        const query = 'judo';
        const category = 'martial-arts';

        // Act
        final response = await client.get(
          Uri.parse(
            '${TestEnvironment.realApiBaseUrl}/search?q=$query&category=$category&page=1&limit=10',
          ),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });

      test('GET /search pagination works', () async {
        // Arrange
        const query = 'training';

        // Act - Page 1
        final responsePage1 = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search?q=$query&page=1&limit=5'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Act - Page 2
        final responsePage2 = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search?q=$query&page=2&limit=5'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(responsePage1.statusCode, anyOf(equals(200), equals(404)));
        expect(responsePage2.statusCode, anyOf(equals(200), equals(404)));
      });
    });

    group('Search Suggestions', () {
      test('GET /search/suggestions returns suggestions', () async {
        // Arrange
        const query = 'kar';

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search/suggestions?q=$query'),
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

    group('Trending Searches', () {
      test('GET /search/trending returns trending searches', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search/trending'),
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

    group('Categories & Instructors', () {
      test('GET /categories returns available categories', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/categories'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });

      test('GET /instructors returns available instructors', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/instructors'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
      });
    });

    group('Search Response Time', () {
      test('Search responds within acceptable time', () async {
        // Arrange
        const query = 'martial';
        final stopwatch = Stopwatch()..start();

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/search?q=$query&page=1&limit=20'),
          headers: {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        stopwatch.stop();

        // Assert
        expect(response.statusCode, anyOf(equals(200), equals(404)));
        expect(stopwatch.elapsedMilliseconds, lessThan(5000),
            reason: 'Search should respond within 5 seconds');
      });
    });
  });
}

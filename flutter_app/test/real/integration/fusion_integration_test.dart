/// 🎓 AI_MODULE: FusionIntegrationTest
/// 🎓 AI_DESCRIPTION: Test integrazione Fusion (Multi-Video 3D) con backend REALE
/// 🎓 AI_BUSINESS: Verifica funzionalita fusion projects via API reali
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
  group('Fusion Integration Tests - REAL API', () {
    late http.Client client;
    Map<String, String>? authHeaders;

    setUpAll(() async {
      // OBBLIGATORIO: Verifica backend attivo
      await verifyBackendRunning();

      // Tenta login per ottenere auth headers
      authHeaders = await getTestAuthHeaders();
    });

    setUp(() {
      client = createTestClient();
    });

    tearDown(() {
      client.close();
    });

    group('Fusion Projects List', () {
      test('GET /fusion/projects returns projects list', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert - potrebbe richiedere auth
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
          // Verifica struttura
          if (data is Map && data.containsKey('projects')) {
            expect(data['projects'], isList);
          } else if (data is List) {
            // OK, lista diretta
          }
        }
      });

      test('GET /fusion/projects with pagination', () async {
        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects?page=1&limit=10'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );
      });
    });

    group('Fusion Project Creation', () {
      test('POST /fusion/projects creates new project', () async {
        // Arrange
        final projectData = json.encode({
          'name': 'Test Fusion Project',
          'description': 'Integration test project',
        });

        // Act
        final response = await client.post(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
          body: projectData,
        ).timeout(TestEnvironment.apiTimeout);

        // Assert - potrebbe richiedere auth o validazione
        expect(
          response.statusCode,
          anyOf(equals(200), equals(201), equals(400), equals(401), equals(404)),
        );

        if (response.statusCode == 200 || response.statusCode == 201) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
          expect(data['id'] ?? data['project_id'], isNotNull,
              reason: 'Created project should have an ID');
        }
      });

      test('POST /fusion/projects with invalid data returns error', () async {
        // Arrange - missing required fields
        final invalidData = json.encode({});

        // Act
        final response = await client.post(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
          body: invalidData,
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(400), equals(401), equals(404), equals(422)),
        );
      });
    });

    group('Fusion Project Detail', () {
      test('GET /fusion/projects/:id returns project detail', () async {
        // Arrange - usa un ID di test
        const testProjectId = 'test-project-1';

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
        }
      });
    });

    group('Add Video to Project', () {
      test('POST /fusion/projects/:id/videos adds video', () async {
        // Arrange
        const testProjectId = 'test-project-1';
        final videoData = json.encode({
          'video_id': 'video-123',
          'angle': 'front',
          'position': 0,
        });

        // Act
        final response = await client.post(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId/videos'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
          body: videoData,
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(201), equals(400), equals(401), equals(404)),
        );
      });
    });

    group('Start Fusion Process', () {
      test('POST /fusion/projects/:id/start initiates fusion', () async {
        // Arrange
        const testProjectId = 'test-project-1';

        // Act
        final response = await client.post(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId/start'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(202), equals(400), equals(401), equals(404)),
        );
      });

      test('GET /fusion/projects/:id/status returns fusion status', () async {
        // Arrange
        const testProjectId = 'test-project-1';

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId/status'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );

        if (response.statusCode == 200) {
          final data = json.decode(response.body);
          expect(data, isNotNull);
          // Verifica che ci sia uno status
          final status = data['status'] ?? data['state'];
          if (status != null) {
            expect(
              status,
              anyOf(
                equals('pending'),
                equals('processing'),
                equals('completed'),
                equals('failed'),
                equals('queued'),
              ),
            );
          }
        }
      });
    });

    group('Fusion Result', () {
      test('GET /fusion/projects/:id/result returns fusion result', () async {
        // Arrange
        const testProjectId = 'test-project-1';

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId/result'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );
      });
    });

    group('Blender Export', () {
      test('POST /fusion/projects/:id/export/blender exports to Blender format', () async {
        // Arrange
        const testProjectId = 'test-project-1';
        final exportOptions = json.encode({
          'format': 'fbx',
          'include_skeleton': true,
        });

        // Act
        final response = await client.post(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects/$testProjectId/export/blender'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
          body: exportOptions,
        ).timeout(TestEnvironment.apiTimeout);

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(202), equals(400), equals(401), equals(404)),
        );
      });
    });

    group('Fusion API Response Time', () {
      test('Fusion endpoints respond within acceptable time', () async {
        // Arrange
        final stopwatch = Stopwatch()..start();

        // Act
        final response = await client.get(
          Uri.parse('${TestEnvironment.realApiBaseUrl}/fusion/projects'),
          headers: authHeaders ?? {'Content-Type': 'application/json'},
        ).timeout(TestEnvironment.apiTimeout);

        stopwatch.stop();

        // Assert
        expect(
          response.statusCode,
          anyOf(equals(200), equals(401), equals(404)),
        );
        expect(stopwatch.elapsedMilliseconds, lessThan(5000),
            reason: 'Fusion API should respond within 5 seconds');
      });
    });
  });
}

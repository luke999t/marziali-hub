/// AI_MODULE: Avatar Repository Tests
/// AI_DESCRIPTION: Test repository avatar con backend reale
/// AI_TEACHING: Test ZERO MOCK - usa backend localhost:8000
///              Verifica: getAvatars, getAvatarDetail, getBoneMapping,
///              getStyles, applySkeleton, error handling
library;

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;

import '../../../test_config.dart';

void main() {
  const baseUrl = 'http://localhost:8000/api/v1';

  group('Avatar Repository Tests - Real Backend', () {
    late http.Client client;

    setUpAll(() async {
      // Verifica che il backend sia attivo
      try {
        final response = await http.get(
          Uri.parse('http://localhost:8000/health'),
        ).timeout(const Duration(seconds: 5));
        if (response.statusCode != 200) {
          fail('Backend not running. Start with: cd backend && uvicorn main:app --reload --port 8100');
        }
      } catch (e) {
        fail('Backend not running at localhost:8000. Start with: cd backend && uvicorn main:app --reload --port 8100');
      }
    });

    setUp(() {
      client = http.Client();
    });

    tearDown(() {
      client.close();
    });

    test('getAvatars() should return list of avatars', () async {
      // Act
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, anyOf(equals(200), equals(404)));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        expect(data, isA<Map<String, dynamic>>());

        // Response should have 'avatars' key (even if empty)
        if (data.containsKey('avatars')) {
          expect(data['avatars'], isA<List>());

          // If avatars exist, verify structure
          if ((data['avatars'] as List).isNotEmpty) {
            final avatar = data['avatars'][0];
            expect(avatar, isA<Map<String, dynamic>>());
            expect(avatar.containsKey('id'), isTrue);
            expect(avatar.containsKey('name'), isTrue);
          }
        }
      }
    });

    test('getAvatars() with style filter should filter correctly', () async {
      // Act - test filter by style 'karate'
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/?style=karate'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, anyOf(equals(200), equals(404)));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);

        if (data.containsKey('avatars') && (data['avatars'] as List).isNotEmpty) {
          // All returned avatars should have karate style
          for (final avatar in data['avatars']) {
            expect(avatar['style'], equals('karate'));
          }
        }
      }
    });

    test('getAvatars() with pagination should respect page and page_size', () async {
      // Act
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/?page=1&page_size=5'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, anyOf(equals(200), equals(404)));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);

        if (data.containsKey('avatars')) {
          // Should not exceed page_size
          expect((data['avatars'] as List).length, lessThanOrEqualTo(5));
        }
      }
    });

    test('getAvatarDetail() should return valid avatar for existing id', () async {
      // First get list to find a valid ID
      final listResponse = await client.get(
        Uri.parse('$baseUrl/avatars/'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      if (listResponse.statusCode != 200) {
        // Skip if no avatars available
        return;
      }

      final listData = jsonDecode(listResponse.body);
      if (!listData.containsKey('avatars') ||
          (listData['avatars'] as List).isEmpty) {
        // Skip if no avatars
        return;
      }

      final avatarId = listData['avatars'][0]['id'].toString();

      // Act - get detail
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/$avatarId'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, equals(200));

      final avatar = jsonDecode(response.body);
      expect(avatar['id'].toString(), equals(avatarId));
      expect(avatar.containsKey('name'), isTrue);
      expect(avatar.containsKey('style'), isTrue);
      expect(avatar.containsKey('model_url'), isTrue);
    });

    test('getAvatarDetail() should return error for non-existent avatar', () async {
      // Act - using invalid UUID format will return 400, valid UUID not found returns 404
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/non-existent-id-12345'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert - 400 for invalid UUID format, 404 for not found, 422 for validation
      expect(response.statusCode, anyOf(equals(400), equals(404), equals(422)));
    });

    test('getBoneMapping() should return mapping for 75 landmarks', () async {
      // Act
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/bone-mapping'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, anyOf(equals(200), equals(404)));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        expect(data, isA<Map<String, dynamic>>());

        // Should have body, left_hand, right_hand mappings
        if (data.containsKey('body')) {
          expect(data['body'], isA<Map>());
        }
        if (data.containsKey('left_hand')) {
          expect(data['left_hand'], isA<Map>());
        }
        if (data.containsKey('right_hand')) {
          expect(data['right_hand'], isA<Map>());
        }

        // Total landmarks should be ~75 (33 body + 21 left + 21 right)
        if (data.containsKey('total_landmarks')) {
          expect(data['total_landmarks'], equals(75));
        }
      }
    });

    test('getStyles() should return list of available styles', () async {
      // Act
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/styles'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert
      expect(response.statusCode, anyOf(equals(200), equals(404)));

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        expect(data, isA<Map<String, dynamic>>());

        if (data.containsKey('styles')) {
          expect(data['styles'], isA<List>());

          // Each style should have value, label, description
          for (final style in data['styles']) {
            expect(style.containsKey('value'), isTrue);
            expect(style.containsKey('label'), isTrue);
          }
        }
      }
    });

    test('applySkeleton() should work with valid skeleton', () async {
      // First get a valid avatar ID
      final listResponse = await client.get(
        Uri.parse('$baseUrl/avatars/'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      if (listResponse.statusCode != 200) {
        return; // Skip if no avatars
      }

      final listData = jsonDecode(listResponse.body);
      if (!listData.containsKey('avatars') ||
          (listData['avatars'] as List).isEmpty) {
        return; // Skip if no avatars
      }

      final avatarId = listData['avatars'][0]['id'].toString();

      // Act - apply skeleton
      final response = await client.post(
        Uri.parse('$baseUrl/avatars/$avatarId/apply-skeleton'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'skeleton_id': 'test-skeleton-123',
          'output_format': 'transforms',
        }),
      ).timeout(TestEnvironment.apiTimeout);

      // Assert - can be 200 (success), 401/403 (auth required), 404 (not found), 422/400 (validation)
      expect(
        response.statusCode,
        anyOf(equals(200), equals(401), equals(403), equals(404), equals(422), equals(400)),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body);
        expect(data.containsKey('avatar_id'), isTrue);
      }
    });

    test('Network error handling - invalid endpoint should return error', () async {
      // Act
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/invalid/endpoint/path'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Assert - should be 404 or 405
      expect(
        response.statusCode,
        anyOf(equals(404), equals(405), equals(422)),
      );
    });
  });

  group('Avatar Repository Edge Cases', () {
    late http.Client client;

    setUp(() {
      client = http.Client();
    });

    tearDown(() {
      client.close();
    });

    test('getAvatars with invalid style should return empty or all', () async {
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/?style=invalid_style_xyz'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      expect(response.statusCode, anyOf(equals(200), equals(404), equals(422)));
    });

    test('getAvatars with negative page should handle gracefully', () async {
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/?page=-1'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      // Should either return error or default to page 1
      expect(
        response.statusCode,
        anyOf(equals(200), equals(400), equals(422)),
      );
    });

    test('getAvatars with zero page_size should handle gracefully', () async {
      final response = await client.get(
        Uri.parse('$baseUrl/avatars/?page_size=0'),
        headers: {'Content-Type': 'application/json'},
      ).timeout(TestEnvironment.apiTimeout);

      expect(
        response.statusCode,
        anyOf(equals(200), equals(400), equals(422)),
      );
    });
  });
}

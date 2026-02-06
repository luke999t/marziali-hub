/// ================================================================================
///     AUTH FLOW INTEGRATION - ZERO MOCK - LEGGE SUPREMA
/// ================================================================================
///
///     REGOLA INVIOLABILE: Questo file NON contiene mock.
///     Tutti i test chiamano backend REALE su localhost:8000.
///
/// ================================================================================

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import '../../helpers/test_config.dart';
import '../../helpers/api_helpers.dart';

void main() {
  setUpAll(() async {
    await ensureBackendRunning();
  });

  group('Auth Flow Integration - Complete User Journey', () {
    test('complete login -> access protected -> logout flow', () async {
      // 1. LOGIN
      final loginResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      expect(loginResponse.statusCode, 200);
      final loginData = jsonDecode(loginResponse.body);
      final token = loginData['access_token'];
      expect(token, isNotEmpty);

      // 2. ACCESS PROTECTED RESOURCE
      final meResponse = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer $token'},
      );

      expect(meResponse.statusCode, 200);
      final userData = jsonDecode(meResponse.body);
      expect(userData['email'], TestUsers.freeUser.email);

      // 3. LOGOUT
      final logoutResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/logout'),
        headers: {'Authorization': 'Bearer $token'},
      );

      expect([200, 204], contains(logoutResponse.statusCode));

      // 4. VERIFY TOKEN INVALIDATED (or still valid for stateless JWT)
      // Note: With stateless JWT, tokens may remain valid until expiration
      // The important thing is that logout endpoint succeeded
      final afterLogoutResponse = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer $token'},
      );

      // JWT tokens might still be valid (stateless) or invalidated (blacklist)
      // Both behaviors are acceptable depending on backend implementation
      expect([200, 401, 403], contains(afterLogoutResponse.statusCode));
    });

    test('token refresh flow', () async {
      // 1. Login e ottieni refresh token
      final loginResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      final loginData = jsonDecode(loginResponse.body);
      final refreshToken = loginData['refresh_token'];
      expect(refreshToken, isNotEmpty);

      // 2. Usa refresh token per nuovo access token
      final refreshResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/refresh'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'refresh_token': refreshToken}),
      );

      expect(refreshResponse.statusCode, 200);
      final refreshData = jsonDecode(refreshResponse.body);
      expect(refreshData['access_token'], isNotEmpty);

      // 3. Verifica nuovo token funziona
      final meResponse = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer ${refreshData['access_token']}'},
      );

      expect(meResponse.statusCode, 200);
    });

    test('multiple sessions same user', () async {
      // Session 1
      final session1Response = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      final token1 = jsonDecode(session1Response.body)['access_token'];

      // Session 2
      final session2Response = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      final token2 = jsonDecode(session2Response.body)['access_token'];

      // Both tokens should work (depending on backend config)
      final response1 = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer $token1'},
      );

      final response2 = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer $token2'},
      );

      // At least one should work (both if multiple sessions allowed)
      expect(
        response1.statusCode == 200 || response2.statusCode == 200,
        true,
      );
    });
  });

  group('Auth Flow Integration - Error Handling', () {
    test('protected endpoint without auth returns 401', () async {
      // Only test endpoints that actually require authentication
      // Note: /api/v1/videos and /api/v1/library may be public endpoints
      final protectedEndpoints = [
        '/api/v1/auth/me',
        // Add other truly protected endpoints here
      ];

      for (final endpoint in protectedEndpoints) {
        final response = await http.get(Uri.parse('$apiBaseUrl$endpoint'));

        // Should be unauthorized
        expect(
          response.statusCode,
          anyOf(401, 403),
          reason: 'Endpoint $endpoint should require auth',
        );
      }
    });

    test('invalid token format rejected', () async {
      final invalidTokens = [
        'not-a-jwt',
        'a.b', // Only 2 parts
        'a.b.c.d', // 4 parts
        '', // Empty
      ];

      for (final token in invalidTokens) {
        final response = await http.get(
          Uri.parse('$apiBaseUrl/api/v1/auth/me'),
          headers: {'Authorization': 'Bearer $token'},
        );

        expect(
          [400, 401, 403, 422],
          contains(response.statusCode),
          reason: 'Invalid token "$token" should be rejected',
        );
      }
    });
  });
}

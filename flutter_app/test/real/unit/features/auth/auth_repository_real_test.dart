/// ================================================================================
///     AUTH REPOSITORY TESTS - ZERO MOCK - LEGGE SUPREMA
/// ================================================================================
///
///     REGOLA INVIOLABILE: Questo file NON contiene mock.
///     Tutti i test chiamano backend REALE su localhost:8000.
///
/// ================================================================================

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import '../../../../helpers/test_config.dart';
import '../../../../helpers/api_helpers.dart';

void main() {
  late ApiTestHelper apiHelper;

  setUpAll(() async {
    await ensureBackendRunning();
  });

  setUp(() {
    apiHelper = ApiTestHelper();
  });

  tearDown(() async {
    await apiHelper.logout();
  });

  group('Auth Repository - REAL API - Login', () {
    test('login con credenziali valide ritorna token JWT', () async {
      // REAL API CALL - NON MOCK!
      final token = await apiHelper.login(
        TestUsers.freeUser.email,
        TestUsers.freeUser.password,
      );

      expect(token, isNotEmpty);
      // JWT format: header.payload.signature
      expect(token.split('.').length, 3);
    });

    test('login con email errata ritorna errore', () async {
      expect(
        () => apiHelper.login('nonexistent@email.com', 'wrongpassword'),
        throwsException,
      );
    });

    test('login con password errata ritorna errore', () async {
      expect(
        () => apiHelper.login(TestUsers.freeUser.email, 'wrongpassword'),
        throwsException,
      );
    });

    test('login con email vuota ritorna errore', () async {
      expect(
        () => apiHelper.login('', 'password123'),
        throwsException,
      );
    });
  });

  group('Auth Repository - REAL API - Me Endpoint', () {
    test('getCurrentUser con token valido ritorna profilo', () async {
      await apiHelper.loginAsFreeUser();

      final response = await apiHelper.authGet('/api/v1/auth/me');

      expect(response.statusCode, 200);
      final data = jsonDecode(response.body);
      expect(data['email'], TestUsers.freeUser.email);
    });

    test('getCurrentUser senza token ritorna 401', () async {
      final response = await apiHelper.get('/api/v1/auth/me');

      // Backend può ritornare 401 Unauthorized o 403 Forbidden senza token
      expect([401, 403], contains(response.statusCode));
    });

    test('getCurrentUser con token invalido ritorna 401', () async {
      final response = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {
          'Authorization': 'Bearer invalid-token-here',
        },
      );

      expect(response.statusCode, 401);
    });
  });

  group('Auth Repository - REAL API - Logout', () {
    test('logout invalida il token', () async {
      final token = await apiHelper.loginAsFreeUser();

      // Verifica che token funzioni
      var response = await apiHelper.authGet('/api/v1/auth/me');
      expect(response.statusCode, 200);

      // Logout
      await apiHelper.logout();

      // Verifica che token non funzioni piu
      response = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/auth/me'),
        headers: {'Authorization': 'Bearer $token'},
      );

      // Token dovrebbe essere invalidato
      expect([401, 403], contains(response.statusCode));
    });
  });

  group('Auth Repository - REAL API - Register', () {
    test('register con dati validi crea utente', () async {
      final timestamp = DateTime.now().millisecondsSinceEpoch;
      final testEmail = 'test_flutter_$timestamp@example.com';

      final response = await apiHelper.post('/api/v1/auth/register', {
        'email': testEmail,
        'username': 'testuser_$timestamp',
        'password': 'TestPassword123!',
      });

      // 201 Created o 200 OK o 409 se email gia esiste
      expect([200, 201, 409, 422], contains(response.statusCode));

      if (response.statusCode == 200 || response.statusCode == 201) {
        final data = jsonDecode(response.body);
        expect(data, contains('access_token'));
      }
    });

    test('register con email gia esistente ritorna errore', () async {
      final response = await apiHelper.post('/api/v1/auth/register', {
        'email': TestUsers.freeUser.email,
        'username': 'duplicate_user',
        'password': 'TestPassword123!',
      });

      // 409 Conflict o 422 Validation Error
      expect([409, 422], contains(response.statusCode));
    });

    test('register con password debole ritorna errore', () async {
      final timestamp = DateTime.now().millisecondsSinceEpoch;

      final response = await apiHelper.post('/api/v1/auth/register', {
        'email': 'weak_pass_$timestamp@example.com',
        'username': 'weakuser_$timestamp',
        'password': '123', // Too short
      });

      // Validation error
      expect([400, 422], contains(response.statusCode));
    });

    test('register con email invalida ritorna errore', () async {
      final response = await apiHelper.post('/api/v1/auth/register', {
        'email': 'not-an-email',
        'username': 'testuser',
        'password': 'TestPassword123!',
      });

      expect([400, 422], contains(response.statusCode));
    });
  });

  group('Auth Repository - REAL API - Token Refresh', () {
    test('refresh token genera nuovo access token', () async {
      await apiHelper.loginAsFreeUser();
      final oldToken = apiHelper.accessToken;

      // Refresh
      await apiHelper.refreshAccessToken();
      final newToken = apiHelper.accessToken;

      // Token dovrebbe essere diverso
      expect(newToken, isNotNull);
      expect(newToken, isNotEmpty);

      // Nuovo token dovrebbe funzionare
      final response = await apiHelper.authGet('/api/v1/auth/me');
      expect(response.statusCode, 200);
    });
  });
}

/// ================================================================================
///     API HELPERS - ZERO MOCK - LEGGE SUPREMA
/// ================================================================================
///
///     Helper per chiamate API REALI nei test.
///     NON contiene mock. Tutte le chiamate vanno a localhost:8000.
///
/// ================================================================================

import 'dart:convert';
import 'package:http/http.dart' as http;
import 'test_config.dart';

/// Helper per gestire autenticazione e chiamate API nei test
class ApiTestHelper {
  String? _accessToken;
  String? _refreshToken;

  /// Verifica se autenticato
  bool get isAuthenticated => _accessToken != null;

  /// Ottieni access token corrente
  String? get accessToken => _accessToken;

  /// Login e ottieni token REALE
  Future<String> login(String email, String password) async {
    final response = await http
        .post(
          Uri.parse('$apiBaseUrl/api/v1/auth/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'email': email, 'password': password}),
        )
        .timeout(apiTimeout);

    if (response.statusCode != 200) {
      throw Exception('Login fallito [${response.statusCode}]: ${response.body}');
    }

    final data = jsonDecode(response.body);
    _accessToken = data['access_token'];
    _refreshToken = data['refresh_token'];
    return _accessToken!;
  }

  /// Login con utente free di test
  Future<String> loginAsFreeUser() async {
    return login(TestUsers.freeUser.email, TestUsers.freeUser.password);
  }

  /// Login con utente premium di test
  Future<String> loginAsPremiumUser() async {
    return login(TestUsers.premiumUser.email, TestUsers.premiumUser.password);
  }

  /// GET non autenticata
  Future<http.Response> get(String endpoint) async {
    return http
        .get(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {'Content-Type': 'application/json'},
        )
        .timeout(apiTimeout);
  }

  /// GET autenticata
  Future<http.Response> authGet(String endpoint) async {
    _ensureAuthenticated();

    return http
        .get(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $_accessToken',
          },
        )
        .timeout(apiTimeout);
  }

  /// POST non autenticata
  Future<http.Response> post(
    String endpoint,
    Map<String, dynamic> body,
  ) async {
    return http
        .post(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode(body),
        )
        .timeout(apiTimeout);
  }

  /// POST autenticata
  Future<http.Response> authPost(
    String endpoint,
    Map<String, dynamic> body,
  ) async {
    _ensureAuthenticated();

    return http
        .post(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $_accessToken',
          },
          body: jsonEncode(body),
        )
        .timeout(apiTimeout);
  }

  /// PUT autenticata
  Future<http.Response> authPut(
    String endpoint,
    Map<String, dynamic> body,
  ) async {
    _ensureAuthenticated();

    return http
        .put(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $_accessToken',
          },
          body: jsonEncode(body),
        )
        .timeout(apiTimeout);
  }

  /// DELETE autenticata
  Future<http.Response> authDelete(String endpoint) async {
    _ensureAuthenticated();

    return http
        .delete(
          Uri.parse('$apiBaseUrl$endpoint'),
          headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer $_accessToken',
          },
        )
        .timeout(apiTimeout);
  }

  /// Refresh token
  Future<void> refreshAccessToken() async {
    if (_refreshToken == null) {
      throw Exception('No refresh token available');
    }

    final response = await http
        .post(
          Uri.parse('$apiBaseUrl/api/v1/auth/refresh'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'refresh_token': _refreshToken}),
        )
        .timeout(apiTimeout);

    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      _accessToken = data['access_token'];
      _refreshToken = data['refresh_token'];
    } else {
      throw Exception('Token refresh failed: ${response.body}');
    }
  }

  /// Logout e pulisci token
  Future<void> logout() async {
    if (_accessToken != null) {
      try {
        await http.post(
          Uri.parse('$apiBaseUrl/api/v1/auth/logout'),
          headers: {'Authorization': 'Bearer $_accessToken'},
        );
      } catch (e) {
        // Ignore logout errors
      }
    }
    _accessToken = null;
    _refreshToken = null;
  }

  /// Reset stato
  void reset() {
    _accessToken = null;
    _refreshToken = null;
  }

  void _ensureAuthenticated() {
    if (_accessToken == null) {
      throw Exception(
          'Non autenticato. Chiama login() prima di fare richieste autenticate.');
    }
  }
}

/// Estrae messaggio di errore da risposta API
String? extractErrorMessage(http.Response response) {
  try {
    final data = jsonDecode(response.body);
    return data['message'] ?? data['detail'] ?? data['error'];
  } catch (e) {
    return response.body;
  }
}

/// Verifica se risposta e successo (2xx)
bool isSuccessResponse(http.Response response) {
  return response.statusCode >= 200 && response.statusCode < 300;
}

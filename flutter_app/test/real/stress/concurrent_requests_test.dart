/// ================================================================================
///     STRESS TESTS - CONCURRENT REQUESTS
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

void main() {
  setUpAll(() async {
    await ensureBackendRunning();
  });

  group('Concurrent Requests Stress', () {
    test('10 concurrent health checks succeed', () async {
      final futures = List.generate(
          10, (_) => http.get(Uri.parse('$apiBaseUrl/health')));

      final responses = await Future.wait(futures);

      var successCount = 0;
      for (final response in responses) {
        if (response.statusCode == 200) successCount++;
      }

      expect(successCount, 10);
      print('10/10 concurrent health checks succeeded');
    });

    test('5 concurrent logins succeed', () async {
      final futures = List.generate(
        5,
        (_) => http.post(
          Uri.parse('$apiBaseUrl/api/v1/auth/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'email': TestUsers.freeUser.email,
            'password': TestUsers.freeUser.password,
          }),
        ),
      );

      final responses = await Future.wait(futures);

      var successCount = 0;
      for (final response in responses) {
        if (response.statusCode == 200) successCount++;
      }

      expect(successCount, greaterThanOrEqualTo(3));
      print('$successCount/5 concurrent logins succeeded');
    });

    test('20 concurrent pause-ad requests succeed', () async {
      // First login to get auth token
      final loginResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );
      final token = jsonDecode(loginResponse.body)['access_token'];

      // Generate UUIDs for video IDs
      final futures = List.generate(
        20,
        (i) => http.get(
          Uri.parse('$apiBaseUrl/api/v1/ads/pause-ad?video_id=00000000-0000-0000-0000-00000000000${i % 10}'),
          headers: {'Authorization': 'Bearer $token'},
        ),
      );

      final responses = await Future.wait(futures);

      var successCount = 0;
      for (final response in responses) {
        if (response.statusCode == 200) successCount++;
      }

      expect(successCount, greaterThanOrEqualTo(15));
      print('$successCount/20 concurrent pause-ad requests succeeded');
    });

    test('50 sequential requests in <15 seconds', () async {
      final stopwatch = Stopwatch()..start();

      for (var i = 0; i < 50; i++) {
        await http.get(Uri.parse('$apiBaseUrl/health'));
      }

      stopwatch.stop();

      expect(stopwatch.elapsedMilliseconds, lessThan(15000));
      print('50 sequential requests: ${stopwatch.elapsedMilliseconds}ms');
    });

    test('mixed concurrent operations', () async {
      // First login to get auth token
      final loginResponse = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );
      final token = jsonDecode(loginResponse.body)['access_token'];

      final futures = <Future<http.Response>>[];

      // Mix di operazioni diverse (con autenticazione per ads)
      for (var i = 0; i < 5; i++) {
        futures.add(http.get(Uri.parse('$apiBaseUrl/health')));
        futures.add(http.get(
          Uri.parse('$apiBaseUrl/api/v1/ads/pause-ad?video_id=00000000-0000-0000-0000-00000000000$i'),
          headers: {'Authorization': 'Bearer $token'},
        ));
      }

      final responses = await Future.wait(futures);

      var successCount = 0;
      for (final response in responses) {
        if (response.statusCode == 200) successCount++;
      }

      expect(successCount, greaterThanOrEqualTo(8));
      print('$successCount/10 mixed concurrent operations succeeded');
    });
  });

  group('Burst Traffic Simulation', () {
    test('burst of 10 requests followed by pause', () async {
      final results = <int>[];

      // Burst 1
      var burst1Futures = List.generate(
          10, (_) => http.get(Uri.parse('$apiBaseUrl/health')));
      var responses = await Future.wait(burst1Futures);
      results.addAll(responses.map((r) => r.statusCode));

      // Pause
      await Future.delayed(const Duration(milliseconds: 500));

      // Burst 2
      var burst2Futures = List.generate(
          10, (_) => http.get(Uri.parse('$apiBaseUrl/health')));
      responses = await Future.wait(burst2Futures);
      results.addAll(responses.map((r) => r.statusCode));

      final successCount = results.where((code) => code == 200).length;
      expect(successCount, greaterThanOrEqualTo(15));
      print('$successCount/20 burst requests succeeded');
    });

    test('sustained load over 5 seconds', () async {
      final stopwatch = Stopwatch()..start();
      var requestCount = 0;
      var successCount = 0;

      // Run for 5 seconds
      while (stopwatch.elapsedMilliseconds < 5000) {
        final response = await http.get(Uri.parse('$apiBaseUrl/health'));
        requestCount++;
        if (response.statusCode == 200) successCount++;
      }

      stopwatch.stop();

      final rps = requestCount / 5;
      print('Sustained load: $requestCount requests in 5s (${rps.toStringAsFixed(1)} req/s)');
      print('Success rate: ${(successCount / requestCount * 100).toStringAsFixed(1)}%');

      expect(successCount / requestCount, greaterThan(0.9));
    });
  });
}

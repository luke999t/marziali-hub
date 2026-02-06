/// ================================================================================
///     PERFORMANCE TESTS - API RESPONSE TIME
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

  group('API Response Time', () {
    test('health endpoint responds in <100ms', () async {
      final stopwatch = Stopwatch()..start();

      await http.get(Uri.parse('$apiBaseUrl/health'));

      stopwatch.stop();

      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(PerformanceThresholds.healthEndpointMs),
      );
      print('Health endpoint: ${stopwatch.elapsedMilliseconds}ms');
    });

    test('login responds in <500ms', () async {
      final stopwatch = Stopwatch()..start();

      await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      stopwatch.stop();

      expect(
        stopwatch.elapsedMilliseconds,
        lessThan(PerformanceThresholds.loginEndpointMs),
      );
      print('Login endpoint: ${stopwatch.elapsedMilliseconds}ms');
    });

    test('pause-ad responds in <500ms', () async {
      final stopwatch = Stopwatch()..start();

      await http.get(Uri.parse(
          '$apiBaseUrl/api/v1/ads/pause-ad?user_tier=free&video_id=test'));

      stopwatch.stop();

      expect(stopwatch.elapsedMilliseconds, lessThan(500));
      print('Pause-ad endpoint: ${stopwatch.elapsedMilliseconds}ms');
    });

    test('average response time over 10 requests is acceptable', () async {
      final times = <int>[];

      for (var i = 0; i < 10; i++) {
        final stopwatch = Stopwatch()..start();
        await http.get(Uri.parse('$apiBaseUrl/health'));
        stopwatch.stop();
        times.add(stopwatch.elapsedMilliseconds);
      }

      final average = times.reduce((a, b) => a + b) / times.length;
      final max = times.reduce((a, b) => a > b ? a : b);
      final min = times.reduce((a, b) => a < b ? a : b);

      print('Response times - Avg: ${average.toStringAsFixed(1)}ms, '
          'Min: ${min}ms, Max: ${max}ms');

      expect(average, lessThan(200));
    });
  });

  group('Response Time Under Load', () {
    test('response time stable under light load', () async {
      final baselineTimes = <int>[];
      final loadTimes = <int>[];

      // Baseline: single requests
      for (var i = 0; i < 5; i++) {
        final stopwatch = Stopwatch()..start();
        await http.get(Uri.parse('$apiBaseUrl/health'));
        stopwatch.stop();
        baselineTimes.add(stopwatch.elapsedMilliseconds);
      }

      // Under load: parallel requests
      final futures = List.generate(5, (i) async {
        final stopwatch = Stopwatch()..start();
        await http.get(Uri.parse('$apiBaseUrl/health'));
        stopwatch.stop();
        return stopwatch.elapsedMilliseconds;
      });

      loadTimes.addAll(await Future.wait(futures));

      final baselineAvg = baselineTimes.reduce((a, b) => a + b) / 5;
      final loadAvg = loadTimes.reduce((a, b) => a + b) / 5;

      print('Baseline avg: ${baselineAvg.toStringAsFixed(1)}ms');
      print('Under load avg: ${loadAvg.toStringAsFixed(1)}ms');

      // Load time should not be more than 3x baseline
      expect(loadAvg, lessThan(baselineAvg * 3 + 100));
    });
  });

  group('Payload Size Performance', () {
    test('small payload response is fast', () async {
      final stopwatch = Stopwatch()..start();

      await http.get(Uri.parse('$apiBaseUrl/health'));

      stopwatch.stop();
      expect(stopwatch.elapsedMilliseconds, lessThan(100));
    });

    test('login with full response is acceptable', () async {
      final stopwatch = Stopwatch()..start();

      final response = await http.post(
        Uri.parse('$apiBaseUrl/api/v1/auth/login'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'email': TestUsers.freeUser.email,
          'password': TestUsers.freeUser.password,
        }),
      );

      stopwatch.stop();

      // Check response size
      final responseSize = response.bodyBytes.length;
      print('Login response size: $responseSize bytes');
      print('Login response time: ${stopwatch.elapsedMilliseconds}ms');

      expect(stopwatch.elapsedMilliseconds, lessThan(1000));
    });
  });
}

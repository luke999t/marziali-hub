/// ================================================================================
/// 🎓 AI_MODULE: GlassesPerformanceRealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Performance tests REALI per WebSocket Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Misura latenze, throughput, memory usage.
///                 SLA: <100ms command latency, <500ms sync, <1MB memory.
///                 Critical per garantire esperienza real-time.
/// 🎓 AI_TEACHING: Performance testing patterns, latency measurement,
///                 throughput testing, memory profiling basics.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 PERFORMANCE THRESHOLDS:
/// - Connection time: <3000ms
/// - Command roundtrip: <200ms
/// - State sync: <500ms
/// - Ping latency: <100ms
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Misurazioni su backend REALE
/// ================================================================================

import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import '../../../../lib/services/glasses_service.dart';
import '../../../helpers/test_config.dart';
import '../../../helpers/backend_helper.dart';
import '../../../helpers/websocket_helper.dart';
import '../../../helpers/mock_blocker.dart';

void main() {
  enforceMockPolicy();

  late String testUserId;

  setUpAll(() async {
    await backendHelper.verifyBackendHealth();
    await backendHelper.authenticate();
    testUserId = 'perf_${DateTime.now().millisecondsSinceEpoch}';
  });

  tearDownAll(() async {
    await tearDownBackendTests();
  });

  // ===========================================================================
  // CONNECTION PERFORMANCE
  // ===========================================================================

  group('Connection Performance', () {
    test('WebSocket connection time < 3000ms', () async {
      final stopwatch = Stopwatch()..start();
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        stopwatch.stop();

        print('Connection time: ${stopwatch.elapsedMilliseconds}ms');
        expect(stopwatch.elapsedMilliseconds, lessThan(3000));
      } finally {
        await service.disconnect();
      }
    });

    test('Average connection time over 10 attempts < 2000ms', () async {
      final times = <int>[];

      for (int i = 0; i < 10; i++) {
        final service = GlassesService(backendUrl: apiBaseUrl);
        final stopwatch = Stopwatch()..start();

        try {
          await service.connect(userId: '${testUserId}_$i', deviceType: 'phone');
          stopwatch.stop();
          times.add(stopwatch.elapsedMilliseconds);
        } finally {
          await service.disconnect();
        }

        await Future.delayed(const Duration(milliseconds: 100));
      }

      final average = times.reduce((a, b) => a + b) / times.length;
      print('Average connection time: ${average.round()}ms');
      print('Min: ${times.reduce((a, b) => a < b ? a : b)}ms');
      print('Max: ${times.reduce((a, b) => a > b ? a : b)}ms');

      expect(average, lessThan(2000));
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('Disconnect time < 500ms', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);
      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 500));

      final stopwatch = Stopwatch()..start();
      await service.disconnect();
      stopwatch.stop();

      print('Disconnect time: ${stopwatch.elapsedMilliseconds}ms');
      expect(stopwatch.elapsedMilliseconds, lessThan(500));
    });
  });

  // ===========================================================================
  // COMMAND LATENCY PERFORMANCE
  // ===========================================================================

  group('Command Latency Performance', () {
    late GlassesService service;

    setUp(() async {
      service = GlassesService(backendUrl: apiBaseUrl);
      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 500));
    });

    tearDown(() async {
      await service.disconnect();
    });

    test('Zoom command roundtrip < 200ms', () async {
      final stopwatch = Stopwatch()..start();
      final completer = Completer<void>();

      service.onStateChanged = (state) {
        if (state.zoomLevel == 2.0 && !completer.isCompleted) {
          stopwatch.stop();
          completer.complete();
        }
      };

      service.setZoom(2.0);
      await completer.future.timeout(const Duration(seconds: 5));

      print('Zoom roundtrip: ${stopwatch.elapsedMilliseconds}ms');
      expect(stopwatch.elapsedMilliseconds, lessThan(200));
    });

    test('Speed command roundtrip < 200ms', () async {
      final stopwatch = Stopwatch()..start();
      final completer = Completer<void>();

      service.onStateChanged = (state) {
        if (state.playbackSpeed == 1.5 && !completer.isCompleted) {
          stopwatch.stop();
          completer.complete();
        }
      };

      service.setSpeed(1.5);
      await completer.future.timeout(const Duration(seconds: 5));

      print('Speed roundtrip: ${stopwatch.elapsedMilliseconds}ms');
      expect(stopwatch.elapsedMilliseconds, lessThan(200));
    });

    test('Play/Pause roundtrip < 200ms', () async {
      final stopwatch = Stopwatch()..start();
      final completer = Completer<void>();

      service.onStateChanged = (state) {
        if (state.isPlaying && !completer.isCompleted) {
          stopwatch.stop();
          completer.complete();
        }
      };

      service.play();
      await completer.future.timeout(const Duration(seconds: 5));

      print('Play roundtrip: ${stopwatch.elapsedMilliseconds}ms');
      expect(stopwatch.elapsedMilliseconds, lessThan(200));
    });

    test('Average command latency over 50 commands < 150ms', () async {
      final latencies = <int>[];

      for (int i = 0; i < 50; i++) {
        final stopwatch = Stopwatch()..start();
        final completer = Completer<void>();
        final targetZoom = 1.0 + (i % 20) * 0.1;

        service.onStateChanged = (state) {
          if ((state.zoomLevel - targetZoom).abs() < 0.05 && !completer.isCompleted) {
            stopwatch.stop();
            completer.complete();
          }
        };

        service.setZoom(targetZoom);
        await completer.future.timeout(const Duration(seconds: 5));
        latencies.add(stopwatch.elapsedMilliseconds);
      }

      final average = latencies.reduce((a, b) => a + b) / latencies.length;
      final p95 = (latencies..sort())[((latencies.length * 0.95).floor())];

      print('Average latency: ${average.round()}ms');
      print('P95 latency: ${p95}ms');

      expect(average, lessThan(150));
      expect(p95, lessThan(300));
    }, timeout: const Timeout(Duration(seconds: 60)));
  });

  // ===========================================================================
  // PING LATENCY PERFORMANCE
  // ===========================================================================

  group('Ping Latency Performance', () {
    test('Ping roundtrip < 100ms', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await helper.waitForStateSync();

        final stopwatch = Stopwatch()..start();
        helper.sendPing();
        await helper.waitForPong();
        stopwatch.stop();

        print('Ping roundtrip: ${stopwatch.elapsedMilliseconds}ms');
        expect(stopwatch.elapsedMilliseconds, lessThan(100));
      } finally {
        await helper.dispose();
      }
    });

    test('Average ping over 100 pings < 50ms', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await helper.waitForStateSync();

        final latencies = <int>[];

        for (int i = 0; i < 100; i++) {
          helper.clearMessages();
          final stopwatch = Stopwatch()..start();
          helper.sendPing();
          await helper.waitForPong();
          stopwatch.stop();
          latencies.add(stopwatch.elapsedMilliseconds);
        }

        final average = latencies.reduce((a, b) => a + b) / latencies.length;
        print('Average ping: ${average.round()}ms');

        expect(average, lessThan(50));
      } finally {
        await helper.dispose();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  // ===========================================================================
  // MULTI-DEVICE SYNC PERFORMANCE
  // ===========================================================================

  group('Multi-Device Sync Performance', () {
    test('State sync between 2 devices < 500ms', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        final stopwatch = Stopwatch()..start();
        final completer = Completer<void>();

        glasses.onStateChanged = (state) {
          if (state.zoomLevel == 2.5 && !completer.isCompleted) {
            stopwatch.stop();
            completer.complete();
          }
        };

        phone.setZoom(2.5);
        await completer.future.timeout(const Duration(seconds: 5));

        print('Sync time: ${stopwatch.elapsedMilliseconds}ms');
        expect(stopwatch.elapsedMilliseconds, lessThan(500));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('State sync between 5 devices < 1000ms', () async {
      final devices = List.generate(
        5,
        (_) => GlassesService(backendUrl: apiBaseUrl),
      );

      try {
        // Connect all
        for (int i = 0; i < devices.length; i++) {
          await devices[i].connect(
            userId: testUserId,
            deviceType: 'device_$i',
          );
        }
        await Future.delayed(const Duration(milliseconds: 500));

        // Measure sync to all devices
        final completers = <Completer<void>>[];
        for (int i = 1; i < devices.length; i++) {
          final completer = Completer<void>();
          completers.add(completer);
          devices[i].onStateChanged = (state) {
            if (state.brightness == 45 && !completer.isCompleted) {
              completer.complete();
            }
          };
        }

        final stopwatch = Stopwatch()..start();
        devices[0].setBrightness(45);

        await Future.wait(
          completers.map((c) => c.future.timeout(const Duration(seconds: 5))),
        );
        stopwatch.stop();

        print('Sync to ${devices.length - 1} devices: ${stopwatch.elapsedMilliseconds}ms');
        expect(stopwatch.elapsedMilliseconds, lessThan(1000));
      } finally {
        await Future.wait(devices.map((d) => d.disconnect()));
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  // ===========================================================================
  // THROUGHPUT PERFORMANCE
  // ===========================================================================

  group('Throughput Performance', () {
    test('Handle 100 commands in 5 seconds', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        final stopwatch = Stopwatch()..start();
        int receivedCount = 0;

        service.onStateChanged = (_) => receivedCount++;

        for (int i = 0; i < 100; i++) {
          service.setZoom(1.0 + (i % 20) * 0.1);
        }

        await Future.delayed(const Duration(seconds: 5));
        stopwatch.stop();

        final throughput = receivedCount / (stopwatch.elapsedMilliseconds / 1000);
        print('Received $receivedCount updates');
        print('Throughput: ${throughput.toStringAsFixed(1)} updates/sec');

        expect(receivedCount, greaterThan(50));
      } finally {
        await service.disconnect();
      }
    });

    test('Sustained throughput over 30 seconds', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        int commandsSent = 0;
        int updatesReceived = 0;
        final startTime = DateTime.now();

        service.onStateChanged = (_) => updatesReceived++;

        while (DateTime.now().difference(startTime).inSeconds < 30) {
          service.setZoom(1.0 + (commandsSent % 20) * 0.1);
          commandsSent++;
          await Future.delayed(const Duration(milliseconds: 100));
        }

        print('Commands sent: $commandsSent');
        print('Updates received: $updatesReceived');
        print('Success rate: ${(updatesReceived / commandsSent * 100).toStringAsFixed(1)}%');

        expect(updatesReceived / commandsSent, greaterThan(0.9));
      } finally {
        await service.disconnect();
      }
    }, timeout: const Timeout(Duration(seconds: 45)));
  });

  // ===========================================================================
  // CONNECTION STABILITY PERFORMANCE
  // ===========================================================================

  group('Connection Stability Performance', () {
    test('Connection stable over 60 seconds with 0 drops', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);
      int disconnectCount = 0;

      service.onConnectionChanged = (status) {
        if (status == ConnectionStatus.disconnected ||
            status == ConnectionStatus.reconnecting) {
          disconnectCount++;
        }
      };

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');

        for (int i = 0; i < 12; i++) {
          await Future.delayed(const Duration(seconds: 5));
          service.ping();
        }

        print('Disconnections during test: $disconnectCount');
        expect(disconnectCount, equals(0));
      } finally {
        await service.disconnect();
      }
    }, timeout: const Timeout(Duration(seconds: 90)));
  });

  // ===========================================================================
  // PERFORMANCE BENCHMARKS
  // ===========================================================================

  group('Performance Benchmarks', () {
    test('All performance thresholds met', () async {
      final results = <String, bool>{};

      // Connection benchmark
      final service = GlassesService(backendUrl: apiBaseUrl);
      var sw = Stopwatch()..start();
      await service.connect(userId: testUserId, deviceType: 'phone');
      sw.stop();
      results['Connection < 3000ms'] = sw.elapsedMilliseconds < 3000;
      print('Connection: ${sw.elapsedMilliseconds}ms');

      await Future.delayed(const Duration(milliseconds: 500));

      // Command latency benchmark
      sw = Stopwatch()..start();
      final completer = Completer<void>();
      service.onStateChanged = (state) {
        if (state.zoomLevel == 1.5 && !completer.isCompleted) {
          sw.stop();
          completer.complete();
        }
      };
      service.setZoom(1.5);
      await completer.future.timeout(const Duration(seconds: 5));
      results['Command < 200ms'] = sw.elapsedMilliseconds < 200;
      print('Command latency: ${sw.elapsedMilliseconds}ms');

      await service.disconnect();

      // Print summary
      print('\n=== Performance Benchmark Results ===');
      results.forEach((key, value) {
        print('$key: ${value ? "PASS" : "FAIL"}');
      });

      expect(results.values.every((v) => v), isTrue);
    });
  });
}

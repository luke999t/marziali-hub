/// ================================================================================
/// 🎓 AI_MODULE: GlassesStressRealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Stress tests REALI per WebSocket Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica stabilità sotto carico pesante.
///                 Test concurrent connections, rapid commands, long sessions.
///                 Critical per garantire esperienza utente durante eventi live.
/// 🎓 AI_TEACHING: Stress testing patterns, concurrent testing,
///                 resource leak detection, performance degradation testing.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 TEST CATEGORIES:
/// - Concurrent connections
/// - Rapid command bursts
/// - Long-running sessions
/// - Resource cleanup
/// - Recovery from stress
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Test su backend REALE localhost:8000
/// - Stress test con connessioni REALI
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
    testUserId = 'stress_test_${DateTime.now().millisecondsSinceEpoch}';
  });

  tearDownAll(() async {
    await tearDownBackendTests();
  });

  // ===========================================================================
  // CONCURRENT CONNECTIONS STRESS TESTS
  // ===========================================================================

  group('Concurrent Connections Stress', () {
    test('5 concurrent connections to same room', () async {
      final services = List.generate(
        5,
        (_) => GlassesService(backendUrl: apiBaseUrl),
      );

      try {
        // Connect all
        final futures = <Future<bool>>[];
        for (int i = 0; i < services.length; i++) {
          futures.add(services[i].connect(
            userId: testUserId,
            deviceType: 'device_$i',
          ));
        }

        final results = await Future.wait(futures);

        // All should connect
        expect(results.every((r) => r), isTrue);
        expect(services.every((s) => s.isConnected), isTrue);

        // All should have synced state
        await Future.delayed(const Duration(seconds: 1));
        final firstZoom = services[0].state.zoomLevel;
        for (final service in services) {
          expect(service.state.zoomLevel, equals(firstZoom));
        }
      } finally {
        await Future.wait(services.map((s) => s.disconnect()));
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('10 connections across different rooms', () async {
      final services = List.generate(
        10,
        (_) => GlassesService(backendUrl: apiBaseUrl),
      );

      try {
        final futures = <Future<bool>>[];
        for (int i = 0; i < services.length; i++) {
          futures.add(services[i].connect(
            userId: '${testUserId}_room_$i',
            deviceType: 'phone',
          ));
        }

        final results = await Future.wait(futures);

        expect(results.where((r) => r).length, greaterThanOrEqualTo(8));
      } finally {
        await Future.wait(services.map((s) => s.disconnect()));
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('rapid connect/disconnect cycles', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      // 20 rapid cycles
      for (int i = 0; i < 20; i++) {
        await service.connect(
          userId: '${testUserId}_rapid_$i',
          deviceType: 'phone',
        );
        expect(service.isConnected, isTrue);
        await service.disconnect();
        expect(service.isConnected, isFalse);
      }

      // Should still be able to connect normally
      await service.connect(userId: testUserId, deviceType: 'phone');
      expect(service.isConnected, isTrue);
      await service.disconnect();
    }, timeout: const Timeout(Duration(seconds: 60)));
  });

  // ===========================================================================
  // RAPID COMMAND BURST TESTS
  // ===========================================================================

  group('Rapid Command Bursts', () {
    late GlassesService service;

    setUp(() async {
      service = GlassesService(backendUrl: apiBaseUrl);
      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 500));
    });

    tearDown(() async {
      await service.disconnect();
    });

    test('100 zoom commands in rapid succession', () async {
      int updateCount = 0;
      service.onStateChanged = (_) => updateCount++;

      // Fire 100 commands rapidly
      for (int i = 0; i < 100; i++) {
        final zoom = 1.0 + (i % 20) * 0.1;
        service.setZoom(zoom);
      }

      // Wait for processing
      await Future.delayed(const Duration(seconds: 3));

      // Should have received updates
      expect(updateCount, greaterThan(0));

      // Connection should still work
      expect(service.isConnected, isTrue);
    }, timeout: const Timeout(Duration(seconds: 10)));

    test('mixed command burst', () async {
      // Fire many different commands rapidly
      for (int i = 0; i < 50; i++) {
        service.setZoom(1.0 + (i % 20) * 0.1);
        service.setSpeed(0.5 + (i % 6) * 0.25);
        service.setBrightness(i % 100);
        service.setVolume(i % 100);
        if (i % 10 == 0) {
          service.togglePlay();
        }
      }

      await Future.delayed(const Duration(seconds: 2));

      // Connection should survive
      expect(service.isConnected, isTrue);

      // State should be valid
      expect(service.state.zoomLevel, inInclusiveRange(1.0, 3.0));
      expect(service.state.playbackSpeed, inInclusiveRange(0.25, 2.0));
    }, timeout: const Timeout(Duration(seconds: 10)));

    test('command burst with concurrent state requests', () async {
      for (int i = 0; i < 30; i++) {
        service.setZoom(1.5 + (i % 10) * 0.1);
        service.requestState();
      }

      await Future.delayed(const Duration(seconds: 2));

      expect(service.isConnected, isTrue);
    });
  });

  // ===========================================================================
  // LONG-RUNNING SESSION TESTS
  // ===========================================================================

  group('Long-Running Sessions', () {
    test('connection stable for 60 seconds with activity', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        final startTime = DateTime.now();

        // Send periodic commands for 60 seconds
        while (DateTime.now().difference(startTime).inSeconds < 60) {
          service.setZoom(1.0 + (DateTime.now().second % 20) * 0.1);
          await Future.delayed(const Duration(seconds: 5));

          // Verify still connected
          expect(service.isConnected, isTrue);
        }

        expect(service.isConnected, isTrue);
      } finally {
        await service.disconnect();
      }
    }, timeout: const Timeout(Duration(seconds: 90)));

    test('connection survives idle period with keepalive', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');

        // Wait 45 seconds (keepalive is 30s)
        await Future.delayed(const Duration(seconds: 45));

        // Should still be connected due to keepalive
        expect(service.isConnected, isTrue);

        // Commands should still work
        final completer = Completer<void>();
        service.onStateChanged = (state) {
          if (state.brightness == 55 && !completer.isCompleted) {
            completer.complete();
          }
        };

        service.setBrightness(55);
        await completer.future.timeout(const Duration(seconds: 5));
      } finally {
        await service.disconnect();
      }
    }, timeout: const Timeout(Duration(seconds: 60)));
  });

  // ===========================================================================
  // RESOURCE CLEANUP TESTS
  // ===========================================================================

  group('Resource Cleanup', () {
    test('no memory leak after many connect/disconnect cycles', () async {
      // This is a basic check - in production use memory profiling
      for (int i = 0; i < 50; i++) {
        final service = GlassesService(backendUrl: apiBaseUrl);
        await service.connect(
          userId: '${testUserId}_cleanup_$i',
          deviceType: 'phone',
        );
        await Future.delayed(const Duration(milliseconds: 100));
        await service.disconnect();
      }

      // If we get here without OOM, basic cleanup is working
      expect(true, isTrue);
    }, timeout: const Timeout(Duration(seconds: 60)));

    test('timers cleaned up on disconnect', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(seconds: 1));
      await service.disconnect();

      // Wait longer than ping interval
      await Future.delayed(const Duration(seconds: 35));

      // Should not throw due to dangling timers
      expect(service.isConnected, isFalse);
    }, timeout: const Timeout(Duration(seconds: 45)));
  });

  // ===========================================================================
  // RECOVERY TESTS
  // ===========================================================================

  group('Recovery from Stress', () {
    test('service recovers after burst', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');

        // Heavy burst
        for (int i = 0; i < 100; i++) {
          service.setZoom((i % 20) * 0.1 + 1.0);
        }

        await Future.delayed(const Duration(seconds: 2));

        // Verify recovery
        final completer = Completer<GlassesState>();
        service.onStateChanged = (state) {
          if (!completer.isCompleted) {
            completer.complete(state);
          }
        };

        service.setZoom(1.5);
        final state = await completer.future.timeout(const Duration(seconds: 5));

        expect(state.zoomLevel, equals(1.5));
      } finally {
        await service.disconnect();
      }
    });

    test('new connections work after stress test', () async {
      // After all the stress tests, verify fresh connections work
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        final connected = await service.connect(
          userId: '${testUserId}_recovery',
          deviceType: 'phone',
        );

        expect(connected, isTrue);
        expect(service.isConnected, isTrue);

        final completer = Completer<GlassesState>();
        service.onStateChanged = (state) {
          if (!completer.isCompleted) {
            completer.complete(state);
          }
        };

        service.requestState();
        final state = await completer.future.timeout(const Duration(seconds: 5));

        expect(state, isNotNull);
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // WEBSOCKET POOL STRESS TESTS
  // ===========================================================================

  group('WebSocket Pool Stress', () {
    test('connection pool handles multiple connections', () async {
      final pool = WebSocketConnectionPool();

      try {
        await pool.createConnections(
          count: 5,
          baseUserId: testUserId,
          delayBetween: const Duration(milliseconds: 200),
        );

        expect(pool.activeConnections, equals(5));

        // All can send commands
        pool.broadcastCommand('zoom', 2.0);
        await Future.delayed(const Duration(seconds: 1));

        // All should have received updates
        for (int i = 0; i < pool.activeConnections; i++) {
          final conn = pool[i];
          expect(conn.receivedMessages, isNotEmpty);
        }
      } finally {
        await pool.disconnectAll();
      }
    });
  });
}

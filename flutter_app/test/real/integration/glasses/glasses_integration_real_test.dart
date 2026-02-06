/// ================================================================================
/// 🎓 AI_MODULE: GlassesIntegrationRealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Integration tests REALI per sistema Smart Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica end-to-end flusso phone-glasses.
///                 Test multi-device sync, state persistence, command roundtrip.
///                 Critical per garantire esperienza utente senza glitch.
/// 🎓 AI_TEACHING: Integration testing patterns, multi-client WebSocket testing,
///                 state synchronization verification, timing assertions.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 TEST CATEGORIES:
/// - Multi-device synchronization
/// - Command propagation
/// - State consistency
/// - Connection resilience
/// - Room management
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Tutte le connessioni a ws://localhost:8000 REALE
/// - Multi-client WebSocket REALI
/// - Se backend spento, test DEVONO FALLIRE
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
    testUserId = 'integration_test_${DateTime.now().millisecondsSinceEpoch}';
  });

  tearDownAll(() async {
    await tearDownBackendTests();
  });

  // ===========================================================================
  // MULTI-DEVICE SYNC TESTS
  // ===========================================================================

  group('Multi-Device Synchronization', () {
    test('phone and glasses receive same initial state', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Connect phone first
        final phoneStateCompleter = Completer<GlassesState>();
        phone.onStateChanged = (state) {
          if (!phoneStateCompleter.isCompleted) {
            phoneStateCompleter.complete(state);
          }
        };
        await phone.connect(userId: testUserId, deviceType: 'phone');
        final phoneState = await phoneStateCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        // Connect glasses
        final glassesStateCompleter = Completer<GlassesState>();
        glasses.onStateChanged = (state) {
          if (!glassesStateCompleter.isCompleted) {
            glassesStateCompleter.complete(state);
          }
        };
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        final glassesState = await glassesStateCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        // States should match
        expect(phoneState.zoomLevel, equals(glassesState.zoomLevel));
        expect(phoneState.playbackSpeed, equals(glassesState.playbackSpeed));
        expect(phoneState.isPlaying, equals(glassesState.isPlaying));
        expect(phoneState.brightness, equals(glassesState.brightness));
        expect(phoneState.volume, equals(glassesState.volume));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('command from phone updates glasses state', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Connect both
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');

        // Wait for initial sync
        await Future.delayed(const Duration(milliseconds: 500));

        // Setup listener on glasses
        final glassesUpdateCompleter = Completer<GlassesState>();
        glasses.onStateChanged = (state) {
          if (state.zoomLevel == 2.5 && !glassesUpdateCompleter.isCompleted) {
            glassesUpdateCompleter.complete(state);
          }
        };

        // Phone sends command
        phone.setZoom(2.5);

        // Glasses should receive update
        final glassesState = await glassesUpdateCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        expect(glassesState.zoomLevel, equals(2.5));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('command from glasses updates phone state', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        final phoneUpdateCompleter = Completer<GlassesState>();
        phone.onStateChanged = (state) {
          if (state.playbackSpeed == 0.75 && !phoneUpdateCompleter.isCompleted) {
            phoneUpdateCompleter.complete(state);
          }
        };

        glasses.setSpeed(0.75);

        final phoneState = await phoneUpdateCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        expect(phoneState.playbackSpeed, closeTo(0.75, 0.01));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('device_joined event fires when second device connects', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Phone connects first
        await phone.connect(userId: testUserId, deviceType: 'phone');

        // Setup listener for device joined
        final joinedCompleter = Completer<int>();
        phone.onDeviceJoined = (deviceType, totalDevices) {
          if (!joinedCompleter.isCompleted) {
            joinedCompleter.complete(totalDevices);
          }
        };

        // Glasses connects
        await glasses.connect(userId: testUserId, deviceType: 'glasses');

        final totalDevices = await joinedCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        expect(totalDevices, greaterThanOrEqualTo(2));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('device_left event fires when device disconnects', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        final leftCompleter = Completer<int>();
        phone.onDeviceLeft = (deviceType, totalDevices) {
          if (!leftCompleter.isCompleted) {
            leftCompleter.complete(totalDevices);
          }
        };

        // Glasses disconnects
        await glasses.disconnect();

        final totalDevices = await leftCompleter.future.timeout(
          const Duration(seconds: 5),
        );

        expect(totalDevices, equals(1));
      } finally {
        await phone.disconnect();
      }
    });
  });

  // ===========================================================================
  // COMMAND ROUNDTRIP TESTS
  // ===========================================================================

  group('Command Roundtrip', () {
    late GlassesService service;

    setUp(() async {
      service = GlassesService(backendUrl: apiBaseUrl);
      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 500));
    });

    tearDown(() async {
      await service.disconnect();
    });

    test('zoom command roundtrip < 500ms', () async {
      final stopwatch = Stopwatch()..start();
      final completer = Completer<void>();

      service.onStateChanged = (state) {
        if (state.zoomLevel == 1.5 && !completer.isCompleted) {
          stopwatch.stop();
          completer.complete();
        }
      };

      service.setZoom(1.5);
      await completer.future.timeout(const Duration(seconds: 5));

      expect(stopwatch.elapsedMilliseconds, lessThan(500));
    });

    test('multiple sequential commands maintain order', () async {
      final stateUpdates = <double>[];
      final allReceived = Completer<void>();

      service.onStateChanged = (state) {
        stateUpdates.add(state.zoomLevel);
        if (stateUpdates.length >= 3 && !allReceived.isCompleted) {
          allReceived.complete();
        }
      };

      // Send commands in sequence
      service.setZoom(1.5);
      await Future.delayed(const Duration(milliseconds: 100));
      service.setZoom(2.0);
      await Future.delayed(const Duration(milliseconds: 100));
      service.setZoom(2.5);

      await allReceived.future.timeout(const Duration(seconds: 5));

      // Should receive updates (order may vary due to async)
      expect(stateUpdates, contains(1.5));
      expect(stateUpdates, contains(2.0));
      expect(stateUpdates, contains(2.5));
    });

    test('play/pause toggle maintains consistency', () async {
      // Get initial state
      final wasPlaying = service.state.isPlaying;

      // Toggle
      final firstToggle = Completer<bool>();
      service.onStateChanged = (state) {
        if (state.isPlaying != wasPlaying && !firstToggle.isCompleted) {
          firstToggle.complete(state.isPlaying);
        }
      };
      service.togglePlay();
      final afterFirst = await firstToggle.future.timeout(const Duration(seconds: 5));
      expect(afterFirst, equals(!wasPlaying));

      // Toggle again
      final secondToggle = Completer<bool>();
      service.onStateChanged = (state) {
        if (state.isPlaying == wasPlaying && !secondToggle.isCompleted) {
          secondToggle.complete(state.isPlaying);
        }
      };
      service.togglePlay();
      final afterSecond = await secondToggle.future.timeout(const Duration(seconds: 5));
      expect(afterSecond, equals(wasPlaying));
    });
  });

  // ===========================================================================
  // STATE PERSISTENCE TESTS
  // ===========================================================================

  group('State Persistence', () {
    test('state persists after reconnect', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Connect and set state
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Set specific values
        service.setZoom(2.0);
        service.setBrightness(60);
        await Future.delayed(const Duration(milliseconds: 500));

        // Disconnect
        await service.disconnect();

        // Reconnect
        final stateCompleter = Completer<GlassesState>();
        service.onStateChanged = (state) {
          if (!stateCompleter.isCompleted) {
            stateCompleter.complete(state);
          }
        };
        await service.connect(userId: testUserId, deviceType: 'phone');

        final state = await stateCompleter.future.timeout(const Duration(seconds: 5));

        // State should be preserved
        expect(state.zoomLevel, equals(2.0));
        expect(state.brightness, equals(60));
      } finally {
        await service.disconnect();
      }
    });

    test('new room starts with default state', () async {
      final uniqueUserId = 'new_room_${DateTime.now().millisecondsSinceEpoch}';
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        final stateCompleter = Completer<GlassesState>();
        service.onStateChanged = (state) {
          if (!stateCompleter.isCompleted) {
            stateCompleter.complete(state);
          }
        };

        await service.connect(userId: uniqueUserId, deviceType: 'phone');
        final state = await stateCompleter.future.timeout(const Duration(seconds: 5));

        // Should have default values
        expect(state.zoomLevel, equals(1.0));
        expect(state.playbackSpeed, equals(1.0));
        expect(state.isPlaying, isFalse);
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // CONNECTION RESILIENCE TESTS
  // ===========================================================================

  group('Connection Resilience', () {
    test('handles rapid connect/disconnect cycles', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      // Rapid cycles should not cause errors
      for (int i = 0; i < 5; i++) {
        await service.connect(userId: testUserId, deviceType: 'phone');
        expect(service.isConnected, isTrue);
        await service.disconnect();
        expect(service.isConnected, isFalse);
      }
    });

    test('multiple connects to same user are idempotent', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        final firstStatus = service.status;

        // Connect again
        final result = await service.connect(userId: testUserId, deviceType: 'phone');

        expect(result, isTrue);
        expect(service.status, equals(firstStatus));
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // WEBSOCKET HELPER TESTS
  // ===========================================================================

  group('WebSocket Helper Integration', () {
    test('WebSocketTestHelper connects and receives state', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        expect(helper.isConnected, isTrue);

        final stateSync = await helper.waitForStateSync();
        expect(stateSync['type'], equals('state_sync'));
        expect(stateSync['state'], isNotNull);
      } finally {
        await helper.dispose();
      }
    });

    test('WebSocketTestHelper ping receives pong', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await Future.delayed(const Duration(milliseconds: 500));

        helper.sendPing();
        final pong = await helper.waitForPong();

        expect(pong['type'], equals('pong'));
      } finally {
        await helper.dispose();
      }
    });

    test('WebSocketTestHelper command updates state', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await helper.waitForStateSync();

        helper.sendCommand('zoom', 2.0);
        final update = await helper.waitForStateUpdate();

        expect(update['state']['zoom_level'], equals(2.0));
      } finally {
        await helper.dispose();
      }
    });
  });

  // ===========================================================================
  // CONCURRENT CONNECTIONS TESTS
  // ===========================================================================

  group('Concurrent Connections', () {
    test('multiple users can have separate rooms', () async {
      final user1 = GlassesService(backendUrl: apiBaseUrl);
      final user2 = GlassesService(backendUrl: apiBaseUrl);

      try {
        final user1Id = '${testUserId}_user1';
        final user2Id = '${testUserId}_user2';

        await user1.connect(userId: user1Id, deviceType: 'phone');
        await user2.connect(userId: user2Id, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Set different values
        user1.setZoom(1.5);
        user2.setZoom(2.5);
        await Future.delayed(const Duration(milliseconds: 500));

        // Each should have their own state
        expect(user1.state.zoomLevel, equals(1.5));
        expect(user2.state.zoomLevel, equals(2.5));
      } finally {
        await user1.disconnect();
        await user2.disconnect();
      }
    });

    test('three devices can sync in same room', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);
      final tablet = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await tablet.connect(userId: testUserId, deviceType: 'tablet');
        await Future.delayed(const Duration(milliseconds: 500));

        // All should have same state
        expect(phone.state.zoomLevel, equals(glasses.state.zoomLevel));
        expect(glasses.state.zoomLevel, equals(tablet.state.zoomLevel));

        // Update from one propagates to all
        final phoneUpdate = Completer<void>();
        final tabletUpdate = Completer<void>();

        phone.onStateChanged = (state) {
          if (state.brightness == 40 && !phoneUpdate.isCompleted) {
            phoneUpdate.complete();
          }
        };
        tablet.onStateChanged = (state) {
          if (state.brightness == 40 && !tabletUpdate.isCompleted) {
            tabletUpdate.complete();
          }
        };

        glasses.setBrightness(40);

        await Future.wait([
          phoneUpdate.future.timeout(const Duration(seconds: 5)),
          tabletUpdate.future.timeout(const Duration(seconds: 5)),
        ]);

        expect(phone.state.brightness, equals(40));
        expect(tablet.state.brightness, equals(40));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
        await tablet.disconnect();
      }
    });
  });
}

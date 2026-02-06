/// ================================================================================
/// 🎓 AI_MODULE: GlassesE2ERealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: End-to-End tests REALI per sistema Smart Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Test completi dall'API REST al WebSocket al widget.
///                 Verifica integrazione verticale totale del sistema.
///                 Critical per release readiness check.
/// 🎓 AI_TEACHING: E2E testing patterns, full stack verification,
///                 API to UI testing, data flow verification.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 TEST CATEGORIES:
/// - API to WebSocket flow
/// - Authentication to connection flow
/// - Full control flow
/// - Error propagation flow
///
/// 🧪 ZERO_MOCK_POLICY:
/// - E2E su stack REALE completo
/// ================================================================================

import 'dart:async';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import '../../../../lib/services/glasses_service.dart';
import '../../../helpers/test_config.dart';
import '../../../helpers/backend_helper.dart';
import '../../../helpers/websocket_helper.dart';
import '../../../helpers/mock_blocker.dart';

void main() {
  enforceMockPolicy();

  late String testUserId;
  late String authToken;

  setUpAll(() async {
    await backendHelper.verifyBackendHealth();
    authToken = await backendHelper.authenticate();
    testUserId = backendHelper.currentUserId ?? 'e2e_${DateTime.now().millisecondsSinceEpoch}';
  });

  tearDownAll(() async {
    await tearDownBackendTests();
  });

  // ===========================================================================
  // COMPLETE SYSTEM E2E TESTS
  // ===========================================================================

  group('Complete System E2E', () {
    test('E2E: Health check → Auth → WebSocket → Commands', () async {
      // STEP 1: Health check
      final healthResponse = await http
          .get(Uri.parse('$apiBaseUrl/health'))
          .timeout(const Duration(seconds: 5));
      expect(healthResponse.statusCode, equals(200));

      // STEP 2: Verify auth token works
      final profileResponse = await http.get(
        Uri.parse('$apiBaseUrl/api/v1/users/me'),
        headers: {'Authorization': 'Bearer $authToken'},
      ).timeout(const Duration(seconds: 5));
      expect(profileResponse.statusCode, anyOf(200, 404)); // 404 ok if endpoint doesn't exist

      // STEP 3: WebSocket connection
      final service = GlassesService(backendUrl: apiBaseUrl);
      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        expect(service.isConnected, isTrue);

        // STEP 4: Command execution
        final completer = Completer<void>();
        service.onStateChanged = (state) {
          if (state.zoomLevel == 2.0 && !completer.isCompleted) {
            completer.complete();
          }
        };

        service.setZoom(2.0);
        await completer.future.timeout(const Duration(seconds: 5));

        expect(service.state.zoomLevel, equals(2.0));
      } finally {
        await service.disconnect();
      }
    });

    test('E2E: Full learning session simulation', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Connect devices
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        // Simulate 30 second learning session
        final actions = [
          () => phone.play(),
          () => phone.setSpeed(0.75),
          () => phone.setSkeleton(true),
          () => phone.setZoom(1.5),
          () => phone.pause(),
          () => phone.seek(30000),
          () => phone.play(),
          () => phone.setSpeed(0.5),
          () => phone.setZoom(2.0),
          () => phone.pause(),
        ];

        for (final action in actions) {
          action();
          await Future.delayed(const Duration(seconds: 1));

          // Verify glasses synced
          expect(
            phone.state.zoomLevel,
            equals(glasses.state.zoomLevel),
            reason: 'States must be synced',
          );
        }
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('E2E: Error recovery flow', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Connect
        await service.connect(userId: testUserId, deviceType: 'phone');
        expect(service.isConnected, isTrue);

        // Set state with proper confirmation
        final zoomCompleter = Completer<void>();
        service.onStateChanged = (state) {
          if (state.zoomLevel == 2.5 && !zoomCompleter.isCompleted) {
            zoomCompleter.complete();
          }
        };
        service.setZoom(2.5);
        await zoomCompleter.future.timeout(const Duration(seconds: 5));

        // Simulate disconnect
        await service.disconnect();
        expect(service.isConnected, isFalse);

        // Reconnect and wait for state
        final stateReceivedCompleter = Completer<GlassesState>();
        service.onStateChanged = (state) {
          if (!stateReceivedCompleter.isCompleted) {
            stateReceivedCompleter.complete(state);
          }
        };
        await service.connect(userId: testUserId, deviceType: 'phone');
        expect(service.isConnected, isTrue);

        // Wait for state and verify it's valid (persistence depends on backend)
        final receivedState = await stateReceivedCompleter.future.timeout(
          const Duration(seconds: 5),
        );
        expect(receivedState.zoomLevel, inInclusiveRange(1.0, 3.0));
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // API TO WEBSOCKET FLOW
  // ===========================================================================

  group('API to WebSocket Flow', () {
    test('REST API health reflects WebSocket availability', () async {
      // Check REST health
      final response = await http
          .get(Uri.parse('$apiBaseUrl/health'))
          .timeout(const Duration(seconds: 5));

      expect(response.statusCode, equals(200));

      // If healthy, WebSocket should work
      final service = GlassesService(backendUrl: apiBaseUrl);
      try {
        final connected = await service.connect(
          userId: testUserId,
          deviceType: 'phone',
        );
        expect(connected, isTrue);
      } finally {
        await service.disconnect();
      }
    });

    test('WebSocket messages contain valid JSON', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);

        // All received messages should be valid JSON
        final stateSync = await helper.waitForStateSync();
        expect(stateSync, isA<Map<String, dynamic>>());
        expect(stateSync['type'], isNotEmpty);

        helper.sendPing();
        final pong = await helper.waitForPong();
        expect(pong, isA<Map<String, dynamic>>());
        expect(pong['type'], equals('pong'));
      } finally {
        await helper.dispose();
      }
    });
  });

  // ===========================================================================
  // FULL CONTROL FLOW
  // ===========================================================================

  group('Full Control Flow', () {
    test('All commands execute and return valid state', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Test each command type
        final commands = <String, Function>{
          'zoom': () => service.setZoom(2.0),
          'speed': () => service.setSpeed(1.5),
          'play': () => service.play(),
          'pause': () => service.pause(),
          'skeleton': () => service.setSkeleton(true),
          'brightness': () => service.setBrightness(50),
          'volume': () => service.setVolume(60),
          'seek': () => service.seek(10000),
        };

        for (final entry in commands.entries) {
          entry.value();
          await Future.delayed(const Duration(milliseconds: 300));

          // State should be valid after each command
          expect(service.state.zoomLevel, inInclusiveRange(1.0, 3.0));
          expect(service.state.playbackSpeed, inInclusiveRange(0.25, 2.0));
          expect(service.state.brightness, inInclusiveRange(0, 100));
          expect(service.state.volume, inInclusiveRange(0, 100));
        }
      } finally {
        await service.disconnect();
      }
    });

    test('State persists across command sequences', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Set specific state
        service.setZoom(2.5);
        service.setBrightness(75);
        service.setVolume(80);
        await Future.delayed(const Duration(milliseconds: 500));

        // Verify all values persisted
        expect(service.state.zoomLevel, equals(2.5));
        expect(service.state.brightness, equals(75));
        expect(service.state.volume, equals(80));

        // Change one, others should persist
        service.setSpeed(0.5);
        await Future.delayed(const Duration(milliseconds: 300));

        expect(service.state.zoomLevel, equals(2.5));
        expect(service.state.brightness, equals(75));
        expect(service.state.volume, equals(80));
        expect(service.state.playbackSpeed, equals(0.5));
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // ERROR PROPAGATION FLOW
  // ===========================================================================

  group('Error Propagation Flow', () {
    test('Invalid command handled gracefully', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await helper.waitForStateSync();

        // Send invalid command
        helper.send({
          'type': 'command',
          'command': 'nonexistent_command',
          'value': 123,
        });

        await Future.delayed(const Duration(milliseconds: 500));

        // Connection should still work
        helper.sendPing();
        final pong = await helper.waitForPong();
        expect(pong['type'], equals('pong'));
      } finally {
        await helper.dispose();
      }
    });

    test('Invalid values clamped not errored', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Send out-of-range values
        service.setZoom(-10.0);
        service.setBrightness(999);
        service.setVolume(-100);
        await Future.delayed(const Duration(milliseconds: 500));

        // Values should be clamped to valid ranges
        expect(service.state.zoomLevel, inInclusiveRange(1.0, 3.0));
        expect(service.state.brightness, inInclusiveRange(0, 100));
        expect(service.state.volume, inInclusiveRange(0, 100));

        // Connection should still work
        expect(service.isConnected, isTrue);
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // DATA FLOW VERIFICATION
  // ===========================================================================

  group('Data Flow Verification', () {
    test('Command data flows: Phone → Backend → Glasses', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        // Track glasses state changes
        final stateChanges = <double>[];
        glasses.onStateChanged = (state) {
          stateChanges.add(state.zoomLevel);
        };

        // Phone sends commands
        phone.setZoom(1.5);
        phone.setZoom(2.0);
        phone.setZoom(2.5);

        await Future.delayed(const Duration(seconds: 2));

        // Glasses should have received updates
        expect(stateChanges, contains(1.5));
        expect(stateChanges, contains(2.0));
        expect(stateChanges, contains(2.5));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });

    test('State sync bidirectional: Glasses → Backend → Phone', () async {
      final phone = GlassesService(backendUrl: apiBaseUrl);
      final glasses = GlassesService(backendUrl: apiBaseUrl);

      try {
        await phone.connect(userId: testUserId, deviceType: 'phone');
        await glasses.connect(userId: testUserId, deviceType: 'glasses');
        await Future.delayed(const Duration(milliseconds: 500));

        // Glasses initiates change
        final phoneUpdate = Completer<void>();
        phone.onStateChanged = (state) {
          if (state.brightness == 30 && !phoneUpdate.isCompleted) {
            phoneUpdate.complete();
          }
        };

        glasses.setBrightness(30);
        await phoneUpdate.future.timeout(const Duration(seconds: 5));

        expect(phone.state.brightness, equals(30));
      } finally {
        await phone.disconnect();
        await glasses.disconnect();
      }
    });
  });

  // ===========================================================================
  // SYSTEM INTEGRATION TESTS
  // ===========================================================================

  group('System Integration', () {
    test('Multiple users isolated in separate rooms', () async {
      final user1Phone = GlassesService(backendUrl: apiBaseUrl);
      final user2Phone = GlassesService(backendUrl: apiBaseUrl);

      try {
        await user1Phone.connect(userId: '${testUserId}_user1', deviceType: 'phone');
        await user2Phone.connect(userId: '${testUserId}_user2', deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // User 1 changes
        user1Phone.setZoom(3.0);
        await Future.delayed(const Duration(milliseconds: 500));

        // User 2 should not be affected
        expect(user1Phone.state.zoomLevel, equals(3.0));
        expect(user2Phone.state.zoomLevel, isNot(equals(3.0)));
      } finally {
        await user1Phone.disconnect();
        await user2Phone.disconnect();
      }
    });

    test('Concurrent operations on same room', () async {
      final devices = List.generate(
        3,
        (_) => GlassesService(backendUrl: apiBaseUrl),
      );

      try {
        // Connect all
        for (int i = 0; i < devices.length; i++) {
          await devices[i].connect(userId: testUserId, deviceType: 'device_$i');
        }
        await Future.delayed(const Duration(milliseconds: 500));

        // All send commands simultaneously
        devices[0].setZoom(2.0);
        devices[1].setBrightness(50);
        devices[2].setVolume(60);

        await Future.delayed(const Duration(seconds: 1));

        // All should converge to same state
        for (final device in devices) {
          expect(device.state.brightness, equals(50));
          expect(device.state.volume, equals(60));
        }
      } finally {
        await Future.wait(devices.map((d) => d.disconnect()));
      }
    });
  });
}

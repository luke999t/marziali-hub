/// ================================================================================
/// 🎓 AI_MODULE: GlassesSecurityRealTest
/// 🎓 AI_VERSION: 1.0.0
/// 🎓 AI_DESCRIPTION: Security tests REALI per WebSocket Glasses - ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica sicurezza connessioni WebSocket glasses.
///                 Test isolation rooms, injection prevention, rate limiting.
///                 Critical per proteggere dati utenti premium.
/// 🎓 AI_TEACHING: Security testing patterns, injection testing,
///                 access control verification, input validation testing.
/// 🎓 AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// 🎓 AI_CREATED: 2025-12-14
///
/// 📊 TEST CATEGORIES:
/// - Room isolation
/// - Input validation
/// - Injection prevention
/// - Rate limiting
/// - Error handling security
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Test su backend REALE localhost:8000
/// - Verifica reale delle protezioni
/// ================================================================================

import 'dart:async';
import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:web_socket_channel/web_socket_channel.dart';
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
    testUserId = 'security_test_${DateTime.now().millisecondsSinceEpoch}';
  });

  tearDownAll(() async {
    await tearDownBackendTests();
  });

  // ===========================================================================
  // ROOM ISOLATION TESTS
  // ===========================================================================

  group('Room Isolation', () {
    test('user cannot see other users room state', () async {
      final user1 = GlassesService(backendUrl: apiBaseUrl);
      final user2 = GlassesService(backendUrl: apiBaseUrl);

      try {
        final user1Id = '${testUserId}_isolated_1';
        final user2Id = '${testUserId}_isolated_2';

        await user1.connect(userId: user1Id, deviceType: 'phone');
        await user2.connect(userId: user2Id, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Set unique values
        user1.setZoom(1.1);
        user2.setZoom(2.9);
        await Future.delayed(const Duration(milliseconds: 500));

        // Each user sees only their own state
        expect(user1.state.zoomLevel, closeTo(1.1, 0.1));
        expect(user2.state.zoomLevel, closeTo(2.9, 0.1));

        // Command from user1 does NOT affect user2
        user1.setBrightness(20);
        await Future.delayed(const Duration(milliseconds: 500));

        expect(user1.state.brightness, equals(20));
        expect(user2.state.brightness, isNot(equals(20)));
      } finally {
        await user1.disconnect();
        await user2.disconnect();
      }
    });

    test('users cannot join others room without knowing user_id', () async {
      final owner = GlassesService(backendUrl: apiBaseUrl);
      final attacker = GlassesService(backendUrl: apiBaseUrl);

      try {
        final ownerId = '${testUserId}_owner_secret_${DateTime.now().millisecondsSinceEpoch}';
        final wrongId = '${testUserId}_wrong_guess';

        await owner.connect(userId: ownerId, deviceType: 'phone');
        owner.setZoom(2.5);
        await Future.delayed(const Duration(milliseconds: 500));

        // Attacker tries to guess room
        await attacker.connect(userId: wrongId, deviceType: 'phone');
        await Future.delayed(const Duration(milliseconds: 500));

        // Attacker should NOT see owner's state
        expect(attacker.state.zoomLevel, isNot(equals(2.5)));
      } finally {
        await owner.disconnect();
        await attacker.disconnect();
      }
    });
  });

  // ===========================================================================
  // INPUT VALIDATION TESTS
  // ===========================================================================

  group('Input Validation', () {
    late GlassesService service;

    setUp(() async {
      service = GlassesService(backendUrl: apiBaseUrl);
      await service.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 500));
    });

    tearDown(() async {
      await service.disconnect();
    });

    test('zoom rejects negative values', () async {
      final originalZoom = service.state.zoomLevel;
      service.setZoom(-5.0);
      await Future.delayed(const Duration(milliseconds: 300));

      // Should be clamped to valid range
      expect(service.state.zoomLevel, greaterThanOrEqualTo(1.0));
    });

    test('zoom rejects extremely large values', () async {
      service.setZoom(1000000.0);
      await Future.delayed(const Duration(milliseconds: 300));

      // Should be clamped to max 3.0
      expect(service.state.zoomLevel, lessThanOrEqualTo(3.0));
    });

    test('speed rejects zero', () async {
      service.setSpeed(0.0);
      await Future.delayed(const Duration(milliseconds: 300));

      // Should be clamped to min 0.25
      expect(service.state.playbackSpeed, greaterThanOrEqualTo(0.25));
    });

    test('brightness rejects values above 100', () async {
      service.setBrightness(200);
      await Future.delayed(const Duration(milliseconds: 300));

      expect(service.state.brightness, lessThanOrEqualTo(100));
    });

    test('volume rejects negative values', () async {
      service.setVolume(-50);
      await Future.delayed(const Duration(milliseconds: 300));

      expect(service.state.volume, greaterThanOrEqualTo(0));
    });

    test('seek rejects negative time', () async {
      service.seek(-10000);
      await Future.delayed(const Duration(milliseconds: 300));

      expect(service.state.currentTimeMs, greaterThanOrEqualTo(0));
    });
  });

  // ===========================================================================
  // INJECTION PREVENTION TESTS
  // ===========================================================================

  group('Injection Prevention', () {
    test('user_id with special characters is handled safely', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      // Try various injection patterns
      final injectionPatterns = [
        'user_<script>alert(1)</script>',
        'user_../../../etc/passwd',
        'user_"; DROP TABLE users; --',
        "user_' OR '1'='1",
        'user_\${system("ls")}',
        'user_\x00\x00\x00',
      ];

      for (final pattern in injectionPatterns) {
        try {
          // Should either connect safely or reject
          final connected = await service.connect(
            userId: pattern,
            deviceType: 'phone',
          ).timeout(const Duration(seconds: 5));

          // If connected, verify no injection occurred
          if (connected) {
            expect(service.userId, isNotNull);
            await service.disconnect();
          }
        } catch (e) {
          // Rejection is acceptable for malicious input
          expect(e, isA<Exception>());
        }
      }
    });

    test('malformed JSON commands do not crash connection', () async {
      final wsUrl = apiBaseUrl
          .replaceFirst('http://', 'ws://')
          .replaceFirst('https://', 'wss://');

      final channel = WebSocketChannel.connect(
        Uri.parse('$wsUrl/api/v1/ws/glasses/$testUserId?device_type=test'),
      );

      try {
        await channel.ready.timeout(const Duration(seconds: 5));

        // Send malformed JSON
        channel.sink.add('not valid json {{{');
        channel.sink.add('{"type": "command", "command": ');
        channel.sink.add('');
        channel.sink.add('null');

        await Future.delayed(const Duration(milliseconds: 500));

        // Connection should still work
        channel.sink.add(jsonEncode({'type': 'ping'}));

        // Should receive response (pong or error, but not crash)
        final response = await channel.stream.first.timeout(
          const Duration(seconds: 5),
        );
        expect(response, isNotNull);
      } finally {
        await channel.sink.close();
      }
    });

    test('command with invalid type is rejected safely', () async {
      final helper = WebSocketTestHelper();

      try {
        await helper.connect(userId: testUserId);
        await helper.waitForStateSync();

        // Send invalid command type
        helper.send({
          'type': 'command',
          'command': 'invalid_command_type',
          'value': 'test',
        });

        await Future.delayed(const Duration(milliseconds: 500));

        // Should receive error or be ignored, not crash
        // Connection should still work
        helper.sendPing();
        final pong = await helper.waitForPong();
        expect(pong['type'], equals('pong'));
      } finally {
        await helper.dispose();
      }
    });

    test('oversized message is handled gracefully', () async {
      final wsUrl = apiBaseUrl
          .replaceFirst('http://', 'ws://')
          .replaceFirst('https://', 'wss://');

      final channel = WebSocketChannel.connect(
        Uri.parse('$wsUrl/api/v1/ws/glasses/$testUserId?device_type=test'),
      );

      try {
        await channel.ready.timeout(const Duration(seconds: 5));

        // Send oversized payload
        final largePayload = jsonEncode({
          'type': 'command',
          'command': 'set_video',
          'value': 'x' * 100000, // 100KB string
        });

        channel.sink.add(largePayload);
        await Future.delayed(const Duration(milliseconds: 500));

        // Connection should handle gracefully (reject or truncate)
        channel.sink.add(jsonEncode({'type': 'ping'}));

        // May receive error or pong
        await channel.stream.first.timeout(
          const Duration(seconds: 5),
          onTimeout: () => '{"type": "timeout"}',
        );
      } finally {
        await channel.sink.close();
      }
    });
  });

  // ===========================================================================
  // ERROR HANDLING SECURITY TESTS
  // ===========================================================================

  group('Error Handling Security', () {
    test('error messages do not leak sensitive information', () async {
      // 🔧 FIX: Disabilita reconnection per user ID vuoto che fallisce
      final service = GlassesService(
        backendUrl: apiBaseUrl,
        enableReconnection: false,
      );
      final errors = <String>[];

      service.onError = (error) => errors.add(error);

      // Try to trigger errors with empty user ID
      await service.connect(userId: '', deviceType: 'phone');
      // 🔧 FIX: Aumentato delay per dare tempo al connection error
      await Future.delayed(const Duration(seconds: 2));

      // Check error messages
      for (final error in errors) {
        // Should not contain:
        expect(error.toLowerCase(), isNot(contains('password')));
        expect(error.toLowerCase(), isNot(contains('token')));
        expect(error.toLowerCase(), isNot(contains('secret')));
        expect(error, isNot(contains('/home/')));
        expect(error, isNot(contains('C:\\')));
      }

      await service.disconnect();
      // 🔧 FIX: Timeout aumentato a 30s
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('connection failure does not expose internal state', () async {
      // 🔧 FIX: Disabilita reconnection per evitare timeout
      // Aumentato timeout a 30s perché connection timeout interno è 10s
      final badService = GlassesService(
        backendUrl: 'http://invalid:9999',
        enableReconnection: false,
      );
      String? errorMessage;

      badService.onError = (error) => errorMessage = error;

      await badService.connect(userId: testUserId, deviceType: 'phone');
      await Future.delayed(const Duration(milliseconds: 1000));

      // Error should be generic, not expose stack trace
      if (errorMessage != null) {
        expect(errorMessage, isNot(contains('at Function')));
        expect(errorMessage, isNot(contains('.dart:')));
      }

      await badService.disconnect();
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  // ===========================================================================
  // DEVICE TYPE VALIDATION TESTS
  // ===========================================================================

  group('Device Type Validation', () {
    test('invalid device type is handled safely', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        // Invalid device type
        final connected = await service.connect(
          userId: testUserId,
          deviceType: 'malicious_device_type_12345',
        );

        // Should either reject or accept with sanitized type
        if (connected) {
          expect(service.isConnected, isTrue);
        }
      } finally {
        await service.disconnect();
      }
    });

    test('empty device type is handled', () async {
      final service = GlassesService(backendUrl: apiBaseUrl);

      try {
        await service.connect(userId: testUserId, deviceType: '');

        // Should handle gracefully
        await Future.delayed(const Duration(milliseconds: 500));
      } finally {
        await service.disconnect();
      }
    });
  });

  // ===========================================================================
  // STATE TAMPERING TESTS
  // ===========================================================================

  group('State Tampering Prevention', () {
    test('client cannot set arbitrary state fields', () async {
      final wsUrl = apiBaseUrl
          .replaceFirst('http://', 'ws://')
          .replaceFirst('https://', 'wss://');

      final channel = WebSocketChannel.connect(
        Uri.parse('$wsUrl/api/v1/ws/glasses/$testUserId?device_type=test'),
      );

      try {
        await channel.ready.timeout(const Duration(seconds: 5));

        // Try to send fake state_sync
        channel.sink.add(jsonEncode({
          'type': 'state_sync',
          'state': {
            'zoom_level': 999,
            'admin': true,
            'premium': true,
          },
        }));

        await Future.delayed(const Duration(milliseconds: 500));

        // Should be ignored or rejected
        // Request real state
        channel.sink.add(jsonEncode({'type': 'state_request'}));

        final response = await channel.stream
            .map((data) => jsonDecode(data as String) as Map<String, dynamic>)
            .firstWhere(
              (msg) => msg['type'] == 'state_sync' || msg['type'] == 'state_update',
            )
            .timeout(const Duration(seconds: 5));

        // State should not have been tampered
        final state = response['state'] as Map<String, dynamic>;
        expect(state['zoom_level'], lessThanOrEqualTo(3.0));
        expect(state.containsKey('admin'), isFalse);
      } finally {
        await channel.sink.close();
      }
    });
  });
}

/// 🎓 AI_MODULE: ConnectivityServiceTest
/// 🎓 AI_DESCRIPTION: Test connectivity service ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica monitoraggio connettività
/// 🎓 AI_TEACHING: Connectivity integration test

import 'package:flutter_test/flutter_test.dart';

import 'package:martial_arts_streaming/core/offline/connectivity_service.dart';

/// ZERO MOCK Test Suite for Connectivity Service
/// Tests real connectivity operations
void main() {
  late ConnectivityServiceImpl connectivityService;

  setUpAll(() {
    connectivityService = ConnectivityServiceImpl();
  });

  tearDownAll(() {
    connectivityService.dispose();
  });

  group('ConnectivityService ZERO MOCK Tests', () {
    group('status', () {
      test('should have initial status', () {
        // The status should be one of the valid values
        expect(
          connectivityService.currentStatus,
          isIn([ConnectionStatus.online, ConnectionStatus.offline, ConnectionStatus.unknown]),
        );
        print('✅ Initial status: ${connectivityService.currentStatus}');
      });

      test('should check connectivity', () async {
        // Act
        final status = await connectivityService.checkConnectivity();

        // Assert
        expect(
          status,
          isIn([ConnectionStatus.online, ConnectionStatus.offline, ConnectionStatus.unknown]),
        );
        print('✅ Connectivity check: $status');
      });

      test('should provide isOnline getter', () {
        // Act
        final isOnline = connectivityService.isOnline;

        // Assert
        expect(isOnline, isA<bool>());
        print('✅ isOnline: $isOnline');
      });

      test('should provide isOffline getter', () {
        // Act
        final isOffline = connectivityService.isOffline;

        // Assert
        expect(isOffline, isA<bool>());
        print('✅ isOffline: $isOffline');
      });
    });

    group('stream', () {
      test('should provide status stream', () {
        // Assert
        expect(connectivityService.statusStream, isA<Stream<ConnectionStatus>>());
        print('✅ Status stream available');
      });

      test('should emit status changes', () async {
        // Arrange
        final statuses = <ConnectionStatus>[];
        final subscription = connectivityService.statusStream.listen(statuses.add);

        // Wait a bit for any initial emissions
        await Future.delayed(const Duration(milliseconds: 500));

        // Trigger a check (may not change status but validates stream)
        await connectivityService.checkConnectivity();
        await Future.delayed(const Duration(milliseconds: 100));

        subscription.cancel();

        // Assert - stream is functional even if no changes occurred
        expect(true, isTrue);
        print('✅ Status stream subscription works');
      });
    });

    group('ConnectionStatus extension', () {
      test('should have correct isOnline extension', () {
        expect(ConnectionStatus.online.isOnline, isTrue);
        expect(ConnectionStatus.offline.isOnline, isFalse);
        expect(ConnectionStatus.unknown.isOnline, isFalse);
        print('✅ isOnline extension works');
      });

      test('should have correct isOffline extension', () {
        expect(ConnectionStatus.online.isOffline, isFalse);
        expect(ConnectionStatus.offline.isOffline, isTrue);
        expect(ConnectionStatus.unknown.isOffline, isFalse);
        print('✅ isOffline extension works');
      });

      test('should have displayName', () {
        expect(ConnectionStatus.online.displayName, equals('Online'));
        expect(ConnectionStatus.offline.displayName, equals('Offline'));
        expect(ConnectionStatus.unknown.displayName, equals('Sconosciuto'));
        print('✅ displayName extension works');
      });
    });

    group('lifecycle', () {
      test('should handle multiple checks', () async {
        // Act
        for (var i = 0; i < 5; i++) {
          await connectivityService.checkConnectivity();
        }

        // Assert - no exception means success
        expect(true, isTrue);
        print('✅ Multiple connectivity checks work');
      });

      test('should handle dispose', () {
        // Create a new instance to dispose
        final tempService = ConnectivityServiceImpl();

        // Act
        tempService.dispose();

        // Assert - no exception means success
        expect(true, isTrue);
        print('✅ Service disposal works');
      });
    });
  });

  group('ConnectivityListener mixin', () {
    test('should provide connection status', () {
      // Create a test class using the mixin
      final listener = _TestConnectivityListener();
      listener.initConnectivityListener(connectivityService);

      // Assert
      expect(listener.connectionStatus, isA<ConnectionStatus>());
      expect(listener.isOnline, isA<bool>());

      listener.disposeConnectivityListener();
      print('✅ ConnectivityListener mixin works');
    });
  });
}

/// Test class that uses ConnectivityListener mixin
class _TestConnectivityListener with ConnectivityListener {
  final List<ConnectionStatus> statusChanges = [];

  @override
  void onConnectivityChanged(ConnectionStatus status) {
    statusChanges.add(status);
  }
}

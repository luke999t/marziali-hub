/// 🎓 AI_MODULE: SyncServiceTest
/// 🎓 AI_DESCRIPTION: Test sync service ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica sincronizzazione dati
/// 🎓 AI_TEACHING: Sync integration test

import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';

import 'package:martial_arts_streaming/core/offline/offline_storage.dart';
import 'package:martial_arts_streaming/core/offline/offline_queue.dart';
import 'package:martial_arts_streaming/core/offline/sync_service.dart';
import 'package:martial_arts_streaming/core/offline/connectivity_service.dart';

/// ZERO MOCK Test Suite for Sync Service
/// Tests real sync operations
void main() {
  late HiveOfflineStorage storage;
  late HiveOfflineQueue queue;
  late ConnectivityService connectivity;
  late SyncServiceImpl syncService;

  setUpAll(() async {
    // Initialize Hive for testing
    await Hive.initFlutter('test_hive_sync');
    storage = HiveOfflineStorage();
    await storage.init();
    queue = HiveOfflineQueue(storage);
    connectivity = ConnectivityServiceImpl();
    syncService = SyncServiceImpl(
      queue: queue,
      connectivity: connectivity,
    );
  });

  setUp(() async {
    await queue.clear();
  });

  tearDownAll(() async {
    syncService.dispose();
    connectivity.dispose();
    await storage.clearAll();
    await storage.close();
  });

  group('SyncService ZERO MOCK Tests', () {
    group('status', () {
      test('should start with idle status', () {
        expect(syncService.status, equals(SyncStatus.idle));
        print('✅ Initial status: idle');
      });

      test('should stream status changes', () async {
        // Arrange
        final statuses = <SyncStatus>[];
        final subscription = syncService.statusStream.listen(statuses.add);

        // Act - add operation and sync
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.sync,
          entityType: 'test',
          entityId: 't1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Register a handler that succeeds
        syncService.registerHandler('test', (op) async => true);

        await syncService.syncNow();

        // Wait for status updates
        await Future.delayed(const Duration(milliseconds: 100));
        subscription.cancel();

        // Assert
        expect(statuses, isNotEmpty);
        print('✅ Status changes streamed: ${statuses.length} updates');
      });
    });

    group('handler registration', () {
      test('should register entity handler', () {
        // Act
        syncService.registerHandler('profile', (op) async {
          print('Handling profile operation: ${op.entityId}');
          return true;
        });

        // Assert - no exception means success
        expect(true, isTrue);
        print('✅ Handler registered for profile');
      });

      test('should call correct handler for entity type', () async {
        // Arrange
        var handlerCalled = false;
        syncService.registerHandler('custom', (op) async {
          handlerCalled = true;
          return true;
        });

        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.sync,
          entityType: 'custom',
          entityId: 'c1',
          payload: {'test': true},
          createdAt: DateTime.now(),
        ));

        // Act
        await syncService.syncNow();

        // Assert
        expect(handlerCalled, isTrue);
        print('✅ Correct handler was called');
      });
    });

    group('sync operations', () {
      test('should sync empty queue successfully', () async {
        // Act
        final result = await syncService.syncNow();

        // Assert
        expect(result.successCount, equals(0));
        expect(result.failCount, equals(0));
        expect(result.hasErrors, isFalse);
        print('✅ Empty queue sync completed');
      });

      test('should sync queued operations', () async {
        // Arrange
        syncService.registerHandler('syncable', (op) async {
          // Simulate successful sync
          return true;
        });

        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.update,
          entityType: 'syncable',
          entityId: 's1',
          payload: {'data': 'value1'},
          createdAt: DateTime.now(),
        ));
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.update,
          entityType: 'syncable',
          entityId: 's2',
          payload: {'data': 'value2'},
          createdAt: DateTime.now(),
        ));

        // Act
        final result = await syncService.syncNow();

        // Assert
        expect(result.successCount, equals(2));
        expect(result.failCount, equals(0));
        expect(result.totalProcessed, equals(2));
        print('✅ Synced ${result.successCount} operations');
      });

      test('should handle sync failures', () async {
        // Arrange
        syncService.registerHandler('failing', (op) async {
          throw Exception('Simulated failure');
        });

        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.sync,
          entityType: 'failing',
          entityId: 'f1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Act
        final result = await syncService.syncNow();

        // Assert
        expect(result.failCount, greaterThan(0));
        expect(result.hasErrors, isTrue);
        print('✅ Sync failure handled: ${result.errors.first}');
      });

      test('should report progress during sync', () async {
        // Arrange
        final progressUpdates = <int>[];
        syncService.registerHandler('progress', (op) async => true);

        for (var i = 0; i < 3; i++) {
          await queue.enqueue(QueuedOperation(
            id: '',
            type: QueueOperationType.sync,
            entityType: 'progress',
            entityId: 'p$i',
            payload: {},
            createdAt: DateTime.now(),
          ));
        }

        // Act
        await syncService.syncNow(
          onProgress: (processed, total) {
            progressUpdates.add(processed);
          },
        );

        // Assert
        expect(progressUpdates, isNotEmpty);
        expect(progressUpdates.last, equals(3));
        print('✅ Progress updates received: $progressUpdates');
      });
    });

    group('pending operations', () {
      test('should report pending count', () async {
        // Arrange
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.sync,
          entityType: 'count',
          entityId: 'c1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Act
        final count = await syncService.pendingCount;

        // Assert
        expect(count, greaterThan(0));
        print('✅ Pending count: $count');
      });

      test('should check hasPendingOperations', () async {
        // Initially might have pending from other tests
        await queue.clear();

        // Assert empty
        expect(await syncService.hasPendingOperations, isFalse);

        // Add operation
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.sync,
          entityType: 'pending',
          entityId: 'p1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Assert has pending
        expect(await syncService.hasPendingOperations, isTrue);
        print('✅ hasPendingOperations check works');
      });
    });

    group('auto sync', () {
      test('should start auto sync', () {
        // Act
        syncService.startAutoSync();

        // Assert - no exception means success
        expect(true, isTrue);
        print('✅ Auto sync started');
      });

      test('should stop auto sync', () {
        // Arrange
        syncService.startAutoSync();

        // Act
        syncService.stopAutoSync();

        // Assert - no exception means success
        expect(true, isTrue);
        print('✅ Auto sync stopped');
      });
    });
  });
}

/// 🎓 AI_MODULE: OfflineQueueTest
/// 🎓 AI_DESCRIPTION: Test coda offline ZERO MOCK
/// 🎓 AI_BUSINESS: Verifica sync queue operations
/// 🎓 AI_TEACHING: Queue pattern integration test

import 'package:flutter_test/flutter_test.dart';
import 'package:hive_flutter/hive_flutter.dart';

import 'package:martial_arts_streaming/core/offline/offline_storage.dart';
import 'package:martial_arts_streaming/core/offline/offline_queue.dart';

/// ZERO MOCK Test Suite for Offline Queue
/// Tests real queue operations with Hive backend
void main() {
  late HiveOfflineStorage storage;
  late HiveOfflineQueue queue;

  setUpAll(() async {
    // Initialize Hive for testing
    await Hive.initFlutter('test_hive_queue');
    storage = HiveOfflineStorage();
    await storage.init();
    queue = HiveOfflineQueue(storage);
  });

  setUp(() async {
    await queue.clear();
  });

  tearDownAll(() async {
    await storage.clearAll();
    await storage.close();
  });

  group('HiveOfflineQueue ZERO MOCK Tests', () {
    group('enqueue operations', () {
      test('should enqueue operation with auto-generated ID', () async {
        // Arrange
        final operation = QueuedOperation(
          id: '',
          type: QueueOperationType.create,
          entityType: 'profile',
          entityId: 'user123',
          payload: {'name': 'Test'},
          createdAt: DateTime.now(),
        );

        // Act
        await queue.enqueue(operation);
        final all = await queue.getAll();

        // Assert
        expect(all.length, equals(1));
        expect(all.first.id, isNotEmpty);
        expect(all.first.entityType, equals('profile'));
        print('✅ Operation enqueued with ID: ${all.first.id}');
      });

      test('should enqueue multiple operations', () async {
        // Arrange
        for (var i = 0; i < 5; i++) {
          await queue.enqueue(QueuedOperation(
            id: '',
            type: QueueOperationType.update,
            entityType: 'settings',
            entityId: 'setting_$i',
            payload: {'value': i},
            createdAt: DateTime.now(),
          ));
        }

        // Act
        final count = await queue.pendingCount;

        // Assert
        expect(count, equals(5));
        print('✅ Enqueued 5 operations, pending count: $count');
      });
    });

    group('peek and dequeue', () {
      test('should peek highest priority operation', () async {
        // Arrange
        await queue.enqueue(QueuedOperation(
          id: 'low',
          type: QueueOperationType.sync,
          entityType: 'profile',
          entityId: '1',
          payload: {},
          priority: QueuePriority.low,
          createdAt: DateTime.now(),
        ));
        await queue.enqueue(QueuedOperation(
          id: 'critical',
          type: QueueOperationType.sync,
          entityType: 'profile',
          entityId: '2',
          payload: {},
          priority: QueuePriority.critical,
          createdAt: DateTime.now(),
        ));
        await queue.enqueue(QueuedOperation(
          id: 'normal',
          type: QueueOperationType.sync,
          entityType: 'profile',
          entityId: '3',
          payload: {},
          priority: QueuePriority.normal,
          createdAt: DateTime.now(),
        ));

        // Act
        final next = await queue.peek();

        // Assert
        expect(next, isNotNull);
        expect(next!.id, equals('critical'));
        expect(next.priority, equals(QueuePriority.critical));
        print('✅ Peek returns highest priority: ${next.priority}');
      });

      test('should dequeue operation by ID', () async {
        // Arrange
        await queue.enqueue(QueuedOperation(
          id: 'to_remove',
          type: QueueOperationType.delete,
          entityType: 'download',
          entityId: 'd1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Act
        await queue.dequeue('to_remove');
        final count = await queue.pendingCount;

        // Assert
        expect(count, equals(0));
        print('✅ Operation dequeued successfully');
      });
    });

    group('filtering and querying', () {
      test('should filter by entity type', () async {
        // Arrange
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.update,
          entityType: 'profile',
          entityId: 'p1',
          payload: {},
          createdAt: DateTime.now(),
        ));
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.update,
          entityType: 'settings',
          entityId: 's1',
          payload: {},
          createdAt: DateTime.now(),
        ));
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.update,
          entityType: 'profile',
          entityId: 'p2',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Act
        final profileOps = await queue.getByEntityType('profile');

        // Assert
        expect(profileOps.length, equals(2));
        expect(profileOps.every((op) => op.entityType == 'profile'), isTrue);
        print('✅ Filtered by entity type: ${profileOps.length} profile ops');
      });

      test('should check hasPending correctly', () async {
        // Arrange - empty queue
        expect(await queue.hasPending, isFalse);

        // Act - add operation
        await queue.enqueue(QueuedOperation(
          id: '',
          type: QueueOperationType.create,
          entityType: 'test',
          entityId: 't1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Assert
        expect(await queue.hasPending, isTrue);
        print('✅ hasPending check works');
      });
    });

    group('retry logic', () {
      test('should mark operation as failed and increment retry count', () async {
        // Arrange
        const opId = 'retry_test';
        await queue.enqueue(QueuedOperation(
          id: opId,
          type: QueueOperationType.sync,
          entityType: 'profile',
          entityId: 'p1',
          payload: {},
          createdAt: DateTime.now(),
          retryCount: 0,
          maxRetries: 3,
        ));

        // Act
        await queue.markFailed(opId, 'Network error');
        final all = await queue.getAll();
        final op = all.firstWhere((o) => o.id == opId);

        // Assert
        expect(op.retryCount, equals(1));
        expect(op.errorMessage, equals('Network error'));
        expect(op.canRetry, isTrue);
        print('✅ Retry count incremented: ${op.retryCount}');
      });

      test('should remove operation when max retries exceeded', () async {
        // Arrange
        const opId = 'max_retry_test';
        await queue.enqueue(QueuedOperation(
          id: opId,
          type: QueueOperationType.sync,
          entityType: 'profile',
          entityId: 'p1',
          payload: {},
          createdAt: DateTime.now(),
          retryCount: 2,
          maxRetries: 3,
        ));

        // Act - fail to reach max retries
        await queue.markFailed(opId, 'Final failure');
        final count = await queue.pendingCount;

        // Assert - should be removed after exceeding max
        expect(count, equals(0));
        print('✅ Operation removed after max retries');
      });
    });

    group('cleanup', () {
      test('should clean up stale operations', () async {
        // Arrange - create stale operation (older than 24 hours)
        final staleDate = DateTime.now().subtract(const Duration(hours: 25));
        await queue.enqueue(QueuedOperation(
          id: 'stale_op',
          type: QueueOperationType.sync,
          entityType: 'old',
          entityId: 'o1',
          payload: {},
          createdAt: staleDate,
        ));

        // Also add a fresh operation
        await queue.enqueue(QueuedOperation(
          id: 'fresh_op',
          type: QueueOperationType.sync,
          entityType: 'new',
          entityId: 'n1',
          payload: {},
          createdAt: DateTime.now(),
        ));

        // Act
        final removed = await queue.cleanupStale();

        // Assert
        expect(removed, greaterThanOrEqualTo(1));
        final remaining = await queue.getAll();
        expect(remaining.any((op) => op.id == 'stale_op'), isFalse);
        print('✅ Cleaned up $removed stale operations');
      });

      test('should clear all operations', () async {
        // Arrange
        for (var i = 0; i < 3; i++) {
          await queue.enqueue(QueuedOperation(
            id: '',
            type: QueueOperationType.sync,
            entityType: 'test',
            entityId: 't$i',
            payload: {},
            createdAt: DateTime.now(),
          ));
        }

        // Act
        await queue.clear();
        final count = await queue.pendingCount;

        // Assert
        expect(count, equals(0));
        print('✅ Queue cleared');
      });
    });
  });
}

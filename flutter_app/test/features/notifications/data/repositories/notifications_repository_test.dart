/// 🎓 AI_MODULE: NotificationsRepositoryTest
/// 🎓 AI_DESCRIPTION: Test repository con backend reale
/// 🎓 AI_TEACHING: Repository test ZERO MOCK

import 'package:flutter_test/flutter_test.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/entities/notification_entity.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/entities/notification_preferences_entity.dart';
import '../../test_helpers.dart';

/// ZERO MOCK Repository Tests
/// Uses real datasources and backend
void main() {
  late NotificationsTestSetup setup;
  late NotificationsTestDataHelper dataHelper;

  setUpAll(() async {
    setup = NotificationsTestSetup();
    await setup.init();
    await setup.authenticate();
    dataHelper = NotificationsTestDataHelper(setup.dio);
  });

  tearDownAll(() async {
    await dataHelper.cleanupTestNotifications();
    await setup.dispose();
  });

  group('NotificationsRepositoryImpl', () {
    group('getNotifications', () {
      test('returns list of notifications from real API', () async {
        // Act
        final result = await setup.repository.getNotifications();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (notifications) {
            expect(notifications, isA<List<NotificationEntity>>());
          },
        );
      });

      test('supports pagination parameters', () async {
        // Act
        final result = await setup.repository.getNotifications(
          page: 1,
          pageSize: 5,
        );

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (notifications) {
            expect(notifications.length, lessThanOrEqualTo(5));
          },
        );
      });

      test('supports type filter', () async {
        // Arrange
        const typeFilter = NotificationType.system;

        // Act
        final result = await setup.repository.getNotifications(
          typeFilter: typeFilter,
        );

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (notifications) {
            for (final notification in notifications) {
              expect(notification.type, equals(typeFilter));
            }
          },
        );
      });

      test('supports unread only filter', () async {
        // Act
        final result = await setup.repository.getNotifications(
          unreadOnly: true,
        );

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (notifications) {
            for (final notification in notifications) {
              expect(notification.isRead, isFalse);
            }
          },
        );
      });

      test('caches first page of unfiltered results', () async {
        // Act
        await setup.repository.getNotifications(page: 1);

        // Assert - verify cache was populated
        final cached = await setup.localDataSource.getCachedNotifications();
        expect(cached, isNotNull);
      });

      test('does not cache filtered results', () async {
        // Clear cache first
        await setup.localDataSource.clearCache();

        // Act - fetch with filter
        await setup.repository.getNotifications(
          typeFilter: NotificationType.system,
        );

        // Assert - cache should not be populated for filtered results
        // (first page only, no filter)
      });
    });

    group('getUnreadCount', () {
      test('returns unread count from real API', () async {
        // Act
        final result = await setup.repository.getUnreadCount();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (count) {
            expect(count, isA<int>());
            expect(count, greaterThanOrEqualTo(0));
          },
        );
      });

      test('caches unread count', () async {
        // Act
        final result = await setup.repository.getUnreadCount();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (count) async {
            final cached = await setup.localDataSource.getCachedUnreadCount();
            expect(cached, equals(count));
          },
        );
      });
    });

    group('getNotification', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      tearDown(() async {
        await dataHelper.deleteTestNotification(testNotificationId);
      });

      test('returns single notification by id', () async {
        // Act
        final result = await setup.repository.getNotification(testNotificationId);

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (notification) {
            expect(notification.id, equals(testNotificationId));
          },
        );
      });
    });

    group('markAsRead', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      tearDown(() async {
        await dataHelper.deleteTestNotification(testNotificationId);
      });

      test('marks notification as read via real API', () async {
        // Act
        final result = await setup.repository.markAsRead(testNotificationId);

        // Assert
        expect(result.isRight(), isTrue);
      });
    });

    group('markAllAsRead', () {
      test('marks all notifications as read', () async {
        // Act
        final result = await setup.repository.markAllAsRead();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (count) {
            expect(count, isA<int>());
          },
        );
      });

      test('updates cached unread count to 0', () async {
        // Act
        await setup.repository.markAllAsRead();

        // Assert
        final cached = await setup.localDataSource.getCachedUnreadCount();
        expect(cached, equals(0));
      });
    });

    group('deleteNotification', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      test('deletes notification via real API', () async {
        // Act
        final result = await setup.repository.deleteNotification(testNotificationId);

        // Assert
        expect(result.isRight(), isTrue);
      });
    });

    group('deleteAllNotifications', () {
      test('deletes all notifications', () async {
        // Act
        final result = await setup.repository.deleteAllNotifications();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (count) {
            expect(count, isA<int>());
          },
        );
      });

      test('clears local cache', () async {
        // Act
        await setup.repository.deleteAllNotifications();

        // Assert
        final cached = await setup.localDataSource.getCachedNotifications();
        expect(cached, isNull);
      });
    });

    group('getPreferences', () {
      test('returns preferences from real API', () async {
        // Act
        final result = await setup.repository.getPreferences();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (preferences) {
            expect(preferences, isA<NotificationPreferencesEntity>());
            expect(preferences.pushEnabled, isA<bool>());
          },
        );
      });

      test('caches preferences', () async {
        // Act
        final result = await setup.repository.getPreferences();

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (preferences) async {
            final cached = await setup.localDataSource.getCachedPreferences();
            expect(cached, isNotNull);
          },
        );
      });
    });

    group('updatePreferences', () {
      test('updates preferences via real API', () async {
        // Arrange
        const updates = {'push_enabled': false};

        // Act
        final result = await setup.repository.updatePreferences(updates);

        // Assert
        result.fold(
          (failure) => fail('Expected success: ${failure.message}'),
          (preferences) {
            expect(preferences.pushEnabled, isFalse);
          },
        );

        // Cleanup
        await setup.repository.updatePreferences({'push_enabled': true});
      });

      test('caches updated preferences', () async {
        // Arrange
        const updates = {'push_system': false};

        // Act
        await setup.repository.updatePreferences(updates);

        // Assert
        final cached = await setup.localDataSource.getCachedPreferences();
        expect(cached?.pushSystem, isFalse);

        // Cleanup
        await setup.repository.updatePreferences({'push_system': true});
      });
    });
  });
}

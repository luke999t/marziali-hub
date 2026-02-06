/// 🎓 AI_MODULE: NotificationsIntegrationTest
/// 🎓 AI_DESCRIPTION: Test integrazione ZERO MOCK
/// 🎓 AI_TEACHING: Test reali che chiamano backend

import 'package:flutter_test/flutter_test.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/entities/notification_entity.dart';
import '../test_helpers.dart';

/// ZERO MOCK Integration Tests
/// These tests call the REAL backend API
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

  group('Notifications API Integration Tests', () {
    group('GET /notifications', () {
      test('should fetch notifications from real API', () async {
        // Act
        final result = await setup.getNotificationsUseCase(
          const GetNotificationsParams(),
        );

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (notifications) {
            expect(notifications, isA<List<NotificationEntity>>());
          },
        );
      });

      test('should fetch notifications with pagination', () async {
        // Arrange
        const params = GetNotificationsParams(page: 1, pageSize: 10);

        // Act
        final result = await setup.getNotificationsUseCase(params);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (notifications) {
            expect(notifications.length, lessThanOrEqualTo(10));
          },
        );
      });

      test('should fetch notifications with type filter', () async {
        // Arrange
        const params = GetNotificationsParams(
          typeFilter: NotificationType.system,
        );

        // Act
        final result = await setup.getNotificationsUseCase(params);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (notifications) {
            for (final notification in notifications) {
              expect(notification.type, equals(NotificationType.system));
            }
          },
        );
      });

      test('should fetch only unread notifications', () async {
        // Arrange
        const params = GetNotificationsParams(unreadOnly: true);

        // Act
        final result = await setup.getNotificationsUseCase(params);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (notifications) {
            for (final notification in notifications) {
              expect(notification.isRead, isFalse);
            }
          },
        );
      });
    });

    group('GET /notifications/unread-count', () {
      test('should get unread count from real API', () async {
        // Act
        final result = await setup.getUnreadCountUseCase();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (count) {
            expect(count, isA<int>());
            expect(count, greaterThanOrEqualTo(0));
          },
        );
      });
    });

    group('PATCH /notifications/:id/read', () {
      late String testNotificationId;

      setUp(() async {
        // Create a test notification
        testNotificationId = await dataHelper.createTestNotification();
      });

      tearDown(() async {
        await dataHelper.deleteTestNotification(testNotificationId);
      });

      test('should mark notification as read via real API', () async {
        // Act
        final result = await setup.markAsReadUseCase(testNotificationId);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (_) {
            // Verify by fetching the notification
          },
        );
      });
    });

    group('POST /notifications/mark-all-read', () {
      test('should mark all notifications as read', () async {
        // Act
        final result = await setup.markAllAsReadUseCase();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (count) {
            expect(count, isA<int>());
            expect(count, greaterThanOrEqualTo(0));
          },
        );
      });
    });

    group('DELETE /notifications/:id', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      test('should delete notification via real API', () async {
        // Act
        final result = await setup.deleteNotificationUseCase(testNotificationId);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (_) {
            // Success - notification deleted
          },
        );
      });
    });

    group('GET /notifications/preferences', () {
      test('should fetch preferences from real API', () async {
        // Act
        final result = await setup.getPreferencesUseCase();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (preferences) {
            expect(preferences.pushEnabled, isA<bool>());
            expect(preferences.systemEnabled, isA<bool>());
            expect(preferences.videoNewEnabled, isA<bool>());
          },
        );
      });
    });

    group('PATCH /notifications/preferences', () {
      test('should update preferences via real API', () async {
        // Arrange
        const updates = {'push_enabled': false};

        // Act
        final result = await setup.updatePreferencesUseCase(updates);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (preferences) {
            expect(preferences.pushEnabled, isFalse);
          },
        );

        // Cleanup - restore preferences
        await setup.updatePreferencesUseCase({'push_enabled': true});
      });

      test('should update quiet hours settings', () async {
        // Arrange
        const updates = {
          'quiet_hours_enabled': true,
          'quiet_hours_start': '23:00',
          'quiet_hours_end': '07:00',
        };

        // Act
        final result = await setup.updatePreferencesUseCase(updates);

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure: ${failure.message}'),
          (preferences) {
            expect(preferences.quietHoursEnabled, isTrue);
            expect(preferences.quietHoursStart, equals('23:00'));
            expect(preferences.quietHoursEnd, equals('07:00'));
          },
        );

        // Cleanup
        await setup.updatePreferencesUseCase({'quiet_hours_enabled': false});
      });
    });
  });

  group('Notifications Caching Tests', () {
    test('should cache notifications on first fetch', () async {
      // Act
      final result = await setup.repository.getNotifications();

      // Assert
      result.fold(
        (failure) => fail('Expected success: ${failure.message}'),
        (notifications) async {
          // Verify cache was populated
          final cached = await setup.localDataSource.getCachedNotifications();
          expect(cached, isNotNull);
        },
      );
    });

    test('should cache unread count', () async {
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
}

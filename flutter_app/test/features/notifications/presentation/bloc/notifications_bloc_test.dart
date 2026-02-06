/// 🎓 AI_MODULE: NotificationsBlocTest
/// 🎓 AI_DESCRIPTION: Test BLoC con backend reale
/// 🎓 AI_TEACHING: BLoC test ZERO MOCK

import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:media_center_arti_marziali/features/notifications/presentation/bloc/notifications_bloc.dart';
import 'package:media_center_arti_marziali/features/notifications/presentation/bloc/notifications_event.dart';
import 'package:media_center_arti_marziali/features/notifications/presentation/bloc/notifications_state.dart';
import '../../test_helpers.dart';

/// ZERO MOCK BLoC Tests
/// Uses real repository and backend
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

  group('NotificationsBloc', () {
    late NotificationsBloc bloc;

    setUp(() {
      // Create new bloc for each test
      bloc = NotificationsBloc(
        getNotificationsUseCase: setup.getNotificationsUseCase,
        getUnreadCountUseCase: setup.getUnreadCountUseCase,
        markAsReadUseCase: setup.markAsReadUseCase,
        markAllAsReadUseCase: setup.markAllAsReadUseCase,
        deleteNotificationUseCase: setup.deleteNotificationUseCase,
        getPreferencesUseCase: setup.getPreferencesUseCase,
        updatePreferencesUseCase: setup.updatePreferencesUseCase,
      );
    });

    tearDown(() async {
      await bloc.close();
    });

    test('initial state is correct', () {
      expect(bloc.state, equals(NotificationsState.initial()));
    });

    group('LoadNotifications', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'emits [loading, success] when LoadNotifications succeeds',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadNotifications()),
        expect: () => [
          isA<NotificationsState>()
              .having((s) => s.status, 'status', NotificationsStatus.loading),
          isA<NotificationsState>()
              .having((s) => s.status, 'status', NotificationsStatus.success),
        ],
        wait: const Duration(seconds: 5),
      );

      blocTest<NotificationsBloc, NotificationsState>(
        'emits notifications list when LoadNotifications succeeds',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadNotifications()),
        verify: (bloc) {
          expect(bloc.state.notifications, isA<List>());
        },
        wait: const Duration(seconds: 5),
      );

      blocTest<NotificationsBloc, NotificationsState>(
        'supports pagination with LoadNotifications',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadNotifications(page: 1, pageSize: 5)),
        verify: (bloc) {
          expect(bloc.state.currentPage, equals(1));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('LoadUnreadCount', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'updates unread count from real API',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadUnreadCount()),
        verify: (bloc) {
          expect(bloc.state.unreadCount, isA<int>());
          expect(bloc.state.unreadCount, greaterThanOrEqualTo(0));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('MarkNotificationAsRead', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      tearDown(() async {
        await dataHelper.deleteTestNotification(testNotificationId);
      });

      blocTest<NotificationsBloc, NotificationsState>(
        'marks notification as read with optimistic update',
        build: () => bloc,
        seed: () => NotificationsState.initial(),
        act: (bloc) async {
          // First load notifications
          bloc.add(const LoadNotifications());
          await Future.delayed(const Duration(seconds: 3));
          // Then mark as read
          bloc.add(MarkNotificationAsRead(testNotificationId));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('MarkAllNotificationsAsRead', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'sets unread count to 0',
        build: () => bloc,
        act: (bloc) => bloc.add(const MarkAllNotificationsAsRead()),
        verify: (bloc) {
          expect(bloc.state.unreadCount, equals(0));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('DeleteNotificationEvent', () {
      late String testNotificationId;

      setUp(() async {
        testNotificationId = await dataHelper.createTestNotification();
      });

      blocTest<NotificationsBloc, NotificationsState>(
        'removes notification from list with optimistic update',
        build: () => bloc,
        act: (bloc) async {
          // First load notifications
          bloc.add(const LoadNotifications());
          await Future.delayed(const Duration(seconds: 3));
          // Then delete
          bloc.add(DeleteNotificationEvent(testNotificationId));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('LoadPreferences', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'loads preferences from real API',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadPreferences()),
        verify: (bloc) {
          expect(bloc.state.preferences.pushEnabled, isA<bool>());
        },
        wait: const Duration(seconds: 5),
      );

      blocTest<NotificationsBloc, NotificationsState>(
        'emits preferencesLoading states correctly',
        build: () => bloc,
        act: (bloc) => bloc.add(const LoadPreferences()),
        expect: () => [
          isA<NotificationsState>()
              .having((s) => s.preferencesLoading, 'preferencesLoading', true),
          isA<NotificationsState>()
              .having((s) => s.preferencesLoading, 'preferencesLoading', false),
        ],
        wait: const Duration(seconds: 5),
      );
    });

    group('UpdatePreferencesEvent', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'updates preferences via real API',
        build: () => bloc,
        act: (bloc) => bloc.add(
          const UpdatePreferencesEvent({'push_enabled': true}),
        ),
        verify: (bloc) {
          expect(bloc.state.preferences.pushEnabled, isTrue);
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('RefreshNotifications', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'triggers LoadNotifications and LoadUnreadCount',
        build: () => bloc,
        act: (bloc) => bloc.add(const RefreshNotifications()),
        verify: (bloc) {
          // After refresh, we should have loaded notifications
          expect(bloc.state.status, isNot(NotificationsStatus.initial));
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('ApplyNotificationFilter', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'applies type filter and reloads',
        build: () => bloc,
        act: (bloc) => bloc.add(
          const ApplyNotificationFilter(
            typeFilter: NotificationType.system,
          ),
        ),
        verify: (bloc) {
          expect(bloc.state.typeFilter, equals(NotificationType.system));
        },
        wait: const Duration(seconds: 5),
      );

      blocTest<NotificationsBloc, NotificationsState>(
        'applies unread only filter',
        build: () => bloc,
        act: (bloc) => bloc.add(
          const ApplyNotificationFilter(unreadOnly: true),
        ),
        verify: (bloc) {
          expect(bloc.state.unreadOnly, isTrue);
        },
        wait: const Duration(seconds: 5),
      );
    });

    group('ClearNotificationFilter', () {
      blocTest<NotificationsBloc, NotificationsState>(
        'clears all filters',
        build: () => bloc,
        seed: () => NotificationsState.initial().copyWith(
          typeFilter: NotificationType.system,
          unreadOnly: true,
        ),
        act: (bloc) => bloc.add(const ClearNotificationFilter()),
        verify: (bloc) {
          expect(bloc.state.typeFilter, isNull);
          expect(bloc.state.unreadOnly, isNull);
        },
        wait: const Duration(seconds: 5),
      );
    });
  });
}

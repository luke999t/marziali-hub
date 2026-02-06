/// 🎓 AI_MODULE: EventsBlocTest
/// 🎓 AI_DESCRIPTION: Test per EventsBloc
/// 🎓 AI_BUSINESS: Verifica state management eventi
/// 🎓 AI_TEACHING: BLoC test con bloc_test
/// 🎓 AI_CREATED: 2025-01-17
/// 🎓 AI_TASK: CODE 3 - Flutter Events Feature

import 'package:flutter_test/flutter_test.dart';
import 'package:media_center/features/events/domain/entities/event_entity.dart';
import 'package:media_center/features/events/domain/entities/events_filter.dart';
import 'package:media_center/features/events/presentation/bloc/events_event.dart';
import 'package:media_center/features/events/presentation/bloc/events_state.dart';

void main() {
  group('EventsEvent', () {
    test('LoadEvents with filter has correct props', () {
      const filter = EventsFilter(page: 1, pageSize: 20);
      const event1 = LoadEvents(filter: filter, refresh: false);
      const event2 = LoadEvents(filter: filter, refresh: false);
      const event3 = LoadEvents(filter: filter, refresh: true);

      expect(event1.props, equals(event2.props));
      expect(event1.props, isNot(equals(event3.props)));
    });

    test('LoadEventDetail contains eventId in props', () {
      const event1 = LoadEventDetail('event-1');
      const event2 = LoadEventDetail('event-1');
      const event3 = LoadEventDetail('event-2');

      expect(event1.props, equals(event2.props));
      expect(event1.props, isNot(equals(event3.props)));
    });

    test('SubscribeToEvent has correct eventId', () {
      const event = SubscribeToEvent('event-123');
      expect(event.eventId, equals('event-123'));
      expect(event.props, equals(['event-123']));
    });

    test('UnsubscribeFromEvent has all required props', () {
      const event = UnsubscribeFromEvent(
        eventId: 'event-1',
        subscriptionId: 'sub-1',
        reason: 'Schedule conflict',
      );

      expect(event.eventId, equals('event-1'));
      expect(event.subscriptionId, equals('sub-1'));
      expect(event.reason, equals('Schedule conflict'));
      expect(event.props, hasLength(3));
    });

    test('ApplyFilter has filter in props', () {
      const filter = EventsFilter(
        eventType: EventType.stage,
        isFree: true,
      );
      const event = ApplyFilter(filter);

      expect(event.filter, equals(filter));
      expect(event.props, contains(filter));
    });

    test('JoinWaitingList has eventId', () {
      const event = JoinWaitingList('event-wl-1');
      expect(event.eventId, equals('event-wl-1'));
    });

    test('ChangeSortOrder has sortBy prop', () {
      const event = ChangeSortOrder(EventSortBy.priceDesc);
      expect(event.sortBy, equals(EventSortBy.priceDesc));
      expect(event.props, equals([EventSortBy.priceDesc]));
    });

    test('LoadNearbyEvents has coordinates', () {
      const event = LoadNearbyEvents(
        latitude: 45.0,
        longitude: 9.0,
        radiusKm: 30,
      );

      expect(event.latitude, equals(45.0));
      expect(event.longitude, equals(9.0));
      expect(event.radiusKm, equals(30));
      expect(event.props, hasLength(3));
    });
  });

  group('EventsState', () {
    test('initial state has correct default values', () {
      final state = EventsState.initial();

      expect(state.eventsLoadingState, equals(EventsLoadingState.initial));
      expect(state.events, isEmpty);
      expect(state.totalEventsCount, equals(0));
      expect(state.currentPage, equals(1));
      expect(state.hasMoreEvents, isFalse);
      expect(state.eventsError, isNull);
      expect(state.selectedEvent, isNull);
      expect(state.isSubscribing, isFalse);
      expect(state.isFromCache, isFalse);
      expect(state.currentFilter, equals(const EventsFilter()));
    });

    test('copyWith updates loading state', () {
      final initial = EventsState.initial();
      final updated = initial.copyWith(
        eventsLoadingState: EventsLoadingState.loading,
      );

      expect(updated.eventsLoadingState, equals(EventsLoadingState.loading));
      expect(initial.eventsLoadingState, equals(EventsLoadingState.initial));
    });

    test('copyWith clears error when flag is set', () {
      final withError = EventsState.initial().copyWith(
        eventsError: 'Some error occurred',
      );

      expect(withError.eventsError, equals('Some error occurred'));

      final cleared = withError.copyWith(clearEventsError: true);
      expect(cleared.eventsError, isNull);
    });

    test('copyWith clears selected event when flag is set', () {
      final testEvent = _createTestEvent();
      final withEvent = EventsState.initial().copyWith(
        selectedEvent: testEvent,
      );

      expect(withEvent.selectedEvent, isNotNull);

      final cleared = withEvent.copyWith(clearSelectedEvent: true);
      expect(cleared.selectedEvent, isNull);
    });

    test('isLoadingEvents returns true for loading states', () {
      final loading = EventsState.initial().copyWith(
        eventsLoadingState: EventsLoadingState.loading,
      );
      final loadingMore = EventsState.initial().copyWith(
        eventsLoadingState: EventsLoadingState.loadingMore,
      );
      final loaded = EventsState.initial().copyWith(
        eventsLoadingState: EventsLoadingState.loaded,
      );

      expect(loading.isLoadingEvents, isTrue);
      expect(loadingMore.isLoadingEvents, isTrue);
      expect(loaded.isLoadingEvents, isFalse);
    });

    test('isRefreshing returns true only for refreshing state', () {
      final refreshing = EventsState.initial().copyWith(
        eventsLoadingState: EventsLoadingState.refreshing,
      );
      final loading = EventsState.initial().copyWith(
        eventsLoadingState: EventsLoadingState.loading,
      );

      expect(refreshing.isRefreshing, isTrue);
      expect(loading.isRefreshing, isFalse);
    });

    test('hasEventsError checks eventsError', () {
      final noError = EventsState.initial();
      final withError = noError.copyWith(eventsError: 'Error message');

      expect(noError.hasEventsError, isFalse);
      expect(withError.hasEventsError, isTrue);
    });

    test('hasEvents checks events list', () {
      final empty = EventsState.initial();
      final withEvents = empty.copyWith(events: [_createTestEvent()]);

      expect(empty.hasEvents, isFalse);
      expect(withEvents.hasEvents, isTrue);
    });

    test('isLoadingDetail returns true when loading detail', () {
      final loading = EventsState.initial().copyWith(
        detailLoadingState: EventsLoadingState.loading,
      );
      final loaded = EventsState.initial().copyWith(
        detailLoadingState: EventsLoadingState.loaded,
      );

      expect(loading.isLoadingDetail, isTrue);
      expect(loaded.isLoadingDetail, isFalse);
    });

    test('isPerformingSubscriptionOperation checks both flags', () {
      final subscribing = EventsState.initial().copyWith(isSubscribing: true);
      final unsubscribing =
          EventsState.initial().copyWith(isUnsubscribing: true);
      final idle = EventsState.initial();

      expect(subscribing.isPerformingSubscriptionOperation, isTrue);
      expect(unsubscribing.isPerformingSubscriptionOperation, isTrue);
      expect(idle.isPerformingSubscriptionOperation, isFalse);
    });

    test('hasActiveFilters delegates to filter', () {
      final noFilters = EventsState.initial();
      final withFilters = noFilters.copyWith(
        currentFilter: const EventsFilter(isFree: true),
      );

      expect(noFilters.hasActiveFilters, isFalse);
      expect(withFilters.hasActiveFilters, isTrue);
    });

    test('activeFilterCount delegates to filter', () {
      final state = EventsState.initial().copyWith(
        currentFilter: const EventsFilter(
          isFree: true,
          eventType: EventType.stage,
        ),
      );

      expect(state.activeFilterCount, equals(2));
    });

    test('props includes all state properties', () {
      final state = EventsState.initial();
      expect(state.props, isNotEmpty);
      expect(state.props.length, greaterThan(20));
    });

    test('states with same values are equal', () {
      final state1 = EventsState.initial();
      final state2 = EventsState.initial();

      expect(state1, equals(state2));
    });

    test('states with different values are not equal', () {
      final state1 = EventsState.initial();
      final state2 = state1.copyWith(isSubscribing: true);

      expect(state1, isNot(equals(state2)));
    });
  });

  group('EventsFilter', () {
    test('default filter has no active filters', () {
      const filter = EventsFilter();
      expect(filter.hasActiveFilters, isFalse);
      expect(filter.activeFilterCount, equals(0));
    });

    test('filter with eventType has 1 active filter', () {
      const filter = EventsFilter(eventType: EventType.workshop);
      expect(filter.hasActiveFilters, isTrue);
      expect(filter.activeFilterCount, equals(1));
    });

    test('filter with multiple options counts correctly', () {
      const filter = EventsFilter(
        eventType: EventType.stage,
        isFree: true,
        isAvailable: true,
        searchQuery: 'karate',
      );

      expect(filter.activeFilterCount, equals(4));
    });

    test('toQueryParams creates correct map', () {
      const filter = EventsFilter(
        page: 2,
        pageSize: 30,
        eventType: EventType.seminar,
        isFree: true,
        sortBy: EventSortBy.priceAsc,
      );

      final params = filter.toQueryParams();

      expect(params['page'], equals('2'));
      expect(params['page_size'], equals('30'));
      expect(params['event_type'], equals('seminar'));
      expect(params['is_free'], equals('true'));
      expect(params['sort_by'], equals('price_asc'));
    });

    test('copyWith creates new filter with updated values', () {
      const original = EventsFilter(page: 1, eventType: EventType.stage);

      final updated = original.copyWith(page: 2, isFree: true);

      expect(updated.page, equals(2));
      expect(updated.eventType, equals(EventType.stage));
      expect(updated.isFree, isTrue);
    });

    test('factory free creates free filter', () {
      final filter = EventsFilter.free();
      expect(filter.isFree, isTrue);
    });

    test('factory available creates available filter', () {
      final filter = EventsFilter.available();
      expect(filter.isAvailable, isTrue);
    });

    test('factory upcoming creates upcoming filter', () {
      final filter = EventsFilter.upcoming();
      expect(filter.upcomingOnly, isTrue);
    });

    test('factory byType creates typed filter', () {
      final filter = EventsFilter.byType(EventType.competition);
      expect(filter.eventType, equals(EventType.competition));
    });
  });
}

/// Helper function to create test event
EventEntity _createTestEvent() {
  return _TestEventEntity(
    id: 'test-event',
    title: 'Test Event',
    description: 'A test event',
    eventType: EventType.stage,
    status: EventStatus.published,
    startDate: DateTime.now().add(const Duration(days: 10)),
    endDate: DateTime.now().add(const Duration(days: 10, hours: 2)),
    maxParticipants: 50,
    currentParticipants: 25,
    price: 100,
    currency: 'EUR',
    instructors: [],
    requirements: [],
    isFeatured: false,
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
  );
}

/// Concrete implementation for testing
class _TestEventEntity extends EventEntity {
  const _TestEventEntity({
    required super.id,
    required super.title,
    required super.description,
    required super.eventType,
    required super.status,
    required super.startDate,
    required super.endDate,
    super.location,
    super.address,
    super.latitude,
    super.longitude,
    required super.maxParticipants,
    required super.currentParticipants,
    required super.price,
    required super.currency,
    required super.instructors,
    required super.requirements,
    super.imageUrl,
    super.thumbnailUrl,
    required super.isFeatured,
    super.registrationDeadline,
    super.minParticipants,
    required super.createdAt,
    required super.updatedAt,
  });
}

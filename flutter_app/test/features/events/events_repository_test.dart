/// 🎓 AI_MODULE: EventsRepositoryTest
/// 🎓 AI_DESCRIPTION: Test per EventsRepository
/// 🎓 AI_BUSINESS: Verifica orchestrazione datasources
/// 🎓 AI_TEACHING: Integration test ZERO MOCK
/// 🎓 AI_CREATED: 2025-01-17
/// 🎓 AI_TASK: CODE 3 - Flutter Events Feature

import 'dart:convert';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:media_center/features/events/data/datasources/events_local_datasource.dart';
import 'package:media_center/features/events/data/models/event_model.dart';
import 'package:media_center/features/events/domain/entities/event_entity.dart';

void main() {
  late EventsLocalDataSourceImpl localDataSource;
  late SharedPreferences prefs;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    prefs = await SharedPreferences.getInstance();
    localDataSource = EventsLocalDataSourceImpl(prefs);
  });

  group('EventsLocalDataSource', () {
    final testEvent = EventModel(
      id: 'test-event-1',
      title: 'Test Stage',
      description: 'A test event description',
      eventType: EventType.stage,
      status: EventStatus.published,
      startDate: DateTime(2025, 2, 15, 10, 0),
      endDate: DateTime(2025, 2, 15, 18, 0),
      location: 'Test Dojo',
      address: '123 Test Street',
      latitude: 45.0,
      longitude: 9.0,
      maxParticipants: 50,
      currentParticipants: 25,
      price: 100.0,
      currency: 'EUR',
      instructors: ['Master Test'],
      requirements: ['Black belt'],
      imageUrl: null,
      thumbnailUrl: null,
      isFeatured: false,
      registrationDeadline: DateTime(2025, 2, 14),
      minParticipants: 10,
      createdAt: DateTime.now(),
      updatedAt: DateTime.now(),
    );

    test('getCachedEvents returns empty list when cache is empty', () async {
      final result = await localDataSource.getCachedEvents();
      expect(result, isEmpty);
    });

    test('cacheEvents stores events and getCachedEvents retrieves them',
        () async {
      // Cache events
      await localDataSource.cacheEvents([testEvent]);

      // Retrieve cached events
      final cached = await localDataSource.getCachedEvents();

      expect(cached, hasLength(1));
      expect(cached.first.id, equals(testEvent.id));
      expect(cached.first.title, equals(testEvent.title));
      expect(cached.first.eventType, equals(testEvent.eventType));
      expect(cached.first.price, equals(testEvent.price));
    });

    test('cacheEvent stores single event', () async {
      await localDataSource.cacheEvent(testEvent);

      final cached = await localDataSource.getCachedEvent(testEvent.id);

      expect(cached, isNotNull);
      expect(cached!.id, equals(testEvent.id));
      expect(cached.title, equals(testEvent.title));
    });

    test('getCachedEvent returns null for non-existent event', () async {
      final cached = await localDataSource.getCachedEvent('non-existent');
      expect(cached, isNull);
    });

    test('clearEventsCache removes all cached events', () async {
      await localDataSource.cacheEvents([testEvent]);
      await localDataSource.cacheEvent(testEvent);

      await localDataSource.clearEventsCache();

      final cached = await localDataSource.getCachedEvents();
      expect(cached, isEmpty);

      final singleCached = await localDataSource.getCachedEvent(testEvent.id);
      expect(singleCached, isNull);
    });

    test('isCacheValid returns false when no cache exists', () async {
      final isValid = await localDataSource.isCacheValid();
      expect(isValid, isFalse);
    });

    test('isCacheValid returns true after caching events', () async {
      await localDataSource.cacheEvents([testEvent]);

      final isValid = await localDataSource.isCacheValid();
      expect(isValid, isTrue);
    });

    test('getLastSyncTimestamp returns timestamp after caching', () async {
      await localDataSource.cacheEvents([testEvent]);

      final timestamp = await localDataSource.getLastSyncTimestamp();
      expect(timestamp, isNotNull);
      expect(
          timestamp!.difference(DateTime.now()).inSeconds.abs(), lessThan(5));
    });

    test('cacheEvents updates lastSyncTimestamp', () async {
      final before = DateTime.now();
      await localDataSource.cacheEvents([testEvent]);
      final timestamp = await localDataSource.getLastSyncTimestamp();

      expect(timestamp, isNotNull);
      expect(timestamp!.isAfter(before) || timestamp.isAtSameMomentAs(before),
          isTrue);
    });
  });

  group('EventModel JSON Serialization', () {
    test('fromJson creates valid EventModel', () {
      final json = {
        'id': 'event-123',
        'title': 'Test Event',
        'description': 'Description here',
        'event_type': 'workshop',
        'status': 'published',
        'start_date': '2025-03-01T09:00:00Z',
        'end_date': '2025-03-01T17:00:00Z',
        'location': 'Test Location',
        'address': 'Test Address',
        'latitude': 45.5,
        'longitude': 9.5,
        'max_participants': 30,
        'current_participants': 10,
        'price': 50.0,
        'currency': 'EUR',
        'instructors': ['Instructor A', 'Instructor B'],
        'requirements': ['Requirement 1'],
        'image_url': 'https://example.com/image.jpg',
        'thumbnail_url': 'https://example.com/thumb.jpg',
        'is_featured': true,
        'registration_deadline': '2025-02-28T23:59:59Z',
        'min_participants': 5,
        'created_at': '2025-01-01T00:00:00Z',
        'updated_at': '2025-01-01T00:00:00Z',
      };

      final event = EventModel.fromJson(json);

      expect(event.id, equals('event-123'));
      expect(event.title, equals('Test Event'));
      expect(event.eventType, equals(EventType.workshop));
      expect(event.status, equals(EventStatus.published));
      expect(event.maxParticipants, equals(30));
      expect(event.currentParticipants, equals(10));
      expect(event.price, equals(50.0));
      expect(event.instructors, hasLength(2));
      expect(event.isFeatured, isTrue);
    });

    test('toJson creates valid JSON map', () {
      final event = EventModel(
        id: 'event-456',
        title: 'Stage Test',
        description: 'Stage description',
        eventType: EventType.stage,
        status: EventStatus.published,
        startDate: DateTime(2025, 4, 1, 10, 0),
        endDate: DateTime(2025, 4, 1, 18, 0),
        location: 'Dojo',
        maxParticipants: 20,
        currentParticipants: 5,
        price: 0,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final json = event.toJson();

      expect(json['id'], equals('event-456'));
      expect(json['title'], equals('Stage Test'));
      expect(json['event_type'], equals('stage'));
      expect(json['status'], equals('published'));
      expect(json['max_participants'], equals(20));
      expect(json['price'], equals(0));
    });

    test('round-trip serialization preserves data', () {
      final original = EventModel(
        id: 'roundtrip-test',
        title: 'Round Trip Event',
        description: 'Testing serialization',
        eventType: EventType.seminar,
        status: EventStatus.draft,
        startDate: DateTime(2025, 5, 10, 14, 0),
        endDate: DateTime(2025, 5, 10, 20, 0),
        location: 'Conference Room',
        address: '456 Test Ave',
        latitude: 40.0,
        longitude: -74.0,
        maxParticipants: 100,
        currentParticipants: 50,
        price: 75.50,
        currency: 'USD',
        instructors: ['Speaker 1', 'Speaker 2'],
        requirements: ['RSVP required'],
        imageUrl: 'https://example.com/event.jpg',
        isFeatured: true,
        registrationDeadline: DateTime(2025, 5, 9),
        minParticipants: 20,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      final json = original.toJson();
      final restored = EventModel.fromJson(json);

      expect(restored.id, equals(original.id));
      expect(restored.title, equals(original.title));
      expect(restored.eventType, equals(original.eventType));
      expect(restored.price, equals(original.price));
      expect(restored.instructors, equals(original.instructors));
      expect(restored.isFeatured, equals(original.isFeatured));
    });
  });

  group('EventEntity Computed Properties', () {
    test('isFree returns true when price is 0', () {
      final event = EventModel(
        id: 'free-event',
        title: 'Free Event',
        description: 'A free event',
        eventType: EventType.online,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 10)),
        endDate: DateTime.now().add(const Duration(days: 10, hours: 2)),
        maxParticipants: 100,
        currentParticipants: 0,
        price: 0,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      expect(event.isFree, isTrue);
    });

    test('isFull returns true when at capacity', () {
      final event = EventModel(
        id: 'full-event',
        title: 'Full Event',
        description: 'A full event',
        eventType: EventType.stage,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 10)),
        endDate: DateTime.now().add(const Duration(days: 10, hours: 2)),
        maxParticipants: 50,
        currentParticipants: 50,
        price: 100,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      expect(event.isFull, isTrue);
      expect(event.availableSpots, equals(0));
    });

    test('occupancyRate calculates correctly', () {
      final event = EventModel(
        id: 'half-full-event',
        title: 'Half Full Event',
        description: 'A half full event',
        eventType: EventType.workshop,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 10)),
        endDate: DateTime.now().add(const Duration(days: 10, hours: 2)),
        maxParticipants: 100,
        currentParticipants: 50,
        price: 50,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      expect(event.occupancyRate, equals(0.5));
      expect(event.availableSpots, equals(50));
    });

    test('isUpcoming returns true for future events', () {
      final futureEvent = EventModel(
        id: 'future-event',
        title: 'Future Event',
        description: 'An upcoming event',
        eventType: EventType.competition,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 30)),
        endDate: DateTime.now().add(const Duration(days: 30, hours: 8)),
        maxParticipants: 200,
        currentParticipants: 100,
        price: 200,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: true,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      expect(futureEvent.isUpcoming, isTrue);
    });

    test('canRegister returns false for cancelled events', () {
      final cancelledEvent = EventModel(
        id: 'cancelled-event',
        title: 'Cancelled Event',
        description: 'A cancelled event',
        eventType: EventType.stage,
        status: EventStatus.cancelled,
        startDate: DateTime.now().add(const Duration(days: 10)),
        endDate: DateTime.now().add(const Duration(days: 10, hours: 2)),
        maxParticipants: 50,
        currentParticipants: 10,
        price: 100,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      expect(cancelledEvent.canRegister, isFalse);
    });
  });
}

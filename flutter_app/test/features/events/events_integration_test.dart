/// 🎓 AI_MODULE: EventsIntegrationTest
/// 🎓 AI_DESCRIPTION: Integration test per Events feature
/// 🎓 AI_BUSINESS: Verifica end-to-end flussi eventi
/// 🎓 AI_TEACHING: Widget test con BLoC ZERO MOCK
/// 🎓 AI_CREATED: 2025-01-17
/// 🎓 AI_TASK: CODE 3 - Flutter Events Feature

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:media_center/features/events/data/models/event_model.dart';
import 'package:media_center/features/events/data/models/event_subscription_model.dart';
import 'package:media_center/features/events/data/models/waiting_list_model.dart';
import 'package:media_center/features/events/domain/entities/event_entity.dart';
import 'package:media_center/features/events/domain/entities/event_subscription_entity.dart';
import 'package:media_center/features/events/domain/entities/waiting_list_entry_entity.dart';
import 'package:media_center/features/events/presentation/widgets/event_card_widget.dart';
import 'package:media_center/features/events/presentation/widgets/event_filter_chip.dart';
import 'package:media_center/features/events/presentation/widgets/subscription_button_widget.dart';
import 'package:media_center/features/events/presentation/widgets/event_countdown_widget.dart';

void main() {
  group('EventCardWidget', () {
    late EventModel testEvent;

    setUp(() {
      testEvent = EventModel(
        id: 'test-event-1',
        title: 'Test Stage Milano',
        description: 'Un bellissimo stage di arti marziali',
        eventType: EventType.stage,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 10)),
        endDate: DateTime.now().add(const Duration(days: 10, hours: 8)),
        location: 'Dojo Milano',
        address: 'Via Roma 123',
        maxParticipants: 50,
        currentParticipants: 25,
        price: 100.0,
        currency: 'EUR',
        instructors: ['Master Tanaka'],
        requirements: ['Cintura nera'],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );
    });

    testWidgets('displays event title and location', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: testEvent),
          ),
        ),
      );

      expect(find.text('Test Stage Milano'), findsOneWidget);
      expect(find.text('Dojo Milano'), findsOneWidget);
    });

    testWidgets('displays event type badge', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: testEvent),
          ),
        ),
      );

      expect(find.text('Stage'), findsOneWidget);
    });

    testWidgets('displays price for paid events', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: testEvent),
          ),
        ),
      );

      expect(find.text('100 EUR'), findsOneWidget);
    });

    testWidgets('displays Gratuito badge for free events', (tester) async {
      final freeEvent = EventModel(
        id: 'free-event',
        title: 'Free Workshop',
        description: 'A free workshop',
        eventType: EventType.workshop,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 5)),
        endDate: DateTime.now().add(const Duration(days: 5, hours: 2)),
        maxParticipants: 30,
        currentParticipants: 10,
        price: 0,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: freeEvent),
          ),
        ),
      );

      expect(find.text('Gratuito'), findsOneWidget);
    });

    testWidgets('displays Completo badge when event is full', (tester) async {
      final fullEvent = EventModel(
        id: 'full-event',
        title: 'Full Stage',
        description: 'A full stage',
        eventType: EventType.stage,
        status: EventStatus.published,
        startDate: DateTime.now().add(const Duration(days: 5)),
        endDate: DateTime.now().add(const Duration(days: 5, hours: 2)),
        maxParticipants: 30,
        currentParticipants: 30,
        price: 50,
        currency: 'EUR',
        instructors: [],
        requirements: [],
        isFeatured: false,
        createdAt: DateTime.now(),
        updatedAt: DateTime.now(),
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: fullEvent),
          ),
        ),
      );

      expect(find.text('Completo'), findsOneWidget);
    });

    testWidgets('shows participants count', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(event: testEvent),
          ),
        ),
      );

      expect(find.text('25/50'), findsOneWidget);
    });

    testWidgets('triggers onTap callback when tapped', (tester) async {
      bool tapped = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCardWidget(
              event: testEvent,
              onTap: () => tapped = true,
            ),
          ),
        ),
      );

      await tester.tap(find.byType(InkWell).first);
      expect(tapped, isTrue);
    });
  });

  group('EventFilterChip', () {
    testWidgets('displays label text', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventFilterChip(
              label: 'Gratuiti',
              isSelected: false,
              onTap: () {},
            ),
          ),
        ),
      );

      expect(find.text('Gratuiti'), findsOneWidget);
    });

    testWidgets('shows check icon when selected', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventFilterChip(
              label: 'Stage',
              isSelected: true,
              onTap: () {},
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.check), findsOneWidget);
    });

    testWidgets('does not show check icon when not selected', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventFilterChip(
              label: 'Workshop',
              isSelected: false,
              onTap: () {},
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.check), findsNothing);
    });

    testWidgets('triggers onTap when tapped', (tester) async {
      bool tapped = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventFilterChip(
              label: 'Test',
              isSelected: false,
              onTap: () => tapped = true,
            ),
          ),
        ),
      );

      await tester.tap(find.byType(InkWell));
      expect(tapped, isTrue);
    });
  });

  group('SubscriptionButtonWidget', () {
    testWidgets('displays label when not loading', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SubscriptionButtonWidget(
              label: 'Iscriviti ora',
              icon: Icons.check_circle,
              isLoading: false,
              onPressed: () {},
            ),
          ),
        ),
      );

      expect(find.text('Iscriviti ora'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('shows loading state when isLoading is true', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SubscriptionButtonWidget(
              label: 'Iscriviti ora',
              icon: Icons.check_circle,
              isLoading: true,
              onPressed: () {},
            ),
          ),
        ),
      );

      expect(find.text('Caricamento...'), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('button is disabled when loading', (tester) async {
      bool pressed = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SubscriptionButtonWidget(
              label: 'Iscriviti',
              icon: Icons.add,
              isLoading: true,
              onPressed: () => pressed = true,
            ),
          ),
        ),
      );

      await tester.tap(find.byType(FloatingActionButton));
      expect(pressed, isFalse);
    });
  });

  group('EventCountdownWidget', () {
    testWidgets('displays countdown for future date', (tester) async {
      final futureDate = DateTime.now().add(const Duration(days: 5, hours: 3));

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCountdownWidget(targetDate: futureDate),
          ),
        ),
      );

      // Should show countdown sections
      expect(find.text('Giorni'), findsOneWidget);
      expect(find.text('Ore'), findsOneWidget);
      expect(find.text('Min'), findsOneWidget);
    });

    testWidgets('shows event in corso for past date', (tester) async {
      final pastDate = DateTime.now().subtract(const Duration(hours: 1));

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCountdownWidget(targetDate: pastDate),
          ),
        ),
      );

      expect(find.text('Evento in corso'), findsOneWidget);
    });

    testWidgets('compact mode shows shorter format', (tester) async {
      final futureDate = DateTime.now().add(const Duration(days: 2, hours: 5));

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EventCountdownWidget(
              targetDate: futureDate,
              compact: true,
            ),
          ),
        ),
      );

      // Compact mode shows timer icon
      expect(find.byIcon(Icons.timer), findsOneWidget);
    });
  });

  group('Model Serialization', () {
    test('EventSubscriptionModel fromJson parses correctly', () {
      final json = {
        'id': 'sub-123',
        'event_id': 'event-456',
        'user_id': 'user-789',
        'status': 'confirmed',
        'amount_paid': 100.0,
        'payment_intent_id': 'pi_xxx',
        'subscribed_at': '2025-01-15T10:00:00Z',
        'confirmed_at': '2025-01-15T10:05:00Z',
        'event_title': 'Test Event',
        'event_start_date': '2025-02-01T09:00:00Z',
      };

      final subscription = EventSubscriptionModel.fromJson(json);

      expect(subscription.id, equals('sub-123'));
      expect(subscription.eventId, equals('event-456'));
      expect(subscription.status, equals(SubscriptionStatus.confirmed));
      expect(subscription.amountPaid, equals(100.0));
      expect(subscription.eventTitle, equals('Test Event'));
    });

    test('WaitingListModel fromJson parses correctly', () {
      final json = {
        'id': 'wl-123',
        'event_id': 'event-456',
        'user_id': 'user-789',
        'position': 5,
        'status': 'waiting',
        'joined_at': '2025-01-15T10:00:00Z',
        'event_title': 'Popular Stage',
        'total_in_queue': 10,
      };

      final entry = WaitingListModel.fromJson(json);

      expect(entry.id, equals('wl-123'));
      expect(entry.position, equals(5));
      expect(entry.status, equals(WaitingListStatus.waiting));
      expect(entry.totalInQueue, equals(10));
    });

    test('WaitingListModel handles notified status', () {
      final json = {
        'id': 'wl-notified',
        'event_id': 'event-1',
        'user_id': 'user-1',
        'position': 1,
        'status': 'notified',
        'joined_at': '2025-01-10T10:00:00Z',
        'notified_at': '2025-01-15T10:00:00Z',
        'expires_at': '2025-01-16T10:00:00Z',
      };

      final entry = WaitingListModel.fromJson(json);

      expect(entry.status, equals(WaitingListStatus.notified));
      expect(entry.notifiedAt, isNotNull);
      expect(entry.expiresAt, isNotNull);
    });

    test('EventSubscriptionModel toJson creates valid map', () {
      final subscription = EventSubscriptionModel(
        id: 'sub-test',
        eventId: 'event-test',
        userId: 'user-test',
        status: SubscriptionStatus.pending,
        amountPaid: 50.0,
        subscribedAt: DateTime(2025, 1, 15, 10, 0),
        eventTitle: 'Test',
      );

      final json = subscription.toJson();

      expect(json['id'], equals('sub-test'));
      expect(json['status'], equals('pending'));
      expect(json['amount_paid'], equals(50.0));
    });
  });

  group('Entity Computed Properties', () {
    test('EventSubscriptionEntity canCancel is false for cancelled', () {
      final subscription = EventSubscriptionModel(
        id: 'sub-cancelled',
        eventId: 'event-1',
        userId: 'user-1',
        status: SubscriptionStatus.cancelled,
        amountPaid: 0,
        subscribedAt: DateTime.now(),
      );

      expect(subscription.canCancel, isFalse);
    });

    test('EventSubscriptionEntity isActive is true for confirmed', () {
      final subscription = EventSubscriptionModel(
        id: 'sub-active',
        eventId: 'event-1',
        userId: 'user-1',
        status: SubscriptionStatus.confirmed,
        amountPaid: 100,
        subscribedAt: DateTime.now(),
        confirmedAt: DateTime.now(),
      );

      expect(subscription.isActive, isTrue);
    });

    test('EventSubscriptionEntity isPending checks pending status', () {
      final subscription = EventSubscriptionModel(
        id: 'sub-pending',
        eventId: 'event-1',
        userId: 'user-1',
        status: SubscriptionStatus.pending,
        amountPaid: 50,
        subscribedAt: DateTime.now(),
      );

      expect(subscription.isPending, isTrue);
    });

    test('WaitingListEntryEntity formattedPosition formats correctly', () {
      final entry = WaitingListModel(
        id: 'wl-1',
        eventId: 'event-1',
        userId: 'user-1',
        position: 5,
        status: WaitingListStatus.waiting,
        joinedAt: DateTime.now(),
        totalInQueue: 20,
      );

      expect(entry.formattedPosition, equals('#5/20'));
    });
  });
}

/// ============================================================================
/// EVENTS FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: EventsFlowTests
/// AI_DESCRIPTION: E2E tests for events functionality
/// AI_BUSINESS: Verifica browse eventi, dettaglio, iscrizione
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 7
/// 1. Browse events list
/// 2. View event details
/// 3. Subscribe to event
/// 4. Unsubscribe from event
/// 5. View my subscriptions
/// 6. Filter events by status
/// 7. Verify sold out event behavior
///
/// ============================================================================
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Events Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;
    late EventsRobot eventsRobot;

    // ======================== TEST 1 ========================
    testWidgets(
      '1. Browse events list displays available events',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        eventsRobot = EventsRobot(tester);

        // Login
        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Navigate to events
        await eventsRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Verify events list has items
        eventsRobot.verifyEventsListHasItems();
      },
      skip: true,
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. View event details shows complete information',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Tap first event
        await eventsRobot.tapFirstEvent();
        await eventsRobot.verifyEventDetailScreenVisible();

        // Verify details are shown
        eventsRobot.verifyEventDateDisplayed();
        eventsRobot.verifyCapacityInfo();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Subscribe to event succeeds',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();

        // Find an event to subscribe
        await eventsRobot.tapFirstEvent();
        await eventsRobot.verifyEventDetailScreenVisible();

        // Verify not subscribed state
        eventsRobot.verifyNotSubscribedState();

        // Subscribe
        await eventsRobot.tapSubscribe();
        await eventsRobot.confirmSubscription();

        // Verify subscription success
        await eventsRobot.verifySubscriptionSuccess();
        eventsRobot.verifySubscribedState();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. Unsubscribe from event succeeds',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();

        // Go to my subscriptions
        await eventsRobot.navigateToMySubscriptions();
        await eventsRobot.verifyMySubscriptionsVisible();

        // Tap first subscribed event
        await eventsRobot.tapFirstEvent();
        await eventsRobot.verifyEventDetailScreenVisible();

        // Verify subscribed state
        eventsRobot.verifySubscribedState();

        // Unsubscribe
        await eventsRobot.tapUnsubscribe();
        await eventsRobot.confirmUnsubscription();

        // Verify unsubscription success
        await eventsRobot.verifyUnsubscriptionSuccess();
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. View my subscriptions shows subscribed events',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Navigate to my subscriptions
        await eventsRobot.navigateToMySubscriptions();
        await eventsRobot.verifyMySubscriptionsVisible();
      },
      skip: true,
    );

    // ======================== TEST 6 ========================
    testWidgets(
      '6. Filter events by status shows filtered results',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Filter by upcoming
        await eventsRobot.filterUpcoming();

        // Verify filtered results
        eventsRobot.verifyEventsListHasItems();

        // Clear filters
        await eventsRobot.clearFilters();

        // Filter by past
        await eventsRobot.filterPast();
      },
      skip: true,
    );

    // ======================== TEST 7 ========================
    testWidgets(
      '7. Sold out event shows appropriate state',
      (tester) async {
        authRobot = AuthRobot(tester);
        eventsRobot = EventsRobot(tester);

        await authRobot.login(TestUsers.primary);
        await eventsRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Try to find a sold out event
        // This would depend on test data having sold out events
        await eventsRobot.scrollDownForMore();

        // If we find a sold out event
        final soldOutText = find.textContaining('Esaurito');
        if (tester.any(soldOutText)) {
          // Tap on the sold out event
          await eventsRobot.tapEventByTitle('');

          // Verify sold out state
          eventsRobot.verifySoldOutState();
        }

        // Note: This test depends on having sold out events in test data
      },
      skip: true,
    );
  });
}

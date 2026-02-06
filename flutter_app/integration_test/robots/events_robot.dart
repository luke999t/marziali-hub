/// ============================================================================
/// EVENTS ROBOT
/// ============================================================================
///
/// AI_MODULE: EventsRobot
/// AI_DESCRIPTION: Page Object for events screens
/// AI_BUSINESS: Encapsulates event browsing, details, subscription interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import 'base_robot.dart';

class EventsRobot extends BaseRobot {
  const EventsRobot(super.tester);

  // ======================== EVENTS LIST SCREEN ========================

  /// Navigate to events screen
  Future<void> navigateToEvents() async {
    await tapByIcon(Icons.event);
    await settle(TestTimeouts.pageLoad);
  }

  /// Verify events screen is displayed
  Future<void> verifyEventsScreenVisible() async {
    await settle(TestTimeouts.pageLoad);
    // Events screen should show list of events or empty state
    final eventIcon = find.byIcon(Icons.event);
    final calendarIcon = find.byIcon(Icons.calendar_today);
    final listView = find.byType(ListView);
    final gridView = find.byType(GridView);

    final isEventsVisible = tester.any(eventIcon) ||
        tester.any(calendarIcon) ||
        tester.any(listView) ||
        tester.any(gridView);

    expect(isEventsVisible, isTrue, reason: 'Events screen should be visible');
  }

  /// Verify events list has items
  void verifyEventsListHasItems() {
    final cards = find.byType(Card);
    final listTiles = find.byType(ListTile);
    final hasItems = tester.any(cards) || tester.any(listTiles);
    expect(hasItems, isTrue, reason: 'Events list should have items');
  }

  /// Verify empty events state
  void verifyEmptyEventsState() {
    final emptyText = find.textContaining('vuoto');
    final noEvents = find.textContaining('No events');
    final nessunEvento = find.textContaining('Nessun evento');
    final hasEmpty =
        tester.any(emptyText) || tester.any(noEvents) || tester.any(nessunEvento);
    expect(hasEmpty, isTrue);
  }

  /// Tap on first event card
  Future<void> tapFirstEvent() async {
    final cards = find.byType(Card);
    final listTiles = find.byType(ListTile);
    final inkWells = find.byType(InkWell);

    if (tester.any(cards)) {
      await tap(cards.first);
    } else if (tester.any(listTiles)) {
      await tap(listTiles.first);
    } else if (tester.any(inkWells)) {
      await tap(inkWells.first);
    }
    await settle();
  }

  /// Tap on event by title
  Future<void> tapEventByTitle(String title) async {
    final eventFinder = find.textContaining(title);
    await scrollUntilVisible(eventFinder);
    await tap(eventFinder);
    await settle();
  }

  /// Scroll down to load more events
  Future<void> scrollDownForMore() async {
    await scrollDown();
    await settle(TestTimeouts.loadMore);
  }

  /// Pull to refresh events
  Future<void> refreshEvents() async {
    await pullToRefresh();
  }

  // ======================== EVENT FILTERS ========================

  /// Open filters
  Future<void> openFilters() async {
    final filterButton = find.byIcon(Icons.filter_list);
    final filterAlt = find.byIcon(Icons.filter_alt);
    final filterText = find.textContaining('Filtri');

    if (tester.any(filterButton)) {
      await tap(filterButton.first);
    } else if (tester.any(filterAlt)) {
      await tap(filterAlt.first);
    } else if (tester.any(filterText)) {
      await tap(filterText.first);
    }
    await settle();
  }

  /// Filter by upcoming events
  Future<void> filterUpcoming() async {
    final upcoming = find.textContaining('Prossimi');
    final upcomingEn = find.textContaining('Upcoming');
    final futuro = find.textContaining('Futuri');

    if (tester.any(upcoming)) {
      await tap(upcoming.first);
    } else if (tester.any(upcomingEn)) {
      await tap(upcomingEn.first);
    } else if (tester.any(futuro)) {
      await tap(futuro.first);
    }
    await settle();
  }

  /// Filter by past events
  Future<void> filterPast() async {
    final past = find.textContaining('Passati');
    final pastEn = find.textContaining('Past');
    final conclusi = find.textContaining('Conclusi');

    if (tester.any(past)) {
      await tap(past.first);
    } else if (tester.any(pastEn)) {
      await tap(pastEn.first);
    } else if (tester.any(conclusi)) {
      await tap(conclusi.first);
    }
    await settle();
  }

  /// Filter by my subscriptions
  Future<void> filterMySubscriptions() async {
    final myEvents = find.textContaining('Miei');
    final subscribed = find.textContaining('Iscritto');
    final mySubscriptions = find.textContaining('Le mie iscrizioni');

    if (tester.any(myEvents)) {
      await tap(myEvents.first);
    } else if (tester.any(subscribed)) {
      await tap(subscribed.first);
    } else if (tester.any(mySubscriptions)) {
      await tap(mySubscriptions.first);
    }
    await settle();
  }

  /// Apply filters
  Future<void> applyFilters() async {
    final applyButton = find.textContaining('Applica');
    final applyEn = find.textContaining('Apply');

    if (tester.any(applyButton)) {
      await tap(applyButton.first);
    } else if (tester.any(applyEn)) {
      await tap(applyEn.first);
    }
    await settle();
  }

  /// Clear filters
  Future<void> clearFilters() async {
    final clearButton = find.textContaining('Rimuovi');
    final clearEn = find.textContaining('Clear');
    final resetButton = find.textContaining('Reset');

    if (tester.any(clearButton)) {
      await tap(clearButton.first);
    } else if (tester.any(clearEn)) {
      await tap(clearEn.first);
    } else if (tester.any(resetButton)) {
      await tap(resetButton.first);
    }
    await settle();
  }

  // ======================== EVENT DETAIL SCREEN ========================

  /// Verify event detail screen is displayed
  Future<void> verifyEventDetailScreenVisible() async {
    await settle(TestTimeouts.pageLoad);
    // Event detail should show title, description, location, date
    final hasContent = tester.any(find.byType(SingleChildScrollView)) ||
        tester.any(find.byType(CustomScrollView)) ||
        tester.any(find.textContaining('Descrizione')) ||
        tester.any(find.textContaining('Description'));

    expect(hasContent, isTrue, reason: 'Event detail screen should be visible');
  }

  /// Verify event title is displayed
  void verifyEventTitle(String title) {
    final titleFinder = find.textContaining(title);
    verifyExists(titleFinder);
  }

  /// Verify event location is displayed
  void verifyEventLocation(String location) {
    final locationFinder = find.textContaining(location);
    verifyExists(locationFinder);
  }

  /// Verify event date is displayed
  void verifyEventDateDisplayed() {
    // Date is typically shown with date icons or formatted text
    final dateIcon = find.byIcon(Icons.calendar_today);
    final scheduleIcon = find.byIcon(Icons.schedule);
    final hasDate = tester.any(dateIcon) || tester.any(scheduleIcon);
    expect(hasDate, isTrue);
  }

  /// Verify event price is displayed
  void verifyEventPrice(String price) {
    final priceFinder = find.textContaining(price);
    verifyExists(priceFinder);
  }

  /// Verify event capacity info
  void verifyCapacityInfo() {
    final capacityText = find.textContaining('post');
    final spotsText = find.textContaining('spots');
    final disponibili = find.textContaining('disponibil');
    final hasCapacity =
        tester.any(capacityText) || tester.any(spotsText) || tester.any(disponibili);
    expect(hasCapacity, isTrue);
  }

  // ======================== SUBSCRIPTION ========================

  /// Tap subscribe button
  Future<void> tapSubscribe() async {
    final subscribeButton = find.textContaining('Iscriviti');
    final subscribeEn = find.textContaining('Subscribe');
    final registerButton = find.textContaining('Registrati');
    final joinButton = find.textContaining('Partecipa');

    if (tester.any(subscribeButton)) {
      await tap(subscribeButton.first);
    } else if (tester.any(subscribeEn)) {
      await tap(subscribeEn.first);
    } else if (tester.any(registerButton)) {
      await tap(registerButton.first);
    } else if (tester.any(joinButton)) {
      await tap(joinButton.first);
    }
    await settle();
  }

  /// Confirm subscription (in dialog)
  Future<void> confirmSubscription() async {
    final confirmButton = find.textContaining('Conferma');
    final proceedButton = find.textContaining('Procedi');
    final yesButton = find.text('Sì');

    if (tester.any(confirmButton)) {
      await tap(confirmButton.first);
    } else if (tester.any(proceedButton)) {
      await tap(proceedButton.first);
    } else if (tester.any(yesButton)) {
      await tap(yesButton.first);
    }
    await settle(TestTimeouts.network);
  }

  /// Verify subscription success
  Future<void> verifySubscriptionSuccess() async {
    await settle();
    final successSnackbar = find.byType(SnackBar);
    final iscritto = find.textContaining('Iscritto');
    final subscribed = find.textContaining('Subscribed');
    final success = find.textContaining('successo');

    final hasSuccess = tester.any(successSnackbar) ||
        tester.any(iscritto) ||
        tester.any(subscribed) ||
        tester.any(success);
    expect(hasSuccess, isTrue, reason: 'Subscription success expected');
  }

  /// Tap unsubscribe button
  Future<void> tapUnsubscribe() async {
    final unsubscribeButton = find.textContaining('Annulla iscrizione');
    final unsubscribeEn = find.textContaining('Unsubscribe');
    final cancelButton = find.textContaining('Disdici');

    if (tester.any(unsubscribeButton)) {
      await tap(unsubscribeButton.first);
    } else if (tester.any(unsubscribeEn)) {
      await tap(unsubscribeEn.first);
    } else if (tester.any(cancelButton)) {
      await tap(cancelButton.first);
    }
    await settle();
  }

  /// Confirm unsubscription (in dialog)
  Future<void> confirmUnsubscription() async {
    final confirmButton = find.textContaining('Conferma');
    final yesButton = find.text('Sì');

    if (tester.any(confirmButton)) {
      await tap(confirmButton.first);
    } else if (tester.any(yesButton)) {
      await tap(yesButton.first);
    }
    await settle(TestTimeouts.network);
  }

  /// Verify unsubscription success
  Future<void> verifyUnsubscriptionSuccess() async {
    await settle();
    final successSnackbar = find.byType(SnackBar);
    final cancelled = find.textContaining('annullata');
    final unsubscribed = find.textContaining('Unsubscribed');

    final hasSuccess =
        tester.any(successSnackbar) || tester.any(cancelled) || tester.any(unsubscribed);
    expect(hasSuccess, isTrue, reason: 'Unsubscription success expected');
  }

  /// Verify subscribed state (button shows unsubscribe option)
  void verifySubscribedState() {
    final unsubscribe = find.textContaining('Annulla');
    final subscribed = find.textContaining('Iscritto');
    final isSubscribed = tester.any(unsubscribe) || tester.any(subscribed);
    expect(isSubscribed, isTrue);
  }

  /// Verify not subscribed state
  void verifyNotSubscribedState() {
    final subscribe = find.textContaining('Iscriviti');
    final join = find.textContaining('Partecipa');
    final isNotSubscribed = tester.any(subscribe) || tester.any(join);
    expect(isNotSubscribed, isTrue);
  }

  /// Verify sold out state
  void verifySoldOutState() {
    final soldOut = find.textContaining('Esaurito');
    final full = find.textContaining('Pieno');
    final noSpots = find.textContaining('No spots');
    final isSoldOut =
        tester.any(soldOut) || tester.any(full) || tester.any(noSpots);
    expect(isSoldOut, isTrue);
  }

  // ======================== MY SUBSCRIPTIONS ========================

  /// Navigate to my subscriptions
  Future<void> navigateToMySubscriptions() async {
    final myTab = find.textContaining('Le mie');
    final mySubsEn = find.textContaining('My');
    final iscrizioni = find.textContaining('Iscrizioni');

    if (tester.any(myTab)) {
      await tap(myTab.first);
    } else if (tester.any(mySubsEn)) {
      await tap(mySubsEn.first);
    } else if (tester.any(iscrizioni)) {
      await tap(iscrizioni.first);
    }
    await settle();
  }

  /// Verify my subscriptions visible
  Future<void> verifyMySubscriptionsVisible() async {
    await settle();
    final listView = find.byType(ListView);
    final gridView = find.byType(GridView);
    final emptyState = find.textContaining('vuoto');

    final hasContent =
        tester.any(listView) || tester.any(gridView) || tester.any(emptyState);
    expect(hasContent, isTrue);
  }

  // ======================== NAVIGATION ========================

  /// Go back from event detail
  Future<void> goBack() async {
    final backButton = find.byIcon(Icons.arrow_back);
    if (tester.any(backButton)) {
      await tap(backButton.first);
    } else {
      await tester.pageBack();
    }
    await settle();
  }

  /// Share event
  Future<void> shareEvent() async {
    final shareButton = find.byIcon(Icons.share);
    if (tester.any(shareButton)) {
      await tap(shareButton.first);
    }
    await settle();
  }
}

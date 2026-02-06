/// ============================================================================
/// SEARCH ROBOT
/// ============================================================================
///
/// AI_MODULE: SearchRobot
/// AI_DESCRIPTION: Page Object for search screen
/// AI_BUSINESS: Encapsulates search, filter, and results interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import 'base_robot.dart';

class SearchRobot extends BaseRobot {
  const SearchRobot(super.tester);

  // ======================== SEARCH SCREEN ========================

  /// Navigate to search screen
  Future<void> navigateToSearch() async {
    await tapByIcon(Icons.search);
    await settle(TestTimeouts.pageLoad);
  }

  /// Verify search screen is displayed
  Future<void> verifySearchScreenVisible() async {
    await settle(TestTimeouts.pageLoad);
    // Search screen should have search field
    final searchField = find.byType(TextField);
    final searchIcon = find.byIcon(Icons.search);

    final isSearchVisible = tester.any(searchField) || tester.any(searchIcon);
    expect(isSearchVisible, isTrue, reason: 'Search screen should be visible');
  }

  /// Verify search field is displayed
  void verifySearchFieldDisplayed() {
    final searchField = find.byType(TextField);
    final textFormField = find.byType(TextFormField);
    final hasField = tester.any(searchField) || tester.any(textFormField);
    expect(hasField, isTrue);
  }

  // ======================== SEARCH INPUT ========================

  /// Enter search query
  Future<void> enterSearchQuery(String query) async {
    final searchField = find.byType(TextField).first;
    await enterText(searchField, query);
    await pump(const Duration(milliseconds: 500));
  }

  /// Clear search query
  Future<void> clearSearchQuery() async {
    final clearButton = find.byIcon(Icons.clear);
    final closeButton = find.byIcon(Icons.close);

    if (tester.any(clearButton)) {
      await tap(clearButton.first);
    } else if (tester.any(closeButton)) {
      await tap(closeButton.first);
    } else {
      final searchField = find.byType(TextField).first;
      await clearAndEnterText(searchField, '');
    }
    await settle();
  }

  /// Submit search
  Future<void> submitSearch() async {
    await tester.testTextInput.receiveAction(TextInputAction.search);
    await settle(TestTimeouts.network);
  }

  /// Search with query (enter + submit)
  Future<void> searchFor(String query) async {
    await enterSearchQuery(query);
    await submitSearch();
  }

  // ======================== SEARCH RESULTS ========================

  /// Verify search results visible
  Future<void> verifySearchResultsVisible() async {
    await settle();
    final listView = find.byType(ListView);
    final gridView = find.byType(GridView);
    final cards = find.byType(Card);

    final hasResults =
        tester.any(listView) || tester.any(gridView) || tester.any(cards);
    expect(hasResults, isTrue, reason: 'Search results should be visible');
  }

  /// Verify no results message
  void verifyNoResultsMessage() {
    final noResults = find.textContaining('Nessun risultato');
    final notFound = find.textContaining('Not found');
    final noResultsEn = find.textContaining('No results');
    final zeroResults = find.textContaining('0 risultat');

    final hasNoResults = tester.any(noResults) ||
        tester.any(notFound) ||
        tester.any(noResultsEn) ||
        tester.any(zeroResults);
    expect(hasNoResults, isTrue);
  }

  /// Get result count
  int getResultCount() {
    final cards = find.byType(Card);
    return tester.widgetList(cards).length;
  }

  /// Verify result count
  void verifyResultCount(int expectedCount) {
    expect(getResultCount(), equals(expectedCount));
  }

  /// Verify at least N results
  void verifyAtLeastNResults(int minCount) {
    expect(getResultCount(), greaterThanOrEqualTo(minCount));
  }

  /// Tap on first result
  Future<void> tapFirstResult() async {
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

  /// Tap result by title
  Future<void> tapResultByTitle(String title) async {
    final titleFinder = find.textContaining(title);
    await tap(titleFinder.first);
    await settle();
  }

  // ======================== FILTERS ========================

  /// Open search filters
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

  /// Select category filter
  Future<void> selectCategoryFilter(String category) async {
    final categoryFinder = find.textContaining(category);
    await tap(categoryFinder.first);
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
    await settle(TestTimeouts.network);
  }

  /// Clear all filters
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

  /// Verify active filter chip
  void verifyActiveFilter(String filterName) {
    final chip = find.ancestor(
      of: find.textContaining(filterName),
      matching: find.byType(Chip),
    );
    verifyExists(chip);
  }

  // ======================== SEARCH HISTORY ========================

  /// Verify search history visible
  void verifySearchHistoryVisible() {
    final historyIcon = find.byIcon(Icons.history);
    final recentText = find.textContaining('Recenti');
    final recentEn = find.textContaining('Recent');

    final hasHistory =
        tester.any(historyIcon) || tester.any(recentText) || tester.any(recentEn);
    expect(hasHistory, isTrue);
  }

  /// Tap on history item
  Future<void> tapHistoryItem(String query) async {
    final historyItem = find.textContaining(query);
    await tap(historyItem.first);
    await settle(TestTimeouts.network);
  }

  /// Clear search history
  Future<void> clearSearchHistory() async {
    final clearButton = find.textContaining('Cancella');
    final clearEn = find.textContaining('Clear history');

    if (tester.any(clearButton)) {
      await tap(clearButton.first);
    } else if (tester.any(clearEn)) {
      await tap(clearEn.first);
    }
    await settle();

    // Confirm if dialog appears
    final confirmButton = find.textContaining('Conferma');
    if (tester.any(confirmButton)) {
      await tap(confirmButton.first);
    }
    await settle();
  }

  /// Delete single history item
  Future<void> deleteHistoryItem(String query) async {
    final historyItem = find.ancestor(
      of: find.textContaining(query),
      matching: find.byType(ListTile),
    );

    if (tester.any(historyItem)) {
      // Swipe to delete
      await swipeLeft(historyItem.first);
      await settle();
    }
  }

  // ======================== SUGGESTIONS ========================

  /// Verify search suggestions visible
  void verifySuggestionsVisible() {
    final suggestions = find.byType(ListTile);
    verifyExistsAtLeastOne(suggestions);
  }

  /// Tap on suggestion
  Future<void> tapSuggestion(String suggestion) async {
    final suggestionFinder = find.textContaining(suggestion);
    await tap(suggestionFinder.first);
    await settle(TestTimeouts.network);
  }

  // ======================== LOADING STATE ========================

  /// Verify loading indicator
  void verifyLoadingIndicator() {
    final progress = find.byType(CircularProgressIndicator);
    verifyExists(progress);
  }

  /// Wait for loading to complete
  Future<void> waitForLoadingComplete() async {
    final loading = find.byType(CircularProgressIndicator);
    if (tester.any(loading)) {
      await waitForWidgetToDisappear(loading, timeout: TestTimeouts.network);
    }
  }

  // ======================== NAVIGATION ========================

  /// Go back from search
  Future<void> goBack() async {
    final backButton = find.byIcon(Icons.arrow_back);
    if (tester.any(backButton)) {
      await tap(backButton.first);
    } else {
      await tester.pageBack();
    }
    await settle();
  }
}

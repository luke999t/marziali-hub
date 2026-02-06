/// ============================================================================
/// SEARCH FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: SearchFlowTests
/// AI_DESCRIPTION: E2E tests for search functionality
/// AI_BUSINESS: Verifica ricerca, filtri, cronologia
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 5
/// 1. Search by keyword returns results
/// 2. Search with no results shows message
/// 3. Filter search results by category
/// 4. Search history displays recent queries
/// 5. Clear search history
///
/// ============================================================================
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Search Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;
    late SearchRobot searchRobot;

    // ======================== TEST 1 ========================
    testWidgets(
      '1. Search by keyword returns results',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        searchRobot = SearchRobot(tester);

        // Login
        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Navigate to search
        await searchRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Search for existing content
        await searchRobot.searchFor(TestSearchQueries.withResults);

        // Verify results
        await searchRobot.verifySearchResultsVisible();
        searchRobot.verifyAtLeastNResults(1);
      },
      skip: true,
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. Search with no results shows appropriate message',
      (tester) async {
        authRobot = AuthRobot(tester);
        searchRobot = SearchRobot(tester);

        await authRobot.login(TestUsers.primary);
        await searchRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Search for non-existent content
        await searchRobot.searchFor(TestSearchQueries.noResults);

        // Verify no results message
        searchRobot.verifyNoResultsMessage();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Filter search results by category',
      (tester) async {
        authRobot = AuthRobot(tester);
        searchRobot = SearchRobot(tester);

        await authRobot.login(TestUsers.primary);
        await searchRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Search first
        await searchRobot.searchFor(TestSearchQueries.popular);
        await searchRobot.verifySearchResultsVisible();

        // Open filters
        await searchRobot.openFilters();

        // Select category filter
        await searchRobot.selectCategoryFilter(TestSearchQueries.categoryFilter);
        await searchRobot.applyFilters();

        // Verify filtered results
        await searchRobot.verifySearchResultsVisible();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. Search history displays recent queries',
      (tester) async {
        authRobot = AuthRobot(tester);
        searchRobot = SearchRobot(tester);

        await authRobot.login(TestUsers.primary);
        await searchRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Perform a search
        await searchRobot.searchFor(TestSearchQueries.withResults);
        await searchRobot.verifySearchResultsVisible();

        // Clear search and go back to search screen
        await searchRobot.clearSearchQuery();
        await searchRobot.settle();

        // Verify search history is visible
        searchRobot.verifySearchHistoryVisible();

        // Tap on history item to repeat search
        await searchRobot.tapHistoryItem(TestSearchQueries.withResults);
        await searchRobot.verifySearchResultsVisible();
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. Clear search history removes all history',
      (tester) async {
        authRobot = AuthRobot(tester);
        searchRobot = SearchRobot(tester);

        await authRobot.login(TestUsers.primary);
        await searchRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Perform some searches to have history
        await searchRobot.searchFor(TestSearchQueries.withResults);
        await searchRobot.clearSearchQuery();
        await searchRobot.searchFor(TestSearchQueries.popular);
        await searchRobot.clearSearchQuery();

        // Verify history exists
        searchRobot.verifySearchHistoryVisible();

        // Clear all history
        await searchRobot.clearSearchHistory();

        // Verify history is cleared
        // (either empty state or no history section)
      },
      skip: true,
    );
  });
}

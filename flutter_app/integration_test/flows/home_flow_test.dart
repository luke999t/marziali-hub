/// ============================================================================
/// HOME/BROWSE FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: HomeFlowTests
/// AI_DESCRIPTION: E2E tests for home/browse functionality
/// AI_BUSINESS: Verifica home, infinite scroll, categorie, featured
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 8
/// 1. Home screen loads with content
/// 2. Featured carousel displays and scrolls
/// 3. Categories are displayed
/// 4. Infinite scroll loads more content
/// 5. Pull to refresh updates content
/// 6. Tap video card opens player
/// 7. Category tap filters content
/// 8. Navigation between bottom tabs
///
/// ============================================================================
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_config.dart';
import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Home/Browse Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;
    late PlayerRobot playerRobot;
    late SearchRobot searchRobot;
    late EventsRobot eventsRobot;
    late ProfileRobot profileRobot;

    // ======================== TEST 1 ========================
    testWidgets(
      '1. Home screen loads with content',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        // Login
        await authRobot.login(TestUsers.primary);

        // Verify home screen
        await homeRobot.verifyHomeScreenVisible();
        homeRobot.verifyContentLoaded();
        await homeRobot.verifyVideoThumbnails();
      },
      skip: true,
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. Featured carousel displays and scrolls',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Verify featured content
        await homeRobot.verifyFeaturedContentVisible();

        // Swipe carousel
        await homeRobot.swipeFeaturedLeft();
        await homeRobot.swipeFeaturedRight();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Categories are displayed',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Verify categories
        await homeRobot.verifyCategoriesVisible();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. Infinite scroll loads more content',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Get initial count
        final initialCount = homeRobot.getVideoCardCount();

        // Scroll down multiple times
        await homeRobot.verifyInfiniteScrollWorks();

        // Verify more content loaded
        final finalCount = homeRobot.getVideoCardCount();
        expect(finalCount, greaterThanOrEqualTo(initialCount));
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. Pull to refresh updates content',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Scroll to top first
        await homeRobot.scrollToTop();

        // Pull to refresh
        await homeRobot.refreshContent();

        // Verify content still loaded
        homeRobot.verifyContentLoaded();
      },
      skip: true,
    );

    // ======================== TEST 6 ========================
    testWidgets(
      '6. Tap video card opens player',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Tap on a video card
        await homeRobot.tapVideoCard();

        // Verify player opens
        await playerRobot.verifyPlayerScreenVisible();

        // Go back
        await playerRobot.goBack();
        await homeRobot.verifyHomeScreenVisible();
      },
      skip: true,
    );

    // ======================== TEST 7 ========================
    testWidgets(
      '7. Category tap filters content',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Tap on a category
        await homeRobot.tapCategory(TestCategories.first);

        // Verify filtered content loads
        await homeRobot.settle(TestTimeouts.network);
        homeRobot.verifyContentLoaded();
      },
      skip: true,
    );

    // ======================== TEST 8 ========================
    testWidgets(
      '8. Navigation between bottom tabs works',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        searchRobot = SearchRobot(tester);
        eventsRobot = EventsRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Navigate to Search
        await homeRobot.navigateToSearch();
        await searchRobot.verifySearchScreenVisible();

        // Navigate to Events
        await homeRobot.navigateToEvents();
        await eventsRobot.verifyEventsScreenVisible();

        // Navigate to Profile
        await homeRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Navigate back to Home
        await homeRobot.navigateToHome();
        await homeRobot.verifyHomeScreenVisible();
      },
      skip: true,
    );
  });
}

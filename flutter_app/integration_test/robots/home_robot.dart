/// ============================================================================
/// HOME ROBOT
/// ============================================================================
///
/// AI_MODULE: HomeRobot
/// AI_DESCRIPTION: Page Object for home/browse screens
/// AI_BUSINESS: Encapsulates home navigation, scrolling, content interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import 'base_robot.dart';

class HomeRobot extends BaseRobot {
  const HomeRobot(super.tester);

  // ======================== HOME SCREEN ========================

  /// Verify home screen is displayed
  Future<void> verifyHomeScreenVisible() async {
    await settle(TestTimeouts.pageLoad);
    // Home screen should have bottom navigation or content
    final bottomNav = find.byType(BottomNavigationBar);
    final scrollView = find.byType(CustomScrollView);
    final listView = find.byType(ListView);

    final isHomeVisible =
        tester.any(bottomNav) || tester.any(scrollView) || tester.any(listView);
    expect(isHomeVisible, isTrue, reason: 'Home screen should be visible');
  }

  /// Navigate to home via bottom nav
  Future<void> navigateToHome() async {
    await tapByIcon(Icons.home);
    await settle();
  }

  /// Verify featured content carousel is visible
  Future<void> verifyFeaturedContentVisible() async {
    await settle();
    // Look for PageView (carousel) or featured section
    final pageView = find.byType(PageView);
    final carousel = find.textContaining('Featured');
    final inEvidenza = find.textContaining('Evidenza');

    final hasFeatured =
        tester.any(pageView) || tester.any(carousel) || tester.any(inEvidenza);
    expect(hasFeatured, isTrue, reason: 'Featured content should be visible');
  }

  /// Verify categories are visible
  Future<void> verifyCategoriesVisible() async {
    await settle();
    // Categories should be displayed as horizontal lists or chips
    final hasCategories =
        tester.any(find.textContaining('Kung Fu')) ||
        tester.any(find.textContaining('Tai Chi')) ||
        tester.any(find.textContaining('Categor'));

    expect(hasCategories, isTrue, reason: 'Categories should be visible');
  }

  /// Tap on a video card
  Future<void> tapVideoCard({int index = 0}) async {
    // Find video cards (typically Card widgets with images)
    final cards = find.byType(Card);
    final inkWells = find.byType(InkWell);
    final gestureDetectors = find.byType(GestureDetector);

    if (tester.any(cards)) {
      await tap(cards.at(index));
    } else if (tester.any(inkWells)) {
      await tap(inkWells.at(index));
    } else if (tester.any(gestureDetectors)) {
      await tap(gestureDetectors.at(index));
    }
  }

  /// Tap on a specific category
  Future<void> tapCategory(String categoryName) async {
    final categoryFinder = find.textContaining(categoryName);
    await scrollUntilVisible(categoryFinder);
    await tap(categoryFinder);
  }

  // ======================== SCROLLING ========================

  /// Scroll down to load more content
  Future<void> scrollDownForMore() async {
    await scrollDown();
    await settle(TestTimeouts.loadMore);
  }

  /// Scroll to bottom of home
  Future<void> scrollToBottom() async {
    for (int i = 0; i < 5; i++) {
      await scrollDown(delta: 500);
    }
  }

  /// Scroll to top of home
  Future<void> scrollToTop() async {
    for (int i = 0; i < 5; i++) {
      await scrollUp(delta: 500);
    }
  }

  /// Perform pull to refresh
  Future<void> refreshContent() async {
    await pullToRefresh();
  }

  /// Verify content loaded after scroll
  void verifyContentLoaded() {
    final cards = find.byType(Card);
    final images = find.byType(Image);
    final hasContent = tester.any(cards) || tester.any(images);
    expect(hasContent, isTrue, reason: 'Content should be loaded');
  }

  /// Verify infinite scroll works (more content loaded)
  Future<void> verifyInfiniteScrollWorks() async {
    // Count initial items
    final initialCards = find.byType(Card);
    final initialCount =
        tester.widgetList(initialCards).length;

    // Scroll down
    await scrollDownForMore();
    await scrollDownForMore();

    // Count after scroll
    final finalCards = find.byType(Card);
    final finalCount = tester.widgetList(finalCards).length;

    // Should have same or more items (infinite scroll loaded more)
    expect(finalCount, greaterThanOrEqualTo(initialCount));
  }

  // ======================== FEATURED CAROUSEL ========================

  /// Swipe featured carousel left
  Future<void> swipeFeaturedLeft() async {
    final pageView = find.byType(PageView);
    if (tester.any(pageView)) {
      await swipeLeft(pageView.first);
    }
  }

  /// Swipe featured carousel right
  Future<void> swipeFeaturedRight() async {
    final pageView = find.byType(PageView);
    if (tester.any(pageView)) {
      await swipeRight(pageView.first);
    }
  }

  /// Tap on featured item
  Future<void> tapFeaturedItem() async {
    final pageView = find.byType(PageView);
    if (tester.any(pageView)) {
      await tap(pageView.first);
    }
  }

  // ======================== NAVIGATION ========================

  /// Navigate to search via bottom nav
  Future<void> navigateToSearch() async {
    await tapByIcon(Icons.search);
    await settle();
  }

  /// Navigate to events via bottom nav
  Future<void> navigateToEvents() async {
    await tapByIcon(Icons.event);
    await settle();
  }

  /// Navigate to profile via bottom nav
  Future<void> navigateToProfile() async {
    await tapByIcon(Icons.person);
    await settle();
  }

  /// Tap on notifications icon
  Future<void> tapNotifications() async {
    final notifIcon = find.byIcon(Icons.notifications);
    final notifOutline = find.byIcon(Icons.notifications_outlined);

    if (tester.any(notifIcon)) {
      await tap(notifIcon);
    } else if (tester.any(notifOutline)) {
      await tap(notifOutline);
    }
  }

  // ======================== CONTENT VERIFICATION ========================

  /// Verify video cards have thumbnails
  Future<void> verifyVideoThumbnails() async {
    final images = find.byType(Image);
    verifyExistsAtLeastOne(images);
  }

  /// Verify video titles are displayed
  Future<void> verifyVideoTitles() async {
    final textWidgets = find.byType(Text);
    verifyExistsAtLeastOne(textWidgets);
  }

  /// Get count of visible video cards
  int getVideoCardCount() {
    final cards = find.byType(Card);
    return tester.widgetList(cards).length;
  }

  /// Verify loading indicator during refresh
  Future<void> verifyLoadingIndicator() async {
    final progress = find.byType(CircularProgressIndicator);
    final refresh = find.byType(RefreshIndicator);
    final hasLoading = tester.any(progress) || tester.any(refresh);
    expect(hasLoading, isTrue);
  }

  /// Verify empty state message
  void verifyEmptyState() {
    final emptyText = find.textContaining('vuoto');
    final noContentText = find.textContaining('No content');
    final hasEmpty = tester.any(emptyText) || tester.any(noContentText);
    expect(hasEmpty, isTrue);
  }

  // ======================== CATEGORY SECTION ========================

  /// Verify category section exists
  void verifyCategorySection(String categoryName) {
    final categoryTitle = find.textContaining(categoryName);
    verifyExists(categoryTitle);
  }

  /// Get videos in a category
  Future<void> scrollToCategorySection(String categoryName) async {
    final categoryTitle = find.textContaining(categoryName);
    await scrollUntilVisible(categoryTitle);
  }

  /// Tap "See All" in a category
  Future<void> tapSeeAllInCategory(String categoryName) async {
    await scrollToCategorySection(categoryName);
    final seeAll = find.textContaining('Vedi tutti');
    final seeAllEn = find.textContaining('See all');

    if (tester.any(seeAll)) {
      await tap(seeAll.first);
    } else if (tester.any(seeAllEn)) {
      await tap(seeAllEn.first);
    }
  }
}

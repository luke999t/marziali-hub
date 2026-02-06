/// ============================================================================
/// BASE ROBOT
/// ============================================================================
///
/// AI_MODULE: BaseRobot
/// AI_DESCRIPTION: Base class for Page Object pattern robots
/// AI_BUSINESS: Provides common functionality for all test robots
/// AI_TEACHING: Encapsulates widget finding and interaction logic
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';

/// Base robot class with common functionality
abstract class BaseRobot {
  final WidgetTester tester;

  const BaseRobot(this.tester);

  // ======================== FINDERS ========================

  /// Find widget by Key
  Finder findByKey(String key) => find.byKey(Key(key));

  /// Find widget by type
  Finder findByType<T>() => find.byType(T);

  /// Find widget by text
  Finder findByText(String text) => find.text(text);

  /// Find widget by text containing
  Finder findByTextContaining(String text) =>
      find.textContaining(text, findRichText: true);

  /// Find widget by icon
  Finder findByIcon(IconData icon) => find.byIcon(icon);

  /// Find widget by semantic label
  Finder findBySemanticsLabel(String label) => find.bySemanticsLabel(label);

  /// Find widget by tooltip
  Finder findByTooltip(String tooltip) => find.byTooltip(tooltip);

  // ======================== ACTIONS ========================

  /// Tap on a finder
  Future<void> tap(Finder finder, {bool settle = true}) async {
    await tester.tap(finder);
    if (settle) {
      await tester.pumpAndSettle(TestTimeouts.settle);
    } else {
      await tester.pump();
    }
  }

  /// Tap by key
  Future<void> tapByKey(String key, {bool settle = true}) async {
    await tap(findByKey(key), settle: settle);
  }

  /// Tap by text
  Future<void> tapByText(String text, {bool settle = true}) async {
    await tap(findByText(text), settle: settle);
  }

  /// Tap by icon
  Future<void> tapByIcon(IconData icon, {bool settle = true}) async {
    await tap(findByIcon(icon), settle: settle);
  }

  /// Enter text in a text field
  Future<void> enterText(Finder finder, String text) async {
    await tester.enterText(finder, text);
    await tester.pump();
  }

  /// Enter text by key
  Future<void> enterTextByKey(String key, String text) async {
    await enterText(findByKey(key), text);
  }

  /// Clear and enter text
  Future<void> clearAndEnterText(Finder finder, String text) async {
    await tester.enterText(finder, '');
    await tester.pump();
    await tester.enterText(finder, text);
    await tester.pump();
  }

  /// Scroll until widget is visible
  Future<void> scrollUntilVisible(
    Finder finder, {
    Finder? scrollable,
    double delta = 100,
    int maxScrolls = 50,
  }) async {
    final scrollableFinder = scrollable ?? find.byType(Scrollable).first;

    await tester.scrollUntilVisible(
      finder,
      delta,
      scrollable: scrollableFinder,
      maxScrolls: maxScrolls,
    );
    await tester.pumpAndSettle();
  }

  /// Scroll down in a scrollable
  Future<void> scrollDown({Finder? scrollable, double delta = 300}) async {
    final scrollableFinder = scrollable ?? find.byType(Scrollable).first;
    await tester.drag(scrollableFinder, Offset(0, -delta));
    await tester.pumpAndSettle();
  }

  /// Scroll up in a scrollable
  Future<void> scrollUp({Finder? scrollable, double delta = 300}) async {
    final scrollableFinder = scrollable ?? find.byType(Scrollable).first;
    await tester.drag(scrollableFinder, Offset(0, delta));
    await tester.pumpAndSettle();
  }

  /// Pull to refresh
  Future<void> pullToRefresh({Finder? scrollable}) async {
    final scrollableFinder = scrollable ?? find.byType(Scrollable).first;
    await tester.drag(scrollableFinder, const Offset(0, 300));
    await tester.pumpAndSettle(TestTimeouts.pullRefresh);
  }

  /// Swipe left
  Future<void> swipeLeft(Finder finder, {double distance = 300}) async {
    await tester.drag(finder, Offset(-distance, 0));
    await tester.pumpAndSettle();
  }

  /// Swipe right
  Future<void> swipeRight(Finder finder, {double distance = 300}) async {
    await tester.drag(finder, Offset(distance, 0));
    await tester.pumpAndSettle();
  }

  /// Long press
  Future<void> longPress(Finder finder) async {
    await tester.longPress(finder);
    await tester.pumpAndSettle();
  }

  /// Double tap
  Future<void> doubleTap(Finder finder) async {
    await tester.tap(finder);
    await tester.pump(const Duration(milliseconds: 50));
    await tester.tap(finder);
    await tester.pumpAndSettle();
  }

  // ======================== WAIT ========================

  /// Wait for widget to appear
  Future<void> waitForWidget(
    Finder finder, {
    Duration timeout = TestTimeouts.pageLoad,
  }) async {
    final endTime = DateTime.now().add(timeout);

    while (DateTime.now().isBefore(endTime)) {
      await tester.pump(const Duration(milliseconds: 100));
      if (tester.any(finder)) {
        await tester.pumpAndSettle();
        return;
      }
    }

    throw TestFailure('Widget not found within timeout: $finder');
  }

  /// Wait for widget by key
  Future<void> waitForKey(
    String key, {
    Duration timeout = TestTimeouts.pageLoad,
  }) async {
    await waitForWidget(findByKey(key), timeout: timeout);
  }

  /// Wait for text to appear
  Future<void> waitForText(
    String text, {
    Duration timeout = TestTimeouts.pageLoad,
  }) async {
    await waitForWidget(findByText(text), timeout: timeout);
  }

  /// Wait for widget to disappear
  Future<void> waitForWidgetToDisappear(
    Finder finder, {
    Duration timeout = TestTimeouts.pageLoad,
  }) async {
    final endTime = DateTime.now().add(timeout);

    while (DateTime.now().isBefore(endTime)) {
      await tester.pump(const Duration(milliseconds: 100));
      if (!tester.any(finder)) {
        return;
      }
    }

    throw TestFailure('Widget still visible after timeout: $finder');
  }

  /// Pump and settle with timeout
  Future<void> settle([Duration? timeout]) async {
    await tester.pumpAndSettle(timeout ?? TestTimeouts.settle);
  }

  /// Just pump
  Future<void> pump([Duration? duration]) async {
    await tester.pump(duration);
  }

  // ======================== ASSERTIONS ========================

  /// Verify widget exists
  void verifyExists(Finder finder) {
    expect(finder, findsOneWidget);
  }

  /// Verify widget does not exist
  void verifyNotExists(Finder finder) {
    expect(finder, findsNothing);
  }

  /// Verify multiple widgets exist
  void verifyExistsMultiple(Finder finder, int count) {
    expect(finder, findsNWidgets(count));
  }

  /// Verify at least one widget exists
  void verifyExistsAtLeastOne(Finder finder) {
    expect(finder, findsAtLeastNWidgets(1));
  }

  /// Verify text is visible
  void verifyTextVisible(String text) {
    expect(findByText(text), findsOneWidget);
  }

  /// Verify text is not visible
  void verifyTextNotVisible(String text) {
    expect(findByText(text), findsNothing);
  }

  /// Verify widget is enabled
  void verifyEnabled(Finder finder) {
    final widget = tester.widget(finder);
    if (widget is ElevatedButton) {
      expect(widget.onPressed, isNotNull);
    } else if (widget is TextButton) {
      expect(widget.onPressed, isNotNull);
    } else if (widget is IconButton) {
      expect(widget.onPressed, isNotNull);
    }
  }

  /// Verify widget is disabled
  void verifyDisabled(Finder finder) {
    final widget = tester.widget(finder);
    if (widget is ElevatedButton) {
      expect(widget.onPressed, isNull);
    } else if (widget is TextButton) {
      expect(widget.onPressed, isNull);
    } else if (widget is IconButton) {
      expect(widget.onPressed, isNull);
    }
  }

  /// Get text from a Text widget
  String? getTextContent(Finder finder) {
    final widget = tester.widget<Text>(finder);
    return widget.data;
  }

  /// Get widget state
  T getWidgetState<T extends State>(Finder finder) {
    final element = tester.element(finder);
    return (element as StatefulElement).state as T;
  }
}

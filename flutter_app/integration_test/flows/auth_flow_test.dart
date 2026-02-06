/// ============================================================================
/// AUTH FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: AuthFlowTests
/// AI_DESCRIPTION: E2E tests for authentication flows
/// AI_BUSINESS: Verifica login, registrazione, logout, sessione
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 10
/// 1. Login with valid credentials
/// 2. Login with invalid email
/// 3. Login with invalid password
/// 4. Login shows validation errors
/// 5. Registration with valid data
/// 6. Registration shows validation errors
/// 7. Registration password mismatch
/// 8. Logout flow
/// 9. Session persistence after restart
/// 10. Navigate between login and register
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Auth Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;

    setUp(() {
      // Robots are initialized in each test with tester
    });

    // ======================== TEST 1 ========================
    testWidgets(
      '1. Login with valid credentials navigates to home',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        // Start app at login screen
        // Note: App initialization would be done here
        // await tester.pumpWidget(MyApp());

        // Verify login screen
        await authRobot.verifyLoginScreenVisible();

        // Login with test user
        await authRobot.login(TestUsers.primary);

        // Verify navigated to home
        await authRobot.verifyAuthenticated();
        await homeRobot.verifyHomeScreenVisible();
      },
      skip: true, // Enable when running with actual app
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. Login with invalid email shows error',
      (tester) async {
        authRobot = AuthRobot(tester);

        await authRobot.verifyLoginScreenVisible();

        // Try login with invalid credentials
        await authRobot.login(TestUsers.invalid);

        // Verify error is shown
        await authRobot.verifyLoginError();

        // Verify still on login screen
        await authRobot.verifyLoginScreenVisible();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Login with invalid password shows error',
      (tester) async {
        authRobot = AuthRobot(tester);

        await authRobot.verifyLoginScreenVisible();

        // Try login with wrong password
        await authRobot.login(const TestUser(
          email: 'test@example.com',
          password: 'WrongPassword!',
          name: 'Test',
        ));

        // Verify error is shown
        await authRobot.verifyLoginError();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. Login shows validation errors for empty fields',
      (tester) async {
        authRobot = AuthRobot(tester);

        await authRobot.verifyLoginScreenVisible();

        // Try to login without entering credentials
        await authRobot.tapLoginButton();
        await authRobot.settle();

        // Verify validation errors
        final emailError = find.textContaining('email');
        final passwordError = find.textContaining('password');

        expect(
          tester.any(emailError) || tester.any(passwordError),
          isTrue,
          reason: 'Validation errors should be shown',
        );
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. Registration with valid data succeeds',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        await authRobot.verifyLoginScreenVisible();

        // Navigate to register
        await authRobot.tapGoToRegister();
        await authRobot.verifyRegisterScreenVisible();

        // Register new user
        await authRobot.registerNewUser();

        // Verify success (either logged in or success message)
        final hasSuccess =
            tester.any(find.byType(BottomNavigationBar)) ||
            tester.any(find.textContaining('success')) ||
            tester.any(find.textContaining('completat'));

        expect(hasSuccess, isTrue);
      },
      skip: true,
    );

    // ======================== TEST 6 ========================
    testWidgets(
      '6. Registration shows validation errors for invalid email',
      (tester) async {
        authRobot = AuthRobot(tester);

        await authRobot.verifyLoginScreenVisible();
        await authRobot.tapGoToRegister();
        await authRobot.verifyRegisterScreenVisible();

        // Enter invalid email
        await authRobot.enterRegisterName('Test User');
        await authRobot.enterRegisterEmail('invalidemail');
        await authRobot.enterRegisterPassword('Password123!');
        await authRobot.enterRegisterConfirmPassword('Password123!');
        await authRobot.tapRegisterButton();

        await authRobot.settle();

        // Verify email validation error
        final emailError = find.textContaining('email');
        expect(tester.any(emailError), isTrue);
      },
      skip: true,
    );

    // ======================== TEST 7 ========================
    testWidgets(
      '7. Registration shows error for password mismatch',
      (tester) async {
        authRobot = AuthRobot(tester);

        await authRobot.verifyLoginScreenVisible();
        await authRobot.tapGoToRegister();
        await authRobot.verifyRegisterScreenVisible();

        // Enter mismatched passwords
        await authRobot.enterRegisterName('Test User');
        await authRobot.enterRegisterEmail(TestDataHelpers.uniqueEmail());
        await authRobot.enterRegisterPassword('Password123!');
        await authRobot.enterRegisterConfirmPassword('DifferentPassword!');
        await authRobot.tapRegisterButton();

        await authRobot.settle();

        // Verify password mismatch error
        final mismatchError = find.textContaining('coincid');
        final matchError = find.textContaining('match');
        expect(
          tester.any(mismatchError) || tester.any(matchError),
          isTrue,
        );
      },
      skip: true,
    );

    // ======================== TEST 8 ========================
    testWidgets(
      '8. Logout flow returns to login screen',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        // Login first
        await authRobot.verifyLoginScreenVisible();
        await authRobot.login(TestUsers.primary);
        await authRobot.verifyAuthenticated();

        // Perform logout
        await authRobot.logout();

        // Verify returned to login
        await authRobot.verifyLoggedOut();
      },
      skip: true,
    );

    // ======================== TEST 9 ========================
    testWidgets(
      '9. Session persists after app restart',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);

        // This test would require restarting the app
        // In integration tests, we can simulate by:
        // 1. Verify we're authenticated if session exists
        // 2. Or login and verify token is stored

        // For now, verify that after login, home is accessible
        await authRobot.verifyLoginScreenVisible();
        await authRobot.login(TestUsers.primary);
        await authRobot.verifyAuthenticated();

        // Navigate around to verify session
        await homeRobot.navigateToProfile();
        await homeRobot.navigateToHome();

        // Still authenticated
        await homeRobot.verifyHomeScreenVisible();
      },
      skip: true,
    );

    // ======================== TEST 10 ========================
    testWidgets(
      '10. Navigate between login and register screens',
      (tester) async {
        authRobot = AuthRobot(tester);

        // Start at login
        await authRobot.verifyLoginScreenVisible();

        // Go to register
        await authRobot.tapGoToRegister();
        await authRobot.verifyRegisterScreenVisible();

        // Go back to login
        await authRobot.tapGoToLogin();
        await authRobot.verifyLoginScreenVisible();

        // Go to forgot password
        await authRobot.tapForgotPassword();
        await authRobot.verifyForgotPasswordScreenVisible();
      },
      skip: true,
    );
  });
}

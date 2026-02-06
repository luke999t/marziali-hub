/// ============================================================================
/// AUTH ROBOT
/// ============================================================================
///
/// AI_MODULE: AuthRobot
/// AI_DESCRIPTION: Page Object for authentication screens
/// AI_BUSINESS: Encapsulates login, register, logout interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import '../helpers/test_data.dart';
import 'base_robot.dart';

class AuthRobot extends BaseRobot {
  const AuthRobot(super.tester);

  // ======================== LOGIN SCREEN ========================

  /// Verify login screen is displayed
  Future<void> verifyLoginScreenVisible() async {
    await waitForText('Login', timeout: TestTimeouts.pageLoad);
    verifyTextVisible('Login');
  }

  /// Enter email on login screen
  Future<void> enterLoginEmail(String email) async {
    final emailField = find.byType(TextField).first;
    await enterText(emailField, email);
  }

  /// Enter password on login screen
  Future<void> enterLoginPassword(String password) async {
    final passwordFields = find.byType(TextField);
    // Password is typically the second TextField
    await enterText(passwordFields.at(1), password);
  }

  /// Tap login button
  Future<void> tapLoginButton() async {
    // Find button with "Login" or "Accedi" text
    final loginButton = find.widgetWithText(ElevatedButton, 'Login');
    final accediButton = find.widgetWithText(ElevatedButton, 'Accedi');

    if (tester.any(loginButton)) {
      await tap(loginButton);
    } else if (tester.any(accediButton)) {
      await tap(accediButton);
    } else {
      // Try finding any ElevatedButton
      await tap(find.byType(ElevatedButton).first);
    }
  }

  /// Perform complete login flow
  Future<void> login(TestUser user) async {
    await verifyLoginScreenVisible();
    await enterLoginEmail(user.email);
    await enterLoginPassword(user.password);
    await tapLoginButton();
    await settle(TestTimeouts.authFlow);
  }

  /// Login with test user
  Future<void> loginWithTestUser() async {
    await login(TestUsers.primary);
  }

  /// Verify login error is shown
  Future<void> verifyLoginError() async {
    // Look for error indicators
    final errorFinder = find.byType(SnackBar);
    final errorTextFinder = find.textContaining('error', findRichText: true);
    final erroreTextFinder = find.textContaining('errore', findRichText: true);

    final hasError = tester.any(errorFinder) ||
        tester.any(errorTextFinder) ||
        tester.any(erroreTextFinder);

    expect(hasError, isTrue, reason: 'Expected login error to be shown');
  }

  /// Tap "Forgot Password" link
  Future<void> tapForgotPassword() async {
    final forgotPassword = find.textContaining('Password');
    await tap(forgotPassword);
  }

  /// Tap "Register" link
  Future<void> tapGoToRegister() async {
    final registerLink = find.textContaining('Registr');
    await tap(registerLink);
  }

  // ======================== REGISTER SCREEN ========================

  /// Verify register screen is displayed
  Future<void> verifyRegisterScreenVisible() async {
    await waitForText('Registr', timeout: TestTimeouts.pageLoad);
  }

  /// Enter name on register screen
  Future<void> enterRegisterName(String name) async {
    final nameField = find.byType(TextField).first;
    await enterText(nameField, name);
  }

  /// Enter email on register screen
  Future<void> enterRegisterEmail(String email) async {
    final emailField = find.byType(TextField).at(1);
    await enterText(emailField, email);
  }

  /// Enter password on register screen
  Future<void> enterRegisterPassword(String password) async {
    final passwordField = find.byType(TextField).at(2);
    await enterText(passwordField, password);
  }

  /// Enter confirm password on register screen
  Future<void> enterRegisterConfirmPassword(String password) async {
    final confirmField = find.byType(TextField).at(3);
    await enterText(confirmField, password);
  }

  /// Tap register button
  Future<void> tapRegisterButton() async {
    final registerButton = find.widgetWithText(ElevatedButton, 'Registra');
    final signupButton = find.widgetWithText(ElevatedButton, 'Sign Up');
    final createButton = find.widgetWithText(ElevatedButton, 'Crea');

    if (tester.any(registerButton)) {
      await tap(registerButton);
    } else if (tester.any(signupButton)) {
      await tap(signupButton);
    } else if (tester.any(createButton)) {
      await tap(createButton);
    } else {
      await tap(find.byType(ElevatedButton).first);
    }
  }

  /// Perform complete registration flow
  Future<void> register(TestUser user) async {
    await verifyRegisterScreenVisible();
    await enterRegisterName(user.name);
    await enterRegisterEmail(user.email);
    await enterRegisterPassword(user.password);
    await enterRegisterConfirmPassword(user.password);
    await tapRegisterButton();
    await settle(TestTimeouts.authFlow);
  }

  /// Register with new unique user
  Future<void> registerNewUser() async {
    final newUser = TestUsers.newUser();
    await register(newUser);
  }

  /// Verify registration error is shown
  Future<void> verifyRegisterError() async {
    await settle();
    final hasSnackbar = tester.any(find.byType(SnackBar));
    final hasErrorText = tester.any(find.textContaining('error'));
    expect(hasSnackbar || hasErrorText, isTrue);
  }

  /// Tap "Go to Login" link
  Future<void> tapGoToLogin() async {
    final loginLink = find.textContaining('Login');
    await tap(loginLink);
  }

  // ======================== FORGOT PASSWORD ========================

  /// Verify forgot password screen is displayed
  Future<void> verifyForgotPasswordScreenVisible() async {
    await waitForText('Password', timeout: TestTimeouts.pageLoad);
  }

  /// Enter email for password reset
  Future<void> enterResetEmail(String email) async {
    final emailField = find.byType(TextField).first;
    await enterText(emailField, email);
  }

  /// Tap send reset link button
  Future<void> tapSendResetLink() async {
    await tap(find.byType(ElevatedButton).first);
  }

  /// Perform password reset request
  Future<void> requestPasswordReset(String email) async {
    await verifyForgotPasswordScreenVisible();
    await enterResetEmail(email);
    await tapSendResetLink();
    await settle();
  }

  // ======================== LOGOUT ========================

  /// Perform logout from profile screen
  Future<void> logout() async {
    // Navigate to profile first
    await tapByIcon(Icons.person);
    await settle();

    // Find and tap logout button
    final logoutButton = find.textContaining('Logout');
    final esciButton = find.textContaining('Esci');

    if (tester.any(logoutButton)) {
      await scrollUntilVisible(logoutButton);
      await tap(logoutButton);
    } else if (tester.any(esciButton)) {
      await scrollUntilVisible(esciButton);
      await tap(esciButton);
    }

    // Confirm logout if dialog appears
    final confirmButton = find.textContaining('Conferma');
    final yesButton = find.text('Sì');
    if (tester.any(confirmButton)) {
      await tap(confirmButton);
    } else if (tester.any(yesButton)) {
      await tap(yesButton);
    }

    await settle(TestTimeouts.authFlow);
  }

  /// Verify redirected to login after logout
  Future<void> verifyLoggedOut() async {
    await verifyLoginScreenVisible();
  }

  // ======================== SESSION ========================

  /// Verify user is authenticated (home screen visible)
  Future<void> verifyAuthenticated() async {
    // After login, should see home or main content
    final homeFinder = find.byIcon(Icons.home);
    final bottomNavFinder = find.byType(BottomNavigationBar);

    await settle(TestTimeouts.pageLoad);

    final isAuthenticated =
        tester.any(homeFinder) || tester.any(bottomNavFinder);
    expect(isAuthenticated, isTrue,
        reason: 'User should be authenticated and see home');
  }

  /// Verify user is not authenticated (on login screen)
  Future<void> verifyNotAuthenticated() async {
    await verifyLoginScreenVisible();
  }
}

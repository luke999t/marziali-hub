/// ============================================================================
/// PROFILE FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: ProfileFlowTests
/// AI_DESCRIPTION: E2E tests for profile management flows
/// AI_BUSINESS: Verifica profilo, modifica, cronologia, preferiti
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 8
/// 1. View profile displays user info
/// 2. Edit profile and save changes
/// 3. Change avatar
/// 4. View watch history
/// 5. View favorites list
/// 6. Navigate to settings
/// 7. Change password
/// 8. Clear watch history
///
/// ============================================================================
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Profile Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;
    late ProfileRobot profileRobot;

    // ======================== TEST 1 ========================
    testWidgets(
      '1. View profile displays user information',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        profileRobot = ProfileRobot(tester);

        // Login
        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Navigate to profile
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Verify user info is displayed
        profileRobot.verifyAvatarDisplayed();
        profileRobot.verifyUserNameDisplayed(TestUsers.primary.name);
      },
      skip: true,
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. Edit profile and save changes',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Tap edit profile
        await profileRobot.tapEditProfile();
        await profileRobot.verifyEditProfileScreenVisible();

        // Update name
        await profileRobot.updateName(TestProfileData.newName);

        // Update bio
        await profileRobot.updateBio(TestProfileData.newBio);

        // Save
        await profileRobot.saveProfile();

        // Verify success
        await profileRobot.verifyProfileUpdateSuccess();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Change avatar opens picker',
      (tester) async {
        authRobot = AuthRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();

        // Tap edit profile
        await profileRobot.tapEditProfile();
        await profileRobot.verifyEditProfileScreenVisible();

        // Tap change avatar
        await profileRobot.tapChangeAvatar();

        // Verify avatar picker options appear
        profileRobot.verifyAvatarPickerVisible();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. View watch history shows viewed videos',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        profileRobot = ProfileRobot(tester);
        final playerRobot = PlayerRobot(tester);

        // Login and watch a video first
        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Watch a video briefly
        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.pump(const Duration(seconds: 2));
        await playerRobot.goBack();

        // Navigate to profile
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Navigate to watch history
        await profileRobot.navigateToWatchHistory();
        await profileRobot.verifyWatchHistoryVisible();
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. View favorites list',
      (tester) async {
        authRobot = AuthRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Navigate to favorites
        await profileRobot.navigateToFavorites();
        await profileRobot.verifyFavoritesVisible();
      },
      skip: true,
    );

    // ======================== TEST 6 ========================
    testWidgets(
      '6. Navigate to settings screen',
      (tester) async {
        authRobot = AuthRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Navigate to settings
        await profileRobot.navigateToSettings();
        await profileRobot.verifySettingsScreenVisible();

        // Toggle a setting
        await profileRobot.toggleSetting('Notifiche');
      },
      skip: true,
    );

    // ======================== TEST 7 ========================
    testWidgets(
      '7. Change password flow',
      (tester) async {
        authRobot = AuthRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();
        await profileRobot.navigateToSettings();

        // Navigate to change password
        await profileRobot.navigateToChangePassword();

        // Change password
        await profileRobot.changePassword(
          currentPassword: TestProfileData.currentPassword,
          newPassword: TestProfileData.newPassword,
        );

        // Note: In real test, we might want to revert the password
        // or use a test-specific user for this
      },
      skip: true,
    );

    // ======================== TEST 8 ========================
    testWidgets(
      '8. Clear watch history',
      (tester) async {
        authRobot = AuthRobot(tester);
        profileRobot = ProfileRobot(tester);

        await authRobot.login(TestUsers.primary);
        await profileRobot.navigateToProfile();
        await profileRobot.verifyProfileScreenVisible();

        // Navigate to watch history
        await profileRobot.navigateToWatchHistory();
        await profileRobot.verifyWatchHistoryVisible();

        // Clear history
        await profileRobot.clearWatchHistory();

        // Verify history is empty or cleared message shown
        // (depends on implementation)
      },
      skip: true,
    );
  });
}

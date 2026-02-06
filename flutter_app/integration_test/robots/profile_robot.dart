/// ============================================================================
/// PROFILE ROBOT
/// ============================================================================
///
/// AI_MODULE: ProfileRobot
/// AI_DESCRIPTION: Page Object for profile screens
/// AI_BUSINESS: Encapsulates profile view, edit, settings interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import 'base_robot.dart';

class ProfileRobot extends BaseRobot {
  const ProfileRobot(super.tester);

  // ======================== PROFILE SCREEN ========================

  /// Navigate to profile screen
  Future<void> navigateToProfile() async {
    await tapByIcon(Icons.person);
    await settle(TestTimeouts.pageLoad);
  }

  /// Verify profile screen is displayed
  Future<void> verifyProfileScreenVisible() async {
    await settle(TestTimeouts.pageLoad);
    // Profile should show user info and options
    final profileAvatar = find.byType(CircleAvatar);
    final profileIcon = find.byIcon(Icons.person);
    final accountIcon = find.byIcon(Icons.account_circle);

    final isProfileVisible = tester.any(profileAvatar) ||
        tester.any(profileIcon) ||
        tester.any(accountIcon);

    expect(isProfileVisible, isTrue, reason: 'Profile screen should be visible');
  }

  /// Verify user name is displayed
  void verifyUserNameDisplayed(String name) {
    final nameFinder = find.textContaining(name);
    verifyExists(nameFinder);
  }

  /// Verify user email is displayed
  void verifyUserEmailDisplayed(String email) {
    final emailFinder = find.textContaining(email);
    verifyExists(emailFinder);
  }

  /// Verify avatar is displayed
  void verifyAvatarDisplayed() {
    final avatar = find.byType(CircleAvatar);
    verifyExists(avatar);
  }

  // ======================== EDIT PROFILE ========================

  /// Tap edit profile button
  Future<void> tapEditProfile() async {
    final editButton = find.byIcon(Icons.edit);
    final modifyText = find.textContaining('Modifica');
    final editText = find.textContaining('Edit');

    if (tester.any(editButton)) {
      await tap(editButton.first);
    } else if (tester.any(modifyText)) {
      await tap(modifyText.first);
    } else if (tester.any(editText)) {
      await tap(editText.first);
    }
    await settle();
  }

  /// Verify edit profile screen is displayed
  Future<void> verifyEditProfileScreenVisible() async {
    await settle();
    final textFields = find.byType(TextField);
    final textFormFields = find.byType(TextFormField);
    final hasEditFields = tester.any(textFields) || tester.any(textFormFields);
    expect(hasEditFields, isTrue, reason: 'Edit profile fields should be visible');
  }

  /// Update name in edit profile
  Future<void> updateName(String newName) async {
    final nameField = find.byType(TextField).first;
    await clearAndEnterText(nameField, newName);
  }

  /// Update bio in edit profile
  Future<void> updateBio(String newBio) async {
    // Bio is typically the second or third field
    final fields = find.byType(TextField);
    if (tester.widgetList(fields).length > 1) {
      await clearAndEnterText(fields.at(1), newBio);
    }
  }

  /// Save profile changes
  Future<void> saveProfile() async {
    final saveButton = find.textContaining('Salva');
    final saveEn = find.textContaining('Save');
    final confirmButton = find.textContaining('Conferma');

    if (tester.any(saveButton)) {
      await tap(saveButton.first);
    } else if (tester.any(saveEn)) {
      await tap(saveEn.first);
    } else if (tester.any(confirmButton)) {
      await tap(confirmButton.first);
    } else {
      // Try elevated button
      await tap(find.byType(ElevatedButton).first);
    }
    await settle();
  }

  /// Cancel edit profile
  Future<void> cancelEdit() async {
    final cancelButton = find.textContaining('Annulla');
    final cancelEn = find.textContaining('Cancel');

    if (tester.any(cancelButton)) {
      await tap(cancelButton.first);
    } else if (tester.any(cancelEn)) {
      await tap(cancelEn.first);
    } else {
      await goBack();
    }
    await settle();
  }

  /// Verify profile update success
  Future<void> verifyProfileUpdateSuccess() async {
    await settle();
    final successSnackbar = find.byType(SnackBar);
    final successText = find.textContaining('aggiornato');
    final successEn = find.textContaining('updated');

    final hasSuccess = tester.any(successSnackbar) ||
        tester.any(successText) ||
        tester.any(successEn);
    expect(hasSuccess, isTrue, reason: 'Profile update success message expected');
  }

  // ======================== AVATAR ========================

  /// Tap on avatar to change
  Future<void> tapChangeAvatar() async {
    final avatar = find.byType(CircleAvatar);
    final cameraIcon = find.byIcon(Icons.camera_alt);
    final photoIcon = find.byIcon(Icons.photo);

    if (tester.any(cameraIcon)) {
      await tap(cameraIcon.first);
    } else if (tester.any(photoIcon)) {
      await tap(photoIcon.first);
    } else if (tester.any(avatar)) {
      await tap(avatar.first);
    }
    await settle();
  }

  /// Verify avatar picker options
  void verifyAvatarPickerVisible() {
    final gallery = find.textContaining('Galleria');
    final camera = find.textContaining('Camera');
    final photo = find.textContaining('Photo');

    final hasOptions =
        tester.any(gallery) || tester.any(camera) || tester.any(photo);
    expect(hasOptions, isTrue);
  }

  /// Select gallery option for avatar
  Future<void> selectGallery() async {
    final gallery = find.textContaining('Galleria');
    final photo = find.textContaining('Photo');

    if (tester.any(gallery)) {
      await tap(gallery.first);
    } else if (tester.any(photo)) {
      await tap(photo.first);
    }
    await settle();
  }

  // ======================== WATCH HISTORY ========================

  /// Navigate to watch history
  Future<void> navigateToWatchHistory() async {
    final historyButton = find.textContaining('Cronologia');
    final historyEn = find.textContaining('History');
    final watchedText = find.textContaining('Visti');

    if (tester.any(historyButton)) {
      await scrollUntilVisible(historyButton);
      await tap(historyButton.first);
    } else if (tester.any(historyEn)) {
      await scrollUntilVisible(historyEn);
      await tap(historyEn.first);
    } else if (tester.any(watchedText)) {
      await scrollUntilVisible(watchedText);
      await tap(watchedText.first);
    }
    await settle();
  }

  /// Verify watch history screen visible
  Future<void> verifyWatchHistoryVisible() async {
    await settle();
    final listView = find.byType(ListView);
    final gridView = find.byType(GridView);
    final hasContent = tester.any(listView) || tester.any(gridView);
    expect(hasContent, isTrue);
  }

  /// Clear watch history
  Future<void> clearWatchHistory() async {
    final clearButton = find.textContaining('Cancella');
    final clearEn = find.textContaining('Clear');

    if (tester.any(clearButton)) {
      await tap(clearButton.first);
    } else if (tester.any(clearEn)) {
      await tap(clearEn.first);
    }
    await settle();

    // Confirm clear
    final confirm = find.textContaining('Conferma');
    final yes = find.text('Sì');
    if (tester.any(confirm)) {
      await tap(confirm.first);
    } else if (tester.any(yes)) {
      await tap(yes.first);
    }
    await settle();
  }

  // ======================== FAVORITES ========================

  /// Navigate to favorites
  Future<void> navigateToFavorites() async {
    final favoritesButton = find.textContaining('Preferiti');
    final favoritesEn = find.textContaining('Favorites');
    final heartIcon = find.byIcon(Icons.favorite);

    if (tester.any(favoritesButton)) {
      await scrollUntilVisible(favoritesButton);
      await tap(favoritesButton.first);
    } else if (tester.any(favoritesEn)) {
      await scrollUntilVisible(favoritesEn);
      await tap(favoritesEn.first);
    } else if (tester.any(heartIcon)) {
      await tap(heartIcon.first);
    }
    await settle();
  }

  /// Verify favorites screen visible
  Future<void> verifyFavoritesVisible() async {
    await settle();
    final listView = find.byType(ListView);
    final gridView = find.byType(GridView);
    final emptyText = find.textContaining('vuoto');
    final hasContent =
        tester.any(listView) || tester.any(gridView) || tester.any(emptyText);
    expect(hasContent, isTrue);
  }

  /// Verify empty favorites message
  void verifyEmptyFavorites() {
    final emptyText = find.textContaining('vuoto');
    final noFavorites = find.textContaining('No favorites');
    final hasEmpty = tester.any(emptyText) || tester.any(noFavorites);
    expect(hasEmpty, isTrue);
  }

  // ======================== SETTINGS ========================

  /// Navigate to settings
  Future<void> navigateToSettings() async {
    final settingsButton = find.byIcon(Icons.settings);
    final settingsText = find.textContaining('Impostazioni');
    final settingsEn = find.textContaining('Settings');

    if (tester.any(settingsButton)) {
      await tap(settingsButton.first);
    } else if (tester.any(settingsText)) {
      await scrollUntilVisible(settingsText);
      await tap(settingsText.first);
    } else if (tester.any(settingsEn)) {
      await scrollUntilVisible(settingsEn);
      await tap(settingsEn.first);
    }
    await settle();
  }

  /// Verify settings screen visible
  Future<void> verifySettingsScreenVisible() async {
    await settle();
    // Settings should have switches or list tiles
    final switches = find.byType(Switch);
    final listTiles = find.byType(ListTile);
    final hasSettings = tester.any(switches) || tester.any(listTiles);
    expect(hasSettings, isTrue);
  }

  /// Toggle a setting switch
  Future<void> toggleSetting(String settingName) async {
    final settingTile = find.ancestor(
      of: find.textContaining(settingName),
      matching: find.byType(ListTile),
    );

    if (tester.any(settingTile)) {
      final switchWidget = find.descendant(
        of: settingTile,
        matching: find.byType(Switch),
      );
      if (tester.any(switchWidget)) {
        await tap(switchWidget.first);
      }
    }
    await settle();
  }

  /// Navigate to change password
  Future<void> navigateToChangePassword() async {
    final changePassword = find.textContaining('Password');
    await scrollUntilVisible(changePassword);
    await tap(changePassword.first);
    await settle();
  }

  /// Change password
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    final fields = find.byType(TextField);

    // Enter current password
    await enterText(fields.at(0), currentPassword);
    // Enter new password
    await enterText(fields.at(1), newPassword);
    // Confirm new password
    await enterText(fields.at(2), newPassword);

    // Save
    await tap(find.byType(ElevatedButton).first);
    await settle();
  }

  // ======================== LOGOUT ========================

  /// Tap logout button
  Future<void> tapLogout() async {
    final logoutButton = find.textContaining('Logout');
    final esciButton = find.textContaining('Esci');
    final exitIcon = find.byIcon(Icons.exit_to_app);

    if (tester.any(logoutButton)) {
      await scrollUntilVisible(logoutButton);
      await tap(logoutButton.first);
    } else if (tester.any(esciButton)) {
      await scrollUntilVisible(esciButton);
      await tap(esciButton.first);
    } else if (tester.any(exitIcon)) {
      await tap(exitIcon.first);
    }
    await settle();
  }

  /// Confirm logout in dialog
  Future<void> confirmLogout() async {
    final confirmButton = find.textContaining('Conferma');
    final yesButton = find.text('Sì');
    final logoutConfirm = find.textContaining('Logout');

    if (tester.any(confirmButton)) {
      await tap(confirmButton.first);
    } else if (tester.any(yesButton)) {
      await tap(yesButton.first);
    } else if (tester.any(logoutConfirm)) {
      await tap(logoutConfirm.last);
    }
    await settle(TestTimeouts.authFlow);
  }

  /// Cancel logout
  Future<void> cancelLogout() async {
    final cancelButton = find.textContaining('Annulla');
    final noButton = find.text('No');

    if (tester.any(cancelButton)) {
      await tap(cancelButton.first);
    } else if (tester.any(noButton)) {
      await tap(noButton.first);
    }
    await settle();
  }

  // ======================== NAVIGATION ========================

  /// Go back from any profile sub-screen
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

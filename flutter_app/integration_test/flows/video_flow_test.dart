/// ============================================================================
/// VIDEO PLAYER FLOW TESTS
/// ============================================================================
///
/// AI_MODULE: VideoFlowTests
/// AI_DESCRIPTION: E2E tests for video player functionality
/// AI_BUSINESS: Verifica playback, controlli, skeleton overlay
/// AI_TEACHING: ZERO MOCK - test con backend reale
///
/// Test Count: 12
/// 1. Open video from home screen
/// 2. Play and pause video
/// 3. Seek forward 10 seconds
/// 4. Seek backward 10 seconds
/// 5. Seek using progress bar
/// 6. Toggle fullscreen mode
/// 7. Change video quality
/// 8. Toggle skeleton overlay
/// 9. Skeleton overlay syncs with video
/// 10. Mute and unmute video
/// 11. Download video for offline
/// 12. Navigate back from player
///
/// ============================================================================
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../helpers/test_data.dart';
import '../robots/robots.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Video Player Flow Tests', () {
    late AuthRobot authRobot;
    late HomeRobot homeRobot;
    late PlayerRobot playerRobot;

    // ======================== TEST 1 ========================
    testWidgets(
      '1. Open video from home screen displays player',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        // Login first
        await authRobot.verifyLoginScreenVisible();
        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Tap on first video
        await homeRobot.tapVideoCard();

        // Verify player is displayed
        await playerRobot.verifyPlayerScreenVisible();
        await playerRobot.waitForVideoToLoad();
      },
      skip: true,
    );

    // ======================== TEST 2 ========================
    testWidgets(
      '2. Play and pause video works correctly',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        // Navigate to player
        await authRobot.login(TestUsers.primary);
        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();

        // Show controls
        await playerRobot.showControls();

        // Tap play
        await playerRobot.tapPlay();
        playerRobot.verifyVideoPlaying();

        // Wait a moment
        await playerRobot.pump(const Duration(seconds: 2));

        // Tap pause
        await playerRobot.showControls();
        await playerRobot.tapPause();
        playerRobot.verifyVideoPaused();
      },
      skip: true,
    );

    // ======================== TEST 3 ========================
    testWidgets(
      '3. Seek forward 10 seconds',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        // Assume already at player
        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Seek forward
        await playerRobot.seekForward();

        // Verify controls still visible
        playerRobot.verifyControlsVisible();
      },
      skip: true,
    );

    // ======================== TEST 4 ========================
    testWidgets(
      '4. Seek backward 10 seconds',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // First seek forward to have room to seek back
        await playerRobot.seekForward();
        await playerRobot.seekForward();

        // Now seek backward
        await playerRobot.seekBackward();

        playerRobot.verifyControlsVisible();
      },
      skip: true,
    );

    // ======================== TEST 5 ========================
    testWidgets(
      '5. Seek using progress bar',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Seek to 50% position
        await playerRobot.seekToPosition(0.5);

        // Verify video is still playable
        playerRobot.verifyControlsVisible();
      },
      skip: true,
    );

    // ======================== TEST 6 ========================
    testWidgets(
      '6. Toggle fullscreen mode',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Enter fullscreen
        await playerRobot.toggleFullscreen();
        playerRobot.verifyFullscreenActive();

        // Exit fullscreen
        await playerRobot.showControls();
        await playerRobot.exitFullscreen();
      },
      skip: true,
    );

    // ======================== TEST 7 ========================
    testWidgets(
      '7. Change video quality',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Open quality settings
        await playerRobot.openQualitySettings();
        playerRobot.verifyQualityOptionsVisible();

        // Select a quality option
        await playerRobot.selectQuality('720');

        // Verify video continues playing
        await playerRobot.showControls();
        playerRobot.verifyControlsVisible();
      },
      skip: true,
    );

    // ======================== TEST 8 ========================
    testWidgets(
      '8. Toggle skeleton overlay',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Enable skeleton overlay
        await playerRobot.toggleSkeletonOverlay();
        await playerRobot.verifySkeletonOverlayVisible();

        // Disable skeleton overlay
        await playerRobot.showControls();
        await playerRobot.toggleSkeletonOverlay();
        playerRobot.verifySkeletonOverlayHidden();
      },
      skip: true,
    );

    // ======================== TEST 9 ========================
    testWidgets(
      '9. Skeleton overlay syncs with video playback',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        // Find a video with skeleton data
        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Enable skeleton overlay
        await playerRobot.toggleSkeletonOverlay();
        await playerRobot.verifySkeletonOverlayVisible();

        // Play video and verify skeleton updates
        await playerRobot.showControls();
        await playerRobot.tapPlay();
        await playerRobot.pump(const Duration(seconds: 2));

        // Skeleton should still be visible
        await playerRobot.verifySkeletonOverlayVisible();

        // Pause
        await playerRobot.showControls();
        await playerRobot.tapPause();
      },
      skip: true,
    );

    // ======================== TEST 10 ========================
    testWidgets(
      '10. Mute and unmute video',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Mute video
        await playerRobot.mute();
        playerRobot.verifyMuted();

        // Unmute video
        await playerRobot.showControls();
        await playerRobot.unmute();
      },
      skip: true,
    );

    // ======================== TEST 11 ========================
    testWidgets(
      '11. Download video for offline viewing',
      (tester) async {
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await homeRobot.tapVideoCard();
        await playerRobot.waitForVideoToLoad();
        await playerRobot.showControls();

        // Tap download
        await playerRobot.tapDownload();

        // Verify download started
        playerRobot.verifyDownloadStarted();
      },
      skip: true,
    );

    // ======================== TEST 12 ========================
    testWidgets(
      '12. Navigate back from player returns to previous screen',
      (tester) async {
        authRobot = AuthRobot(tester);
        homeRobot = HomeRobot(tester);
        playerRobot = PlayerRobot(tester);

        await authRobot.login(TestUsers.primary);
        await homeRobot.verifyHomeScreenVisible();

        // Open video
        await homeRobot.tapVideoCard();
        await playerRobot.verifyPlayerScreenVisible();

        // Go back
        await playerRobot.goBack();

        // Verify back at home
        await homeRobot.verifyHomeScreenVisible();
      },
      skip: true,
    );
  });
}

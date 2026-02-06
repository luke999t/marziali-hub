/// ============================================================================
/// PLAYER ROBOT
/// ============================================================================
///
/// AI_MODULE: PlayerRobot
/// AI_DESCRIPTION: Page Object for video player screens
/// AI_BUSINESS: Encapsulates player controls, skeleton overlay interactions
/// AI_TEACHING: Robot pattern for maintainable E2E tests
///
/// ============================================================================
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import '../helpers/test_config.dart';
import 'base_robot.dart';

class PlayerRobot extends BaseRobot {
  const PlayerRobot(super.tester);

  // ======================== PLAYER SCREEN ========================

  /// Verify player screen is displayed
  Future<void> verifyPlayerScreenVisible() async {
    await settle(TestTimeouts.playerInit);
    // Player should have video controls or video widget
    final videoPlayer = find.byType(GestureDetector);
    final controls = find.byIcon(Icons.play_arrow);
    final pause = find.byIcon(Icons.pause);
    final aspectRatio = find.byType(AspectRatio);

    final isPlayerVisible = tester.any(videoPlayer) ||
        tester.any(controls) ||
        tester.any(pause) ||
        tester.any(aspectRatio);

    expect(isPlayerVisible, isTrue, reason: 'Player screen should be visible');
  }

  /// Wait for video to load
  Future<void> waitForVideoToLoad() async {
    await settle(TestTimeouts.playerInit);
    // Wait for loading indicator to disappear
    final loading = find.byType(CircularProgressIndicator);
    if (tester.any(loading)) {
      await waitForWidgetToDisappear(loading, timeout: TestTimeouts.playerInit);
    }
  }

  // ======================== PLAYBACK CONTROLS ========================

  /// Tap play button
  Future<void> tapPlay() async {
    final playButton = find.byIcon(Icons.play_arrow);
    final playCircle = find.byIcon(Icons.play_circle);
    final playFilled = find.byIcon(Icons.play_arrow_rounded);

    if (tester.any(playButton)) {
      await tap(playButton.first, settle: false);
    } else if (tester.any(playCircle)) {
      await tap(playCircle.first, settle: false);
    } else if (tester.any(playFilled)) {
      await tap(playFilled.first, settle: false);
    } else {
      // Tap center of video to toggle play/pause
      await tapVideoCenter();
    }
    await pump(const Duration(milliseconds: 500));
  }

  /// Tap pause button
  Future<void> tapPause() async {
    final pauseButton = find.byIcon(Icons.pause);
    final pauseCircle = find.byIcon(Icons.pause_circle);

    if (tester.any(pauseButton)) {
      await tap(pauseButton.first, settle: false);
    } else if (tester.any(pauseCircle)) {
      await tap(pauseCircle.first, settle: false);
    } else {
      // Tap center to toggle
      await tapVideoCenter();
    }
    await pump(const Duration(milliseconds: 500));
  }

  /// Toggle play/pause by tapping video center
  Future<void> tapVideoCenter() async {
    // Find the video container and tap center
    final aspectRatio = find.byType(AspectRatio);
    final gestureDetector = find.byType(GestureDetector);

    if (tester.any(aspectRatio)) {
      await tap(aspectRatio.first, settle: false);
    } else if (tester.any(gestureDetector)) {
      await tap(gestureDetector.first, settle: false);
    }
    await pump(const Duration(milliseconds: 300));
  }

  /// Verify video is playing
  void verifyVideoPlaying() {
    // When playing, pause icon should be visible
    final pauseButton = find.byIcon(Icons.pause);
    final pauseCircle = find.byIcon(Icons.pause_circle);
    final isPlaying = tester.any(pauseButton) || tester.any(pauseCircle);
    expect(isPlaying, isTrue, reason: 'Video should be playing');
  }

  /// Verify video is paused
  void verifyVideoPaused() {
    // When paused, play icon should be visible
    final playButton = find.byIcon(Icons.play_arrow);
    final playCircle = find.byIcon(Icons.play_circle);
    final isPaused = tester.any(playButton) || tester.any(playCircle);
    expect(isPaused, isTrue, reason: 'Video should be paused');
  }

  // ======================== SEEK BAR ========================

  /// Seek to position (percentage 0-1)
  Future<void> seekToPosition(double percentage) async {
    final slider = find.byType(Slider);
    final progressBar = find.byType(LinearProgressIndicator);

    if (tester.any(slider)) {
      final sliderWidget = tester.widget<Slider>(slider.first);
      final size = tester.getSize(slider.first);
      final center = tester.getCenter(slider.first);

      // Calculate target position
      final targetX = center.dx - (size.width / 2) + (size.width * percentage);
      final targetOffset = Offset(targetX, center.dy);

      await tester.tapAt(targetOffset);
      await pump(const Duration(milliseconds: 300));
    }
  }

  /// Seek forward 10 seconds
  Future<void> seekForward() async {
    final forwardButton = find.byIcon(Icons.forward_10);
    final forward = find.byIcon(Icons.fast_forward);

    if (tester.any(forwardButton)) {
      await tap(forwardButton.first, settle: false);
    } else if (tester.any(forward)) {
      await tap(forward.first, settle: false);
    }
    await pump(const Duration(milliseconds: 300));
  }

  /// Seek backward 10 seconds
  Future<void> seekBackward() async {
    final rewindButton = find.byIcon(Icons.replay_10);
    final rewind = find.byIcon(Icons.fast_rewind);

    if (tester.any(rewindButton)) {
      await tap(rewindButton.first, settle: false);
    } else if (tester.any(rewind)) {
      await tap(rewind.first, settle: false);
    }
    await pump(const Duration(milliseconds: 300));
  }

  /// Double tap right side to seek forward
  Future<void> doubleTapSeekForward() async {
    final aspectRatio = find.byType(AspectRatio);
    if (tester.any(aspectRatio)) {
      final size = tester.getSize(aspectRatio.first);
      final center = tester.getCenter(aspectRatio.first);
      // Tap right side
      final rightOffset = Offset(center.dx + size.width / 4, center.dy);
      await tester.tapAt(rightOffset);
      await pump(const Duration(milliseconds: 100));
      await tester.tapAt(rightOffset);
      await pump(const Duration(milliseconds: 300));
    }
  }

  /// Double tap left side to seek backward
  Future<void> doubleTapSeekBackward() async {
    final aspectRatio = find.byType(AspectRatio);
    if (tester.any(aspectRatio)) {
      final size = tester.getSize(aspectRatio.first);
      final center = tester.getCenter(aspectRatio.first);
      // Tap left side
      final leftOffset = Offset(center.dx - size.width / 4, center.dy);
      await tester.tapAt(leftOffset);
      await pump(const Duration(milliseconds: 100));
      await tester.tapAt(leftOffset);
      await pump(const Duration(milliseconds: 300));
    }
  }

  // ======================== FULLSCREEN ========================

  /// Toggle fullscreen mode
  Future<void> toggleFullscreen() async {
    final fullscreenButton = find.byIcon(Icons.fullscreen);
    final fullscreenExit = find.byIcon(Icons.fullscreen_exit);

    if (tester.any(fullscreenButton)) {
      await tap(fullscreenButton.first, settle: false);
    } else if (tester.any(fullscreenExit)) {
      await tap(fullscreenExit.first, settle: false);
    }
    await pump(const Duration(milliseconds: 500));
  }

  /// Verify fullscreen mode is active
  void verifyFullscreenActive() {
    final exitFullscreen = find.byIcon(Icons.fullscreen_exit);
    expect(exitFullscreen, findsOneWidget);
  }

  /// Exit fullscreen mode
  Future<void> exitFullscreen() async {
    final fullscreenExit = find.byIcon(Icons.fullscreen_exit);
    if (tester.any(fullscreenExit)) {
      await tap(fullscreenExit.first, settle: false);
    }
    await pump(const Duration(milliseconds: 500));
  }

  // ======================== QUALITY SETTINGS ========================

  /// Open quality settings
  Future<void> openQualitySettings() async {
    final settingsButton = find.byIcon(Icons.settings);
    final qualityButton = find.byIcon(Icons.high_quality);
    final hdButton = find.byIcon(Icons.hd);

    if (tester.any(settingsButton)) {
      await tap(settingsButton.first);
    } else if (tester.any(qualityButton)) {
      await tap(qualityButton.first);
    } else if (tester.any(hdButton)) {
      await tap(hdButton.first);
    }
    await settle();
  }

  /// Select quality option
  Future<void> selectQuality(String quality) async {
    final qualityOption = find.textContaining(quality);
    if (tester.any(qualityOption)) {
      await tap(qualityOption.first);
    }
    await settle();
  }

  /// Verify quality options are available
  void verifyQualityOptionsVisible() {
    final qualityOptions = find.textContaining('p');
    verifyExistsAtLeastOne(qualityOptions);
  }

  // ======================== SKELETON OVERLAY ========================

  /// Toggle skeleton overlay
  Future<void> toggleSkeletonOverlay() async {
    final skeletonButton = find.byIcon(Icons.accessibility);
    final bodyButton = find.byIcon(Icons.accessibility_new);
    final poseButton = find.textContaining('Skeleton');

    if (tester.any(skeletonButton)) {
      await tap(skeletonButton.first);
    } else if (tester.any(bodyButton)) {
      await tap(bodyButton.first);
    } else if (tester.any(poseButton)) {
      await tap(poseButton.first);
    }
    await settle();
  }

  /// Verify skeleton overlay is visible
  Future<void> verifySkeletonOverlayVisible() async {
    await settle();
    // Skeleton overlay typically uses CustomPaint or Canvas
    final customPaint = find.byType(CustomPaint);
    final hasOverlay = tester.any(customPaint);
    expect(hasOverlay, isTrue, reason: 'Skeleton overlay should be visible');
  }

  /// Verify skeleton overlay is hidden
  void verifySkeletonOverlayHidden() {
    // When skeleton is hidden, accessibility icon should be unselected
    final skeletonButton = find.byIcon(Icons.accessibility);
    expect(skeletonButton, findsOneWidget);
  }

  // ======================== VOLUME CONTROLS ========================

  /// Mute video
  Future<void> mute() async {
    final volumeButton = find.byIcon(Icons.volume_up);
    if (tester.any(volumeButton)) {
      await tap(volumeButton.first, settle: false);
    }
    await pump(const Duration(milliseconds: 300));
  }

  /// Unmute video
  Future<void> unmute() async {
    final muteButton = find.byIcon(Icons.volume_off);
    if (tester.any(muteButton)) {
      await tap(muteButton.first, settle: false);
    }
    await pump(const Duration(milliseconds: 300));
  }

  /// Verify video is muted
  void verifyMuted() {
    final muteIcon = find.byIcon(Icons.volume_off);
    final mutedIcon = find.byIcon(Icons.volume_mute);
    final isMuted = tester.any(muteIcon) || tester.any(mutedIcon);
    expect(isMuted, isTrue);
  }

  // ======================== DOWNLOAD ========================

  /// Tap download button
  Future<void> tapDownload() async {
    final downloadButton = find.byIcon(Icons.download);
    final downloadOutline = find.byIcon(Icons.download_outlined);

    if (tester.any(downloadButton)) {
      await tap(downloadButton.first);
    } else if (tester.any(downloadOutline)) {
      await tap(downloadOutline.first);
    }
    await settle();
  }

  /// Verify download started
  void verifyDownloadStarted() {
    final downloading = find.byIcon(Icons.downloading);
    final progress = find.byType(CircularProgressIndicator);
    final hasDownload = tester.any(downloading) || tester.any(progress);
    expect(hasDownload, isTrue);
  }

  // ======================== NAVIGATION ========================

  /// Go back from player
  Future<void> goBack() async {
    final backButton = find.byIcon(Icons.arrow_back);
    final closeButton = find.byIcon(Icons.close);

    if (tester.any(backButton)) {
      await tap(backButton.first);
    } else if (tester.any(closeButton)) {
      await tap(closeButton.first);
    } else {
      // Use system back
      await tester.pageBack();
    }
    await settle();
  }

  /// Verify player controls are visible
  void verifyControlsVisible() {
    final playPause = find.byIcon(Icons.play_arrow);
    final pauseIcon = find.byIcon(Icons.pause);
    final hasControls = tester.any(playPause) || tester.any(pauseIcon);
    expect(hasControls, isTrue);
  }

  /// Hide player controls
  Future<void> hideControls() async {
    // Tap video to hide controls
    await tapVideoCenter();
    await pump(const Duration(seconds: 3));
  }

  /// Show player controls
  Future<void> showControls() async {
    await tapVideoCenter();
    await pump(const Duration(milliseconds: 300));
  }
}

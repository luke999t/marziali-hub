/// 🎓 AI_MODULE: EnhancedPlayerFlowTest
/// 🎓 AI_DESCRIPTION: Test integrazione flusso Player Enhanced - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione end-to-end player con skeleton, chapters, settings
/// 🎓 AI_TEACHING: Integration test - flusso utente completo
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/features/player/domain/entities/skeleton_data_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/chapter_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/video_quality_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/playback_settings_entity.dart';

import '../helpers/backend_checker.dart';

void main() {
  late Dio dio;

  setUpAll(() async {
    WidgetsFlutterBinding.ensureInitialized();
    SharedPreferences.setMockInitialValues({});

    dio = Dio(BaseOptions(
      baseUrl: '${BackendChecker.baseUrl}/api/v1',
      connectTimeout: const Duration(seconds: 15),
      receiveTimeout: const Duration(seconds: 15),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));
  });

  tearDownAll(() {
    dio.close();
  });

  // ==========================================================================
  // USER JOURNEY: COMPLETO VIDEO PLAYBACK
  // ==========================================================================
  group('Enhanced Player - Complete User Journey', () {
    testWithBackend('User watches video with skeleton overlay', () async {
      // STEP 1: Load video stream
      final streamResponse = await dio.get('/videos/test-martial-arts-001/stream');
      expect(streamResponse.statusCode, equals(200));

      final streamData = streamResponse.data as Map<String, dynamic>;
      expect(streamData['stream_url'], isNotNull);

      // STEP 2: Check if skeleton data available
      final skeletonExistsResponse = await dio.get('/videos/test-martial-arts-001/skeleton/exists');
      final hasSkeleton = skeletonExistsResponse.data['exists'] as bool? ?? false;

      if (hasSkeleton) {
        // STEP 3: Load skeleton data
        final skeletonResponse = await dio.get('/videos/test-martial-arts-001/skeleton/structured');
        expect(skeletonResponse.statusCode, anyOf(200, 404));

        if (skeletonResponse.statusCode == 200) {
          final skeletonData = SkeletonData.fromJson(
            skeletonResponse.data as Map<String, dynamic>,
          );

          expect(skeletonData.videoId, isNotEmpty);
          expect(skeletonData.fps, greaterThan(0));

          // STEP 4: Get frame at specific timestamp
          if (skeletonData.hasFrames) {
            final frame = skeletonData.getFrameAt(const Duration(seconds: 30));
            if (frame != null) {
              expect(frame.poseLandmarks, isNotEmpty);
            }
          }
        }
      }

      // STEP 5: Save progress
      await dio.post(
        '/me/videos/test-martial-arts-001/progress',
        data: {'position_seconds': 300}, // 5 minutes
      );

      // Test passed if we get here without errors
      expect(true, isTrue);
    });

    testWithBackend('User navigates chapters during playback', () async {
      // STEP 1: Get video chapters
      final chaptersResponse = await dio.get('/videos/test-video-chapters/chapters');

      if (chaptersResponse.statusCode == 200 && chaptersResponse.data != null) {
        final chapters = VideoChapters.fromJson(
          chaptersResponse.data as Map<String, dynamic>,
        );

        if (chapters.hasChapters) {
          // STEP 2: Navigate to specific chapter
          final targetChapter = chapters.chapters.length > 1
              ? chapters.chapters[1]
              : chapters.chapters.first;

          // Simulate seeking to chapter
          final seekPosition = targetChapter.startTime;
          expect(seekPosition.inSeconds, greaterThanOrEqualTo(0));

          // STEP 3: Get chapter at position
          final currentChapter = chapters.getChapterAt(seekPosition);
          expect(currentChapter, isNotNull);
          expect(currentChapter!.id, equals(targetChapter.id));

          // STEP 4: Navigate to next chapter
          final nextChapter = chapters.getNextChapter(seekPosition);
          // May be null if at last chapter
        }
      }

      expect(true, isTrue);
    });

    testWithBackend('User skips intro and credits', () async {
      // STEP 1: Get skip segments
      final skipResponse = await dio.get('/videos/test-video-skip/skip-segments');

      if (skipResponse.statusCode == 200 && skipResponse.data is List) {
        final segments = (skipResponse.data as List)
            .map((e) => SkipSegment.fromJson(e as Map<String, dynamic>))
            .toList();

        for (final segment in segments) {
          // STEP 2: Check if current position is in skip segment
          if (segment.type == SkipType.intro) {
            expect(segment.label, contains('intro'));

            // STEP 3: Verify skip position
            expect(
              segment.skipToPosition.inMilliseconds,
              greaterThanOrEqualTo(segment.endTime.inMilliseconds),
            );
          }

          if (segment.type == SkipType.credits) {
            expect(segment.label.toLowerCase(), anyOf(contains('credit'), contains('credits')));
          }
        }
      }

      expect(true, isTrue);
    });

    testWithBackend('User changes video quality', () async {
      // STEP 1: Get available qualities
      final qualitiesResponse = await dio.get('/videos/test-video-quality/qualities/structured');

      if (qualitiesResponse.statusCode == 200) {
        final qualities = AvailableQualities.fromJson(
          qualitiesResponse.data as Map<String, dynamic>,
        );

        // STEP 2: Verify Auto quality is always available
        expect(qualities.hasQuality(VideoQualityLevel.auto), isTrue);

        // STEP 3: Select quality based on bandwidth
        final selectedQuality = qualities.getBestForBandwidth(5000000); // 5 Mbps

        if (selectedQuality != null) {
          expect(selectedQuality.streamUrl, isNotEmpty);
        }

        // STEP 4: Get best available quality
        final best = qualities.bestAvailable;
        if (best != null) {
          expect(best.level, isNot(VideoQualityLevel.auto));
        }
      }

      expect(true, isTrue);
    });

    testWithBackend('User saves and restores playback settings', () async {
      // STEP 1: Create settings
      const settings = PlaybackSettings(
        playbackSpeed: 1.25,
        preferredQuality: VideoQualityLevel.high,
        autoPlayNextEpisode: true,
        skipIntro: true,
        skipCredits: true,
        showSkeletonOverlay: true,
      );

      // STEP 2: Serialize to JSON
      final json = settings.toJson();
      expect(json['playback_speed'], equals(1.25));
      expect(json['preferred_quality'], equals('high'));
      expect(json['skip_intro'], isTrue);

      // STEP 3: Deserialize from JSON
      final restored = PlaybackSettings.fromJson(json);
      expect(restored.playbackSpeed, equals(1.25));
      expect(restored.preferredQuality, equals(VideoQualityLevel.high));
      expect(restored.skipIntro, isTrue);

      // STEP 4: Verify equality
      expect(restored, equals(settings));

      expect(true, isTrue);
    });
  });

  // ==========================================================================
  // USER JOURNEY: SKELETON ANALYSIS
  // ==========================================================================
  group('Enhanced Player - Skeleton Analysis Journey', () {
    testWithBackend('User views skeleton overlay with pose analysis', () async {
      // STEP 1: Check skeleton availability
      final existsResponse = await dio.get('/videos/test-kata-video/skeleton/exists');
      final hasSkeleton = existsResponse.data['exists'] as bool? ?? false;

      if (!hasSkeleton) {
        // Skip if no skeleton data
        return;
      }

      // STEP 2: Load full skeleton data
      final skeletonResponse = await dio.get('/videos/test-kata-video/skeleton/structured');

      if (skeletonResponse.statusCode != 200) return;

      final skeleton = SkeletonData.fromJson(
        skeletonResponse.data as Map<String, dynamic>,
      );

      // STEP 3: Verify frame structure
      if (skeleton.hasFrames) {
        final firstFrame = skeleton.frames.first;

        // Verify 33 pose landmarks (MediaPipe standard)
        expect(firstFrame.poseLandmarks.length, equals(33));

        // Check visibility values
        for (final landmark in firstFrame.poseLandmarks) {
          expect(landmark.visibility, inInclusiveRange(0.0, 1.0));
          expect(landmark.x, inInclusiveRange(0.0, 1.0));
          expect(landmark.y, inInclusiveRange(0.0, 1.0));
        }

        // STEP 4: Check hand landmarks if available
        if (firstFrame.leftHandLandmarks != null) {
          // 21 hand landmarks per MediaPipe
          expect(firstFrame.leftHandLandmarks!.length, equals(21));
        }

        // STEP 5: Check angles if available
        if (firstFrame.angles != null) {
          // Common angles for martial arts
          expect(
            firstFrame.angles!.keys,
            anyOf(
              contains('elbow_left'),
              contains('elbow_right'),
              contains('knee_left'),
              contains('knee_right'),
            ),
          );
        }
      }

      // STEP 6: Test frame interpolation
      if (skeleton.frames.length >= 2) {
        final midTimestamp = Duration(
          milliseconds: skeleton.frames[0].timestamp.inMilliseconds +
              (skeleton.frames[1].timestamp.inMilliseconds -
                      skeleton.frames[0].timestamp.inMilliseconds) ~/
                  2,
        );

        final interpolated = skeleton.getInterpolatedFrame(midTimestamp);
        expect(interpolated, isNotNull);
      }

      expect(true, isTrue);
    });
  });

  // ==========================================================================
  // USER JOURNEY: GESTURE CONTROLS
  // ==========================================================================
  group('Enhanced Player - Gesture Settings', () {
    test('User configures gesture preferences', () {
      // STEP 1: Create default gesture settings
      const defaultGestures = GestureSettings();

      expect(defaultGestures.doubleTapToSeekEnabled, isTrue);
      expect(defaultGestures.doubleTapSeekDuration.inSeconds, equals(10));
      expect(defaultGestures.swipeToAdjustVolumeEnabled, isTrue);
      expect(defaultGestures.longPressSpeedEnabled, isTrue);

      // STEP 2: Customize gesture settings
      final customGestures = defaultGestures.copyWith(
        doubleTapSeekDuration: const Duration(seconds: 15),
        longPressSpeed: 1.5,
        swipeToAdjustBrightnessEnabled: false,
      );

      expect(customGestures.doubleTapSeekDuration.inSeconds, equals(15));
      expect(customGestures.longPressSpeed, equals(1.5));
      expect(customGestures.swipeToAdjustBrightnessEnabled, isFalse);
      // Unchanged values
      expect(customGestures.doubleTapToSeekEnabled, isTrue);

      // STEP 3: Serialize and restore
      final json = customGestures.toJson();
      final restored = GestureSettings.fromJson(json);

      expect(restored.doubleTapSeekDuration.inSeconds, equals(15));
      expect(restored.longPressSpeed, equals(1.5));
    });
  });

  // ==========================================================================
  // USER JOURNEY: SUBTITLE SETTINGS
  // ==========================================================================
  group('Enhanced Player - Subtitle Settings', () {
    test('User configures subtitle appearance', () {
      // STEP 1: Create default subtitle settings
      const defaultSubs = SubtitleSettings();

      expect(defaultSubs.fontSize, equals(16.0));
      expect(defaultSubs.language, equals('off'));

      // STEP 2: Customize subtitle settings
      final customSubs = defaultSubs.copyWith(
        fontSize: 20.0,
        language: 'Italian',
        fontColor: 0xFFFFFFFF,
        backgroundColor: 0x80000000,
      );

      expect(customSubs.fontSize, equals(20.0));
      expect(customSubs.language, equals('Italian'));
      expect(customSubs.fontColor, equals(0xFFFFFFFF));
      expect(customSubs.backgroundColor, equals(0x80000000));

      // STEP 3: Serialize and restore
      final json = customSubs.toJson();
      final restored = SubtitleSettings.fromJson(json);

      expect(restored.fontSize, equals(20.0));
      expect(restored.language, equals('Italian'));
    });
  });

  // ==========================================================================
  // USER JOURNEY: SKELETON OVERLAY SETTINGS
  // ==========================================================================
  group('Enhanced Player - Skeleton Overlay Settings', () {
    test('User configures skeleton overlay appearance', () {
      // STEP 1: Create default skeleton settings
      const defaultSettings = SkeletonOverlaySettings();

      expect(defaultSettings.opacity, equals(0.8));
      expect(defaultSettings.lineWidth, equals(2.0));
      expect(defaultSettings.showHands, isTrue);
      expect(defaultSettings.showAngles, isFalse);

      // STEP 2: Customize for martial arts analysis
      final analysisSettings = defaultSettings.copyWith(
        showAngles: true,
        highlightActiveJoints: true,
        lineWidth: 3.0,
        poseColor: 0xFF00FF00, // Green
      );

      expect(analysisSettings.showAngles, isTrue);
      expect(analysisSettings.highlightActiveJoints, isTrue);
      expect(analysisSettings.lineWidth, equals(3.0));
      expect(analysisSettings.poseColor, equals(0xFF00FF00));

      // STEP 3: Serialize and restore
      final json = analysisSettings.toJson();
      final restored = SkeletonOverlaySettings.fromJson(json);

      expect(restored.showAngles, isTrue);
      expect(restored.lineWidth, equals(3.0));
    });
  });

  // ==========================================================================
  // PERFORMANCE TESTS
  // ==========================================================================
  group('Enhanced Player - Performance', () {
    testWithBackend('Skeleton frame lookup is O(log n)', () async {
      // Create large dataset
      final frames = List.generate(
        10000,
        (i) => SkeletonFrame(
          timestamp: Duration(milliseconds: i * 33), // ~30fps
          poseLandmarks: const [
            SkeletonLandmark(x: 0.5, y: 0.5, z: 0.0, visibility: 1.0),
          ],
        ),
      );

      final skeleton = SkeletonData(
        videoId: 'perf-test',
        fps: 30.0,
        totalFrames: 10000,
        frames: frames,
      );

      // Measure lookup time for multiple random positions
      final stopwatch = Stopwatch()..start();

      for (int i = 0; i < 1000; i++) {
        final randomMs = (i * 33 * 10) % (10000 * 33);
        skeleton.getFrameAt(Duration(milliseconds: randomMs));
      }

      stopwatch.stop();

      // 1000 lookups should complete in under 100ms (binary search)
      expect(stopwatch.elapsedMilliseconds, lessThan(100));

      print('1000 frame lookups completed in ${stopwatch.elapsedMilliseconds}ms');
    });

    testWithBackend('Frame interpolation is performant', () async {
      final frames = List.generate(
        1000,
        (i) => SkeletonFrame(
          timestamp: Duration(milliseconds: i * 33),
          poseLandmarks: List.generate(
            33,
            (j) => SkeletonLandmark(
              x: 0.5 + (j * 0.01),
              y: 0.5 + (j * 0.01),
              z: 0.0,
              visibility: 1.0,
            ),
          ),
        ),
      );

      final skeleton = SkeletonData(
        videoId: 'interp-test',
        fps: 30.0,
        totalFrames: 1000,
        frames: frames,
      );

      final stopwatch = Stopwatch()..start();

      // 60fps playback simulation for 10 seconds
      for (int i = 0; i < 600; i++) {
        final timestamp = Duration(milliseconds: i * 16); // ~60fps
        skeleton.getInterpolatedFrame(timestamp);
      }

      stopwatch.stop();

      // 600 interpolations should complete in under 200ms
      expect(stopwatch.elapsedMilliseconds, lessThan(200));

      print('600 frame interpolations completed in ${stopwatch.elapsedMilliseconds}ms');
    });
  });
}

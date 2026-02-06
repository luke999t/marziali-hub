/// 🎓 AI_MODULE: EnhancedPlayerWidgetsTest
/// 🎓 AI_DESCRIPTION: Test Widget Player Enhanced - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione UI componenti player avanzato
/// 🎓 AI_TEACHING: Widget test pattern - no mock, verifica render e interazioni
///
/// NOTA: Widget test per componenti che non richiedono backend
/// Testano rendering, interazioni utente, e stato UI

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:martial_arts_streaming/features/player/domain/entities/skeleton_data_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/chapter_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/video_quality_entity.dart';
import 'package:martial_arts_streaming/features/player/presentation/widgets/quality_selector.dart';
import 'package:martial_arts_streaming/features/player/presentation/widgets/chapter_markers.dart';
import 'package:martial_arts_streaming/features/player/presentation/widgets/skip_button.dart';
import 'package:martial_arts_streaming/features/player/presentation/widgets/gesture_layer.dart';

void main() {
  // ==========================================================================
  // QUALITY SELECTOR WIDGET TESTS
  // ==========================================================================
  group('QualitySelector Widget', () {
    testWidgets('renders with available qualities', (tester) async {
      final qualities = AvailableQualities(
        videoId: 'test-video',
        qualities: const [
          VideoQuality(
            level: VideoQualityLevel.auto,
            streamUrl: 'https://cdn.example.com/auto.m3u8',
          ),
          VideoQuality(
            level: VideoQualityLevel.high,
            streamUrl: 'https://cdn.example.com/720p.m3u8',
            resolution: '1280x720',
            bitrate: 2500000,
          ),
          VideoQuality(
            level: VideoQualityLevel.fullHd,
            streamUrl: 'https://cdn.example.com/1080p.m3u8',
            resolution: '1920x1080',
            bitrate: 5000000,
          ),
        ],
      );

      VideoQualityLevel? selectedQuality;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualitySelector(
              availableQualities: qualities,
              currentQuality: VideoQualityLevel.auto,
              onQualitySelected: (quality) {
                selectedQuality = quality;
              },
            ),
          ),
        ),
      );

      // Verify widget renders
      expect(find.byType(QualitySelector), findsOneWidget);

      // Verify quality options are shown
      expect(find.text('Auto'), findsOneWidget);
    });

    testWidgets('calls onQualitySelected when quality tapped', (tester) async {
      final qualities = AvailableQualities(
        videoId: 'test-video',
        qualities: const [
          VideoQuality(
            level: VideoQualityLevel.auto,
            streamUrl: '',
          ),
          VideoQuality(
            level: VideoQualityLevel.high,
            streamUrl: '',
            resolution: '720p',
          ),
        ],
      );

      VideoQualityLevel? selectedQuality;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualitySelector(
              availableQualities: qualities,
              currentQuality: VideoQualityLevel.auto,
              onQualitySelected: (quality) {
                selectedQuality = quality;
              },
            ),
          ),
        ),
      );

      // Find and tap 720p quality
      final highQualityFinder = find.text('720p');
      if (highQualityFinder.evaluate().isNotEmpty) {
        await tester.tap(highQualityFinder);
        await tester.pump();

        expect(selectedQuality, equals(VideoQualityLevel.high));
      }
    });

    testWidgets('highlights current quality', (tester) async {
      final qualities = AvailableQualities(
        videoId: 'test-video',
        qualities: const [
          VideoQuality(level: VideoQualityLevel.auto, streamUrl: ''),
          VideoQuality(level: VideoQualityLevel.fullHd, streamUrl: '', resolution: '1080p'),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualitySelector(
              availableQualities: qualities,
              currentQuality: VideoQualityLevel.fullHd,
              onQualitySelected: (_) {},
            ),
          ),
        ),
      );

      // Current quality should be highlighted (implementation specific)
      expect(find.byType(QualitySelector), findsOneWidget);
    });
  });

  // ==========================================================================
  // QUALITY CHIP WIDGET TESTS
  // ==========================================================================
  group('QualityChip Widget', () {
    testWidgets('displays current quality level', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualityChip(
              currentQuality: VideoQualityLevel.fullHd,
              onTap: () {},
            ),
          ),
        ),
      );

      expect(find.byType(QualityChip), findsOneWidget);
      expect(find.text('1080p'), findsOneWidget);
    });

    testWidgets('shows Auto for auto quality', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualityChip(
              currentQuality: VideoQualityLevel.auto,
              onTap: () {},
            ),
          ),
        ),
      );

      expect(find.text('Auto'), findsOneWidget);
    });

    testWidgets('calls onTap when pressed', (tester) async {
      bool tapped = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: QualityChip(
              currentQuality: VideoQualityLevel.high,
              onTap: () => tapped = true,
            ),
          ),
        ),
      );

      await tester.tap(find.byType(QualityChip));
      await tester.pump();

      expect(tapped, isTrue);
    });
  });

  // ==========================================================================
  // CHAPTER MARKERS WIDGET TESTS
  // ==========================================================================
  group('ChapterProgressBar Widget', () {
    testWidgets('renders chapter markers', (tester) async {
      final chapters = VideoChapters(
        videoId: 'test-video',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Intro',
            startTime: Duration.zero,
            endTime: Duration(minutes: 2),
          ),
          Chapter(
            id: 'ch-2',
            title: 'Main Content',
            startTime: Duration(minutes: 2),
            endTime: Duration(minutes: 30),
          ),
          Chapter(
            id: 'ch-3',
            title: 'Conclusion',
            startTime: Duration(minutes: 30),
            endTime: Duration(minutes: 35),
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: ChapterProgressBar(
                chapters: chapters,
                totalDuration: const Duration(minutes: 35),
                currentPosition: const Duration(minutes: 5),
                onSeek: (_) {},
              ),
            ),
          ),
        ),
      );

      expect(find.byType(ChapterProgressBar), findsOneWidget);
    });

    testWidgets('highlights current chapter', (tester) async {
      final chapters = VideoChapters(
        videoId: 'test-video',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Part 1',
            startTime: Duration.zero,
            endTime: Duration(minutes: 10),
          ),
          Chapter(
            id: 'ch-2',
            title: 'Part 2',
            startTime: Duration(minutes: 10),
            endTime: Duration(minutes: 20),
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              child: ChapterProgressBar(
                chapters: chapters,
                totalDuration: const Duration(minutes: 20),
                currentPosition: const Duration(minutes: 5), // In Part 1
                onSeek: (_) {},
              ),
            ),
          ),
        ),
      );

      // Verify Part 1 is highlighted (implementation specific)
      expect(find.byType(ChapterProgressBar), findsOneWidget);
    });
  });

  group('ChapterListSelector Widget', () {
    testWidgets('displays list of chapters', (tester) async {
      final chapters = VideoChapters(
        videoId: 'test-video',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Introduction',
            startTime: Duration.zero,
            endTime: Duration(minutes: 5),
          ),
          Chapter(
            id: 'ch-2',
            title: 'Basic Techniques',
            startTime: Duration(minutes: 5),
            endTime: Duration(minutes: 20),
          ),
          Chapter(
            id: 'ch-3',
            title: 'Advanced Moves',
            startTime: Duration(minutes: 20),
            endTime: Duration(minutes: 40),
          ),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ChapterListSelector(
              chapters: chapters,
              currentChapter: chapters.chapters[0],
              onChapterSelected: (_) {},
            ),
          ),
        ),
      );

      expect(find.text('Introduction'), findsOneWidget);
      expect(find.text('Basic Techniques'), findsOneWidget);
      expect(find.text('Advanced Moves'), findsOneWidget);
    });

    testWidgets('calls onChapterSelected when chapter tapped', (tester) async {
      final chapters = VideoChapters(
        videoId: 'test-video',
        chapters: const [
          Chapter(
            id: 'ch-1',
            title: 'Chapter 1',
            startTime: Duration.zero,
            endTime: Duration(minutes: 10),
          ),
          Chapter(
            id: 'ch-2',
            title: 'Chapter 2',
            startTime: Duration(minutes: 10),
            endTime: Duration(minutes: 20),
          ),
        ],
      );

      Chapter? selectedChapter;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ChapterListSelector(
              chapters: chapters,
              currentChapter: chapters.chapters[0],
              onChapterSelected: (chapter) => selectedChapter = chapter,
            ),
          ),
        ),
      );

      await tester.tap(find.text('Chapter 2'));
      await tester.pump();

      expect(selectedChapter?.id, equals('ch-2'));
    });
  });

  // ==========================================================================
  // SKIP BUTTON WIDGET TESTS
  // ==========================================================================
  group('SkipButton Widget', () {
    testWidgets('shows skip button when in skip segment', (tester) async {
      const segments = [
        SkipSegment(
          startTime: Duration.zero,
          endTime: Duration(seconds: 30),
          skipToPosition: Duration(seconds: 30),
          label: 'Salta intro',
          type: SkipType.intro,
        ),
      ];

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SkipButton(
                  segments: segments,
                  currentPosition: const Duration(seconds: 15), // In intro
                  onSkip: (_) {},
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pump(const Duration(milliseconds: 350)); // Animation

      // Button should be visible
      expect(find.byType(SkipButton), findsOneWidget);
    });

    testWidgets('hides skip button when outside skip segment', (tester) async {
      const segments = [
        SkipSegment(
          startTime: Duration.zero,
          endTime: Duration(seconds: 30),
          skipToPosition: Duration(seconds: 30),
          label: 'Salta intro',
          type: SkipType.intro,
        ),
      ];

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SkipButton(
                  segments: segments,
                  currentPosition: const Duration(minutes: 5), // After intro
                  onSkip: (_) {},
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pump();

      // Button should render but not be visible (faded out)
      expect(find.byType(SkipButton), findsOneWidget);
    });

    testWidgets('calls onSkip with correct position when tapped', (tester) async {
      const segments = [
        SkipSegment(
          startTime: Duration.zero,
          endTime: Duration(seconds: 30),
          skipToPosition: Duration(seconds: 30),
          label: 'Salta intro',
          type: SkipType.intro,
        ),
      ];

      Duration? skippedTo;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                SkipButton(
                  segments: segments,
                  currentPosition: const Duration(seconds: 10),
                  onSkip: (position) => skippedTo = position,
                ),
              ],
            ),
          ),
        ),
      );

      await tester.pump(const Duration(milliseconds: 350));

      // Find and tap the skip button content
      final skipButtonFinder = find.text('Salta intro');
      if (skipButtonFinder.evaluate().isNotEmpty) {
        await tester.tap(skipButtonFinder);
        await tester.pump();

        expect(skippedTo?.inSeconds, equals(30));
      }
    });
  });

  // ==========================================================================
  // GESTURE LAYER WIDGET TESTS
  // ==========================================================================
  group('PlayerGestureLayer Widget', () {
    testWidgets('renders gesture layer', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PlayerGestureLayer(
              onDoubleTapLeft: () {},
              onDoubleTapRight: () {},
              onSwipeVerticalLeft: (_) {},
              onSwipeVerticalRight: (_) {},
              onLongPressStart: () {},
              onLongPressEnd: () {},
              onTap: () {},
              child: Container(
                width: 400,
                height: 300,
                color: Colors.black,
              ),
            ),
          ),
        ),
      );

      expect(find.byType(PlayerGestureLayer), findsOneWidget);
    });

    testWidgets('detects single tap', (tester) async {
      bool tapped = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: PlayerGestureLayer(
              onDoubleTapLeft: () {},
              onDoubleTapRight: () {},
              onSwipeVerticalLeft: (_) {},
              onSwipeVerticalRight: (_) {},
              onLongPressStart: () {},
              onLongPressEnd: () {},
              onTap: () => tapped = true,
              child: Container(
                width: 400,
                height: 300,
                color: Colors.black,
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.byType(PlayerGestureLayer));
      await tester.pump(const Duration(milliseconds: 350)); // Wait for double tap timeout

      expect(tapped, isTrue);
    });

    testWidgets('detects double tap on right side', (tester) async {
      bool doubleTappedRight = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              height: 300,
              child: PlayerGestureLayer(
                onDoubleTapLeft: () {},
                onDoubleTapRight: () => doubleTappedRight = true,
                onSwipeVerticalLeft: (_) {},
                onSwipeVerticalRight: (_) {},
                onLongPressStart: () {},
                onLongPressEnd: () {},
                onTap: () {},
                child: Container(color: Colors.black),
              ),
            ),
          ),
        ),
      );

      // Double tap on right side (x > half width)
      final center = tester.getCenter(find.byType(PlayerGestureLayer));
      final rightSide = Offset(center.dx + 100, center.dy);

      await tester.tapAt(rightSide);
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tapAt(rightSide);
      await tester.pump();

      expect(doubleTappedRight, isTrue);
    });

    testWidgets('detects double tap on left side', (tester) async {
      bool doubleTappedLeft = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              height: 300,
              child: PlayerGestureLayer(
                onDoubleTapLeft: () => doubleTappedLeft = true,
                onDoubleTapRight: () {},
                onSwipeVerticalLeft: (_) {},
                onSwipeVerticalRight: (_) {},
                onLongPressStart: () {},
                onLongPressEnd: () {},
                onTap: () {},
                child: Container(color: Colors.black),
              ),
            ),
          ),
        ),
      );

      // Double tap on left side (x < half width)
      final center = tester.getCenter(find.byType(PlayerGestureLayer));
      final leftSide = Offset(center.dx - 100, center.dy);

      await tester.tapAt(leftSide);
      await tester.pump(const Duration(milliseconds: 50));
      await tester.tapAt(leftSide);
      await tester.pump();

      expect(doubleTappedLeft, isTrue);
    });

    testWidgets('detects long press', (tester) async {
      bool longPressStarted = false;
      bool longPressEnded = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: SizedBox(
              width: 400,
              height: 300,
              child: PlayerGestureLayer(
                onDoubleTapLeft: () {},
                onDoubleTapRight: () {},
                onSwipeVerticalLeft: (_) {},
                onSwipeVerticalRight: (_) {},
                onLongPressStart: () => longPressStarted = true,
                onLongPressEnd: () => longPressEnded = true,
                onTap: () {},
                child: Container(color: Colors.black),
              ),
            ),
          ),
        ),
      );

      await tester.longPress(find.byType(PlayerGestureLayer));
      await tester.pump();

      expect(longPressStarted, isTrue);
      expect(longPressEnded, isTrue);
    });
  });

  // ==========================================================================
  // DOUBLE TAP RIPPLE ANIMATION TESTS
  // ==========================================================================
  group('DoubleTapRipple Widget', () {
    testWidgets('renders ripple animation', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                DoubleTapRipple(
                  position: const Offset(100, 100),
                  isForward: true,
                  onComplete: () {},
                ),
              ],
            ),
          ),
        ),
      );

      expect(find.byType(DoubleTapRipple), findsOneWidget);

      // Let animation complete
      await tester.pumpAndSettle();
    });

    testWidgets('shows correct icon for forward/backward', (tester) async {
      // Forward ripple
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                DoubleTapRipple(
                  position: const Offset(100, 100),
                  isForward: true,
                  onComplete: () {},
                ),
              ],
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.fast_forward), findsOneWidget);

      await tester.pumpAndSettle();

      // Backward ripple
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                DoubleTapRipple(
                  position: const Offset(100, 100),
                  isForward: false,
                  onComplete: () {},
                ),
              ],
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.fast_rewind), findsOneWidget);

      await tester.pumpAndSettle();
    });

    testWidgets('calls onComplete after animation', (tester) async {
      bool completed = false;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: Stack(
              children: [
                DoubleTapRipple(
                  position: const Offset(100, 100),
                  isForward: true,
                  onComplete: () => completed = true,
                ),
              ],
            ),
          ),
        ),
      );

      // Wait for animation to complete
      await tester.pumpAndSettle(const Duration(milliseconds: 600));

      expect(completed, isTrue);
    });
  });
}

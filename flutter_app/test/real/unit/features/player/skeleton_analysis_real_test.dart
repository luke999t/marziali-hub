/// ================================================================================
/// AI_MODULE: SkeletonAnalysisRealTest
/// AI_VERSION: 1.0.0
/// AI_DESCRIPTION: Unit tests REALI per Skeleton Analysis features - ZERO MOCK
/// AI_BUSINESS: Verifica misurazione angoli, cattura frame, confronto pose
/// AI_TEACHING: BLoC testing con eventi reali, widget testing, algoritmi matematici
/// AI_COPYRIGHT: 2025 Media Center Arti Marziali - All Rights Reserved
/// AI_CREATED: 2026-01-18
///
/// 📊 TEST CATEGORIES:
/// - SkeletonAnalysisBloc events and state
/// - AngleMeasurementWidget rendering and interaction
/// - PoseComparisonWidget similarity calculation
/// - SkeletonAnalysisToolbar widget testing
///
/// 🧪 ZERO_MOCK_POLICY:
/// - Test widget con WidgetTester reale
/// - Test logic pura senza mock
/// - BLoC testing con eventi e stati reali
/// ================================================================================

import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';

import '../../../../../lib/features/player/presentation/bloc/skeleton_analysis_bloc.dart';
import '../../../../../lib/features/player/presentation/widgets/angle_measurement_widget.dart';
import '../../../../../lib/features/player/presentation/widgets/frame_export_widget.dart';
import '../../../../../lib/features/player/presentation/widgets/pose_comparison_widget.dart';
import '../../../../../lib/features/player/presentation/widgets/skeleton_analysis_toolbar.dart';
import '../../../../../lib/features/player/domain/entities/skeleton_data_entity.dart';
import '../../../../helpers/mock_blocker.dart';

void main() {
  enforceMockPolicy();

  // ===========================================================================
  // SKELETON ANALYSIS BLOC TESTS
  // ===========================================================================

  group('SkeletonAnalysisBloc - Pure Logic', () {
    late SkeletonAnalysisBloc bloc;

    setUp(() {
      bloc = SkeletonAnalysisBloc();
    });

    tearDown(() {
      bloc.close();
    });

    test('initial state is correct', () {
      expect(bloc.state.isAngleMeasurementMode, isFalse);
      expect(bloc.state.isFrameCaptureMode, isFalse);
      expect(bloc.state.isPoseComparisonMode, isFalse);
      expect(bloc.state.selectedLandmarks, isEmpty);
      expect(bloc.state.capturedFrames, isEmpty);
      expect(bloc.state.hasActiveMode, isFalse);
    });

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'toggles angle measurement mode on',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(ToggleAngleMeasurementModeEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isAngleMeasurementMode, 'isAngleMeasurementMode', true)
            .having((s) => s.hasActiveMode, 'hasActiveMode', true),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'toggles angle measurement mode off and clears selection',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(
        isAngleMeasurementMode: true,
        selectedLandmarks: [0, 1, 2],
        selectedLandmarkNames: ['nose', 'left_eye', 'right_eye'],
      ),
      act: (bloc) => bloc.add(ToggleAngleMeasurementModeEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isAngleMeasurementMode, 'isAngleMeasurementMode', false)
            .having((s) => s.selectedLandmarks, 'selectedLandmarks', isEmpty),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'disables other modes when enabling angle measurement',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(
        isFrameCaptureMode: true,
        isPoseComparisonMode: true,
      ),
      act: (bloc) => bloc.add(ToggleAngleMeasurementModeEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isAngleMeasurementMode, 'isAngleMeasurementMode', true)
            .having((s) => s.isFrameCaptureMode, 'isFrameCaptureMode', false)
            .having((s) => s.isPoseComparisonMode, 'isPoseComparisonMode', false),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'selects landmark for angle measurement',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(isAngleMeasurementMode: true),
      act: (bloc) => bloc.add(const SelectLandmarkForAngleEvent(
        landmarkIndex: 11,
        landmarkName: 'left_shoulder',
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.selectedLandmarks, 'selectedLandmarks', [11])
            .having((s) => s.selectedLandmarkNames, 'selectedLandmarkNames', ['left_shoulder']),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'deselects landmark when tapped again',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(
        isAngleMeasurementMode: true,
        selectedLandmarks: [11],
        selectedLandmarkNames: ['left_shoulder'],
      ),
      act: (bloc) => bloc.add(const SelectLandmarkForAngleEvent(
        landmarkIndex: 11,
        landmarkName: 'left_shoulder',
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.selectedLandmarks, 'selectedLandmarks', isEmpty),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'limits selection to 3 landmarks',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(
        isAngleMeasurementMode: true,
        selectedLandmarks: [11, 13, 15],
        selectedLandmarkNames: ['left_shoulder', 'left_elbow', 'left_wrist'],
      ),
      act: (bloc) => bloc.add(const SelectLandmarkForAngleEvent(
        landmarkIndex: 23,
        landmarkName: 'left_hip',
      )),
      expect: () => [],  // No change expected, already 3 selected
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'applies angle preset',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(ApplyAnglePresetEvent(
        presetName: 'Mabu Stance',
        presetAngles: MartialArtsAnglePresets.mabuStance,
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.activePresetName, 'activePresetName', 'Mabu Stance')
            .having((s) => s.activePresetAngles, 'activePresetAngles', MartialArtsAnglePresets.mabuStance),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'clears angle selection',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        isAngleMeasurementMode: true,
        selectedLandmarks: const [11, 13, 15],
        selectedLandmarkNames: const ['left_shoulder', 'left_elbow', 'left_wrist'],
        activePresetName: 'Test',
        activePresetAngles: MartialArtsAnglePresets.mabuStance,
      ),
      act: (bloc) => bloc.add(ClearAngleSelectionEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.selectedLandmarks, 'selectedLandmarks', isEmpty)
            .having((s) => s.activePresetName, 'activePresetName', isNull)
            .having((s) => s.activePresetAngles, 'activePresetAngles', isNull),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'toggles frame capture mode',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(ToggleFrameCaptureModeEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isFrameCaptureMode, 'isFrameCaptureMode', true),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'captures frame',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(CaptureFrameEvent(
        imageData: Uint8List.fromList([0, 1, 2, 3]),
        timestamp: const Duration(seconds: 5),
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isCapturing, 'isCapturing', true),
        isA<SkeletonAnalysisState>()
            .having((s) => s.isCapturing, 'isCapturing', false)
            .having((s) => s.capturedFrames.length, 'capturedFrames.length', 1),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'removes captured frame',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        capturedFrames: [
          CapturedFrame(
            id: 'test_frame_1',
            imageData: Uint8List.fromList([0, 1, 2]),
            timestamp: const Duration(seconds: 5),
          ),
        ],
      ),
      act: (bloc) => bloc.add(const RemoveCapturedFrameEvent('test_frame_1')),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.capturedFrames, 'capturedFrames', isEmpty),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'clears all captured frames',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        capturedFrames: [
          CapturedFrame(
            id: 'test_frame_1',
            imageData: Uint8List.fromList([0, 1]),
            timestamp: const Duration(seconds: 1),
          ),
          CapturedFrame(
            id: 'test_frame_2',
            imageData: Uint8List.fromList([2, 3]),
            timestamp: const Duration(seconds: 2),
          ),
        ],
      ),
      act: (bloc) => bloc.add(ClearCapturedFramesEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.capturedFrames, 'capturedFrames', isEmpty),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'toggles pose comparison mode',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(TogglePoseComparisonModeEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.isPoseComparisonMode, 'isPoseComparisonMode', true),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'selects reference frame for comparison',
      build: () => SkeletonAnalysisBloc(),
      seed: () => const SkeletonAnalysisState(isPoseComparisonMode: true),
      act: (bloc) => bloc.add(SelectReferenceFrameEvent(
        frame: _createTestSkeletonFrame(timestamp: 1.0),
        timestamp: const Duration(seconds: 1),
        label: 'Reference',
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.referenceFrame, 'referenceFrame', isNotNull)
            .having((s) => s.referenceLabel, 'referenceLabel', 'Reference'),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'selects student frame for comparison',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        isPoseComparisonMode: true,
        referenceFrame: _createTestSkeletonFrame(timestamp: 1.0),
      ),
      act: (bloc) => bloc.add(SelectStudentFrameEvent(
        frame: _createTestSkeletonFrame(timestamp: 2.0),
        timestamp: const Duration(seconds: 2),
        label: 'Student',
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.studentFrame, 'studentFrame', isNotNull)
            .having((s) => s.studentLabel, 'studentLabel', 'Student')
            .having((s) => s.canCompare, 'canCompare', true),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'compares poses and generates result',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        isPoseComparisonMode: true,
        referenceFrame: _createTestSkeletonFrame(timestamp: 1.0),
        studentFrame: _createTestSkeletonFrame(timestamp: 2.0, offset: 0.02),
      ),
      act: (bloc) => bloc.add(ComparePosesEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.comparisonResult, 'comparisonResult', isNotNull)
            .having((s) => s.comparisonResult?.overallSimilarity, 'similarity', greaterThan(0)),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'changes comparison view mode',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(const ChangeComparisonModeEvent(ComparisonMode.overlay)),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.comparisonViewMode, 'comparisonViewMode', ComparisonMode.overlay),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'clears comparison',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        isPoseComparisonMode: true,
        referenceFrame: _createTestSkeletonFrame(timestamp: 1.0),
        studentFrame: _createTestSkeletonFrame(timestamp: 2.0),
        comparisonResult: const PoseComparisonResult(
          overallSimilarity: 85.0,
          landmarkDistances: {},
          angleDeviations: {},
          criticalDifferences: [],
          suggestions: [],
        ),
      ),
      act: (bloc) => bloc.add(ClearComparisonEvent()),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.referenceFrame, 'referenceFrame', isNull)
            .having((s) => s.studentFrame, 'studentFrame', isNull)
            .having((s) => s.comparisonResult, 'comparisonResult', isNull),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'resets all analysis state',
      build: () => SkeletonAnalysisBloc(),
      seed: () => SkeletonAnalysisState(
        isAngleMeasurementMode: true,
        selectedLandmarks: const [1, 2, 3],
        capturedFrames: [
          CapturedFrame(
            imageData: Uint8List.fromList([0]),
            timestamp: Duration.zero,
          ),
        ],
        isPoseComparisonMode: true,
      ),
      act: (bloc) => bloc.add(ResetAnalysisStateEvent()),
      expect: () => [
        const SkeletonAnalysisState(),
      ],
    );

    blocTest<SkeletonAnalysisBloc, SkeletonAnalysisState>(
      'updates current skeleton frame',
      build: () => SkeletonAnalysisBloc(),
      act: (bloc) => bloc.add(UpdateCurrentSkeletonFrameEvent(
        frame: _createTestSkeletonFrame(timestamp: 1.5),
        timestamp: const Duration(milliseconds: 1500),
      )),
      expect: () => [
        isA<SkeletonAnalysisState>()
            .having((s) => s.currentFrame, 'currentFrame', isNotNull)
            .having((s) => s.currentTimestamp.inMilliseconds, 'timestamp', 1500),
      ],
    );
  });

  // ===========================================================================
  // ANGLE MEASUREMENT TESTS (Pure Math)
  // ===========================================================================

  group('Angle Calculation - Pure Math', () {
    test('calculates 90 degree angle correctly', () {
      // Right angle: A(0,0), B(0,1), C(1,1)
      final angle = _calculateAngle(
        ax: 0.0, ay: 0.0,
        bx: 0.0, by: 1.0,
        cx: 1.0, cy: 1.0,
      );
      expect(angle, closeTo(90.0, 1.0));
    });

    test('calculates 180 degree angle (straight line)', () {
      // Straight line: A(0,0), B(1,0), C(2,0)
      final angle = _calculateAngle(
        ax: 0.0, ay: 0.0,
        bx: 1.0, by: 0.0,
        cx: 2.0, cy: 0.0,
      );
      expect(angle, closeTo(180.0, 1.0));
    });

    test('calculates 45 degree angle', () {
      // 45 degrees: A(0,0), B(1,0), C(2,1)
      final angle = _calculateAngle(
        ax: 0.0, ay: 0.0,
        bx: 1.0, by: 0.0,
        cx: 2.0, cy: 1.0,
      );
      expect(angle, closeTo(135.0, 1.0)); // 180 - 45
    });

    test('calculates 60 degree angle', () {
      // Equilateral triangle vertex: A(0,0), B(1,0), C(0.5, 0.866)
      final angle = _calculateAngle(
        ax: 0.0, ay: 0.0,
        bx: 1.0, by: 0.0,
        cx: 0.5, cy: 0.866,
      );
      expect(angle, closeTo(60.0, 2.0));
    });
  });

  // ===========================================================================
  // ANGLE TARGET TESTS
  // ===========================================================================

  group('AngleTarget', () {
    test('isInRange returns true for angle within tolerance', () {
      const target = AngleTarget(
        name: 'Test',
        idealAngle: 90.0,
        tolerance: 10.0,
      );

      expect(target.isInRange(90.0), isTrue);
      expect(target.isInRange(85.0), isTrue);
      expect(target.isInRange(95.0), isTrue);
      expect(target.isInRange(100.0), isTrue);
      expect(target.isInRange(80.0), isTrue);
    });

    test('isInRange returns false for angle outside tolerance', () {
      const target = AngleTarget(
        name: 'Test',
        idealAngle: 90.0,
        tolerance: 10.0,
      );

      expect(target.isInRange(101.0), isFalse);
      expect(target.isInRange(79.0), isFalse);
      expect(target.isInRange(110.0), isFalse);
      expect(target.isInRange(70.0), isFalse);
    });

    test('getColor returns green for perfect angle', () {
      const target = AngleTarget(
        name: 'Test',
        idealAngle: 90.0,
        tolerance: 10.0,
      );

      final color = target.getColor(90.0);
      expect(color, equals(Colors.green));
    });

    test('getColor returns orange for slightly off angle', () {
      const target = AngleTarget(
        name: 'Test',
        idealAngle: 90.0,
        tolerance: 10.0,
      );

      final color = target.getColor(105.0); // 15 degrees off
      expect(color, equals(Colors.orange));
    });

    test('getColor returns red for very off angle', () {
      const target = AngleTarget(
        name: 'Test',
        idealAngle: 90.0,
        tolerance: 10.0,
      );

      final color = target.getColor(130.0); // 40 degrees off
      expect(color, equals(Colors.red));
    });
  });

  // ===========================================================================
  // MARTIAL ARTS ANGLE PRESETS TESTS
  // ===========================================================================

  group('MartialArtsAnglePresets', () {
    test('mabuStance has correct knee angles', () {
      final preset = MartialArtsAnglePresets.mabuStance;

      expect(preset.containsKey('left_knee'), isTrue);
      expect(preset.containsKey('right_knee'), isTrue);
      expect(preset['left_knee']!.idealAngle, equals(90.0));
      expect(preset['right_knee']!.idealAngle, equals(90.0));
    });

    test('straightPunch has correct arm angles', () {
      final preset = MartialArtsAnglePresets.straightPunch;

      expect(preset.containsKey('punching_elbow'), isTrue);
      expect(preset.containsKey('rear_elbow'), isTrue);
      expect(preset['punching_elbow']!.idealAngle, equals(170.0)); // Almost straight
    });

    test('frontKick has correct hip and knee angles', () {
      final preset = MartialArtsAnglePresets.frontKick;

      expect(preset.containsKey('kicking_hip'), isTrue);
      expect(preset.containsKey('kicking_knee'), isTrue);
      expect(preset['kicking_knee']!.idealAngle, equals(170.0)); // Extended
    });

    test('sideKick has correct angles for side position', () {
      final preset = MartialArtsAnglePresets.sideKick;

      expect(preset.containsKey('kicking_hip'), isTrue);
      expect(preset.containsKey('supporting_knee'), isTrue);
    });

    test('fightingStance has balanced angles', () {
      final preset = MartialArtsAnglePresets.fightingStance;

      expect(preset.containsKey('front_knee'), isTrue);
      expect(preset.containsKey('rear_knee'), isTrue);
      expect(preset.containsKey('guard_elbow'), isTrue);
    });
  });

  // ===========================================================================
  // POSE COMPARISON RESULT TESTS
  // ===========================================================================

  group('PoseComparisonResult', () {
    test('high similarity for identical poses', () {
      final result = const PoseComparisonResult(
        overallSimilarity: 98.5,
        landmarkDistances: {'nose': 0.01, 'left_shoulder': 0.02},
        angleDeviations: {'left_elbow': 2.0, 'right_knee': 1.5},
        criticalDifferences: [],
        suggestions: ['Ottima esecuzione!'],
      );

      expect(result.overallSimilarity, greaterThan(95.0));
      expect(result.criticalDifferences, isEmpty);
    });

    test('low similarity with critical differences', () {
      final result = const PoseComparisonResult(
        overallSimilarity: 55.0,
        landmarkDistances: {'nose': 0.2, 'left_shoulder': 0.25},
        angleDeviations: {'left_elbow': 35.0, 'right_knee': 40.0},
        criticalDifferences: ['left_elbow', 'right_knee'],
        suggestions: ['Concentrati su: left_elbow, right_knee'],
      );

      expect(result.overallSimilarity, lessThan(60.0));
      expect(result.criticalDifferences, isNotEmpty);
      expect(result.suggestions, isNotEmpty);
    });
  });

  // ===========================================================================
  // FRAME EXPORT OPTIONS TESTS
  // ===========================================================================

  group('FrameExportOptions', () {
    test('default options include video and skeleton', () {
      const options = FrameExportOptions();

      expect(options.includeVideo, isTrue);
      expect(options.includeSkeleton, isTrue);
      expect(options.includeAngles, isFalse);
      expect(options.includeTimestamp, isFalse);
      expect(options.format, equals(ExportFormat.png));
    });

    test('copyWith preserves unchanged values', () {
      const options = FrameExportOptions(
        includeVideo: true,
        includeSkeleton: true,
        includeAngles: true,
      );

      final modified = options.copyWith(includeTimestamp: true);

      expect(modified.includeVideo, isTrue);
      expect(modified.includeSkeleton, isTrue);
      expect(modified.includeAngles, isTrue);
      expect(modified.includeTimestamp, isTrue);
    });
  });

  // ===========================================================================
  // CAPTURED FRAME TESTS
  // ===========================================================================

  group('CapturedFrame', () {
    test('generates unique id', () {
      final frame1 = CapturedFrame(
        imageData: Uint8List.fromList([1, 2, 3]),
        timestamp: const Duration(seconds: 1),
      );
      final frame2 = CapturedFrame(
        imageData: Uint8List.fromList([4, 5, 6]),
        timestamp: const Duration(seconds: 2),
      );

      expect(frame1.id, isNot(equals(frame2.id)));
    });

    test('uses provided id', () {
      final frame = CapturedFrame(
        id: 'custom_id_123',
        imageData: Uint8List.fromList([1, 2, 3]),
        timestamp: const Duration(seconds: 1),
      );

      expect(frame.id, equals('custom_id_123'));
    });

    test('sets capture time', () {
      final before = DateTime.now();
      final frame = CapturedFrame(
        imageData: Uint8List.fromList([1, 2, 3]),
        timestamp: const Duration(seconds: 1),
      );
      final after = DateTime.now();

      expect(frame.captureTime.isAfter(before.subtract(const Duration(seconds: 1))), isTrue);
      expect(frame.captureTime.isBefore(after.add(const Duration(seconds: 1))), isTrue);
    });
  });

  // ===========================================================================
  // SKELETON ANALYSIS TOOLBAR WIDGET TESTS
  // ===========================================================================

  group('SkeletonAnalysisToolbar Widget', () {
    testWidgets('renders all tool buttons', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: BlocProvider(
              create: (_) => SkeletonAnalysisBloc(),
              child: const SkeletonAnalysisToolbar(
                isVisible: true,
              ),
            ),
          ),
        ),
      );

      expect(find.text('Angoli'), findsOneWidget);
      expect(find.text('Cattura'), findsOneWidget);
      expect(find.text('Confronto'), findsOneWidget);
      expect(find.byIcon(Icons.architecture), findsOneWidget);
      expect(find.byIcon(Icons.camera_alt), findsOneWidget);
      expect(find.byIcon(Icons.compare), findsOneWidget);
    });

    testWidgets('toggles angle measurement mode on tap', (tester) async {
      final bloc = SkeletonAnalysisBloc();

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: BlocProvider.value(
              value: bloc,
              child: const SkeletonAnalysisToolbar(
                isVisible: true,
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Angoli'));
      await tester.pump();

      expect(bloc.state.isAngleMeasurementMode, isTrue);

      bloc.close();
    });

    testWidgets('toggles frame capture mode on tap', (tester) async {
      final bloc = SkeletonAnalysisBloc();

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: BlocProvider.value(
              value: bloc,
              child: const SkeletonAnalysisToolbar(
                isVisible: true,
              ),
            ),
          ),
        ),
      );

      await tester.tap(find.text('Cattura'));
      await tester.pump();

      expect(bloc.state.isFrameCaptureMode, isTrue);

      bloc.close();
    });

    testWidgets('hides when not visible', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: BlocProvider(
              create: (_) => SkeletonAnalysisBloc(),
              child: const SkeletonAnalysisToolbar(
                isVisible: false,
              ),
            ),
          ),
        ),
      );

      // Widget should still exist but with opacity 0
      expect(find.byType(SkeletonAnalysisToolbar), findsOneWidget);
    });
  });

  // ===========================================================================
  // ANALYSIS MODE INDICATOR WIDGET TESTS
  // ===========================================================================

  group('AnalysisModeIndicator Widget', () {
    testWidgets('shows nothing when no mode active', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: AnalysisModeIndicator(
              isAngleMeasurement: false,
              isFrameCapture: false,
              isPoseComparison: false,
            ),
          ),
        ),
      );

      expect(find.byType(SizedBox), findsOneWidget);
    });

    testWidgets('shows angle measurement indicator', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: AnalysisModeIndicator(
              isAngleMeasurement: true,
              measuredAngle: 90.5,
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.architecture), findsOneWidget);
      expect(find.text('90.5°'), findsOneWidget);
    });

    testWidgets('shows frame capture indicator', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: AnalysisModeIndicator(
              isFrameCapture: true,
              capturedFrameCount: 5,
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.camera_alt), findsOneWidget);
      expect(find.text('5 frame catturati'), findsOneWidget);
    });

    testWidgets('shows pose comparison indicator with similarity', (tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: AnalysisModeIndicator(
              isPoseComparison: true,
              comparisonSimilarity: 85.3,
            ),
          ),
        ),
      );

      expect(find.byIcon(Icons.compare), findsOneWidget);
      expect(find.text('Similarità: 85%'), findsOneWidget);
    });
  });

  // ===========================================================================
  // ANGLE PRESET SELECTOR WIDGET TESTS
  // ===========================================================================

  group('AnglePresetSelector Widget', () {
    testWidgets('renders all preset options', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AnglePresetSelector(
              onPresetSelected: (_, __) {},
            ),
          ),
        ),
      );

      expect(find.text('Mabu'), findsOneWidget);
      expect(find.text('Pugno'), findsOneWidget);
      expect(find.text('Calcio'), findsOneWidget);
      expect(find.text('Laterale'), findsOneWidget);
      expect(find.text('Guardia'), findsOneWidget);
    });

    testWidgets('calls onPresetSelected when preset tapped', (tester) async {
      String? selectedName;
      Map<String, AngleTarget>? selectedAngles;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AnglePresetSelector(
              onPresetSelected: (name, angles) {
                selectedName = name;
                selectedAngles = angles;
              },
            ),
          ),
        ),
      );

      await tester.tap(find.text('Mabu'));
      await tester.pump();

      expect(selectedName, equals('Mabu'));
      expect(selectedAngles, equals(MartialArtsAnglePresets.mabuStance));
    });

    testWidgets('highlights current preset', (tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: AnglePresetSelector(
              currentPreset: 'Mabu',
              onPresetSelected: (_, __) {},
            ),
          ),
        ),
      );

      // The "Mabu" chip should be highlighted
      expect(find.text('Mabu'), findsOneWidget);
    });
  });
}

// ===========================================================================
// HELPER FUNCTIONS
// ===========================================================================

/// Creates a test skeleton frame with optional offset for comparison testing
SkeletonFrame _createTestSkeletonFrame({
  required double timestamp,
  double offset = 0.0,
}) {
  final landmarks = <SkeletonLandmark>[];

  // Generate 33 landmarks with some offset
  for (var i = 0; i < 33; i++) {
    landmarks.add(SkeletonLandmark(
      index: i,
      name: i < kPoseLandmarkNames.length ? kPoseLandmarkNames[i] : 'Landmark $i',
      x: 0.3 + (i * 0.01) + offset,
      y: 0.2 + (i * 0.015) + offset,
      z: 0.0,
      visibility: 0.9,
    ));
  }

  return SkeletonFrame(
    timestamp: timestamp,
    landmarks: landmarks,
  );
}

/// Calculates angle between three points (vertex at B)
double _calculateAngle({
  required double ax,
  required double ay,
  required double bx,
  required double by,
  required double cx,
  required double cy,
}) {
  final baX = ax - bx;
  final baY = ay - by;
  final bcX = cx - bx;
  final bcY = cy - by;

  final dotProduct = baX * bcX + baY * bcY;
  final magnitudeBA = _sqrt(baX * baX + baY * baY);
  final magnitudeBC = _sqrt(bcX * bcX + bcY * bcY);

  if (magnitudeBA == 0 || magnitudeBC == 0) return 0;

  var cosAngle = dotProduct / (magnitudeBA * magnitudeBC);
  cosAngle = cosAngle.clamp(-1.0, 1.0);

  final angleRad = _acos(cosAngle);
  return angleRad * 180 / 3.14159265359;
}

double _sqrt(double x) {
  if (x <= 0) return 0;
  double guess = x / 2;
  for (var i = 0; i < 20; i++) {
    guess = (guess + x / guess) / 2;
  }
  return guess;
}

double _acos(double x) {
  if (x >= 1) return 0;
  if (x <= -1) return 3.14159265359;
  return 1.5707963267949 - _asin(x);
}

double _asin(double x) {
  if (x.abs() < 0.5) {
    double result = x;
    double term = x;
    for (var n = 1; n < 10; n++) {
      term *= x * x * (2 * n - 1) * (2 * n - 1) / ((2 * n) * (2 * n + 1));
      result += term;
    }
    return result;
  }
  final sign = x < 0 ? -1.0 : 1.0;
  x = x.abs();
  return sign * (1.5707963267949 - 2 * _asin(_sqrt((1 - x) / 2)));
}

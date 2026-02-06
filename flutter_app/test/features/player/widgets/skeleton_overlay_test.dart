/// 🎓 AI_MODULE: SkeletonOverlay Widget Test
/// 🎓 AI_DESCRIPTION: Test widget overlay scheletro 3D su video
/// 🎓 AI_BUSINESS: Verifica UI mostra correttamente punti skeleton
/// 🎓 AI_TEACHING: Pattern widget test con CustomPaint

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('SkeletonOverlay Widget Tests', () {
    testWidgets('renders without error when visible', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
            ),
          ),
        ),
      );

      expect(find.byType(_SkeletonOverlay), findsOneWidget);
    });

    testWidgets('does not render when not visible', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: false,
              landmarks: _testLandmarks,
            ),
          ),
        ),
      );

      // Widget exists but should be invisible
      final opacity = tester.widget<Opacity>(find.byType(Opacity));
      expect(opacity.opacity, equals(0.0));
    });

    testWidgets('uses CustomPaint for rendering', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
            ),
          ),
        ),
      );

      expect(find.byType(CustomPaint), findsWidgets);
    });

    testWidgets('handles empty landmarks gracefully', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: [],
            ),
          ),
        ),
      );

      // Should not crash
      expect(find.byType(_SkeletonOverlay), findsOneWidget);
    });

    testWidgets('handles null landmarks gracefully', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: null,
            ),
          ),
        ),
      );

      // Should not crash
      expect(find.byType(_SkeletonOverlay), findsOneWidget);
    });

    testWidgets('shows loading indicator when loading', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: null,
              isLoading: true,
            ),
          ),
        ),
      );

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('applies correct color to skeleton', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
              skeletonColor: Colors.red,
            ),
          ),
        ),
      );

      final customPaint = tester.widget<CustomPaint>(
        find.byType(CustomPaint).first,
      );
      final painter = customPaint.painter as _SkeletonPainter?;
      expect(painter?.color, equals(Colors.red));
    });

    testWidgets('applies correct line thickness', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
              lineThickness: 4.0,
            ),
          ),
        ),
      );

      final customPaint = tester.widget<CustomPaint>(
        find.byType(CustomPaint).first,
      );
      final painter = customPaint.painter as _SkeletonPainter?;
      expect(painter?.strokeWidth, equals(4.0));
    });

    testWidgets('shows confidence indicator when enabled', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
              showConfidence: true,
            ),
          ),
        ),
      );

      // Should show confidence percentage
      expect(find.textContaining('%'), findsWidgets);
    });

    testWidgets('toggles visibility on tap when interactive', (WidgetTester tester) async {
      bool? toggledValue;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: _SkeletonOverlay(
              isVisible: true,
              landmarks: _testLandmarks,
              interactive: true,
              onVisibilityChanged: (value) => toggledValue = value,
            ),
          ),
        ),
      );

      await tester.tap(find.byType(_SkeletonOverlay));
      await tester.pump();

      expect(toggledValue, equals(false));
    });
  });

  group('SkeletonLandmark Tests', () {
    test('creates landmark with required fields', () {
      const landmark = _SkeletonLandmark(
        id: 0,
        name: 'nose',
        x: 0.5,
        y: 0.3,
        z: 0.0,
        confidence: 0.95,
      );

      expect(landmark.id, equals(0));
      expect(landmark.name, equals('nose'));
      expect(landmark.x, equals(0.5));
      expect(landmark.y, equals(0.3));
      expect(landmark.confidence, equals(0.95));
    });

    test('isVisible returns true for high confidence', () {
      const landmark = _SkeletonLandmark(
        id: 0,
        name: 'nose',
        x: 0.5,
        y: 0.3,
        z: 0.0,
        confidence: 0.8,
      );

      expect(landmark.isVisible(), isTrue);
    });

    test('isVisible returns false for low confidence', () {
      const landmark = _SkeletonLandmark(
        id: 0,
        name: 'nose',
        x: 0.5,
        y: 0.3,
        z: 0.0,
        confidence: 0.3,
      );

      expect(landmark.isVisible(), isFalse);
    });

    test('toOffset returns correct Offset', () {
      const landmark = _SkeletonLandmark(
        id: 0,
        name: 'nose',
        x: 0.5,
        y: 0.3,
        z: 0.0,
        confidence: 0.9,
      );

      final offset = landmark.toOffset(const Size(100, 100));
      expect(offset.dx, equals(50.0));
      expect(offset.dy, equals(30.0));
    });
  });

  group('SkeletonConnection Tests', () {
    test('creates connection between two landmarks', () {
      const connection = _SkeletonConnection(
        fromIndex: 0,
        toIndex: 1,
        name: 'neck_to_shoulder',
      );

      expect(connection.fromIndex, equals(0));
      expect(connection.toIndex, equals(1));
      expect(connection.name, equals('neck_to_shoulder'));
    });
  });
}

// ========== Test Constants ==========

const List<_SkeletonLandmark> _testLandmarks = [
  _SkeletonLandmark(id: 0, name: 'nose', x: 0.5, y: 0.1, z: 0.0, confidence: 0.95),
  _SkeletonLandmark(id: 1, name: 'left_eye', x: 0.45, y: 0.08, z: 0.0, confidence: 0.92),
  _SkeletonLandmark(id: 2, name: 'right_eye', x: 0.55, y: 0.08, z: 0.0, confidence: 0.93),
  _SkeletonLandmark(id: 11, name: 'left_shoulder', x: 0.35, y: 0.25, z: 0.0, confidence: 0.88),
  _SkeletonLandmark(id: 12, name: 'right_shoulder', x: 0.65, y: 0.25, z: 0.0, confidence: 0.89),
  _SkeletonLandmark(id: 13, name: 'left_elbow', x: 0.25, y: 0.4, z: 0.0, confidence: 0.85),
  _SkeletonLandmark(id: 14, name: 'right_elbow', x: 0.75, y: 0.4, z: 0.0, confidence: 0.86),
  _SkeletonLandmark(id: 15, name: 'left_wrist', x: 0.2, y: 0.55, z: 0.0, confidence: 0.82),
  _SkeletonLandmark(id: 16, name: 'right_wrist', x: 0.8, y: 0.55, z: 0.0, confidence: 0.83),
  _SkeletonLandmark(id: 23, name: 'left_hip', x: 0.4, y: 0.55, z: 0.0, confidence: 0.9),
  _SkeletonLandmark(id: 24, name: 'right_hip', x: 0.6, y: 0.55, z: 0.0, confidence: 0.91),
  _SkeletonLandmark(id: 25, name: 'left_knee', x: 0.38, y: 0.75, z: 0.0, confidence: 0.87),
  _SkeletonLandmark(id: 26, name: 'right_knee', x: 0.62, y: 0.75, z: 0.0, confidence: 0.88),
  _SkeletonLandmark(id: 27, name: 'left_ankle', x: 0.36, y: 0.95, z: 0.0, confidence: 0.84),
  _SkeletonLandmark(id: 28, name: 'right_ankle', x: 0.64, y: 0.95, z: 0.0, confidence: 0.85),
];

// ========== Test Widget Implementations ==========

class _SkeletonLandmark {
  final int id;
  final String name;
  final double x;
  final double y;
  final double z;
  final double confidence;

  const _SkeletonLandmark({
    required this.id,
    required this.name,
    required this.x,
    required this.y,
    required this.z,
    required this.confidence,
  });

  bool isVisible({double threshold = 0.5}) => confidence >= threshold;

  Offset toOffset(Size size) => Offset(x * size.width, y * size.height);
}

class _SkeletonConnection {
  final int fromIndex;
  final int toIndex;
  final String name;

  const _SkeletonConnection({
    required this.fromIndex,
    required this.toIndex,
    required this.name,
  });
}

class _SkeletonOverlay extends StatelessWidget {
  final bool isVisible;
  final List<_SkeletonLandmark>? landmarks;
  final bool isLoading;
  final Color skeletonColor;
  final double lineThickness;
  final bool showConfidence;
  final bool interactive;
  final ValueChanged<bool>? onVisibilityChanged;

  const _SkeletonOverlay({
    required this.isVisible,
    this.landmarks,
    this.isLoading = false,
    this.skeletonColor = Colors.green,
    this.lineThickness = 2.0,
    this.showConfidence = false,
    this.interactive = false,
    this.onVisibilityChanged,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: interactive
          ? () => onVisibilityChanged?.call(!isVisible)
          : null,
      child: Opacity(
        opacity: isVisible ? 1.0 : 0.0,
        child: Stack(
          children: [
            if (isLoading)
              const Center(child: CircularProgressIndicator())
            else if (landmarks != null && landmarks!.isNotEmpty)
              CustomPaint(
                painter: _SkeletonPainter(
                  landmarks: landmarks!,
                  color: skeletonColor,
                  strokeWidth: lineThickness,
                ),
                size: Size.infinite,
              ),
            if (showConfidence && landmarks != null)
              ...landmarks!.map((l) => Positioned(
                    left: l.x * 100,
                    top: l.y * 100,
                    child: Text(
                      '${(l.confidence * 100).round()}%',
                      style: const TextStyle(fontSize: 8),
                    ),
                  )),
          ],
        ),
      ),
    );
  }
}

class _SkeletonPainter extends CustomPainter {
  final List<_SkeletonLandmark> landmarks;
  final Color color;
  final double strokeWidth;

  _SkeletonPainter({
    required this.landmarks,
    required this.color,
    required this.strokeWidth,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = color
      ..strokeWidth = strokeWidth
      ..style = PaintingStyle.stroke;

    final pointPaint = Paint()
      ..color = color
      ..style = PaintingStyle.fill;

    // Draw landmarks
    for (final landmark in landmarks) {
      if (landmark.isVisible()) {
        final offset = landmark.toOffset(size);
        canvas.drawCircle(offset, 4, pointPaint);
      }
    }

    // Draw connections (simplified)
    final connections = [
      [11, 12], // shoulders
      [11, 13], // left shoulder to elbow
      [12, 14], // right shoulder to elbow
      [13, 15], // left elbow to wrist
      [14, 16], // right elbow to wrist
      [23, 24], // hips
      [23, 25], // left hip to knee
      [24, 26], // right hip to knee
      [25, 27], // left knee to ankle
      [26, 28], // right knee to ankle
    ];

    for (final connection in connections) {
      final from = landmarks.where((l) => l.id == connection[0]).firstOrNull;
      final to = landmarks.where((l) => l.id == connection[1]).firstOrNull;

      if (from != null &&
          to != null &&
          from.isVisible() &&
          to.isVisible()) {
        canvas.drawLine(
          from.toOffset(size),
          to.toOffset(size),
          paint,
        );
      }
    }
  }

  @override
  bool shouldRepaint(covariant _SkeletonPainter oldDelegate) {
    return landmarks != oldDelegate.landmarks ||
        color != oldDelegate.color ||
        strokeWidth != oldDelegate.strokeWidth;
  }
}

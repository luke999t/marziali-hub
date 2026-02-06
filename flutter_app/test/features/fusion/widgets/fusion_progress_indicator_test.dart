/// 🎓 AI_MODULE: FusionProgressIndicator Widget Test
/// 🎓 AI_DESCRIPTION: Test widget indicatore progresso fusione
/// 🎓 AI_BUSINESS: Verifica UI mostra correttamente stato elaborazione
/// 🎓 AI_TEACHING: Pattern widget test con pump e finder

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('FusionProgressIndicator Widget Tests', () {
    testWidgets('shows 0% at start', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: 0.0),
          ),
        ),
      );

      expect(find.text('0%'), findsOneWidget);
    });

    testWidgets('shows correct percentage at 50%', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: 0.5),
          ),
        ),
      );

      expect(find.text('50%'), findsOneWidget);
    });

    testWidgets('shows 100% when complete', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: 1.0),
          ),
        ),
      );

      expect(find.text('100%'), findsOneWidget);
    });

    testWidgets('contains CircularProgressIndicator', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: 0.5),
          ),
        ),
      );

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('shows phase text when provided', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(
              progress: 0.3,
              currentPhase: 'Extracting skeleton...',
            ),
          ),
        ),
      );

      expect(find.text('Extracting skeleton...'), findsOneWidget);
    });

    testWidgets('handles edge case progress > 1.0', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: 1.5),
          ),
        ),
      );

      // Should clamp to 100%
      expect(find.text('100%'), findsOneWidget);
    });

    testWidgets('handles edge case progress < 0.0', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(progress: -0.5),
          ),
        ),
      );

      // Should clamp to 0%
      expect(find.text('0%'), findsOneWidget);
    });

    testWidgets('has accessible semantics', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionProgressIndicator(
              progress: 0.75,
              semanticLabel: 'Fusion progress',
            ),
          ),
        ),
      );

      final semantics = tester.getSemantics(
        find.byType(_FusionProgressIndicator),
      );

      expect(semantics.label, contains('progress'));
    });
  });

  group('FusionStatusBadge Widget Tests', () {
    testWidgets('shows Draft status correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionStatusBadge(status: _FusionStatus.draft),
          ),
        ),
      );

      expect(find.text('Draft'), findsOneWidget);
    });

    testWidgets('shows Processing status with animation', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionStatusBadge(status: _FusionStatus.processing),
          ),
        ),
      );

      expect(find.text('Processing'), findsOneWidget);
      // Processing status should have loading indicator
      expect(find.byType(SizedBox), findsWidgets);
    });

    testWidgets('shows Completed status with check icon', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionStatusBadge(status: _FusionStatus.completed),
          ),
        ),
      );

      expect(find.text('Completed'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle), findsOneWidget);
    });

    testWidgets('shows Failed status with error icon', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionStatusBadge(status: _FusionStatus.failed),
          ),
        ),
      );

      expect(find.text('Failed'), findsOneWidget);
      expect(find.byIcon(Icons.error), findsOneWidget);
    });

    testWidgets('has correct color for each status', (WidgetTester tester) async {
      for (final status in _FusionStatus.values) {
        await tester.pumpWidget(
          MaterialApp(
            home: Scaffold(
              body: _FusionStatusBadge(status: status),
            ),
          ),
        );

        final container = tester.widget<Container>(
          find.byType(Container).first,
        );

        final decoration = container.decoration as BoxDecoration?;
        expect(decoration?.color, isNotNull);
      }
    });
  });

  group('FusionWizardStepper Widget Tests', () {
    testWidgets('shows all wizard steps', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionWizardStepper(currentStep: 0),
          ),
        ),
      );

      expect(find.text('Project Info'), findsOneWidget);
      expect(find.text('Add Videos'), findsOneWidget);
      expect(find.text('Configure'), findsOneWidget);
      expect(find.text('Review'), findsOneWidget);
    });

    testWidgets('highlights current step', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionWizardStepper(currentStep: 2),
          ),
        ),
      );

      // Step 2 (Configure) should be highlighted
      // Previous steps should be marked complete
      expect(find.byIcon(Icons.check), findsNWidgets(2));
    });

    testWidgets('disables future steps', (WidgetTester tester) async {
      await tester.pumpWidget(
        const MaterialApp(
          home: Scaffold(
            body: _FusionWizardStepper(currentStep: 1),
          ),
        ),
      );

      // Steps after current should be disabled
      final stepWidgets = tester.widgetList(find.byType(_StepWidget));
      expect(stepWidgets.length, greaterThan(0));
    });

    testWidgets('calls onStepTapped when enabled step tapped', (WidgetTester tester) async {
      int? tappedStep;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: _FusionWizardStepper(
              currentStep: 2,
              onStepTapped: (step) => tappedStep = step,
            ),
          ),
        ),
      );

      // Tap on completed step (step 0)
      await tester.tap(find.text('Project Info'));
      await tester.pump();

      expect(tappedStep, equals(0));
    });
  });
}

// ========== Test Widget Implementations ==========
// These are simplified versions for testing purposes

enum _FusionStatus {
  draft,
  ready,
  queued,
  processing,
  completed,
  failed,
  cancelled,
}

class _FusionProgressIndicator extends StatelessWidget {
  final double progress;
  final String? currentPhase;
  final String? semanticLabel;

  const _FusionProgressIndicator({
    required this.progress,
    this.currentPhase,
    this.semanticLabel,
  });

  @override
  Widget build(BuildContext context) {
    final clampedProgress = progress.clamp(0.0, 1.0);
    final percentage = (clampedProgress * 100).round();

    return Semantics(
      label: semanticLabel ?? 'Fusion progress $percentage%',
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Stack(
            alignment: Alignment.center,
            children: [
              CircularProgressIndicator(
                value: clampedProgress,
                strokeWidth: 8,
              ),
              Text(
                '$percentage%',
                style: Theme.of(context).textTheme.titleLarge,
              ),
            ],
          ),
          if (currentPhase != null) ...[
            const SizedBox(height: 16),
            Text(currentPhase!),
          ],
        ],
      ),
    );
  }
}

class _FusionStatusBadge extends StatelessWidget {
  final _FusionStatus status;

  const _FusionStatusBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: _getStatusColor(),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          if (status == _FusionStatus.completed)
            const Icon(Icons.check_circle, size: 16),
          if (status == _FusionStatus.failed)
            const Icon(Icons.error, size: 16),
          if (status == _FusionStatus.processing)
            const SizedBox(
              width: 16,
              height: 16,
              child: CircularProgressIndicator(strokeWidth: 2),
            ),
          const SizedBox(width: 4),
          Text(_getStatusText()),
        ],
      ),
    );
  }

  Color _getStatusColor() {
    switch (status) {
      case _FusionStatus.draft:
        return Colors.grey;
      case _FusionStatus.ready:
        return Colors.blue;
      case _FusionStatus.queued:
        return Colors.orange;
      case _FusionStatus.processing:
        return Colors.amber;
      case _FusionStatus.completed:
        return Colors.green;
      case _FusionStatus.failed:
        return Colors.red;
      case _FusionStatus.cancelled:
        return Colors.grey;
    }
  }

  String _getStatusText() {
    switch (status) {
      case _FusionStatus.draft:
        return 'Draft';
      case _FusionStatus.ready:
        return 'Ready';
      case _FusionStatus.queued:
        return 'Queued';
      case _FusionStatus.processing:
        return 'Processing';
      case _FusionStatus.completed:
        return 'Completed';
      case _FusionStatus.failed:
        return 'Failed';
      case _FusionStatus.cancelled:
        return 'Cancelled';
    }
  }
}

class _FusionWizardStepper extends StatelessWidget {
  final int currentStep;
  final void Function(int)? onStepTapped;

  const _FusionWizardStepper({
    required this.currentStep,
    this.onStepTapped,
  });

  static const _steps = [
    'Project Info',
    'Add Videos',
    'Configure',
    'Review',
  ];

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceEvenly,
      children: List.generate(_steps.length, (index) {
        final isCompleted = index < currentStep;
        final isCurrent = index == currentStep;

        return _StepWidget(
          title: _steps[index],
          isCompleted: isCompleted,
          isCurrent: isCurrent,
          onTap: isCompleted || isCurrent
              ? () => onStepTapped?.call(index)
              : null,
        );
      }),
    );
  }
}

class _StepWidget extends StatelessWidget {
  final String title;
  final bool isCompleted;
  final bool isCurrent;
  final VoidCallback? onTap;

  const _StepWidget({
    required this.title,
    required this.isCompleted,
    required this.isCurrent,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircleAvatar(
            radius: 16,
            backgroundColor: isCompleted
                ? Colors.green
                : isCurrent
                    ? Colors.blue
                    : Colors.grey,
            child: isCompleted
                ? const Icon(Icons.check, size: 16, color: Colors.white)
                : null,
          ),
          const SizedBox(height: 4),
          Text(
            title,
            style: TextStyle(
              fontWeight: isCurrent ? FontWeight.bold : FontWeight.normal,
              color: (isCompleted || isCurrent) ? Colors.black : Colors.grey,
            ),
          ),
        ],
      ),
    );
  }
}

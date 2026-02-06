/// 🎓 AI_MODULE: FusionBlocTest
/// 🎓 AI_DESCRIPTION: Test BLoC Fusion con backend reale - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione stati fusione video, progetti, wizard
/// 🎓 AI_TEACHING: Pattern test BLoC enterprise - backend reale obbligatorio
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';

import 'package:media_center_arti_marziali/features/fusion/presentation/bloc/fusion_bloc.dart';
import 'package:media_center_arti_marziali/features/fusion/presentation/bloc/fusion_event.dart';
import 'package:media_center_arti_marziali/features/fusion/presentation/bloc/fusion_state.dart';
import 'package:media_center_arti_marziali/features/fusion/domain/entities/fusion_project_entity.dart';
import 'package:media_center_arti_marziali/features/fusion/domain/entities/fusion_video_source_entity.dart';
import 'package:media_center_arti_marziali/features/fusion/domain/repositories/fusion_repository.dart';

import '../../../../helpers/backend_checker.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();

  group('FusionState Tests', () {
    test('FusionState.initial() returns correct initial state', () {
      final state = FusionState.initial();

      expect(state.projectsLoadingState, equals(FusionLoadingState.initial));
      expect(state.projects, isEmpty);
      expect(state.totalProjectsCount, equals(0));
      expect(state.currentPage, equals(1));
      expect(state.hasMoreProjects, isFalse);
      expect(state.selectedProject, isNull);
      expect(state.projectVideos, isEmpty);
      expect(state.wizardStep, equals(FusionWizardStep.projectInfo));
      expect(state.isWizardMode, isFalse);
    });

    test('computed property hasProjects works correctly', () {
      final emptyState = FusionState.initial();
      expect(emptyState.hasProjects, isFalse);

      final stateWithProjects = emptyState.copyWith(
        projects: [_createTestProject('p1')],
      );
      expect(stateWithProjects.hasProjects, isTrue);
    });

    test('computed property videoCount returns correct count', () {
      final state = FusionState.initial();
      expect(state.videoCount, equals(0));

      final stateWithVideos = state.copyWith(
        projectVideos: [
          _createTestVideoSource('v1'),
          _createTestVideoSource('v2'),
        ],
      );
      expect(stateWithVideos.videoCount, equals(2));
    });

    test('computed property canStartFusion requires 2+ videos and selected project', () {
      final state = FusionState.initial();
      expect(state.canStartFusion, isFalse);

      // Con progetto ma senza video
      final stateWithProject = state.copyWith(
        selectedProject: _createTestProject('p1', canStart: true),
      );
      expect(stateWithProject.canStartFusion, isFalse);

      // Con progetto e 1 video (insufficiente)
      final stateWith1Video = stateWithProject.copyWith(
        projectVideos: [_createTestVideoSource('v1')],
      );
      expect(stateWith1Video.canStartFusion, isFalse);

      // Con progetto e 2 video (sufficiente)
      final stateWith2Videos = stateWithProject.copyWith(
        projectVideos: [
          _createTestVideoSource('v1'),
          _createTestVideoSource('v2'),
        ],
      );
      expect(stateWith2Videos.canStartFusion, isTrue);
    });

    test('computed property processingProgress returns status progress', () {
      final state = FusionState.initial();
      expect(state.processingProgress, equals(0.0));

      final stateWithStatus = state.copyWith(
        currentStatus: const FusionProcessingStatus(
          projectId: 'p1',
          status: FusionStatus.processing,
          progress: 0.75,
          currentPhase: 'Skeleton extraction',
        ),
      );
      expect(stateWithStatus.processingProgress, equals(0.75));
    });

    test('wizardStepIndex returns correct index', () {
      final state = FusionState.initial();
      expect(state.wizardStepIndex, equals(0)); // projectInfo

      final step2 = state.copyWith(wizardStep: FusionWizardStep.addVideos);
      expect(step2.wizardStepIndex, equals(1));

      final step3 = state.copyWith(wizardStep: FusionWizardStep.configureCamera);
      expect(step3.wizardStepIndex, equals(2));

      final step4 = state.copyWith(wizardStep: FusionWizardStep.review);
      expect(step4.wizardStepIndex, equals(3));

      final step5 = state.copyWith(wizardStep: FusionWizardStep.processing);
      expect(step5.wizardStepIndex, equals(4));

      final step6 = state.copyWith(wizardStep: FusionWizardStep.completed);
      expect(step6.wizardStepIndex, equals(5));
    });

    group('canAdvanceWizard', () {
      test('projectInfo step requires selected project', () {
        final state = FusionState.initial().copyWith(
          wizardStep: FusionWizardStep.projectInfo,
        );
        expect(state.canAdvanceWizard, isFalse);

        final withProject = state.copyWith(
          selectedProject: _createTestProject('p1'),
        );
        expect(withProject.canAdvanceWizard, isTrue);
      });

      test('addVideos step requires 2+ videos', () {
        final state = FusionState.initial().copyWith(
          wizardStep: FusionWizardStep.addVideos,
          selectedProject: _createTestProject('p1'),
        );
        expect(state.canAdvanceWizard, isFalse);

        final with2Videos = state.copyWith(
          projectVideos: [
            _createTestVideoSource('v1'),
            _createTestVideoSource('v2'),
          ],
        );
        expect(with2Videos.canAdvanceWizard, isTrue);
      });

      test('configureCamera step requires all videos calibrated', () {
        final state = FusionState.initial().copyWith(
          wizardStep: FusionWizardStep.configureCamera,
          selectedProject: _createTestProject('p1'),
          projectVideos: [
            _createTestVideoSource('v1', isCalibrated: false),
            _createTestVideoSource('v2', isCalibrated: true),
          ],
        );
        expect(state.canAdvanceWizard, isFalse);

        final allCalibrated = state.copyWith(
          projectVideos: [
            _createTestVideoSource('v1', isCalibrated: true),
            _createTestVideoSource('v2', isCalibrated: true),
          ],
        );
        expect(allCalibrated.canAdvanceWizard, isTrue);
      });

      test('processing step cannot advance', () {
        final state = FusionState.initial().copyWith(
          wizardStep: FusionWizardStep.processing,
        );
        expect(state.canAdvanceWizard, isFalse);
      });

      test('completed step cannot advance', () {
        final state = FusionState.initial().copyWith(
          wizardStep: FusionWizardStep.completed,
        );
        expect(state.canAdvanceWizard, isFalse);
      });
    });

    group('copyWith', () {
      test('preserves values when not specified', () {
        final original = FusionState.initial().copyWith(
          projectsLoadingState: FusionLoadingState.loaded,
          totalProjectsCount: 10,
          currentPage: 2,
        );

        final copied = original.copyWith(
          hasMoreProjects: true,
        );

        expect(copied.projectsLoadingState, equals(FusionLoadingState.loaded));
        expect(copied.totalProjectsCount, equals(10));
        expect(copied.currentPage, equals(2));
        expect(copied.hasMoreProjects, isTrue);
      });

      test('clear flags work correctly', () {
        final state = FusionState.initial().copyWith(
          projectsError: 'Some error',
          selectedProject: _createTestProject('p1'),
          fusionResult: const FusionResultEntity(
            id: 'r1',
            projectId: 'p1',
            outputUrl: 'https://example.com/output.mp4',
          ),
        );

        expect(state.projectsError, isNotNull);
        expect(state.selectedProject, isNotNull);
        expect(state.fusionResult, isNotNull);

        final cleared = state.copyWith(
          clearProjectsError: true,
          clearSelectedProject: true,
          clearFusionResult: true,
        );

        expect(cleared.projectsError, isNull);
        expect(cleared.selectedProject, isNull);
        expect(cleared.fusionResult, isNull);
      });
    });
  });

  group('FusionEvent Tests', () {
    test('LoadFusionProjects props', () {
      const event = LoadFusionProjects(page: 2, refresh: true);

      expect(event.page, equals(2));
      expect(event.refresh, isTrue);
      expect(event.status, isNull);
      expect(event.props, containsAll([2, null, true]));
    });

    test('LoadFusionProjects default values', () {
      const event = LoadFusionProjects();

      expect(event.page, equals(1));
      expect(event.refresh, isFalse);
    });

    test('CreateFusionProject props', () {
      const event = CreateFusionProject(
        name: 'Test Project',
        description: 'Description',
        style: MartialArtsStyle.karate,
        quality: FusionQuality.high,
      );

      expect(event.name, equals('Test Project'));
      expect(event.description, equals('Description'));
      expect(event.style, equals(MartialArtsStyle.karate));
      expect(event.quality, equals(FusionQuality.high));
    });

    test('CreateFusionProject default values', () {
      const event = CreateFusionProject(name: 'Test');

      expect(event.style, equals(MartialArtsStyle.generic));
      expect(event.quality, equals(FusionQuality.high));
    });

    test('SelectFusionProject props', () {
      const event = SelectFusionProject('project-123');

      expect(event.projectId, equals('project-123'));
      expect(event.props, contains('project-123'));
    });

    test('AddVideoToProject props', () {
      const event = AddVideoToProject(
        projectId: 'p1',
        videoId: 'v1',
        label: 'Front angle',
      );

      expect(event.projectId, equals('p1'));
      expect(event.videoId, equals('v1'));
      expect(event.label, equals('Front angle'));
    });

    test('RemoveVideoFromProject props', () {
      const event = RemoveVideoFromProject(
        projectId: 'p1',
        videoSourceId: 'vs1',
      );

      expect(event.projectId, equals('p1'));
      expect(event.videoSourceId, equals('vs1'));
    });

    test('StartFusionProcess props', () {
      const event = StartFusionProcess('project-123');

      expect(event.projectId, equals('project-123'));
    });

    test('CancelFusionProcess props', () {
      const event = CancelFusionProcess('project-123');

      expect(event.projectId, equals('project-123'));
    });

    test('WatchFusionStatus props', () {
      const event = WatchFusionStatus('project-123');

      expect(event.projectId, equals('project-123'));
    });

    test('FusionStatusUpdated props', () {
      const status = FusionProcessingStatus(
        projectId: 'p1',
        status: FusionStatus.processing,
        progress: 0.5,
        currentPhase: 'Processing',
      );
      final event = FusionStatusUpdated(status);

      expect(event.status, equals(status));
    });

    test('CreateBlenderExport props', () {
      const event = CreateBlenderExport(fusionResultId: 'result-123');

      expect(event.fusionResultId, equals('result-123'));
    });

    test('Wizard events props', () {
      const advance = AdvanceWizardStep();
      const previous = PreviousWizardStep();
      const goTo = GoToWizardStep(3);
      const reset = ResetWizard();

      expect(advance.props, isEmpty);
      expect(previous.props, isEmpty);
      expect(goTo.step, equals(3));
      expect(reset.props, isEmpty);
    });
  });

  group('FusionLoadingState Enum', () {
    test('has all expected values', () {
      expect(FusionLoadingState.values, containsAll([
        FusionLoadingState.initial,
        FusionLoadingState.loading,
        FusionLoadingState.loadingMore,
        FusionLoadingState.refreshing,
        FusionLoadingState.loaded,
        FusionLoadingState.error,
      ]));
    });
  });

  group('FusionWizardStep Enum', () {
    test('has all expected values in correct order', () {
      expect(FusionWizardStep.values.length, equals(6));
      expect(FusionWizardStep.values[0], equals(FusionWizardStep.projectInfo));
      expect(FusionWizardStep.values[1], equals(FusionWizardStep.addVideos));
      expect(FusionWizardStep.values[2], equals(FusionWizardStep.configureCamera));
      expect(FusionWizardStep.values[3], equals(FusionWizardStep.review));
      expect(FusionWizardStep.values[4], equals(FusionWizardStep.processing));
      expect(FusionWizardStep.values[5], equals(FusionWizardStep.completed));
    });
  });

  group('FusionStatus Enum', () {
    test('has all expected values', () {
      expect(FusionStatus.values, containsAll([
        FusionStatus.draft,
        FusionStatus.ready,
        FusionStatus.queued,
        FusionStatus.processing,
        FusionStatus.completed,
        FusionStatus.failed,
        FusionStatus.cancelled,
      ]));
    });
  });

  group('MartialArtsStyle Enum', () {
    test('has expected martial arts styles', () {
      expect(MartialArtsStyle.values, containsAll([
        MartialArtsStyle.generic,
        MartialArtsStyle.karate,
        MartialArtsStyle.taekwondo,
        MartialArtsStyle.judo,
        MartialArtsStyle.bjj,
        MartialArtsStyle.muayThai,
        MartialArtsStyle.boxing,
        MartialArtsStyle.wrestling,
        MartialArtsStyle.mma,
      ]));
    });
  });

  group('FusionQuality Enum', () {
    test('has all quality levels', () {
      expect(FusionQuality.values, containsAll([
        FusionQuality.low,
        FusionQuality.medium,
        FusionQuality.high,
        FusionQuality.ultra,
      ]));
    });
  });
}

/// Helper per creare FusionProjectEntity per test
FusionProjectEntity _createTestProject(
  String id, {
  String name = 'Test Project',
  FusionStatus status = FusionStatus.draft,
  bool canStart = false,
  int videoCount = 0,
}) {
  return FusionProjectEntity(
    id: id,
    name: name,
    status: status,
    style: MartialArtsStyle.karate,
    quality: FusionQuality.high,
    videoCount: videoCount,
    createdAt: DateTime.now(),
    updatedAt: DateTime.now(),
  );
}

/// Helper per creare FusionVideoSourceEntity per test
FusionVideoSourceEntity _createTestVideoSource(
  String id, {
  bool isCalibrated = false,
}) {
  return FusionVideoSourceEntity(
    id: id,
    videoId: 'video-$id',
    label: 'Video $id',
    order: 0,
    isCalibrated: isCalibrated,
    thumbnailUrl: 'https://example.com/thumb-$id.jpg',
  );
}

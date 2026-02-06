/// AI_MODULE: Avatar BLoC Tests
/// AI_DESCRIPTION: Test BLoC avatar con state transitions
/// AI_TEACHING: Verifica transizioni stato:
///              initial -> loading -> loaded/error
///              FilterByStyle, ToggleSkeletonOverlay, ResetView
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/avatar/domain/entities/avatar.dart';
import 'package:martial_arts_streaming/features/avatar/domain/repositories/avatar_repository.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/get_avatars.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/get_avatar_detail.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/apply_skeleton.dart';
import 'package:martial_arts_streaming/features/avatar/presentation/bloc/avatar_bloc.dart';
import 'package:martial_arts_streaming/features/avatar/presentation/bloc/avatar_event.dart';
import 'package:martial_arts_streaming/features/avatar/presentation/bloc/avatar_state.dart';

// Test implementation of AvatarRepository
class TestAvatarRepository implements AvatarRepository {
  List<AvatarEntity> avatarsToReturn = [];
  AvatarEntity? avatarDetailToReturn;
  BoneMappingEntity? boneMappingToReturn;
  List<AvatarStyleInfoEntity> stylesToReturn = [];
  ApplySkeletonResultEntity? skeletonResultToReturn;
  Failure? failureToReturn;
  String? lastStyleFilter;

  @override
  Future<Either<Failure, List<AvatarEntity>>> getAvatars({
    String? style,
    int page = 1,
    int pageSize = 20,
  }) async {
    lastStyleFilter = style;
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }

    // Filter by style if provided
    final filtered = style == null
        ? avatarsToReturn
        : avatarsToReturn.where((a) => a.style.toApiString() == style).toList();

    return Right(filtered);
  }

  @override
  Future<Either<Failure, AvatarEntity>> getAvatarDetail(String avatarId) async {
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }
    if (avatarDetailToReturn != null) {
      return Right(avatarDetailToReturn!);
    }
    return const Left(NotFoundFailure('Avatar not found'));
  }

  @override
  Future<Either<Failure, BoneMappingEntity>> getBoneMapping() async {
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }
    if (boneMappingToReturn != null) {
      return Right(boneMappingToReturn!);
    }
    return const Right(BoneMappingEntity(
      body: {},
      leftHand: {},
      rightHand: {},
      totalBones: 0,
    ));
  }

  @override
  Future<Either<Failure, ApplySkeletonResultEntity>> applySkeleton({
    required String avatarId,
    required String skeletonId,
    int? frameNumber,
    String outputFormat = 'transforms',
  }) async {
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }
    if (skeletonResultToReturn != null) {
      return Right(skeletonResultToReturn!);
    }
    return const Left(ServerFailure('Skeleton not found'));
  }

  @override
  Future<Either<Failure, List<AvatarStyleInfoEntity>>> getStyles() async {
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }
    return Right(stylesToReturn);
  }
}

void main() {
  late TestAvatarRepository repository;
  late GetAvatarsUseCase getAvatarsUseCase;
  late GetAvatarDetailUseCase getAvatarDetailUseCase;
  late ApplySkeletonUseCase applySkeletonUseCase;

  // Test data
  final testAvatars = [
    AvatarEntity(
      id: '1',
      name: 'Karate Master',
      style: AvatarStyle.karate,
      modelUrl: 'https://example.com/karate.glb',
      rigType: 'readyplayerme',
      createdAt: DateTime(2025, 1, 1),
    ),
    AvatarEntity(
      id: '2',
      name: 'Kung Fu Fighter',
      style: AvatarStyle.kungFu,
      modelUrl: 'https://example.com/kungfu.glb',
      rigType: 'readyplayerme',
      createdAt: DateTime(2025, 1, 2),
    ),
  ];

  final testAvatar = testAvatars.first;

  final testStyles = [
    const AvatarStyleInfoEntity(
      value: 'karate',
      label: 'Karate',
      description: 'Traditional karate style',
      avatarCount: 5,
    ),
    const AvatarStyleInfoEntity(
      value: 'kung_fu',
      label: 'Kung Fu',
      description: 'Chinese martial arts',
      avatarCount: 3,
    ),
  ];

  const testBoneMapping = BoneMappingEntity(
    body: {0: 'hips', 1: 'spine'},
    leftHand: {0: 'left_wrist'},
    rightHand: {0: 'right_wrist'},
    totalLandmarks: 75,
    totalBones: 4,
  );

  setUp(() {
    repository = TestAvatarRepository();
    getAvatarsUseCase = GetAvatarsUseCase(repository);
    getAvatarDetailUseCase = GetAvatarDetailUseCase(repository);
    applySkeletonUseCase = ApplySkeletonUseCase(repository);
  });

  AvatarBloc createBloc() {
    return AvatarBloc(
      getAvatarsUseCase: getAvatarsUseCase,
      getAvatarDetailUseCase: getAvatarDetailUseCase,
      applySkeletonUseCase: applySkeletonUseCase,
      repository: repository,
    );
  }

  group('AvatarBloc Initial State', () {
    test('initial state should be AvatarState with initial status', () {
      final bloc = createBloc();

      expect(bloc.state.status, equals(AvatarStatus.initial));
      expect(bloc.state.avatars, isEmpty);
      expect(bloc.state.selectedAvatar, isNull);
      expect(bloc.state.showSkeletonOverlay, isFalse);

      bloc.close();
    });
  });

  group('LoadAvatarsEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'emits [loading, loaded] when LoadAvatarsEvent succeeds',
      build: () {
        repository.avatarsToReturn = testAvatars;
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadAvatarsEvent()),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        AvatarState(
          status: AvatarStatus.loaded,
          avatars: testAvatars,
          currentPage: 1,
        ),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'emits [loading, error] when LoadAvatarsEvent fails',
      build: () {
        repository.failureToReturn = const ServerFailure('Network error');
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadAvatarsEvent()),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        const AvatarState(
          status: AvatarStatus.error,
          errorMessage: 'Network error',
        ),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'LoadAvatarsEvent with style filter filters correctly',
      build: () {
        repository.avatarsToReturn = testAvatars;
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadAvatarsEvent(style: 'karate')),
      verify: (_) {
        expect(repository.lastStyleFilter, equals('karate'));
      },
    );
  });

  group('LoadAvatarDetailEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'emits [loading, loaded with selectedAvatar] when detail succeeds',
      build: () {
        repository.avatarDetailToReturn = testAvatar;
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadAvatarDetailEvent('1')),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        AvatarState(
          status: AvatarStatus.loaded,
          selectedAvatar: testAvatar,
        ),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'emits [loading, error] when avatar not found',
      build: () {
        repository.failureToReturn = const NotFoundFailure('Avatar not found');
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadAvatarDetailEvent('999')),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        const AvatarState(
          status: AvatarStatus.error,
          errorMessage: 'Avatar not found',
        ),
      ],
    );
  });

  group('LoadStylesEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'populates styles when LoadStylesEvent succeeds',
      build: () {
        repository.stylesToReturn = testStyles;
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadStylesEvent()),
      expect: () => [
        AvatarState(styles: testStyles),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'does not emit error when styles fail (non-blocking)',
      build: () {
        repository.failureToReturn = const ServerFailure('Failed');
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadStylesEvent()),
      expect: () => <AvatarState>[], // No state change on failure (non-blocking)
    );
  });

  group('FilterByStyleEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'changes selectedStyle and triggers LoadAvatarsEvent',
      build: () {
        repository.avatarsToReturn = testAvatars;
        return createBloc();
      },
      act: (bloc) => bloc.add(const FilterByStyleEvent('karate')),
      expect: () => [
        const AvatarState(selectedStyle: 'karate'),
        const AvatarState(selectedStyle: 'karate', status: AvatarStatus.loading),
        isA<AvatarState>()
            .having((s) => s.status, 'status', AvatarStatus.loaded)
            .having((s) => s.selectedStyle, 'selectedStyle', 'karate'),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'FilterByStyleEvent with null clears style filter',
      build: () {
        repository.avatarsToReturn = testAvatars;
        return createBloc();
      },
      seed: () => const AvatarState(selectedStyle: 'karate'),
      act: (bloc) => bloc.add(const FilterByStyleEvent(null)),
      verify: (_) {
        expect(repository.lastStyleFilter, isNull);
      },
    );
  });

  group('ToggleSkeletonOverlayEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'toggles showSkeletonOverlay from false to true',
      build: createBloc,
      act: (bloc) => bloc.add(const ToggleSkeletonOverlayEvent()),
      expect: () => [
        const AvatarState(showSkeletonOverlay: true),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'toggles showSkeletonOverlay from true to false',
      build: createBloc,
      seed: () => const AvatarState(showSkeletonOverlay: true),
      act: (bloc) => bloc.add(const ToggleSkeletonOverlayEvent()),
      expect: () => [
        const AvatarState(showSkeletonOverlay: false),
      ],
    );
  });

  group('ResetViewEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'clears selectedAvatar and skeletonResult',
      build: createBloc,
      seed: () => AvatarState(
        selectedAvatar: testAvatar,
        showSkeletonOverlay: true,
        skeletonResult: const ApplySkeletonResultEntity(
          avatarId: '1',
          skeletonId: 'sk1',
          frameCount: 10,
          boneTransforms: [],
        ),
      ),
      act: (bloc) => bloc.add(const ResetViewEvent()),
      expect: () => [
        const AvatarState(
          showSkeletonOverlay: false,
          selectedAvatar: null,
          skeletonResult: null,
        ),
      ],
    );
  });

  group('LoadBoneMappingEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'populates boneMapping when succeeds',
      build: () {
        repository.boneMappingToReturn = testBoneMapping;
        return createBloc();
      },
      act: (bloc) => bloc.add(const LoadBoneMappingEvent()),
      expect: () => [
        const AvatarState(boneMapping: testBoneMapping),
      ],
    );
  });

  group('ApplySkeletonEvent', () {
    blocTest<AvatarBloc, AvatarState>(
      'emits [loading, loaded with skeletonResult] when succeeds',
      build: () {
        repository.skeletonResultToReturn = const ApplySkeletonResultEntity(
          avatarId: '1',
          skeletonId: 'skeleton-1',
          frameCount: 100,
          boneTransforms: [],
        );
        return createBloc();
      },
      act: (bloc) => bloc.add(const ApplySkeletonEvent(
        avatarId: '1',
        skeletonId: 'skeleton-1',
      )),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        const AvatarState(
          status: AvatarStatus.loaded,
          skeletonResult: ApplySkeletonResultEntity(
            avatarId: '1',
            skeletonId: 'skeleton-1',
            frameCount: 100,
            boneTransforms: [],
          ),
        ),
      ],
    );

    blocTest<AvatarBloc, AvatarState>(
      'emits error when applySkeleton fails',
      build: () {
        repository.failureToReturn = const ServerFailure('Skeleton not found');
        return createBloc();
      },
      act: (bloc) => bloc.add(const ApplySkeletonEvent(
        avatarId: '1',
        skeletonId: 'invalid',
      )),
      expect: () => [
        const AvatarState(status: AvatarStatus.loading),
        const AvatarState(
          status: AvatarStatus.error,
          errorMessage: 'Skeleton not found',
        ),
      ],
    );
  });

  group('AvatarState copyWith', () {
    test('copyWith preserves existing values', () {
      final state = AvatarState(
        status: AvatarStatus.loaded,
        avatars: testAvatars,
        selectedStyle: 'karate',
      );

      final newState = state.copyWith(showSkeletonOverlay: true);

      expect(newState.status, equals(AvatarStatus.loaded));
      expect(newState.avatars, equals(testAvatars));
      expect(newState.selectedStyle, equals('karate'));
      expect(newState.showSkeletonOverlay, isTrue);
    });

    test('copyWith with clearSelectedAvatar sets to null', () {
      final state = AvatarState(selectedAvatar: testAvatar);
      final newState = state.copyWith(clearSelectedAvatar: true);

      expect(newState.selectedAvatar, isNull);
    });

    test('copyWith with clearError sets errorMessage to null', () {
      const state = AvatarState(errorMessage: 'Some error');
      final newState = state.copyWith(clearError: true);

      expect(newState.errorMessage, isNull);
    });
  });

  group('AvatarEvent Equatable', () {
    test('LoadAvatarsEvent with same props are equal', () {
      const event1 = LoadAvatarsEvent(style: 'karate', page: 1);
      const event2 = LoadAvatarsEvent(style: 'karate', page: 1);

      expect(event1, equals(event2));
    });

    test('LoadAvatarDetailEvent with same avatarId are equal', () {
      const event1 = LoadAvatarDetailEvent('1');
      const event2 = LoadAvatarDetailEvent('1');

      expect(event1, equals(event2));
    });

    test('FilterByStyleEvent with different styles are not equal', () {
      const event1 = FilterByStyleEvent('karate');
      const event2 = FilterByStyleEvent('judo');

      expect(event1, isNot(equals(event2)));
    });
  });
}

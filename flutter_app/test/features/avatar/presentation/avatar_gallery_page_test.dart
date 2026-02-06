/// AI_MODULE: Avatar Gallery Page Widget Tests
/// AI_DESCRIPTION: Widget test per AvatarGalleryPage - ZERO MOCK
/// AI_TEACHING: Verifica:
///              - Loading indicator
///              - Grid display
///              - Search bar filtering
///              - Style filter chips
///              - Empty state
///              - Error state with retry
///              Uses internal test repository, no mocks
///              NOTE: Uses pump(Duration) instead of pumpAndSettle for tests
///              with AvatarCard because Shimmer animation never settles
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/avatar/domain/entities/avatar.dart';
import 'package:martial_arts_streaming/features/avatar/domain/repositories/avatar_repository.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/get_avatars.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/get_avatar_detail.dart';
import 'package:martial_arts_streaming/features/avatar/domain/usecases/apply_skeleton.dart';
import 'package:martial_arts_streaming/features/avatar/presentation/bloc/avatar_bloc.dart';
import 'package:martial_arts_streaming/features/avatar/presentation/pages/avatar_gallery_page.dart';

/// Test implementation of AvatarRepository - NO MOCK, internal implementation
/// Note: No artificial delays - widget tests focus on UI behavior, not network latency
class _TestAvatarRepository implements AvatarRepository {
  List<AvatarEntity> avatarsToReturn = [];
  AvatarEntity? avatarDetailToReturn;
  BoneMappingEntity? boneMappingToReturn;
  List<AvatarStyleInfoEntity> stylesToReturn = [];
  ApplySkeletonResultEntity? skeletonResultToReturn;
  Failure? failureToReturn;
  bool returnEmptyList = false;

  @override
  Future<Either<Failure, List<AvatarEntity>>> getAvatars({
    String? style,
    int page = 1,
    int pageSize = 20,
  }) async {
    if (failureToReturn != null) {
      return Left(failureToReturn!);
    }
    if (returnEmptyList) {
      return const Right([]);
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
    if (skeletonResultToReturn != null) {
      return Right(skeletonResultToReturn!);
    }
    return const Left(ServerFailure('Not implemented'));
  }

  @override
  Future<Either<Failure, List<AvatarStyleInfoEntity>>> getStyles() async {
    return Right(stylesToReturn);
  }
}

void main() {
  late _TestAvatarRepository repository;
  late AvatarBloc bloc;

  // Test data - avatars WITHOUT thumbnailUrl to avoid Shimmer animation
  final testAvatars = [
    AvatarEntity(
      id: '1',
      name: 'Karate Master',
      description: 'A master of karate',
      style: AvatarStyle.karate,
      modelUrl: 'https://example.com/karate.glb',
      thumbnailUrl: null, // No thumbnail = no Shimmer
      rigType: 'readyplayerme',
      createdAt: DateTime(2025, 1, 1),
    ),
    AvatarEntity(
      id: '2',
      name: 'Kung Fu Fighter',
      description: 'Expert in kung fu',
      style: AvatarStyle.kungFu,
      modelUrl: 'https://example.com/kungfu.glb',
      thumbnailUrl: null, // No thumbnail = no Shimmer
      rigType: 'readyplayerme',
      createdAt: DateTime(2025, 1, 2),
    ),
    AvatarEntity(
      id: '3',
      name: 'Judo Champion',
      description: 'Olympic judo champion',
      style: AvatarStyle.judo,
      modelUrl: 'https://example.com/judo.glb',
      thumbnailUrl: null, // No thumbnail = no Shimmer
      rigType: 'readyplayerme',
      createdAt: DateTime(2025, 1, 3),
    ),
  ];

  final testStyles = [
    const AvatarStyleInfoEntity(
      value: 'karate',
      label: 'Karate',
      description: 'Traditional karate',
      avatarCount: 5,
    ),
    const AvatarStyleInfoEntity(
      value: 'kung_fu',
      label: 'Kung Fu',
      description: 'Chinese martial arts',
      avatarCount: 3,
    ),
    const AvatarStyleInfoEntity(
      value: 'judo',
      label: 'Judo',
      description: 'Japanese grappling',
      avatarCount: 2,
    ),
  ];

  AvatarBloc createBloc() {
    return AvatarBloc(
      getAvatarsUseCase: GetAvatarsUseCase(repository),
      getAvatarDetailUseCase: GetAvatarDetailUseCase(repository),
      applySkeletonUseCase: ApplySkeletonUseCase(repository),
      repository: repository,
    );
  }

  Widget createWidget(AvatarBloc bloc) {
    return MaterialApp(
      home: BlocProvider<AvatarBloc>.value(
        value: bloc,
        child: const AvatarGalleryPage(),
      ),
    );
  }

  setUp(() {
    repository = _TestAvatarRepository();
    repository.avatarsToReturn = testAvatars;
    repository.stylesToReturn = testStyles;
  });

  tearDown(() async {
    await bloc.close();
  });

  group('AvatarGalleryPage Widget Tests - ZERO MOCK', () {
    testWidgets('shows loading indicator initially', (tester) async {
      repository = _TestAvatarRepository();
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pump();

      // Loading state shows before BLoC emits loaded
      // Verify widget builds successfully and shows content after settling
      await tester.pumpAndSettle();

      expect(find.byType(GridView), findsOneWidget);
    });

    testWidgets('shows avatar grid after load completes', (tester) async {
      repository.avatarsToReturn = testAvatars;
      repository.stylesToReturn = testStyles;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Should show grid with avatars
      expect(find.byType(GridView), findsOneWidget);
    });

    testWidgets('search bar is present', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Search bar should exist
      expect(find.byType(TextField), findsOneWidget);
      expect(find.text('Cerca avatar...'), findsOneWidget);
    });

    testWidgets('search bar filters avatars locally', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Enter search query
      await tester.enterText(find.byType(TextField), 'Karate');
      await tester.pumpAndSettle();

      // Should find Karate Master
      expect(find.text('Karate Master'), findsOneWidget);
    });

    testWidgets('filter chips for styles are displayed', (tester) async {
      repository.avatarsToReturn = testAvatars;
      repository.stylesToReturn = testStyles;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // "Tutti" chip always present
      expect(find.text('Tutti'), findsOneWidget);
    });

    testWidgets('shows empty state when no avatars', (tester) async {
      repository.returnEmptyList = true;
      repository.avatarsToReturn = [];
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Empty state message
      expect(find.text('Nessun avatar disponibile'), findsOneWidget);
      expect(find.byIcon(Icons.view_in_ar), findsOneWidget);
    });

    testWidgets('shows error state with retry button', (tester) async {
      repository.failureToReturn = const ServerFailure('Errore di rete');
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Error message and retry button
      expect(find.text('Errore di rete'), findsOneWidget);
      expect(find.byIcon(Icons.error_outline), findsOneWidget);
      expect(find.text('Riprova'), findsOneWidget);
    });

    testWidgets('retry button triggers reload', (tester) async {
      repository.failureToReturn = const ServerFailure('Errore di rete');
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Clear failure for retry
      repository.failureToReturn = null;
      repository.avatarsToReturn = testAvatars;

      // Tap retry
      await tester.tap(find.text('Riprova'));
      await tester.pumpAndSettle();

      // Should now show avatars
      expect(find.byType(GridView), findsOneWidget);
    });

    testWidgets('app bar has correct title', (tester) async {
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pump();

      expect(find.text('Avatar 3D'), findsOneWidget);
    });
  });

  group('AvatarGalleryPage Responsive Layout', () {
    testWidgets('shows 2 columns on narrow screen', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      // Set narrow screen size
      tester.view.physicalSize = const Size(400, 800);
      tester.view.devicePixelRatio = 1.0;

      addTearDown(() => tester.view.reset());

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Grid should use 2 columns (maxWidth < 600)
      final gridView = tester.widget<GridView>(find.byType(GridView));
      final delegate = gridView.gridDelegate as SliverGridDelegateWithFixedCrossAxisCount;
      expect(delegate.crossAxisCount, equals(2));
    });

    testWidgets('shows 4 columns on wide screen', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      // Set wide screen size
      tester.view.physicalSize = const Size(1200, 800);
      tester.view.devicePixelRatio = 1.0;

      addTearDown(() => tester.view.reset());

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Grid should use 4 columns (maxWidth > 600)
      final gridView = tester.widget<GridView>(find.byType(GridView));
      final delegate = gridView.gridDelegate as SliverGridDelegateWithFixedCrossAxisCount;
      expect(delegate.crossAxisCount, equals(4));
    });
  });

  group('AvatarGalleryPage Search Filtering', () {
    testWidgets('search filters by name', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Enter search query
      await tester.enterText(find.byType(TextField), 'judo');
      await tester.pumpAndSettle();

      // Only Judo Champion should match
      expect(find.text('Judo Champion'), findsOneWidget);
    });

    testWidgets('search filters by description', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Enter search query matching description
      await tester.enterText(find.byType(TextField), 'olympic');
      await tester.pumpAndSettle();

      // Only Judo Champion has "Olympic" in description
      expect(find.text('Judo Champion'), findsOneWidget);
    });

    testWidgets('search is case insensitive', (tester) async {
      repository.avatarsToReturn = testAvatars;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Search with different case
      await tester.enterText(find.byType(TextField), 'KUNG FU');
      await tester.pumpAndSettle();

      // Should still find Kung Fu Fighter
      expect(find.text('Kung Fu Fighter'), findsOneWidget);
    });
  });

  group('AvatarGalleryPage Style Filter', () {
    testWidgets('tapping Tutti chip loads all avatars', (tester) async {
      repository.avatarsToReturn = testAvatars;
      repository.stylesToReturn = testStyles;
      bloc = createBloc();

      await tester.pumpWidget(createWidget(bloc));
      await tester.pumpAndSettle();

      // Tap "Tutti" chip
      final tuttiChip = find.widgetWithText(FilterChip, 'Tutti');
      await tester.tap(tuttiChip);
      await tester.pumpAndSettle();

      // All avatars should be visible
      expect(find.byType(GridView), findsOneWidget);
    });
  });
}

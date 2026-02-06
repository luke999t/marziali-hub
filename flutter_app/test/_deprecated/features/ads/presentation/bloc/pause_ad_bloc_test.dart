/// ================================================================================
/// AI_MODULE: PauseAdBloc Tests
/// AI_DESCRIPTION: Test suite per PauseAdBloc
/// AI_BUSINESS: Verifica state management pause ads overlay
/// AI_TEACHING: bloc_test, state transitions, timer handling
///
/// COVERAGE_TARGET: >= 90%
///
/// TEST CASES:
/// - Initial state
/// - Fetch success -> visible state
/// - Fetch for premium -> hidden state
/// - Hide overlay event
/// - Record impression event
/// - Record click events
/// - Error handling
/// ================================================================================

import 'package:flutter_test/flutter_test.dart';
import 'package:bloc_test/bloc_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:dartz/dartz.dart';

import 'package:media_center_app/core/error/failures.dart';
import 'package:media_center_app/features/ads/domain/entities/pause_ad.dart';
import 'package:media_center_app/features/ads/domain/usecases/fetch_pause_ad_usecase.dart';
import 'package:media_center_app/features/ads/domain/usecases/record_impression_usecase.dart';
import 'package:media_center_app/features/ads/domain/usecases/record_click_usecase.dart';
import 'package:media_center_app/features/ads/presentation/bloc/pause_ad_bloc.dart';

@GenerateMocks([
  FetchPauseAdUseCase,
  RecordImpressionUseCase,
  RecordClickUseCase,
])
import 'pause_ad_bloc_test.mocks.dart';

void main() {
  late PauseAdBloc bloc;
  late MockFetchPauseAdUseCase mockFetchPauseAdUseCase;
  late MockRecordImpressionUseCase mockRecordImpressionUseCase;
  late MockRecordClickUseCase mockRecordClickUseCase;

  setUp(() {
    mockFetchPauseAdUseCase = MockFetchPauseAdUseCase();
    mockRecordImpressionUseCase = MockRecordImpressionUseCase();
    mockRecordClickUseCase = MockRecordClickUseCase();

    bloc = PauseAdBloc(
      fetchPauseAdUseCase: mockFetchPauseAdUseCase,
      recordImpressionUseCase: mockRecordImpressionUseCase,
      recordClickUseCase: mockRecordClickUseCase,
    );
  });

  tearDown(() {
    bloc.close();
  });

  // Test data
  final testPauseAd = PauseAd(
    suggestedVideo: const SuggestedVideo(
      id: 'suggested-456',
      title: 'Kata Heian Nidan',
      thumbnailUrl: 'https://example.com/thumb.jpg',
      duration: 180,
      maestroName: 'Maestro Chen',
      style: 'Karate Shotokan',
    ),
    sponsorAd: const SponsorAd(
      id: 'ad-001',
      advertiser: 'Decathlon',
      title: 'Kimono -30%',
      imageUrl: 'https://example.com/ad.jpg',
      clickUrl: 'https://decathlon.it/promo',
    ),
    impressionId: 'imp-uuid-123',
    showOverlay: true,
  );

  final testEmptyPauseAd = const PauseAd(
    impressionId: '',
    showOverlay: false,
  );

  group('PauseAdBloc', () {
    test('initial state should be PauseAdState.initial()', () {
      expect(bloc.state.status, PauseAdStatus.initial);
      expect(bloc.state.pauseAd, null);
      expect(bloc.state.impressionSent, false);
    });

    group('FetchPauseAdEvent', () {
      blocTest<PauseAdBloc, PauseAdState>(
        'emits [loading, visible] when fetch succeeds with content',
        build: () {
          when(mockFetchPauseAdUseCase(any))
              .thenAnswer((_) async => Right(testPauseAd));
          return bloc;
        },
        act: (bloc) => bloc.add(const FetchPauseAdEvent(
          userTier: 'free',
          videoId: 'video-123',
        )),
        expect: () => [
          isA<PauseAdState>().having((s) => s.status, 'status', PauseAdStatus.loading),
          isA<PauseAdState>()
              .having((s) => s.status, 'status', PauseAdStatus.visible)
              .having((s) => s.pauseAd, 'pauseAd', testPauseAd),
        ],
        verify: (_) {
          verify(mockFetchPauseAdUseCase(any)).called(1);
        },
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'emits [loading, hidden] when fetch returns empty PauseAd (premium user)',
        build: () {
          when(mockFetchPauseAdUseCase(any))
              .thenAnswer((_) async => Right(testEmptyPauseAd));
          return bloc;
        },
        act: (bloc) => bloc.add(const FetchPauseAdEvent(
          userTier: 'premium',
          videoId: 'video-123',
        )),
        expect: () => [
          isA<PauseAdState>().having((s) => s.status, 'status', PauseAdStatus.loading),
          isA<PauseAdState>().having((s) => s.status, 'status', PauseAdStatus.hidden),
        ],
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'emits [loading, error] when fetch fails',
        build: () {
          when(mockFetchPauseAdUseCase(any))
              .thenAnswer((_) async => const Left(NetworkFailure('No connection')));
          return bloc;
        },
        act: (bloc) => bloc.add(const FetchPauseAdEvent(
          userTier: 'free',
          videoId: 'video-123',
        )),
        expect: () => [
          isA<PauseAdState>().having((s) => s.status, 'status', PauseAdStatus.loading),
          isA<PauseAdState>()
              .having((s) => s.status, 'status', PauseAdStatus.error)
              .having((s) => s.errorMessage, 'errorMessage', 'No connection'),
        ],
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'stores currentVideoId when fetching',
        build: () {
          when(mockFetchPauseAdUseCase(any))
              .thenAnswer((_) async => Right(testPauseAd));
          return bloc;
        },
        act: (bloc) => bloc.add(const FetchPauseAdEvent(
          userTier: 'free',
          videoId: 'video-xyz',
        )),
        verify: (bloc) {
          expect(bloc.state.currentVideoId, 'video-xyz');
        },
      );
    });

    group('HideOverlayEvent', () {
      blocTest<PauseAdBloc, PauseAdState>(
        'emits hidden status when HideOverlayEvent is added',
        build: () => bloc,
        seed: () => PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        ),
        act: (bloc) => bloc.add(const HideOverlayEvent()),
        expect: () => [
          isA<PauseAdState>().having((s) => s.status, 'status', PauseAdStatus.hidden),
        ],
      );
    });

    group('RecordImpressionEvent', () {
      blocTest<PauseAdBloc, PauseAdState>(
        'calls recordImpressionUseCase and sets impressionSent=true',
        build: () {
          when(mockRecordImpressionUseCase(any))
              .thenAnswer((_) async => const Right(null));
          return bloc;
        },
        seed: () => PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
          currentVideoId: 'video-123',
          impressionSent: false,
        ),
        act: (bloc) => bloc.add(const RecordImpressionEvent()),
        expect: () => [
          isA<PauseAdState>()
              .having((s) => s.status, 'status', PauseAdStatus.impressionRecorded)
              .having((s) => s.impressionSent, 'impressionSent', true),
        ],
        verify: (_) {
          verify(mockRecordImpressionUseCase(any)).called(1);
        },
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'does not call usecase when impression already sent',
        build: () => bloc,
        seed: () => PauseAdState(
          status: PauseAdStatus.impressionRecorded,
          pauseAd: testPauseAd,
          currentVideoId: 'video-123',
          impressionSent: true,
        ),
        act: (bloc) => bloc.add(const RecordImpressionEvent()),
        expect: () => [],
        verify: (_) {
          verifyNever(mockRecordImpressionUseCase(any));
        },
      );
    });

    group('RecordClickEvent', () {
      blocTest<PauseAdBloc, PauseAdState>(
        'calls recordClickUseCase for ad click',
        build: () {
          when(mockRecordClickUseCase(any))
              .thenAnswer((_) async => const Right(null));
          return bloc;
        },
        seed: () => PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        ),
        act: (bloc) => bloc.add(const RecordClickEvent(AdClickType.ad)),
        verify: (_) {
          verify(mockRecordClickUseCase(any)).called(1);
        },
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'calls recordClickUseCase for suggested video click',
        build: () {
          when(mockRecordClickUseCase(any))
              .thenAnswer((_) async => const Right(null));
          return bloc;
        },
        seed: () => PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
        ),
        act: (bloc) => bloc.add(const RecordClickEvent(AdClickType.suggested)),
        verify: (_) {
          verify(mockRecordClickUseCase(any)).called(1);
        },
      );

      blocTest<PauseAdBloc, PauseAdState>(
        'does not crash when pauseAd is null',
        build: () => bloc,
        seed: () => const PauseAdState(status: PauseAdStatus.initial),
        act: (bloc) => bloc.add(const RecordClickEvent(AdClickType.ad)),
        expect: () => [],
        verify: (_) {
          verifyNever(mockRecordClickUseCase(any));
        },
      );
    });

    group('ResetPauseAdEvent', () {
      blocTest<PauseAdBloc, PauseAdState>(
        'resets state to initial',
        build: () => bloc,
        seed: () => PauseAdState(
          status: PauseAdStatus.visible,
          pauseAd: testPauseAd,
          currentVideoId: 'video-123',
          impressionSent: true,
        ),
        act: (bloc) => bloc.add(const ResetPauseAdEvent()),
        expect: () => [
          isA<PauseAdState>()
              .having((s) => s.status, 'status', PauseAdStatus.initial)
              .having((s) => s.pauseAd, 'pauseAd', null)
              .having((s) => s.impressionSent, 'impressionSent', false),
        ],
      );
    });
  });

  group('PauseAdState', () {
    test('shouldShowOverlay returns true for visible status', () {
      final state = PauseAdState(
        status: PauseAdStatus.visible,
        pauseAd: testPauseAd,
      );
      expect(state.shouldShowOverlay, true);
    });

    test('shouldShowOverlay returns true for impressionRecorded status', () {
      final state = PauseAdState(
        status: PauseAdStatus.impressionRecorded,
        pauseAd: testPauseAd,
      );
      expect(state.shouldShowOverlay, true);
    });

    test('shouldShowOverlay returns false for hidden status', () {
      final state = PauseAdState(
        status: PauseAdStatus.hidden,
        pauseAd: testPauseAd,
      );
      expect(state.shouldShowOverlay, false);
    });

    test('hasContent returns true when pauseAd has content', () {
      final state = PauseAdState(
        status: PauseAdStatus.visible,
        pauseAd: testPauseAd,
      );
      expect(state.hasContent, true);
    });

    test('hasContent returns false when pauseAd is null', () {
      const state = PauseAdState(status: PauseAdStatus.initial);
      expect(state.hasContent, false);
    });
  });
}

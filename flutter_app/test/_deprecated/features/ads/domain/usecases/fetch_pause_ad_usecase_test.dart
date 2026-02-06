/// ================================================================================
/// AI_MODULE: FetchPauseAdUseCase Tests
/// AI_DESCRIPTION: Test suite per FetchPauseAdUseCase
/// AI_BUSINESS: Verifica logica tier eligibility e fetch pause ads
/// AI_TEACHING: BDD testing, dartz Either, mock repositories
///
/// COVERAGE_TARGET: >= 90%
///
/// TEST CASES:
/// - Premium users never see ads
/// - Business users never see ads
/// - Free users always see ads
/// - Hybrid users see ads based on frequency
/// - Unknown tier defaults to free
/// ================================================================================

import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:dartz/dartz.dart';

import 'package:media_center_app/core/error/failures.dart';
import 'package:media_center_app/features/ads/domain/entities/pause_ad.dart';
import 'package:media_center_app/features/ads/domain/repositories/ads_repository.dart';
import 'package:media_center_app/features/ads/domain/usecases/fetch_pause_ad_usecase.dart';

@GenerateMocks([AdsRepository])
import 'fetch_pause_ad_usecase_test.mocks.dart';

void main() {
  late FetchPauseAdUseCase useCase;
  late MockAdsRepository mockRepository;

  setUp(() {
    mockRepository = MockAdsRepository();
    useCase = FetchPauseAdUseCase(mockRepository);
  });

  // Test data
  const testVideoId = 'video-123';

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

  group('FetchPauseAdUseCase', () {
    group('Premium tier', () {
      test('should return empty PauseAd with showOverlay=false for premium users', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'premium',
          videoId: testVideoId,
        );

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        result.fold(
          (failure) => fail('Should not return failure'),
          (pauseAd) {
            expect(pauseAd.showOverlay, false);
            expect(pauseAd.impressionId, '');
            expect(pauseAd.hasContent, false);
          },
        );

        // BUSINESS RULE: Premium users NEVER call API
        verifyNever(mockRepository.fetchPauseAd(
          userTier: anyNamed('userTier'),
          videoId: anyNamed('videoId'),
        ));
      });

      test('should handle PREMIUM in any case', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'PREMIUM',
          videoId: testVideoId,
        );

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        result.fold(
          (failure) => fail('Should not return failure'),
          (pauseAd) => expect(pauseAd.showOverlay, false),
        );
      });
    });

    group('Business tier', () {
      test('should return empty PauseAd with showOverlay=false for business users', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'business',
          videoId: testVideoId,
        );

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        result.fold(
          (failure) => fail('Should not return failure'),
          (pauseAd) {
            expect(pauseAd.showOverlay, false);
            expect(pauseAd.impressionId, '');
          },
        );

        // BUSINESS RULE: Business users NEVER call API
        verifyNever(mockRepository.fetchPauseAd(
          userTier: anyNamed('userTier'),
          videoId: anyNamed('videoId'),
        ));
      });
    });

    group('Free tier', () {
      test('should call repository and return PauseAd for free users', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'free',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).thenAnswer((_) async => Right(testPauseAd));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        result.fold(
          (failure) => fail('Should not return failure'),
          (pauseAd) {
            expect(pauseAd.showOverlay, true);
            expect(pauseAd.hasContent, true);
            expect(pauseAd.suggestedVideo?.id, 'suggested-456');
            expect(pauseAd.sponsorAd?.id, 'ad-001');
          },
        );

        verify(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).called(1);
      });
    });

    group('Hybrid tiers', () {
      test('should call repository for hybrid_light users', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'hybrid_light',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'hybrid_light',
          videoId: testVideoId,
        )).thenAnswer((_) async => Right(testPauseAd));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        verify(mockRepository.fetchPauseAd(
          userTier: 'hybrid_light',
          videoId: testVideoId,
        )).called(1);
      });

      test('should call repository for hybrid_standard users', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'hybrid_standard',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'hybrid_standard',
          videoId: testVideoId,
        )).thenAnswer((_) async => Right(testPauseAd));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);
        verify(mockRepository.fetchPauseAd(
          userTier: 'hybrid_standard',
          videoId: testVideoId,
        )).called(1);
      });
    });

    group('Unknown tier', () {
      test('should default to free tier for unknown tier', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'unknown_tier',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).thenAnswer((_) async => Right(testPauseAd));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isRight(), true);

        // BUSINESS RULE: Unknown tier treated as free (conservative)
        verify(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).called(1);
      });
    });

    group('Error handling', () {
      test('should return failure when repository returns failure', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'free',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).thenAnswer((_) async => const Left(NetworkFailure('No connection')));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isLeft(), true);
        result.fold(
          (failure) => expect(failure, isA<NetworkFailure>()),
          (_) => fail('Should return failure'),
        );
      });

      test('should return ServerFailure when server error occurs', () async {
        // Arrange
        const params = FetchPauseAdParams(
          userTier: 'free',
          videoId: testVideoId,
        );

        when(mockRepository.fetchPauseAd(
          userTier: 'free',
          videoId: testVideoId,
        )).thenAnswer((_) async => const Left(ServerFailure('Server error')));

        // Act
        final result = await useCase(params);

        // Assert
        expect(result.isLeft(), true);
        result.fold(
          (failure) => expect(failure, isA<ServerFailure>()),
          (_) => fail('Should return failure'),
        );
      });
    });
  });
}

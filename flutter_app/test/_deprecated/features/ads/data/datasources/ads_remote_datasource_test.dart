/// ================================================================================
/// AI_MODULE: AdsRemoteDataSource Tests
/// AI_DESCRIPTION: Test suite per AdsRemoteDataSource
/// AI_BUSINESS: Verifica chiamate API pause ads
/// AI_TEACHING: Mockito, HTTP testing, error handling
///
/// COVERAGE_TARGET: >= 90%
///
/// TEST CASES:
/// - fetchPauseAd success
/// - fetchPauseAd with query params
/// - recordImpression success
/// - recordClick success
/// - Retry on 5xx errors
/// - No retry on 4xx errors
/// ================================================================================

import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:dio/dio.dart';

import 'package:media_center_app/core/network/api_client.dart';
import 'package:media_center_app/core/error/exceptions.dart';
import 'package:media_center_app/features/ads/data/datasources/ads_remote_datasource.dart';
import 'package:media_center_app/features/ads/domain/entities/pause_ad.dart';

@GenerateMocks([ApiClient])
import 'ads_remote_datasource_test.mocks.dart';

void main() {
  late AdsRemoteDataSourceImpl dataSource;
  late MockApiClient mockApiClient;

  setUp(() {
    mockApiClient = MockApiClient();
    dataSource = AdsRemoteDataSourceImpl(mockApiClient);
  });

  // Test data
  final testPauseAdJson = {
    'suggested_video': {
      'id': 'video-123',
      'title': 'Kata Heian Nidan',
      'thumbnail_url': 'https://example.com/thumb.jpg',
      'duration': 180,
      'maestro_name': 'Maestro Chen',
      'style': 'Karate Shotokan',
      'category': 'kata',
    },
    'sponsor_ad': {
      'id': 'ad-001',
      'advertiser': 'Decathlon',
      'title': 'Kimono -30%',
      'description': 'Offerta speciale',
      'image_url': 'https://example.com/ad.jpg',
      'click_url': 'https://decathlon.it/promo',
    },
    'impression_id': 'imp-uuid-123',
    'show_overlay': true,
  };

  group('AdsRemoteDataSource', () {
    group('fetchPauseAd', () {
      test('should return PauseAdModel when API call is successful', () async {
        // Arrange
        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenAnswer((_) async => Response(
              data: testPauseAdJson,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad'),
            ));

        // Act
        final result = await dataSource.fetchPauseAd(
          userTier: 'free',
          videoId: 'video-123',
        );

        // Assert
        expect(result.impressionId, 'imp-uuid-123');
        expect(result.showOverlay, true);
        expect(result.suggestedVideo?.id, 'video-123');
        expect(result.sponsorAd?.id, 'ad-001');

        verify(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: {
            'user_tier': 'free',
            'video_id': 'video-123',
          },
        )).called(1);
      });

      test('should include correct query parameters', () async {
        // Arrange
        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenAnswer((_) async => Response(
              data: testPauseAdJson,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad'),
            ));

        // Act
        await dataSource.fetchPauseAd(
          userTier: 'hybrid_light',
          videoId: 'video-xyz',
        );

        // Assert
        verify(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: {
            'user_tier': 'hybrid_light',
            'video_id': 'video-xyz',
          },
        )).called(1);
      });

      test('should handle null suggestedVideo in response', () async {
        // Arrange
        final jsonWithoutVideo = {
          ...testPauseAdJson,
          'suggested_video': null,
        };

        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenAnswer((_) async => Response(
              data: jsonWithoutVideo,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad'),
            ));

        // Act
        final result = await dataSource.fetchPauseAd(
          userTier: 'free',
          videoId: 'video-123',
        );

        // Assert
        expect(result.suggestedVideo, null);
        expect(result.sponsorAd, isNotNull);
      });

      test('should handle null sponsorAd in response', () async {
        // Arrange
        final jsonWithoutAd = {
          ...testPauseAdJson,
          'sponsor_ad': null,
        };

        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenAnswer((_) async => Response(
              data: jsonWithoutAd,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad'),
            ));

        // Act
        final result = await dataSource.fetchPauseAd(
          userTier: 'free',
          videoId: 'video-123',
        );

        // Assert
        expect(result.suggestedVideo, isNotNull);
        expect(result.sponsorAd, null);
      });

      test('should retry on ServerException and succeed', () async {
        // Arrange
        var callCount = 0;
        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenAnswer((_) async {
          callCount++;
          if (callCount == 1) {
            throw ServerException('Server error');
          }
          return Response(
            data: testPauseAdJson,
            statusCode: 200,
            requestOptions: RequestOptions(path: '/ads/pause-ad'),
          );
        });

        // Act
        final result = await dataSource.fetchPauseAd(
          userTier: 'free',
          videoId: 'video-123',
        );

        // Assert
        expect(result.impressionId, 'imp-uuid-123');
        expect(callCount, 2);
      });

      test('should throw after max retries on persistent ServerException', () async {
        // Arrange
        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenThrow(ServerException('Server error'));

        // Act & Assert
        expect(
          () => dataSource.fetchPauseAd(
            userTier: 'free',
            videoId: 'video-123',
          ),
          throwsA(isA<ServerException>()),
        );
      });

      test('should not retry on ValidationException (4xx)', () async {
        // Arrange
        when(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).thenThrow(ValidationException('Bad request'));

        // Act & Assert
        expect(
          () => dataSource.fetchPauseAd(
            userTier: 'free',
            videoId: 'video-123',
          ),
          throwsA(isA<ValidationException>()),
        );

        // Should only be called once (no retry)
        verify(mockApiClient.get(
          '/ads/pause-ad',
          queryParameters: anyNamed('queryParameters'),
        )).called(1);
      });
    });

    group('recordImpression', () {
      test('should call POST with correct body', () async {
        // Arrange
        when(mockApiClient.post(
          '/ads/pause-ad/impression',
          data: anyNamed('data'),
        )).thenAnswer((_) async => Response(
              data: {'success': true},
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad/impression'),
            ));

        // Act
        await dataSource.recordImpression(
          impressionId: 'imp-123',
          adId: 'ad-001',
          videoId: 'video-456',
        );

        // Assert
        verify(mockApiClient.post(
          '/ads/pause-ad/impression',
          data: argThat(
            allOf(
              containsPair('impression_id', 'imp-123'),
              containsPair('ad_id', 'ad-001'),
              containsPair('video_id', 'video-456'),
              contains('timestamp'),
            ),
            named: 'data',
          ),
        )).called(1);
      });

      test('should include ISO 8601 timestamp', () async {
        // Arrange
        Map<String, dynamic>? capturedData;
        when(mockApiClient.post(
          '/ads/pause-ad/impression',
          data: anyNamed('data'),
        )).thenAnswer((invocation) async {
          capturedData = invocation.namedArguments[const Symbol('data')];
          return Response(
            data: {'success': true},
            statusCode: 200,
            requestOptions: RequestOptions(path: '/ads/pause-ad/impression'),
          );
        });

        // Act
        await dataSource.recordImpression(
          impressionId: 'imp-123',
          adId: 'ad-001',
          videoId: 'video-456',
        );

        // Assert
        expect(capturedData?['timestamp'], isA<String>());
        final timestamp = capturedData?['timestamp'] as String;
        expect(DateTime.tryParse(timestamp), isNotNull);
      });
    });

    group('recordClick', () {
      test('should call POST with ad click type', () async {
        // Arrange
        when(mockApiClient.post(
          '/ads/pause-ad/click',
          data: anyNamed('data'),
        )).thenAnswer((_) async => Response(
              data: {'success': true},
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad/click'),
            ));

        // Act
        await dataSource.recordClick(
          impressionId: 'imp-123',
          clickType: AdClickType.ad,
        );

        // Assert
        verify(mockApiClient.post(
          '/ads/pause-ad/click',
          data: argThat(
            allOf(
              containsPair('impression_id', 'imp-123'),
              containsPair('click_type', 'ad'),
              contains('timestamp'),
            ),
            named: 'data',
          ),
        )).called(1);
      });

      test('should call POST with suggested click type', () async {
        // Arrange
        when(mockApiClient.post(
          '/ads/pause-ad/click',
          data: anyNamed('data'),
        )).thenAnswer((_) async => Response(
              data: {'success': true},
              statusCode: 200,
              requestOptions: RequestOptions(path: '/ads/pause-ad/click'),
            ));

        // Act
        await dataSource.recordClick(
          impressionId: 'imp-123',
          clickType: AdClickType.suggested,
        );

        // Assert
        verify(mockApiClient.post(
          '/ads/pause-ad/click',
          data: argThat(
            containsPair('click_type', 'suggested'),
            named: 'data',
          ),
        )).called(1);
      });
    });
  });
}

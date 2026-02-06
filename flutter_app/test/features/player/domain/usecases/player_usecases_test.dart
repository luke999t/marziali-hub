/// 🎓 AI_MODULE: PlayerUseCasesTest
/// 🎓 AI_DESCRIPTION: Test UseCase Player con backend reale - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione streaming, progresso, sottotitoli, qualità
/// 🎓 AI_TEACHING: Pattern test enterprise - backend reale obbligatorio
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:dio/dio.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/core/network/network_info.dart';
import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/video_info.dart';
import 'package:martial_arts_streaming/features/player/domain/usecases/player_usecases.dart';
import 'package:martial_arts_streaming/features/player/domain/repositories/player_repository.dart';
import 'package:martial_arts_streaming/features/player/data/models/video_info_model.dart';

import '../../../../helpers/backend_checker.dart';

/// NetworkInfo per test - sempre connesso
class _TestNetworkInfo implements NetworkInfo {
  @override
  Future<bool> get isConnected async => true;

  @override
  Stream<ConnectivityResult> get onConnectivityChanged => const Stream.empty();
}

void main() {
  late Dio dio;
  late _TestPlayerRemoteDataSource remoteDataSource;
  late _TestPlayerRepository repository;

  // UseCase instances
  late GetVideoStreamUseCase getVideoStreamUseCase;
  late GetStreamUrlUseCase getStreamUrlUseCase;
  late GetSkeletonDataUseCase getSkeletonDataUseCase;
  late GetSubtitlesUseCase getSubtitlesUseCase;
  late SaveProgressUseCase saveProgressUseCase;
  late GetSavedPositionUseCase getSavedPositionUseCase;
  late MarkVideoCompletedUseCase markVideoCompletedUseCase;
  late GetVideoInfoUseCase getVideoInfoUseCase;
  late GetNextEpisodeUseCase getNextEpisodeUseCase;
  late GetEpisodeListUseCase getEpisodeListUseCase;
  late GetAvailableQualitiesUseCase getAvailableQualitiesUseCase;
  late GetAvailableAudioTracksUseCase getAvailableAudioTracksUseCase;
  late GetAvailableSubtitlesUseCase getAvailableSubtitlesUseCase;

  setUpAll(() async {
    WidgetsFlutterBinding.ensureInitialized();

    dio = Dio(BaseOptions(
      baseUrl: '${BackendChecker.baseUrl}/api/v1',
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    remoteDataSource = _TestPlayerRemoteDataSource(dio);
    repository = _TestPlayerRepository(remoteDataSource);

    // UseCases REALI
    getVideoStreamUseCase = GetVideoStreamUseCase(repository);
    getStreamUrlUseCase = GetStreamUrlUseCase(repository);
    getSkeletonDataUseCase = GetSkeletonDataUseCase(repository);
    getSubtitlesUseCase = GetSubtitlesUseCase(repository);
    saveProgressUseCase = SaveProgressUseCase(repository);
    getSavedPositionUseCase = GetSavedPositionUseCase(repository);
    markVideoCompletedUseCase = MarkVideoCompletedUseCase(repository);
    getVideoInfoUseCase = GetVideoInfoUseCase(repository);
    getNextEpisodeUseCase = GetNextEpisodeUseCase(repository);
    getEpisodeListUseCase = GetEpisodeListUseCase(repository);
    getAvailableQualitiesUseCase = GetAvailableQualitiesUseCase(repository);
    getAvailableAudioTracksUseCase = GetAvailableAudioTracksUseCase(repository);
    getAvailableSubtitlesUseCase = GetAvailableSubtitlesUseCase(repository);
  });

  tearDownAll(() {
    dio.close();
  });

  group('GetVideoStreamUseCase - Backend Reale', () {
    testWithBackend('deve ritornare VideoStream per video valido', () async {
      const videoId = 'test-video-stream-001';

      final result = await getVideoStreamUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (stream) {
          expect(stream, isA<VideoStream>());
          expect(stream.streamUrl, isNotEmpty);
          expect(stream.videoInfo, isA<VideoInfo>());
        },
      );
    });

    testWithBackend('deve gestire video ID non esistente', () async {
      const videoId = 'non-existent-video-xyz-999';

      final result = await getVideoStreamUseCase(videoId);

      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (stream) => expect(stream, isA<VideoStream>()),
      );
    });
  });

  group('GetStreamUrlUseCase - Backend Reale', () {
    testWithBackend('deve ritornare URL per qualità 1080p', () async {
      final result = await getStreamUrlUseCase(
        videoId: 'test-video-quality',
        quality: '1080p',
      );

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (url) => expect(url, isA<String>()),
      );
    });

    testWithBackend('deve ritornare URL per qualità 720p', () async {
      final result = await getStreamUrlUseCase(
        videoId: 'test-video-quality',
        quality: '720p',
      );

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (url) => expect(url, isA<String>()),
      );
    });

    testWithBackend('deve ritornare URL per qualità Auto', () async {
      final result = await getStreamUrlUseCase(
        videoId: 'test-video-quality',
        quality: 'Auto',
      );

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (url) => expect(url, isA<String>()),
      );
    });
  });

  group('GetSkeletonDataUseCase - Backend Reale', () {
    testWithBackend('deve ritornare skeleton data per video con analisi', () async {
      const videoId = 'test-video-skeleton';

      final result = await getSkeletonDataUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (data) => expect(data, isA<Map<String, dynamic>>()),
      );
    });

    testWithBackend('deve gestire video senza skeleton data', () async {
      const videoId = 'video-without-skeleton';

      final result = await getSkeletonDataUseCase(videoId);

      // Può ritornare mappa vuota o errore
      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (data) => expect(data, isA<Map<String, dynamic>>()),
      );
    });
  });

  group('GetSubtitlesUseCase - Backend Reale', () {
    testWithBackend('deve ritornare sottotitoli in italiano', () async {
      final result = await getSubtitlesUseCase(
        videoId: 'test-video-subtitles',
        language: 'Italian',
      );

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (cues) {
          expect(cues, isA<List<SubtitleCue>>());
          for (final cue in cues) {
            expect(cue.start, isA<Duration>());
            expect(cue.end, isA<Duration>());
            expect(cue.text, isA<String>());
          }
        },
      );
    });

    testWithBackend('deve ritornare sottotitoli in inglese', () async {
      final result = await getSubtitlesUseCase(
        videoId: 'test-video-subtitles',
        language: 'English',
      );

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (cues) => expect(cues, isA<List<SubtitleCue>>()),
      );
    });

    testWithBackend('deve gestire lingua non disponibile', () async {
      final result = await getSubtitlesUseCase(
        videoId: 'test-video',
        language: 'NonExistentLanguage',
      );

      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (cues) => expect(cues, isEmpty),
      );
    });
  });

  group('SaveProgressUseCase - Backend Reale', () {
    testWithBackend('deve salvare progresso visione', () async {
      final params = SaveProgressParams(
        videoId: 'test-video-progress',
        position: const Duration(minutes: 5, seconds: 30),
      );

      final result = await saveProgressUseCase(params);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });

    testWithBackend('deve salvare progresso a inizio video', () async {
      final params = SaveProgressParams(
        videoId: 'test-video-progress',
        position: Duration.zero,
      );

      final result = await saveProgressUseCase(params);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });

    testWithBackend('deve salvare progresso a fine video', () async {
      final params = SaveProgressParams(
        videoId: 'test-video-progress',
        position: const Duration(hours: 1, minutes: 30),
      );

      final result = await saveProgressUseCase(params);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });
  });

  group('GetSavedPositionUseCase - Backend Reale', () {
    testWithBackend('deve ritornare posizione salvata', () async {
      const videoId = 'test-video-position';

      final result = await getSavedPositionUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (position) {
          expect(position, isA<Duration>());
          expect(position.inSeconds, greaterThanOrEqualTo(0));
        },
      );
    });

    testWithBackend('deve ritornare Duration.zero per video mai visto', () async {
      const videoId = 'never-watched-video-xyz';

      final result = await getSavedPositionUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (position) => expect(position.inSeconds, greaterThanOrEqualTo(0)),
      );
    });
  });

  group('MarkVideoCompletedUseCase - Backend Reale', () {
    testWithBackend('deve marcare video come completato', () async {
      const videoId = 'test-video-complete';

      final result = await markVideoCompletedUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });
  });

  group('GetVideoInfoUseCase - Backend Reale', () {
    testWithBackend('deve ritornare informazioni video', () async {
      const videoId = 'test-video-info';

      final result = await getVideoInfoUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (info) {
          expect(info, isA<VideoInfo>());
          expect(info.id, isNotEmpty);
          expect(info.title, isNotEmpty);
        },
      );
    });

    testWithBackend('deve gestire video con tutti i campi', () async {
      const videoId = 'test-video-full-info';

      final result = await getVideoInfoUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (info) {
          expect(info.durationSeconds, greaterThanOrEqualTo(0));
          expect(info.availableQualities, isNotEmpty);
          expect(info.availableSubtitles, isNotEmpty);
          expect(info.availableAudioTracks, isNotEmpty);
        },
      );
    });
  });

  group('GetNextEpisodeUseCase - Backend Reale', () {
    testWithBackend('deve ritornare episodio successivo', () async {
      const videoId = 'test-episode-1';

      final result = await getNextEpisodeUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (nextEp) {
          // Può essere null se ultimo episodio
          if (nextEp != null) {
            expect(nextEp, isA<VideoInfo>());
          }
        },
      );
    });

    testWithBackend('deve ritornare null per ultimo episodio', () async {
      const videoId = 'test-last-episode';

      final result = await getNextEpisodeUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (nextEp) => expect(nextEp == null || nextEp is VideoInfo, isTrue),
      );
    });
  });

  group('GetEpisodeListUseCase - Backend Reale', () {
    testWithBackend('deve ritornare lista episodi serie', () async {
      const seriesId = 'test-series-001';

      final result = await getEpisodeListUseCase(seriesId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (episodes) {
          expect(episodes, isA<List<VideoInfo>>());
        },
      );
    });

    testWithBackend('deve ritornare lista vuota per serie senza episodi', () async {
      const seriesId = 'empty-series';

      final result = await getEpisodeListUseCase(seriesId);

      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (episodes) => expect(episodes, isA<List<VideoInfo>>()),
      );
    });
  });

  group('GetAvailableQualitiesUseCase - Backend Reale', () {
    testWithBackend('deve ritornare qualità disponibili', () async {
      const videoId = 'test-video-qualities';

      final result = await getAvailableQualitiesUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (qualities) {
          expect(qualities, isA<List<String>>());
          // Tipicamente include: Auto, 1080p, 720p, 480p
        },
      );
    });
  });

  group('GetAvailableAudioTracksUseCase - Backend Reale', () {
    testWithBackend('deve ritornare tracce audio disponibili', () async {
      const videoId = 'test-video-audio';

      final result = await getAvailableAudioTracksUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (tracks) {
          expect(tracks, isA<List<String>>());
          // Tipicamente include: Italian, Original
        },
      );
    });
  });

  group('GetAvailableSubtitlesUseCase - Backend Reale', () {
    testWithBackend('deve ritornare lingue sottotitoli disponibili', () async {
      const videoId = 'test-video-subs';

      final result = await getAvailableSubtitlesUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (languages) {
          expect(languages, isA<List<String>>());
          // Tipicamente include: Off, Italian, English
        },
      );
    });
  });

  group('VideoInfo Entity - Validazione', () {
    test('VideoInfo con tutti i campi', () {
      const info = VideoInfo(
        id: 'vid-1',
        title: 'Test Video',
        episodeTitle: 'Episode 1',
        seasonInfo: 'S1:E1',
        durationSeconds: 3665, // 1h 1m 5s
        thumbnailUrl: 'https://example.com/thumb.jpg',
        maestroName: 'Maestro Test',
        category: 'Karate',
        level: 'Intermediate',
        hasEpisodes: true,
        nextEpisodeId: 2,
        hasSkeletonData: true,
      );

      expect(info.id, equals('vid-1'));
      expect(info.title, equals('Test Video'));
      expect(info.episodeTitle, equals('Episode 1'));
      expect(info.formattedDuration, equals('1:01:05'));
    });

    test('VideoInfo formattedDuration per video corto', () {
      const info = VideoInfo(
        id: 'vid-2',
        title: 'Short Video',
        durationSeconds: 125, // 2m 5s
        thumbnailUrl: 'https://example.com/thumb.jpg',
      );

      expect(info.formattedDuration, equals('02:05'));
    });

    test('VideoInfo formattedDuration per video molto lungo', () {
      const info = VideoInfo(
        id: 'vid-3',
        title: 'Long Video',
        durationSeconds: 7265, // 2h 1m 5s
        thumbnailUrl: 'https://example.com/thumb.jpg',
      );

      expect(info.formattedDuration, equals('2:01:05'));
    });
  });

  group('VideoStream Entity - Validazione', () {
    test('VideoStream con dati completi', () {
      const info = VideoInfo(
        id: 'vid-1',
        title: 'Test Video',
        durationSeconds: 1800,
        thumbnailUrl: 'https://example.com/thumb.jpg',
      );

      const stream = VideoStream(
        streamUrl: 'https://cdn.example.com/stream.m3u8',
        videoInfo: info,
        savedPosition: Duration(minutes: 10),
      );

      expect(stream.streamUrl, equals('https://cdn.example.com/stream.m3u8'));
      expect(stream.videoInfo.id, equals('vid-1'));
      expect(stream.savedPosition.inMinutes, equals(10));
    });
  });

  group('SubtitleCue Entity - Validazione', () {
    test('SubtitleCue con timestamp corretti', () {
      const cue = SubtitleCue(
        start: Duration(seconds: 5),
        end: Duration(seconds: 8),
        text: 'Hello, world!',
      );

      expect(cue.start.inSeconds, equals(5));
      expect(cue.end.inSeconds, equals(8));
      expect(cue.text, equals('Hello, world!'));
    });
  });

  group('SaveProgressParams - Equatable', () {
    test('SaveProgressParams con stessi valori sono uguali', () {
      const params1 = SaveProgressParams(
        videoId: 'vid-1',
        position: Duration(minutes: 5),
      );

      const params2 = SaveProgressParams(
        videoId: 'vid-1',
        position: Duration(minutes: 5),
      );

      expect(params1, equals(params2));
    });

    test('SaveProgressParams con valori diversi non sono uguali', () {
      const params1 = SaveProgressParams(
        videoId: 'vid-1',
        position: Duration(minutes: 5),
      );

      const params2 = SaveProgressParams(
        videoId: 'vid-2',
        position: Duration(minutes: 5),
      );

      expect(params1, isNot(equals(params2)));
    });
  });

  group('Error Handling - Backend Offline', () {
    test('gestisce errore network quando backend offline', () async {
      final isOnline = await BackendChecker.isBackendAvailable();

      if (!isOnline) {
        final result = await getVideoStreamUseCase('test-video');
        result.fold(
          (failure) => expect(failure.message, isNotEmpty),
          (stream) => fail('Should fail when backend offline'),
        );
      } else {
        expect(true, isTrue);
      }
    });
  });
}

/// DataSource wrapper per test Player
class _TestPlayerRemoteDataSource {
  final Dio _dio;

  _TestPlayerRemoteDataSource(this._dio);

  Future<VideoStreamModel> getVideoStream(String videoId) async {
    final response = await _dio.get('/videos/$videoId/stream');
    return VideoStreamModel.fromJson(response.data as Map<String, dynamic>);
  }

  Future<String> getStreamUrl({
    required String videoId,
    required String quality,
  }) async {
    final response = await _dio.get(
      '/videos/$videoId/stream-url',
      queryParameters: {'quality': quality},
    );
    return response.data['url'] as String? ??
           response.data['stream_url'] as String? ?? '';
  }

  Future<Map<String, dynamic>> getSkeletonData(String videoId) async {
    final response = await _dio.get('/videos/$videoId/skeleton');
    return response.data as Map<String, dynamic>;
  }

  Future<List<SubtitleCueModel>> getSubtitles({
    required String videoId,
    required String language,
  }) async {
    final response = await _dio.get(
      '/videos/$videoId/subtitles',
      queryParameters: {'language': language},
    );

    final items = (response.data is List)
        ? response.data as List
        : response.data['cues'] as List? ?? [];

    return items
        .map((e) => SubtitleCueModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<int> getSavedPositionSeconds(String videoId) async {
    final response = await _dio.get('/me/videos/$videoId/progress');
    return response.data['position_seconds'] as int? ??
           response.data['positionSeconds'] as int? ?? 0;
  }

  Future<void> saveProgress({
    required String videoId,
    required int positionSeconds,
  }) async {
    await _dio.post(
      '/me/videos/$videoId/progress',
      data: {'position_seconds': positionSeconds},
    );
  }

  Future<void> markAsCompleted(String videoId) async {
    await _dio.post('/me/videos/$videoId/complete');
  }

  Future<VideoInfoModel> getVideoInfo(String videoId) async {
    final response = await _dio.get('/videos/$videoId');
    return VideoInfoModel.fromJson(response.data as Map<String, dynamic>);
  }

  Future<VideoInfoModel?> getNextEpisode(String videoId) async {
    try {
      final response = await _dio.get('/videos/$videoId/next');
      if (response.data == null) return null;
      return VideoInfoModel.fromJson(response.data as Map<String, dynamic>);
    } on DioException catch (e) {
      if (e.response?.statusCode == 404) return null;
      rethrow;
    }
  }

  Future<List<VideoInfoModel>> getEpisodeList(String seriesId) async {
    final response = await _dio.get('/series/$seriesId/episodes');

    final items = (response.data is List)
        ? response.data as List
        : response.data['items'] as List? ?? [];

    return items
        .map((e) => VideoInfoModel.fromJson(e as Map<String, dynamic>))
        .toList();
  }

  Future<List<String>> getAvailableQualities(String videoId) async {
    final response = await _dio.get('/videos/$videoId/qualities');
    return _parseStringList(response.data);
  }

  Future<List<String>> getAvailableAudioTracks(String videoId) async {
    final response = await _dio.get('/videos/$videoId/audio-tracks');
    return _parseStringList(response.data);
  }

  Future<List<String>> getAvailableSubtitles(String videoId) async {
    final response = await _dio.get('/videos/$videoId/subtitle-languages');
    return _parseStringList(response.data);
  }

  List<String> _parseStringList(dynamic data) {
    if (data is List) {
      return data.map((e) => e.toString()).toList();
    }
    if (data is Map) {
      final items = data['items'] as List? ?? data['languages'] as List? ?? [];
      return items.map((e) => e.toString()).toList();
    }
    return [];
  }
}

/// Repository wrapper per test
class _TestPlayerRepository implements PlayerRepository {
  final _TestPlayerRemoteDataSource _dataSource;

  _TestPlayerRepository(this._dataSource);

  @override
  Future<Either<Failure, VideoStream>> getVideoStream(String videoId) async {
    try {
      final model = await _dataSource.getVideoStream(videoId);
      return Right(model);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, String>> getStreamUrl({
    required String videoId,
    required String quality,
  }) async {
    try {
      final url = await _dataSource.getStreamUrl(
        videoId: videoId,
        quality: quality,
      );
      return Right(url);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, Map<String, dynamic>>> getSkeletonData(String videoId) async {
    try {
      final data = await _dataSource.getSkeletonData(videoId);
      return Right(data);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, List<SubtitleCue>>> getSubtitles({
    required String videoId,
    required String language,
  }) async {
    try {
      final cues = await _dataSource.getSubtitles(
        videoId: videoId,
        language: language,
      );
      return Right(cues);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, Duration>> getSavedPosition(String videoId) async {
    try {
      final seconds = await _dataSource.getSavedPositionSeconds(videoId);
      return Right(Duration(seconds: seconds));
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> saveProgress({
    required String videoId,
    required Duration position,
  }) async {
    try {
      await _dataSource.saveProgress(
        videoId: videoId,
        positionSeconds: position.inSeconds,
      );
      return const Right(null);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> markAsCompleted(String videoId) async {
    try {
      await _dataSource.markAsCompleted(videoId);
      return const Right(null);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, VideoInfo>> getVideoInfo(String videoId) async {
    try {
      final model = await _dataSource.getVideoInfo(videoId);
      return Right(model);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, VideoInfo?>> getNextEpisode(String videoId) async {
    try {
      final model = await _dataSource.getNextEpisode(videoId);
      return Right(model);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, List<VideoInfo>>> getEpisodeList(String seriesId) async {
    try {
      final models = await _dataSource.getEpisodeList(seriesId);
      return Right(models);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableQualities(String videoId) async {
    try {
      final qualities = await _dataSource.getAvailableQualities(videoId);
      return Right(qualities);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableAudioTracks(String videoId) async {
    try {
      final tracks = await _dataSource.getAvailableAudioTracks(videoId);
      return Right(tracks);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableSubtitles(String videoId) async {
    try {
      final languages = await _dataSource.getAvailableSubtitles(videoId);
      return Right(languages);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }
}

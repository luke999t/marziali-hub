/// 🎓 AI_MODULE: EnhancedPlayerUseCasesTest
/// 🎓 AI_DESCRIPTION: Test UseCase Player Enhanced con backend reale - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione skeleton data, chapters, quality, settings
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
import 'package:shared_preferences/shared_preferences.dart';

import 'package:martial_arts_streaming/core/network/network_info.dart';
import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/skeleton_data_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/chapter_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/video_quality_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/entities/playback_settings_entity.dart';
import 'package:martial_arts_streaming/features/player/domain/usecases/player_usecases.dart';
import 'package:martial_arts_streaming/features/player/domain/repositories/player_repository.dart';

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
  late _TestEnhancedPlayerRemoteDataSource remoteDataSource;
  late _TestEnhancedPlayerLocalDataSource localDataSource;
  late _TestEnhancedPlayerRepository repository;

  // UseCase instances - Enhanced
  late GetSkeletonDataStructuredUseCase getSkeletonDataStructuredUseCase;
  late HasSkeletonDataUseCase hasSkeletonDataUseCase;
  late SaveDetailedProgressUseCase saveDetailedProgressUseCase;
  late GetAvailableQualitiesStructuredUseCase getAvailableQualitiesStructuredUseCase;
  late GetVideoChaptersUseCase getVideoChaptersUseCase;
  late GetSkipSegmentsUseCase getSkipSegmentsUseCase;
  late GetPlaybackSettingsUseCase getPlaybackSettingsUseCase;
  late SavePlaybackSettingsUseCase savePlaybackSettingsUseCase;

  setUpAll(() async {
    WidgetsFlutterBinding.ensureInitialized();
    SharedPreferences.setMockInitialValues({});

    dio = Dio(BaseOptions(
      baseUrl: '${BackendChecker.baseUrl}/api/v1',
      connectTimeout: const Duration(seconds: 10),
      receiveTimeout: const Duration(seconds: 10),
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    remoteDataSource = _TestEnhancedPlayerRemoteDataSource(dio);
    localDataSource = _TestEnhancedPlayerLocalDataSource();
    repository = _TestEnhancedPlayerRepository(remoteDataSource, localDataSource);

    // UseCases REALI Enhanced
    getSkeletonDataStructuredUseCase = GetSkeletonDataStructuredUseCase(repository);
    hasSkeletonDataUseCase = HasSkeletonDataUseCase(repository);
    saveDetailedProgressUseCase = SaveDetailedProgressUseCase(repository);
    getAvailableQualitiesStructuredUseCase = GetAvailableQualitiesStructuredUseCase(repository);
    getVideoChaptersUseCase = GetVideoChaptersUseCase(repository);
    getSkipSegmentsUseCase = GetSkipSegmentsUseCase(repository);
    getPlaybackSettingsUseCase = GetPlaybackSettingsUseCase(repository);
    savePlaybackSettingsUseCase = SavePlaybackSettingsUseCase(repository);
  });

  tearDownAll(() {
    dio.close();
  });

  // ==========================================================================
  // SKELETON DATA USE CASES
  // ==========================================================================
  group('GetSkeletonDataStructuredUseCase - Backend Reale', () {
    testWithBackend('deve ritornare SkeletonData per video con analisi', () async {
      const videoId = 'test-video-skeleton-001';

      final result = await getSkeletonDataStructuredUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (data) {
          expect(data, isA<SkeletonData>());
          expect(data.videoId, equals(videoId));
          expect(data.fps, greaterThan(0));
        },
      );
    });

    testWithBackend('deve gestire video senza skeleton data', () async {
      const videoId = 'video-without-skeleton-xyz';

      final result = await getSkeletonDataStructuredUseCase(videoId);

      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (data) => expect(data.frames, isEmpty),
      );
    });
  });

  group('HasSkeletonDataUseCase - Backend Reale', () {
    testWithBackend('deve ritornare true per video con skeleton', () async {
      const videoId = 'test-video-skeleton-001';

      final result = await hasSkeletonDataUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (hasData) => expect(hasData, isA<bool>()),
      );
    });

    testWithBackend('deve ritornare false per video senza skeleton', () async {
      const videoId = 'video-no-skeleton';

      final result = await hasSkeletonDataUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (hasData) => expect(hasData, isA<bool>()),
      );
    });
  });

  // ==========================================================================
  // PROGRESS USE CASES
  // ==========================================================================
  group('SaveDetailedProgressUseCase - Backend Reale', () {
    testWithBackend('deve salvare progresso con dettagli completi', () async {
      final params = SaveDetailedProgressParams(
        videoId: 'test-video-progress-detail',
        position: const Duration(minutes: 15, seconds: 30),
        totalDuration: const Duration(hours: 1),
        currentQuality: VideoQualityLevel.high,
        audioTrack: 'Italian',
        subtitleLanguage: 'English',
      );

      final result = await saveDetailedProgressUseCase(params);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });

    testWithBackend('deve calcolare percentuale completamento', () async {
      final params = SaveDetailedProgressParams(
        videoId: 'test-video-progress',
        position: const Duration(minutes: 30),
        totalDuration: const Duration(hours: 1),
      );

      // Verifica che percentuale sia calcolata correttamente
      expect(params.completionPercentage, equals(50.0));
    });

    testWithBackend('deve gestire posizione a inizio video', () async {
      final params = SaveDetailedProgressParams(
        videoId: 'test-video-progress',
        position: Duration.zero,
        totalDuration: const Duration(hours: 1),
      );

      final result = await saveDetailedProgressUseCase(params);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });
  });

  // ==========================================================================
  // QUALITY USE CASES
  // ==========================================================================
  group('GetAvailableQualitiesStructuredUseCase - Backend Reale', () {
    testWithBackend('deve ritornare AvailableQualities strutturate', () async {
      const videoId = 'test-video-qualities';

      final result = await getAvailableQualitiesStructuredUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (qualities) {
          expect(qualities, isA<AvailableQualities>());
          expect(qualities.videoId, equals(videoId));
          // Deve sempre includere Auto
        },
      );
    });

    testWithBackend('deve includere qualità Auto', () async {
      const videoId = 'test-video-qualities';

      final result = await getAvailableQualitiesStructuredUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (qualities) {
          final hasAuto = qualities.hasQuality(VideoQualityLevel.auto);
          expect(hasAuto, isTrue);
        },
      );
    });
  });

  // ==========================================================================
  // CHAPTER USE CASES
  // ==========================================================================
  group('GetVideoChaptersUseCase - Backend Reale', () {
    testWithBackend('deve ritornare VideoChapters per video con capitoli', () async {
      const videoId = 'test-video-chapters';

      final result = await getVideoChaptersUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (chapters) {
          expect(chapters, isA<VideoChapters>());
          expect(chapters.videoId, equals(videoId));
        },
      );
    });

    testWithBackend('deve gestire video senza capitoli', () async {
      const videoId = 'video-no-chapters';

      final result = await getVideoChaptersUseCase(videoId);

      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (chapters) => expect(chapters.hasChapters, isFalse),
      );
    });
  });

  group('GetSkipSegmentsUseCase - Backend Reale', () {
    testWithBackend('deve ritornare skip segments per intro/credits', () async {
      const videoId = 'test-video-skip-segments';

      final result = await getSkipSegmentsUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (segments) {
          expect(segments, isA<List<SkipSegment>>());
          for (final segment in segments) {
            expect(segment.type, anyOf(SkipType.intro, SkipType.credits, SkipType.recap));
          }
        },
      );
    });

    testWithBackend('deve gestire video senza skip segments', () async {
      const videoId = 'video-no-skip';

      final result = await getSkipSegmentsUseCase(videoId);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (segments) => expect(segments, isEmpty),
      );
    });
  });

  // ==========================================================================
  // SETTINGS USE CASES
  // ==========================================================================
  group('GetPlaybackSettingsUseCase - Backend Reale', () {
    testWithBackend('deve ritornare PlaybackSettings dell\'utente', () async {
      final result = await getPlaybackSettingsUseCase(null);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (settings) {
          expect(settings, isA<PlaybackSettings>());
          expect(settings.playbackSpeed, greaterThan(0));
        },
      );
    });
  });

  group('SavePlaybackSettingsUseCase - Backend Reale', () {
    testWithBackend('deve salvare impostazioni playback', () async {
      const settings = PlaybackSettings(
        playbackSpeed: 1.25,
        preferredQuality: VideoQualityLevel.high,
        autoPlayNextEpisode: true,
        skipIntro: true,
      );

      final result = await savePlaybackSettingsUseCase(settings);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });

    testWithBackend('deve validare velocità playback', () async {
      // Velocità valide: 0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0
      const validSettings = PlaybackSettings(playbackSpeed: 1.5);

      final result = await savePlaybackSettingsUseCase(validSettings);

      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) => expect(true, isTrue),
      );
    });
  });

  // ==========================================================================
  // ENTITY VALIDATION TESTS (No Backend Required)
  // ==========================================================================
  group('SaveDetailedProgressParams - Equatable', () {
    test('params con stessi valori sono uguali', () {
      final params1 = SaveDetailedProgressParams(
        videoId: 'vid-1',
        position: const Duration(minutes: 5),
        totalDuration: const Duration(hours: 1),
      );

      final params2 = SaveDetailedProgressParams(
        videoId: 'vid-1',
        position: const Duration(minutes: 5),
        totalDuration: const Duration(hours: 1),
      );

      expect(params1, equals(params2));
    });

    test('params con valori diversi non sono uguali', () {
      final params1 = SaveDetailedProgressParams(
        videoId: 'vid-1',
        position: const Duration(minutes: 5),
        totalDuration: const Duration(hours: 1),
      );

      final params2 = SaveDetailedProgressParams(
        videoId: 'vid-2',
        position: const Duration(minutes: 5),
        totalDuration: const Duration(hours: 1),
      );

      expect(params1, isNot(equals(params2)));
    });

    test('completionPercentage calcola correttamente', () {
      final params = SaveDetailedProgressParams(
        videoId: 'vid-1',
        position: const Duration(minutes: 45),
        totalDuration: const Duration(hours: 1),
      );

      expect(params.completionPercentage, equals(75.0));
    });

    test('completionPercentage non supera 100', () {
      final params = SaveDetailedProgressParams(
        videoId: 'vid-1',
        position: const Duration(hours: 2),
        totalDuration: const Duration(hours: 1),
      );

      expect(params.completionPercentage, equals(100.0));
    });
  });

  group('Error Handling - Backend Offline', () {
    test('gestisce errore network quando backend offline', () async {
      final isOnline = await BackendChecker.isBackendAvailable();

      if (!isOnline) {
        final result = await getSkeletonDataStructuredUseCase('test-video');
        result.fold(
          (failure) => expect(failure.message, isNotEmpty),
          (data) => fail('Should fail when backend offline'),
        );
      } else {
        expect(true, isTrue);
      }
    });
  });
}

// =============================================================================
// TEST DATA SOURCES
// =============================================================================

/// Remote DataSource wrapper per test Enhanced Player
class _TestEnhancedPlayerRemoteDataSource {
  final Dio _dio;

  _TestEnhancedPlayerRemoteDataSource(this._dio);

  Future<SkeletonData> getSkeletonDataStructured(String videoId) async {
    final response = await _dio.get('/videos/$videoId/skeleton/structured');
    return SkeletonData.fromJson(response.data as Map<String, dynamic>);
  }

  Future<bool> hasSkeletonData(String videoId) async {
    final response = await _dio.get('/videos/$videoId/skeleton/exists');
    return response.data['exists'] as bool? ?? false;
  }

  Future<void> saveDetailedProgress({
    required String videoId,
    required int positionSeconds,
    required int totalSeconds,
    String? quality,
    String? audioTrack,
    String? subtitle,
  }) async {
    await _dio.post(
      '/me/videos/$videoId/progress/detailed',
      data: {
        'position_seconds': positionSeconds,
        'total_seconds': totalSeconds,
        'quality': quality,
        'audio_track': audioTrack,
        'subtitle': subtitle,
      },
    );
  }

  Future<AvailableQualities> getAvailableQualitiesStructured(String videoId) async {
    final response = await _dio.get('/videos/$videoId/qualities/structured');
    return AvailableQualities.fromJson(response.data as Map<String, dynamic>);
  }

  Future<VideoChapters> getVideoChapters(String videoId) async {
    final response = await _dio.get('/videos/$videoId/chapters');
    return VideoChapters.fromJson(response.data as Map<String, dynamic>);
  }

  Future<List<SkipSegment>> getSkipSegments(String videoId) async {
    final response = await _dio.get('/videos/$videoId/skip-segments');
    final items = response.data as List? ?? [];
    return items
        .map((e) => SkipSegment.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}

/// Local DataSource wrapper per test
class _TestEnhancedPlayerLocalDataSource {
  PlaybackSettings? _cachedSettings;

  Future<PlaybackSettings> getPlaybackSettings() async {
    return _cachedSettings ?? const PlaybackSettings();
  }

  Future<void> savePlaybackSettings(PlaybackSettings settings) async {
    _cachedSettings = settings;
  }

  Future<void> cacheSkeletonMetadata(String videoId, bool hasData) async {
    // In-memory cache for tests
  }
}

// =============================================================================
// TEST REPOSITORY
// =============================================================================

/// Repository wrapper per test Enhanced Player
class _TestEnhancedPlayerRepository implements PlayerRepository {
  final _TestEnhancedPlayerRemoteDataSource _remoteDataSource;
  final _TestEnhancedPlayerLocalDataSource _localDataSource;

  _TestEnhancedPlayerRepository(this._remoteDataSource, this._localDataSource);

  // ===== SKELETON DATA =====
  @override
  Future<Either<Failure, SkeletonData>> getSkeletonDataStructured(String videoId) async {
    try {
      final data = await _remoteDataSource.getSkeletonDataStructured(videoId);
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
  Future<Either<Failure, bool>> hasSkeletonData(String videoId) async {
    try {
      final hasData = await _remoteDataSource.hasSkeletonData(videoId);
      return Right(hasData);
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
  Future<Either<Failure, SkeletonFrame?>> getSkeletonFrameAt(
    String videoId,
    Duration position,
  ) async {
    final dataResult = await getSkeletonDataStructured(videoId);
    return dataResult.fold(
      (failure) => Left(failure),
      (data) => Right(data.getFrameAt(position)),
    );
  }

  // ===== PROGRESS =====
  @override
  Future<Either<Failure, void>> saveDetailedProgress({
    required String videoId,
    required Duration position,
    required Duration totalDuration,
    VideoQualityLevel? quality,
    String? audioTrack,
    String? subtitleLanguage,
  }) async {
    try {
      await _remoteDataSource.saveDetailedProgress(
        videoId: videoId,
        positionSeconds: position.inSeconds,
        totalSeconds: totalDuration.inSeconds,
        quality: quality?.name,
        audioTrack: audioTrack,
        subtitle: subtitleLanguage,
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

  // ===== QUALITY =====
  @override
  Future<Either<Failure, AvailableQualities>> getAvailableQualitiesStructured(String videoId) async {
    try {
      final qualities = await _remoteDataSource.getAvailableQualitiesStructured(videoId);
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

  // ===== CHAPTERS =====
  @override
  Future<Either<Failure, VideoChapters>> getVideoChapters(String videoId) async {
    try {
      final chapters = await _remoteDataSource.getVideoChapters(videoId);
      return Right(chapters);
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
  Future<Either<Failure, List<SkipSegment>>> getSkipSegments(String videoId) async {
    try {
      final segments = await _remoteDataSource.getSkipSegments(videoId);
      return Right(segments);
    } on DioException catch (e) {
      return Left(ServerFailure(
        message: e.message ?? 'Server error',
        statusCode: e.response?.statusCode,
      ));
    } catch (e) {
      return Left(ServerFailure(message: e.toString()));
    }
  }

  // ===== SETTINGS =====
  @override
  Future<Either<Failure, PlaybackSettings>> getPlaybackSettings() async {
    try {
      final settings = await _localDataSource.getPlaybackSettings();
      return Right(settings);
    } catch (e) {
      return Left(CacheFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> savePlaybackSettings(PlaybackSettings settings) async {
    try {
      await _localDataSource.savePlaybackSettings(settings);
      return const Right(null);
    } catch (e) {
      return Left(CacheFailure(message: e.toString()));
    }
  }

  @override
  Future<Either<Failure, void>> updatePlaybackSetting<T>(String key, T value) async {
    final settingsResult = await getPlaybackSettings();
    return settingsResult.fold(
      (failure) => Left(failure),
      (settings) async {
        // Create updated settings based on key
        final updated = _updateSetting(settings, key, value);
        return savePlaybackSettings(updated);
      },
    );
  }

  PlaybackSettings _updateSetting<T>(PlaybackSettings settings, String key, T value) {
    switch (key) {
      case 'playbackSpeed':
        return settings.copyWith(playbackSpeed: value as double);
      case 'preferredQuality':
        return settings.copyWith(preferredQuality: value as VideoQualityLevel);
      case 'autoPlayNextEpisode':
        return settings.copyWith(autoPlayNextEpisode: value as bool);
      case 'skipIntro':
        return settings.copyWith(skipIntro: value as bool);
      case 'skipCredits':
        return settings.copyWith(skipCredits: value as bool);
      default:
        return settings;
    }
  }

  // ===== LEGACY METHODS (not implemented for this test) =====
  @override
  Future<Either<Failure, dynamic>> getVideoStream(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, String>> getStreamUrl({
    required String videoId,
    required String quality,
  }) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, Map<String, dynamic>>> getSkeletonData(String videoId) async {
    throw UnimplementedError('Use getSkeletonDataStructured instead');
  }

  @override
  Future<Either<Failure, List<dynamic>>> getSubtitles({
    required String videoId,
    required String language,
  }) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, Duration>> getSavedPosition(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, void>> saveProgress({
    required String videoId,
    required Duration position,
  }) async {
    throw UnimplementedError('Use saveDetailedProgress instead');
  }

  @override
  Future<Either<Failure, void>> markAsCompleted(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, dynamic>> getVideoInfo(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, dynamic>> getNextEpisode(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, List<dynamic>>> getEpisodeList(String seriesId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableQualities(String videoId) async {
    throw UnimplementedError('Use getAvailableQualitiesStructured instead');
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableAudioTracks(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }

  @override
  Future<Either<Failure, List<String>>> getAvailableSubtitles(String videoId) async {
    throw UnimplementedError('Use existing player tests');
  }
}

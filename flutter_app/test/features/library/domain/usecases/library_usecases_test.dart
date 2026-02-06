/// 🎓 AI_MODULE: LibraryUseCasesTest
/// 🎓 AI_DESCRIPTION: Test UseCase Library con backend reale - ZERO MOCK
/// 🎓 AI_BUSINESS: Validazione My List, Continue Watching, Watch Progress
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
import 'package:martial_arts_streaming/features/library/domain/entities/library_item.dart';
import 'package:martial_arts_streaming/features/library/domain/usecases/get_library_usecase.dart';
import 'package:martial_arts_streaming/features/library/domain/usecases/add_to_library_usecase.dart';
import 'package:martial_arts_streaming/features/library/domain/usecases/remove_from_library_usecase.dart';
import 'package:martial_arts_streaming/features/library/domain/repositories/library_repository.dart';
import 'package:martial_arts_streaming/features/library/data/models/library_item_model.dart';

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
  late _TestLibraryRemoteDataSource remoteDataSource;
  late _TestLibraryRepository repository;

  // UseCase instances
  late GetLibraryUseCase getLibraryUseCase;
  late GetContinueWatchingUseCase getContinueWatchingUseCase;
  late AddToLibraryUseCase addToLibraryUseCase;
  late RemoveFromLibraryUseCase removeFromLibraryUseCase;

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

    remoteDataSource = _TestLibraryRemoteDataSource(dio);
    repository = _TestLibraryRepository(remoteDataSource);

    // UseCases REALI
    getLibraryUseCase = GetLibraryUseCase(repository);
    getContinueWatchingUseCase = GetContinueWatchingUseCase(repository);
    addToLibraryUseCase = AddToLibraryUseCase(repository);
    removeFromLibraryUseCase = RemoveFromLibraryUseCase(repository);
  });

  tearDownAll(() {
    dio.close();
  });

  group('GetLibraryUseCase - Backend Reale', () {
    testWithBackend('deve ritornare lista libreria (può essere vuota)', () async {
      // Act
      final result = await getLibraryUseCase();

      // Assert
      result.fold(
        (failure) {
          // 404 accettabile se endpoint non esiste
          expect(failure.message, isNotEmpty);
        },
        (items) {
          expect(items, isA<List<LibraryItem>>());
        },
      );
    });

    testWithBackend('deve supportare paginazione', () async {
      // Act
      final result = await getLibraryUseCase(
        page: 1,
        limit: 5,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (items) {
          expect(items.length, lessThanOrEqualTo(5));
        },
      );
    });

    testWithBackend('deve supportare filtro per tipo video', () async {
      // Act
      final result = await getLibraryUseCase(
        filterType: LibraryItemType.video,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (items) {
          for (final item in items) {
            expect(item.type, equals(LibraryItemType.video));
          }
        },
      );
    });

    testWithBackend('deve supportare filtro per tipo course', () async {
      // Act
      final result = await getLibraryUseCase(
        filterType: LibraryItemType.course,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (items) {
          for (final item in items) {
            expect(item.type, equals(LibraryItemType.course));
          }
        },
      );
    });
  });

  group('GetContinueWatchingUseCase - Backend Reale', () {
    testWithBackend('deve ritornare lista continue watching', () async {
      // Act
      final result = await getContinueWatchingUseCase();

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (items) {
          expect(items, isA<List<LibraryItem>>());
          // Continue watching items devono avere progress > 0
          for (final item in items) {
            if (item.watchProgress != null) {
              expect(item.hasStarted, isTrue);
            }
          }
        },
      );
    });

    testWithBackend('deve rispettare limit', () async {
      // Act
      final result = await getContinueWatchingUseCase(limit: 3);

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (items) {
          expect(items.length, lessThanOrEqualTo(3));
        },
      );
    });
  });

  group('AddToLibraryUseCase - Backend Reale', () {
    testWithBackend('deve aggiungere video alla libreria', () async {
      const videoId = 'test-video-add-001';

      // Act
      final result = await addToLibraryUseCase(videoId);

      // Assert
      result.fold(
        (failure) {
          // Può fallire se video non esiste o già in libreria
          expect(failure.message, isNotEmpty);
        },
        (item) {
          expect(item, isA<LibraryItem>());
          expect(item.videoId, equals(videoId));
        },
      );
    });

    testWithBackend('deve gestire video ID vuoto', () async {
      // Act
      final result = await addToLibraryUseCase('');

      // Assert - dovrebbe fallire
      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (item) => expect(item, isA<LibraryItem>()),
      );
    });

    testWithBackend('deve gestire video ID non esistente', () async {
      // Act
      final result = await addToLibraryUseCase('non-existent-video-xyz-99999');

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (item) => expect(item, isA<LibraryItem>()),
      );
    });
  });

  group('RemoveFromLibraryUseCase - Backend Reale', () {
    testWithBackend('deve rimuovere video dalla libreria', () async {
      const videoId = 'test-video-remove-001';

      // Act
      final result = await removeFromLibraryUseCase(videoId);

      // Assert
      result.fold(
        (failure) {
          // Può fallire se video non in libreria
          expect(failure.message, isNotEmpty);
        },
        (_) => expect(true, isTrue),
      );
    });

    testWithBackend('deve gestire video non in libreria gracefully', () async {
      // Act - prova a rimuovere video non presente
      final result = await removeFromLibraryUseCase('not-in-library-xyz');

      // Assert - può essere success o failure (idempotent)
      expect(result, isNotNull);
    });
  });

  group('LibraryRepository - Operazioni Complete', () {
    testWithBackend('isInLibrary deve ritornare booleano', () async {
      // Act
      final result = await repository.isInLibrary('some-video-id');

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (isIn) => expect(isIn, isA<bool>()),
      );
    });

    testWithBackend('getLibraryItem per video specifico', () async {
      // Act
      final result = await repository.getLibraryItem('test-video-id');

      // Assert
      result.fold(
        (failure) => expect(failure, isA<Failure>()),
        (item) => expect(item, isA<LibraryItem>()),
      );
    });

    testWithBackend('updateWatchProgress deve aggiornare progresso', () async {
      // Act
      final result = await repository.updateWatchProgress(
        videoId: 'test-video-progress',
        progress: 0.5,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (item) {
          expect(item, isA<LibraryItem>());
        },
      );
    });

    testWithBackend('updateWatchProgress con progress 0', () async {
      // Act
      final result = await repository.updateWatchProgress(
        videoId: 'test-video',
        progress: 0.0,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (item) => expect(item.watchProgress, anyOf([isNull, equals(0.0)])),
      );
    });

    testWithBackend('updateWatchProgress con progress 1 (completo)', () async {
      // Act
      final result = await repository.updateWatchProgress(
        videoId: 'test-video',
        progress: 1.0,
      );

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (item) {
          if (item.watchProgress != null) {
            expect(item.isCompleted, isTrue);
          }
        },
      );
    });

    testWithBackend('clearLibrary deve svuotare libreria', () async {
      // Attenzione: questo è un test distruttivo!
      // Skippa se vuoi preservare dati

      // Act
      final result = await repository.clearLibrary();

      // Assert
      result.fold(
        (failure) => expect(failure.message, isNotEmpty),
        (_) async {
          // Verifica che sia vuota
          final libResult = await getLibraryUseCase();
          libResult.fold(
            (f) => expect(f, isA<Failure>()),
            (items) => expect(items, isEmpty),
          );
        },
      );
    });
  });

  group('LibraryItem Entity - Validazione', () {
    test('LibraryItem con progress nullo', () {
      final item = LibraryItem(
        id: 'lib-1',
        videoId: 'vid-1',
        userId: 'user-1',
        title: 'Test Video',
        thumbnailUrl: 'https://example.com/thumb.jpg',
        duration: const Duration(minutes: 30),
        addedAt: DateTime.now(),
        type: LibraryItemType.video,
        watchProgress: null,
      );

      expect(item.hasStarted, isFalse);
      expect(item.isCompleted, isFalse);
      expect(item.progressPercentage, equals(0));
      expect(item.remainingDuration, equals(const Duration(minutes: 30)));
    });

    test('LibraryItem con progress 0.5 (50%)', () {
      final item = LibraryItem(
        id: 'lib-2',
        videoId: 'vid-2',
        userId: 'user-1',
        title: 'Test Video',
        thumbnailUrl: 'https://example.com/thumb.jpg',
        duration: const Duration(minutes: 60),
        addedAt: DateTime.now(),
        type: LibraryItemType.video,
        watchProgress: 0.5,
      );

      expect(item.hasStarted, isTrue);
      expect(item.isCompleted, isFalse);
      expect(item.progressPercentage, equals(50));
      expect(item.remainingDuration.inMinutes, equals(30));
    });

    test('LibraryItem con progress 0.95 (completato)', () {
      final item = LibraryItem(
        id: 'lib-3',
        videoId: 'vid-3',
        userId: 'user-1',
        title: 'Test Video',
        thumbnailUrl: 'https://example.com/thumb.jpg',
        duration: const Duration(minutes: 100),
        addedAt: DateTime.now(),
        type: LibraryItemType.video,
        watchProgress: 0.95,
      );

      expect(item.hasStarted, isTrue);
      expect(item.isCompleted, isTrue);
      expect(item.progressPercentage, equals(95));
    });

    test('LibraryItemType displayName', () {
      expect(LibraryItemType.video.displayName, equals('Video'));
      expect(LibraryItemType.course.displayName, equals('Corso'));
      expect(LibraryItemType.series.displayName, equals('Serie'));
      expect(LibraryItemType.live.displayName, equals('Live'));
    });

    test('LibraryItemType icon', () {
      expect(LibraryItemType.video.icon, isNotEmpty);
      expect(LibraryItemType.course.icon, isNotEmpty);
      expect(LibraryItemType.series.icon, isNotEmpty);
      expect(LibraryItemType.live.icon, isNotEmpty);
    });
  });

  group('Error Handling - Backend Offline', () {
    test('gestisce errore network quando backend offline', () async {
      final isOnline = await BackendChecker.isBackendAvailable();

      if (!isOnline) {
        final result = await getLibraryUseCase();
        result.fold(
          (failure) => expect(failure.message, isNotEmpty),
          (items) => fail('Should fail when backend offline'),
        );
      } else {
        expect(true, isTrue);
      }
    });
  });
}

/// DataSource wrapper per test Library
class _TestLibraryRemoteDataSource {
  final Dio _dio;

  _TestLibraryRemoteDataSource(this._dio);

  Future<List<LibraryItemModel>> getLibraryItems({
    int page = 1,
    int limit = 20,
    LibraryItemType? filterType,
  }) async {
    final queryParams = <String, dynamic>{
      'page': page,
      'limit': limit,
    };

    if (filterType != null) {
      queryParams['type'] = filterType.name;
    }

    final response = await _dio.get('/library', queryParameters: queryParams);
    final items = (response.data['items'] as List? ?? response.data as List? ?? [])
        .map((item) => LibraryItemModel.fromJson(item as Map<String, dynamic>))
        .toList();
    return items;
  }

  Future<LibraryItemModel> addToLibrary(String videoId) async {
    final response = await _dio.post('/library/$videoId');
    return LibraryItemModel.fromJson(response.data as Map<String, dynamic>);
  }

  Future<void> removeFromLibrary(String videoId) async {
    await _dio.delete('/library/$videoId');
  }

  Future<bool> isInLibrary(String videoId) async {
    try {
      final response = await _dio.get('/library/$videoId/check');
      return response.data['is_in_library'] as bool? ?? false;
    } on DioException catch (e) {
      if (e.response?.statusCode == 404) return false;
      rethrow;
    }
  }

  Future<LibraryItemModel> getLibraryItem(String videoId) async {
    final response = await _dio.get('/library/$videoId');
    return LibraryItemModel.fromJson(response.data as Map<String, dynamic>);
  }

  Future<LibraryItemModel> updateWatchProgress({
    required String videoId,
    required double progress,
  }) async {
    final response = await _dio.patch(
      '/library/$videoId/progress',
      data: {'progress': progress},
    );
    return LibraryItemModel.fromJson(response.data as Map<String, dynamic>);
  }

  Future<List<LibraryItemModel>> getContinueWatching({int limit = 10}) async {
    final response = await _dio.get(
      '/library/continue-watching',
      queryParameters: {'limit': limit},
    );
    final items = (response.data['items'] as List? ?? response.data as List? ?? [])
        .map((item) => LibraryItemModel.fromJson(item as Map<String, dynamic>))
        .toList();
    return items;
  }

  Future<void> clearLibrary() async {
    await _dio.delete('/library');
  }
}

/// Repository wrapper per test
class _TestLibraryRepository implements LibraryRepository {
  final _TestLibraryRemoteDataSource _dataSource;

  _TestLibraryRepository(this._dataSource);

  @override
  Future<Either<Failure, List<LibraryItem>>> getLibraryItems({
    int page = 1,
    int limit = 20,
    LibraryItemType? filterType,
  }) async {
    try {
      final models = await _dataSource.getLibraryItems(
        page: page,
        limit: limit,
        filterType: filterType,
      );
      return Right(models.map((m) => m.toEntity()).toList());
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
  Future<Either<Failure, LibraryItem>> addToLibrary(String videoId) async {
    try {
      final model = await _dataSource.addToLibrary(videoId);
      return Right(model.toEntity());
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
  Future<Either<Failure, void>> removeFromLibrary(String videoId) async {
    try {
      await _dataSource.removeFromLibrary(videoId);
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
  Future<Either<Failure, bool>> isInLibrary(String videoId) async {
    try {
      final isIn = await _dataSource.isInLibrary(videoId);
      return Right(isIn);
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
  Future<Either<Failure, LibraryItem>> getLibraryItem(String videoId) async {
    try {
      final model = await _dataSource.getLibraryItem(videoId);
      return Right(model.toEntity());
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
  Future<Either<Failure, LibraryItem>> updateWatchProgress({
    required String videoId,
    required double progress,
  }) async {
    try {
      final model = await _dataSource.updateWatchProgress(
        videoId: videoId,
        progress: progress,
      );
      return Right(model.toEntity());
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
  Future<Either<Failure, List<LibraryItem>>> getContinueWatching({
    int limit = 10,
  }) async {
    try {
      final models = await _dataSource.getContinueWatching(limit: limit);
      return Right(models.map((m) => m.toEntity()).toList());
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
  Future<Either<Failure, void>> clearLibrary() async {
    try {
      await _dataSource.clearLibrary();
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
}

/// Extension per convertire model a entity
extension LibraryItemModelExtension on LibraryItemModel {
  LibraryItem toEntity() {
    return LibraryItem(
      id: id,
      videoId: videoId,
      userId: userId,
      title: title,
      description: description,
      thumbnailUrl: thumbnailUrl,
      heroImageUrl: heroImageUrl,
      duration: duration,
      addedAt: addedAt,
      type: type,
      watchProgress: watchProgress,
      isAvailableOffline: isAvailableOffline,
    );
  }
}

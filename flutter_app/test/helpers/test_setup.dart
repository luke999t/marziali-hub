/// 🎓 AI_MODULE: TestSetup
/// 🎓 AI_DESCRIPTION: Setup comune per test suite - ZERO MOCK
/// 🎓 AI_BUSINESS: Inizializzazione dipendenze reali per test
/// 🎓 AI_TEACHING: Dependency injection per test con backend reale
///
/// REGOLA ZERO MOCK:
/// - Nessun mockito, mocktail, fake
/// - Backend reale localhost:8000
/// - Skip se backend offline

import 'package:flutter_test/flutter_test.dart';
import 'package:get_it/get_it.dart';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

import 'package:martial_arts_streaming/core/network/api_client.dart';
import 'package:martial_arts_streaming/core/network/network_info.dart';
import 'package:martial_arts_streaming/features/search/data/datasources/search_remote_datasource.dart';
import 'package:martial_arts_streaming/features/search/data/repositories/search_repository_impl.dart';
import 'package:martial_arts_streaming/features/search/domain/repositories/search_repository.dart';
import 'package:martial_arts_streaming/features/search/domain/usecases/search_usecases.dart';
import 'package:martial_arts_streaming/features/search/presentation/bloc/search_bloc.dart';
import 'package:martial_arts_streaming/features/home/data/datasources/home_remote_datasource.dart';
import 'package:martial_arts_streaming/features/home/data/repositories/home_repository_impl.dart';
import 'package:martial_arts_streaming/features/home/domain/repositories/home_repository.dart';
import 'package:martial_arts_streaming/features/home/domain/usecases/home_usecases.dart';
import 'package:martial_arts_streaming/features/home/domain/usecases/get_featured_content_usecase.dart';
import 'package:martial_arts_streaming/features/home/domain/usecases/get_categories_usecase.dart';
import 'package:martial_arts_streaming/features/home/presentation/bloc/home_bloc.dart';

import 'backend_checker.dart';

final testGetIt = GetIt.instance;

/// Configura dipendenze reali per test
/// ZERO MOCK - usa backend reale
Future<void> setupTestDependencies() async {
  // Reset GetIt
  await testGetIt.reset();

  // SharedPreferences per test
  SharedPreferences.setMockInitialValues({});
  final sharedPreferences = await SharedPreferences.getInstance();
  testGetIt.registerSingleton<SharedPreferences>(sharedPreferences);

  // Connectivity
  testGetIt.registerSingleton<Connectivity>(Connectivity());

  // Network Info - usa implementazione reale
  testGetIt.registerSingleton<NetworkInfo>(
    NetworkInfoImpl(testGetIt<Connectivity>()),
  );

  // Dio configurato per test con backend reale
  final dio = Dio(BaseOptions(
    baseUrl: '${BackendChecker.baseUrl}/api/v1',
    connectTimeout: const Duration(seconds: 10),
    receiveTimeout: const Duration(seconds: 10),
    sendTimeout: const Duration(seconds: 10),
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  ));

  // Log interceptor per debug test
  dio.interceptors.add(LogInterceptor(
    requestBody: true,
    responseBody: true,
    logPrint: (obj) => print('🧪 TEST DIO: $obj'),
  ));

  testGetIt.registerSingleton<Dio>(dio);

  // API Client - REALE, non mock
  // Nota: ApiClient richiede FlutterSecureStorage che non funziona in test
  // Usiamo una versione semplificata per test
  testGetIt.registerSingleton<Dio>(dio);

  // ==================== SEARCH ====================
  testGetIt.registerLazySingleton<SearchRemoteDataSource>(
    () => SearchRemoteDataSourceImpl(TestApiClient(dio)),
  );

  testGetIt.registerLazySingleton<SearchRepository>(
    () => SearchRepositoryImpl(
      remoteDataSource: testGetIt<SearchRemoteDataSource>(),
      networkInfo: testGetIt<NetworkInfo>(),
      sharedPreferences: testGetIt<SharedPreferences>(),
    ),
  );

  testGetIt.registerLazySingleton(
    () => SearchUseCase(testGetIt<SearchRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => GetTrendingSearchesUseCase(testGetIt<SearchRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => GetSearchHistoryUseCase(testGetIt<SearchRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => AddToSearchHistoryUseCase(testGetIt<SearchRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => ClearSearchHistoryUseCase(testGetIt<SearchRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => RemoveFromSearchHistoryUseCase(testGetIt<SearchRepository>()),
  );

  testGetIt.registerFactory(() => SearchBloc(
        searchContentUseCase: testGetIt<SearchUseCase>(),
        getTrendingSearchesUseCase: testGetIt<GetTrendingSearchesUseCase>(),
        getSearchHistoryUseCase: testGetIt<GetSearchHistoryUseCase>(),
        addToSearchHistoryUseCase: testGetIt<AddToSearchHistoryUseCase>(),
        clearSearchHistoryUseCase: testGetIt<ClearSearchHistoryUseCase>(),
        removeFromSearchHistoryUseCase:
            testGetIt<RemoveFromSearchHistoryUseCase>(),
      ));

  // ==================== HOME ====================
  testGetIt.registerLazySingleton<HomeRemoteDataSource>(
    () => HomeRemoteDataSourceImpl(TestApiClient(dio)),
  );

  testGetIt.registerLazySingleton<HomeRepository>(
    () => HomeRepositoryImpl(
      remoteDataSource: testGetIt<HomeRemoteDataSource>(),
      networkInfo: testGetIt<NetworkInfo>(),
    ),
  );

  testGetIt.registerLazySingleton(
    () => GetFeaturedContentUseCase(testGetIt<HomeRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => GetCategoriesUseCase(testGetIt<HomeRepository>()),
  );
  testGetIt.registerLazySingleton(
    () => GetContentRowsUseCase(testGetIt<HomeRepository>()),
  );

  testGetIt.registerFactory(() => HomeBloc(
        getFeaturedContentUseCase: testGetIt<GetFeaturedContentUseCase>(),
        getCategoriesUseCase: testGetIt<GetCategoriesUseCase>(),
        getContentRowsUseCase: testGetIt<GetContentRowsUseCase>(),
      ));
}

/// Pulisce dipendenze dopo i test
Future<void> tearDownTestDependencies() async {
  await testGetIt.reset();
  BackendChecker.invalidateCache();
}

/// ApiClient semplificato per test (senza FlutterSecureStorage)
class TestApiClient {
  final Dio _dio;

  TestApiClient(this._dio);

  Future<Response<dynamic>> get(
    String path, {
    Map<String, dynamic>? queryParameters,
  }) {
    return _dio.get(path, queryParameters: queryParameters);
  }

  Future<Response<dynamic>> post(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
  }) {
    return _dio.post(path, data: data, queryParameters: queryParameters);
  }

  Future<Response<dynamic>> put(
    String path, {
    dynamic data,
    Map<String, dynamic>? queryParameters,
  }) {
    return _dio.put(path, data: data, queryParameters: queryParameters);
  }

  Future<Response<dynamic>> delete(
    String path, {
    Map<String, dynamic>? queryParameters,
  }) {
    return _dio.delete(path, queryParameters: queryParameters);
  }
}

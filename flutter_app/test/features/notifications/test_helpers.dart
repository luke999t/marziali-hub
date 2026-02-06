/// 🎓 AI_MODULE: NotificationsTestHelpers
/// 🎓 AI_DESCRIPTION: Helper per test notifiche ZERO MOCK
/// 🎓 AI_TEACHING: Setup reale per test integrazione

import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:connectivity_plus/connectivity_plus.dart';

import 'package:media_center_arti_marziali/core/network/api_client.dart';
import 'package:media_center_arti_marziali/core/network/network_info.dart';
import 'package:media_center_arti_marziali/features/notifications/data/datasources/notifications_remote_datasource.dart';
import 'package:media_center_arti_marziali/features/notifications/data/datasources/notifications_local_datasource.dart';
import 'package:media_center_arti_marziali/features/notifications/data/repositories/notifications_repository_impl.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/repositories/notifications_repository.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/get_notifications_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/get_unread_count_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/mark_as_read_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/mark_all_read_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/delete_notification_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/domain/usecases/preferences_usecase.dart';
import 'package:media_center_arti_marziali/features/notifications/presentation/bloc/notifications_bloc.dart';

/// Test configuration
class TestConfig {
  /// Base URL for test API - use real backend
  static const String baseUrl = 'http://localhost:8100/api/v1';

  /// Test user credentials
  static const String testEmail = 'test@example.com';
  static const String testPassword = 'testpassword123';

  /// Test timeout
  static const Duration timeout = Duration(seconds: 30);
}

/// ZERO MOCK test setup - calls real backend
class NotificationsTestSetup {
  late Dio dio;
  late ApiClient apiClient;
  late NetworkInfo networkInfo;
  late SharedPreferences sharedPreferences;
  late FlutterSecureStorage secureStorage;
  late NotificationsRemoteDataSource remoteDataSource;
  late NotificationsLocalDataSource localDataSource;
  late NotificationsRepository repository;
  late NotificationsBloc bloc;

  // Use Cases
  late GetNotificationsUseCase getNotificationsUseCase;
  late GetUnreadCountUseCase getUnreadCountUseCase;
  late MarkAsReadUseCase markAsReadUseCase;
  late MarkAllAsReadUseCase markAllAsReadUseCase;
  late DeleteNotificationUseCase deleteNotificationUseCase;
  late GetPreferencesUseCase getPreferencesUseCase;
  late UpdatePreferencesUseCase updatePreferencesUseCase;

  String? authToken;

  /// Initialize all real dependencies - ZERO MOCK
  Future<void> init() async {
    // Initialize SharedPreferences
    SharedPreferences.setMockInitialValues({});
    sharedPreferences = await SharedPreferences.getInstance();

    // Initialize Dio with real configuration
    dio = Dio(BaseOptions(
      baseUrl: TestConfig.baseUrl,
      connectTimeout: TestConfig.timeout,
      receiveTimeout: TestConfig.timeout,
      sendTimeout: TestConfig.timeout,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    ));

    // Add logging for debugging
    dio.interceptors.add(LogInterceptor(
      requestBody: true,
      responseBody: true,
      logPrint: (obj) => print('TEST DIO: $obj'),
    ));

    // Initialize secure storage (use mock for tests)
    secureStorage = const FlutterSecureStorage(
      aOptions: AndroidOptions(encryptedSharedPreferences: true),
    );

    // Network Info - real implementation
    networkInfo = NetworkInfoImpl(Connectivity());

    // API Client with real Dio
    apiClient = ApiClient(dio, secureStorage);

    // Data Sources - real implementations
    remoteDataSource = NotificationsRemoteDataSourceImpl(apiClient);
    localDataSource = NotificationsLocalDataSourceImpl(sharedPreferences);

    // Repository - real implementation
    repository = NotificationsRepositoryImpl(
      remoteDataSource: remoteDataSource,
      localDataSource: localDataSource,
      networkInfo: networkInfo,
    );

    // Use Cases - real implementations
    getNotificationsUseCase = GetNotificationsUseCase(repository);
    getUnreadCountUseCase = GetUnreadCountUseCase(repository);
    markAsReadUseCase = MarkAsReadUseCase(repository);
    markAllAsReadUseCase = MarkAllAsReadUseCase(repository);
    deleteNotificationUseCase = DeleteNotificationUseCase(repository);
    getPreferencesUseCase = GetPreferencesUseCase(repository);
    updatePreferencesUseCase = UpdatePreferencesUseCase(repository);

    // BLoC - with real use cases
    bloc = NotificationsBloc(
      getNotificationsUseCase: getNotificationsUseCase,
      getUnreadCountUseCase: getUnreadCountUseCase,
      markAsReadUseCase: markAsReadUseCase,
      markAllAsReadUseCase: markAllAsReadUseCase,
      deleteNotificationUseCase: deleteNotificationUseCase,
      getPreferencesUseCase: getPreferencesUseCase,
      updatePreferencesUseCase: updatePreferencesUseCase,
    );
  }

  /// Authenticate for tests that require auth
  Future<void> authenticate() async {
    try {
      final response = await dio.post(
        '/auth/login',
        data: {
          'email': TestConfig.testEmail,
          'password': TestConfig.testPassword,
        },
      );

      authToken = response.data['access_token'] as String?;
      if (authToken != null) {
        dio.options.headers['Authorization'] = 'Bearer $authToken';
      }
    } catch (e) {
      print('Test authentication failed: $e');
      rethrow;
    }
  }

  /// Clean up resources
  Future<void> dispose() async {
    await bloc.close();
    dio.close();
  }
}

/// Helper to create test notifications in the backend
class NotificationsTestDataHelper {
  final Dio dio;

  NotificationsTestDataHelper(this.dio);

  /// Create a test notification via API
  Future<String> createTestNotification({
    String type = 'system',
    String priority = 'normal',
    String title = 'Test Notification',
    String body = 'This is a test notification body',
  }) async {
    try {
      final response = await dio.post(
        '/notifications/test/create',
        data: {
          'type': type,
          'priority': priority,
          'title': title,
          'body': body,
        },
      );
      return response.data['id'] as String;
    } catch (e) {
      print('Failed to create test notification: $e');
      rethrow;
    }
  }

  /// Delete a test notification
  Future<void> deleteTestNotification(String id) async {
    try {
      await dio.delete('/notifications/$id');
    } catch (e) {
      print('Failed to delete test notification: $e');
    }
  }

  /// Clean up all test notifications
  Future<void> cleanupTestNotifications() async {
    try {
      await dio.delete('/notifications');
    } catch (e) {
      print('Failed to cleanup test notifications: $e');
    }
  }
}

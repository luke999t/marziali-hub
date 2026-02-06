import 'package:dartz/dartz.dart';
import 'package:mocktail/mocktail.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:dio/dio.dart';

import 'package:martial_arts_streaming/core/network/api_client.dart';
import 'package:martial_arts_streaming/core/network/network_info.dart';
import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/auth/domain/repositories/auth_repository.dart';
import 'package:martial_arts_streaming/features/auth/domain/entities/user.dart';
import 'package:martial_arts_streaming/features/auth/data/datasources/auth_remote_datasource.dart';
import 'package:martial_arts_streaming/features/auth/data/datasources/auth_local_datasource.dart';
import 'package:martial_arts_streaming/features/auth/data/models/auth_response_model.dart';
import 'package:martial_arts_streaming/features/auth/data/models/user_model.dart';

// Repository Mocks
class MockAuthRepository extends Mock implements AuthRepository {}

// DataSource Mocks
class MockAuthRemoteDataSource extends Mock implements AuthRemoteDataSource {}

class MockAuthLocalDataSource extends Mock implements AuthLocalDataSource {}

// Network Mocks
class MockNetworkInfo extends Mock implements NetworkInfo {}

class MockApiClient extends Mock implements ApiClient {}

class MockConnectivity extends Mock implements Connectivity {}

class MockFlutterSecureStorage extends Mock implements FlutterSecureStorage {}

class MockDio extends Mock implements Dio {}

// Fake Classes for mocktail
class FakeUser extends Fake implements User {}

class FakeUserModel extends Fake implements UserModel {}

class FakeAuthResponseModel extends Fake implements AuthResponseModel {}

class FakeFailure extends Fake implements Failure {}

class FakeUri extends Fake implements Uri {}

class FakeResponse extends Fake implements Response<dynamic> {}

// Test Fixtures
class AuthTestFixtures {
  static const testEmail = 'test@example.com';
  static const testPassword = 'password123';
  static const testUsername = 'testuser';
  static const testAccessToken = 'access_token_123';
  static const testRefreshToken = 'refresh_token_456';

  static UserModel get testUserModel => UserModel(
        id: 'user_123',
        email: testEmail,
        username: testUsername,
        tier: UserTier.premium,
        isVerified: true,
        isMaestro: false,
        createdAt: DateTime(2024, 1, 1),
        preferences: const UserPreferencesModel(),
        stellineBalance: 100,
      );

  static AuthResponseModel get testAuthResponse => AuthResponseModel(
        accessToken: testAccessToken,
        refreshToken: testRefreshToken,
        user: testUserModel,
      );

  static User get testUser => testUserModel;
}

// Stub Helpers
extension MockAuthRepositoryStubs on MockAuthRepository {
  void stubLoginSuccess(User user) {
    when(() => login(
          email: any(named: 'email'),
          password: any(named: 'password'),
          rememberMe: any(named: 'rememberMe'),
        )).thenAnswer((_) async => Right(user));
  }

  void stubLoginFailure(Failure failure) {
    when(() => login(
          email: any(named: 'email'),
          password: any(named: 'password'),
          rememberMe: any(named: 'rememberMe'),
        )).thenAnswer((_) async => Left(failure));
  }

  void stubRegisterSuccess(User user) {
    when(() => register(
          email: any(named: 'email'),
          username: any(named: 'username'),
          password: any(named: 'password'),
          acceptTerms: any(named: 'acceptTerms'),
        )).thenAnswer((_) async => Right(user));
  }

  void stubRegisterFailure(Failure failure) {
    when(() => register(
          email: any(named: 'email'),
          username: any(named: 'username'),
          password: any(named: 'password'),
          acceptTerms: any(named: 'acceptTerms'),
        )).thenAnswer((_) async => Left(failure));
  }

  void stubGetCurrentUserSuccess(User user) {
    when(() => getCurrentUser()).thenAnswer((_) async => Right(user));
  }

  void stubGetCurrentUserFailure(Failure failure) {
    when(() => getCurrentUser()).thenAnswer((_) async => Left(failure));
  }

  void stubIsAuthenticated(bool value) {
    when(() => isAuthenticated()).thenAnswer((_) async => value);
  }

  void stubLogoutSuccess() {
    when(() => logout()).thenAnswer((_) async => const Right(null));
  }
}

extension MockNetworkInfoStubs on MockNetworkInfo {
  void stubIsConnected(bool value) {
    when(() => isConnected).thenAnswer((_) async => value);
  }
}

extension MockAuthRemoteDataSourceStubs on MockAuthRemoteDataSource {
  void stubLoginSuccess(AuthResponseModel response) {
    when(() => login(
          email: any(named: 'email'),
          password: any(named: 'password'),
        )).thenAnswer((_) async => response);
  }

  void stubLoginThrows(Exception exception) {
    when(() => login(
          email: any(named: 'email'),
          password: any(named: 'password'),
        )).thenThrow(exception);
  }
}

extension MockAuthLocalDataSourceStubs on MockAuthLocalDataSource {
  void stubCacheTokensSuccess() {
    when(() => cacheTokens(
          accessToken: any(named: 'accessToken'),
          refreshToken: any(named: 'refreshToken'),
        )).thenAnswer((_) async {});
  }

  void stubGetAccessToken(String? token) {
    when(() => getAccessToken()).thenAnswer((_) async => token);
  }

  void stubGetRefreshToken(String? token) {
    when(() => getRefreshToken()).thenAnswer((_) async => token);
  }

  void stubCacheUserSuccess() {
    when(() => cacheUser(any())).thenAnswer((_) async {});
  }

  void stubGetCachedUser(UserModel? user) {
    when(() => getCachedUser()).thenAnswer((_) async => user);
  }
}

// Setup function for all mocks
void registerFallbackValues() {
  registerFallbackValue(FakeUser());
  registerFallbackValue(FakeUserModel());
  registerFallbackValue(FakeAuthResponseModel());
  registerFallbackValue(FakeFailure());
  registerFallbackValue(FakeUri());
  registerFallbackValue(FakeResponse());
}

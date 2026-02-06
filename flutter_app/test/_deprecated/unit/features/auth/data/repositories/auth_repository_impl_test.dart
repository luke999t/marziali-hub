import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:dartz/dartz.dart';

import 'package:martial_arts_streaming/core/error/exceptions.dart';
import 'package:martial_arts_streaming/core/error/failures.dart';
import 'package:martial_arts_streaming/features/auth/data/repositories/auth_repository_impl.dart';
import 'package:martial_arts_streaming/features/auth/data/models/auth_response_model.dart';
import 'package:martial_arts_streaming/features/auth/data/models/user_model.dart';
import 'package:martial_arts_streaming/features/auth/domain/entities/user.dart';

import '../../../../../test_config.dart';
import '../../../../../mocks/mock_repositories.dart';

@Tags([TestTags.unit])
void main() {
  late AuthRepositoryImpl repository;
  late MockAuthRemoteDataSource mockRemoteDataSource;
  late MockAuthLocalDataSource mockLocalDataSource;
  late MockNetworkInfo mockNetworkInfo;

  setUpAll(() {
    registerFallbackValues();
  });

  setUp(() {
    mockRemoteDataSource = MockAuthRemoteDataSource();
    mockLocalDataSource = MockAuthLocalDataSource();
    mockNetworkInfo = MockNetworkInfo();
    repository = AuthRepositoryImpl(
      remoteDataSource: mockRemoteDataSource,
      localDataSource: mockLocalDataSource,
      networkInfo: mockNetworkInfo,
    );
  });

  group('AuthRepositoryImpl', () {
    group('login', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;
      final testAuthResponse = AuthTestFixtures.testAuthResponse;

      test('should return User when login is successful with network', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        mockRemoteDataSource.stubLoginSuccess(testAuthResponse);
        mockLocalDataSource.stubCacheTokensSuccess();
        mockLocalDataSource.stubCacheUserSuccess();

        // Act
        final result = await repository.login(email: email, password: password);

        // Assert
        expect(result, isA<Right<Failure, User>>());
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) {
            expect(user.email, equals(testAuthResponse.user.email));
          },
        );

        verify(() => mockRemoteDataSource.login(email: email, password: password)).called(1);
        verify(() => mockLocalDataSource.cacheTokens(
              accessToken: testAuthResponse.accessToken,
              refreshToken: testAuthResponse.refreshToken,
            )).called(1);
        verify(() => mockLocalDataSource.cacheUser(testAuthResponse.user)).called(1);
      });

      test('should return NetworkFailure when no internet connection', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(false);

        // Act
        final result = await repository.login(email: email, password: password);

        // Assert
        expect(result, isA<Left<Failure, User>>());
        result.fold(
          (failure) => expect(failure, isA<NetworkFailure>()),
          (user) => fail('Expected failure but got success'),
        );

        verifyNever(() => mockRemoteDataSource.login(
              email: any(named: 'email'),
              password: any(named: 'password'),
            ));
      });

      test('should return AuthFailure when credentials are invalid', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        mockRemoteDataSource.stubLoginThrows(AuthException('Invalid credentials'));

        // Act
        final result = await repository.login(email: email, password: password);

        // Assert
        expect(result, isA<Left<Failure, User>>());
        result.fold(
          (failure) {
            expect(failure, isA<AuthFailure>());
            expect(failure.message, equals('Invalid credentials'));
          },
          (user) => fail('Expected failure but got success'),
        );
      });

      test('should return ServerFailure on server error', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        mockRemoteDataSource.stubLoginThrows(ServerException('Internal server error'));

        // Act
        final result = await repository.login(email: email, password: password);

        // Assert
        result.fold(
          (failure) => expect(failure, isA<ServerFailure>()),
          (user) => fail('Expected failure but got success'),
        );
      });
    });

    group('register', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;
      const username = TestDataFactory.validUsername;
      final testAuthResponse = AuthTestFixtures.testAuthResponse;

      test('should return User when registration is successful', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.register(
              email: any(named: 'email'),
              username: any(named: 'username'),
              password: any(named: 'password'),
            )).thenAnswer((_) async => testAuthResponse);
        mockLocalDataSource.stubCacheTokensSuccess();
        mockLocalDataSource.stubCacheUserSuccess();

        // Act
        final result = await repository.register(
          email: email,
          username: username,
          password: password,
        );

        // Assert
        expect(result, isA<Right<Failure, User>>());
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.email, equals(testAuthResponse.user.email)),
        );
      });

      test('should return ValidationFailure when email already exists', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.register(
              email: any(named: 'email'),
              username: any(named: 'username'),
              password: any(named: 'password'),
            )).thenThrow(ValidationException(
          'Validation failed',
          fieldErrors: {'email': ['Email already in use']},
        ));

        // Act
        final result = await repository.register(
          email: email,
          username: username,
          password: password,
        );

        // Assert
        result.fold(
          (failure) {
            expect(failure, isA<ValidationFailure>());
            final validationFailure = failure as ValidationFailure;
            expect(validationFailure.fieldErrors?.keys, contains('email'));
          },
          (user) => fail('Expected failure but got success'),
        );
      });

      test('should return NetworkFailure when offline', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(false);

        // Act
        final result = await repository.register(
          email: email,
          username: username,
          password: password,
        );

        // Assert
        result.fold(
          (failure) => expect(failure, isA<NetworkFailure>()),
          (user) => fail('Expected failure but got success'),
        );
      });
    });

    group('logout', () {
      test('should clear local data and return success on logout', () async {
        // Arrange
        when(() => mockRemoteDataSource.logout()).thenAnswer((_) async {});
        when(() => mockLocalDataSource.clearTokens()).thenAnswer((_) async {});
        when(() => mockLocalDataSource.clearCachedUser()).thenAnswer((_) async {});

        // Act
        final result = await repository.logout();

        // Assert
        expect(result, isA<Right<Failure, void>>());
        verify(() => mockRemoteDataSource.logout()).called(1);
        verify(() => mockLocalDataSource.clearTokens()).called(1);
        verify(() => mockLocalDataSource.clearCachedUser()).called(1);
      });

      test('should clear local data even if remote logout fails', () async {
        // Arrange
        when(() => mockRemoteDataSource.logout())
            .thenThrow(ServerException('Server error'));
        when(() => mockLocalDataSource.clearTokens()).thenAnswer((_) async {});
        when(() => mockLocalDataSource.clearCachedUser()).thenAnswer((_) async {});

        // Act
        final result = await repository.logout();

        // Assert
        expect(result, isA<Right<Failure, void>>());
        verify(() => mockLocalDataSource.clearTokens()).called(1);
        verify(() => mockLocalDataSource.clearCachedUser()).called(1);
      });
    });

    group('getCurrentUser', () {
      final testUser = AuthTestFixtures.testUserModel;

      test('should return User from remote when online', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.getCurrentUser())
            .thenAnswer((_) async => testUser);
        mockLocalDataSource.stubCacheUserSuccess();

        // Act
        final result = await repository.getCurrentUser();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.id, equals(testUser.id)),
        );
        verify(() => mockLocalDataSource.cacheUser(testUser)).called(1);
      });

      test('should return cached User when offline', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(false);
        mockLocalDataSource.stubGetCachedUser(testUser);

        // Act
        final result = await repository.getCurrentUser();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.id, equals(testUser.id)),
        );
      });

      test('should return cached User when network fails', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.getCurrentUser())
            .thenThrow(NetworkException('Connection failed'));
        mockLocalDataSource.stubGetCachedUser(testUser);

        // Act
        final result = await repository.getCurrentUser();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.id, equals(testUser.id)),
        );
      });

      test('should return NetworkFailure when offline and no cache', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(false);
        mockLocalDataSource.stubGetCachedUser(null);

        // Act
        final result = await repository.getCurrentUser();

        // Assert
        result.fold(
          (failure) => expect(failure, isA<NetworkFailure>()),
          (user) => fail('Expected failure but got success'),
        );
      });
    });

    group('isAuthenticated', () {
      test('should return true when access token exists', () async {
        // Arrange
        mockLocalDataSource.stubGetAccessToken('valid_token');

        // Act
        final result = await repository.isAuthenticated();

        // Assert
        expect(result, isTrue);
      });

      test('should return false when access token does not exist', () async {
        // Arrange
        mockLocalDataSource.stubGetAccessToken(null);

        // Act
        final result = await repository.isAuthenticated();

        // Assert
        expect(result, isFalse);
      });
    });

    group('forgotPassword', () {
      test('should return success when email is sent', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.forgotPassword(any()))
            .thenAnswer((_) async {});

        // Act
        final result = await repository.forgotPassword(TestDataFactory.validEmail);

        // Assert
        expect(result, isA<Right<Failure, void>>());
      });

      test('should return NetworkFailure when offline', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(false);

        // Act
        final result = await repository.forgotPassword(TestDataFactory.validEmail);

        // Assert
        result.fold(
          (failure) => expect(failure, isA<NetworkFailure>()),
          (_) => fail('Expected failure but got success'),
        );
      });
    });

    group('resetPassword', () {
      test('should return success when password is reset', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.resetPassword(
              token: any(named: 'token'),
              newPassword: any(named: 'newPassword'),
            )).thenAnswer((_) async {});

        // Act
        final result = await repository.resetPassword(
          token: 'valid_token',
          newPassword: TestDataFactory.validPassword,
        );

        // Assert
        expect(result, isA<Right<Failure, void>>());
      });

      test('should return AuthFailure when token is invalid', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.resetPassword(
              token: any(named: 'token'),
              newPassword: any(named: 'newPassword'),
            )).thenThrow(AuthException('Invalid token'));

        // Act
        final result = await repository.resetPassword(
          token: 'invalid_token',
          newPassword: TestDataFactory.validPassword,
        );

        // Assert
        result.fold(
          (failure) => expect(failure, isA<AuthFailure>()),
          (_) => fail('Expected failure but got success'),
        );
      });
    });

    group('refreshToken', () {
      final testAuthResponse = AuthTestFixtures.testAuthResponse;

      test('should return success and cache new tokens', () async {
        // Arrange
        mockLocalDataSource.stubGetRefreshToken('old_refresh_token');
        when(() => mockRemoteDataSource.refreshToken(any()))
            .thenAnswer((_) async => testAuthResponse);
        mockLocalDataSource.stubCacheTokensSuccess();

        // Act
        final result = await repository.refreshToken();

        // Assert
        expect(result, isA<Right<Failure, void>>());
        verify(() => mockLocalDataSource.cacheTokens(
              accessToken: testAuthResponse.accessToken,
              refreshToken: testAuthResponse.refreshToken,
            )).called(1);
      });

      test('should return AuthFailure when no refresh token available', () async {
        // Arrange
        mockLocalDataSource.stubGetRefreshToken(null);

        // Act
        final result = await repository.refreshToken();

        // Assert
        result.fold(
          (failure) {
            expect(failure, isA<AuthFailure>());
            expect(failure.message, contains('No refresh token'));
          },
          (_) => fail('Expected failure but got success'),
        );
      });

      test('should clear tokens when refresh fails', () async {
        // Arrange
        mockLocalDataSource.stubGetRefreshToken('old_refresh_token');
        when(() => mockRemoteDataSource.refreshToken(any()))
            .thenThrow(AuthException('Token expired'));
        when(() => mockLocalDataSource.clearTokens()).thenAnswer((_) async {});

        // Act
        final result = await repository.refreshToken();

        // Assert
        result.fold(
          (failure) => expect(failure, isA<AuthFailure>()),
          (_) => fail('Expected failure but got success'),
        );
        verify(() => mockLocalDataSource.clearTokens()).called(1);
      });
    });

    group('signInWithGoogle', () {
      final testAuthResponse = AuthTestFixtures.testAuthResponse;

      test('should return User when Google sign-in succeeds', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.signInWithGoogle())
            .thenAnswer((_) async => testAuthResponse);
        mockLocalDataSource.stubCacheTokensSuccess();
        mockLocalDataSource.stubCacheUserSuccess();

        // Act
        final result = await repository.signInWithGoogle();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.email, equals(testAuthResponse.user.email)),
        );
      });
    });

    group('signInWithApple', () {
      final testAuthResponse = AuthTestFixtures.testAuthResponse;

      test('should return User when Apple sign-in succeeds', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.signInWithApple())
            .thenAnswer((_) async => testAuthResponse);
        mockLocalDataSource.stubCacheTokensSuccess();
        mockLocalDataSource.stubCacheUserSuccess();

        // Act
        final result = await repository.signInWithApple();

        // Assert
        result.fold(
          (failure) => fail('Expected success but got failure'),
          (user) => expect(user.email, equals(testAuthResponse.user.email)),
        );
      });
    });

    group('verifyEmail', () {
      test('should return success when email is verified', () async {
        // Arrange
        mockNetworkInfo.stubIsConnected(true);
        when(() => mockRemoteDataSource.verifyEmail(any()))
            .thenAnswer((_) async {});

        // Act
        final result = await repository.verifyEmail('valid_token');

        // Assert
        expect(result, isA<Right<Failure, void>>());
      });
    });
  });
}

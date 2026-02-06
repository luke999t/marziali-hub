import 'package:flutter_test/flutter_test.dart';
import 'package:mocktail/mocktail.dart';
import 'package:dio/dio.dart';

import 'package:martial_arts_streaming/core/network/api_client.dart';
import 'package:martial_arts_streaming/core/error/exceptions.dart';
import 'package:martial_arts_streaming/features/auth/data/datasources/auth_remote_datasource.dart';
import 'package:martial_arts_streaming/features/auth/data/models/auth_response_model.dart';
import 'package:martial_arts_streaming/features/auth/data/models/user_model.dart';

import '../../../../../test_config.dart';
import '../../../../../mocks/mock_repositories.dart';

@Tags([TestTags.unit])
void main() {
  late AuthRemoteDataSourceImpl dataSource;
  late MockApiClient mockApiClient;

  setUpAll(() {
    registerFallbackValues();
  });

  setUp(() {
    mockApiClient = MockApiClient();
    dataSource = AuthRemoteDataSourceImpl(mockApiClient);
  });

  group('AuthRemoteDataSource', () {
    group('login', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;

      test('should return AuthResponseModel when login is successful', () async {
        // Arrange
        final responseData = TestDataFactory.createAuthResponseJson();
        when(() => mockApiClient.post(
              '/auth/login',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              data: responseData,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/login'),
            ));

        // Act
        final result = await dataSource.login(email: email, password: password);

        // Assert
        expect(result, isA<AuthResponseModel>());
        expect(result.accessToken, equals(responseData['access_token']));
        expect(result.user.email, equals(responseData['user']['email']));

        verify(() => mockApiClient.post(
              '/auth/login',
              data: {'email': email, 'password': password},
            )).called(1);
      });

      test('should throw AuthException when credentials are invalid', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/login',
              data: any(named: 'data'),
            )).thenThrow(AuthException('Invalid credentials'));

        // Act & Assert
        expect(
          () => dataSource.login(email: email, password: password),
          throwsA(isA<AuthException>()),
        );
      });

      test('should throw NetworkException when network fails', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/login',
              data: any(named: 'data'),
            )).thenThrow(NetworkException('Connection failed'));

        // Act & Assert
        expect(
          () => dataSource.login(email: email, password: password),
          throwsA(isA<AppException>()),
        );
      });

      test('should throw ServerException for unexpected errors', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/login',
              data: any(named: 'data'),
            )).thenThrow(Exception('Unknown error'));

        // Act & Assert
        expect(
          () => dataSource.login(email: email, password: password),
          throwsA(isA<ServerException>()),
        );
      });
    });

    group('register', () {
      const email = TestDataFactory.validEmail;
      const password = TestDataFactory.validPassword;
      const username = TestDataFactory.validUsername;

      test('should return AuthResponseModel when registration is successful', () async {
        // Arrange
        final responseData = TestDataFactory.createAuthResponseJson();
        when(() => mockApiClient.post(
              '/auth/register',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              data: responseData,
              statusCode: 201,
              requestOptions: RequestOptions(path: '/auth/register'),
            ));

        // Act
        final result = await dataSource.register(
          email: email,
          username: username,
          password: password,
        );

        // Assert
        expect(result, isA<AuthResponseModel>());
        expect(result.accessToken, isNotEmpty);

        verify(() => mockApiClient.post(
              '/auth/register',
              data: {
                'email': email,
                'username': username,
                'password': password,
              },
            )).called(1);
      });

      test('should throw ValidationException when email already exists', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/register',
              data: any(named: 'data'),
            )).thenThrow(ValidationException(
          'Email already registered',
          fieldErrors: {'email': ['Email already in use']},
        ));

        // Act & Assert
        expect(
          () => dataSource.register(
            email: email,
            username: username,
            password: password,
          ),
          throwsA(isA<AppException>()),
        );
      });
    });

    group('logout', () {
      test('should complete successfully when logout succeeds', () async {
        // Arrange
        when(() => mockApiClient.post('/auth/logout')).thenAnswer(
          (_) async => Response(
            statusCode: 200,
            requestOptions: RequestOptions(path: '/auth/logout'),
          ),
        );
        when(() => mockApiClient.clearTokens()).thenAnswer((_) async {});

        // Act & Assert
        await expectLater(dataSource.logout(), completes);

        verify(() => mockApiClient.post('/auth/logout')).called(1);
        verify(() => mockApiClient.clearTokens()).called(1);
      });

      test('should clear tokens locally even if server fails', () async {
        // Arrange
        when(() => mockApiClient.post('/auth/logout'))
            .thenThrow(ServerException('Server error'));
        when(() => mockApiClient.clearTokens()).thenAnswer((_) async {});

        // Act
        await dataSource.logout();

        // Assert
        verify(() => mockApiClient.clearTokens()).called(1);
      });
    });

    group('getCurrentUser', () {
      test('should return UserModel when successful', () async {
        // Arrange
        final userData = TestDataFactory.createUserJson();
        when(() => mockApiClient.get('/auth/me')).thenAnswer(
          (_) async => Response(
            data: userData,
            statusCode: 200,
            requestOptions: RequestOptions(path: '/auth/me'),
          ),
        );

        // Act
        final result = await dataSource.getCurrentUser();

        // Assert
        expect(result, isA<UserModel>());
        expect(result.email, equals(userData['email']));
      });

      test('should throw AuthException when not authenticated', () async {
        // Arrange
        when(() => mockApiClient.get('/auth/me'))
            .thenThrow(AuthException('Not authenticated'));

        // Act & Assert
        expect(
          () => dataSource.getCurrentUser(),
          throwsA(isA<AuthException>()),
        );
      });
    });

    group('refreshToken', () {
      test('should return new tokens when refresh succeeds', () async {
        // Arrange
        final responseData = TestDataFactory.createAuthResponseJson(
          accessToken: 'new_access_token',
          refreshToken: 'new_refresh_token',
        );
        when(() => mockApiClient.post(
              '/auth/refresh',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              data: responseData,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/refresh'),
            ));

        // Act
        final result = await dataSource.refreshToken('old_refresh_token');

        // Assert
        expect(result.accessToken, equals('new_access_token'));
        expect(result.refreshToken, equals('new_refresh_token'));
      });

      test('should throw AuthException when refresh token is invalid', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/refresh',
              data: any(named: 'data'),
            )).thenThrow(AuthException('Invalid refresh token'));

        // Act & Assert
        expect(
          () => dataSource.refreshToken('invalid_token'),
          throwsA(isA<AuthException>()),
        );
      });
    });

    group('forgotPassword', () {
      test('should complete successfully when email is valid', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/forgot-password',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/forgot-password'),
            ));

        // Act & Assert
        await expectLater(
          dataSource.forgotPassword(TestDataFactory.validEmail),
          completes,
        );
      });
    });

    group('resetPassword', () {
      test('should complete successfully when token and password are valid', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/reset-password',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/reset-password'),
            ));

        // Act & Assert
        await expectLater(
          dataSource.resetPassword(
            token: 'valid_token',
            newPassword: TestDataFactory.validPassword,
          ),
          completes,
        );
      });
    });

    group('verifyEmail', () {
      test('should complete successfully when token is valid', () async {
        // Arrange
        when(() => mockApiClient.post(
              '/auth/verify-email',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/verify-email'),
            ));

        // Act & Assert
        await expectLater(
          dataSource.verifyEmail('valid_token'),
          completes,
        );
      });
    });

    group('signInWithGoogle', () {
      test('should return AuthResponseModel when Google sign-in succeeds', () async {
        // Arrange
        final responseData = TestDataFactory.createAuthResponseJson();
        when(() => mockApiClient.post(
              '/auth/google',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              data: responseData,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/google'),
            ));

        // Act
        final result = await dataSource.signInWithGoogle();

        // Assert
        expect(result, isA<AuthResponseModel>());
        verify(() => mockApiClient.post(
              '/auth/google',
              data: any(named: 'data'),
            )).called(1);
      });
    });

    group('signInWithApple', () {
      test('should return AuthResponseModel when Apple sign-in succeeds', () async {
        // Arrange
        final responseData = TestDataFactory.createAuthResponseJson();
        when(() => mockApiClient.post(
              '/auth/apple',
              data: any(named: 'data'),
            )).thenAnswer((_) async => Response(
              data: responseData,
              statusCode: 200,
              requestOptions: RequestOptions(path: '/auth/apple'),
            ));

        // Act
        final result = await dataSource.signInWithApple();

        // Assert
        expect(result, isA<AuthResponseModel>());
        verify(() => mockApiClient.post(
              '/auth/apple',
              data: any(named: 'data'),
            )).called(1);
      });
    });
  });
}
